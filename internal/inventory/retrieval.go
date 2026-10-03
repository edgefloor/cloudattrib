package inventory

import (
	"context"
	"slices"
	"strings"
	"time"

	"cloudattrib/internal/model"
)

// RetrievalMode chooses how retained descriptions are ranked.
type RetrievalMode string

const (
	// RetrievalLexical ranks retained description terms without local inference.
	RetrievalLexical RetrievalMode = "lexical"
	// RetrievalSemantic ranks local model vectors from the active generation.
	RetrievalSemantic RetrievalMode = "semantic"
	// RetrievalHybrid fuses lexical and semantic candidates, with explicit fallback.
	RetrievalHybrid RetrievalMode = "hybrid"
)

// RetrievalRequest is a bounded top-results query in one explicit context.
type RetrievalRequest struct {
	Text      string        `json:"text"`
	Mode      RetrievalMode `json:"mode"`
	ScopeRoot string        `json:"scope_root,omitempty"`
	ContextID string        `json:"context_id,omitempty"`
	Limit     int           `json:"limit,omitempty"`
}

// RetrievalResult retains source evidence and labels similarity as ranking only.
type RetrievalResult struct {
	EvidenceResult
	MatchModes         []string `json:"match_modes"`
	SemanticSimilarity *float64 `json:"semantic_similarity,omitempty"`
	ModelGeneration    string   `json:"model_generation,omitempty"`
	FusionScore        float64  `json:"fusion_score,omitempty"`
}

// RetrievalPage is a bounded window, not a count of all relevant assets.
type RetrievalPage struct {
	Items              []RetrievalResult `json:"items"`
	Truncated          bool              `json:"truncated"`
	CandidateTruncated bool              `json:"candidate_truncated"`
	DegradedToLexical  bool              `json:"degraded_to_lexical"`
	ModelGeneration    string            `json:"model_generation,omitempty"`
}

// SemanticQuery gives PostgreSQL a validated vector and scope before ranking.
type SemanticQuery struct {
	Vector       []float32
	GenerationID string
	ContextID    string
	ScopeRoot    string
	Limit        int
}

// SemanticStore reads the active generation and exact filtered vector matches.
type SemanticStore interface {
	ActiveEmbeddingGeneration(context.Context) (EmbeddingGeneration, error)
	SearchInventorySemantic(context.Context, SemanticQuery) (EvidencePage, error)
}

// RetrievalLexicalStore ranks any matching query term for natural-language
// retrieval while the inventory evidence endpoint keeps its existing filter.
type RetrievalLexicalStore interface {
	SearchInventoryRetrievalLexical(context.Context, EvidenceQuery) (EvidencePage, error)
}

// EmbeddingProvider selects a local model for the active generation at query
// time, allowing a database cutover without restarting inventory readers.
type EmbeddingProvider interface {
	ForGeneration(context.Context, EmbeddingGeneration) (Embedder, error)
}

type fixedEmbeddingProvider struct {
	generationID string
	embedder     Embedder
}

func (p fixedEmbeddingProvider) ForGeneration(_ context.Context, generation EmbeddingGeneration) (Embedder, error) {
	if generation.ID != p.generationID {
		return nil, model.NewError(model.CodeCapabilityUnavailable, "loaded model does not match active generation", nil)
	}
	return p.embedder, nil
}

// WithEmbedder enables optional local inference for the named model generation.
// Configure it before concurrent service use.
func (s *Service) WithEmbedder(generationID string, embedder Embedder) *Service {
	return s.WithEmbeddingProvider(fixedEmbeddingProvider{generationID: generationID, embedder: embedder})
}

// WithEmbeddingProvider enables a generation-aware local model provider.
// Configure it before concurrent service use.
func (s *Service) WithEmbeddingProvider(provider EmbeddingProvider) *Service {
	s.embeddingProvider = provider
	// Bound the complete inference and vector-query path while admitting the
	// ten concurrent readers used by the inventory capacity contract.
	s.embeddingSlots = make(chan struct{}, 10)
	return s
}

// Retrieve combines exact hostname, lexical, and optional local semantic hits.
func (s *Service) Retrieve(ctx context.Context, request RetrievalRequest) (RetrievalPage, error) {
	if s == nil || s.store == nil {
		return RetrievalPage{}, model.NewError(model.CodeInvalidOptions, "inventory store is required", nil)
	}
	request.Text = strings.TrimSpace(request.Text)
	if request.Text == "" || len(request.Text) > 1024 || strings.ContainsAny(request.Text, "\x00\r\n") {
		return RetrievalPage{}, model.NewError(model.CodeInvalidOptions, "retrieval text must contain 1 to 1024 characters", nil)
	}
	if request.Mode == "" {
		request.Mode = RetrievalHybrid
	}
	if request.Mode != RetrievalLexical && request.Mode != RetrievalSemantic && request.Mode != RetrievalHybrid {
		return RetrievalPage{}, model.NewError(model.CodeInvalidOptions, "invalid retrieval mode", nil)
	}
	if request.Limit == 0 {
		request.Limit = 50
	}
	if request.Limit < 1 || request.Limit > 100 {
		return RetrievalPage{}, model.NewError(model.CodeInvalidOptions, "retrieval limit must be between 1 and 100", nil)
	}
	if request.ScopeRoot != "" {
		root, _, err := Normalize(request.ScopeRoot)
		if err != nil {
			return RetrievalPage{}, err
		}
		request.ScopeRoot = root
	}
	if request.ContextID == "" {
		request.ContextID = s.defaultContext
	}
	if request.ContextID == "" || len(request.ContextID) > 128 || strings.ContainsAny(request.ContextID, "\x00\r\n") {
		return RetrievalPage{}, model.NewError(model.CodeInvalidOptions, "retrieval requires a valid observation context", nil)
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	candidateLimit := min(request.Limit*2, 100)
	var lexical, semantic EvidencePage
	var generationID string
	var lexicalErr, semanticErr error
	searchLexical := func() {
		query := EvidenceQuery{
			Text: request.Text, ScopeRoot: request.ScopeRoot, ContextID: request.ContextID, Limit: candidateLimit,
		}
		if retrievalStore, ok := s.store.(RetrievalLexicalStore); ok {
			lexical, lexicalErr = retrievalStore.SearchInventoryRetrievalLexical(ctx, query)
		} else {
			lexical, lexicalErr = s.store.SearchInventoryEvidence(ctx, query)
		}
	}
	if request.Mode == RetrievalHybrid {
		lexicalDone := make(chan struct{})
		go func() {
			defer close(lexicalDone)
			searchLexical()
		}()
		semantic, generationID, semanticErr = s.searchSemantic(ctx, request, candidateLimit)
		<-lexicalDone
	} else if request.Mode == RetrievalLexical {
		searchLexical()
	} else {
		semantic, generationID, semanticErr = s.searchSemantic(ctx, request, candidateLimit)
	}
	if lexicalErr != nil {
		return RetrievalPage{}, lexicalErr
	}
	if request.Mode != RetrievalLexical {
		if semanticErr != nil && request.Mode == RetrievalSemantic {
			return RetrievalPage{}, semanticErr
		}
		if semanticErr != nil && ctx.Err() != nil {
			return RetrievalPage{}, ctx.Err()
		}
	}
	pinned, err := s.exactEvidenceMatch(ctx, request)
	if err != nil {
		return RetrievalPage{}, err
	}
	page := combineRetrieval(request.Mode, request.Limit, pinned, lexical, semantic, generationID)
	page.DegradedToLexical = request.Mode == RetrievalHybrid && semanticErr != nil
	return page, nil
}

func (s *Service) searchSemantic(ctx context.Context, request RetrievalRequest, limit int) (EvidencePage, string, error) {
	semanticStore, ok := s.store.(SemanticStore)
	if !ok || s.embeddingProvider == nil || s.embeddingSlots == nil {
		return EvidencePage{}, "", model.NewError(model.CodeCapabilityUnavailable, "local semantic search is unavailable", nil)
	}
	generation, err := semanticStore.ActiveEmbeddingGeneration(ctx)
	if err != nil {
		return EvidencePage{}, "", err
	}
	select {
	case s.embeddingSlots <- struct{}{}:
		defer func() { <-s.embeddingSlots }()
	case <-ctx.Done():
		return EvidencePage{}, "", ctx.Err()
	}
	embedder, err := s.embeddingProvider.ForGeneration(ctx, generation)
	if err != nil || embedder == nil {
		if err == nil {
			err = model.NewError(model.CodeCapabilityUnavailable, "local model is unavailable", nil)
		}
		return EvidencePage{}, "", err
	}
	vector, err := embedder.Embed(ctx, generation.QueryPrefix+request.Text)
	if err != nil {
		return EvidencePage{}, "", model.NewError(model.CodeCapabilityUnavailable, "local query embedding failed", err)
	}
	if err := ValidateEmbedding(vector, generation.Dimensions); err != nil {
		return EvidencePage{}, "", err
	}
	page, err := semanticStore.SearchInventorySemantic(ctx, SemanticQuery{Vector: vector,
		GenerationID: generation.ID, ContextID: request.ContextID, ScopeRoot: request.ScopeRoot, Limit: limit})
	if err != nil {
		return EvidencePage{}, "", err
	}
	return page, generation.ID, nil
}

func (s *Service) exactEvidenceMatch(ctx context.Context, request RetrievalRequest) (*EvidenceResult, error) {
	hostname, _, err := Normalize(request.Text)
	if err != nil || request.ScopeRoot != "" && !WithinScope(hostname, request.ScopeRoot) {
		return nil, nil
	}
	prepared, _, err := PrepareSearch(SearchRequest{Mode: SearchExact, Query: hostname, ScopeRoot: request.ScopeRoot, Limit: 1})
	if err != nil {
		return nil, err
	}
	assets, err := s.store.SearchInventory(ctx, prepared, "")
	if err != nil {
		return nil, err
	}
	if len(assets.Items) == 0 {
		return nil, nil
	}
	item, err := s.store.ReadInventoryEvidence(ctx, hostname, request.ContextID)
	if err != nil {
		if model.ErrorCodeOf(err) == model.CodeNotFound {
			return nil, nil
		}
		return nil, err
	}
	return &item, nil
}

func combineRetrieval(mode RetrievalMode, limit int, pinned *EvidenceResult, lexical, semantic EvidencePage, generationID string) RetrievalPage {
	page := RetrievalPage{Items: []RetrievalResult{}, CandidateTruncated: lexical.Truncated || semantic.Truncated, ModelGeneration: generationID}
	byAsset := make(map[string]*RetrievalResult, len(lexical.Items)+len(semantic.Items)+1)
	add := func(item EvidenceResult, matchMode string, position int) {
		result := byAsset[item.AssetID]
		if result == nil {
			copy := RetrievalResult{EvidenceResult: item, MatchModes: []string{}}
			result = &copy
			byAsset[item.AssetID] = result
		}
		if !slices.Contains(result.MatchModes, matchMode) {
			result.MatchModes = append(result.MatchModes, matchMode)
		}
		if matchMode == "semantic" {
			similarity := item.Rank
			result.SemanticSimilarity = &similarity
			result.ModelGeneration = generationID
		}
		result.FusionScore += 1 / float64(60+position+1)
	}
	for index, item := range lexical.Items {
		add(item, "lexical", index)
	}
	for index, item := range semantic.Items {
		add(item, "semantic", index)
	}
	if pinned != nil {
		add(*pinned, "exact_hostname", 0)
	}
	for _, item := range byAsset {
		page.Items = append(page.Items, *item)
	}
	slices.SortFunc(page.Items, func(left, right RetrievalResult) int {
		leftExact, rightExact := slices.Contains(left.MatchModes, "exact_hostname"), slices.Contains(right.MatchModes, "exact_hostname")
		if leftExact != rightExact {
			if leftExact {
				return -1
			}
			return 1
		}
		if mode == RetrievalSemantic && left.SemanticSimilarity != nil && right.SemanticSimilarity != nil && *left.SemanticSimilarity != *right.SemanticSimilarity {
			if *left.SemanticSimilarity > *right.SemanticSimilarity {
				return -1
			}
			return 1
		}
		if left.FusionScore != right.FusionScore {
			if left.FusionScore > right.FusionScore {
				return -1
			}
			return 1
		}
		return strings.Compare(left.Hostname, right.Hostname)
	})
	if len(page.Items) > limit {
		page.Items = page.Items[:limit]
		page.Truncated = true
	}
	page.Truncated = page.Truncated || page.CandidateTruncated
	return page
}
