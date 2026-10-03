package inventory

import (
	"context"
	"strings"
	"testing"

	"cloudattrib/internal/model"
)

type retrievalTestStore struct {
	*recordingStore
	lexical    EvidencePage
	semantic   EvidencePage
	generation EmbeddingGeneration
	query      SemanticQuery
}

func (s *retrievalTestStore) SearchInventoryEvidence(context.Context, EvidenceQuery) (EvidencePage, error) {
	return s.lexical, nil
}

func (s *retrievalTestStore) SearchInventoryRetrievalLexical(context.Context, EvidenceQuery) (EvidencePage, error) {
	return s.lexical, nil
}

func (s *retrievalTestStore) ActiveEmbeddingGeneration(context.Context) (EmbeddingGeneration, error) {
	return s.generation, nil
}

func (s *retrievalTestStore) SearchInventorySemantic(_ context.Context, query SemanticQuery) (EvidencePage, error) {
	s.query = query
	return s.semantic, nil
}

type retrievalTestEmbedder struct{}

func (retrievalTestEmbedder) Embed(context.Context, string) ([]float32, error) {
	return []float32{1, 0, 0}, nil
}

type retrievalTestProvider struct{ seen []string }

func (provider *retrievalTestProvider) ForGeneration(_ context.Context, generation EmbeddingGeneration) (Embedder, error) {
	provider.seen = append(provider.seen, generation.ID)
	return retrievalTestEmbedder{}, nil
}

func TestRetrieveHybridCombinesDistinctModesAndFilters(t *testing.T) {
	store := &retrievalTestStore{recordingStore: &recordingStore{},
		generation: EmbeddingGeneration{ID: "gen-1", Dimensions: 3},
		lexical:    EvidencePage{Items: []EvidenceResult{{AssetID: "a", Hostname: "a.example.com", Description: "technology portal", Rank: 0.8}}},
		semantic: EvidencePage{Items: []EvidenceResult{{AssetID: "a", Hostname: "a.example.com", Rank: 0.9},
			{AssetID: "b", Hostname: "b.example.com", Rank: 0.7}}},
	}
	service := NewService(store).WithDefaultContext("public-view").WithEmbedder("gen-1", retrievalTestEmbedder{})
	page, err := service.Retrieve(t.Context(), RetrievalRequest{Text: "customer portal", ScopeRoot: "example.com", Limit: 2})
	if err != nil {
		t.Fatal(err)
	}
	if page.DegradedToLexical || len(page.Items) != 2 || page.Items[0].AssetID != "a" ||
		len(page.Items[0].MatchModes) != 2 || page.Items[0].SemanticSimilarity == nil ||
		*page.Items[0].SemanticSimilarity != 0.9 || page.Items[1].AssetID != "b" ||
		store.query.ContextID != "public-view" || store.query.ScopeRoot != "example.com" ||
		store.query.GenerationID != "gen-1" || page.ModelGeneration != "gen-1" {
		t.Fatalf("retrieval page=%#v semantic query=%#v", page, store.query)
	}
}

func TestRetrieveHybridDeclaresMissingModelAndSemanticFails(t *testing.T) {
	store := &retrievalTestStore{recordingStore: &recordingStore{},
		lexical: EvidencePage{Items: []EvidenceResult{{AssetID: "a", Hostname: "a.example.com"}}}}
	service := NewService(store).WithDefaultContext("public-view")
	page, err := service.Retrieve(t.Context(), RetrievalRequest{Text: "customer portal", Mode: RetrievalHybrid})
	if err != nil || !page.DegradedToLexical || len(page.Items) != 1 || page.Items[0].MatchModes[0] != "lexical" {
		t.Fatalf("hybrid fallback = %#v, %v", page, err)
	}
	if _, err := service.Retrieve(t.Context(), RetrievalRequest{Text: "customer portal", Mode: RetrievalSemantic}); model.ErrorCodeOf(err) != model.CodeCapabilityUnavailable {
		t.Fatalf("semantic without model = %v", err)
	}
}

func TestCombineRetrievalPinsExactHostnameAndReportsTruncation(t *testing.T) {
	pinned := &EvidenceResult{AssetID: "exact", Hostname: "api.example.com", ProjectionStatus: "pending"}
	page := combineRetrieval(RetrievalHybrid, 2, pinned,
		EvidencePage{Items: []EvidenceResult{{AssetID: "lexical", Hostname: "a.example.com"}}, Truncated: true},
		EvidencePage{Items: []EvidenceResult{{AssetID: "semantic", Hostname: "b.example.com", Rank: 0.8}}}, "gen-1")
	if len(page.Items) != 2 || page.Items[0].AssetID != "exact" || !slicesContains(page.Items[0].MatchModes, "exact_hostname") ||
		!page.Truncated || !page.CandidateTruncated {
		t.Fatalf("pinned page = %#v", page)
	}
}

func TestRetrieveRejectsUnboundedQuery(t *testing.T) {
	service := NewService(&recordingStore{}).WithDefaultContext("public-view")
	if _, err := service.Retrieve(t.Context(), RetrievalRequest{Text: strings.Repeat("x", 1025)}); model.ErrorCodeOf(err) != model.CodeInvalidOptions {
		t.Fatalf("oversized query = %v", err)
	}
}

func TestRetrieveFollowsActiveGenerationWithoutReconfiguringService(t *testing.T) {
	store := &retrievalTestStore{recordingStore: &recordingStore{},
		generation: EmbeddingGeneration{ID: "first", Dimensions: 3},
		semantic:   EvidencePage{Items: []EvidenceResult{{AssetID: "a", Hostname: "a.example.com", Rank: 0.8}}}}
	provider := &retrievalTestProvider{}
	service := NewService(store).WithDefaultContext("unknown").WithEmbeddingProvider(provider)
	first, err := service.Retrieve(t.Context(), RetrievalRequest{Text: "monitoring portal", Mode: RetrievalSemantic})
	if err != nil || first.ModelGeneration != "first" {
		t.Fatalf("first generation = %#v, %v", first, err)
	}
	store.generation.ID = "second"
	second, err := service.Retrieve(t.Context(), RetrievalRequest{Text: "monitoring portal", Mode: RetrievalSemantic})
	if err != nil || second.ModelGeneration != "second" || len(provider.seen) != 2 || provider.seen[1] != "second" {
		t.Fatalf("cutover generation = %#v, seen=%v, error=%v", second, provider.seen, err)
	}
}

func TestRetrieveSemanticAdmissionHonorsCancellation(t *testing.T) {
	store := &retrievalTestStore{recordingStore: &recordingStore{},
		generation: EmbeddingGeneration{ID: "gen-1", Dimensions: 3}}
	provider := &retrievalTestProvider{}
	service := NewService(store).WithDefaultContext("unknown").WithEmbeddingProvider(provider)
	for range cap(service.embeddingSlots) {
		service.embeddingSlots <- struct{}{}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, err := service.Retrieve(ctx, RetrievalRequest{Text: "customer portal", Mode: RetrievalSemantic})
	if err != context.Canceled || len(provider.seen) != 0 {
		t.Fatalf("saturated semantic search error=%v provider calls=%v", err, provider.seen)
	}
}

func slicesContains(values []string, needle string) bool {
	for _, value := range values {
		if value == needle {
			return true
		}
	}
	return false
}
