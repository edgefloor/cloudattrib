package postgres

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"

	"cloudattrib/internal/inventory"
	"cloudattrib/internal/model"
)

// ActiveEmbeddingGeneration returns the one generation used by query inference.
func (s *Store) ActiveEmbeddingGeneration(ctx context.Context) (inventory.EmbeddingGeneration, error) {
	var generation inventory.EmbeddingGeneration
	err := s.pool.QueryRow(ctx, `SELECT generation_id,model_id,model_revision,artifact_sha256,model_license,
		dimensions,document_format_version,preprocessing,query_prefix,document_prefix,metric
		FROM inventory_embedding_generations WHERE status='active'`).Scan(
		&generation.ID, &generation.ModelID, &generation.ModelRevision, &generation.ArtifactSHA256,
		&generation.License, &generation.Dimensions, &generation.DocumentFormatVersion,
		&generation.Preprocessing, &generation.QueryPrefix, &generation.DocumentPrefix, &generation.Metric)
	if errors.Is(err, pgx.ErrNoRows) {
		return inventory.EmbeddingGeneration{}, model.NewError(model.CodeCapabilityUnavailable, "no active embedding generation", nil)
	}
	if err != nil {
		return inventory.EmbeddingGeneration{}, persistence("read active embedding generation", err)
	}
	return generation, nil
}

// SearchInventorySemantic ranks exact vectors after context, scope, and current
// description filtering. It never applies a global top-K before scope filtering.
func (s *Store) SearchInventorySemantic(ctx context.Context, request inventory.SemanticQuery) (inventory.EvidencePage, error) {
	if request.GenerationID == "" || request.ContextID == "" || request.Limit < 1 || request.Limit > 100 {
		return inventory.EvidencePage{}, model.NewError(model.CodeInvalidOptions, "invalid semantic search filters or limit", nil)
	}
	if err := inventory.ValidateEmbedding(request.Vector, len(request.Vector)); err != nil {
		return inventory.EvidencePage{}, err
	}
	rows, err := s.pool.Query(ctx, `WITH ranked AS MATERIALIZED (
		SELECT e.asset_id,e.context_id,a.hostname,(1-(e.embedding <=> $4::vector))::real AS rank
		FROM inventory_embeddings e
		JOIN inventory_asset_contexts c ON c.asset_id=e.asset_id AND c.context_id=e.context_id
		JOIN inventory_assets a ON a.asset_id=e.asset_id
		WHERE e.generation_id=$1 AND e.context_id=$2 AND a.archived_at IS NULL
			AND e.description_revision=c.description_revision AND e.description_hash=c.description_hash
			AND e.deletion_generation=c.deletion_generation
			AND $1=(SELECT g.generation_id FROM inventory_embedding_generations g
				WHERE g.generation_id=$1 AND g.status='active')
			AND ($3='' OR EXISTS (SELECT 1 FROM inventory_memberships m WHERE m.asset_id=a.asset_id AND m.root=$3))
		ORDER BY rank DESC,a.hostname COLLATE "C" LIMIT $5
	)
	SELECT r.asset_id,r.hostname,r.context_id,c.description,c.description_revision,c.description_hash,
		COALESCE(c.description_report_id,''),c.description_evidence_ids,c.description_observation_ids,
		c.coverage,c.latest_coverage,c.omitted,c.latest_attempt_at,
		COALESCE(c.latest_attempt_report_id,''),c.last_positive_at,COALESCE(c.last_positive_report_id,''),
		c.latest_http_status,c.latest_http_at,c.last_http_response_status,c.last_http_response_at,
		COALESCE(c.last_http_response_report_id,''),r.rank
	FROM ranked r JOIN inventory_asset_contexts c ON c.asset_id=r.asset_id AND c.context_id=r.context_id
	ORDER BY r.rank DESC,r.hostname COLLATE "C"`,
		request.GenerationID, request.ContextID, request.ScopeRoot, pgVectorLiteral(request.Vector), request.Limit+1)
	if err != nil {
		return inventory.EvidencePage{}, persistence("search inventory embeddings", err)
	}
	defer rows.Close()
	page := inventory.EvidencePage{Items: make([]inventory.EvidenceResult, 0, request.Limit)}
	for rows.Next() {
		item, err := scanInventoryEvidence(rows)
		if err != nil {
			return inventory.EvidencePage{}, persistence("scan inventory semantic result", err)
		}
		item.MatchedTerms = []string{}
		page.Items = append(page.Items, item)
	}
	if err := rows.Err(); err != nil {
		return inventory.EvidencePage{}, persistence("iterate inventory semantic results", err)
	}
	if len(page.Items) > request.Limit {
		page.Items = page.Items[:request.Limit]
		page.Truncated = true
	}
	return page, nil
}
