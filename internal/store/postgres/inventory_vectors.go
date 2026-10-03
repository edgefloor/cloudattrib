package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"cloudattrib/internal/inventory"
	"cloudattrib/internal/model"
)

const inventoryVectorExtensionVersion = "0.8.6"
const embeddingRollbackWindowDays = 7

// EnableInventoryVectors explicitly provisions the optional vector storage.
// Ordinary schema migration and inventory search do not require pgvector.
func (s *Store) EnableInventoryVectors(ctx context.Context) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return persistence("begin inventory vector setup", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(174120260920)`); err != nil {
		return persistence("lock inventory vector setup", err)
	}
	if _, err := tx.Exec(ctx, `CREATE EXTENSION IF NOT EXISTS vector`); err != nil {
		return model.NewError(model.CodeCapabilityUnavailable, "pgvector extension cannot be installed", err)
	}
	var installedVersion string
	if err := tx.QueryRow(ctx, `SELECT extversion FROM pg_extension WHERE extname='vector'`).Scan(&installedVersion); err != nil {
		return persistence("read pgvector version", err)
	}
	if installedVersion != inventoryVectorExtensionVersion {
		return model.NewError(model.CodeCapabilityUnavailable,
			fmt.Sprintf("pgvector %s is required; found %s", inventoryVectorExtensionVersion, installedVersion), nil)
	}
	if _, err := tx.Exec(ctx, `CREATE TABLE IF NOT EXISTS inventory_embeddings (
		asset_id text NOT NULL,
		context_id text NOT NULL,
		generation_id text NOT NULL REFERENCES inventory_embedding_generations(generation_id) ON DELETE CASCADE,
		description_revision bigint NOT NULL,
		description_hash text NOT NULL,
		deletion_generation bigint NOT NULL,
		embedding halfvec NOT NULL CHECK (vector_dims(embedding) BETWEEN 1 AND 2000),
		created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
		updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
		PRIMARY KEY (asset_id,context_id,generation_id),
		FOREIGN KEY (asset_id,context_id) REFERENCES inventory_asset_contexts(asset_id,context_id) ON DELETE CASCADE
	)`); err != nil {
		return persistence("create inventory vector storage", err)
	}
	var storageType string
	if err := tx.QueryRow(ctx, `SELECT a.atttypid::regtype::text FROM pg_attribute a
		WHERE a.attrelid='inventory_embeddings'::regclass AND a.attname='embedding'`).Scan(&storageType); err != nil {
		return persistence("read inventory vector storage type", err)
	}
	if storageType != "halfvec" {
		return model.NewError(model.CodeCapabilityUnavailable,
			"inventory vector storage uses an incompatible type; migrate it before enabling semantic search", nil)
	}
	if err := tx.Commit(ctx); err != nil {
		return persistence("commit inventory vector setup", err)
	}
	return nil
}

// InventoryEmbeddingCoverage measures the current vector set without counting
// stale description revisions or archived task attempts as covered.
func (s *Store) InventoryEmbeddingCoverage(ctx context.Context, generationID string) (inventory.EmbeddingCoverage, error) {
	if !inventory.SafeGenerationID(generationID) {
		return inventory.EmbeddingCoverage{}, model.NewError(model.CodeInvalidOptions, "invalid embedding generation ID", nil)
	}
	var status string
	var rollbackUntil *time.Time
	if err := s.pool.QueryRow(ctx, `SELECT status,CASE WHEN status='retained' THEN retained_at+make_interval(days=>$2) END
		FROM inventory_embedding_generations WHERE generation_id=$1`, generationID, embeddingRollbackWindowDays).
		Scan(&status, &rollbackUntil); err != nil {
		if err == pgx.ErrNoRows {
			return inventory.EmbeddingCoverage{}, model.NewError(model.CodeNotFound, "embedding generation not found", nil)
		}
		return inventory.EmbeddingCoverage{}, persistence("check embedding generation", err)
	}
	coverage, err := inventoryEmbeddingCoverage(ctx, s.pool, generationID)
	if err != nil {
		return inventory.EmbeddingCoverage{}, err
	}
	coverage.Status = status
	coverage.RollbackUntil = rollbackUntil
	return coverage, nil
}

type embeddingCoverageQuerier interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

func inventoryEmbeddingCoverage(ctx context.Context, querier embeddingCoverageQuerier, generationID string) (inventory.EmbeddingCoverage, error) {
	coverage := inventory.EmbeddingCoverage{GenerationID: generationID}
	err := querier.QueryRow(ctx, `WITH eligible AS (
		SELECT c.asset_id,c.context_id,c.description_revision,c.description_hash,c.deletion_generation
		FROM inventory_asset_contexts c WHERE c.description_hash<>''
	), states AS (
		SELECT e.asset_id,e.context_id,
			(v.asset_id IS NOT NULL) AS current_vector,
			(t.status='failed' AND t.attempts>=5) AS exhausted
		FROM eligible e
		LEFT JOIN inventory_embeddings v ON v.asset_id=e.asset_id AND v.context_id=e.context_id
			AND v.generation_id=$1 AND v.description_revision=e.description_revision
			AND v.description_hash=e.description_hash AND v.deletion_generation=e.deletion_generation
		LEFT JOIN inventory_embedding_tasks t ON t.asset_id=e.asset_id AND t.context_id=e.context_id
			AND t.generation_id=$1 AND t.description_revision=e.description_revision
			AND t.description_hash=e.description_hash AND t.deletion_generation=e.deletion_generation
	)
	SELECT count(*),count(*) FILTER (WHERE current_vector),
		count(*) FILTER (WHERE NOT current_vector AND exhausted),
		count(*) FILTER (WHERE NOT current_vector AND NOT COALESCE(exhausted,false)) FROM states`, generationID).
		Scan(&coverage.Eligible, &coverage.Current, &coverage.Failed, &coverage.Pending)
	if err != nil {
		return inventory.EmbeddingCoverage{}, persistence("read inventory embedding coverage", err)
	}
	return coverage, nil
}

// ActivateInventoryEmbeddingGeneration publishes a built generation only after
// every current description has a vector or an explicit exhausted failure.
func (s *Store) ActivateInventoryEmbeddingGeneration(ctx context.Context, generationID string) (inventory.EmbeddingCoverage, error) {
	if generationID == "" {
		return inventory.EmbeddingCoverage{}, model.NewError(model.CodeInvalidOptions, "embedding generation ID is required", nil)
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return inventory.EmbeddingCoverage{}, persistence("begin embedding generation activation", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(174120260922)`); err != nil {
		return inventory.EmbeddingCoverage{}, persistence("serialize embedding generation activation", err)
	}
	var status string
	if err := tx.QueryRow(ctx, `SELECT status FROM inventory_embedding_generations WHERE generation_id=$1 FOR UPDATE`, generationID).Scan(&status); err != nil {
		if err == pgx.ErrNoRows {
			return inventory.EmbeddingCoverage{}, model.NewError(model.CodeNotFound, "embedding generation not found", nil)
		}
		return inventory.EmbeddingCoverage{}, persistence("lock embedding generation", err)
	}
	if status != "building" {
		return inventory.EmbeddingCoverage{}, model.NewError(model.CodeInvalidOptions, "only a building embedding generation can be activated", nil)
	}
	coverage, err := inventoryEmbeddingCoverage(ctx, tx, generationID)
	if err != nil {
		return inventory.EmbeddingCoverage{}, err
	}
	if coverage.Pending != 0 {
		return coverage, model.NewError(model.CodeCapabilityUnavailable, "embedding generation still has unindexed descriptions", nil)
	}
	if _, err := tx.Exec(ctx, `UPDATE inventory_embedding_generations SET status='retained',retained_at=clock_timestamp() WHERE status='active'`); err != nil {
		return inventory.EmbeddingCoverage{}, persistence("retain preceding embedding generation", err)
	}
	if _, err := tx.Exec(ctx, `UPDATE inventory_embedding_generations SET status='active',retained_at=NULL WHERE generation_id=$1`, generationID); err != nil {
		return inventory.EmbeddingCoverage{}, persistence("activate embedding generation", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return inventory.EmbeddingCoverage{}, persistence("commit embedding generation activation", err)
	}
	coverage.Status = "active"
	return coverage, nil
}

// RollbackInventoryEmbeddingGeneration atomically selects a retained generation
// within seven days of its replacement. Missing current vectors are requeued;
// semantic queries exclude them until rebuilt from retained descriptions.
func (s *Store) RollbackInventoryEmbeddingGeneration(ctx context.Context, generationID string) (inventory.EmbeddingCoverage, error) {
	if generationID == "" {
		return inventory.EmbeddingCoverage{}, model.NewError(model.CodeInvalidOptions, "embedding generation ID is required", nil)
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return inventory.EmbeddingCoverage{}, persistence("begin embedding generation rollback", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(174120260922)`); err != nil {
		return inventory.EmbeddingCoverage{}, persistence("serialize embedding generation rollback", err)
	}
	var status string
	var withinWindow bool
	err = tx.QueryRow(ctx, `SELECT status,COALESCE(retained_at>=clock_timestamp()-make_interval(days=>$2),false)
		FROM inventory_embedding_generations WHERE generation_id=$1 FOR UPDATE`, generationID, embeddingRollbackWindowDays).
		Scan(&status, &withinWindow)
	if err == pgx.ErrNoRows {
		return inventory.EmbeddingCoverage{}, model.NewError(model.CodeNotFound, "embedding generation not found", nil)
	}
	if err != nil {
		return inventory.EmbeddingCoverage{}, persistence("lock retained embedding generation", err)
	}
	if status != "retained" || !withinWindow {
		return inventory.EmbeddingCoverage{}, model.NewError(model.CodeCapabilityUnavailable, "embedding generation is outside its rollback window", nil)
	}
	if _, err := tx.Exec(ctx, `UPDATE inventory_embedding_generations SET status='retained',retained_at=clock_timestamp()
		WHERE status='active'`); err != nil {
		return inventory.EmbeddingCoverage{}, persistence("retain replaced embedding generation", err)
	}
	if _, err := tx.Exec(ctx, `UPDATE inventory_embedding_generations SET status='active',retained_at=NULL WHERE generation_id=$1`, generationID); err != nil {
		return inventory.EmbeddingCoverage{}, persistence("select rollback embedding generation", err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO inventory_embedding_tasks
		(asset_id,context_id,generation_id,description_revision,description_hash,deletion_generation)
		SELECT c.asset_id,c.context_id,$1,c.description_revision,c.description_hash,c.deletion_generation
		FROM inventory_asset_contexts c WHERE c.description_hash<>'' AND NOT EXISTS (
			SELECT 1 FROM inventory_embeddings e WHERE e.asset_id=c.asset_id AND e.context_id=c.context_id
			AND e.generation_id=$1 AND e.description_revision=c.description_revision
			AND e.description_hash=c.description_hash AND e.deletion_generation=c.deletion_generation)
		ON CONFLICT (asset_id,context_id,generation_id) DO UPDATE SET
		description_revision=EXCLUDED.description_revision,description_hash=EXCLUDED.description_hash,
		deletion_generation=EXCLUDED.deletion_generation,status='pending',attempts=0,
		lease_token=NULL,lease_expires_at=NULL,next_attempt_at=NULL,last_error='',updated_at=clock_timestamp()`, generationID); err != nil {
		return inventory.EmbeddingCoverage{}, persistence("queue rollback embedding gaps", err)
	}
	coverage, err := inventoryEmbeddingCoverage(ctx, tx, generationID)
	if err != nil {
		return inventory.EmbeddingCoverage{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return inventory.EmbeddingCoverage{}, persistence("commit embedding generation rollback", err)
	}
	coverage.Status = "active"
	return coverage, nil
}

// PruneInventoryEmbeddingGeneration removes an expired retained generation and
// its vectors and queued work. The activation lock prevents racing a rollback.
func (s *Store) PruneInventoryEmbeddingGeneration(ctx context.Context, generationID string) error {
	if !inventory.SafeGenerationID(generationID) {
		return model.NewError(model.CodeInvalidOptions, "invalid embedding generation ID", nil)
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return persistence("begin embedding generation pruning", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(174120260922)`); err != nil {
		return persistence("serialize embedding generation pruning", err)
	}
	var expired bool
	err = tx.QueryRow(ctx, `SELECT status='retained' AND COALESCE(retained_at<clock_timestamp()-make_interval(days=>$2),false)
		FROM inventory_embedding_generations WHERE generation_id=$1 FOR UPDATE`, generationID, embeddingRollbackWindowDays).Scan(&expired)
	if err == pgx.ErrNoRows {
		return model.NewError(model.CodeNotFound, "embedding generation not found", nil)
	}
	if err != nil {
		return persistence("lock embedding generation for pruning", err)
	}
	if !expired {
		return model.NewError(model.CodeCapabilityUnavailable, "embedding generation is not an expired retained generation", nil)
	}
	if _, err := tx.Exec(ctx, `DELETE FROM inventory_embedding_generations WHERE generation_id=$1`, generationID); err != nil {
		return persistence("prune embedding generation", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return persistence("commit embedding generation pruning", err)
	}
	return nil
}

// BeginInventoryEmbeddingGeneration captures all current descriptions for a
// new, immutable model contract. Later projection writes queue their own work.
func (s *Store) BeginInventoryEmbeddingGeneration(ctx context.Context, generation inventory.EmbeddingGeneration) (int64, error) {
	if err := inventory.ValidateEmbeddingGeneration(generation); err != nil {
		return 0, err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return 0, persistence("begin inventory embedding generation", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(174120260922)`); err != nil {
		return 0, persistence("serialize inventory embedding generation", err)
	}
	var vectorStorageReady bool
	if err := tx.QueryRow(ctx, `SELECT to_regclass('inventory_embeddings') IS NOT NULL`).Scan(&vectorStorageReady); err != nil {
		return 0, persistence("check inventory vector storage", err)
	}
	if !vectorStorageReady {
		return 0, model.NewError(model.CodeCapabilityUnavailable, "inventory vector storage is not enabled", nil)
	}
	inserted, err := tx.Exec(ctx, `INSERT INTO inventory_embedding_generations
		(generation_id,model_id,model_revision,artifact_sha256,model_license,dimensions,document_format_version,
		preprocessing,query_prefix,document_prefix,metric,status)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,'building') ON CONFLICT (generation_id) DO NOTHING`,
		generation.ID, generation.ModelID, generation.ModelRevision, generation.ArtifactSHA256, generation.License,
		generation.Dimensions, generation.DocumentFormatVersion, generation.Preprocessing,
		generation.QueryPrefix, generation.DocumentPrefix, generation.Metric)
	if err != nil {
		return 0, persistence("create inventory embedding generation", err)
	}
	if inserted.RowsAffected() == 0 {
		return 0, model.NewError(model.CodeIdempotencyConflict, "embedding generation ID already exists", nil)
	}
	queued, err := tx.Exec(ctx, `INSERT INTO inventory_embedding_tasks
		(asset_id,context_id,generation_id,description_revision,description_hash,deletion_generation)
		SELECT asset_id,context_id,$1,description_revision,description_hash,deletion_generation
		FROM inventory_asset_contexts WHERE description_hash<>''`, generation.ID)
	if err != nil {
		return 0, persistence("queue initial inventory embeddings", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, persistence("commit inventory embedding generation", err)
	}
	return queued.RowsAffected(), nil
}
