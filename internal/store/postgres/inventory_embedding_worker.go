package postgres

import (
	"context"
	"errors"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"

	"cloudattrib/internal/inventory"
	"cloudattrib/internal/model"
)

type inventoryEmbeddingClaim struct {
	AssetID            string
	ContextID          string
	GenerationID       string
	DescriptionHash    string
	DeletionGeneration int64
	Dimensions         int
	DocumentPrefix     string
	Token              string
}

// EmbeddingGenerationsWithPendingWork returns bounded local model contracts for
// work whose lease or retry delay allows another attempt now.
func (s *Store) EmbeddingGenerationsWithPendingWork(ctx context.Context, limit int) ([]inventory.EmbeddingGeneration, error) {
	if limit < 1 || limit > 16 {
		return nil, model.NewError(model.CodeInvalidOptions, "invalid embedding generation page", nil)
	}
	rows, err := s.pool.Query(ctx, `SELECT g.generation_id,g.model_id,g.model_revision,g.artifact_sha256,g.model_license,
		g.dimensions,g.document_format_version,g.preprocessing,g.query_prefix,g.document_prefix,g.metric
		FROM inventory_embedding_generations g WHERE g.status IN ('building','active')
		AND EXISTS (SELECT 1 FROM inventory_embedding_tasks t WHERE t.generation_id=g.generation_id AND t.attempts<5
		AND (t.status='pending' OR t.status='failed' AND t.next_attempt_at<=clock_timestamp()
		OR t.status='running' AND t.lease_expires_at<=clock_timestamp()))
		ORDER BY g.created_at,g.generation_id LIMIT $1`, limit)
	if err != nil {
		return nil, persistence("read embedding generations with work", err)
	}
	defer rows.Close()
	generations := make([]inventory.EmbeddingGeneration, 0, limit)
	for rows.Next() {
		var g inventory.EmbeddingGeneration
		if err := rows.Scan(&g.ID, &g.ModelID, &g.ModelRevision, &g.ArtifactSHA256, &g.License,
			&g.Dimensions, &g.DocumentFormatVersion, &g.Preprocessing, &g.QueryPrefix, &g.DocumentPrefix, &g.Metric); err != nil {
			return nil, persistence("scan embedding generation", err)
		}
		generations = append(generations, g)
	}
	if err := rows.Err(); err != nil {
		return nil, persistence("iterate embedding generations", err)
	}
	return generations, nil
}

func (s *Store) claimInventoryEmbedding(ctx context.Context, generationID string) (*inventoryEmbeddingClaim, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, persistence("begin inventory embedding claim", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	claim := &inventoryEmbeddingClaim{}
	err = tx.QueryRow(ctx, `SELECT t.asset_id,t.context_id,t.generation_id,t.description_hash,t.deletion_generation,
		g.dimensions,g.document_prefix FROM inventory_embedding_tasks t
		JOIN inventory_embedding_generations g ON g.generation_id=t.generation_id
		WHERE t.generation_id=$1 AND g.status IN ('building','active') AND t.attempts<5
		AND (t.status='pending' OR t.status='failed' AND t.next_attempt_at<=clock_timestamp()
		OR t.status='running' AND t.lease_expires_at<=clock_timestamp())
		ORDER BY t.created_at,t.asset_id,t.context_id FOR UPDATE OF t SKIP LOCKED LIMIT 1`, generationID).
		Scan(&claim.AssetID, &claim.ContextID, &claim.GenerationID, &claim.DescriptionHash,
			&claim.DeletionGeneration, &claim.Dimensions, &claim.DocumentPrefix)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, persistence("claim inventory embedding", err)
	}
	claim.Token, err = newID("inventory-embedding")
	if err != nil {
		return nil, err
	}
	if _, err := tx.Exec(ctx, `UPDATE inventory_embedding_tasks SET status='running',attempts=attempts+1,
		lease_token=$4,lease_expires_at=clock_timestamp()+interval '30 seconds',updated_at=clock_timestamp()
		WHERE asset_id=$1 AND context_id=$2 AND generation_id=$3`,
		claim.AssetID, claim.ContextID, claim.GenerationID, claim.Token); err != nil {
		return nil, persistence("lease inventory embedding", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, persistence("commit inventory embedding claim", err)
	}
	return claim, nil
}

// ProcessNextInventoryEmbedding computes one local vector outside a database
// transaction and publishes it only for the still-current description.
func (s *Store) ProcessNextInventoryEmbedding(ctx context.Context, generationID string, embedder inventory.Embedder) (bool, error) {
	if generationID == "" || embedder == nil {
		return false, model.NewError(model.CodeInvalidOptions, "embedding generation and local model are required", nil)
	}
	ctx, cancel := context.WithTimeout(ctx, 25*time.Second)
	defer cancel()
	claim, err := s.claimInventoryEmbedding(ctx, generationID)
	if err != nil || claim == nil {
		return false, err
	}
	var description, currentHash string
	err = s.pool.QueryRow(ctx, `SELECT description,description_hash FROM inventory_asset_contexts
		WHERE asset_id=$1 AND context_id=$2 AND deletion_generation=$3`,
		claim.AssetID, claim.ContextID, claim.DeletionGeneration).Scan(&description, &currentHash)
	if errors.Is(err, pgx.ErrNoRows) || err == nil && currentHash != claim.DescriptionHash {
		return true, nil // deletion or a new description invalidated this lease
	}
	if err == nil {
		var vector []float32
		vector, err = embedder.Embed(ctx, claim.DocumentPrefix+description)
		if err == nil {
			err = inventory.ValidateEmbedding(vector, claim.Dimensions)
		}
		if err == nil {
			err = s.publishInventoryEmbedding(ctx, *claim, vector)
		}
	}
	if err != nil {
		failCtx, failCancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
		defer failCancel()
		if failErr := s.failInventoryEmbedding(failCtx, *claim); failErr != nil {
			return true, errors.Join(err, failErr)
		}
		return true, err
	}
	return true, nil
}

func (s *Store) publishInventoryEmbedding(ctx context.Context, claim inventoryEmbeddingClaim, vector []float32) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return persistence("begin inventory embedding publication", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	// Use the same order as description publication, which may replace this task.
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(174120260922)`); err != nil {
		return persistence("serialize inventory embedding publication", err)
	}
	var revision, deletionGeneration int64
	var taskHash string
	err = tx.QueryRow(ctx, `SELECT description_revision,description_hash,deletion_generation
		FROM inventory_embedding_tasks WHERE asset_id=$1 AND context_id=$2 AND generation_id=$3
		AND status='running' AND lease_token=$4 AND lease_expires_at>clock_timestamp() FOR UPDATE`,
		claim.AssetID, claim.ContextID, claim.GenerationID, claim.Token).Scan(&revision, &taskHash, &deletionGeneration)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil // replaced, deleted, or lease expired
	}
	if err != nil {
		return persistence("lock inventory embedding task", err)
	}
	var currentRevision, currentDeletionGeneration int64
	var currentHash, generationStatus string
	err = tx.QueryRow(ctx, `SELECT c.description_revision,c.description_hash,c.deletion_generation,g.status
		FROM inventory_asset_contexts c JOIN inventory_embedding_generations g ON g.generation_id=$3
		WHERE c.asset_id=$1 AND c.context_id=$2 FOR UPDATE OF c`,
		claim.AssetID, claim.ContextID, claim.GenerationID).
		Scan(&currentRevision, &currentHash, &currentDeletionGeneration, &generationStatus)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return persistence("check current inventory description", err)
	}
	if currentRevision != revision || currentHash != taskHash || currentDeletionGeneration != deletionGeneration ||
		(generationStatus != "building" && generationStatus != "active") {
		return nil // another projection owns the next task revision
	}
	if _, err := tx.Exec(ctx, `INSERT INTO inventory_embeddings
		(asset_id,context_id,generation_id,description_revision,description_hash,deletion_generation,embedding)
		VALUES($1,$2,$3,$4,$5,$6,$7::halfvec)
		ON CONFLICT (asset_id,context_id,generation_id) DO UPDATE SET
		description_revision=EXCLUDED.description_revision,description_hash=EXCLUDED.description_hash,
		deletion_generation=EXCLUDED.deletion_generation,embedding=EXCLUDED.embedding,updated_at=clock_timestamp()`,
		claim.AssetID, claim.ContextID, claim.GenerationID, revision, taskHash, deletionGeneration, pgVectorLiteral(vector)); err != nil {
		return persistence("publish inventory embedding", err)
	}
	if _, err := tx.Exec(ctx, `DELETE FROM inventory_embedding_tasks WHERE asset_id=$1 AND context_id=$2 AND generation_id=$3 AND lease_token=$4`,
		claim.AssetID, claim.ContextID, claim.GenerationID, claim.Token); err != nil {
		return persistence("complete inventory embedding task", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return persistence("commit inventory embedding publication", err)
	}
	return nil
}

func (s *Store) failInventoryEmbedding(ctx context.Context, claim inventoryEmbeddingClaim) error {
	_, err := s.pool.Exec(ctx, `UPDATE inventory_embedding_tasks SET status='failed',lease_token=NULL,
		lease_expires_at=NULL,next_attempt_at=clock_timestamp()+make_interval(secs=>LEAST(300,attempts*attempts)),
		last_error='embedding_failed',updated_at=clock_timestamp()
		WHERE asset_id=$1 AND context_id=$2 AND generation_id=$3 AND lease_token=$4`,
		claim.AssetID, claim.ContextID, claim.GenerationID, claim.Token)
	if err != nil {
		return persistence("record inventory embedding failure", err)
	}
	return nil
}

func pgVectorLiteral(vector []float32) string {
	result := make([]byte, 0, len(vector)*12)
	result = append(result, '[')
	for i, coordinate := range vector {
		if i > 0 {
			result = append(result, ',')
		}
		result = strconv.AppendFloat(result, float64(coordinate), 'g', -1, 32)
	}
	return string(append(result, ']'))
}
