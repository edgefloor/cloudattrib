package runtime

import (
	"context"

	"cloudattrib/internal/config"
	"cloudattrib/internal/embedding"
	"cloudattrib/internal/inventory"
	"cloudattrib/internal/jobs"
	"cloudattrib/internal/model"
	"cloudattrib/internal/policy"
)

// EnableInventoryVectors provisions the optional pgvector table explicitly.
func EnableInventoryVectors(ctx context.Context, configuration config.Config) error {
	store, err := openCTStore(ctx, configuration)
	if err != nil {
		return err
	}
	defer store.Close()
	return store.EnableInventoryVectors(ctx)
}

// BeginInventoryEmbeddingGeneration records a pinned model and queues retained descriptions.
func BeginInventoryEmbeddingGeneration(ctx context.Context, configuration config.Config, generation inventory.EmbeddingGeneration) (int64, error) {
	store, err := openCTStore(ctx, configuration)
	if err != nil {
		return 0, err
	}
	defer store.Close()
	return store.BeginInventoryEmbeddingGeneration(ctx, generation)
}

// InventoryEmbeddingCoverage reports the current vector coverage of one generation.
func InventoryEmbeddingCoverage(ctx context.Context, configuration config.Config, generationID string) (inventory.EmbeddingCoverage, error) {
	store, err := openCTStore(ctx, configuration)
	if err != nil {
		return inventory.EmbeddingCoverage{}, err
	}
	defer store.Close()
	return store.InventoryEmbeddingCoverage(ctx, generationID)
}

// ActivateInventoryEmbeddingGeneration switches only after indexing reaches its gate.
func ActivateInventoryEmbeddingGeneration(ctx context.Context, configuration config.Config, generationID string) (inventory.EmbeddingCoverage, error) {
	store, err := openCTStore(ctx, configuration)
	if err != nil {
		return inventory.EmbeddingCoverage{}, err
	}
	defer store.Close()
	return store.ActivateInventoryEmbeddingGeneration(ctx, generationID)
}

// RollbackInventoryEmbeddingGeneration restores a retained generation within seven days.
func RollbackInventoryEmbeddingGeneration(ctx context.Context, configuration config.Config, generationID string) (inventory.EmbeddingCoverage, error) {
	store, err := openCTStore(ctx, configuration)
	if err != nil {
		return inventory.EmbeddingCoverage{}, err
	}
	defer store.Close()
	return store.RollbackInventoryEmbeddingGeneration(ctx, generationID)
}

// PruneInventoryEmbeddingGeneration removes expired retained vectors and work.
func PruneInventoryEmbeddingGeneration(ctx context.Context, configuration config.Config, generationID string) error {
	store, err := openCTStore(ctx, configuration)
	if err != nil {
		return err
	}
	defer store.Close()
	return store.PruneInventoryEmbeddingGeneration(ctx, generationID)
}

// ImportInventory publishes one bounded, retryable hostname chunk.
func ImportInventory(ctx context.Context, configuration config.Config, request inventory.ImportRequest) (inventory.ImportReceipt, error) {
	store, err := openCTStore(ctx, configuration)
	if err != nil {
		return inventory.ImportReceipt{}, err
	}
	defer store.Close()
	return inventory.NewService(store).Import(ctx, request)
}

// ValidateInventory freezes selected known names into existing target jobs.
func ValidateInventory(ctx context.Context, configuration config.Config, operatorID string, request inventory.ValidationRequest) (jobs.Job, error) {
	store, err := openCTStore(ctx, configuration)
	if err != nil {
		return jobs.Job{}, err
	}
	defer store.Close()
	return inventory.NewValidator(inventory.NewService(store), store, store).Validate(ctx, operatorID, request)
}

// SearchInventoryEvidence reads ranked retained descriptions in one resolver context.
func SearchInventoryEvidence(ctx context.Context, configuration config.Config, request inventory.EvidenceQuery) (inventory.EvidencePage, error) {
	store, err := openCTStore(ctx, configuration)
	if err != nil {
		return inventory.EvidencePage{}, err
	}
	defer store.Close()
	return inventory.NewService(store).WithDefaultContext(observationContextID(configuration.Resolver, policy.PublicDestinationPolicyRevision)).SearchEvidence(ctx, request)
}

// RetrieveInventory combines retained lexical and optional local semantic matches.
func RetrieveInventory(ctx context.Context, configuration config.Config, request inventory.RetrievalRequest) (inventory.RetrievalPage, error) {
	store, err := openCTStore(ctx, configuration)
	if err != nil {
		return inventory.RetrievalPage{}, err
	}
	defer store.Close()
	service := inventory.NewService(store).WithDefaultContext(observationContextID(configuration.Resolver, policy.PublicDestinationPolicyRevision))
	if configuration.Embedding.Enabled {
		provider, err := embedding.NewProvider(configuration.Embedding.SocketDirectory)
		if err != nil {
			return inventory.RetrievalPage{}, err
		}
		service.WithEmbeddingProvider(provider)
	}
	return service.Retrieve(ctx, request)
}

// ReadInventoryEvidence reads one asset's retained evidence state.
func ReadInventoryEvidence(ctx context.Context, configuration config.Config, hostname, contextID string) (inventory.EvidenceResult, error) {
	store, err := openCTStore(ctx, configuration)
	if err != nil {
		return inventory.EvidenceResult{}, err
	}
	defer store.Close()
	return inventory.NewService(store).WithDefaultContext(observationContextID(configuration.Resolver, policy.PublicDestinationPolicyRevision)).ReadEvidence(ctx, hostname, contextID)
}

// InventoryProjectionStatus reads durable indexing lag.
func InventoryProjectionStatus(ctx context.Context, configuration config.Config) (inventory.ProjectionStatus, error) {
	store, err := openCTStore(ctx, configuration)
	if err != nil {
		return inventory.ProjectionStatus{}, err
	}
	defer store.Close()
	return inventory.NewService(store).ProjectionStatus(ctx)
}

// SearchInventory reads one bounded page of known names.
func SearchInventory(ctx context.Context, configuration config.Config, request inventory.SearchRequest) (inventory.Page, error) {
	store, err := openCTStore(ctx, configuration)
	if err != nil {
		return inventory.Page{}, err
	}
	defer store.Close()
	return inventory.NewService(store).Search(ctx, request)
}

// ReadInventory reads one known hostname.
func ReadInventory(ctx context.Context, configuration config.Config, hostname string) (inventory.Asset, error) {
	store, err := openCTStore(ctx, configuration)
	if err != nil {
		return inventory.Asset{}, err
	}
	defer store.Close()
	return inventory.NewService(store).Read(ctx, hostname)
}

// ArchiveInventory changes default asset visibility.
func ArchiveInventory(ctx context.Context, configuration config.Config, hostname string, archived bool) (inventory.Asset, error) {
	store, err := openCTStore(ctx, configuration)
	if err != nil {
		return inventory.Asset{}, err
	}
	defer store.Close()
	return inventory.NewService(store).Archive(ctx, hostname, archived)
}

// DeleteInventory removes inventory-owned data and optionally suppresses rediscovery.
func DeleteInventory(ctx context.Context, configuration config.Config, hostname string, suppress bool) (int64, error) {
	store, err := openCTStore(ctx, configuration)
	if err != nil {
		return 0, err
	}
	defer store.Close()
	return inventory.NewService(store).Delete(ctx, hostname, suppress)
}

// BackfillCTInventory copies one restartable page of historical CT sightings.
func BackfillCTInventory(ctx context.Context, configuration config.Config, cursor string, limit int) (inventory.BackfillPage, error) {
	store, err := openCTStore(ctx, configuration)
	if err != nil {
		return inventory.BackfillPage{}, err
	}
	defer store.Close()
	return store.BackfillCTInventory(ctx, cursor, limit)
}

// BackfillInventoryReports queues retained historical reports without network collection.
func BackfillInventoryReports(ctx context.Context, configuration config.Config, cursor string, limit int) (inventory.BackfillPage, error) {
	store, err := openCTStore(ctx, configuration)
	if err != nil {
		return inventory.BackfillPage{}, err
	}
	defer store.Close()
	return store.BackfillInventoryReports(ctx, cursor, limit)
}

// ProcessInventoryProjections runs at most limit durable indexing tasks.
func ProcessInventoryProjections(ctx context.Context, configuration config.Config, limit int) (int, error) {
	if limit < 1 || limit > 1000 {
		return 0, model.NewError(model.CodeInvalidOptions, "projection limit must be between 1 and 1000", nil)
	}
	store, err := openCTStore(ctx, configuration)
	if err != nil {
		return 0, err
	}
	defer store.Close()
	processed := 0
	for processed < limit {
		found, err := store.ProcessNextInventoryProjection(ctx)
		if err != nil {
			return processed, err
		}
		if !found {
			break
		}
		processed++
	}
	return processed, nil
}
