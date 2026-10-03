package runtime

import (
	"cloudattrib/internal/config"
	"cloudattrib/internal/inventory"
	"cloudattrib/internal/jobs"
	"context"
)

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
