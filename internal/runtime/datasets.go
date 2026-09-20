package runtime

import (
	"context"
	"fmt"

	"cloudattrib/internal/config"
	"cloudattrib/internal/datasets"
	"cloudattrib/internal/store/postgres"
)

// ImportDatasets validates local source artifacts and publishes an immutable candidate.
func ImportDatasets(ctx context.Context, configuration config.Config, sourceDirectory string) (datasets.ValidationReport, error) {
	if sourceDirectory == "" {
		sourceDirectory = configuration.Data.SourceDirectory
	}
	repository, err := datasets.NewRepository(configuration.Data.BundleDirectory, detectorBuildID)
	if err != nil {
		return datasets.ValidationReport{}, err
	}
	return repository.Import(ctx, sourceDirectory)
}

// ValidateDataset revalidates an immutable candidate from disk.
func ValidateDataset(ctx context.Context, configuration config.Config, candidateID string) (datasets.ValidationReport, error) {
	repository, err := datasets.NewRepository(configuration.Data.BundleDirectory, detectorBuildID)
	if err != nil {
		return datasets.ValidationReport{}, err
	}
	return repository.Validate(ctx, candidateID)
}

// ActivateDataset coordinates durable admission metadata with filesystem publication.
func ActivateDataset(ctx context.Context, configuration config.Config, candidateID, approvalHash, action string) (datasets.Activation, error) {
	repository, err := datasets.NewRepository(configuration.Data.BundleDirectory, detectorBuildID)
	if err != nil {
		return datasets.Activation{}, err
	}
	report, err := repository.Validate(ctx, candidateID)
	if err != nil {
		return datasets.Activation{}, err
	}
	if approvalHash == "" || approvalHash != report.CandidateHash {
		return datasets.Activation{}, fmt.Errorf("approval hash does not match the validated candidate")
	}
	manifest, manifestBytes, err := repository.Manifest(candidateID)
	if err != nil {
		return datasets.Activation{}, err
	}
	store, err := openDatasetStore(ctx, configuration)
	if err != nil {
		return datasets.Activation{}, err
	}
	defer store.Close()
	if err := store.RegisterBundle(ctx, manifest.BundleID, manifestBytes, true); err != nil {
		return datasets.Activation{}, fmt.Errorf("register dataset candidate: %w", err)
	}
	activation, err := repository.Activate(ctx, candidateID, approvalHash, action)
	if err != nil {
		return datasets.Activation{}, err
	}
	if err := store.RecordBundleActivation(ctx, candidateID); err != nil {
		return activation, fmt.Errorf("record durable dataset activation: %w", err)
	}
	return activation, nil
}

// DatasetStatus returns desired, candidate, and process-load state.
func DatasetStatus(configuration config.Config) (datasets.RepositoryStatus, error) {
	repository, err := datasets.NewRepository(configuration.Data.BundleDirectory, detectorBuildID)
	if err != nil {
		return datasets.RepositoryStatus{}, err
	}
	return repository.Status()
}

// PruneDataset removes an unprotected candidate while serialized with durable admission.
func PruneDataset(ctx context.Context, configuration config.Config, candidateID string) (bool, error) {
	repository, err := datasets.NewRepository(configuration.Data.BundleDirectory, detectorBuildID)
	if err != nil {
		return false, err
	}
	store, err := openDatasetStore(ctx, configuration)
	if err != nil {
		return false, err
	}
	defer store.Close()
	return repository.Prune(candidateID, func(bundleID string) (bool, error) {
		protected := false
		err := store.WithBundlePruneLock(ctx, bundleID, func(pinned bool) error {
			protected = pinned
			return nil
		})
		return protected, err
	})
}

func openDatasetStore(ctx context.Context, configuration config.Config) (*postgres.Store, error) {
	dsn, err := readDSN(configuration.Storage.PostgresDSNFile)
	if err != nil {
		return nil, err
	}
	return postgres.Open(ctx, dsn, configuration.Limits.MaximumBacklogTargets)
}
