package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"cloudattrib/internal/app"
	"cloudattrib/internal/cli"
	"cloudattrib/internal/config"
	"cloudattrib/internal/ctlog"
	"cloudattrib/internal/datasets"
	localruntime "cloudattrib/internal/runtime"
)

func main() {
	configuration := config.Default()
	if configPath := os.Getenv("CLOUDATTRIB_CONFIG"); configPath != "" {
		loaded, err := config.Load(configPath)
		if err != nil {
			_, _ = fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		configuration = loaded
	}
	if resolver := os.Getenv("CLOUDATTRIB_RESOLVER"); resolver != "" {
		configuration.Resolver.Address = resolver
	}
	if dsnFile := os.Getenv("CLOUDATTRIB_POSTGRES_DSN_FILE"); dsnFile != "" {
		configuration.Storage.PostgresDSNFile = dsnFile
	}
	if enabled := os.Getenv("CLOUDATTRIB_CT_ENABLED"); enabled != "" {
		value, parseErr := strconv.ParseBool(enabled)
		if parseErr != nil {
			_, _ = fmt.Fprintln(os.Stderr, "CLOUDATTRIB_CT_ENABLED must be a boolean")
			os.Exit(2)
		}
		configuration.CT.Enabled = value
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	var analyzer app.Analyzer
	closeLocal := func() {}
	if requiresLocalAnalyzer(os.Args[1:]) {
		var err error
		analyzer, closeLocal, err = localruntime.OpenLocal(ctx, configuration)
		if err != nil {
			_, _ = fmt.Fprintln(os.Stderr, err)
			os.Exit(4)
		}
	}
	defer closeLocal()
	os.Exit(cli.Run(ctx, os.Args[1:], cli.Dependencies{Analyzer: analyzer, Serve: func(ctx context.Context, configPath string) error {
		resolved, err := resolveConfiguration(configuration, configPath)
		if err != nil {
			return err
		}
		return localruntime.Serve(ctx, resolved)
	}, CTImport: func(ctx context.Context, reader io.Reader, roots []string) (int, error) {
		return localruntime.ImportCT(ctx, configuration, reader, roots)
	}, CTCollect: func(ctx context.Context, path string) (ctlog.Metrics, error) {
		return localruntime.CollectCT(ctx, configuration, path)
	}, DatasetImport: func(ctx context.Context, configPath, sourceDirectory string) (datasets.ValidationReport, error) {
		resolved, err := resolveConfiguration(configuration, configPath)
		if err != nil {
			return datasets.ValidationReport{}, err
		}
		return localruntime.ImportDatasets(ctx, resolved, sourceDirectory)
	}, DatasetValidate: func(ctx context.Context, configPath, candidateID string) (datasets.ValidationReport, error) {
		resolved, err := resolveConfiguration(configuration, configPath)
		if err != nil {
			return datasets.ValidationReport{}, err
		}
		return localruntime.ValidateDataset(ctx, resolved, candidateID)
	}, DatasetActivate: func(ctx context.Context, configPath, candidateID, approvalHash, action string) (datasets.Activation, error) {
		resolved, err := resolveConfiguration(configuration, configPath)
		if err != nil {
			return datasets.Activation{}, err
		}
		return localruntime.ActivateDataset(ctx, resolved, candidateID, approvalHash, action)
	}, DatasetStatus: func(_ context.Context, configPath string) (datasets.RepositoryStatus, error) {
		resolved, err := resolveConfiguration(configuration, configPath)
		if err != nil {
			return datasets.RepositoryStatus{}, err
		}
		return localruntime.DatasetStatus(resolved)
	}, DatasetPrune: func(ctx context.Context, configPath, candidateID string) (bool, error) {
		resolved, err := resolveConfiguration(configuration, configPath)
		if err != nil {
			return false, err
		}
		return localruntime.PruneDataset(ctx, resolved, candidateID)
	}}))
}

func requiresLocalAnalyzer(args []string) bool {
	if len(args) == 0 {
		return false
	}
	switch args[0] {
	case "analyze", "batch", "lookup-ip", "reclassify":
		return true
	default:
		return false
	}
}

func resolveConfiguration(defaultConfiguration config.Config, path string) (config.Config, error) {
	if path == "" {
		return defaultConfiguration, nil
	}
	return config.Load(path)
}
