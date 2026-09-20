package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"cloudattrib/internal/cli"
	"cloudattrib/internal/config"
	"cloudattrib/internal/ctlog"
	localruntime "cloudattrib/internal/runtime"
)

func main() {
	configuration := config.Default()
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
	analyzer, closeLocal, err := localruntime.OpenLocal(ctx, configuration)
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(4)
	}
	defer closeLocal()
	os.Exit(cli.Run(ctx, os.Args[1:], cli.Dependencies{Analyzer: analyzer, Serve: func(ctx context.Context) error {
		return localruntime.Serve(ctx, configuration)
	}, CTImport: func(ctx context.Context, reader io.Reader, roots []string) (int, error) {
		return localruntime.ImportCT(ctx, configuration, reader, roots)
	}, CTCollect: func(ctx context.Context, path string) (ctlog.Metrics, error) {
		return localruntime.CollectCT(ctx, configuration, path)
	}}))
}
