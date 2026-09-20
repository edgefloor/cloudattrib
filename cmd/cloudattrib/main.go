package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"cloudattrib/internal/cli"
	"cloudattrib/internal/config"
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
	analyzer, err := localruntime.NewLocal(configuration)
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(4)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	os.Exit(cli.Run(ctx, os.Args[1:], cli.Dependencies{Analyzer: analyzer, Serve: func(ctx context.Context) error {
		return localruntime.Serve(ctx, configuration)
	}}))
}
