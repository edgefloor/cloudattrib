package main

import (
	"context"
	"fmt"
	"os"

	"cloudattrib/internal/cli"
	"cloudattrib/internal/config"
	localruntime "cloudattrib/internal/runtime"
)

func main() {
	configuration := config.Default()
	if resolver := os.Getenv("CLOUDATTRIB_RESOLVER"); resolver != "" {
		configuration.Resolver.Address = resolver
	}
	analyzer, err := localruntime.NewLocal(configuration)
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(4)
	}
	os.Exit(cli.Run(context.Background(), os.Args[1:], cli.Dependencies{Analyzer: analyzer}))
}
