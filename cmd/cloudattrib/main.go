package main

import (
	"context"
	"os"

	"cloudattrib/internal/cli"
)

func main() {
	os.Exit(cli.Run(context.Background(), os.Args[1:], cli.Dependencies{}))
}
