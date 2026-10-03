package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"io"
	"os"

	"cloudattrib/internal/inventory"
	"cloudattrib/internal/model"
)

const maxEmbeddingContractBytes = 16 << 10

func runInventoryEmbedding(ctx context.Context, args []string, dependencies Dependencies, streams commandStreams) int {
	if len(args) == 0 {
		return diagnostic(streams.stderr, model.NewError(model.CodeInvalidSyntax, "inventory embedding requires an operation", nil))
	}
	operation := args[0]
	if operation != "enable-vectors" && operation != "begin" && operation != "status" && operation != "activate" && operation != "rollback" && operation != "prune" {
		return diagnostic(streams.stderr, model.NewError(model.CodeInvalidSyntax, "unknown inventory embedding operation", nil))
	}
	flags := flag.NewFlagSet("inventory embedding "+operation, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	contractPath := flags.String("contract", "", "")
	generationID := flags.String("generation", "", "")
	if err := flags.Parse(args[1:]); err != nil || flags.NArg() != 0 ||
		(operation == "begin" && (*contractPath == "" || *generationID != "")) ||
		(operation == "enable-vectors" && (*contractPath != "" || *generationID != "")) ||
		(operation != "begin" && operation != "enable-vectors" && (*generationID == "" || *contractPath != "")) {
		return diagnostic(streams.stderr, model.NewError(model.CodeInvalidSyntax, "invalid inventory embedding flags", err))
	}
	switch operation {
	case "enable-vectors":
		if dependencies.InventoryVectorsEnable == nil {
			return diagnostic(streams.stderr, model.NewError(model.CodeCapabilityUnavailable, "inventory vector setup is unavailable", nil))
		}
		if err := dependencies.InventoryVectorsEnable(ctx); err != nil {
			return diagnostic(streams.stderr, err)
		}
		return writeCommandJSON(streams, map[string]bool{"vectors_enabled": true})
	case "begin":
		if dependencies.InventoryEmbeddingBegin == nil {
			return diagnostic(streams.stderr, model.NewError(model.CodeCapabilityUnavailable, "inventory embedding setup is unavailable", nil))
		}
		file, err := os.Open(*contractPath)
		if err != nil {
			return diagnostic(streams.stderr, model.NewError(model.CodeInvalidOptions, "read embedding contract", err))
		}
		content, err := io.ReadAll(io.LimitReader(file, maxEmbeddingContractBytes+1))
		closeErr := file.Close()
		if err == nil {
			err = closeErr
		}
		if err != nil {
			return diagnostic(streams.stderr, model.NewError(model.CodeInvalidOptions, "read embedding contract", err))
		}
		if len(content) == 0 || len(content) > maxEmbeddingContractBytes {
			return diagnostic(streams.stderr, model.NewError(model.CodeInvalidOptions, "embedding contract must be between 1 and 16384 bytes", nil))
		}
		var generation inventory.EmbeddingGeneration
		decoder := json.NewDecoder(bytes.NewReader(content))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&generation); err != nil {
			return diagnostic(streams.stderr, model.NewError(model.CodeInvalidOptions, "decode embedding contract", err))
		}
		var extra any
		if err := decoder.Decode(&extra); err != io.EOF {
			return diagnostic(streams.stderr, model.NewError(model.CodeInvalidOptions, "embedding contract must contain one JSON object", err))
		}
		if err := inventory.ValidateEmbeddingGeneration(generation); err != nil {
			return diagnostic(streams.stderr, err)
		}
		queued, err := dependencies.InventoryEmbeddingBegin(ctx, generation)
		if err != nil {
			return diagnostic(streams.stderr, err)
		}
		return writeCommandJSON(streams, struct {
			GenerationID string `json:"generation_id"`
			Queued       int64  `json:"queued"`
		}{generation.ID, queued})
	case "prune":
		if dependencies.InventoryEmbeddingPrune == nil {
			return diagnostic(streams.stderr, model.NewError(model.CodeCapabilityUnavailable, "inventory embedding pruning is unavailable", nil))
		}
		if err := dependencies.InventoryEmbeddingPrune(ctx, *generationID); err != nil {
			return diagnostic(streams.stderr, err)
		}
		return writeCommandJSON(streams, map[string]string{"pruned_generation_id": *generationID})
	default:
		var operationFunc func(context.Context, string) (inventory.EmbeddingCoverage, error)
		switch operation {
		case "status":
			operationFunc = dependencies.InventoryEmbeddingStatus
		case "activate":
			operationFunc = dependencies.InventoryEmbeddingActivate
		case "rollback":
			operationFunc = dependencies.InventoryEmbeddingRollback
		}
		if operationFunc == nil {
			return diagnostic(streams.stderr, model.NewError(model.CodeCapabilityUnavailable, "inventory embedding operation is unavailable", nil))
		}
		coverage, err := operationFunc(ctx, *generationID)
		if err != nil {
			return diagnostic(streams.stderr, err)
		}
		return writeCommandJSON(streams, coverage)
	}
}
