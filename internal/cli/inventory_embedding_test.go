package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"cloudattrib/internal/inventory"
)

func TestInventoryEmbeddingCommands(t *testing.T) {
	var output, errors bytes.Buffer
	generation := inventory.EmbeddingGeneration{ID: "candidate-1", ModelID: "fixture", ModelRevision: "rev-1",
		ArtifactSHA256: strings.Repeat("a", 64), License: "MIT", Dimensions: 3,
		DocumentFormatVersion: inventory.DescriptionFormatVersion, Preprocessing: "fixture-v1", Metric: "cosine"}
	content, err := json.Marshal(generation)
	if err != nil {
		t.Fatal(err)
	}
	contract := filepath.Join(t.TempDir(), "generation.json")
	if err := os.WriteFile(contract, content, 0600); err != nil {
		t.Fatal(err)
	}
	var calls []string
	deps := Dependencies{Stdout: &output, Stderr: &errors,
		InventoryVectorsEnable: func(context.Context) error { calls = append(calls, "enable"); return nil },
		InventoryEmbeddingBegin: func(_ context.Context, got inventory.EmbeddingGeneration) (int64, error) {
			if got != generation {
				t.Fatalf("generation = %#v", got)
			}
			calls = append(calls, "begin")
			return 12, nil
		},
		InventoryEmbeddingStatus: func(_ context.Context, id string) (inventory.EmbeddingCoverage, error) {
			calls = append(calls, "status:"+id)
			return inventory.EmbeddingCoverage{GenerationID: id, Pending: 12}, nil
		},
		InventoryEmbeddingActivate: func(_ context.Context, id string) (inventory.EmbeddingCoverage, error) {
			calls = append(calls, "activate:"+id)
			return inventory.EmbeddingCoverage{GenerationID: id, Current: 12}, nil
		},
		InventoryEmbeddingRollback: func(_ context.Context, id string) (inventory.EmbeddingCoverage, error) {
			calls = append(calls, "rollback:"+id)
			return inventory.EmbeddingCoverage{GenerationID: id, Pending: 1}, nil
		},
		InventoryEmbeddingPrune: func(_ context.Context, id string) error {
			calls = append(calls, "prune:"+id)
			return nil
		},
	}
	for _, args := range [][]string{
		{"inventory", "embedding", "enable-vectors"},
		{"inventory", "embedding", "begin", "--contract", contract},
		{"inventory", "embedding", "status", "--generation", generation.ID},
		{"inventory", "embedding", "activate", "--generation", generation.ID},
		{"inventory", "embedding", "rollback", "--generation", generation.ID},
		{"inventory", "embedding", "prune", "--generation", generation.ID},
	} {
		output.Reset()
		errors.Reset()
		if exit := Run(t.Context(), args, deps); exit != 0 {
			t.Fatalf("%v: exit=%d stderr=%q", args, exit, errors.String())
		}
		if !json.Valid(output.Bytes()) {
			t.Fatalf("%v: invalid output %q", args, output.String())
		}
	}
	if strings.Join(calls, ",") != "enable,begin,status:candidate-1,activate:candidate-1,rollback:candidate-1,prune:candidate-1" {
		t.Fatalf("calls = %v", calls)
	}
	if err := os.WriteFile(contract, append(content, []byte(` {}`)...), 0600); err != nil {
		t.Fatal(err)
	}
	if exit := Run(t.Context(), []string{"inventory", "embedding", "begin", "--contract", contract}, deps); exit == 0 {
		t.Fatal("accepted multiple JSON values")
	}
}
