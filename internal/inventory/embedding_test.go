package inventory

import (
	"math"
	"strings"
	"testing"

	"cloudattrib/internal/model"
)

func TestValidateEmbeddingGeneration(t *testing.T) {
	t.Parallel()
	valid := EmbeddingGeneration{ID: "model-1", ModelID: "local-model", ModelRevision: "revision-1",
		ArtifactSHA256: strings.Repeat("a", 64), License: "MIT", Dimensions: 384,
		DocumentFormatVersion: DescriptionFormatVersion, Preprocessing: "normalize-v1", Metric: "cosine"}
	if err := ValidateEmbeddingGeneration(valid); err != nil {
		t.Fatal(err)
	}
	invalid := valid
	invalid.ArtifactSHA256 = "unknown"
	if err := ValidateEmbeddingGeneration(invalid); model.ErrorCodeOf(err) != model.CodeInvalidOptions {
		t.Fatalf("invalid digest: %v", err)
	}
	invalid = valid
	invalid.DocumentFormatVersion = "1"
	if err := ValidateEmbeddingGeneration(invalid); model.ErrorCodeOf(err) != model.CodeInvalidOptions {
		t.Fatalf("stale description format: %v", err)
	}
}

func TestValidateEmbedding(t *testing.T) {
	t.Parallel()
	if err := ValidateEmbedding([]float32{1, 0, 0}, 3); err != nil {
		t.Fatal(err)
	}
	for _, vector := range [][]float32{{1, 0}, {0, 0, 0}, {1, float32(math.NaN()), 0}, {1, float32(math.Inf(1)), 0}} {
		if err := ValidateEmbedding(vector, 3); model.ErrorCodeOf(err) != model.CodeInvalidOptions {
			t.Fatalf("vector %v: %v", vector, err)
		}
	}
}
