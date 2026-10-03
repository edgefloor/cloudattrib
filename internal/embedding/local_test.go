package embedding

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"cloudattrib/internal/inventory"
	"cloudattrib/internal/model"
)

func TestPrivateLocalWorkerContractAndInference(t *testing.T) {
	directory, err := os.MkdirTemp("/tmp", "cloudattrib-embedding-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	generation := inventory.EmbeddingGeneration{ID: "model-1", ModelID: "fixture", ModelRevision: "revision",
		ArtifactSHA256: strings.Repeat("a", 64), License: "MIT", Dimensions: 3,
		DocumentFormatVersion: inventory.DescriptionFormatVersion, Preprocessing: "fixture", Metric: "cosine"}
	path := filepath.Join(directory, generation.ID+".sock")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	received := make(chan string, 1)
	server := &http.Server{Handler: http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/health":
			_ = json.NewEncoder(writer).Encode(generation)
		case "/embed":
			var input struct {
				Text string `json:"text"`
			}
			if err := json.NewDecoder(request.Body).Decode(&input); err != nil {
				t.Errorf("decode worker request: %v", err)
			}
			received <- input.Text
			_ = json.NewEncoder(writer).Encode(map[string]any{"vector": []float32{1, 0, 0}})
		default:
			http.NotFound(writer, request)
		}
	})}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { _ = server.Close() })
	provider, err := NewProvider(directory)
	if err != nil {
		t.Fatal(err)
	}
	worker, err := provider.ForGeneration(t.Context(), generation)
	if err != nil {
		t.Fatal(err)
	}
	vector, err := worker.Embed(t.Context(), "customer login")
	if err != nil || len(vector) != 3 || vector[0] != 1 || <-received != "customer login" {
		t.Fatalf("local vector=%v error=%v", vector, err)
	}
	wrong := generation
	wrong.ArtifactSHA256 = strings.Repeat("b", 64)
	if _, err := provider.ForGeneration(context.Background(), wrong); model.ErrorCodeOf(err) != model.CodeCapabilityUnavailable {
		t.Fatalf("mismatched local contract: %v", err)
	}
}

func TestLocalWorkerRejectsUnsafeSocketDirectory(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := NewProvider(directory); model.ErrorCodeOf(err) != model.CodeInvalidOptions {
		t.Fatalf("shared socket directory: %v", err)
	}
}

func TestLocalWorkerRealModel(t *testing.T) {
	contractPath := os.Getenv("CLOUDATTRIB_EMBEDDING_TEST_CONTRACT")
	directory := os.Getenv("CLOUDATTRIB_EMBEDDING_TEST_SOCKET_DIR")
	if contractPath == "" || directory == "" {
		t.Skip("local model worker test configuration is not set")
	}
	encoded, err := os.ReadFile(contractPath)
	if err != nil {
		t.Fatal(err)
	}
	var generation inventory.EmbeddingGeneration
	if err := json.Unmarshal(encoded, &generation); err != nil {
		t.Fatal(err)
	}
	provider, err := NewProvider(directory)
	if err != nil {
		t.Fatal(err)
	}
	worker, err := provider.ForGeneration(t.Context(), generation)
	if err != nil {
		t.Fatal(err)
	}
	vector, err := worker.Embed(t.Context(), "hostname portal.example.com technology grafana")
	if err != nil {
		t.Fatal(err)
	}
	if err := inventory.ValidateEmbedding(vector, generation.Dimensions); err != nil {
		t.Fatal(err)
	}
}
