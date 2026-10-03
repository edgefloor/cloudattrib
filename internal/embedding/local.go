// Package embedding connects to explicitly provisioned local model workers.
package embedding

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"cloudattrib/internal/inventory"
	"cloudattrib/internal/model"
)

const maximumWorkerResponseBytes = 64 << 10

// Provider resolves one private Unix socket per immutable model generation.
type Provider struct {
	directory string
}

// NewProvider checks that the local worker directory is private and owned by
// this process's user. It neither starts a worker nor downloads model files.
func NewProvider(directory string) (*Provider, error) {
	if !filepath.IsAbs(directory) {
		return nil, model.NewError(model.CodeInvalidOptions, "embedding socket directory must be absolute", nil)
	}
	info, err := os.Lstat(directory)
	if err != nil {
		return nil, model.NewError(model.CodeCapabilityUnavailable, "embedding socket directory is unavailable", err)
	}
	if !info.IsDir() || info.Mode().Perm()&0o077 != 0 || !ownedByCurrentUser(info) {
		return nil, model.NewError(model.CodeInvalidOptions, "embedding socket directory must be private and owned by the current user", nil)
	}
	return &Provider{directory: directory}, nil
}

func ownedByCurrentUser(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == uint32(os.Geteuid())
}

// ForGeneration verifies the local worker's contract before it can see text.
func (provider *Provider) ForGeneration(ctx context.Context, generation inventory.EmbeddingGeneration) (inventory.Embedder, error) {
	if provider == nil || !inventory.SafeGenerationID(generation.ID) {
		return nil, model.NewError(model.CodeInvalidOptions, "invalid local embedding generation", nil)
	}
	path := filepath.Join(provider.directory, generation.ID+".sock")
	info, err := os.Lstat(path)
	if err != nil {
		return nil, model.NewError(model.CodeCapabilityUnavailable, "local embedding worker is unavailable", err)
	}
	if info.Mode()&os.ModeSocket == 0 || info.Mode().Perm()&0o077 != 0 || !ownedByCurrentUser(info) {
		return nil, model.NewError(model.CodeCapabilityUnavailable, "local embedding socket is not private", nil)
	}
	transport := &http.Transport{DisableKeepAlives: true, MaxConnsPerHost: 1,
		ResponseHeaderTimeout: 5 * time.Second,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", path)
		}}
	worker := &worker{client: &http.Client{Transport: transport}, generation: generation}
	var health inventory.EmbeddingGeneration
	if err := worker.call(ctx, http.MethodGet, "/health", nil, &health); err != nil {
		return nil, err
	}
	if health != generation {
		return nil, model.NewError(model.CodeCapabilityUnavailable, "local model contract does not match active generation", nil)
	}
	return worker, nil
}

type worker struct {
	client     *http.Client
	generation inventory.EmbeddingGeneration
}

func (w *worker) Embed(ctx context.Context, text string) ([]float32, error) {
	if len(text) == 0 || len(text) > 8192 {
		return nil, model.NewError(model.CodeInvalidOptions, "embedding input exceeds the local worker limit", nil)
	}
	var result struct {
		Vector []float32 `json:"vector"`
	}
	if err := w.call(ctx, http.MethodPost, "/embed", struct {
		Text string `json:"text"`
	}{Text: text}, &result); err != nil {
		return nil, err
	}
	if err := inventory.ValidateEmbedding(result.Vector, w.generation.Dimensions); err != nil {
		return nil, err
	}
	return result.Vector, nil
}

func (w *worker) call(ctx context.Context, method, route string, input, output any) error {
	var body io.Reader
	if input != nil {
		encoded, err := json.Marshal(input)
		if err != nil {
			return err
		}
		body = bytes.NewReader(encoded)
	}
	request, err := http.NewRequestWithContext(ctx, method, "http://local-embedding"+route, body)
	if err != nil {
		return err
	}
	if input != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := w.client.Do(request)
	if err != nil {
		return model.NewError(model.CodeCapabilityUnavailable, "local embedding worker request failed", err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		return model.NewError(model.CodeCapabilityUnavailable,
			fmt.Sprintf("local embedding worker returned status %d", response.StatusCode), nil)
	}
	encoded, err := io.ReadAll(io.LimitReader(response.Body, maximumWorkerResponseBytes+1))
	if err != nil || len(encoded) > maximumWorkerResponseBytes {
		return model.NewError(model.CodeCapabilityUnavailable, "local embedding worker response is too large", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(output); err != nil {
		return model.NewError(model.CodeCapabilityUnavailable, "local embedding worker returned invalid JSON", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return model.NewError(model.CodeCapabilityUnavailable, "local embedding worker returned extra data", err)
	}
	return nil
}
