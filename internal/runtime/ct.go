package runtime

import (
	"context"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync"
	"time"

	"cloudattrib/internal/config"
	"cloudattrib/internal/ctlog"
	"cloudattrib/internal/model"
	"cloudattrib/internal/store/postgres"
	"go.yaml.in/yaml/v3"
)

const maximumCTConfigBytes = 1 << 20

type ctCollectorFile struct {
	Protocol      string   `json:"protocol" yaml:"protocol"`
	LogID         string   `json:"log_id" yaml:"log_id"`
	URL           string   `json:"url" yaml:"url"`
	PublicKeyFile string   `json:"public_key_file" yaml:"public_key_file"`
	SourceID      string   `json:"source_id" yaml:"source_id"`
	Roots         []string `json:"roots" yaml:"roots"`
	StartIndex    *uint64  `json:"start_index,omitempty" yaml:"start_index,omitempty"`
	Checkpoint    *struct {
		NextIndex     uint64 `json:"next_index" yaml:"next_index"`
		TreeSize      uint64 `json:"tree_size" yaml:"tree_size"`
		RootHash      string `json:"root_hash" yaml:"root_hash"`
		TreeTimestamp string `json:"tree_timestamp" yaml:"tree_timestamp"`
	} `json:"trusted_checkpoint,omitempty" yaml:"trusted_checkpoint,omitempty"`
	Budget struct {
		MaximumEntries  int   `json:"maximum_entries" yaml:"maximum_entries"`
		BatchSize       int   `json:"batch_size" yaml:"batch_size"`
		MaximumProofs   int   `json:"maximum_proofs" yaml:"maximum_proofs"`
		MaximumRequests int   `json:"maximum_requests" yaml:"maximum_requests"`
		MaximumBytes    int64 `json:"maximum_bytes" yaml:"maximum_bytes"`
		MaximumSeconds  int   `json:"maximum_seconds" yaml:"maximum_seconds"`
	} `json:"budget" yaml:"budget"`
}

// ImportCT imports operator-controlled JSONL into the durable local CT index.
func ImportCT(ctx context.Context, configuration config.Config, reader io.Reader, roots []string) (int, error) {
	store, err := openCTStore(ctx, configuration)
	if err != nil {
		return 0, err
	}
	defer store.Close()
	return ctlog.ImportJSONL(ctx, reader, roots, store)
}

// CollectCT runs one explicitly bounded collection against one configured RFC 6962 log.
func CollectCT(ctx context.Context, configuration config.Config, path string) (ctlog.Metrics, error) {
	supplied, err := loadCTCollectorFile(path)
	if err != nil {
		return ctlog.Metrics{}, err
	}
	if supplied.StartIndex == nil && supplied.Checkpoint == nil {
		return ctlog.Metrics{}, model.NewError(model.CodeInvalidOptions, "CT collector requires start_index or trusted_checkpoint", nil)
	}
	keyDER, err := readPublicKey(supplied.PublicKeyFile)
	if err != nil {
		return ctlog.Metrics{}, err
	}
	budget := ctlog.DefaultBudget()
	if supplied.Budget.MaximumEntries > 0 {
		budget.MaximumEntries = supplied.Budget.MaximumEntries
	}
	if supplied.Budget.BatchSize > 0 {
		budget.BatchSize = supplied.Budget.BatchSize
	}
	if supplied.Budget.MaximumProofs >= 0 && supplied.Budget.MaximumEntries > 0 {
		budget.MaximumProofs = supplied.Budget.MaximumProofs
	}
	if supplied.Budget.MaximumRequests > 0 {
		budget.MaximumRequests = supplied.Budget.MaximumRequests
	}
	if supplied.Budget.MaximumBytes > 0 {
		budget.MaximumBytes = supplied.Budget.MaximumBytes
	}
	if supplied.Budget.MaximumSeconds > 0 {
		budget.MaximumElapsed = time.Duration(supplied.Budget.MaximumSeconds) * time.Second
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	defer transport.CloseIdleConnections()
	wireBudget := newResponseBudgetTransport(transport, budget.MaximumBytes)
	client, keyIdentity, err := ctlog.NewRFC6962Client(supplied.URL, keyDER, &http.Client{Timeout: budget.MaximumElapsed, Transport: wireBudget})
	if err != nil {
		return ctlog.Metrics{}, err
	}
	if supplied.LogID != keyIdentity {
		return ctlog.Metrics{}, model.NewError(model.CodeInvalidOptions, "CT log_id must equal the SHA-256 identity of the pinned key", nil)
	}
	collectorConfig := ctlog.CollectorConfig{
		Protocol: supplied.Protocol, LogID: supplied.LogID, SourceID: supplied.SourceID, KeyIdentity: keyIdentity, Roots: supplied.Roots, Budget: budget,
	}
	if supplied.StartIndex != nil {
		collectorConfig.StartIndex = *supplied.StartIndex
	}
	if supplied.Checkpoint != nil {
		rootHash, decodeErr := hex.DecodeString(supplied.Checkpoint.RootHash)
		if decodeErr != nil || len(rootHash) != 32 {
			return ctlog.Metrics{}, model.NewError(model.CodeInvalidOptions, "trusted checkpoint root_hash must be 32-byte hex", decodeErr)
		}
		timestamp, parseErr := time.Parse(time.RFC3339, supplied.Checkpoint.TreeTimestamp)
		if parseErr != nil {
			return ctlog.Metrics{}, model.NewError(model.CodeInvalidOptions, "parse trusted checkpoint timestamp", parseErr)
		}
		collectorConfig.InitialCheckpoint = &ctlog.Checkpoint{
			LogID: supplied.LogID, NextIndex: supplied.Checkpoint.NextIndex, VerifiedTreeSize: supplied.Checkpoint.TreeSize,
			VerifiedRootHash: rootHash, TreeTimestamp: timestamp, KeyIdentity: keyIdentity,
		}
		collectorConfig.TrustInitialCheckpoint = true
	}
	store, err := openCTStore(ctx, configuration)
	if err != nil {
		return ctlog.Metrics{}, err
	}
	defer store.Close()
	collector, err := ctlog.NewCollector(collectorConfig, client, store)
	if err != nil {
		return ctlog.Metrics{}, model.NewError(model.CodeInvalidOptions, "create CT collector", err)
	}
	metrics, err := collector.Collect(ctx)
	metrics.DownloadedBytes = wireBudget.Consumed()
	if err != nil {
		return metrics, model.NewError(model.CodeCollectionFailed, "collect CT log", err)
	}
	return metrics, nil
}

func loadCTCollectorFile(path string) (ctCollectorFile, error) {
	file, err := os.Open(path)
	if err != nil {
		return ctCollectorFile{}, model.NewError(model.CodeInvalidSyntax, "open CT collector configuration", err)
	}
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maximumCTConfigBytes {
		return ctCollectorFile{}, model.NewError(model.CodeInvalidSyntax, "CT collector configuration must be a non-empty regular file no larger than 1 MiB", err)
	}
	decoder := yaml.NewDecoder(io.LimitReader(file, maximumCTConfigBytes+1))
	decoder.KnownFields(true)
	var supplied ctCollectorFile
	if err := decoder.Decode(&supplied); err != nil {
		return ctCollectorFile{}, model.NewError(model.CodeInvalidSyntax, "decode CT collector configuration", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return ctCollectorFile{}, model.NewError(model.CodeInvalidSyntax, "CT collector configuration contains trailing data", err)
	}
	return supplied, nil
}

type responseBudgetTransport struct {
	base      http.RoundTripper
	maximum   int64
	mu        sync.Mutex
	remaining int64
}

func newResponseBudgetTransport(base http.RoundTripper, maximum int64) *responseBudgetTransport {
	return &responseBudgetTransport{base: base, maximum: maximum, remaining: maximum}
}

func (t *responseBudgetTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	response, err := t.base.RoundTrip(request)
	if response != nil && response.Body != nil {
		response.Body = &responseBudgetBody{body: response.Body, budget: t}
	}
	return response, err
}

func (t *responseBudgetTransport) Consumed() int64 {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.maximum - t.remaining
}

type responseBudgetBody struct {
	body   io.ReadCloser
	budget *responseBudgetTransport
}

func (b *responseBudgetBody) Read(buffer []byte) (int, error) {
	b.budget.mu.Lock()
	remaining := b.budget.remaining
	b.budget.mu.Unlock()
	if remaining <= 0 {
		return 0, fmt.Errorf("CT response byte budget exceeded")
	}
	maximumRead := int64(len(buffer))
	if maximumRead > remaining+1 {
		maximumRead = remaining + 1
	}
	read, err := b.body.Read(buffer[:maximumRead])
	b.budget.mu.Lock()
	defer b.budget.mu.Unlock()
	if int64(read) > b.budget.remaining {
		allowed := int(b.budget.remaining)
		b.budget.remaining = 0
		return allowed, fmt.Errorf("CT response byte budget exceeded")
	}
	b.budget.remaining -= int64(read)
	return read, err
}

func (b *responseBudgetBody) Close() error { return b.body.Close() }

func openCTStore(ctx context.Context, configuration config.Config) (*postgres.Store, error) {
	dsn, err := readDSN(configuration.Storage.PostgresDSNFile)
	if err != nil {
		return nil, err
	}
	return postgres.Open(ctx, dsn, configuration.Limits.MaximumBacklogTargets)
}

func readPublicKey(path string) ([]byte, error) {
	if path == "" {
		return nil, model.NewError(model.CodeInvalidOptions, "CT public_key_file is required", nil)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, model.NewError(model.CodeInvalidOptions, "read CT public key", err)
	}
	if len(content) == 0 || len(content) > 64<<10 {
		return nil, model.NewError(model.CodeInvalidOptions, "CT public key file is empty or too large", nil)
	}
	if block, rest := pem.Decode(content); block != nil {
		if len(rest) != 0 || block.Type != "PUBLIC KEY" {
			return nil, model.NewError(model.CodeInvalidOptions, "CT public key PEM must contain one PUBLIC KEY block", nil)
		}
		return block.Bytes, nil
	}
	return content, nil
}
