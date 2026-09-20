package ctlog

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	ct "github.com/google/certificate-transparency-go"
	cttls "github.com/google/certificate-transparency-go/tls"
	"github.com/transparency-dev/merkle/rfc6962"
)

func TestCollectorVerifiesExactEntryAndPublishesVerifiedCheckpoint(t *testing.T) {
	t.Parallel()

	entry := certificateLeaf(t, []string{"api.example.com"})
	root := rfc6962.DefaultHasher.HashLeaf(entry.LeafInput)
	client := &fixtureLogClient{sth: signedTreeHead(root), entries: []ct.LeafEntry{entry}, proofEntry: entry}
	store := NewMemoryStore()
	collector := newFixtureCollector(t, client, store)

	metrics, err := collector.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}
	if metrics.EntriesFetched != 1 || metrics.RecordsRetained != 1 {
		t.Fatalf("Collect() metrics = %#v", metrics)
	}
	checkpoint, err := store.LoadCheckpoint(context.Background(), "fixture-log")
	if err != nil {
		t.Fatalf("LoadCheckpoint() error = %v", err)
	}
	if checkpoint.NextIndex != 1 || checkpoint.VerifiedTreeSize != 1 {
		t.Fatalf("checkpoint = %#v", checkpoint)
	}
	result, err := store.Discover(context.Background(), "example.com", 20)
	if err != nil {
		t.Fatalf("Discover() error = %v", err)
	}
	if len(result.Candidates) != 1 || result.Candidates[0].Provenance != ProvenanceVerifiedLog || result.Partial {
		t.Fatalf("Discover() = %#v", result)
	}
}

func TestCollectorRejectsAlteredProofEntryWithoutAdvancingVerifiedCheckpoint(t *testing.T) {
	t.Parallel()

	entry := certificateLeaf(t, []string{"api.example.com"})
	root := rfc6962.DefaultHasher.HashLeaf(entry.LeafInput)
	altered := entry
	altered.LeafInput = append([]byte(nil), entry.LeafInput...)
	altered.LeafInput[len(altered.LeafInput)-1] ^= 0xff
	client := &fixtureLogClient{sth: signedTreeHead(root), entries: []ct.LeafEntry{entry}, proofEntry: altered}
	store := NewMemoryStore()
	collector := newFixtureCollector(t, client, store)

	if _, err := collector.Collect(context.Background()); err != nil {
		t.Fatalf("Collect() error = %v", err)
	}
	checkpoint, err := store.LoadCheckpoint(context.Background(), "fixture-log")
	if err != nil {
		t.Fatalf("LoadCheckpoint() error = %v", err)
	}
	if checkpoint.NextIndex != 1 || checkpoint.VerifiedTreeSize != 0 {
		t.Fatalf("checkpoint = %#v", checkpoint)
	}
	result, err := store.Discover(context.Background(), "example.com", 20)
	if err != nil {
		t.Fatalf("Discover() error = %v", err)
	}
	if len(result.Candidates) != 1 || result.Candidates[0].Provenance != ProvenanceLogUnverified || !result.Partial {
		t.Fatalf("Discover() = %#v", result)
	}
	if result.Candidates[0].Verification.EntryInclusion.Status != "failed" {
		t.Fatalf("entry inclusion = %#v", result.Candidates[0].Verification.EntryInclusion)
	}
}

func TestCollectorRecordsProofBudgetAsNotPerformed(t *testing.T) {
	t.Parallel()

	entry := certificateLeaf(t, []string{"api.example.com"})
	root := rfc6962.DefaultHasher.HashLeaf(entry.LeafInput)
	client := &fixtureLogClient{sth: signedTreeHead(root), entries: []ct.LeafEntry{entry}}
	store := NewMemoryStore()
	config := fixtureCollectorConfig()
	config.Budget.MaximumProofs = 0
	collector, err := NewCollector(config, client, store)
	if err != nil {
		t.Fatalf("NewCollector() error = %v", err)
	}
	if _, err := collector.Collect(context.Background()); err != nil {
		t.Fatalf("Collect() error = %v", err)
	}
	result, err := store.Discover(context.Background(), "example.com", 20)
	if err != nil {
		t.Fatalf("Discover() error = %v", err)
	}
	if result.Candidates[0].Verification.EntryInclusion.Status != "not_performed" || result.Candidates[0].Provenance != ProvenanceLogUnverified {
		t.Fatalf("candidate = %#v", result.Candidates[0])
	}
	checkpoint, err := store.LoadCheckpoint(context.Background(), "fixture-log")
	if err != nil || checkpoint.VerifiedTreeSize != 0 {
		t.Fatalf("checkpoint = %#v, %v", checkpoint, err)
	}
}

func TestCollectorDoesNotAdvancePastInvalidCertificate(t *testing.T) {
	t.Parallel()

	leaf := ct.CreateX509MerkleTreeLeaf(ct.ASN1Cert{Data: []byte("not a certificate")}, uint64(time.Now().UnixMilli()))
	leafInput, err := cttls.Marshal(*leaf)
	if err != nil {
		t.Fatalf("marshal leaf: %v", err)
	}
	extraData, err := cttls.Marshal(ct.CertificateChain{})
	if err != nil {
		t.Fatalf("marshal chain: %v", err)
	}
	entry := ct.LeafEntry{LeafInput: leafInput, ExtraData: extraData}
	root := rfc6962.DefaultHasher.HashLeaf(entry.LeafInput)
	client := &fixtureLogClient{sth: signedTreeHead(root), entries: []ct.LeafEntry{entry}, proofEntry: entry}
	store := NewMemoryStore()
	collector := newFixtureCollector(t, client, store)
	if _, err := collector.Collect(context.Background()); err == nil {
		t.Fatal("Collect() error = nil, want invalid certificate")
	}
	checkpoint, err := store.LoadCheckpoint(context.Background(), "fixture-log")
	if err != nil || checkpoint.LogID != "" {
		t.Fatalf("checkpoint advanced after invalid certificate: %#v, %v", checkpoint, err)
	}
}

func TestCollectorKeepsPreviousVerifiedCheckpointWhenContinuityFails(t *testing.T) {
	t.Parallel()

	entry := certificateLeaf(t, []string{"api.example.com"})
	root := rfc6962.DefaultHasher.HashLeaf(entry.LeafInput)
	client := &fixtureLogClient{sth: signedTreeHead(root), entries: []ct.LeafEntry{entry}, proofEntry: entry}
	store := NewMemoryStore()
	previousRoot := make([]byte, 32)
	previousRoot[0] = 1
	if err := store.CommitCollection(context.Background(), nil, Checkpoint{
		LogID: "fixture-log", VerifiedTreeSize: 1, VerifiedRootHash: previousRoot, KeyIdentity: "sha256:key",
	}); err != nil {
		t.Fatalf("seed checkpoint: %v", err)
	}
	collector := newFixtureCollector(t, client, store)
	if _, err := collector.Collect(context.Background()); err != nil {
		t.Fatalf("Collect() error = %v", err)
	}
	checkpoint, err := store.LoadCheckpoint(context.Background(), "fixture-log")
	if err != nil {
		t.Fatalf("LoadCheckpoint() error = %v", err)
	}
	if checkpoint.VerifiedTreeSize != 1 || checkpoint.VerifiedRootHash[0] != 1 {
		t.Fatalf("verified checkpoint advanced after failed continuity: %#v", checkpoint)
	}
	result, err := store.Discover(context.Background(), "example.com", 20)
	if err != nil {
		t.Fatalf("Discover() error = %v", err)
	}
	if result.Candidates[0].Verification.Continuity.Status != "failed" || result.Candidates[0].Provenance != ProvenanceLogUnverified {
		t.Fatalf("candidate = %#v", result.Candidates[0])
	}
}

func TestCollectorResumesFromDurableIngestionCheckpoint(t *testing.T) {
	t.Parallel()

	entries := []ct.LeafEntry{
		certificateLeaf(t, []string{"one.example.com"}),
		certificateLeaf(t, []string{"two.example.com"}),
	}
	hashes := [][]byte{rfc6962.DefaultHasher.HashLeaf(entries[0].LeafInput), rfc6962.DefaultHasher.HashLeaf(entries[1].LeafInput)}
	root := merkleRoot(hashes)
	client := &fixtureLogClient{
		sth: signedTreeHeadSize(root, 2), entries: entries,
		auditPaths: [][][]byte{auditPath(hashes, 0), auditPath(hashes, 1)},
	}
	store := NewMemoryStore()
	collector := newFixtureCollector(t, client, store)
	if _, err := collector.Collect(context.Background()); err != nil {
		t.Fatalf("first Collect() error = %v", err)
	}
	checkpoint, err := store.LoadCheckpoint(context.Background(), "fixture-log")
	if err != nil || checkpoint.NextIndex != 1 {
		t.Fatalf("first checkpoint = %#v, %v", checkpoint, err)
	}
	collector = newFixtureCollector(t, client, store)
	if _, err := collector.Collect(context.Background()); err != nil {
		t.Fatalf("second Collect() error = %v", err)
	}
	checkpoint, err = store.LoadCheckpoint(context.Background(), "fixture-log")
	if err != nil || checkpoint.NextIndex != 2 || checkpoint.VerifiedTreeSize != 2 {
		t.Fatalf("resumed checkpoint = %#v, %v", checkpoint, err)
	}
}

func TestNewCollectorRejectsUnsupportedProtocol(t *testing.T) {
	t.Parallel()

	config := fixtureCollectorConfig()
	config.Protocol = "static-ct-api"
	if _, err := NewCollector(config, &fixtureLogClient{}, NewMemoryStore()); err == nil {
		t.Fatal("NewCollector() error = nil, want unsupported protocol")
	}
}

func BenchmarkCollectorShippingBudget(b *testing.B) {
	entries := make([]ct.LeafEntry, 256)
	hashes := make([][]byte, len(entries))
	for index := range entries {
		entries[index] = certificateLeaf(b, []string{"api.example.com"})
		hashes[index] = rfc6962.DefaultHasher.HashLeaf(entries[index].LeafInput)
	}
	root := merkleRoot(hashes)
	paths := make([][][]byte, len(entries))
	for index := range entries {
		paths[index] = auditPath(hashes, index)
	}
	client := &fixtureLogClient{sth: signedTreeHeadSize(root, uint64(len(entries))), entries: entries, auditPaths: paths}
	config := CollectorConfig{
		Protocol: "rfc6962", LogID: "fixture-log", SourceID: "fixture-source", KeyIdentity: "sha256:key", Roots: []string{"example.com"},
		Budget: DefaultBudget(), Now: func() time.Time { return time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC) },
	}
	b.ResetTimer()
	for range b.N {
		collector, err := NewCollector(config, client, NewMemoryStore())
		if err != nil {
			b.Fatalf("NewCollector() error = %v", err)
		}
		metrics, err := collector.Collect(context.Background())
		if err != nil {
			b.Fatalf("Collect() error = %v", err)
		}
		b.ReportMetric(float64(metrics.DownloadedBytes), "downloaded-B/run")
		b.ReportMetric(float64(metrics.RetainedBytes), "retained-B/run")
		b.ReportMetric(float64(metrics.Requests), "requests/run")
	}
}

func newFixtureCollector(t *testing.T, client LogClient, store Store) *Collector {
	t.Helper()
	collector, err := NewCollector(fixtureCollectorConfig(), client, store)
	if err != nil {
		t.Fatalf("NewCollector() error = %v", err)
	}
	return collector
}

func fixtureCollectorConfig() CollectorConfig {
	return CollectorConfig{
		Protocol: "rfc6962", LogID: "fixture-log", SourceID: "fixture-source", KeyIdentity: "sha256:key", Roots: []string{"example.com"},
		Budget: Budget{MaximumEntries: 1, BatchSize: 1, MaximumProofs: 1, MaximumRequests: 4, MaximumBytes: 1 << 20, MaximumElapsed: time.Second},
		Now:    func() time.Time { return time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC) },
	}
}

func certificateLeaf(t testing.TB, names []string) ct.LeafEntry {
	t.Helper()
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: names[0]}, DNSNames: names,
		NotBefore: time.Date(2026, 9, 19, 0, 0, 0, 0, time.UTC), NotAfter: time.Date(2026, 10, 19, 0, 0, 0, 0, time.UTC),
		KeyUsage: x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, privateKey.Public(), privateKey)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	leaf := ct.CreateX509MerkleTreeLeaf(ct.ASN1Cert{Data: der}, uint64(time.Date(2026, 9, 20, 10, 0, 0, 0, time.UTC).UnixMilli()))
	leafInput, err := cttls.Marshal(*leaf)
	if err != nil {
		t.Fatalf("marshal leaf: %v", err)
	}
	extraData, err := cttls.Marshal(ct.CertificateChain{})
	if err != nil {
		t.Fatalf("marshal chain: %v", err)
	}
	return ct.LeafEntry{LeafInput: leafInput, ExtraData: extraData}
}

func signedTreeHead(root []byte) *ct.SignedTreeHead {
	return signedTreeHeadSize(root, 1)
}

func signedTreeHeadSize(root []byte, size uint64) *ct.SignedTreeHead {
	sth := &ct.SignedTreeHead{TreeSize: size, Timestamp: uint64(time.Date(2026, 9, 20, 11, 0, 0, 0, time.UTC).UnixMilli())}
	copy(sth.SHA256RootHash[:], root)
	return sth
}

type fixtureLogClient struct {
	sth        *ct.SignedTreeHead
	entries    []ct.LeafEntry
	proofEntry ct.LeafEntry
	auditPaths [][][]byte
}

func (c *fixtureLogClient) GetSTH(context.Context) (*ct.SignedTreeHead, error) {
	return c.sth, nil
}

func (c *fixtureLogClient) GetRawEntries(_ context.Context, start, end int64) (*ct.GetEntriesResponse, error) {
	return &ct.GetEntriesResponse{Entries: c.entries[start : end+1]}, nil
}

func (c *fixtureLogClient) GetSTHConsistency(context.Context, uint64, uint64) ([][]byte, error) {
	return nil, nil
}

func (c *fixtureLogClient) GetEntryAndProof(_ context.Context, index, _ uint64) (*ct.GetEntryAndProofResponse, error) {
	entry := c.proofEntry
	var path [][]byte
	if len(c.auditPaths) > 0 {
		entry = c.entries[index]
		path = c.auditPaths[index]
	}
	return &ct.GetEntryAndProofResponse{LeafInput: entry.LeafInput, ExtraData: entry.ExtraData, AuditPath: path}, nil
}

func merkleRoot(hashes [][]byte) []byte {
	if len(hashes) == 1 {
		return hashes[0]
	}
	split := largestPowerOfTwoLessThan(len(hashes))
	return rfc6962.DefaultHasher.HashChildren(merkleRoot(hashes[:split]), merkleRoot(hashes[split:]))
}

func auditPath(hashes [][]byte, index int) [][]byte {
	if len(hashes) == 1 {
		return nil
	}
	split := largestPowerOfTwoLessThan(len(hashes))
	if index < split {
		return append(auditPath(hashes[:split], index), merkleRoot(hashes[split:]))
	}
	return append(auditPath(hashes[split:], index-split), merkleRoot(hashes[:split]))
}

func largestPowerOfTwoLessThan(value int) int {
	result := 1
	for result<<1 < value {
		result <<= 1
	}
	return result
}

var _ LogClient = (*fixtureLogClient)(nil)
