package ctlog

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"
	"time"

	ct "github.com/google/certificate-transparency-go"
	"github.com/transparency-dev/merkle/proof"
	"github.com/transparency-dev/merkle/rfc6962"

	"cloudattrib/internal/model"
)

const (
	verificationProcedure = "rfc6962-sha256"
	verificationVersion   = "1"
)

// LogClient is the bounded RFC 6962 read surface used by Collector.
// GetSTH must reject an invalid signature against the configured pinned key.
type LogClient interface {
	GetSTH(context.Context) (*ct.SignedTreeHead, error)
	GetRawEntries(context.Context, int64, int64) (*ct.GetEntriesResponse, error)
	GetSTHConsistency(context.Context, uint64, uint64) ([][]byte, error)
	GetEntryAndProof(context.Context, uint64, uint64) (*ct.GetEntryAndProofResponse, error)
}

// CollectorConfig binds a collector to one pinned RFC 6962 log and scope.
type CollectorConfig struct {
	Protocol          string
	LogID             string
	SourceID          string
	KeyIdentity       string
	Roots             []string
	StartIndex        uint64
	InitialCheckpoint *Checkpoint
	// TrustInitialCheckpoint permits an operator-supplied authenticated tree to seed continuity verification.
	TrustInitialCheckpoint bool
	Budget                 Budget
	Now                    func() time.Time
}

// Collector acquires and verifies a bounded range from one RFC 6962 log.
type Collector struct {
	config CollectorConfig
	client LogClient
	store  Store
}

// NewCollector validates and constructs a collector without network activity.
func NewCollector(config CollectorConfig, client LogClient, store Store) (*Collector, error) {
	if config.Protocol != "rfc6962" {
		return nil, fmt.Errorf("unsupported CT protocol %q", config.Protocol)
	}
	if config.LogID == "" || config.SourceID == "" || config.KeyIdentity == "" || len(config.Roots) == 0 || client == nil || store == nil {
		return nil, fmt.Errorf("CT log ID, source, pinned key identity, roots, client, and store are required")
	}
	if err := validateBudget(config.Budget); err != nil {
		return nil, err
	}
	config.Roots = slices.Clone(config.Roots)
	for index, root := range config.Roots {
		normalized, err := normalizeName(root)
		if err != nil {
			return nil, fmt.Errorf("normalize CT root: %w", err)
		}
		config.Roots[index] = normalized
	}
	slices.Sort(config.Roots)
	config.Roots = slices.Compact(config.Roots)
	if config.Now == nil {
		config.Now = time.Now
	}
	return &Collector{config: config, client: client, store: store}, nil
}

func validateBudget(budget Budget) error {
	if budget.MaximumEntries <= 0 || budget.BatchSize <= 0 || budget.BatchSize > budget.MaximumEntries || budget.MaximumProofs < 0 ||
		budget.MaximumRequests <= 0 || budget.MaximumBytes <= 0 || budget.MaximumElapsed <= 0 {
		return fmt.Errorf("CT collector budget must be positive and batch size must not exceed entry limit")
	}
	return nil
}

// Collect acquires one bounded range and atomically advances ingestion progress.
func (c *Collector) Collect(ctx context.Context) (Metrics, error) {
	startedAt := c.config.Now()
	ctx, cancel := context.WithTimeout(ctx, c.config.Budget.MaximumElapsed)
	defer cancel()

	checkpoint, err := c.store.LoadCheckpoint(ctx, c.config.LogID)
	if err != nil {
		return Metrics{}, fmt.Errorf("load CT checkpoint: %w", err)
	}
	if checkpoint.LogID == "" {
		checkpoint = Checkpoint{LogID: c.config.LogID, NextIndex: c.config.StartIndex, KeyIdentity: c.config.KeyIdentity}
		if c.config.InitialCheckpoint != nil {
			checkpoint = cloneCheckpoint(*c.config.InitialCheckpoint)
			checkpoint.LogID = c.config.LogID
			checkpoint.KeyIdentity = c.config.KeyIdentity
			if !c.config.TrustInitialCheckpoint {
				checkpoint.VerifiedTreeSize = 0
				checkpoint.VerifiedRootHash = nil
				checkpoint.TreeTimestamp = time.Time{}
				checkpoint.TreeIdentity = ""
			}
		}
	}
	if checkpoint.KeyIdentity != "" && checkpoint.KeyIdentity != c.config.KeyIdentity {
		return Metrics{}, fmt.Errorf("CT checkpoint key identity does not match configured pinned key")
	}

	run := collectionRun{collector: c, checkpoint: checkpoint, metrics: Metrics{}}
	sth, err := run.getSTH(ctx)
	if err != nil {
		return run.metrics, fmt.Errorf("get authenticated CT checkpoint: %w", err)
	}
	if sth.TreeSize < checkpoint.NextIndex {
		return run.metrics, fmt.Errorf("CT tree size %d precedes ingestion index %d", sth.TreeSize, checkpoint.NextIndex)
	}
	run.metrics.BacklogBefore = sth.TreeSize - checkpoint.NextIndex
	continuity := run.verifyContinuity(ctx, sth)

	end := checkpoint.NextIndex + uint64(c.config.Budget.MaximumEntries)
	if end > sth.TreeSize {
		end = sth.TreeSize
	}
	records := make([]Record, 0)
	allIncluded := true
	for start := checkpoint.NextIndex; start < end; {
		batchEnd := start + uint64(c.config.Budget.BatchSize)
		if batchEnd > end {
			batchEnd = end
		}
		entries, fetchErr := run.getEntries(ctx, start, batchEnd-1)
		if fetchErr != nil {
			return run.metrics, fetchErr
		}
		if len(entries) == 0 || len(entries) > int(batchEnd-start) {
			return run.metrics, fmt.Errorf("CT log returned %d entries for range %d-%d", len(entries), start, batchEnd-1)
		}
		for offset, entry := range entries {
			index := start + uint64(offset)
			inclusion, includeErr := run.verifyInclusion(ctx, index, sth, entry)
			if includeErr != nil {
				return run.metrics, includeErr
			}
			if inclusion.Status != model.CTCheckPassed {
				allIncluded = false
			}
			entryRecords, parseErr := c.recordsFromEntry(index, sth, entry, continuity, inclusion)
			if parseErr != nil {
				return run.metrics, fmt.Errorf("parse CT entry %d: %w", index, parseErr)
			}
			records = append(records, entryRecords...)
			run.metrics.EntriesFetched++
		}
		start += uint64(len(entries))
		if start < batchEnd {
			end = start
		}
	}

	checkpoint.NextIndex = end
	checkpoint.LogID = c.config.LogID
	checkpoint.KeyIdentity = c.config.KeyIdentity
	if (continuity.Status == model.CTCheckPassed || continuity.Status == model.CTCheckNotPerformed) && allIncluded {
		checkpoint.VerifiedTreeSize = sth.TreeSize
		checkpoint.VerifiedRootHash = slices.Clone(sth.SHA256RootHash[:])
		checkpoint.TreeTimestamp = ct.TimestampToTime(sth.Timestamp)
		checkpoint.TreeIdentity = treeIdentity(c.config.LogID, sth.TreeSize, sth.SHA256RootHash[:])
	}
	if err := c.store.CommitCollection(ctx, records, checkpoint); err != nil {
		return run.metrics, fmt.Errorf("commit CT collection: %w", err)
	}
	run.metrics.RecordsRetained = len(records)
	run.metrics.RetainedBytes = retainedBytes(records)
	run.metrics.BacklogAfter = sth.TreeSize - end
	run.metrics.Elapsed = c.config.Now().Sub(startedAt)
	run.metrics.IngestionLag = c.config.Now().Sub(ct.TimestampToTime(sth.Timestamp))
	if run.metrics.IngestionLag < 0 {
		run.metrics.IngestionLag = 0
	}
	return run.metrics, nil
}

type collectionRun struct {
	collector  *Collector
	checkpoint Checkpoint
	metrics    Metrics
	proofs     int
}

func (r *collectionRun) beforeRequest(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if r.metrics.Requests >= r.collector.config.Budget.MaximumRequests {
		return fmt.Errorf("CT request budget exhausted")
	}
	r.metrics.Requests++
	return nil
}

func (r *collectionRun) addBytes(count int64) error {
	r.metrics.DownloadedBytes += count
	if r.metrics.DownloadedBytes > r.collector.config.Budget.MaximumBytes {
		return fmt.Errorf("CT byte budget exceeded")
	}
	return nil
}

func (r *collectionRun) getSTH(ctx context.Context) (*ct.SignedTreeHead, error) {
	if err := r.beforeRequest(ctx); err != nil {
		return nil, err
	}
	sth, err := r.collector.client.GetSTH(ctx)
	if err != nil {
		return nil, err
	}
	if sth == nil {
		return nil, fmt.Errorf("CT log returned an empty checkpoint")
	}
	if err := r.addBytes(int64(len(sth.SHA256RootHash) + len(sth.TreeHeadSignature.Signature))); err != nil {
		return nil, err
	}
	return sth, nil
}

func (r *collectionRun) getEntries(ctx context.Context, start, end uint64) ([]ct.LeafEntry, error) {
	if err := r.beforeRequest(ctx); err != nil {
		return nil, err
	}
	response, err := r.collector.client.GetRawEntries(ctx, int64(start), int64(end))
	if err != nil {
		return nil, fmt.Errorf("fetch CT entries %d-%d: %w", start, end, err)
	}
	if response == nil {
		return nil, fmt.Errorf("CT log returned an empty entry response")
	}
	var size int64
	for _, entry := range response.Entries {
		size += int64(len(entry.LeafInput) + len(entry.ExtraData))
	}
	if err := r.addBytes(size); err != nil {
		return nil, err
	}
	return response.Entries, nil
}

func (r *collectionRun) verifyContinuity(ctx context.Context, sth *ct.SignedTreeHead) model.CTVerificationCheck {
	check := verificationCheck(model.CTCheckNotPerformed, r.checkpoint, sth, "initial authenticated checkpoint")
	if r.checkpoint.VerifiedTreeSize == 0 {
		return check
	}
	if sth.TreeSize < r.checkpoint.VerifiedTreeSize {
		return verificationCheck(model.CTCheckFailed, r.checkpoint, sth, "tree size regressed")
	}
	if sth.TreeSize == r.checkpoint.VerifiedTreeSize {
		if bytes.Equal(r.checkpoint.VerifiedRootHash, sth.SHA256RootHash[:]) {
			return verificationCheck(model.CTCheckPassed, r.checkpoint, sth, "")
		}
		return verificationCheck(model.CTCheckFailed, r.checkpoint, sth, "root changed at the same tree size")
	}
	if err := r.beforeRequest(ctx); err != nil {
		return verificationCheck(model.CTCheckFailed, r.checkpoint, sth, err.Error())
	}
	path, err := r.collector.client.GetSTHConsistency(ctx, r.checkpoint.VerifiedTreeSize, sth.TreeSize)
	if err != nil {
		return verificationCheck(model.CTCheckFailed, r.checkpoint, sth, err.Error())
	}
	var size int64
	for _, hash := range path {
		size += int64(len(hash))
	}
	if err := r.addBytes(size); err != nil {
		return verificationCheck(model.CTCheckFailed, r.checkpoint, sth, err.Error())
	}
	if err := proof.VerifyConsistency(rfc6962.DefaultHasher, r.checkpoint.VerifiedTreeSize, sth.TreeSize, path, r.checkpoint.VerifiedRootHash, sth.SHA256RootHash[:]); err != nil {
		return verificationCheck(model.CTCheckFailed, r.checkpoint, sth, err.Error())
	}
	return verificationCheck(model.CTCheckPassed, r.checkpoint, sth, "")
}

func (r *collectionRun) verifyInclusion(ctx context.Context, index uint64, sth *ct.SignedTreeHead, entry ct.LeafEntry) (model.CTVerificationCheck, error) {
	check := verificationCheck(model.CTCheckNotPerformed, r.checkpoint, sth, "proof budget exhausted")
	if r.proofs >= r.collector.config.Budget.MaximumProofs {
		return check, nil
	}
	if err := r.beforeRequest(ctx); err != nil {
		return check, err
	}
	r.proofs++
	response, err := r.collector.client.GetEntryAndProof(ctx, index, sth.TreeSize)
	if err != nil {
		return check, fmt.Errorf("fetch CT inclusion proof for entry %d: %w", index, err)
	}
	if response == nil {
		return check, fmt.Errorf("CT log returned an empty proof for entry %d", index)
	}
	size := int64(len(response.LeafInput) + len(response.ExtraData))
	for _, hash := range response.AuditPath {
		size += int64(len(hash))
	}
	if err := r.addBytes(size); err != nil {
		return check, err
	}
	if !bytes.Equal(response.LeafInput, entry.LeafInput) {
		return verificationCheck(model.CTCheckFailed, r.checkpoint, sth, "proof entry bytes differ from fetched entry"), nil
	}
	leafHash := rfc6962.DefaultHasher.HashLeaf(entry.LeafInput)
	if err := proof.VerifyInclusion(rfc6962.DefaultHasher, index, sth.TreeSize, leafHash, response.AuditPath, sth.SHA256RootHash[:]); err != nil {
		return verificationCheck(model.CTCheckFailed, r.checkpoint, sth, err.Error()), nil
	}
	return verificationCheck(model.CTCheckPassed, r.checkpoint, sth, ""), nil
}

func verificationCheck(status model.CTCheckStatus, checkpoint Checkpoint, sth *ct.SignedTreeHead, reason string) model.CTVerificationCheck {
	return model.CTVerificationCheck{
		Status: status, Procedure: verificationProcedure, ProcedureVersion: verificationVersion,
		TreeIdentity: treeIdentity(checkpoint.LogID, sth.TreeSize, sth.SHA256RootHash[:]), KeyIdentity: checkpoint.KeyIdentity, Reason: reason,
	}
}

func (c *Collector) recordsFromEntry(index uint64, sth *ct.SignedTreeHead, leaf ct.LeafEntry, continuity, inclusion model.CTVerificationCheck) ([]Record, error) {
	entry, err := ct.LogEntryFromLeaf(int64(index), &leaf)
	if err != nil {
		return nil, err
	}
	certificate := entry.X509Cert
	certificateBytes := []byte(nil)
	if certificate != nil {
		certificateBytes = certificate.Raw
	} else if entry.Precert != nil && entry.Precert.TBSCertificate != nil {
		certificate = entry.Precert.TBSCertificate
		certificateBytes = entry.Precert.Submitted.Data
	}
	if certificate == nil || len(certificateBytes) == 0 {
		return nil, fmt.Errorf("entry contains no supported certificate")
	}
	names := slices.Clone(certificate.DNSNames)
	if certificate.Subject.CommonName != "" {
		names = append(names, certificate.Subject.CommonName)
	}
	certificateHash := sha256.Sum256(certificateBytes)
	loggedAt := ct.TimestampToTime(entry.Leaf.TimestampedEntry.Timestamp)
	notBefore, notAfter := certificate.NotBefore, certificate.NotAfter
	signature := verificationCheck(model.CTCheckPassed, Checkpoint{LogID: c.config.LogID, KeyIdentity: c.config.KeyIdentity}, sth, "")
	verification := model.CTVerification{CheckpointSignature: signature, Continuity: continuity, EntryInclusion: inclusion}
	provenance := ProvenanceLogUnverified
	if signature.Status == model.CTCheckPassed && inclusion.Status == model.CTCheckPassed &&
		(continuity.Status == model.CTCheckPassed || continuity.Status == model.CTCheckNotPerformed) {
		provenance = ProvenanceVerifiedLog
	}
	checkpointID := treeIdentity(c.config.LogID, sth.TreeSize, sth.SHA256RootHash[:])
	records := make([]Record, 0, len(names))
	seen := make(map[string]struct{})
	for _, rawName := range names {
		name := strings.TrimSpace(strings.ToLower(rawName))
		wildcard := strings.HasPrefix(name, "*.")
		name = strings.TrimPrefix(name, "*.")
		normalized, normalizeErr := normalizeName(name)
		if normalizeErr != nil || !withinRoots(normalized, c.config.Roots) {
			continue
		}
		if _, duplicate := seen[normalized]; duplicate {
			continue
		}
		seen[normalized] = struct{}{}
		entryIndex := index
		records = append(records, Record{
			Name: normalized, Wildcard: wildcard, CertificateHash: hex.EncodeToString(certificateHash[:]), LogID: c.config.LogID,
			EntryIndex: &entryIndex, LoggedAt: loggedAt, NotBefore: &notBefore, NotAfter: &notAfter, SourceID: c.config.SourceID,
			Provenance: provenance, Verification: verification, CheckpointID: checkpointID,
		})
	}
	return records, nil
}

func treeIdentity(logID string, size uint64, root []byte) string {
	digest := sha256.Sum256([]byte(fmt.Sprintf("%s\x00%d\x00%x", logID, size, root)))
	return "sha256:" + hex.EncodeToString(digest[:])
}

func retainedBytes(records []Record) int64 {
	var total int64
	for _, record := range records {
		total += int64(len(record.Name) + len(record.CertificateHash) + len(record.LogID) + len(record.SourceID) + len(record.CheckpointID))
	}
	return total
}

func cloneCheckpoint(checkpoint Checkpoint) Checkpoint {
	checkpoint.VerifiedRootHash = slices.Clone(checkpoint.VerifiedRootHash)
	return checkpoint
}
