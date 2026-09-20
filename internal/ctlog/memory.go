package ctlog

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"
	"sync"
)

// MemoryStore is a deterministic in-process CT store for tests and local fixtures.
type MemoryStore struct {
	mu          sync.Mutex
	records     map[string]Record
	checkpoints map[string]Checkpoint
}

// NewMemoryStore returns an empty store.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{records: make(map[string]Record), checkpoints: make(map[string]Checkpoint)}
}

// Import atomically adds normalized records.
func (s *MemoryStore) Import(ctx context.Context, records []Record) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.importLocked(records)
	return nil
}

func (s *MemoryStore) importLocked(records []Record) {
	for _, record := range records {
		s.records[record.Name+"\x00"+record.CertificateHash] = cloneRecord(record)
	}
}

// LoadCheckpoint returns the persisted collector position for a log.
func (s *MemoryStore) LoadCheckpoint(ctx context.Context, logID string) (Checkpoint, error) {
	if err := ctx.Err(); err != nil {
		return Checkpoint{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	checkpoint, ok := s.checkpoints[logID]
	if !ok {
		return Checkpoint{}, nil
	}
	checkpoint.VerifiedRootHash = slices.Clone(checkpoint.VerifiedRootHash)
	return checkpoint, nil
}

// CommitCollection atomically publishes records and collector progress.
func (s *MemoryStore) CommitCollection(ctx context.Context, records []Record, checkpoint Checkpoint) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if current, ok := s.checkpoints[checkpoint.LogID]; ok && (checkpoint.NextIndex < current.NextIndex ||
		checkpoint.NextIndex == current.NextIndex && checkpoint.VerifiedTreeSize < current.VerifiedTreeSize) {
		return fmt.Errorf("CT checkpoint would regress")
	}
	s.importLocked(records)
	checkpoint.VerifiedRootHash = slices.Clone(checkpoint.VerifiedRootHash)
	s.checkpoints[checkpoint.LogID] = checkpoint
	return nil
}

// Discover returns recent concrete names and never expands wildcard patterns.
func (s *MemoryStore) Discover(ctx context.Context, root string, limit int) (QueryResult, error) {
	if err := ctx.Err(); err != nil {
		return QueryResult{}, err
	}
	if limit < 1 {
		return QueryResult{}, fmt.Errorf("CT discovery limit must be positive")
	}
	normalizedRoot, err := normalizeName(root)
	if err != nil {
		return QueryResult{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	byName := make(map[string]Record)
	partial := false
	for _, record := range s.records {
		if !withinRoots(record.Name, []string{normalizedRoot}) {
			continue
		}
		if record.Wildcard {
			continue
		}
		if record.Provenance != ProvenanceVerifiedLog {
			partial = true
		}
		current, ok := byName[record.Name]
		if !ok || record.LoggedAt.After(current.LoggedAt) || record.LoggedAt.Equal(current.LoggedAt) && record.CertificateHash < current.CertificateHash {
			byName[record.Name] = record
		}
	}
	records := make([]Record, 0, len(byName))
	for _, record := range byName {
		records = append(records, record)
	}
	slices.SortFunc(records, func(left, right Record) int {
		if !left.LoggedAt.Equal(right.LoggedAt) {
			if left.LoggedAt.After(right.LoggedAt) {
				return -1
			}
			return 1
		}
		return strings.Compare(left.Name, right.Name)
	})
	result := QueryResult{Available: len(records), Partial: partial}
	if len(records) > limit {
		result.Omitted = len(records) - limit
		records = records[:limit]
	}
	identity := sha256.New()
	for _, record := range records {
		result.Candidates = append(result.Candidates, Candidate{
			Hostname: record.Name, CertificateHash: record.CertificateHash, LoggedAt: record.LoggedAt, SourceID: record.SourceID,
			Provenance: record.Provenance, Verification: record.Verification, CheckpointID: record.CheckpointID,
		})
		_, _ = fmt.Fprintf(identity, "%s\x00%s\x00%s\n", record.Name, record.CertificateHash, record.CheckpointID)
	}
	result.IndexIdentity = "sha256:" + hex.EncodeToString(identity.Sum(nil))
	return result, nil
}

func cloneRecord(record Record) Record {
	if record.EntryIndex != nil {
		value := *record.EntryIndex
		record.EntryIndex = &value
	}
	if record.NotBefore != nil {
		value := *record.NotBefore
		record.NotBefore = &value
	}
	if record.NotAfter != nil {
		value := *record.NotAfter
		record.NotAfter = &value
	}
	return record
}

var _ Store = (*MemoryStore)(nil)
var _ Reader = (*MemoryStore)(nil)
