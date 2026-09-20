// Package ctlog imports, verifies, and indexes bounded RFC 6962 certificate-transparency data.
package ctlog

import (
	"context"
	"time"

	"cloudattrib/internal/model"
)

// Provenance records how a CT record was authenticated.
type Provenance string

const (
	// ProvenanceVerifiedLog means the checkpoint and exact entry inclusion were verified.
	ProvenanceVerifiedLog Provenance = "verified_log"
	// ProvenanceLogUnverified means a configured log supplied the entry without complete verification.
	ProvenanceLogUnverified Provenance = "log_unverified"
	// ProvenanceImportedUnverified means an operator-controlled import supplied the entry.
	ProvenanceImportedUnverified Provenance = "imported_unverified"
)

// Record is one normalized certificate name and its immutable provenance.
type Record struct {
	Name            string               `json:"name"`
	Wildcard        bool                 `json:"wildcard"`
	CertificateHash string               `json:"certificate_hash"`
	LogID           string               `json:"log_id,omitempty"`
	EntryIndex      *uint64              `json:"entry_index,omitempty"`
	LoggedAt        time.Time            `json:"logged_at"`
	NotBefore       *time.Time           `json:"not_before,omitempty"`
	NotAfter        *time.Time           `json:"not_after,omitempty"`
	SourceID        string               `json:"source_id"`
	Provenance      Provenance           `json:"provenance"`
	Verification    model.CTVerification `json:"verification"`
	CheckpointID    string               `json:"checkpoint_id,omitempty"`
}

// Checkpoint separates ingestion progress from the last fully verified tree.
type Checkpoint struct {
	LogID            string    `json:"log_id"`
	NextIndex        uint64    `json:"next_index"`
	VerifiedTreeSize uint64    `json:"verified_tree_size,omitempty"`
	VerifiedRootHash []byte    `json:"verified_root_hash,omitempty"`
	TreeTimestamp    time.Time `json:"tree_timestamp,omitempty"`
	TreeIdentity     string    `json:"tree_identity,omitempty"`
	KeyIdentity      string    `json:"key_identity,omitempty"`
}

// Store atomically persists normalized records and collector progress.
type Store interface {
	Import(context.Context, []Record) error
	LoadCheckpoint(context.Context, string) (Checkpoint, error)
	CommitCollection(context.Context, []Record, Checkpoint) error
}

// Candidate is one concrete historical hostname selected for live revalidation.
type Candidate struct {
	Hostname        string               `json:"hostname"`
	CertificateHash string               `json:"certificate_hash"`
	LoggedAt        time.Time            `json:"logged_at"`
	SourceID        string               `json:"source_id"`
	Provenance      Provenance           `json:"provenance"`
	Verification    model.CTVerification `json:"verification"`
	CheckpointID    string               `json:"checkpoint_id,omitempty"`
}

// QueryResult is a deterministic bounded candidate set from one local index snapshot.
type QueryResult struct {
	Candidates    []Candidate `json:"candidates"`
	Available     int         `json:"available"`
	Omitted       int         `json:"omitted"`
	IndexIdentity string      `json:"index_identity"`
	Partial       bool        `json:"partial"`
}

// Reader retrieves local candidates without any request-time network access.
type Reader interface {
	Discover(context.Context, string, int) (QueryResult, error)
}

// Budget bounds every collector run.
type Budget struct {
	MaximumEntries  int
	BatchSize       int
	MaximumProofs   int
	MaximumRequests int
	MaximumBytes    int64
	MaximumElapsed  time.Duration
}

// DefaultBudget returns the measured-probe safety envelope.
func DefaultBudget() Budget {
	return Budget{MaximumEntries: 256, BatchSize: 64, MaximumProofs: 16, MaximumRequests: 24, MaximumBytes: 8 << 20, MaximumElapsed: 60 * time.Second}
}

// Metrics describes the bounded work and operating envelope of one run.
type Metrics struct {
	EntriesFetched  int           `json:"entries_fetched"`
	RecordsRetained int           `json:"records_retained"`
	DownloadedBytes int64         `json:"downloaded_bytes"`
	RetainedBytes   int64         `json:"retained_bytes"`
	Requests        int           `json:"requests"`
	Elapsed         time.Duration `json:"elapsed"`
	IngestionLag    time.Duration `json:"ingestion_lag"`
	BacklogBefore   uint64        `json:"backlog_before"`
	BacklogAfter    uint64        `json:"backlog_after"`
}
