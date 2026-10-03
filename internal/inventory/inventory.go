// Package inventory owns durable concrete-hostname discovery and search contracts.
package inventory

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"time"

	"cloudattrib/internal/model"
	"cloudattrib/internal/target"
)

// MaximumImportEntries bounds one retryable import chunk.
const MaximumImportEntries = 1000

// AssetID is stable for one canonical concrete hostname across sources.
func AssetID(hostname string) string {
	digest := sha256.Sum256([]byte(hostname))
	return "asset-sha256:" + hex.EncodeToString(digest[:])
}

// ReverseLabels creates a label-boundary prefix key for descendant searches.
func ReverseLabels(hostname string) string {
	labels := strings.Split(hostname, ".")
	for left, right := 0, len(labels)-1; left < right; left, right = left+1, right-1 {
		labels[left], labels[right] = labels[right], labels[left]
	}
	return strings.Join(labels, ".") + "."
}

// Normalize returns one concrete hostname and the normalization contract used.
func Normalize(raw string) (string, string, error) {
	includeWWW := false
	normalized, err := target.Normalize(model.AnalyzeRequest{Target: raw, Kind: model.TargetDomain, Mode: model.ModeDNS, IncludeWWW: &includeWWW})
	if err != nil {
		return "", "", err
	}
	return normalized.Target.Canonical, normalized.IDNAProfileVersion, nil
}

// WithinScope requires an exact root or a complete DNS-label suffix.
func WithinScope(hostname, root string) bool {
	return hostname == root || strings.HasSuffix(hostname, "."+root)
}

// Entry is one unverified operator-supplied hostname sighting.
type Entry struct {
	Hostname   string     `json:"hostname"`
	ObservedAt *time.Time `json:"observed_at,omitempty"`
}

// ImportRequest identifies one retryable bounded chunk of hostname sightings.
type ImportRequest struct {
	OperationID string   `json:"operation_id"`
	ChunkID     string   `json:"chunk_id"`
	SourceID    string   `json:"source_id"`
	ScopeRoots  []string `json:"scope_roots"`
	Entries     []Entry  `json:"entries"`
}

// ImportCounts distinguishes accepted names from omissions and duplicates.
type ImportCounts struct {
	Accepted   int `json:"accepted"`
	Duplicate  int `json:"duplicate"`
	Invalid    int `json:"invalid"`
	Wildcard   int `json:"wildcard"`
	OutOfScope int `json:"out_of_scope"`
	Suppressed int `json:"suppressed,omitempty"`
	Stale      int `json:"stale,omitempty"`
}

// ImportReceipt is stable across retries with the same operation and chunk.
type ImportReceipt struct {
	OperationID string       `json:"operation_id"`
	ChunkID     string       `json:"chunk_id"`
	Counts      ImportCounts `json:"counts"`
}

// BackfillPage records progress through historical CT sightings.
type BackfillPage struct {
	Processed  int    `json:"processed"`
	NextCursor string `json:"next_cursor,omitempty"`
	Complete   bool   `json:"complete"`
}

// Sighting is a validated concrete hostname passed to durable storage.
type Sighting struct {
	AssetID              string
	Hostname             string
	ReversedLabels       string
	NormalizationVersion string
	SourceID             string
	FirstObservedAt      *time.Time
	LastObservedAt       *time.Time
	ScopeRoots           []string
}

// Store atomically imports one chunk and returns its durable counts.
type Store interface {
	ImportInventoryChunk(context.Context, ImportReceipt, string, []string, []Sighting, time.Time) (ImportReceipt, error)
	SearchStore
	ArchiveInventory(context.Context, string, bool) (Asset, error)
	DeleteInventory(context.Context, string, bool) (int64, error)
}

// Service validates imports without contacting any target.
type Service struct {
	store Store
}

// NewService builds the inventory application service.
func NewService(store Store) *Service { return &Service{store: store} }

// Search reads only known inventory records and never performs discovery.
func (s *Service) Search(ctx context.Context, request SearchRequest) (Page, error) {
	if s == nil || s.store == nil {
		return Page{}, model.NewError(model.CodeInvalidOptions, "inventory store is required", nil)
	}
	prepared, after, err := PrepareSearch(request)
	if err != nil {
		return Page{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return s.store.SearchInventory(ctx, prepared, after)
}

// Read returns one known asset by canonical hostname.
func (s *Service) Read(ctx context.Context, raw string) (Asset, error) {
	if s == nil || s.store == nil {
		return Asset{}, model.NewError(model.CodeInvalidOptions, "inventory store is required", nil)
	}
	hostname, _, err := Normalize(raw)
	if err != nil {
		return Asset{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return s.store.ReadInventory(ctx, hostname)
}

// Archive hides or restores a known asset without changing its discovery facts.
func (s *Service) Archive(ctx context.Context, raw string, archived bool) (Asset, error) {
	if s == nil || s.store == nil {
		return Asset{}, model.NewError(model.CodeInvalidOptions, "inventory store is required", nil)
	}
	hostname, _, err := Normalize(raw)
	if err != nil {
		return Asset{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return s.store.ArchiveInventory(ctx, hostname, archived)
}

// Delete removes inventory-owned facts; suppression blocks future rediscovery.
func (s *Service) Delete(ctx context.Context, raw string, suppress bool) (int64, error) {
	if s == nil || s.store == nil {
		return 0, model.NewError(model.CodeInvalidOptions, "inventory store is required", nil)
	}
	hostname, _, err := Normalize(raw)
	if err != nil {
		return 0, err
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return s.store.DeleteInventory(ctx, hostname, suppress)
}

// Import validates one chunk and publishes all accepted sightings atomically.
func (s *Service) Import(ctx context.Context, request ImportRequest) (ImportReceipt, error) {
	startedAt := time.Now().UTC()
	if s == nil || s.store == nil || len(request.OperationID) == 0 || len(request.OperationID) > 128 || len(request.ChunkID) == 0 || len(request.ChunkID) > 128 ||
		len(request.SourceID) == 0 || len(request.SourceID) > 128 || len(request.ScopeRoots) == 0 || len(request.ScopeRoots) > 32 || len(request.Entries) == 0 || len(request.Entries) > MaximumImportEntries {
		return ImportReceipt{}, model.NewError(model.CodeInvalidOptions, "inventory import requires bounded identities, scopes, and entries", nil)
	}
	for _, value := range []string{request.OperationID, request.ChunkID, request.SourceID} {
		if strings.ContainsAny(value, "\x00\r\n") {
			return ImportReceipt{}, model.NewError(model.CodeInvalidOptions, "inventory import identity contains control text", nil)
		}
	}
	roots := make([]string, 0, len(request.ScopeRoots))
	for _, raw := range request.ScopeRoots {
		root, _, err := Normalize(raw)
		if err != nil {
			return ImportReceipt{}, fmt.Errorf("normalize inventory scope: %w", err)
		}
		roots = append(roots, root)
	}
	slices.Sort(roots)
	roots = slices.Compact(roots)
	canonicalRequest, err := json.Marshal(request)
	if err != nil {
		return ImportReceipt{}, fmt.Errorf("encode inventory import identity: %w", err)
	}
	digest := sha256.Sum256(canonicalRequest)
	receipt := ImportReceipt{OperationID: request.OperationID, ChunkID: request.ChunkID}
	seen := make(map[string]int, len(request.Entries))
	sightings := make([]Sighting, 0, len(request.Entries))
	for _, entry := range request.Entries {
		if err := ctx.Err(); err != nil {
			return ImportReceipt{}, err
		}
		if strings.HasPrefix(strings.TrimSpace(entry.Hostname), "*.") {
			receipt.Counts.Wildcard++
			continue
		}
		hostname, version, err := Normalize(entry.Hostname)
		if err != nil {
			receipt.Counts.Invalid++
			continue
		}
		matches := make([]string, 0, len(roots))
		for _, root := range roots {
			if WithinScope(hostname, root) {
				matches = append(matches, root)
			}
		}
		if len(matches) == 0 {
			receipt.Counts.OutOfScope++
			continue
		}
		if index, duplicate := seen[hostname]; duplicate {
			receipt.Counts.Duplicate++
			if entry.ObservedAt != nil {
				observed := *entry.ObservedAt
				if sightings[index].FirstObservedAt == nil || observed.Before(*sightings[index].FirstObservedAt) {
					sightings[index].FirstObservedAt = &observed
				}
				if sightings[index].LastObservedAt == nil || observed.After(*sightings[index].LastObservedAt) {
					sightings[index].LastObservedAt = &observed
				}
			}
			continue
		}
		seen[hostname] = len(sightings)
		var observed *time.Time
		if entry.ObservedAt != nil {
			value := *entry.ObservedAt
			observed = &value
		}
		sightings = append(sightings, Sighting{
			AssetID: AssetID(hostname), Hostname: hostname, ReversedLabels: ReverseLabels(hostname), NormalizationVersion: version,
			SourceID: request.SourceID, FirstObservedAt: observed, LastObservedAt: observed, ScopeRoots: matches,
		})
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	return s.store.ImportInventoryChunk(ctx, receipt, "sha256:"+hex.EncodeToString(digest[:]), roots, sightings, startedAt)
}
