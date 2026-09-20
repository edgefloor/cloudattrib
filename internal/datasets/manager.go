// Package datasets validates and publishes immutable attribution views.
package datasets

import (
	"context"
	"fmt"
	"slices"
	"sync"
	"sync/atomic"

	"cloudattrib/internal/model"
)

// Source records one normalized source included in a bundle.
type Source struct {
	ID       string               `json:"id"`
	Revision string               `json:"revision"`
	Digest   string               `json:"digest"`
	Status   model.CoverageStatus `json:"status"`
	Reason   string               `json:"reason,omitempty"`
}

// Artifact records one canonical bundle file.
type Artifact struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

// Manifest describes a complete immutable bundle.
type Manifest struct {
	SchemaVersion            int        `json:"schema_version"`
	BundleID                 string     `json:"bundle_id"`
	Sources                  []Source   `json:"sources"`
	Artifacts                []Artifact `json:"artifacts"`
	CompatibleDetectorBuilds []string   `json:"compatible_detector_builds"`
}

// Candidate combines a validated manifest with its built in-memory view.
type Candidate struct {
	Manifest Manifest
	View     model.AttributionView
}

// Snapshot is one coherent captured manifest and view.
type Snapshot struct {
	Manifest Manifest
	View     model.AttributionView
}

// Manager serializes activation and publishes immutable snapshots atomically.
type Manager struct {
	buildID       string
	mu            sync.Mutex
	active        atomic.Pointer[Snapshot]
	references    ReferenceStore
	lastKnownGood []string
	readers       map[string]int
}

// ReferenceStore coordinates durable job pins with bundle pruning.
type ReferenceStore interface {
	WithBundlePruneLock(context.Context, string, func(bool) error) error
	RecordBundleActivation(context.Context, string) error
	ProtectedBundles(context.Context, int) ([]string, error)
}

// Option configures bundle lifecycle integration.
type Option func(*Manager)

// WithReferenceStore enables durable pruning checks. Without it, pruning fails closed.
func WithReferenceStore(store ReferenceStore) Option {
	return func(manager *Manager) { manager.references = store }
}

// NewManager validates and publishes the initial last-known-good candidate.
func NewManager(ctx context.Context, initial Candidate, buildID string, options ...Option) (*Manager, error) {
	manager := &Manager{buildID: buildID, readers: make(map[string]int)}
	for _, option := range options {
		option(manager)
	}
	if manager.references != nil {
		protected, err := manager.references.ProtectedBundles(ctx, 3)
		if err != nil {
			return nil, fmt.Errorf("load protected bundles: %w", err)
		}
		manager.lastKnownGood = slices.Clone(protected)
	}
	if err := manager.Activate(ctx, initial); err != nil {
		return nil, err
	}
	return manager, nil
}

// Activate validates a complete candidate before one atomic pointer swap.
func (m *Manager) Activate(ctx context.Context, candidate Candidate) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := validateCandidate(candidate, m.buildID); err != nil {
		return err
	}
	if m.references != nil {
		if err := m.references.RecordBundleActivation(ctx, candidate.Manifest.BundleID); err != nil {
			return fmt.Errorf("record bundle activation: %w", err)
		}
	}
	snapshot := &Snapshot{Manifest: cloneManifest(candidate.Manifest), View: candidate.View}
	m.active.Store(snapshot)
	m.lastKnownGood = append([]string{candidate.Manifest.BundleID}, m.lastKnownGood...)
	m.lastKnownGood = slices.Compact(m.lastKnownGood)
	if len(m.lastKnownGood) > 3 {
		m.lastKnownGood = m.lastKnownGood[:3]
	}
	return nil
}

// Capture returns a caller-owned manifest and one immutable view identity.
func (m *Manager) Capture() Snapshot {
	snapshot := m.active.Load()
	if snapshot == nil {
		return Snapshot{}
	}
	return Snapshot{Manifest: cloneManifest(snapshot.Manifest), View: snapshot.View}
}

// Acquire captures a view and protects its bundle until release is called.
func (m *Manager) Acquire() (Snapshot, func()) {
	m.mu.Lock()
	snapshot := m.active.Load()
	if snapshot == nil {
		m.mu.Unlock()
		return Snapshot{}, func() {}
	}
	bundleID := snapshot.Manifest.BundleID
	m.readers[bundleID]++
	result := Snapshot{Manifest: cloneManifest(snapshot.Manifest), View: snapshot.View}
	m.mu.Unlock()
	var once sync.Once
	return result, func() {
		once.Do(func() {
			m.mu.Lock()
			defer m.mu.Unlock()
			m.readers[bundleID]--
			if m.readers[bundleID] == 0 {
				delete(m.readers, bundleID)
			}
		})
	}
}

// Prune runs removal only when local and durable protections permit it.
func (m *Manager) Prune(ctx context.Context, bundleID string, remove func() error) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if bundleID == "" || remove == nil {
		return false, fmt.Errorf("bundle ID and removal callback are required")
	}
	if slices.Contains(m.lastKnownGood, bundleID) || m.readers[bundleID] > 0 {
		return false, nil
	}
	if m.references == nil {
		return false, model.NewError(model.CodePersistenceUnavailable, "durable bundle references cannot be checked", nil)
	}
	removed := false
	if err := m.references.WithBundlePruneLock(ctx, bundleID, func(pinned bool) error {
		if pinned {
			return nil
		}
		if err := remove(); err != nil {
			return err
		}
		removed = true
		return nil
	}); err != nil {
		return false, err
	}
	return removed, nil
}

func validateCandidate(candidate Candidate, buildID string) error {
	manifest := candidate.Manifest
	if manifest.SchemaVersion != 1 || manifest.BundleID == "" {
		return fmt.Errorf("bundle manifest identity is invalid")
	}
	if manifest.BundleID != candidate.View.BundleID() {
		return fmt.Errorf("bundle manifest and view identities differ")
	}
	if !slices.Contains(manifest.CompatibleDetectorBuilds, buildID) {
		return model.NewError(model.CodeBundleIncompatible, "bundle does not support this detector build", nil)
	}
	if len(manifest.Sources) == 0 || len(manifest.Artifacts) == 0 {
		return fmt.Errorf("bundle manifest is incomplete")
	}
	for _, source := range manifest.Sources {
		if source.ID == "" || source.Revision == "" || source.Digest == "" || source.Status == "" {
			return fmt.Errorf("bundle source record is incomplete")
		}
	}
	for _, artifact := range manifest.Artifacts {
		if artifact.Path == "" || artifact.SHA256 == "" || artifact.Size <= 0 {
			return fmt.Errorf("bundle artifact record is incomplete")
		}
	}
	return nil
}

func cloneManifest(manifest Manifest) Manifest {
	manifest.Sources = slices.Clone(manifest.Sources)
	manifest.Artifacts = slices.Clone(manifest.Artifacts)
	manifest.CompatibleDetectorBuilds = slices.Clone(manifest.CompatibleDetectorBuilds)
	return manifest
}
