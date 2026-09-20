// Package datasets validates and publishes immutable attribution views.
package datasets

import (
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
	buildID string
	mu      sync.Mutex
	active  atomic.Pointer[Snapshot]
}

// NewManager validates and publishes the initial last-known-good candidate.
func NewManager(initial Candidate, buildID string) (*Manager, error) {
	manager := &Manager{buildID: buildID}
	if err := manager.Activate(initial); err != nil {
		return nil, err
	}
	return manager, nil
}

// Activate validates a complete candidate before one atomic pointer swap.
func (m *Manager) Activate(candidate Candidate) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := validateCandidate(candidate, m.buildID); err != nil {
		return err
	}
	snapshot := &Snapshot{Manifest: cloneManifest(candidate.Manifest), View: candidate.View}
	m.active.Store(snapshot)
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
