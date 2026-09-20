package datasets

import (
	"context"
	"fmt"
	"sync"
	"testing"

	"cloudattrib/internal/model"
)

func TestFailedActivationKeepsLastKnownGood(t *testing.T) {
	t.Parallel()

	manager, err := NewManager(t.Context(), candidate("bundle-a", "build-a"), "build-a")
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}
	bad := candidate("bundle-b", "other-build")
	if err := manager.Activate(t.Context(), bad); err == nil {
		t.Fatal("Activate() error = nil, want incompatible build error")
	}
	if got := manager.Capture().View.BundleID(); got != "bundle-a" {
		t.Fatalf("active bundle = %q, want bundle-a", got)
	}
}

func TestPruneHonorsLastKnownGoodReadersAndDurablePins(t *testing.T) {
	t.Parallel()

	references := &fixtureReferences{pinned: map[string]bool{"bundle-a": true}}
	manager, err := NewManager(t.Context(), candidate("bundle-a", "build-a"), "build-a", WithReferenceStore(references))
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}
	for _, bundleID := range []string{"bundle-b", "bundle-c", "bundle-d"} {
		if err := manager.Activate(t.Context(), candidate(bundleID, "build-a")); err != nil {
			t.Fatalf("Activate(%s) error = %v", bundleID, err)
		}
	}
	removed := false
	if ok, err := manager.Prune(context.Background(), "bundle-a", func() error { removed = true; return nil }); err != nil || ok || removed {
		t.Fatalf("Prune(pinned) = %v, %v, removed=%v", ok, err, removed)
	}
	references.pinned["bundle-a"] = false
	if ok, err := manager.Prune(context.Background(), "bundle-a", func() error { removed = true; return nil }); err != nil || !ok || !removed {
		t.Fatalf("Prune(unpinned) = %v, %v, removed=%v", ok, err, removed)
	}
	if ok, err := manager.Prune(context.Background(), "bundle-b", func() error { return nil }); err != nil || ok {
		t.Fatalf("Prune(last-known-good) = %v, %v", ok, err)
	}

	acquired, release := manager.Acquire()
	if acquired.Manifest.BundleID != "bundle-d" {
		t.Fatalf("Acquire() bundle = %q", acquired.Manifest.BundleID)
	}
	for _, bundleID := range []string{"bundle-e", "bundle-f", "bundle-g"} {
		if err := manager.Activate(t.Context(), candidate(bundleID, "build-a")); err != nil {
			t.Fatalf("Activate(%s) error = %v", bundleID, err)
		}
	}
	if ok, err := manager.Prune(context.Background(), "bundle-d", func() error { return nil }); err != nil || ok {
		t.Fatalf("Prune(active-reader) = %v, %v", ok, err)
	}
	release()
	if ok, err := manager.Prune(context.Background(), "bundle-d", func() error { return nil }); err != nil || !ok {
		t.Fatalf("Prune(released-reader) = %v, %v", ok, err)
	}
}

func TestManagerRestoresRollbackProtectionAfterRestart(t *testing.T) {
	t.Parallel()

	references := &fixtureReferences{pinned: make(map[string]bool), protected: []string{"bundle-b", "bundle-a"}}
	manager, err := NewManager(t.Context(), candidate("bundle-c", "build-a"), "build-a", WithReferenceStore(references))
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}
	for _, bundleID := range []string{"bundle-a", "bundle-b", "bundle-c"} {
		if removed, pruneErr := manager.Prune(t.Context(), bundleID, func() error { return nil }); pruneErr != nil || removed {
			t.Fatalf("Prune(%s) = %v, %v", bundleID, removed, pruneErr)
		}
	}
}

type fixtureReferences struct {
	pinned    map[string]bool
	protected []string
}

func (f *fixtureReferences) WithBundlePruneLock(_ context.Context, bundleID string, action func(bool) error) error {
	return action(f.pinned[bundleID])
}

func (f *fixtureReferences) RecordBundleActivation(_ context.Context, bundleID string) error {
	for index, existing := range f.protected {
		if existing == bundleID {
			f.protected = append(f.protected[:index], f.protected[index+1:]...)
			break
		}
	}
	f.protected = append([]string{bundleID}, f.protected...)
	if len(f.protected) > 3 {
		f.protected = f.protected[:3]
	}
	return nil
}

func (f *fixtureReferences) ProtectedBundles(context.Context, int) ([]string, error) {
	return append([]string(nil), f.protected...), nil
}

func TestParallelReadersCaptureCoherentViewsDuringActivation(t *testing.T) {
	t.Parallel()

	manager, err := NewManager(t.Context(), candidate("bundle-0", "build-a"), "build-a")
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			for range 200 {
				snapshot := manager.Capture()
				if snapshot.Manifest.BundleID != snapshot.View.BundleID() {
					t.Errorf("mixed snapshot: manifest %q view %q", snapshot.Manifest.BundleID, snapshot.View.BundleID())
					return
				}
			}
		})
	}
	for version := 1; version <= 20; version++ {
		if err := manager.Activate(t.Context(), candidate(fmt.Sprintf("bundle-%d", version), "build-a")); err != nil {
			t.Fatalf("Activate() error = %v", err)
		}
	}
	wg.Wait()
}

func TestCaptureOwnsManifestSlices(t *testing.T) {
	t.Parallel()

	manager, err := NewManager(t.Context(), candidate("bundle-a", "build-a"), "build-a")
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}
	snapshot := manager.Capture()
	snapshot.Manifest.Sources[0].ID = "changed"
	if got := manager.Capture().Manifest.Sources[0].ID; got != "source-a" {
		t.Fatalf("stored source ID = %q, want source-a", got)
	}
}

func candidate(bundleID, buildID string) Candidate {
	return Candidate{
		Manifest: Manifest{
			SchemaVersion:            1,
			BundleID:                 bundleID,
			Sources:                  []Source{{ID: "source-a", Revision: "revision-a", Digest: "sha256:a", Status: model.CoverageComplete}},
			Artifacts:                []Artifact{{Path: "prefix.json", SHA256: "a", Size: 1}},
			CompatibleDetectorBuilds: []string{buildID},
		},
		View: model.NewAttributionView(bundleID, "policy-a", []string{buildID}, []model.CapabilityState{{Name: "prefix", Status: model.CoverageComplete}}),
	}
}
