package datasets

import (
	"fmt"
	"sync"
	"testing"

	"cloudattrib/internal/model"
)

func TestFailedActivationKeepsLastKnownGood(t *testing.T) {
	t.Parallel()

	manager, err := NewManager(candidate("bundle-a", "build-a"), "build-a")
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}
	bad := candidate("bundle-b", "other-build")
	if err := manager.Activate(bad); err == nil {
		t.Fatal("Activate() error = nil, want incompatible build error")
	}
	if got := manager.Capture().View.BundleID(); got != "bundle-a" {
		t.Fatalf("active bundle = %q, want bundle-a", got)
	}
}

func TestParallelReadersCaptureCoherentViewsDuringActivation(t *testing.T) {
	t.Parallel()

	manager, err := NewManager(candidate("bundle-0", "build-a"), "build-a")
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
		if err := manager.Activate(candidate(fmt.Sprintf("bundle-%d", version), "build-a")); err != nil {
			t.Fatalf("Activate() error = %v", err)
		}
	}
	wg.Wait()
}

func TestCaptureOwnsManifestSlices(t *testing.T) {
	t.Parallel()

	manager, err := NewManager(candidate("bundle-a", "build-a"), "build-a")
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
