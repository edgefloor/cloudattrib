package datasets

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestRepositoryImportActivateRollbackCorruptionAndPrune(t *testing.T) {
	t.Parallel()

	root := filepath.Join(t.TempDir(), "bundles")
	repository, err := NewRepository(root, "build-a")
	if err != nil {
		t.Fatalf("NewRepository() error = %v", err)
	}
	firstSources := fixtureSourceDirectory(t, "fixture-1")
	first, err := repository.Import(context.Background(), firstSources)
	if err != nil {
		t.Fatalf("Import(first) error = %v", err)
	}
	if !first.Valid || first.CandidateHash == "" || len(first.Receipts) == 0 {
		t.Fatalf("first validation = %#v", first)
	}
	if _, err := repository.Activate(context.Background(), first.CandidateID, first.CandidateHash, "activate"); err != nil {
		t.Fatalf("Activate(first) error = %v", err)
	}
	secondSources := fixtureSourceDirectory(t, "fixture-2")
	second, err := repository.Import(context.Background(), secondSources)
	if err != nil {
		t.Fatalf("Import(second) error = %v", err)
	}
	if second.CandidateID == first.CandidateID {
		t.Fatal("distinct source revisions produced the same candidate")
	}
	if _, err := repository.Activate(context.Background(), second.CandidateID, "wrong", "activate"); err == nil {
		t.Fatal("Activate(second) accepted the wrong approval hash")
	}
	if _, err := repository.Activate(context.Background(), second.CandidateID, second.CandidateHash, "activate"); err != nil {
		t.Fatalf("Activate(second) error = %v", err)
	}
	if _, err := repository.Activate(context.Background(), first.CandidateID, first.CandidateHash, "rollback"); err != nil {
		t.Fatalf("Activate(rollback) error = %v", err)
	}
	status, err := repository.Status()
	if err != nil || status.Active == nil || status.Active.BundleID != first.CandidateID || len(status.Candidates) != 2 {
		t.Fatalf("Status() = %#v, %v", status, err)
	}
	artifact := filepath.Join(repository.candidateDirectory(second.CandidateID), "sources", "aws-ip-ranges.json")
	if err := os.WriteFile(artifact, []byte(`{"corrupt":true}`), 0o600); err != nil {
		t.Fatalf("corrupt artifact: %v", err)
	}
	if _, err := repository.Validate(context.Background(), second.CandidateID); err == nil {
		t.Fatal("Validate() accepted a corrupt artifact")
	}
	removed, err := repository.Prune(second.CandidateID, func(string) (bool, error) { return false, nil })
	if err != nil || !removed {
		t.Fatalf("Prune(second) = %v, %v", removed, err)
	}
	removed, err = repository.Prune(first.CandidateID, func(string) (bool, error) { return false, nil })
	if err != nil || removed {
		t.Fatalf("Prune(active) = %v, %v", removed, err)
	}
}

func TestRepositoryRejectsConcurrentWriter(t *testing.T) {
	t.Parallel()

	repository, err := NewRepository(filepath.Join(t.TempDir(), "bundles"), "build-a")
	if err != nil {
		t.Fatalf("NewRepository() error = %v", err)
	}
	locked := make(chan struct{})
	release := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- repository.withWriterLock(func() error {
			close(locked)
			<-release
			return nil
		})
	}()
	<-locked
	if _, err := repository.Import(context.Background(), fixtureSourceDirectory(t, "fixture-lock")); err == nil {
		t.Fatal("Import() succeeded while another writer held the lock")
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatalf("lock holder error = %v", err)
	}
}

func TestActivateCommittedPublishesOnlyAfterCommit(t *testing.T) {
	t.Parallel()

	repository, err := NewRepository(filepath.Join(t.TempDir(), "bundles"), "build-a")
	if err != nil {
		t.Fatal(err)
	}
	first, err := repository.Import(t.Context(), fixtureSourceDirectory(t, "coordinated-first"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repository.Activate(t.Context(), first.CandidateID, first.CandidateHash, "activate"); err != nil {
		t.Fatal(err)
	}
	second, err := repository.Import(t.Context(), fixtureSourceDirectory(t, "coordinated-second"))
	if err != nil {
		t.Fatal(err)
	}
	activation, err := repository.ActivateCommitted(t.Context(), second.CandidateID, second.CandidateHash, "activate", func(proposed Activation, _ Manifest, _ []byte) (Activation, error) {
		active, activeErr := repository.Active()
		if activeErr != nil || active == nil || active.BundleID != first.CandidateID {
			t.Fatalf("Active() before commit = %#v, %v", active, activeErr)
		}
		proposed.Generation = 12
		proposed.At = time.Unix(12, 0).UTC()
		return proposed, nil
	})
	if err != nil {
		t.Fatalf("ActivateCommitted() error = %v", err)
	}
	if activation.Generation != 12 || activation.OperationID == "" {
		t.Fatalf("activation = %#v", activation)
	}
	active, err := repository.Active()
	if err != nil || active == nil || active.BundleID != second.CandidateID || active.Generation != 12 {
		t.Fatalf("Active() = %#v, %v", active, err)
	}
	if err := repository.ReconcileCommitted(t.Context(), activation); err != nil {
		t.Fatalf("ReconcileCommitted(idempotent) error = %v", err)
	}

	failure := errors.New("durable activation failed")
	if _, err := repository.ActivateCommitted(t.Context(), first.CandidateID, first.CandidateHash, "rollback", func(Activation, Manifest, []byte) (Activation, error) {
		return Activation{}, failure
	}); !errors.Is(err, failure) {
		t.Fatalf("ActivateCommitted(failure) error = %v", err)
	}
	active, err = repository.Active()
	if err != nil || active == nil || active.BundleID != second.CandidateID {
		t.Fatalf("Active() after failed commit = %#v, %v", active, err)
	}

	activePath := filepath.Join(repository.root, activeFilename)
	if err := os.Remove(activePath); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(activePath, 0o700); err != nil {
		t.Fatal(err)
	}
	var committed Activation
	if _, err := repository.ActivateCommitted(t.Context(), first.CandidateID, first.CandidateHash, "rollback", func(proposed Activation, _ Manifest, _ []byte) (Activation, error) {
		proposed.Generation = 13
		proposed.At = time.Unix(13, 0).UTC()
		committed = proposed
		return proposed, nil
	}); err == nil {
		t.Fatal("ActivateCommitted() error = nil, want publication failure")
	}
	if err := os.Remove(activePath); err != nil {
		t.Fatal(err)
	}
	if err := repository.ReconcileCommitted(t.Context(), committed); err != nil {
		t.Fatalf("ReconcileCommitted(after publication failure) error = %v", err)
	}
	active, err = repository.Active()
	if err != nil || active == nil || active.BundleID != first.CandidateID || active.Generation != 13 {
		t.Fatalf("Active() after reconciliation = %#v, %v", active, err)
	}
	higherPointer := Activation{OperationID: "activation-other-database", Generation: 99, BundleID: second.CandidateID, CandidateHash: second.CandidateHash, Action: "activate", At: time.Unix(99, 0).UTC()}
	if err := repository.publishCommitted(higherPointer, true); err != nil {
		t.Fatal(err)
	}
	if err := repository.ReconcileAuthoritative(t.Context(), committed, func(context.Context) (*Activation, error) {
		copy := committed
		return &copy, nil
	}); err != nil {
		t.Fatalf("ReconcileAuthoritative(restored database) error = %v", err)
	}
	active, err = repository.Active()
	if err != nil || active == nil || active.OperationID != committed.OperationID {
		t.Fatalf("Active() after authoritative regression = %#v, %v", active, err)
	}
	if err := os.WriteFile(activePath, []byte("{corrupt"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := repository.ReconcileAuthoritative(t.Context(), committed, func(context.Context) (*Activation, error) {
		copy := committed
		return &copy, nil
	}); err != nil {
		t.Fatalf("ReconcileAuthoritative(corrupt pointer) error = %v", err)
	}
	if err := repository.publishCommitted(higherPointer, true); err != nil {
		t.Fatal(err)
	}
	if err := repository.ReconcileAuthoritative(t.Context(), committed, func(context.Context) (*Activation, error) {
		copy := higherPointer
		return &copy, nil
	}); err == nil {
		t.Fatal("ReconcileAuthoritative() accepted an activation that was no longer desired")
	}

	stale := Activation{OperationID: "activation-stale", Generation: 11, BundleID: first.CandidateID, CandidateHash: first.CandidateHash, Action: "rollback", At: time.Unix(11, 0).UTC()}
	if err := repository.ReconcileCommitted(t.Context(), stale); err == nil {
		t.Fatal("ReconcileCommitted() accepted a stale generation")
	}
}

func TestRepositoryFlagsStaleFirstCandidate(t *testing.T) {
	t.Parallel()

	repository, err := NewRepository(filepath.Join(t.TempDir(), "bundles"), "build-a")
	if err != nil {
		t.Fatal(err)
	}
	repository.now = func() time.Time { return time.Date(2026, 9, 20, 0, 0, 0, 0, time.UTC) }
	sources := fixtureSourceDirectory(t, "fixture-stale")
	awsPath := filepath.Join(sources, "aws-ip-ranges.json")
	data, err := os.ReadFile(awsPath)
	if err != nil {
		t.Fatal(err)
	}
	data = []byte(strings.Replace(string(data), "2026-09-20T00:00:00Z", "2020-01-01T00:00:00Z", 1))
	if err := os.WriteFile(awsPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	report, err := repository.Import(context.Background(), sources)
	if err != nil {
		t.Fatal(err)
	}
	if !report.ReviewRequired || !slices.Contains(report.Reasons, "stale source aws-ip-ranges") {
		t.Fatalf("report = %#v", report)
	}
}

func fixtureSourceDirectory(t *testing.T, syncToken string) string {
	t.Helper()
	directory := t.TempDir()
	fixtures := map[string]string{
		"aws-ip-ranges.json":         "../../testdata/upstream/aws-ip-ranges.json",
		"gcp-cloud.json":             "../../testdata/upstream/gcp-cloud.json",
		"azure-service-tags.json":    "../../testdata/upstream/azure-service-tags.json",
		"cdncheck-sources-data.json": "../../testdata/upstream/cdncheck-sources-data.json",
		"iptoasn-v4.tsv":             "../../testdata/upstream/iptoasn-v4.tsv",
		"iptoasn-v6.tsv":             "../../testdata/upstream/iptoasn-v6.tsv",
	}
	for target, source := range fixtures {
		data, err := os.ReadFile(source)
		if err != nil {
			t.Fatalf("read fixture %s: %v", source, err)
		}
		if target == "aws-ip-ranges.json" {
			data = []byte(strings.Replace(string(data), "fixture-1", syncToken, 1))
		}
		if err := os.WriteFile(filepath.Join(directory, target), data, 0o600); err != nil {
			t.Fatalf("write fixture %s: %v", target, err)
		}
	}
	return directory
}
