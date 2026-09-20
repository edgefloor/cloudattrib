package postgres

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"cloudattrib/internal/jobs"
	"cloudattrib/internal/model"
)

func TestPostgresAdmissionClaimCompletionAndPinLifecycle(t *testing.T) {
	dsn := os.Getenv("CLOUDATTRIB_POSTGRES_TEST_DSN")
	if dsn == "" {
		t.Skip("CLOUDATTRIB_POSTGRES_TEST_DSN is not set")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	store, err := Open(ctx, dsn, 4)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	t.Cleanup(store.Close)
	if _, err := store.pool.Exec(ctx, `TRUNCATE finding_evidence,findings,evidence,observations,job_targets,reports,bundle_pins,jobs,dataset_bundles RESTART IDENTITY CASCADE; UPDATE queue_capacity SET reserved_targets=0,maximum_targets=4 WHERE singleton=true`); err != nil {
		t.Fatalf("reset database: %v", err)
	}
	if err := store.RegisterBundle(ctx, "fixture-bundle", []byte(`{"schema_version":1}`), true); err != nil {
		t.Fatalf("RegisterBundle() error = %v", err)
	}
	job, err := store.Submit(ctx, jobs.SubmitRequest{OperatorID: "operator-a", IdempotencyKey: "fixture-key", BundleID: "fixture-bundle", Targets: []model.AnalyzeRequest{{Target: "example.com", Kind: model.TargetDomain}}})
	if err != nil {
		t.Fatalf("Submit() error = %v (cause: %v)", err, errors.Unwrap(err))
	}
	pinned, err := store.BundlePinned(ctx, "fixture-bundle")
	if err != nil || !pinned {
		t.Fatalf("BundlePinned() = %v, %v", pinned, err)
	}
	claim, err := store.Claim(ctx, "worker", time.Minute)
	if err != nil {
		t.Fatalf("Claim() error = %v", err)
	}
	report := model.Report{
		SchemaVersion: model.SchemaVersion, ID: "fixture-report", Target: model.Target{Original: "example.com", Canonical: "example.com", Kind: model.TargetDomain},
		Mode: model.ModeFull, StartedAt: time.Unix(1, 0).UTC(), EndedAt: time.Unix(2, 0).UTC(), ClassifiedAt: time.Unix(2, 0).UTC(), BundleID: "fixture-bundle", BuildID: "fixture", Status: model.StatusComplete,
		Observations: []model.Observation{}, Evidence: []model.Evidence{}, Findings: []model.Finding{}, Coverage: []model.Coverage{}, Warnings: []string{},
	}
	if err := store.Complete(ctx, claim.TargetID, claim.AttemptToken, report, jobs.TargetCompleted, ""); err != nil {
		t.Fatalf("Complete() error = %v", err)
	}
	loaded, err := store.Job(ctx, job.ID)
	if err != nil || loaded.Status != jobs.JobCompleted || !loaded.Targets[0].ReportAvailable {
		t.Fatalf("Job() = %#v, %v", loaded, err)
	}
	pinned, err = store.BundlePinned(ctx, "fixture-bundle")
	if err != nil || pinned {
		t.Fatalf("BundlePinned() after completion = %v, %v", pinned, err)
	}

	cancelJob, err := store.Submit(ctx, jobs.SubmitRequest{OperatorID: "operator-a", IdempotencyKey: "cancel-key", BundleID: "fixture-bundle", Targets: []model.AnalyzeRequest{{Target: "one.example", Kind: model.TargetDomain}, {Target: "two.example", Kind: model.TargetDomain}}})
	if err != nil {
		t.Fatalf("Submit(cancel) error = %v", err)
	}
	store.now = func() time.Time { return time.Now().Add(-2 * time.Minute) }
	cancelClaim, err := store.Claim(ctx, "worker", time.Second)
	if err != nil {
		t.Fatalf("Claim(cancel) error = %v", err)
	}
	if err := store.RequestCancel(ctx, cancelJob.ID, "operator-b"); err != nil {
		t.Fatalf("RequestCancel() error = %v", err)
	}
	pinned, err = store.BundlePinned(ctx, "fixture-bundle")
	if err != nil || !pinned {
		t.Fatalf("BundlePinned() during running cancellation = %v, %v", pinned, err)
	}
	if err := store.RecoverExpired(ctx, 3); err != nil {
		t.Fatalf("RecoverExpired() error = %v", err)
	}
	if err := store.Complete(ctx, cancelClaim.TargetID, cancelClaim.AttemptToken, model.Report{}, jobs.TargetCompleted, ""); model.ErrorCodeOf(err) != model.CodeIdempotencyConflict {
		t.Fatalf("stale Complete() error = %v", err)
	}
	loaded, err = store.Job(ctx, cancelJob.ID)
	if err != nil || loaded.Status != jobs.JobCancelled {
		t.Fatalf("cancelled Job() = %#v, %v", loaded, err)
	}
	pinned, err = store.BundlePinned(ctx, "fixture-bundle")
	if err != nil || pinned {
		t.Fatalf("BundlePinned() after cancelled terminals = %v, %v", pinned, err)
	}
}
