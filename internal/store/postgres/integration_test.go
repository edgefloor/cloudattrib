package postgres

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"cloudattrib/internal/app"
	"cloudattrib/internal/ctlog"
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
	if _, err := store.pool.Exec(ctx, `TRUNCATE ct_records,ct_checkpoints,finding_evidence,findings,evidence,observations,job_targets,reports,bundle_pins,jobs,dataset_bundles RESTART IDENTITY CASCADE; UPDATE queue_capacity SET reserved_targets=0,maximum_targets=4 WHERE singleton=true`); err != nil {
		t.Fatalf("reset database: %v", err)
	}
	if err := store.RegisterBundle(ctx, "fixture-bundle", []byte(`{"schema_version":1}`), true); err != nil {
		t.Fatalf("RegisterBundle() error = %v", err)
	}
	ctPassed := model.CTVerificationCheck{Status: model.CTCheckPassed, Procedure: "rfc6962-sha256", ProcedureVersion: "1"}
	ctRecord := ctlog.Record{
		Name: "api.example.com", CertificateHash: "fixture-certificate", LoggedAt: time.Unix(10, 0).UTC(), SourceID: "fixture-log",
		Provenance:   ctlog.ProvenanceVerifiedLog,
		Verification: model.CTVerification{CheckpointSignature: ctPassed, Continuity: ctPassed, EntryInclusion: ctPassed},
	}
	checkpoint := ctlog.Checkpoint{LogID: "sha256:fixture-log", NextIndex: 1, VerifiedTreeSize: 1, VerifiedRootHash: make([]byte, 32), KeyIdentity: "sha256:fixture-key"}
	if err := store.CommitCollection(ctx, []ctlog.Record{ctRecord}, checkpoint); err != nil {
		t.Fatalf("CommitCollection() error = %v", err)
	}
	discovered, err := store.Discover(ctx, "example.com", 20)
	if err != nil || len(discovered.Candidates) != 1 || discovered.Candidates[0].Hostname != "api.example.com" {
		t.Fatalf("Discover() = %#v, %v", discovered, err)
	}
	loadedCheckpoint, err := store.LoadCheckpoint(ctx, checkpoint.LogID)
	if err != nil || loadedCheckpoint.NextIndex != 1 || loadedCheckpoint.VerifiedTreeSize != 1 {
		t.Fatalf("LoadCheckpoint() = %#v, %v", loadedCheckpoint, err)
	}
	if err := store.RecordBundleActivation(ctx, "fixture-bundle"); err != nil {
		t.Fatalf("RecordBundleActivation() error = %v", err)
	}
	protected, err := store.ProtectedBundles(ctx, 3)
	if err != nil || len(protected) != 1 || protected[0] != "fixture-bundle" {
		t.Fatalf("ProtectedBundles() = %v, %v", protected, err)
	}
	if err := store.RegisterBundle(ctx, "fixture-bundle", []byte(`{"schema_version":2}`), true); model.ErrorCodeOf(err) != model.CodeIdempotencyConflict {
		t.Fatalf("mutable RegisterBundle() error = %v", err)
	}
	if err := store.RegisterBundle(ctx, "old-bundle", []byte(`{"schema_version":1,"old":true}`), true); err != nil {
		t.Fatalf("RegisterBundle(old) error = %v", err)
	}
	removed := false
	if err := store.WithBundlePruneLock(ctx, "old-bundle", func(protected bool) error { removed = !protected; return nil }); err != nil || !removed {
		t.Fatalf("WithBundlePruneLock() removed=%v, error=%v", removed, err)
	}
	if _, err := store.Submit(ctx, jobs.SubmitRequest{OperatorID: "operator-a", IdempotencyKey: "pruned-key", BundleID: "old-bundle", Targets: []model.AnalyzeRequest{{Target: "example.com", Kind: model.TargetDomain}}}); model.ErrorCodeOf(err) != model.CodeBundleUnavailable {
		t.Fatalf("Submit(pruned bundle) error = %v", err)
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
		Observations: []model.Observation{{ID: "observation-1", Subject: "example.com", Type: "dns", ObservedAt: time.Unix(1, 0).UTC(), Status: "answered", Payload: model.JSONValue(`{}`)}},
		Evidence:     []model.Evidence{{ID: "evidence-1", ObservationIDs: []string{"observation-1"}, ClassifiedAt: time.Unix(2, 0).UTC(), Subject: "example.com", ProviderID: "aws", ProductID: "aws.cloudfront", Relation: model.RelationWebDelivery, Strength: model.StrengthStrong}},
		Findings:     []model.Finding{{ID: "finding-1", Subject: "example.com", ProviderID: "aws", ProductID: "aws.cloudfront", Relation: model.RelationWebDelivery, Strength: model.StrengthStrong, EvidenceIDs: []string{"evidence-1"}}},
		Coverage:     []model.Coverage{}, Warnings: []string{},
	}
	if err := store.Complete(ctx, claim.TargetID, claim.AttemptToken, report, jobs.TargetCompleted, ""); err != nil {
		t.Fatalf("Complete() error = %v", err)
	}
	if err := store.Complete(ctx, claim.TargetID, claim.AttemptToken, report, jobs.TargetCompleted, ""); err != nil {
		t.Fatalf("repeated Complete() error = %v", err)
	}
	loaded, err := store.Job(ctx, job.ID)
	if err != nil || loaded.Status != jobs.JobCompleted || !loaded.Targets[0].ReportAvailable {
		t.Fatalf("Job() = %#v, %v", loaded, err)
	}
	page, err := store.Findings(ctx, app.FindingQuery{Domain: "example.com", ProviderID: "aws", Limit: 1})
	if err != nil || len(page.Items) != 1 || page.Items[0].Finding.ID != "finding-1" {
		t.Fatalf("Findings() = %#v, %v", page, err)
	}
	pinned, err = store.BundlePinned(ctx, "fixture-bundle")
	if err != nil || pinned {
		t.Fatalf("BundlePinned() after completion = %v, %v", pinned, err)
	}
	replayJob, err := store.Submit(ctx, jobs.SubmitRequest{
		OperatorID: "operator-a", IdempotencyKey: "replay-key", BundleID: "fixture-bundle",
		Reclassifications: []model.ReclassifyRequest{{ReportID: report.ID, BundleID: "fixture-bundle"}},
	})
	if err != nil {
		t.Fatalf("Submit(reclassification) error = %v", err)
	}
	replayClaim, err := store.Claim(ctx, "replay-worker", time.Minute)
	if err != nil || replayClaim.Reclassify == nil || replayClaim.Reclassify.ReportID != report.ID {
		t.Fatalf("Claim(reclassification) = %#v, %v", replayClaim, err)
	}
	reclassified := report.Clone()
	reclassified.ID = "fixture-reclassified"
	reclassified.OriginalReportID = report.ID
	if err := store.Complete(ctx, replayClaim.TargetID, replayClaim.AttemptToken, reclassified, jobs.TargetCompleted, ""); err != nil {
		t.Fatalf("Complete(reclassification) error = %v", err)
	}
	replayLoaded, err := store.Job(ctx, replayJob.ID)
	if err != nil || replayLoaded.Status != jobs.JobCompleted || replayLoaded.Targets[0].Report.OriginalReportID != report.ID {
		t.Fatalf("Job(reclassification) = %#v, %v", replayLoaded, err)
	}

	cancelJob, err := store.Submit(ctx, jobs.SubmitRequest{OperatorID: "operator-a", IdempotencyKey: "cancel-key", BundleID: "fixture-bundle", Targets: []model.AnalyzeRequest{{Target: "one.example.com", Kind: model.TargetDomain}, {Target: "two.example.com", Kind: model.TargetDomain}}})
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
	invalid, err := store.Submit(ctx, jobs.SubmitRequest{OperatorID: "operator-a", IdempotencyKey: "invalid-key", BundleID: "fixture-bundle", Targets: []model.AnalyzeRequest{{Target: "not a domain", Kind: model.TargetDomain}}})
	if err != nil || invalid.Status != jobs.JobFailed || invalid.Targets[0].Status != jobs.TargetFailed {
		t.Fatalf("Submit(invalid row) = %#v, %v", invalid, err)
	}
	var reservations int
	if err := store.pool.QueryRow(ctx, `SELECT reserved_targets FROM queue_capacity WHERE singleton=true`).Scan(&reservations); err != nil || reservations != 0 {
		t.Fatalf("reserved targets after invalid row = %d, %v", reservations, err)
	}
}
