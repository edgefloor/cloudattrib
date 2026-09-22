package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"cloudattrib/internal/app"
	"cloudattrib/internal/ctlog"
	"cloudattrib/internal/jobs"
	"cloudattrib/internal/model"
)

func TestPostgresJobProjectionKeepsReportDocumentsOutOfPolling(t *testing.T) {
	dsn := os.Getenv("CLOUDATTRIB_POSTGRES_TEST_DSN")
	if dsn == "" {
		t.Skip("CLOUDATTRIB_POSTGRES_TEST_DSN is not set")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	store, err := Open(ctx, dsn, 1000)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	t.Cleanup(store.Close)
	if _, err := store.pool.Exec(ctx, `TRUNCATE ct_records,ct_checkpoints,finding_evidence,findings,evidence,observations,job_targets,reports,bundle_pins,jobs,dataset_bundles RESTART IDENTITY CASCADE; UPDATE queue_capacity SET reserved_targets=0,maximum_targets=1000 WHERE singleton=true`); err != nil {
		t.Fatalf("reset database: %v", err)
	}
	report := model.Report{
		SchemaVersion: model.SchemaVersion,
		ID:            "projection-report",
		Target:        model.Target{Original: "example.com", Canonical: "example.com", Kind: model.TargetDomain},
		Status:        model.StatusComplete,
		ClassifiedAt:  time.Unix(1, 0).UTC(),
	}
	if err := store.SaveReport(ctx, report); err != nil {
		t.Fatalf("SaveReport() error = %v", err)
	}
	if _, err := store.pool.Exec(ctx, `INSERT INTO jobs(id,operator_id,idempotency_key,payload_hash,status,created_at,updated_at) VALUES('projection-job','operator','projection-key','hash','completed',clock_timestamp(),clock_timestamp())`); err != nil {
		t.Fatalf("insert job: %v", err)
	}
	batch := &pgx.Batch{}
	for index := range 1000 {
		request, marshalErr := json.Marshal(workRequest{Analyze: &model.AnalyzeRequest{Target: fmt.Sprintf("target-%04d.example.com", index), Kind: model.TargetDomain}})
		if marshalErr != nil {
			t.Fatalf("encode request: %v", marshalErr)
		}
		batch.Queue(`INSERT INTO job_targets(id,job_id,input_index,request,status,attempts,report_id) VALUES($1,'projection-job',$2,$3,'completed',1,'projection-report')`, fmt.Sprintf("projection-target-%04d", index), index, request)
	}
	results := store.pool.SendBatch(ctx, batch)
	if err := results.Close(); err != nil {
		t.Fatalf("insert targets: %v", err)
	}
	loaded, err := store.Job(ctx, "projection-job")
	if err != nil {
		t.Fatalf("Job() error = %v", err)
	}
	if len(loaded.Targets) != 1000 {
		t.Fatalf("target count = %d", len(loaded.Targets))
	}
	for index, target := range loaded.Targets {
		if target.Index != index || target.ReportID != report.ID || target.Report.ID != "" || !target.ReportAvailable || target.Attempts != 1 {
			t.Fatalf("target[%d] = %#v", index, target)
		}
	}
	loadedReport, err := store.LoadReport(ctx, report.ID)
	if err != nil || loadedReport.ID != report.ID {
		t.Fatalf("LoadReport() = %#v, %v", loadedReport, err)
	}
}

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
	publishStarted := make(chan struct{})
	releasePublish := make(chan struct{})
	activationDone := make(chan error, 1)
	go func() {
		activationDone <- store.ActivateBundle(ctx, "coordinated-bundle", []byte(`{"schema_version":1,"bundle_id":"coordinated-bundle"}`), true, func() error {
			close(publishStarted)
			<-releasePublish
			return nil
		})
	}()
	<-publishStarted
	pruneCtx, cancelPrune := context.WithTimeout(ctx, 100*time.Millisecond)
	err = store.WithBundlePruneLock(pruneCtx, "coordinated-bundle", func(bool) error { return nil })
	cancelPrune()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("WithBundlePruneLock() during activation error = %v, want deadline", err)
	}
	close(releasePublish)
	if err := <-activationDone; err != nil {
		t.Fatalf("ActivateBundle() error = %v", err)
	}
	protectedByActivation := false
	if err := store.WithBundlePruneLock(ctx, "coordinated-bundle", func(protected bool) error {
		protectedByActivation = protected
		return nil
	}); err != nil || !protectedByActivation {
		t.Fatalf("WithBundlePruneLock() after activation protected=%v, error=%v", protectedByActivation, err)
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
	if err != nil || len(protected) < 1 || protected[0] != "fixture-bundle" {
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
	metrics, err := store.OperationalMetrics(ctx)
	if err != nil || metrics.ReservedTargets != 1 || metrics.QueuedTargets != 1 || metrics.BundlePins != 1 || metrics.CTCheckpoints != 1 || metrics.ActiveBundleID != "fixture-bundle" {
		t.Fatalf("OperationalMetrics() = %#v, %v", metrics, err)
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
	legacyLoaded, err := store.LoadReport(ctx, report.ID)
	if err != nil {
		t.Fatalf("LoadReport(legacy) error = %v", err)
	}
	if legacyLoaded.ID != report.ID || legacyLoaded.ContentIDVersion != "" {
		t.Fatalf("LoadReport(legacy) identity = %#v", legacyLoaded)
	}
	identityReport := report.Clone()
	identityReport.ID = ""
	identityReport.ContentIDVersion = model.ReportContentIDVersion
	identityReport.Observations[0].Payload = model.JSONValue(`{"nested":{"second":2.00,"first":{"value":1e3}}}`)
	identityReport.ID, err = identityReport.ContentID()
	if err != nil {
		t.Fatalf("ContentID() before JSONB round trip error = %v", err)
	}
	if err := store.SaveReport(ctx, identityReport); err != nil {
		t.Fatalf("SaveReport(identity) error = %v", err)
	}
	identityLoaded, err := store.LoadReport(ctx, identityReport.ID)
	if err != nil {
		t.Fatalf("LoadReport(identity) error = %v", err)
	}
	roundTripID, err := identityLoaded.ContentID()
	if err != nil {
		t.Fatalf("ContentID() after JSONB round trip error = %v", err)
	}
	if roundTripID != identityReport.ID {
		t.Fatalf("ContentID() after JSONB round trip = %q, want %q", roundTripID, identityReport.ID)
	}
	loaded, err := store.Job(ctx, job.ID)
	if err != nil || loaded.Status != jobs.JobCompleted || !loaded.Targets[0].ReportAvailable || loaded.Targets[0].ReportID != report.ID || loaded.Targets[0].Report.ID != "" {
		t.Fatalf("Job() = %#v, %v", loaded, err)
	}
	loadedReport, err := store.LoadReport(ctx, loaded.Targets[0].ReportID)
	if err != nil || loadedReport.ID != report.ID {
		t.Fatalf("LoadReport() = %#v, %v", loadedReport, err)
	}
	page, err := store.Findings(ctx, app.FindingQuery{Domain: "example.com", ProviderID: "aws", Limit: 1})
	if err != nil || len(page.Items) != 1 || page.Items[0].Finding.ID != "finding-1" {
		t.Fatalf("Findings() = %#v, %v", page, err)
	}
	pinned, err = store.BundlePinned(ctx, "fixture-bundle")
	if err != nil || pinned {
		t.Fatalf("BundlePinned() after completion = %v, %v", pinned, err)
	}
	metrics, err = store.OperationalMetrics(ctx)
	if err != nil || metrics.ReservedTargets != 0 || metrics.QueuedTargets != 0 || metrics.RunningTargets != 0 || metrics.BundlePins != 0 {
		t.Fatalf("OperationalMetrics() after completion = %#v, %v", metrics, err)
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
	if err != nil || replayLoaded.Status != jobs.JobCompleted || replayLoaded.Targets[0].ReportID != reclassified.ID || replayLoaded.Targets[0].Report.ID != "" {
		t.Fatalf("Job(reclassification) = %#v, %v", replayLoaded, err)
	}
	replayReport, err := store.LoadReport(ctx, replayLoaded.Targets[0].ReportID)
	if err != nil || replayReport.OriginalReportID != report.ID {
		t.Fatalf("LoadReport(reclassification) = %#v, %v", replayReport, err)
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
