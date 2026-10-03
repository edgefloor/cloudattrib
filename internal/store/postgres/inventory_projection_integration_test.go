package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"cloudattrib/internal/inventory"
	"cloudattrib/internal/jobs"
	"cloudattrib/internal/model"
)

func TestInventoryProjectionPreservesPositiveHistoryAndReferences(t *testing.T) {
	dsn := os.Getenv("CLOUDATTRIB_POSTGRES_TEST_DSN")
	if dsn == "" {
		t.Skip("CLOUDATTRIB_POSTGRES_TEST_DSN is not set")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	store, err := Open(ctx, dsn, 2000)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(store.Close)
	if _, err := store.pool.Exec(ctx, `TRUNCATE inventory_import_chunks,inventory_tombstones,inventory_assets,inventory_scopes,
		inventory_projection_tasks,inventory_context_support,inventory_asset_contexts,inventory_dns_state,
		finding_evidence,findings,evidence,observations,job_targets,reports,bundle_pins,jobs,ct_records,ct_checkpoints CASCADE`); err != nil {
		t.Fatal(err)
	}
	if err := store.RegisterInventoryScopes(ctx, []string{"example.com"}); err != nil {
		t.Fatal(err)
	}
	firstAt := time.Unix(10, 0).UTC()
	first := model.Report{ID: "projection-positive", SchemaVersion: model.SchemaVersion,
		Target: model.Target{Canonical: "api.example.com", Kind: model.TargetDomain}, Mode: model.ModeFull, StartedAt: firstAt, EndedAt: firstAt, ClassifiedAt: firstAt,
		Status: model.StatusComplete,
		Observations: []model.Observation{
			{ID: "query-a", Type: "dns_query", Subject: "api.example.com", ObservedAt: firstAt, Status: "answered", Payload: model.JSONValue(`{"rrtype":"A","owner":"api.example.com"}`)},
			{ID: "http-403", Type: "http_response", Subject: "api.example.com", ObservedAt: firstAt, Status: "responded", Payload: model.JSONValue(`{"status_code":403,"url":"https://api.example.com/?token=secret-token"}`)},
			{ID: "technology-analytics", Type: "technology", Subject: "api.example.com", ObservedAt: firstAt, Status: "detected", Payload: model.JSONValue(`{"name":"Google Analytics"}`)},
		},
		Evidence: []model.Evidence{{ID: "evidence-1", ObservationIDs: []string{"http-403"}, Subject: "api.example.com", Relation: model.RelationWebDelivery}},
		Findings: []model.Finding{{ID: "finding-1", Subject: "api.example.com", ProviderID: "provider-safe", ProductID: "portal", Relation: model.RelationWebDelivery, EvidenceIDs: []string{"evidence-1"}}},
		Coverage: []model.Coverage{{Capability: "dns", Status: model.CoverageComplete}},
	}
	if err := store.SaveReport(ctx, first); err != nil {
		t.Fatal(err)
	}
	asset, err := inventory.NewService(store).Read(ctx, "api.example.com")
	if err != nil || len(asset.Scopes) != 1 {
		t.Fatalf("report asset = %#v, %v", asset, err)
	}
	status, err := store.InventoryProjectionStatus(ctx)
	if err != nil || status.Pending != 1 {
		t.Fatalf("projection status = %#v, %v", status, err)
	}
	processed, err := store.ProcessNextInventoryProjection(ctx)
	if err != nil || !processed {
		t.Fatalf("process positive = %t, %v (cause: %v)", processed, err, errors.Unwrap(err))
	}
	var originalRevision int64
	if err := store.pool.QueryRow(ctx, `SELECT description_revision FROM inventory_asset_contexts WHERE asset_id=$1 AND context_id='unknown'`, asset.ID).Scan(&originalRevision); err != nil {
		t.Fatal(err)
	}
	if _, err := store.pool.Exec(ctx, `UPDATE inventory_asset_contexts SET description_format_version='1' WHERE asset_id=$1 AND context_id='unknown'`, asset.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.pool.Exec(ctx, `INSERT INTO inventory_projection_tasks(report_id,projector_version,deletion_generation) VALUES($1,'1',0)`, first.ID); err != nil {
		t.Fatal(err)
	}
	if processed, err := store.ProcessNextInventoryProjection(ctx); err != nil || !processed {
		t.Fatalf("process prior-version task = %t, %v", processed, err)
	}
	var format string
	var upgradedRevision int64
	if err := store.pool.QueryRow(ctx, `SELECT description_format_version,description_revision FROM inventory_asset_contexts WHERE asset_id=$1 AND context_id='unknown'`, asset.ID).Scan(&format, &upgradedRevision); err != nil {
		t.Fatal(err)
	}
	if format != inventory.DescriptionFormatVersion || upgradedRevision != originalRevision+1 {
		t.Fatalf("reindexed description format=%q revision=%d, want format=%q revision=%d", format, upgradedRevision, inventory.DescriptionFormatVersion, originalRevision+1)
	}
	secondAt := time.Unix(20, 0).UTC()
	failed := model.Report{ID: "projection-timeout", SchemaVersion: model.SchemaVersion,
		Target: first.Target, Mode: model.ModeFull, StartedAt: secondAt, EndedAt: secondAt, ClassifiedAt: secondAt, Status: model.StatusPartial,
		Observations: []model.Observation{
			{ID: "query-a-timeout", Type: "dns_query", Subject: "api.example.com", ObservedAt: secondAt,
				Status: "timeout", Payload: model.JSONValue(`{"rrtype":"A","owner":"api.example.com"}`)},
			{ID: "query-aaaa-nodata", Type: "dns_query", Subject: "api.example.com", ObservedAt: secondAt,
				Status: "nodata", Payload: model.JSONValue(`{"rrtype":"AAAA","owner":"api.example.com"}`)},
		},
		Coverage: []model.Coverage{{Capability: "dns", Status: model.CoveragePartial}},
	}
	if err := store.SaveReport(ctx, failed); err != nil {
		t.Fatal(err)
	}
	processed, err = store.ProcessNextInventoryProjection(ctx)
	if err != nil || !processed {
		t.Fatalf("process timeout = %t, %v", processed, err)
	}
	var latestAt, positiveAt time.Time
	var descriptionText string
	if err := store.pool.QueryRow(ctx, `SELECT latest_attempt_at,last_positive_at,description FROM inventory_asset_contexts WHERE asset_id=$1 AND context_id='unknown'`, asset.ID).
		Scan(&latestAt, &positiveAt, &descriptionText); err != nil {
		t.Fatal(err)
	}
	if !latestAt.Equal(secondAt) || !positiveAt.Equal(firstAt) || !strings.Contains(descriptionText, "HTTP 403") || strings.Contains(descriptionText, "secret-token") {
		t.Fatalf("attempt=%s positive=%s description=%q", latestAt, positiveAt, descriptionText)
	}
	var outcome string
	var lastPositiveAt time.Time
	if err := store.pool.QueryRow(ctx, `SELECT latest_outcome,last_positive_at FROM inventory_dns_state WHERE asset_id=$1 AND context_id='unknown' AND rrtype='A'`, asset.ID).
		Scan(&outcome, &lastPositiveAt); err != nil {
		t.Fatal(err)
	}
	if outcome != "timeout" || !lastPositiveAt.Equal(firstAt) {
		t.Fatalf("DNS latest=%q last positive=%s", outcome, lastPositiveAt)
	}
	evidenceService := inventory.NewService(store).WithDefaultContext("unknown")
	search, err := evidenceService.SearchEvidence(ctx, inventory.EvidenceQuery{Text: "portal", ScopeRoot: "example.com"})
	if err != nil || len(search.Items) != 1 || search.Items[0].Hostname != "api.example.com" || len(search.Items[0].EvidenceIDs) != 1 || search.Items[0].EvidenceIDs[0] != "evidence-1" {
		t.Fatalf("lexical evidence search = %#v, %v", search, err)
	}
	technologySearch, err := evidenceService.SearchEvidence(ctx, inventory.EvidenceQuery{Text: "google analytics", ScopeRoot: "example.com"})
	if err != nil || len(technologySearch.Items) != 1 || technologySearch.Items[0].Hostname != "api.example.com" {
		t.Fatalf("multiword technology search = %#v, %v", technologySearch, err)
	}
	read, err := evidenceService.ReadEvidence(ctx, "api.example.com", "")
	if err != nil || read.ProjectionStatus != "ready" || read.LatestAttemptAt == nil || !read.LatestAttemptAt.Equal(secondAt) || read.LastPositiveAt == nil || !read.LastPositiveAt.Equal(firstAt) ||
		read.LatestHTTPStatus != nil || read.LastHTTPResponseStatus == nil || *read.LastHTTPResponseStatus != 403 || len(read.LatestCoverage) != 1 || read.LatestCoverage[0] != "dns:partial" ||
		len(read.DNSQuestions) != 2 || read.DNSQuestions[0].LatestOutcome != "timeout" || read.DNSQuestions[0].LastPositiveAt == nil || !read.DNSQuestions[0].LastPositiveAt.Equal(firstAt) ||
		read.DNSQuestions[1].RRType != "AAAA" || read.DNSQuestions[1].LatestOutcome != "nodata" || read.DNSQuestions[1].LastPositiveAt != nil {
		t.Fatalf("evidence state = %#v, %v", read, err)
	}
	var protected int
	if err := store.pool.QueryRow(ctx, `SELECT count(*) FROM inventory_context_support WHERE asset_id=$1 AND context_id='unknown'`, asset.ID).Scan(&protected); err != nil || protected != 2 {
		t.Fatalf("protected reports=%d error=%v", protected, err)
	}
	status, err = store.InventoryProjectionStatus(ctx)
	if err != nil || status.Pending != 0 || status.Running != 0 || status.Failed != 0 || status.ProtectedReports != 2 || status.ProtectedDocumentBytes == 0 {
		t.Fatalf("completed status = %#v, %v", status, err)
	}
	thirdAt := time.Unix(30, 0).UTC()
	contextValue := model.KnownProvenance("split-view")
	splitView := model.Report{ID: "projection-split-view", SchemaVersion: model.SchemaVersion,
		Target: first.Target, Mode: model.ModeDNS, StartedAt: thirdAt, EndedAt: thirdAt, ClassifiedAt: thirdAt,
		Status:     model.StatusComplete,
		Provenance: &model.ReportProvenance{Collection: model.CollectionProvenance{ObservationContext: &contextValue}},
		Observations: []model.Observation{{ID: "split-dns", Type: "dns_query", Subject: "api.example.com", ObservedAt: thirdAt,
			Status: "answered", Payload: model.JSONValue(`{"rrtype":"A","owner":"api.example.com"}`)}},
	}
	if err := store.SaveReport(ctx, splitView); err != nil {
		t.Fatal(err)
	}
	if processed, err := store.ProcessNextInventoryProjection(ctx); err != nil || !processed {
		t.Fatalf("project split-view = %t, %v", processed, err)
	}
	split, err := evidenceService.ReadEvidence(ctx, "api.example.com", "split-view")
	if err != nil || split.LatestAttemptAt == nil || !split.LatestAttemptAt.Equal(thirdAt) ||
		len(split.DNSQuestions) != 1 || split.DNSQuestions[0].LatestOutcome != "answered" {
		t.Fatalf("split-view evidence = %#v, %v", split, err)
	}
	unknown, err := evidenceService.ReadEvidence(ctx, "api.example.com", "unknown")
	if err != nil || unknown.LatestAttemptAt == nil || !unknown.LatestAttemptAt.Equal(secondAt) ||
		len(unknown.DNSQuestions) != 2 || unknown.DNSQuestions[0].LatestOutcome != "timeout" {
		t.Fatalf("unknown-view evidence changed = %#v, %v", unknown, err)
	}
}

func TestInventoryProjectionRecoversOlderHTTPResponseAfterNewerTimeout(t *testing.T) {
	dsn := os.Getenv("CLOUDATTRIB_POSTGRES_TEST_DSN")
	if dsn == "" {
		t.Skip("CLOUDATTRIB_POSTGRES_TEST_DSN is not set")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	store, err := Open(ctx, dsn, 2000)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(store.Close)
	if _, err := store.pool.Exec(ctx, `TRUNCATE inventory_import_chunks,inventory_tombstones,inventory_assets,inventory_scopes,
		inventory_projection_tasks,inventory_context_support,inventory_asset_contexts,inventory_dns_state,
		finding_evidence,findings,evidence,observations,job_targets,reports,bundle_pins,jobs,ct_records,ct_checkpoints CASCADE`); err != nil {
		t.Fatal(err)
	}
	newerAt := time.Unix(200, 0).UTC()
	newer := model.Report{ID: "newer-http-timeout", SchemaVersion: model.SchemaVersion,
		Target: model.Target{Canonical: "api.example.com", Kind: model.TargetDomain}, Mode: model.ModeFull,
		StartedAt: newerAt, EndedAt: newerAt, ClassifiedAt: newerAt, Status: model.StatusPartial,
		Coverage: []model.Coverage{{Capability: "http", Status: model.CoveragePartial}},
	}
	if err := store.SaveReport(ctx, newer); err != nil {
		t.Fatal(err)
	}
	if _, err := store.pool.Exec(ctx, `DELETE FROM reports WHERE id=$1`, newer.ID); err == nil {
		t.Fatal("pending projection did not protect its source report")
	}
	if processed, err := store.ProcessNextInventoryProjection(ctx); err != nil || !processed {
		t.Fatalf("project newer timeout = %t, %v", processed, err)
	}
	olderAt := time.Unix(100, 0).UTC()
	older := model.Report{ID: "older-http-response", SchemaVersion: model.SchemaVersion,
		Target: newer.Target, Mode: model.ModeFull, StartedAt: olderAt, EndedAt: olderAt, ClassifiedAt: olderAt,
		Status: model.StatusComplete,
		Observations: []model.Observation{{ID: "older-response", Type: "http_response", Subject: "api.example.com",
			ObservedAt: olderAt, Status: "responded", Payload: model.JSONValue(`{"status_code":500}`)}},
	}
	if err := store.SaveReport(ctx, older); err != nil {
		t.Fatal(err)
	}
	if processed, err := store.ProcessNextInventoryProjection(ctx); err != nil || !processed {
		t.Fatalf("project older response = %t, %v", processed, err)
	}
	result, err := inventory.NewService(store).WithDefaultContext("unknown").ReadEvidence(ctx, "api.example.com", "")
	if err != nil {
		t.Fatal(err)
	}
	if result.LatestAttemptAt == nil || !result.LatestAttemptAt.Equal(newerAt) || result.LatestHTTPStatus != nil ||
		result.LastHTTPResponseAt == nil || !result.LastHTTPResponseAt.Equal(olderAt) ||
		result.LastHTTPResponseStatus == nil || *result.LastHTTPResponseStatus != 500 || result.LastHTTPResponseReportID != older.ID {
		t.Fatalf("out-of-order HTTP state = %#v", result)
	}
	if _, err := store.pool.Exec(ctx, `DELETE FROM reports WHERE id=$1`, older.ID); err == nil {
		t.Fatal("last HTTP response did not protect its source report")
	}
}

func TestInventoryProjectionBackfillLeaseRecoveryAndDeletion(t *testing.T) {
	dsn := os.Getenv("CLOUDATTRIB_POSTGRES_TEST_DSN")
	if dsn == "" {
		t.Skip("CLOUDATTRIB_POSTGRES_TEST_DSN is not set")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	store, err := Open(ctx, dsn, 2000)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(store.Close)
	if _, err := store.pool.Exec(ctx, `TRUNCATE inventory_import_chunks,inventory_tombstones,inventory_assets,inventory_scopes,
		inventory_projection_tasks,inventory_context_support,inventory_asset_contexts,inventory_dns_state,
		finding_evidence,findings,evidence,observations,job_targets,reports,bundle_pins,jobs,ct_records,ct_checkpoints CASCADE`); err != nil {
		t.Fatal(err)
	}
	observed := time.Unix(100, 0).UTC()
	report := model.Report{ID: "historical-report", SchemaVersion: model.SchemaVersion, Target: model.Target{Canonical: "historical.example.com", Kind: model.TargetDomain},
		StartedAt: observed, EndedAt: observed, ClassifiedAt: observed, Status: model.StatusComplete,
		Observations: []model.Observation{{ID: "historical-dns", Type: "dns_query", Subject: "historical.example.com", ObservedAt: observed, Status: "answered", Payload: model.JSONValue(`{"rrtype":"A","owner":"historical.example.com"}`)}},
	}
	encoded, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.pool.Exec(ctx, `INSERT INTO reports(id,target,status,classified_at,bundle_id,document) VALUES($1,$2,$3,$4,$5,$6)`, report.ID, report.Target.Canonical, report.Status, report.ClassifiedAt, "", encoded); err != nil {
		t.Fatal(err)
	}
	page, err := store.BackfillInventoryReports(ctx, "", 1)
	if err != nil || page.Processed != 1 || !page.Complete {
		t.Fatalf("report backfill = %#v, %v", page, err)
	}
	claim, err := store.claimInventoryProjection(ctx)
	if err != nil || claim == nil {
		t.Fatalf("claim = %#v, %v", claim, err)
	}
	if _, err := store.pool.Exec(ctx, `UPDATE inventory_projection_tasks SET lease_expires_at=clock_timestamp()-interval '1 second' WHERE report_id=$1`, report.ID); err != nil {
		t.Fatal(err)
	}
	processed, err := store.ProcessNextInventoryProjection(ctx)
	if err != nil || !processed {
		t.Fatalf("expired lease recovery = %t, %v", processed, err)
	}
	asset, err := inventory.NewService(store).Read(ctx, "historical.example.com")
	if err != nil {
		t.Fatal(err)
	}
	var count int
	if err := store.pool.QueryRow(ctx, `SELECT count(*) FROM inventory_asset_contexts WHERE asset_id=$1`, asset.ID).Scan(&count); err != nil || count != 1 {
		t.Fatalf("projected contexts=%d error=%v", count, err)
	}
	page, err = store.BackfillInventoryReports(ctx, "", 1)
	if err != nil || page.Processed != 1 {
		t.Fatalf("repeat backfill = %#v, %v", page, err)
	}
	if _, err := store.pool.Exec(ctx, `UPDATE inventory_projection_tasks SET status='failed',attempts=5,last_error='projection_failed' WHERE report_id=$1`, report.ID); err != nil {
		t.Fatal(err)
	}
	page, err = store.BackfillInventoryReports(ctx, "", 1)
	if err != nil || page.Processed != 1 {
		t.Fatalf("retry exhausted backfill = %#v, %v", page, err)
	}
	claim, err = store.claimInventoryProjection(ctx)
	if err != nil || claim == nil {
		t.Fatalf("second claim = %#v, %v", claim, err)
	}
	if _, err := inventory.NewService(store).Delete(ctx, "historical.example.com", true); err != nil {
		t.Fatal(err)
	}
	loaded, err := store.LoadReport(ctx, report.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.publishInventoryProjection(ctx, *claim, loaded); err != nil {
		t.Fatalf("discard deleted asset projection: %v", err)
	}
	if _, err := inventory.NewService(store).Read(ctx, "historical.example.com"); model.ErrorCodeOf(err) != model.CodeNotFound {
		t.Fatalf("deleted asset resurrected: %v", err)
	}
}

func TestInventoryValidationFreezesJobTargets(t *testing.T) {
	dsn := os.Getenv("CLOUDATTRIB_POSTGRES_TEST_DSN")
	if dsn == "" {
		t.Skip("CLOUDATTRIB_POSTGRES_TEST_DSN is not set")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	store, err := Open(ctx, dsn, 2000)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(store.Close)
	if _, err := store.pool.Exec(ctx, `TRUNCATE inventory_import_chunks,inventory_tombstones,inventory_assets,inventory_scopes,
		inventory_projection_tasks,inventory_context_support,inventory_asset_contexts,inventory_dns_state,
		finding_evidence,findings,evidence,observations,job_targets,reports,bundle_pins,jobs,ct_records,ct_checkpoints CASCADE;
		UPDATE queue_capacity SET reserved_targets=0 WHERE singleton=true`); err != nil {
		t.Fatal(err)
	}
	service := inventory.NewService(store)
	_, err = service.Import(ctx, inventory.ImportRequest{OperationID: "validation-source", ChunkID: "1", SourceID: "fixture", ScopeRoots: []string{"example.com"}, Entries: []inventory.Entry{{Hostname: "a.example.com"}}})
	if err != nil {
		t.Fatal(err)
	}
	validator := inventory.NewValidator(service, store, store)
	job, err := validator.Validate(ctx, "operator", inventory.ValidationRequest{IdempotencyKey: "validate-1", Mode: model.ModeDNS,
		Selection: &inventory.SearchRequest{Mode: inventory.SearchDescendant, Query: "example.com"}, ScopeRoot: "example.com"})
	if err != nil || len(job.Targets) != 1 || job.Targets[0].Request.Target != "a.example.com" {
		t.Fatalf("job = %#v, %v", job, err)
	}
	_, err = service.Import(ctx, inventory.ImportRequest{OperationID: "validation-source", ChunkID: "2", SourceID: "fixture", ScopeRoots: []string{"example.com"}, Entries: []inventory.Entry{{Hostname: "b.example.com"}}})
	if err != nil {
		t.Fatal(err)
	}
	stored, err := store.Job(ctx, job.ID)
	if err != nil || len(stored.Targets) != 1 || stored.Targets[0].Request.CTDiscovery {
		t.Fatalf("frozen job = %#v, %v", stored, err)
	}
	claim, err := store.Claim(ctx, "inventory-validation-worker", time.Minute)
	if err != nil || claim.TargetID != job.Targets[0].ID {
		t.Fatalf("claim = %#v, %v", claim, err)
	}
	if _, err := service.Delete(ctx, "a.example.com", false); err != nil {
		t.Fatal(err)
	}
	_, err = service.Import(ctx, inventory.ImportRequest{OperationID: "validation-source", ChunkID: "3", SourceID: "fixture", ScopeRoots: []string{"example.com"}, Entries: []inventory.Entry{{Hostname: "a.example.com"}}})
	if err != nil {
		t.Fatal(err)
	}
	completedAt := time.Now().UTC()
	report := model.Report{ID: "late-validation-report", SchemaVersion: model.SchemaVersion,
		Target: model.Target{Canonical: "a.example.com", Kind: model.TargetDomain}, Mode: model.ModeDNS,
		StartedAt: completedAt, EndedAt: completedAt, ClassifiedAt: completedAt, Status: model.StatusComplete,
		Observations: []model.Observation{{ID: "late-dns", Type: "dns_query", Subject: "a.example.com", ObservedAt: completedAt, Status: "answered", Payload: model.JSONValue(`{"rrtype":"A","owner":"a.example.com"}`)}},
	}
	if err := store.Complete(ctx, claim.TargetID, claim.AttemptToken, report, jobs.TargetCompleted, ""); err != nil {
		t.Fatal(err)
	}
	var queued int
	if err := store.pool.QueryRow(ctx, `SELECT count(*) FROM inventory_projection_tasks WHERE report_id=$1`, report.ID).Scan(&queued); err != nil || queued != 0 {
		t.Fatalf("stale validation queued projection=%d error=%v", queued, err)
	}
	asset, err := service.Read(ctx, "a.example.com")
	if err != nil || asset.DeletionGeneration != 1 || len(asset.Sources) != 1 || asset.Sources[0].Kind != "hostname_import" {
		t.Fatalf("rediscovered asset after stale job = %#v, %v", asset, err)
	}
}
