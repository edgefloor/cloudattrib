package postgres

import (
	"context"
	"os"
	"testing"
	"time"

	"cloudattrib/internal/app"
	"cloudattrib/internal/jobs"
	"cloudattrib/internal/model"
	"cloudattrib/internal/retention"
)

func TestReportRetentionPreviewApplyAndReferences(t *testing.T) {
	dsn := os.Getenv("CLOUDATTRIB_POSTGRES_TEST_DSN")
	if dsn == "" {
		t.Skip("CLOUDATTRIB_POSTGRES_TEST_DSN is not set")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	store, err := Open(ctx, dsn, 100)
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
	old := time.Now().UTC().Add(-45 * 24 * time.Hour)
	cutoff := time.Now().UTC().Add(-30 * 24 * time.Hour)
	report := func(id string) model.Report {
		return model.Report{ID: id, SchemaVersion: model.SchemaVersion,
			Target: model.Target{Canonical: "198.51.100.7", Kind: model.TargetIP}, Mode: model.ModeIP,
			StartedAt: old, EndedAt: old, ClassifiedAt: old, Status: model.StatusComplete,
			Observations: []model.Observation{{ID: id + "-observation", Type: "ip_lookup", Subject: "198.51.100.7", ObservedAt: old,
				Payload: model.JSONValue(`{"ip":"198.51.100.7"}`)}},
		}
	}
	for _, id := range []string{"expired", "replay-base"} {
		if err := store.SaveReport(ctx, report(id)); err != nil {
			t.Fatal(err)
		}
		if _, err := store.pool.Exec(ctx, `UPDATE reports SET created_at=$2 WHERE id=$1`, id, old); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := store.pool.Exec(ctx, `INSERT INTO jobs(id,operator_id,idempotency_key,payload_hash,status,created_at,updated_at)
		VALUES('terminal-job','operator','terminal-key','hash','completed',clock_timestamp(),clock_timestamp());
		INSERT INTO job_targets(id,job_id,input_index,request,status,report_id)
		VALUES('terminal-target','terminal-job',0,'{"analyze":{"target":"198.51.100.7","kind":"ip"}}','completed','expired')`); err != nil {
		t.Fatal(err)
	}
	replay := report("retained-replay")
	replay.OriginalReportID = "replay-base"
	if err := store.SaveReport(ctx, replay); err != nil {
		t.Fatal(err)
	}
	firstPage, err := store.RunReportRetention(ctx, retention.Request{Cutoff: cutoff, Limit: 1})
	if err != nil || firstPage.Eligible != 1 || firstPage.NextCursor == "" || firstPage.Complete {
		t.Fatalf("first retention page = %#v, %v", firstPage, err)
	}
	if _, err := store.RunReportRetention(ctx, retention.Request{Cutoff: cutoff.Add(time.Second), Limit: 1, Cursor: firstPage.NextCursor}); model.ErrorCodeOf(err) != model.CodeInvalidOptions {
		t.Fatalf("cursor accepted with another cutoff: %v", err)
	}
	secondPage, err := store.RunReportRetention(ctx, retention.Request{Cutoff: cutoff, Limit: 1, Cursor: firstPage.NextCursor})
	if err != nil || secondPage.Protected != 1 || !secondPage.Complete {
		t.Fatalf("second retention page = %#v, %v", secondPage, err)
	}
	preview, err := store.RunReportRetention(ctx, retention.Request{Cutoff: cutoff, Limit: 10})
	if err != nil || preview.Eligible != 1 || preview.Protected != 1 || preview.Deleted != 0 || !preview.Complete {
		t.Fatalf("preview = %#v, %v", preview, err)
	}
	if _, err := store.LoadReport(ctx, "expired"); err != nil {
		t.Fatalf("dry run deleted report: %v", err)
	}
	cancelled, stop := context.WithCancel(ctx)
	stop()
	if _, err := store.RunReportRetention(cancelled, retention.Request{Cutoff: cutoff, Limit: 10, Apply: true}); err == nil {
		t.Fatal("cancelled retention applied a page")
	}
	apply, err := store.RunReportRetention(ctx, retention.Request{Cutoff: cutoff, Limit: 10, Apply: true})
	if err != nil || apply.Eligible != 1 || apply.Protected != 1 || apply.Deleted != 1 {
		t.Fatalf("apply = %#v, %v", apply, err)
	}
	if _, err := store.LoadReport(ctx, "expired"); model.ErrorCodeOf(err) != model.CodeNotFound {
		t.Fatalf("expired result lookup = %v", err)
	}
	if _, err := store.ObservationPage(ctx, app.ObservationPageQuery{ReportID: "expired", Limit: 1}); model.ErrorCodeOf(err) != model.CodeNotFound {
		t.Fatalf("expired observation page = %v", err)
	}
	var observations int
	if err := store.pool.QueryRow(ctx, `SELECT count(*) FROM observations WHERE report_id='expired'`).Scan(&observations); err != nil || observations != 0 {
		t.Fatalf("expired observations = %d, %v", observations, err)
	}
	var terminalLink *string
	if err := store.pool.QueryRow(ctx, `SELECT report_id FROM job_targets WHERE id='terminal-target'`).Scan(&terminalLink); err != nil || terminalLink != nil {
		t.Fatalf("terminal job link = %v, %v", terminalLink, err)
	}
	if _, err := store.LoadReport(ctx, "replay-base"); err != nil {
		t.Fatalf("retained replay lost source: %v", err)
	}
	again, err := store.RunReportRetention(ctx, retention.Request{Cutoff: cutoff, Limit: 10, Apply: true})
	if err != nil || again.Deleted != 0 || again.Protected != 1 {
		t.Fatalf("repeat cleanup = %#v, %v", again, err)
	}
}

func TestReportRetentionProtectsProjectionInventoryAndActiveReplay(t *testing.T) {
	dsn := os.Getenv("CLOUDATTRIB_POSTGRES_TEST_DSN")
	if dsn == "" {
		t.Skip("CLOUDATTRIB_POSTGRES_TEST_DSN is not set")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	store, err := Open(ctx, dsn, 100)
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
	old := time.Now().UTC().Add(-45 * 24 * time.Hour)
	cutoff := time.Now().UTC().Add(-30 * 24 * time.Hour)
	domain := model.Report{ID: "inventory-supported", SchemaVersion: model.SchemaVersion,
		Target: model.Target{Canonical: "api.example.com", Kind: model.TargetDomain}, Mode: model.ModeDNS,
		StartedAt: old, EndedAt: old, ClassifiedAt: old, Status: model.StatusComplete,
		Observations: []model.Observation{{ID: "inventory-dns", Type: "dns_query", Subject: "api.example.com", ObservedAt: old,
			Status: "answered", Payload: model.JSONValue(`{"rrtype":"A","owner":"api.example.com"}`)}},
	}
	if err := store.SaveReport(ctx, domain); err != nil {
		t.Fatal(err)
	}
	base := model.Report{ID: "queued-replay-input", SchemaVersion: model.SchemaVersion,
		Target: model.Target{Canonical: "198.51.100.7", Kind: model.TargetIP}, Mode: model.ModeIP,
		StartedAt: old, EndedAt: old, ClassifiedAt: old, Status: model.StatusComplete,
	}
	if err := store.SaveReport(ctx, base); err != nil {
		t.Fatal(err)
	}
	if _, err := store.pool.Exec(ctx, `UPDATE reports SET created_at=$1 WHERE id IN ($2,$3)`, old, domain.ID, base.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.pool.Exec(ctx, `INSERT INTO dataset_bundles(bundle_id,manifest,compatible,available) VALUES('retention-rules','{}',true,true)
		ON CONFLICT (bundle_id) DO UPDATE SET compatible=true,available=true`); err != nil {
		t.Fatal(err)
	}
	job, err := store.Submit(ctx, jobs.SubmitRequest{OperatorID: "operator", IdempotencyKey: "replay-key", BundleID: "retention-rules",
		Reclassifications: []model.ReclassifyRequest{{ReportID: base.ID, BundleID: "retention-rules"}}})
	if err != nil {
		t.Fatal(err)
	}
	preview, err := store.RunReportRetention(ctx, retention.Request{Cutoff: cutoff, Limit: 10})
	if err != nil || preview.Protected != 2 || preview.Eligible != 0 {
		t.Fatalf("pending and queued protection = %#v, %v", preview, err)
	}
	if preview.Items[0].Protection != "pending_projection" || preview.Items[1].Protection != "active_reclassification" {
		t.Fatalf("protection reasons = %#v", preview.Items)
	}
	if processed, err := store.ProcessNextInventoryProjection(ctx); err != nil || !processed {
		t.Fatalf("project inventory report = %t, %v", processed, err)
	}
	protected, err := store.RunReportRetention(ctx, retention.Request{Cutoff: cutoff, Limit: 10})
	if err != nil || protected.Protected != 2 || protected.Items[0].Protection != "inventory_evidence" {
		t.Fatalf("projected evidence protection = %#v, %v", protected, err)
	}
	if err := store.RequestCancel(ctx, job.ID, "operator"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.pool.Exec(ctx, `DELETE FROM inventory_assets WHERE hostname='api.example.com'`); err != nil {
		t.Fatal(err)
	}
	apply, err := store.RunReportRetention(ctx, retention.Request{Cutoff: cutoff, Limit: 10, Apply: true})
	if err != nil || apply.Deleted != 2 || apply.Protected != 0 {
		t.Fatalf("released protection cleanup = %#v, %v", apply, err)
	}
}

func TestReportRetentionSerializesReplayAdmission(t *testing.T) {
	dsn := os.Getenv("CLOUDATTRIB_POSTGRES_TEST_DSN")
	if dsn == "" {
		t.Skip("CLOUDATTRIB_POSTGRES_TEST_DSN is not set")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	store, err := Open(ctx, dsn, 100)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(store.Close)
	if _, err := store.pool.Exec(ctx, `TRUNCATE inventory_import_chunks,inventory_tombstones,inventory_assets,inventory_scopes,
		inventory_projection_tasks,inventory_context_support,inventory_asset_contexts,inventory_dns_state,
		finding_evidence,findings,evidence,observations,job_targets,reports,bundle_pins,jobs,ct_records,ct_checkpoints CASCADE;
		UPDATE queue_capacity SET reserved_targets=0 WHERE singleton=true;
		INSERT INTO dataset_bundles(bundle_id,manifest,compatible,available) VALUES('retention-race-rules','{}',true,true)
		ON CONFLICT (bundle_id) DO UPDATE SET compatible=true,available=true`); err != nil {
		t.Fatal(err)
	}
	old := time.Now().UTC().Add(-45 * 24 * time.Hour)
	base := model.Report{ID: "race-source", SchemaVersion: model.SchemaVersion,
		Target: model.Target{Canonical: "198.51.100.7", Kind: model.TargetIP}, Mode: model.ModeIP,
		StartedAt: old, EndedAt: old, ClassifiedAt: old, Status: model.StatusComplete,
	}
	if err := store.SaveReport(ctx, base); err != nil {
		t.Fatal(err)
	}
	if _, err := store.pool.Exec(ctx, `UPDATE reports SET created_at=$2 WHERE id=$1`, base.ID, old); err != nil {
		t.Fatal(err)
	}
	locked := make(chan struct{})
	release := make(chan struct{})
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
	}()
	store.transactionHooks = &transactionHooks{afterReplaySourceLock: func(string) {
		close(locked)
		<-release
	}}
	jobResult := make(chan error, 1)
	go func() {
		_, err := store.Submit(ctx, jobs.SubmitRequest{OperatorID: "operator", IdempotencyKey: "race-replay", BundleID: "retention-race-rules",
			Reclassifications: []model.ReclassifyRequest{{ReportID: base.ID, BundleID: "retention-race-rules"}}})
		jobResult <- err
	}()
	select {
	case <-locked:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	pageResult := make(chan struct {
		page retention.Page
		err  error
	}, 1)
	go func() {
		page, err := store.RunReportRetention(ctx, retention.Request{Cutoff: time.Now().UTC().Add(-30 * 24 * time.Hour), Limit: 10, Apply: true})
		pageResult <- struct {
			page retention.Page
			err  error
		}{page, err}
	}()
	close(release)
	if err := <-jobResult; err != nil {
		t.Fatalf("replay admission = %v", err)
	}
	result := <-pageResult
	if result.err != nil || result.page.Protected != 1 || result.page.Deleted != 0 || result.page.Items[0].Protection != "active_reclassification" {
		t.Fatalf("retention raced admission = %#v, %v", result.page, result.err)
	}
	if _, err := store.LoadReport(ctx, base.ID); err != nil {
		t.Fatalf("accepted replay source was removed: %v", err)
	}
}
