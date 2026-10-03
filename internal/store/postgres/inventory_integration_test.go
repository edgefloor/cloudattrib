package postgres

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"cloudattrib/internal/ctlog"
	"cloudattrib/internal/inventory"
	"cloudattrib/internal/jobs"
	"cloudattrib/internal/model"
)

func TestInventoryImportSearchAndCTCommit(t *testing.T) {
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
	if _, err := store.pool.Exec(ctx, `TRUNCATE inventory_import_chunks,inventory_tombstones,inventory_assets,inventory_scopes,ct_records,ct_checkpoints CASCADE`); err != nil {
		t.Fatal(err)
	}
	service := inventory.NewService(store)
	old := time.Unix(10, 0).UTC()
	request := inventory.ImportRequest{OperationID: "fixture-inventory", ChunkID: "1", SourceID: "old-export",
		ScopeRoots: []string{"example.com", "dev.example.com"}, Entries: []inventory.Entry{
			{Hostname: "API.Dev.Example.Com.", ObservedAt: &old}, {Hostname: "api.dev.example.com"},
			{Hostname: "payments.example.com"}, {Hostname: "outside.example.net"}, {Hostname: "*.example.com"}, {Hostname: "bad name"},
		}}
	receipt, err := service.Import(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	if receipt.Counts.Accepted != 2 || receipt.Counts.Duplicate != 1 || receipt.Counts.Invalid != 1 || receipt.Counts.Wildcard != 1 || receipt.Counts.OutOfScope != 1 {
		t.Fatalf("counts = %#v", receipt.Counts)
	}
	again, err := service.Import(ctx, request)
	if err != nil || again != receipt {
		t.Fatalf("retry = %#v, %v", again, err)
	}
	request.Entries[0].Hostname = "changed.example.com"
	if _, err := service.Import(ctx, request); model.ErrorCodeOf(err) != model.CodeIdempotencyConflict {
		t.Fatalf("changed chunk error = %v", err)
	}
	asset, err := service.Read(ctx, "API.DEV.EXAMPLE.COM.")
	if err != nil {
		t.Fatal(err)
	}
	if asset.ID != inventory.AssetID("api.dev.example.com") || len(asset.Scopes) != 2 || len(asset.Sources) != 1 || asset.Sources[0].FirstObservedAt == nil || !asset.Sources[0].FirstObservedAt.Equal(old) {
		t.Fatalf("asset = %#v", asset)
	}
	unknown, err := service.Read(ctx, "payments.example.com")
	if err != nil || len(unknown.Sources) != 1 || unknown.Sources[0].FirstObservedAt != nil || unknown.Sources[0].LastObservedAt != nil {
		t.Fatalf("unknown source observation time = %#v, %v", unknown, err)
	}
	page, err := service.Search(ctx, inventory.SearchRequest{Mode: inventory.SearchDescendant, Query: "example.com", Limit: 1})
	if err != nil || len(page.Items) != 1 || page.NextCursor == "" {
		t.Fatalf("first page = %#v, %v", page, err)
	}
	second, err := service.Search(ctx, inventory.SearchRequest{Mode: inventory.SearchDescendant, Query: "example.com", Limit: 1, Cursor: page.NextCursor})
	if err != nil || len(second.Items) != 1 || second.Items[0].ID == page.Items[0].ID {
		t.Fatalf("second page = %#v, %v", second, err)
	}
	if _, err := service.Search(ctx, inventory.SearchRequest{Mode: inventory.SearchPartial, Query: "ap", Cursor: page.NextCursor}); model.ErrorCodeOf(err) != model.CodeInvalidOptions {
		t.Fatalf("invalid search error = %v", err)
	}
	for _, search := range []inventory.SearchRequest{
		{Mode: inventory.SearchExact, Query: "api.dev.example.com"},
		{Mode: inventory.SearchPrefix, Query: "api."},
		{Mode: inventory.SearchPartial, Query: "dev"},
		{Mode: inventory.SearchBrowse, ScopeRoot: "dev.example.com"},
	} {
		found, err := service.Search(ctx, search)
		if err != nil || len(found.Items) != 1 || found.Items[0].Hostname != "api.dev.example.com" {
			t.Fatalf("search %#v = %#v, %v", search, found, err)
		}
	}
	entryIndex := uint64(42)
	ctRecord := ctlog.Record{Name: "api.dev.example.com", CertificateHash: "cert-1", LogID: "log-1", EntryIndex: &entryIndex,
		CheckpointID: "checkpoint-1", LoggedAt: time.Unix(20, 0).UTC(), SourceID: "ct-log", Provenance: ctlog.ProvenanceVerifiedLog}
	checkpoint := ctlog.Checkpoint{LogID: "sha256:inventory-ct", NextIndex: 1, VerifiedTreeSize: 1, VerifiedRootHash: make([]byte, 32), KeyIdentity: "sha256:fixture"}
	if err := store.CommitCollection(ctx, []ctlog.Record{ctRecord}, checkpoint); err != nil {
		t.Fatal(err)
	}
	asset, err = service.Read(ctx, "api.dev.example.com")
	if err != nil || len(asset.Sources) != 2 {
		t.Fatalf("CT-linked asset = %#v, %v", asset, err)
	}
	var ctSource *inventory.Source
	for index := range asset.Sources {
		if asset.Sources[index].Kind == "ct" {
			ctSource = &asset.Sources[index]
		}
	}
	if ctSource == nil || ctSource.Reference != "cert-1" || ctSource.LogID != "log-1" || ctSource.EntryIndex != "42" || ctSource.CheckpointID != "checkpoint-1" {
		t.Fatalf("CT source references = %#v", ctSource)
	}
	loaded, err := store.LoadCheckpoint(ctx, checkpoint.LogID)
	if err != nil || loaded.NextIndex != 1 {
		t.Fatalf("checkpoint = %#v, %v", loaded, err)
	}
	regressed := checkpoint
	regressed.NextIndex = 0
	if err := store.CommitCollection(ctx, []ctlog.Record{{Name: "rollback.example.com", CertificateHash: "rollback-cert", SourceID: "ct-log", LoggedAt: old, Provenance: ctlog.ProvenanceVerifiedLog}}, regressed); model.ErrorCodeOf(err) != model.CodeIdempotencyConflict {
		t.Fatalf("regressed checkpoint error = %v", err)
	}
	if _, err := service.Read(ctx, "rollback.example.com"); model.ErrorCodeOf(err) != model.CodeNotFound {
		t.Fatalf("inventory publication survived rollback: %v", err)
	}
	archived, err := service.Archive(ctx, "api.dev.example.com", true)
	if err != nil || archived.ArchivedAt == nil {
		t.Fatalf("archive = %#v, %v", archived, err)
	}
	visible, err := service.Search(ctx, inventory.SearchRequest{Mode: inventory.SearchExact, Query: "api.dev.example.com"})
	if err != nil || len(visible.Items) != 0 {
		t.Fatalf("archived default visibility = %#v, %v", visible, err)
	}
	visible, err = service.Search(ctx, inventory.SearchRequest{Mode: inventory.SearchExact, Query: "api.dev.example.com", IncludeArchived: true})
	if err != nil || len(visible.Items) != 1 {
		t.Fatalf("archived explicit visibility = %#v, %v", visible, err)
	}
	if _, err := service.Delete(ctx, "api.dev.example.com", true); err != nil {
		t.Fatal(err)
	}
	if err := store.Import(ctx, []ctlog.Record{{Name: "api.dev.example.com", CertificateHash: "cert-2", LoggedAt: time.Unix(30, 0).UTC(), SourceID: "ct-log", Provenance: ctlog.ProvenanceVerifiedLog}}); err != nil {
		t.Fatal(err)
	}
	visible, err = service.Search(ctx, inventory.SearchRequest{Mode: inventory.SearchExact, Query: "api.dev.example.com", IncludeArchived: true})
	if err != nil || len(visible.Items) != 0 {
		t.Fatalf("suppressed rediscovery = %#v, %v", visible, err)
	}
	if _, err := service.Delete(ctx, "api.dev.example.com", false); err != nil {
		t.Fatal(err)
	}
	if err := store.Import(ctx, []ctlog.Record{{Name: "api.dev.example.com", CertificateHash: "cert-3", LoggedAt: time.Unix(40, 0).UTC(), SourceID: "ct-log", Provenance: ctlog.ProvenanceVerifiedLog}}); err != nil {
		t.Fatal(err)
	}
	asset, err = service.Read(ctx, "api.dev.example.com")
	if err != nil || asset.DeletionGeneration != 2 || len(asset.Sources) != 1 {
		t.Fatalf("rediscovered asset = %#v, %v", asset, err)
	}
}

func TestInventoryBackfillHistoricalCTPages(t *testing.T) {
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
	if _, err := store.pool.Exec(ctx, `TRUNCATE inventory_import_chunks,inventory_tombstones,inventory_assets,inventory_scopes,ct_records,ct_checkpoints CASCADE`); err != nil {
		t.Fatal(err)
	}
	old := time.Unix(5, 0).UTC()
	for _, name := range []string{"a.example.com", "b.example.com", "*.example.com"} {
		wildcard := name[0] == '*'
		if _, err := store.pool.Exec(ctx, `INSERT INTO ct_records(name,certificate_hash,source_id,wildcard,logged_at,provenance,document)
			VALUES($1,'historical-cert','historical-log',$2,$3,'imported_unverified','{}'::jsonb)`, name, wildcard, old); err != nil {
			t.Fatal(err)
		}
	}
	first, err := store.BackfillCTInventory(ctx, "", 1)
	if err != nil || first.Processed != 1 || first.Complete || first.NextCursor == "" {
		t.Fatalf("first backfill page = %#v, %v", first, err)
	}
	second, err := store.BackfillCTInventory(ctx, first.NextCursor, 1)
	if err != nil || second.Processed != 1 || !second.Complete {
		t.Fatalf("second backfill page = %#v, %v", second, err)
	}
	for _, name := range []string{"a.example.com", "b.example.com"} {
		asset, err := inventory.NewService(store).Read(ctx, name)
		if err != nil || len(asset.Sources) != 1 || asset.Sources[0].FirstObservedAt == nil || !asset.Sources[0].FirstObservedAt.Equal(old) {
			t.Fatalf("backfilled %s = %#v, %v", name, asset, err)
		}
	}
	if err := store.RegisterInventoryScopes(ctx, []string{"example.com"}); err != nil {
		t.Fatal(err)
	}
	backfilled, err := inventory.NewService(store).Read(ctx, "a.example.com")
	if err != nil || len(backfilled.Scopes) != 1 || backfilled.Scopes[0] != "example.com" {
		t.Fatalf("registered CT scope = %#v, %v", backfilled, err)
	}
	page, err := inventory.NewService(store).Search(ctx, inventory.SearchRequest{Mode: inventory.SearchBrowse})
	if err != nil || len(page.Items) != 2 {
		t.Fatalf("wildcard backfill page = %#v, %v", page, err)
	}
	if _, err := store.BackfillCTInventory(ctx, "broken", 1); model.ErrorCodeOf(err) != model.CodeInvalidOptions {
		t.Fatalf("invalid cursor = %v", err)
	}
}

func TestInventoryChunkRollbackBeforeCommit(t *testing.T) {
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
	if _, err := store.pool.Exec(ctx, `TRUNCATE inventory_import_chunks,inventory_tombstones,inventory_assets,inventory_scopes CASCADE`); err != nil {
		t.Fatal(err)
	}
	interrupted := errors.New("interrupted before commit")
	store.transactionHooks = &transactionHooks{beforeInventoryCommit: func() error { return interrupted }}
	service := inventory.NewService(store)
	request := inventory.ImportRequest{OperationID: "rollback", ChunkID: "1", SourceID: "fixture", ScopeRoots: []string{"example.com"}, Entries: []inventory.Entry{{Hostname: "rollback.example.com"}}}
	if _, err := service.Import(ctx, request); !errors.Is(err, interrupted) {
		t.Fatalf("interrupted import = %v", err)
	}
	if _, err := service.Read(ctx, "rollback.example.com"); model.ErrorCodeOf(err) != model.CodeNotFound {
		t.Fatalf("asset survived rollback: %v", err)
	}
	var chunks int
	if err := store.pool.QueryRow(ctx, `SELECT count(*) FROM inventory_import_chunks WHERE operation_id='rollback'`).Scan(&chunks); err != nil || chunks != 0 {
		t.Fatalf("receipt survived rollback: count=%d error=%v", chunks, err)
	}
	store.transactionHooks = nil
	if _, err := service.Import(ctx, request); err != nil {
		t.Fatalf("retry after rollback = %v", err)
	}
}

func TestInventoryScopeRegistrationRacesCTPublication(t *testing.T) {
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
	if _, err := store.pool.Exec(ctx, `TRUNCATE inventory_import_chunks,inventory_tombstones,inventory_assets,inventory_scopes,ct_records,ct_checkpoints CASCADE`); err != nil {
		t.Fatal(err)
	}
	for iteration := range 20 {
		root := fmt.Sprintf("r%d.example.com", iteration)
		hostname := "host." + root
		start := make(chan struct{})
		var wait sync.WaitGroup
		failures := make(chan error, 2)
		wait.Add(2)
		go func() { defer wait.Done(); <-start; failures <- store.RegisterInventoryScopes(ctx, []string{root}) }()
		go func() {
			defer wait.Done()
			<-start
			failures <- store.Import(ctx, []ctlog.Record{{Name: hostname, CertificateHash: fmt.Sprintf("cert-%d", iteration), SourceID: "race-log", LoggedAt: time.Unix(10, 0).UTC(), Provenance: ctlog.ProvenanceVerifiedLog}})
		}()
		close(start)
		wait.Wait()
		close(failures)
		for err := range failures {
			if err != nil {
				t.Fatal(err)
			}
		}
		asset, err := inventory.NewService(store).Read(ctx, hostname)
		if err != nil || len(asset.Scopes) != 1 || asset.Scopes[0] != root {
			t.Fatalf("iteration %d scope=%#v error=%v", iteration, asset.Scopes, err)
		}
	}
}

func TestInventoryDeletionInvalidatesOlderImport(t *testing.T) {
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
	if _, err := store.pool.Exec(ctx, `TRUNCATE inventory_import_chunks,inventory_tombstones,inventory_assets,inventory_scopes CASCADE`); err != nil {
		t.Fatal(err)
	}
	service := inventory.NewService(store)
	store.transactionHooks = &transactionHooks{beforeInventoryPublish: func() error {
		_, err := store.DeleteInventory(ctx, "stale.example.com", false)
		return err
	}}
	request := inventory.ImportRequest{OperationID: "old", ChunkID: "1", SourceID: "fixture", ScopeRoots: []string{"example.com"}, Entries: []inventory.Entry{{Hostname: "stale.example.com"}}}
	receipt, err := service.Import(ctx, request)
	if err != nil || receipt.Counts.Stale != 1 {
		t.Fatalf("stale import = %#v, %v", receipt, err)
	}
	if _, err := service.Read(ctx, "stale.example.com"); model.ErrorCodeOf(err) != model.CodeNotFound {
		t.Fatalf("old import resurrected asset: %v", err)
	}
	store.transactionHooks = nil
	request.OperationID = "new"
	receipt, err = service.Import(ctx, request)
	if err != nil || receipt.Counts.Accepted != 1 {
		t.Fatalf("new import = %#v, %v", receipt, err)
	}
}

func TestInventoryValidationAdmissionFreezesDeletionGeneration(t *testing.T) {
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
	if _, err := store.pool.Exec(ctx, `TRUNCATE inventory_import_chunks,inventory_tombstones,inventory_assets,inventory_scopes,job_targets,bundle_pins,jobs CASCADE; UPDATE queue_capacity SET reserved_targets=0 WHERE singleton=true`); err != nil {
		t.Fatal(err)
	}
	service := inventory.NewService(store)
	_, err = service.Import(ctx, inventory.ImportRequest{OperationID: "validation-fixture", ChunkID: "1", SourceID: "operator", ScopeRoots: []string{"example.com"}, Entries: []inventory.Entry{{Hostname: "api.example.com"}}})
	if err != nil {
		t.Fatal(err)
	}
	asset, err := service.Read(ctx, "api.example.com")
	if err != nil {
		t.Fatal(err)
	}
	validator := inventory.NewValidator(service, store, store)
	job, err := validator.Validate(ctx, "operator", inventory.ValidationRequest{IdempotencyKey: "validation-fixture", Mode: model.ModeDNS, AssetIDs: []string{asset.ID}})
	if err != nil {
		t.Fatal(err)
	}
	var selectedID string
	var selectedGeneration int64
	if err := store.pool.QueryRow(ctx, `SELECT inventory_asset_id,inventory_deletion_generation FROM job_targets WHERE job_id=$1`, job.ID).Scan(&selectedID, &selectedGeneration); err != nil {
		t.Fatal(err)
	}
	if selectedID != asset.ID || selectedGeneration != asset.DeletionGeneration {
		t.Fatalf("frozen selection = %q/%d; asset = %q/%d", selectedID, selectedGeneration, asset.ID, asset.DeletionGeneration)
	}
	if _, err := service.Delete(ctx, asset.Hostname, false); err != nil {
		t.Fatal(err)
	}
	_, err = store.Submit(ctx, jobs.SubmitRequest{OperatorID: "operator", IdempotencyKey: "stale-validation", Targets: []model.AnalyzeRequest{{Target: asset.Hostname, Kind: model.TargetDomain, Mode: model.ModeDNS}}, InventorySelections: []jobs.InventorySelection{{AssetID: asset.ID, DeletionGeneration: selectedGeneration}}})
	if model.ErrorCodeOf(err) != model.CodeNotFound {
		t.Fatalf("admitted deleted asset: %v", err)
	}
}
