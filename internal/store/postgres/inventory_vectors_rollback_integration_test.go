package postgres

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"cloudattrib/internal/inventory"
	"cloudattrib/internal/model"
)

func TestInventoryEmbeddingRollbackRequeuesChangedDescriptions(t *testing.T) {
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
	if err := store.EnableInventoryVectors(ctx); err != nil {
		t.Fatal(err)
	}
	if err := store.RegisterInventoryScopes(ctx, []string{"example.com"}); err != nil {
		t.Fatal(err)
	}
	stamp := time.Now().UnixNano()
	hostname := fmt.Sprintf("rollback-%d.example.com", stamp)
	report := model.Report{ID: fmt.Sprintf("rollback-report-%d", stamp), SchemaVersion: model.SchemaVersion,
		Target: model.Target{Canonical: hostname, Kind: model.TargetDomain}, Mode: model.ModeDNS,
		StartedAt: time.Now().UTC(), EndedAt: time.Now().UTC(), ClassifiedAt: time.Now().UTC(), Status: model.StatusComplete,
		Observations: []model.Observation{{ID: "dns", Type: "dns_query", Subject: hostname,
			ObservedAt: time.Now().UTC(), Status: "answered", Payload: model.JSONValue(`{"rrtype":"A","owner":"` + hostname + `"}`)}},
	}
	if err := store.SaveReport(ctx, report); err != nil {
		t.Fatal(err)
	}
	if processed, err := store.ProcessNextInventoryProjection(ctx); err != nil || !processed {
		t.Fatalf("projection = %t, %v", processed, err)
	}
	var eligible int64
	if err := store.pool.QueryRow(ctx, `SELECT count(*) FROM inventory_asset_contexts WHERE description_hash<>''`).Scan(&eligible); err != nil {
		t.Fatal(err)
	}
	makeGeneration := func(suffix string) inventory.EmbeddingGeneration {
		return inventory.EmbeddingGeneration{ID: fmt.Sprintf("rollback-%d-%s", stamp, suffix), ModelID: "fixture",
			ModelRevision: suffix, ArtifactSHA256: strings.Repeat("a", 64), License: "MIT", Dimensions: 3,
			DocumentFormatVersion: inventory.DescriptionFormatVersion, Preprocessing: "fixture-v1", Metric: "cosine"}
	}
	first, second := makeGeneration("first"), makeGeneration("second")
	for _, generation := range []inventory.EmbeddingGeneration{first, second} {
		t.Cleanup(func() {
			_, _ = store.pool.Exec(context.Background(), `DELETE FROM inventory_embedding_generations WHERE generation_id=$1`, generation.ID)
		})
		queued, err := store.BeginInventoryEmbeddingGeneration(ctx, generation)
		if err != nil || queued != eligible {
			t.Fatalf("begin %s queued=%d error=%v", generation.ID, queued, err)
		}
		for i := int64(0); i < queued; i++ {
			processed, err := store.ProcessNextInventoryEmbedding(ctx, generation.ID, fixtureEmbedder(func(context.Context, string) ([]float32, error) { return []float32{1, 0, 0}, nil }))
			if err != nil || !processed {
				t.Fatalf("embed %s = %t, %v", generation.ID, processed, err)
			}
		}
		if _, err := store.ActivateInventoryEmbeddingGeneration(ctx, generation.ID); err != nil {
			t.Fatal(err)
		}
	}
	retained, err := store.InventoryEmbeddingCoverage(ctx, first.ID)
	if err != nil || retained.Status != "retained" || retained.RollbackUntil == nil || retained.RollbackUntil.Before(time.Now()) {
		t.Fatalf("retained generation status = %#v, %v", retained, err)
	}
	if _, err := store.pool.Exec(ctx, `UPDATE inventory_embedding_generations SET retained_at=clock_timestamp()-interval '8 days' WHERE generation_id=$1`, first.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.RollbackInventoryEmbeddingGeneration(ctx, first.ID); model.ErrorCodeOf(err) != model.CodeCapabilityUnavailable {
		t.Fatalf("expired rollback = %v", err)
	}
	if _, err := store.pool.Exec(ctx, `UPDATE inventory_embedding_generations SET retained_at=clock_timestamp() WHERE generation_id=$1`, first.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.pool.Exec(ctx, `UPDATE inventory_asset_contexts SET description='revised',description_hash='revised-hash',description_revision=description_revision+1 WHERE asset_id=$1`, inventory.AssetID(hostname)); err != nil {
		t.Fatal(err)
	}
	coverage, err := store.RollbackInventoryEmbeddingGeneration(ctx, first.ID)
	if err != nil || coverage.Eligible != eligible || coverage.Current != eligible-1 || coverage.Pending != 1 {
		t.Fatalf("rollback coverage=%#v error=%v", coverage, err)
	}
	active, err := store.ActiveEmbeddingGeneration(ctx)
	if err != nil || active.ID != first.ID {
		t.Fatalf("active after rollback = %#v, %v", active, err)
	}
	var status, hash string
	if err := store.pool.QueryRow(ctx, `SELECT status,description_hash FROM inventory_embedding_tasks WHERE generation_id=$1 AND asset_id=$2`, first.ID, inventory.AssetID(hostname)).Scan(&status, &hash); err != nil || status != "pending" || hash != "revised-hash" {
		t.Fatalf("requeued task = %q %q %v", status, hash, err)
	}
	processed, err := store.ProcessNextInventoryEmbedding(ctx, first.ID, fixtureEmbedder(func(_ context.Context, text string) ([]float32, error) {
		if text != "revised" {
			t.Fatalf("rollback input = %q", text)
		}
		return []float32{0, 1, 0}, nil
	}))
	if err != nil || !processed {
		t.Fatalf("rollback rebuild = %t, %v", processed, err)
	}
	coverage, err = store.InventoryEmbeddingCoverage(ctx, first.ID)
	if err != nil || coverage.Current != eligible || coverage.Pending != 0 {
		t.Fatalf("rebuilt coverage=%#v error=%v", coverage, err)
	}
	if err := store.PruneInventoryEmbeddingGeneration(ctx, first.ID); model.ErrorCodeOf(err) != model.CodeCapabilityUnavailable {
		t.Fatalf("active generation pruning = %v", err)
	}
	if err := store.PruneInventoryEmbeddingGeneration(ctx, second.ID); model.ErrorCodeOf(err) != model.CodeCapabilityUnavailable {
		t.Fatalf("unexpired retained generation pruning = %v", err)
	}
	if _, err := store.pool.Exec(ctx, `UPDATE inventory_embedding_generations SET retained_at=clock_timestamp()-interval '8 days' WHERE generation_id=$1`, second.ID); err != nil {
		t.Fatal(err)
	}
	if err := store.PruneInventoryEmbeddingGeneration(ctx, second.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.InventoryEmbeddingCoverage(ctx, second.ID); model.ErrorCodeOf(err) != model.CodeNotFound {
		t.Fatalf("pruned generation lookup = %v", err)
	}
	var remaining int
	if err := store.pool.QueryRow(ctx, `SELECT count(*) FROM inventory_embeddings WHERE generation_id=$1`, second.ID).Scan(&remaining); err != nil || remaining != 0 {
		t.Fatalf("pruned vector count=%d error=%v", remaining, err)
	}
}
