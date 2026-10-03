package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"cloudattrib/internal/embedding"
	"cloudattrib/internal/inventory"
	"cloudattrib/internal/jobs"
	"cloudattrib/internal/model"
)

type fixtureEmbedder func(context.Context, string) ([]float32, error)

func (embed fixtureEmbedder) Embed(ctx context.Context, text string) ([]float32, error) {
	return embed(ctx, text)
}

func TestPostgresTargetCompletionWhileEmbeddingInferenceRuns(t *testing.T) {
	store, ctx := openPostgresTest(t, 4)
	var available bool
	if err := store.pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_available_extensions WHERE name='vector')`).Scan(&available); err != nil {
		t.Fatal(err)
	}
	if !available {
		t.Skip("optional pgvector extension is unavailable")
	}
	if err := store.EnableInventoryVectors(ctx); err != nil {
		t.Fatal(err)
	}
	if err := store.RegisterInventoryScopes(ctx, []string{"example.com"}); err != nil {
		t.Fatal(err)
	}
	stamp := time.Now().UnixNano()
	hostname := fmt.Sprintf("embedding-work-%d.example.com", stamp)
	observed := time.Now().UTC()
	seed := model.Report{ID: fmt.Sprintf("embedding-work-report-%d", stamp), SchemaVersion: model.SchemaVersion,
		Target: model.Target{Canonical: hostname, Kind: model.TargetDomain}, Mode: model.ModeFull,
		StartedAt: observed, EndedAt: observed, ClassifiedAt: observed, Status: model.StatusComplete,
		Observations: []model.Observation{{ID: fmt.Sprintf("embedding-work-observation-%d", stamp), Type: "technology",
			Subject: hostname, ObservedAt: observed, Status: "detected", Payload: model.JSONValue(`{"name":"Grafana"}`)}},
	}
	if err := store.SaveReport(ctx, seed); err != nil {
		t.Fatal(err)
	}
	projected := false
	for range 50 {
		if _, err := store.ProcessNextInventoryProjection(ctx); err != nil {
			t.Fatal(err)
		}
		var count int
		if err := store.pool.QueryRow(ctx, `SELECT count(*) FROM inventory_asset_contexts WHERE asset_id=$1`, inventory.AssetID(hostname)).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count == 1 {
			projected = true
			break
		}
	}
	if !projected {
		t.Fatal("embedding fixture description was not projected")
	}
	generation := inventory.EmbeddingGeneration{ID: fmt.Sprintf("completion-probe-%d", stamp), ModelID: "fixture",
		ModelRevision: "v1", ArtifactSHA256: strings.Repeat("a", 64), License: "MIT", Dimensions: 3,
		DocumentFormatVersion: inventory.DescriptionFormatVersion, Preprocessing: "fixture-v1", Metric: "cosine"}
	if queued, err := store.BeginInventoryEmbeddingGeneration(ctx, generation); err != nil || queued < 1 {
		t.Fatalf("begin embedding work queued=%d: %v", queued, err)
	}
	t.Cleanup(func() {
		_, _ = store.pool.Exec(context.Background(), `DELETE FROM inventory_embedding_generations WHERE generation_id=$1`, generation.ID)
	})
	entered := make(chan struct{})
	release := make(chan struct{})
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	done := make(chan error, 1)
	t.Cleanup(func() {
		unblock()
		<-done
	})
	go func() {
		_, err := store.ProcessNextInventoryEmbedding(ctx, generation.ID, fixtureEmbedder(func(embedCtx context.Context, _ string) ([]float32, error) {
			close(entered)
			select {
			case <-release:
				return []float32{1, 0, 0}, nil
			case <-embedCtx.Done():
				return nil, embedCtx.Err()
			}
		}))
		done <- err
		close(done)
	}()
	select {
	case <-entered:
	case err := <-done:
		t.Fatalf("embedding inference stopped before it started: %v", err)
	case <-ctx.Done():
		t.Fatalf("embedding inference did not start: %v", ctx.Err())
	}

	operationCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	bundleID := fmt.Sprintf("completion-bundle-%d", stamp)
	if err := store.RegisterBundle(operationCtx, bundleID, []byte(`{"schema_version":1}`), true); err != nil {
		t.Fatal(err)
	}
	job, err := store.Submit(operationCtx, jobs.SubmitRequest{OperatorID: "operator", IdempotencyKey: bundleID,
		BundleID: bundleID, Targets: []model.AnalyzeRequest{{Target: "completion.example.com", Kind: model.TargetDomain}}})
	if err != nil {
		t.Fatal(err)
	}
	claim, err := store.Claim(operationCtx, "worker", time.Minute)
	if err != nil || claim.TargetID == "" {
		t.Fatalf("claim target during embedding inference: %#v, %v", claim, err)
	}
	completed := model.Report{ID: fmt.Sprintf("completion-report-%d", stamp), SchemaVersion: model.SchemaVersion,
		Target: model.Target{Original: "completion.example.com", Canonical: "completion.example.com", Kind: model.TargetDomain},
		Mode:   model.ModeFull, StartedAt: observed, EndedAt: observed, ClassifiedAt: observed,
		BundleID: bundleID, Status: model.StatusComplete}
	if err := store.Complete(operationCtx, claim.TargetID, claim.AttemptToken, completed, jobs.TargetCompleted, ""); err != nil {
		t.Fatalf("complete target while embedding inference is active: %v", err)
	}
	if loaded, err := store.LoadReport(operationCtx, completed.ID); err != nil || loaded.ID != completed.ID || job.ID == "" {
		t.Fatalf("completed report = %#v, job = %#v, error = %v", loaded, job, err)
	}
	unblock()
	if err := <-done; err != nil {
		t.Fatalf("finish embedding work: %v", err)
	}
}

func TestInventoryRealLocalModelLifecycle(t *testing.T) {
	dsn := os.Getenv("CLOUDATTRIB_POSTGRES_TEST_DSN")
	contractPath := os.Getenv("CLOUDATTRIB_EMBEDDING_TEST_CONTRACT")
	socketDirectory := os.Getenv("CLOUDATTRIB_EMBEDDING_TEST_SOCKET_DIR")
	if dsn == "" || contractPath == "" || socketDirectory == "" {
		t.Skip("real local model and PostgreSQL test configuration is not set")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	encoded, err := os.ReadFile(contractPath)
	if err != nil {
		t.Fatal(err)
	}
	var generation inventory.EmbeddingGeneration
	if err := json.Unmarshal(encoded, &generation); err != nil {
		t.Fatal(err)
	}
	provider, err := embedding.NewProvider(socketDirectory)
	if err != nil {
		t.Fatal(err)
	}
	embedder, err := provider.ForGeneration(ctx, generation)
	if err != nil {
		t.Fatal(err)
	}
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
	hostname := fmt.Sprintf("real-model-%d.example.com", stamp)
	report := model.Report{ID: fmt.Sprintf("real-model-report-%d", stamp), SchemaVersion: model.SchemaVersion,
		Target: model.Target{Canonical: hostname, Kind: model.TargetDomain}, Mode: model.ModeFull,
		StartedAt: time.Now().UTC(), EndedAt: time.Now().UTC(), ClassifiedAt: time.Now().UTC(), Status: model.StatusComplete,
		Observations: []model.Observation{{ID: "real-technology", Type: "technology", Subject: hostname,
			ObservedAt: time.Now().UTC(), Status: "detected", Payload: model.JSONValue(`{"name":"Grafana"}`)}},
	}
	if err := store.SaveReport(ctx, report); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 20; i++ {
		if _, err := store.ProcessNextInventoryProjection(ctx); err != nil {
			t.Fatal(err)
		}
		var count int
		if err := store.pool.QueryRow(ctx, `SELECT count(*) FROM inventory_asset_contexts WHERE asset_id=$1`, inventory.AssetID(hostname)).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count == 1 {
			break
		}
	}
	queued, err := store.BeginInventoryEmbeddingGeneration(ctx, generation)
	if err != nil || queued < 1 {
		t.Fatalf("begin real model generation queued=%d error=%v", queued, err)
	}
	t.Cleanup(func() {
		_, _ = store.pool.Exec(context.Background(), `DELETE FROM inventory_embedding_generations WHERE generation_id=$1`, generation.ID)
	})
	for i := int64(0); i < queued; i++ {
		if processed, err := store.ProcessNextInventoryEmbedding(ctx, generation.ID, embedder); err != nil || !processed {
			t.Fatalf("real model indexing = %t, %v", processed, err)
		}
	}
	coverage, err := store.ActivateInventoryEmbeddingGeneration(ctx, generation.ID)
	if err != nil || coverage.Pending != 0 || coverage.Current != coverage.Eligible {
		t.Fatalf("real model activation coverage=%#v error=%v", coverage, err)
	}
	service := inventory.NewService(store).WithDefaultContext("unknown").WithEmbeddingProvider(provider)
	page, err := service.Retrieve(ctx, inventory.RetrievalRequest{Text: "monitoring dashboard", Mode: inventory.RetrievalSemantic,
		ScopeRoot: "example.com", Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, item := range page.Items {
		if item.Hostname == hostname && item.SemanticSimilarity != nil && item.ModelGeneration == generation.ID {
			found = true
		}
	}
	if !found || page.DegradedToLexical {
		t.Fatalf("real model retrieval = %#v", page)
	}
}

func TestInventoryVectorSetupIsOptional(t *testing.T) {
	dsn := os.Getenv("CLOUDATTRIB_POSTGRES_TEST_DSN")
	if dsn == "" {
		t.Skip("CLOUDATTRIB_POSTGRES_TEST_DSN is not set")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	store, err := Open(ctx, dsn, 2000)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(store.Close)
	var metadataExists, vectorTableExists bool
	if err := store.pool.QueryRow(ctx, `SELECT to_regclass('inventory_embedding_tasks') IS NOT NULL,
		to_regclass('inventory_embeddings') IS NOT NULL`).Scan(&metadataExists, &vectorTableExists); err != nil {
		t.Fatal(err)
	}
	if !metadataExists {
		t.Fatal("ordinary migration omitted durable embedding work metadata")
	}
	var available bool
	if err := store.pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_available_extensions WHERE name='vector' AND default_version=$1)`, inventoryVectorExtensionVersion).Scan(&available); err != nil {
		t.Fatal(err)
	}
	if !available {
		if vectorTableExists {
			t.Fatal("vector table exists without compatible extension")
		}
		if err := store.EnableInventoryVectors(ctx); model.ErrorCodeOf(err) != model.CodeCapabilityUnavailable {
			t.Fatalf("optional setup without extension: %v", err)
		}
		return
	}
	if err := store.EnableInventoryVectors(ctx); err != nil {
		t.Fatal(err)
	}
	if err := store.EnableInventoryVectors(ctx); err != nil {
		t.Fatalf("repeated vector setup: %v", err)
	}
	if err := store.pool.QueryRow(ctx, `SELECT to_regclass('inventory_embeddings') IS NOT NULL`).Scan(&vectorTableExists); err != nil || !vectorTableExists {
		t.Fatalf("vector table exists=%t error=%v", vectorTableExists, err)
	}
}

func TestInventoryEmbeddingGenerationCapturesExistingAndFutureDescriptions(t *testing.T) {
	dsn := os.Getenv("CLOUDATTRIB_POSTGRES_TEST_DSN")
	if dsn == "" {
		t.Skip("CLOUDATTRIB_POSTGRES_TEST_DSN is not set")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	store, err := Open(ctx, dsn, 2000)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(store.Close)
	var available bool
	if err := store.pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_available_extensions WHERE name='vector' AND default_version=$1)`, inventoryVectorExtensionVersion).Scan(&available); err != nil {
		t.Fatal(err)
	}
	if !available {
		t.Skip("pinned pgvector extension is not available")
	}
	if err := store.EnableInventoryVectors(ctx); err != nil {
		t.Fatal(err)
	}
	if err := store.RegisterInventoryScopes(ctx, []string{"example.com"}); err != nil {
		t.Fatal(err)
	}
	stamp := time.Now().UnixNano()
	hostname := fmt.Sprintf("vector-%d.example.com", stamp)
	report := model.Report{ID: fmt.Sprintf("vector-report-%d", stamp), SchemaVersion: model.SchemaVersion,
		Target: model.Target{Canonical: hostname, Kind: model.TargetDomain}, Mode: model.ModeDNS,
		StartedAt: time.Now().UTC(), EndedAt: time.Now().UTC(), ClassifiedAt: time.Now().UTC(), Status: model.StatusComplete,
		Observations: []model.Observation{{ID: "vector-dns", Type: "dns_query", Subject: hostname,
			ObservedAt: time.Now().UTC(), Status: "answered", Payload: model.JSONValue(`{"rrtype":"A","owner":"` + hostname + `"}`)}},
	}
	if err := store.SaveReport(ctx, report); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 20; i++ {
		if _, err := store.ProcessNextInventoryProjection(ctx); err != nil {
			t.Fatal(err)
		}
		var count int
		if err := store.pool.QueryRow(ctx, `SELECT count(*) FROM inventory_asset_contexts WHERE asset_id=$1`, inventory.AssetID(hostname)).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count == 1 {
			break
		}
	}
	var initialCount int64
	if err := store.pool.QueryRow(ctx, `SELECT count(*) FROM inventory_asset_contexts WHERE description_hash<>''`).Scan(&initialCount); err != nil {
		t.Fatal(err)
	}
	generationID := fmt.Sprintf("generation-%d", stamp)
	generation := inventory.EmbeddingGeneration{ID: generationID, ModelID: "fixture-model", ModelRevision: "fixture-revision",
		ArtifactSHA256: strings.Repeat("a", 64), License: "MIT", Dimensions: 3,
		DocumentFormatVersion: inventory.DescriptionFormatVersion, Preprocessing: "fixture-v1", Metric: "cosine"}
	t.Cleanup(func() {
		_, _ = store.pool.Exec(context.Background(), `DELETE FROM inventory_embedding_generations WHERE generation_id=$1`, generationID)
	})
	queued, err := store.BeginInventoryEmbeddingGeneration(ctx, generation)
	if err != nil || queued != initialCount {
		t.Fatalf("initial generation queued=%d want=%d error=%v", queued, initialCount, err)
	}
	if coverage, err := store.ActivateInventoryEmbeddingGeneration(ctx, generationID); model.ErrorCodeOf(err) != model.CodeCapabilityUnavailable || coverage.Pending == 0 {
		t.Fatalf("premature generation activation coverage=%#v error=%v", coverage, err)
	}
	if _, err := store.BeginInventoryEmbeddingGeneration(ctx, generation); model.ErrorCodeOf(err) != model.CodeIdempotencyConflict {
		t.Fatalf("reused generation ID: %v", err)
	}
	var count int
	if err := store.pool.QueryRow(ctx, `SELECT count(*) FROM inventory_embedding_tasks WHERE generation_id=$1 AND asset_id=$2`, generationID, inventory.AssetID(hostname)).Scan(&count); err != nil || count != 1 {
		t.Fatalf("initial task count=%d error=%v", count, err)
	}
	for i := int64(0); i < initialCount; i++ {
		processed, err := store.ProcessNextInventoryEmbedding(ctx, generationID, fixtureEmbedder(func(_ context.Context, text string) ([]float32, error) {
			if text == "" {
				t.Fatal("empty embedding input")
			}
			return []float32{1, 0, 0}, nil
		}))
		if err != nil || !processed {
			t.Fatalf("process initial embedding = %t, %v", processed, err)
		}
	}
	var distance float64
	if err := store.pool.QueryRow(ctx, `SELECT embedding <=> '[1,0,0]'::vector FROM inventory_embeddings
		WHERE generation_id=$1 AND asset_id=$2`, generationID, inventory.AssetID(hostname)).Scan(&distance); err != nil || distance != 0 {
		t.Fatalf("stored cosine distance=%v error=%v", distance, err)
	}
	var beforeRevision int64
	var beforeHash string
	if err := store.pool.QueryRow(ctx, `SELECT description_revision,description_hash FROM inventory_asset_contexts WHERE asset_id=$1`,
		inventory.AssetID(hostname)).Scan(&beforeRevision, &beforeHash); err != nil {
		t.Fatal(err)
	}
	repeated := report
	repeated.ID = fmt.Sprintf("vector-repeat-report-%d", stamp)
	repeated.ClassifiedAt = time.Now().UTC().Add(time.Second)
	repeated.Observations = append([]model.Observation(nil), report.Observations...)
	repeated.Observations[0].ID = fmt.Sprintf("vector-repeat-dns-%d", stamp)
	repeated.Observations[0].ObservedAt = repeated.ClassifiedAt
	if err := store.SaveReport(ctx, repeated); err != nil {
		t.Fatal(err)
	}
	for range 20 {
		if processed, err := store.ProcessNextInventoryProjection(ctx); err != nil || !processed {
			t.Fatalf("project unchanged description = %t, %v", processed, err)
		}
		var selected string
		if err := store.pool.QueryRow(ctx, `SELECT description_report_id FROM inventory_asset_contexts WHERE asset_id=$1`,
			inventory.AssetID(hostname)).Scan(&selected); err != nil {
			t.Fatal(err)
		}
		if selected == repeated.ID {
			break
		}
	}
	var afterRevision, vectorRevision int64
	var afterHash string
	if err := store.pool.QueryRow(ctx, `SELECT c.description_revision,c.description_hash,e.description_revision
		FROM inventory_asset_contexts c JOIN inventory_embeddings e USING (asset_id,context_id)
		WHERE c.asset_id=$1 AND e.generation_id=$2`, inventory.AssetID(hostname), generationID).
		Scan(&afterRevision, &afterHash, &vectorRevision); err != nil {
		t.Fatal(err)
	}
	if afterHash != beforeHash || afterRevision <= beforeRevision || vectorRevision != afterRevision {
		t.Fatalf("unchanged text lost current vector: before=(%d,%s) after=(%d,%s) vector=%d",
			beforeRevision, beforeHash, afterRevision, afterHash, vectorRevision)
	}
	futureHostname := fmt.Sprintf("vector-future-%d.example.com", stamp)
	future := report
	future.ID = fmt.Sprintf("vector-future-report-%d", stamp)
	future.Target.Canonical = futureHostname
	future.Observations = []model.Observation{{ID: "future-dns", Type: "dns_query", Subject: futureHostname,
		ObservedAt: time.Now().UTC(), Status: "answered", Payload: model.JSONValue(`{"rrtype":"A","owner":"` + futureHostname + `"}`)}}
	if err := store.SaveReport(ctx, future); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 20; i++ {
		if _, err := store.ProcessNextInventoryProjection(ctx); err != nil {
			t.Fatal(err)
		}
		if err := store.pool.QueryRow(ctx, `SELECT count(*) FROM inventory_embedding_tasks WHERE generation_id=$1 AND asset_id=$2`, generationID, inventory.AssetID(futureHostname)).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count == 1 {
			break
		}
	}
	if count != 1 {
		t.Fatal("future description was not queued for the building generation")
	}
	processed, err := store.ProcessNextInventoryEmbedding(ctx, generationID, fixtureEmbedder(func(_ context.Context, text string) ([]float32, error) {
		if !strings.Contains(text, futureHostname) {
			t.Fatalf("unexpected embedding input %q", text)
		}
		tx, err := store.pool.Begin(ctx)
		if err != nil {
			return nil, err
		}
		defer func() { _ = tx.Rollback(ctx) }()
		if _, err := tx.Exec(ctx, `UPDATE inventory_asset_contexts SET description='changed',description_hash='changed-hash',
			description_revision=description_revision+1 WHERE asset_id=$1`, inventory.AssetID(futureHostname)); err != nil {
			return nil, err
		}
		if _, err := tx.Exec(ctx, `UPDATE inventory_embedding_tasks SET description_hash='changed-hash',
			description_revision=description_revision+1,status='pending',lease_token=NULL,lease_expires_at=NULL
			WHERE asset_id=$1 AND generation_id=$2`, inventory.AssetID(futureHostname), generationID); err != nil {
			return nil, err
		}
		if err := tx.Commit(ctx); err != nil {
			return nil, err
		}
		return []float32{0, 1, 0}, nil
	}))
	if err != nil || !processed {
		t.Fatalf("stale inference = %t, %v", processed, err)
	}
	if err := store.pool.QueryRow(ctx, `SELECT count(*) FROM inventory_embeddings WHERE generation_id=$1 AND asset_id=$2`, generationID, inventory.AssetID(futureHostname)).Scan(&count); err != nil || count != 0 {
		t.Fatalf("stale vector count=%d error=%v", count, err)
	}
	processed, err = store.ProcessNextInventoryEmbedding(ctx, generationID, fixtureEmbedder(func(_ context.Context, text string) ([]float32, error) {
		if text != "changed" {
			t.Fatalf("retried embedding input %q", text)
		}
		return []float32{0, 1, 0}, nil
	}))
	if err != nil || !processed {
		t.Fatalf("retry current description = %t, %v", processed, err)
	}
	if err := store.pool.QueryRow(ctx, `SELECT embedding <=> '[0,1,0]'::vector FROM inventory_embeddings
		WHERE generation_id=$1 AND asset_id=$2`, generationID, inventory.AssetID(futureHostname)).Scan(&distance); err != nil || distance != 0 {
		t.Fatalf("current cosine distance=%v error=%v", distance, err)
	}
	deletedHostname := fmt.Sprintf("vector-deleted-%d.example.com", stamp)
	deleted := report
	deleted.ID = fmt.Sprintf("vector-deleted-report-%d", stamp)
	deleted.Target.Canonical = deletedHostname
	deleted.Observations = []model.Observation{{ID: "deleted-dns", Type: "dns_query", Subject: deletedHostname,
		ObservedAt: time.Now().UTC(), Status: "answered", Payload: model.JSONValue(`{"rrtype":"A","owner":"` + deletedHostname + `"}`)}}
	if err := store.SaveReport(ctx, deleted); err != nil {
		t.Fatal(err)
	}
	if processed, err := store.ProcessNextInventoryProjection(ctx); err != nil || !processed {
		t.Fatalf("project deletion target = %t, %v", processed, err)
	}
	processed, err = store.ProcessNextInventoryEmbedding(ctx, generationID, fixtureEmbedder(func(_ context.Context, text string) ([]float32, error) {
		if !strings.Contains(text, deletedHostname) {
			t.Fatalf("unexpected deletion target input %q", text)
		}
		_, err := inventory.NewService(store).Delete(ctx, deletedHostname, false)
		return []float32{0, 0, 1}, err
	}))
	if err != nil || !processed {
		t.Fatalf("deleted during inference = %t, %v", processed, err)
	}
	if err := store.pool.QueryRow(ctx, `SELECT count(*) FROM inventory_embeddings WHERE generation_id=$1 AND asset_id=$2`, generationID, inventory.AssetID(deletedHostname)).Scan(&count); err != nil || count != 0 {
		t.Fatalf("deleted vector count=%d error=%v", count, err)
	}
	if err := store.RegisterInventoryScopes(ctx, []string{"other.com"}); err != nil {
		t.Fatal(err)
	}
	outsideHostname := fmt.Sprintf("outsider-%d.other.com", stamp)
	outside := report
	outside.ID = fmt.Sprintf("vector-outside-report-%d", stamp)
	outside.Target.Canonical = outsideHostname
	outside.Observations = []model.Observation{{ID: "outside-dns", Type: "dns_query", Subject: outsideHostname,
		ObservedAt: time.Now().UTC(), Status: "answered", Payload: model.JSONValue(`{"rrtype":"A","owner":"` + outsideHostname + `"}`)}}
	if err := store.SaveReport(ctx, outside); err != nil {
		t.Fatal(err)
	}
	if processed, err := store.ProcessNextInventoryProjection(ctx); err != nil || !processed {
		t.Fatalf("project out-of-scope asset = %t, %v", processed, err)
	}
	if processed, err := store.ProcessNextInventoryEmbedding(ctx, generationID, fixtureEmbedder(func(_ context.Context, text string) ([]float32, error) {
		if !strings.Contains(text, outsideHostname) {
			t.Fatalf("unexpected out-of-scope embedding input %q", text)
		}
		return []float32{0, 0, 1}, nil
	})); err != nil || !processed {
		t.Fatalf("embed out-of-scope asset = %t, %v", processed, err)
	}
	coverage, err := store.ActivateInventoryEmbeddingGeneration(ctx, generationID)
	if err != nil || coverage.Pending != 0 || coverage.Current != coverage.Eligible || coverage.Eligible < 2 {
		t.Fatalf("generation activation coverage=%#v error=%v", coverage, err)
	}
	active, err := store.ActiveEmbeddingGeneration(ctx)
	if err != nil || active.ID != generationID {
		t.Fatalf("active generation = %#v, %v", active, err)
	}
	query := inventory.SemanticQuery{Vector: []float32{0, 0, 1}, GenerationID: generationID, ContextID: "unknown", Limit: 1}
	unscoped, err := store.SearchInventorySemantic(ctx, query)
	if err != nil || len(unscoped.Items) != 1 || unscoped.Items[0].Hostname != outsideHostname {
		t.Fatalf("unscoped nearest neighbor = %#v, %v", unscoped, err)
	}
	query.ScopeRoot = "example.com"
	scoped, err := store.SearchInventorySemantic(ctx, query)
	if err != nil || len(scoped.Items) != 1 || !inventory.WithinScope(scoped.Items[0].Hostname, "example.com") || scoped.Items[0].Hostname == outsideHostname {
		t.Fatalf("scope-filtered nearest neighbor = %#v, %v", scoped, err)
	}
	service := inventory.NewService(store).WithDefaultContext("unknown").WithEmbedder(generationID,
		fixtureEmbedder(func(_ context.Context, _ string) ([]float32, error) { return []float32{1, 0, 0}, nil }))
	pinned, err := service.Retrieve(ctx, inventory.RetrievalRequest{Text: futureHostname,
		Mode: inventory.RetrievalSemantic, ScopeRoot: "example.com", Limit: 1})
	if err != nil || len(pinned.Items) != 1 || pinned.Items[0].Hostname != futureHostname ||
		!slices.Contains(pinned.Items[0].MatchModes, "exact_hostname") || pinned.ModelGeneration != generationID {
		t.Fatalf("exact hostname precedence = %#v, %v", pinned, err)
	}
}
