package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"sync"
	"testing"
	"time"

	"cloudattrib/internal/embedding"
	"cloudattrib/internal/inventory"
)

// Run after loading the 10,000- or 100,000-asset capacity fixture into a disposable
// database. This deliberately uses the real worker and durable indexing path.
func TestInventoryRealModelCapacityQualification(t *testing.T) {
	if os.Getenv("CLOUDATTRIB_REAL_MODEL_CAPACITY_QUALIFY") != "1" {
		t.Skip("real model capacity qualification is opt-in")
	}
	dsn := os.Getenv("CLOUDATTRIB_POSTGRES_TEST_DSN")
	contractPath := os.Getenv("CLOUDATTRIB_EMBEDDING_TEST_CONTRACT")
	socketDirectory := os.Getenv("CLOUDATTRIB_EMBEDDING_TEST_SOCKET_DIR")
	if dsn == "" || contractPath == "" || socketDirectory == "" {
		t.Fatal("database, model contract, and private socket directory are required")
	}
	encoded, err := os.ReadFile(contractPath)
	if err != nil {
		t.Fatal(err)
	}
	var generation inventory.EmbeddingGeneration
	if err := json.Unmarshal(encoded, &generation); err != nil {
		t.Fatal(err)
	}
	if err := inventory.ValidateEmbeddingGeneration(generation); err != nil {
		t.Fatal(err)
	}
	expected := 10000
	if os.Getenv("CLOUDATTRIB_REAL_MODEL_CAPACITY_MAX") == "100000" {
		expected = 100000
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Minute)
	defer cancel()
	store, err := Open(ctx, dsn, 2000)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(store.Close)
	var assets, descriptions, existing int
	if err := store.pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM inventory_assets),
		(SELECT count(*) FROM inventory_asset_contexts),
		(SELECT count(*) FROM inventory_embedding_generations WHERE generation_id=$1)`, generation.ID).
		Scan(&assets, &descriptions, &existing); err != nil {
		t.Fatal(err)
	}
	if assets != expected || descriptions != expected || existing != 0 {
		t.Fatalf("qualification requires %d fixture assets and descriptions and a new generation: assets=%d descriptions=%d existing=%d", expected, assets, descriptions, existing)
	}
	provider, err := embedding.NewProvider(socketDirectory)
	if err != nil {
		t.Fatal(err)
	}
	embedder, err := provider.ForGeneration(ctx, generation)
	if err != nil {
		t.Fatal(err)
	}
	queued, err := store.BeginInventoryEmbeddingGeneration(ctx, generation)
	if err != nil || queued != int64(expected) {
		t.Fatalf("begin real model generation queued=%d: %v", queued, err)
	}
	started := time.Now()
	for processed := int64(0); processed < queued; processed++ {
		found, err := store.ProcessNextInventoryEmbedding(ctx, generation.ID, embedder)
		if err != nil || !found {
			t.Fatalf("real model indexing after %d documents found=%t: %v", processed, found, err)
		}
		if (processed+1)%1000 == 0 {
			t.Logf("real model indexed %d descriptions in %s", processed+1, time.Since(started))
		}
	}
	coverage, err := store.ActivateInventoryEmbeddingGeneration(ctx, generation.ID)
	if err != nil || coverage.Current != int64(expected) || coverage.Pending != 0 || coverage.Failed != 0 {
		t.Fatalf("real model activation coverage=%#v: %v", coverage, err)
	}
	var vectorBytes, databaseBytes int64
	if err := store.pool.QueryRow(ctx, `SELECT pg_total_relation_size('inventory_embeddings'),pg_database_size(current_database())`).
		Scan(&vectorBytes, &databaseBytes); err != nil {
		t.Fatal(err)
	}
	t.Logf("real model indexing %d descriptions: duration=%s vector table=%d bytes database=%d bytes",
		expected, time.Since(started), vectorBytes, databaseBytes)

	service := inventory.NewService(store).WithDefaultContext("unknown").WithEmbeddingProvider(provider)
	for _, mode := range []inventory.RetrievalMode{inventory.RetrievalSemantic, inventory.RetrievalHybrid} {
		request := inventory.RetrievalRequest{Text: "customer portal", Mode: mode, ScopeRoot: "example.com", Limit: 10}
		measurements := make([]time.Duration, 0, 50)
		var mu sync.Mutex
		var wg sync.WaitGroup
		failures := make(chan error, 10)
		for worker := 0; worker < 10; worker++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for range 5 {
					queryStarted := time.Now()
					page, err := service.Retrieve(ctx, request)
					if err != nil || len(page.Items) != 10 || page.DegradedToLexical || page.ModelGeneration != generation.ID {
						failures <- fmt.Errorf("%s returned %d items degraded=%t generation=%q: %w",
							mode, len(page.Items), page.DegradedToLexical, page.ModelGeneration, err)
						return
					}
					mu.Lock()
					measurements = append(measurements, time.Since(queryStarted))
					mu.Unlock()
				}
			}()
		}
		wg.Wait()
		close(failures)
		for failure := range failures {
			t.Error(failure)
		}
		if len(measurements) == 0 {
			t.Fatalf("%s returned no successful retrieval", mode)
		}
		slices.Sort(measurements)
		t.Logf("real model service %s, %d assets, 10 concurrent readers, %d queries: p50=%s p95=%s max=%s",
			mode, expected, len(measurements), measurements[len(measurements)/2],
			measurements[(len(measurements)*95+99)/100-1], measurements[len(measurements)-1])
	}
}

// Run after activating the 100,000-asset real-model generation. This query
// contains terms in the fixture description, so hybrid exercises both paths.
func TestInventoryRealModelQueryCapacityQualification(t *testing.T) {
	if os.Getenv("CLOUDATTRIB_REAL_MODEL_QUERY_QUALIFY") != "1" {
		t.Skip("real model query capacity qualification is opt-in")
	}
	dsn := os.Getenv("CLOUDATTRIB_POSTGRES_TEST_DSN")
	socketDirectory := os.Getenv("CLOUDATTRIB_EMBEDDING_TEST_SOCKET_DIR")
	if dsn == "" || socketDirectory == "" {
		t.Fatal("database and private socket directory are required")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Minute)
	defer cancel()
	store, err := Open(ctx, dsn, 2000)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(store.Close)
	generation, err := store.ActiveEmbeddingGeneration(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var assets, vectors int
	if err := store.pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM inventory_assets),
		(SELECT count(*) FROM inventory_embeddings WHERE generation_id=$1)`, generation.ID).
		Scan(&assets, &vectors); err != nil {
		t.Fatal(err)
	}
	if assets != 100000 || vectors != 100000 {
		t.Fatalf("query qualification requires 100000 current real vectors: assets=%d vectors=%d", assets, vectors)
	}
	provider, err := embedding.NewProvider(socketDirectory)
	if err != nil {
		t.Fatal(err)
	}
	embedder, err := provider.ForGeneration(ctx, generation)
	if err != nil {
		t.Fatal(err)
	}
	vector, err := embedder.Embed(ctx, generation.QueryPrefix+"customer portal")
	if err != nil {
		t.Fatal(err)
	}
	for _, scope := range []string{"", "dev.example.com"} {
		lexical, err := store.SearchInventoryEvidence(ctx, inventory.EvidenceQuery{Text: "customer portal", ScopeRoot: scope, ContextID: "unknown", Limit: 10})
		if err != nil || len(lexical.Items) == 0 {
			t.Fatalf("lexical candidates for scope %q: items=%d error=%v", scope, len(lexical.Items), err)
		}
		semantic, err := store.SearchInventorySemantic(ctx, inventory.SemanticQuery{Vector: vector, GenerationID: generation.ID,
			ScopeRoot: scope, ContextID: "unknown", Limit: 10})
		if err != nil || len(semantic.Items) == 0 {
			t.Fatalf("semantic candidates for scope %q: items=%d error=%v", scope, len(semantic.Items), err)
		}
	}
	service := inventory.NewService(store).WithDefaultContext("unknown").WithEmbeddingProvider(provider)
	for _, mode := range []inventory.RetrievalMode{inventory.RetrievalSemantic, inventory.RetrievalHybrid} {
		for _, scope := range []string{"", "dev.example.com"} {
			request := inventory.RetrievalRequest{Text: "customer portal", Mode: mode, ScopeRoot: scope, Limit: 10}
			measurements := make([]time.Duration, 0, 50)
			var mu sync.Mutex
			var wg sync.WaitGroup
			failures := make(chan error, 10)
			for worker := 0; worker < 10; worker++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					for range 5 {
						started := time.Now()
						page, err := service.Retrieve(ctx, request)
						if err != nil || len(page.Items) != 10 || page.DegradedToLexical || page.ModelGeneration != generation.ID {
							failures <- fmt.Errorf("%s scope=%q items=%d degraded=%t generation=%q: %w",
								mode, scope, len(page.Items), page.DegradedToLexical, page.ModelGeneration, err)
							return
						}
						for _, item := range page.Items {
							if scope != "" && !inventory.WithinScope(item.Hostname, scope) {
								failures <- fmt.Errorf("%s returned out-of-scope hostname %q", mode, item.Hostname)
								return
							}
						}
						mu.Lock()
						measurements = append(measurements, time.Since(started))
						mu.Unlock()
					}
				}()
			}
			wg.Wait()
			close(failures)
			for failure := range failures {
				t.Error(failure)
			}
			if len(measurements) == 0 {
				t.Fatalf("%s scope=%q returned no successful retrieval", mode, scope)
			}
			slices.Sort(measurements)
			t.Logf("real model service %s scope=%q, 100000 assets, 10 concurrent readers, %d queries: p50=%s p95=%s max=%s",
				mode, scope, len(measurements), measurements[len(measurements)/2],
				measurements[(len(measurements)*95+99)/100-1], measurements[len(measurements)-1])
		}
	}
}

// Run while the real-model indexing loop is active to observe whether ordinary
// retained search stays available on the shared primary PostgreSQL pool.
func TestInventorySearchDuringEmbeddingQualification(t *testing.T) {
	if os.Getenv("CLOUDATTRIB_INDEXING_RESPONSIVENESS_QUALIFY") != "1" {
		t.Skip("concurrent indexing search qualification is opt-in")
	}
	dsn := os.Getenv("CLOUDATTRIB_POSTGRES_TEST_DSN")
	if dsn == "" {
		t.Fatal("database is required")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	store, err := Open(ctx, dsn, 2000)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(store.Close)
	service := inventory.NewService(store).WithDefaultContext("unknown")
	for _, kind := range []string{"exact_hostname", "lexical"} {
		measurements := make([]time.Duration, 0, 50)
		var mu sync.Mutex
		var wg sync.WaitGroup
		failures := make(chan error, 10)
		for worker := 0; worker < 10; worker++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for range 5 {
					started := time.Now()
					if kind == "exact_hostname" {
						page, err := service.Search(ctx, inventory.SearchRequest{Mode: inventory.SearchExact,
							Query: "capacity-000001.example.com", Limit: 1})
						if err != nil || len(page.Items) != 1 {
							failures <- fmt.Errorf("exact hostname items=%d: %w", len(page.Items), err)
							return
						}
					} else {
						page, err := service.SearchEvidence(ctx, inventory.EvidenceQuery{Text: "customer portal", Limit: 10})
						if err != nil || len(page.Items) != 10 {
							failures <- fmt.Errorf("lexical evidence items=%d: %w", len(page.Items), err)
							return
						}
					}
					mu.Lock()
					measurements = append(measurements, time.Since(started))
					mu.Unlock()
				}
			}()
		}
		wg.Wait()
		close(failures)
		for failure := range failures {
			t.Error(failure)
		}
		if len(measurements) == 0 {
			t.Fatalf("%s produced no successful search", kind)
		}
		slices.Sort(measurements)
		t.Logf("during embedding indexing %s, 10 concurrent readers, %d queries: p50=%s p95=%s max=%s",
			kind, len(measurements), measurements[len(measurements)/2],
			measurements[(len(measurements)*95+99)/100-1], measurements[len(measurements)-1])
	}
}

// Run against a restored copy of the real-model capacity fixture. The model
// artifact and private worker remain outside the database backup.
func TestInventoryRealModelRestoreQualification(t *testing.T) {
	if os.Getenv("CLOUDATTRIB_REAL_MODEL_RESTORE_QUALIFY") != "1" {
		t.Skip("real model restore qualification is opt-in")
	}
	dsn := os.Getenv("CLOUDATTRIB_POSTGRES_TEST_DSN")
	socketDirectory := os.Getenv("CLOUDATTRIB_EMBEDDING_TEST_SOCKET_DIR")
	if dsn == "" || socketDirectory == "" {
		t.Fatal("restored database and private socket directory are required")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	store, err := Open(ctx, dsn, 2000)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(store.Close)
	generation, err := store.ActiveEmbeddingGeneration(ctx)
	if err != nil {
		t.Fatal(err)
	}
	expected := 10000
	if os.Getenv("CLOUDATTRIB_REAL_MODEL_RESTORE_MAX") == "100000" {
		expected = 100000
	}
	var assets, vectors int
	if err := store.pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM inventory_assets),
		(SELECT count(*) FROM inventory_embeddings WHERE generation_id=$1)`, generation.ID).
		Scan(&assets, &vectors); err != nil {
		t.Fatal(err)
	}
	if assets != expected || vectors != expected {
		t.Fatalf("restored assets=%d vectors=%d", assets, vectors)
	}
	provider, err := embedding.NewProvider(socketDirectory)
	if err != nil {
		t.Fatal(err)
	}
	service := inventory.NewService(store).WithDefaultContext("unknown").WithEmbeddingProvider(provider)
	for _, mode := range []inventory.RetrievalMode{inventory.RetrievalSemantic, inventory.RetrievalHybrid} {
		page, err := service.Retrieve(ctx, inventory.RetrievalRequest{Text: "customer login portal", Mode: mode,
			ScopeRoot: "example.com", Limit: 10})
		if err != nil || len(page.Items) != 10 || page.DegradedToLexical || page.ModelGeneration != generation.ID {
			t.Fatalf("restored %s retrieval items=%d degraded=%t generation=%q: %v",
				mode, len(page.Items), page.DegradedToLexical, page.ModelGeneration, err)
		}
	}
}
