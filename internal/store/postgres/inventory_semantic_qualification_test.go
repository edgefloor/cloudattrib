package postgres

import (
	"context"
	"fmt"
	"os"
	"slices"
	"sync"
	"testing"
	"time"

	"cloudattrib/internal/inventory"
)

// Run only against a disposable empty database with the pinned pgvector image.
// Vectors are deterministic fixtures; this measures PostgreSQL, not inference.
func TestInventorySemanticCapacityQualification(t *testing.T) {
	if os.Getenv("CLOUDATTRIB_SEMANTIC_CAPACITY_QUALIFY") != "1" {
		t.Skip("semantic capacity qualification is opt-in")
	}
	dsn := os.Getenv("CLOUDATTRIB_POSTGRES_TEST_DSN")
	if dsn == "" {
		t.Fatal("CLOUDATTRIB_POSTGRES_TEST_DSN is required")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Minute)
	defer cancel()
	store, err := Open(ctx, dsn, 2000)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(store.Close)
	var existing int64
	if err := store.pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM inventory_assets)+(SELECT count(*) FROM inventory_embedding_generations)`).Scan(&existing); err != nil {
		t.Fatal(err)
	}
	reuse := os.Getenv("CLOUDATTRIB_SEMANTIC_CAPACITY_REUSE") == "1"
	if !reuse && existing != 0 {
		t.Fatal("semantic capacity qualification requires an empty disposable database")
	}
	if reuse && existing != 100001 {
		t.Fatalf("capacity fixture reuse requires 100000 assets and one generation, found %d rows", existing)
	}
	maxSize := 100000
	if os.Getenv("CLOUDATTRIB_SEMANTIC_CAPACITY_MAX") == "10000" {
		maxSize = 10000
	}
	if err := store.EnableInventoryVectors(ctx); err != nil {
		t.Fatal(err)
	}
	var parallelWorkers string
	if err := store.pool.QueryRow(ctx, `SELECT current_setting('max_parallel_workers_per_gather')`).Scan(&parallelWorkers); err != nil {
		t.Fatal(err)
	}
	t.Logf("PostgreSQL max_parallel_workers_per_gather=%s", parallelWorkers)
	if !reuse {
		if _, err := store.pool.Exec(ctx, `INSERT INTO inventory_scopes(root) VALUES('example.com'),('dev.example.com')`); err != nil {
			t.Fatal(err)
		}
		if _, err := store.pool.Exec(ctx, `INSERT INTO inventory_embedding_generations(generation_id,model_id,model_revision,artifact_sha256,
		model_license,dimensions,document_format_version,preprocessing,query_prefix,document_prefix,metric,status)
		VALUES('capacity-fixture','deterministic-fixture','v1',repeat('a',64),'MIT',384,$1,'fixture-v1','','','cosine','active')`, inventory.DescriptionFormatVersion); err != nil {
			t.Fatal(err)
		}
	}
	for _, size := range []int{10000, 100000} {
		if size > maxSize {
			break
		}
		if reuse && size == 10000 {
			continue
		}
		start := 1
		if size == 100000 {
			start = 10001
		}
		insertStarted := time.Now()
		if !reuse {
			if _, err := store.pool.Exec(ctx, `INSERT INTO inventory_assets(asset_id,hostname,reversed_labels,normalization_version)
			SELECT 'capacity-'||lpad(i::text,6,'0'),
				'capacity-'||lpad(i::text,6,'0')||CASE WHEN i>90000 THEN '.dev.example.com' ELSE '.example.com' END,
				CASE WHEN i>90000 THEN 'com.example.dev.capacity-' ELSE 'com.example.capacity-' END||lpad(i::text,6,'0')||'.',
				'capacity-fixture' FROM generate_series($1::integer,$2::integer) i`, start, size); err != nil {
				t.Fatal(err)
			}
			if _, err := store.pool.Exec(ctx, `INSERT INTO inventory_memberships(asset_id,root,hostname)
			SELECT asset_id,'example.com',hostname FROM inventory_assets WHERE asset_id BETWEEN $1 AND $2`,
				fmt.Sprintf("capacity-%06d", start), fmt.Sprintf("capacity-%06d", size)); err != nil {
				t.Fatal(err)
			}
			if _, err := store.pool.Exec(ctx, `INSERT INTO inventory_memberships(asset_id,root,hostname)
			SELECT asset_id,'dev.example.com',hostname FROM inventory_assets
			WHERE asset_id BETWEEN $1 AND $2 AND hostname LIKE '%.dev.example.com'`,
				fmt.Sprintf("capacity-%06d", start), fmt.Sprintf("capacity-%06d", size)); err != nil {
				t.Fatal(err)
			}
			if _, err := store.pool.Exec(ctx, `INSERT INTO inventory_asset_contexts(asset_id,context_id,deletion_generation,
			description,description_hash,description_revision,description_format_version)
			SELECT asset_id,'unknown',0,hostname||' customer sign-in portal and DNS evidence',
				md5(hostname||' customer sign-in portal and DNS evidence'),1,$3
			FROM inventory_assets WHERE asset_id BETWEEN $1 AND $2`,
				fmt.Sprintf("capacity-%06d", start), fmt.Sprintf("capacity-%06d", size), inventory.DescriptionFormatVersion); err != nil {
				t.Fatal(err)
			}
			if _, err := store.pool.Exec(ctx, `INSERT INTO inventory_embeddings(asset_id,context_id,generation_id,
			description_revision,description_hash,deletion_generation,embedding)
			SELECT c.asset_id,c.context_id,'capacity-fixture',c.description_revision,c.description_hash,c.deletion_generation,
				(ARRAY[1.0::real,(substring(c.asset_id from 10)::integer%17)::real/17,
				(substring(c.asset_id from 10)::integer%29)::real/29]||array_fill(0.0::real,ARRAY[381]))::halfvec
			FROM inventory_asset_contexts c WHERE c.asset_id BETWEEN $1 AND $2`,
				fmt.Sprintf("capacity-%06d", start), fmt.Sprintf("capacity-%06d", size)); err != nil {
				t.Fatal(err)
			}
			if _, err := store.pool.Exec(ctx, `ANALYZE inventory_assets; ANALYZE inventory_memberships;
			ANALYZE inventory_asset_contexts; ANALYZE inventory_embeddings`); err != nil {
				t.Fatal(err)
			}
		}
		var vectorBytes, databaseBytes int64
		if err := store.pool.QueryRow(ctx, `SELECT pg_total_relation_size('inventory_embeddings'),pg_database_size(current_database())`).Scan(&vectorBytes, &databaseBytes); err != nil {
			t.Fatal(err)
		}
		t.Logf("%d assets: load=%s vector table=%d bytes database=%d bytes", size, time.Since(insertStarted), vectorBytes, databaseBytes)
		for _, scoped := range []bool{false, true} {
			if scoped && size == 10000 {
				continue
			}
			request := inventory.SemanticQuery{GenerationID: "capacity-fixture", ContextID: "unknown", Limit: 10,
				Vector: make([]float32, 384)}
			request.Vector[0], request.Vector[1], request.Vector[2] = 1, 0.3, 0.4
			if scoped {
				request.ScopeRoot = "dev.example.com"
			}
			measurements := make([]time.Duration, 0, 200)
			var mu sync.Mutex
			var wg sync.WaitGroup
			failures := make(chan error, 10)
			for worker := 0; worker < 10; worker++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					for i := 0; i < 20; i++ {
						started := time.Now()
						page, err := store.SearchInventorySemantic(ctx, request)
						if err != nil || len(page.Items) != 10 {
							failures <- fmt.Errorf("semantic query items=%d: %w", len(page.Items), err)
							return
						}
						if scoped && !inventory.WithinScope(page.Items[0].Hostname, "dev.example.com") {
							failures <- fmt.Errorf("out-of-scope result %q", page.Items[0].Hostname)
							return
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
				t.Fatal("semantic qualification produced no successful query")
			}
			slices.Sort(measurements)
			t.Logf("%d assets scope=%q 10 concurrent readers 200 queries: p50=%s p95=%s max=%s",
				size, request.ScopeRoot, measurements[len(measurements)/2], measurements[(len(measurements)*95+99)/100-1], measurements[len(measurements)-1])
		}
	}
	if maxSize == 100000 && os.Getenv("CLOUDATTRIB_SEMANTIC_CAPACITY_APP") == "1" {
		vector := make([]float32, 384)
		vector[0], vector[1], vector[2] = 1, 0.3, 0.4
		service := inventory.NewService(store).WithDefaultContext("unknown").WithEmbedder("capacity-fixture",
			fixtureEmbedder(func(context.Context, string) ([]float32, error) { return vector, nil }))
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
						for i := 0; i < 5; i++ {
							started := time.Now()
							page, err := service.Retrieve(ctx, request)
							if err != nil || len(page.Items) != 10 || page.DegradedToLexical {
								failures <- fmt.Errorf("%s scope=%q retrieval items=%d degraded=%t: %w", mode, scope, len(page.Items), page.DegradedToLexical, err)
								return
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
					t.Fatalf("%s scope=%q: no successful retrieval", mode, scope)
				}
				slices.Sort(measurements)
				t.Logf("service %s scope=%q 10 concurrent readers %d requests: p50=%s p95=%s max=%s",
					mode, scope, len(measurements), measurements[len(measurements)/2],
					measurements[(len(measurements)*95+99)/100-1], measurements[len(measurements)-1])
			}
		}
	}
}

// Run after restoring a capacity fixture into a new disposable database.
func TestInventorySemanticRestoreQualification(t *testing.T) {
	if os.Getenv("CLOUDATTRIB_SEMANTIC_RESTORE_QUALIFY") != "1" {
		t.Skip("semantic restore qualification is opt-in")
	}
	dsn := os.Getenv("CLOUDATTRIB_POSTGRES_TEST_DSN")
	if dsn == "" {
		t.Fatal("CLOUDATTRIB_POSTGRES_TEST_DSN is required")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	store, err := Open(ctx, dsn, 2000)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(store.Close)
	var version, status string
	var assets, vectors int
	if err := store.pool.QueryRow(ctx, `SELECT
		(SELECT extversion FROM pg_extension WHERE extname='vector'),
		(SELECT status FROM inventory_embedding_generations WHERE generation_id='capacity-fixture'),
		(SELECT count(*) FROM inventory_assets),
		(SELECT count(*) FROM inventory_embeddings WHERE generation_id='capacity-fixture')`).
		Scan(&version, &status, &assets, &vectors); err != nil {
		t.Fatal(err)
	}
	if version != inventoryVectorExtensionVersion || status != "active" || assets != 100000 || vectors != 100000 {
		t.Fatalf("restored extension=%q generation=%q assets=%d vectors=%d", version, status, assets, vectors)
	}
	vector := make([]float32, 384)
	vector[0], vector[1], vector[2] = 1, 0.3, 0.4
	service := inventory.NewService(store).WithDefaultContext("unknown").WithEmbedder("capacity-fixture",
		fixtureEmbedder(func(context.Context, string) ([]float32, error) { return vector, nil }))
	for _, mode := range []inventory.RetrievalMode{inventory.RetrievalSemantic, inventory.RetrievalHybrid} {
		page, err := service.Retrieve(ctx, inventory.RetrievalRequest{Text: "customer portal", Mode: mode,
			ScopeRoot: "dev.example.com", Limit: 10})
		if err != nil || len(page.Items) != 10 || page.DegradedToLexical || page.ModelGeneration != "capacity-fixture" {
			t.Fatalf("restored %s retrieval items=%d degraded=%t generation=%q error=%v",
				mode, len(page.Items), page.DegradedToLexical, page.ModelGeneration, err)
		}
		for _, item := range page.Items {
			if !inventory.WithinScope(item.Hostname, "dev.example.com") {
				t.Fatalf("restored %s returned out-of-scope hostname %q", mode, item.Hostname)
			}
		}
	}
}
