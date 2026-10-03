package postgres

import (
	"context"
	"fmt"
	"os"
	"slices"
	"testing"
	"time"

	"cloudattrib/internal/inventory"
)

// Run explicitly with CLOUDATTRIB_INVENTORY_QUALIFY=1 and a disposable PostgreSQL DSN.
// CLOUDATTRIB_INVENTORY_QUALIFY_SIZE=10000 selects the smaller qualification;
// the default is 100000 assets.
func TestInventorySearchQualification(t *testing.T) {
	if os.Getenv("CLOUDATTRIB_INVENTORY_QUALIFY") != "1" {
		t.Skip("inventory qualification is opt-in")
	}
	dsn := os.Getenv("CLOUDATTRIB_POSTGRES_TEST_DSN")
	if dsn == "" {
		t.Fatal("CLOUDATTRIB_POSTGRES_TEST_DSN is required")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	store, err := Open(ctx, dsn, 2000)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(store.Close)
	if _, err := store.pool.Exec(ctx, `TRUNCATE inventory_import_chunks,inventory_tombstones,inventory_assets,inventory_scopes CASCADE`); err != nil {
		t.Fatal(err)
	}
	size := 100000
	if os.Getenv("CLOUDATTRIB_INVENTORY_QUALIFY_SIZE") == "10000" {
		size = 10000
	}
	mainCount := size * 9 / 10
	exactName := fmt.Sprintf("h%06d.example.com", size/2)
	exactFragment := fmt.Sprintf("%06d", size/2)
	_, err = store.pool.Exec(ctx, `INSERT INTO inventory_assets(asset_id,hostname,reversed_labels,normalization_version)
		SELECT 'qualification-'||i,
		CASE WHEN i<=$1 THEN 'h'||lpad(i::text,6,'0')||'.example.com' ELSE 'h'||lpad(i::text,6,'0')||'.dev.example.com' END,
		CASE WHEN i<=$1 THEN 'com.example.h'||lpad(i::text,6,'0')||'.' ELSE 'com.example.dev.h'||lpad(i::text,6,'0')||'.' END,
		'qualification' FROM generate_series(1,$2::integer) i`, mainCount, size)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.pool.Exec(ctx, `INSERT INTO inventory_scopes(root) VALUES('example.com'),('dev.example.com');
		INSERT INTO inventory_memberships(asset_id,root,hostname)
		SELECT asset_id,'example.com',hostname FROM inventory_assets;
		INSERT INTO inventory_memberships(asset_id,root,hostname)
		SELECT asset_id,'dev.example.com',hostname FROM inventory_assets WHERE hostname LIKE '%.dev.example.com';
		ANALYZE inventory_assets; ANALYZE inventory_memberships`); err != nil {
		t.Fatal(err)
	}
	for _, scenario := range []struct {
		name, query string
		argument    string
	}{
		{"exact", `SELECT asset_id FROM inventory_assets WHERE hostname=$1 ORDER BY hostname LIMIT 50`, exactName},
		{"descendant", `WITH candidates AS MATERIALIZED (SELECT asset_id,hostname FROM inventory_assets WHERE reversed_labels LIKE $1) SELECT a.asset_id FROM candidates a ORDER BY a.hostname LIMIT 50`, "com.example.dev.%"},
	} {
		rows, err := store.pool.Query(ctx, "EXPLAIN (ANALYZE, BUFFERS) "+scenario.query, scenario.argument)
		if err != nil {
			t.Fatal(err)
		}
		for rows.Next() {
			var line string
			if err := rows.Scan(&line); err != nil {
				rows.Close()
				t.Fatal(err)
			}
			t.Logf("%s plan: %s", scenario.name, line)
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			t.Fatal(err)
		}
		rows.Close()
	}
	service := inventory.NewService(store)
	writeDone := make(chan error, 1)
	go func() {
		for batch := 0; batch < 10; batch++ {
			_, err := store.pool.Exec(ctx, `INSERT INTO inventory_assets(asset_id,hostname,reversed_labels,normalization_version)
				SELECT 'concurrent-'||i,'c'||lpad(i::text,6,'0')||'.example.com','com.example.c'||lpad(i::text,6,'0')||'.','qualification'
				FROM generate_series($1::integer,$2::integer) i`, batch*100+1, (batch+1)*100)
			if err != nil {
				writeDone <- err
				return
			}
		}
		writeDone <- nil
	}()
	for _, scenario := range []struct {
		name    string
		request inventory.SearchRequest
	}{
		{"exact", inventory.SearchRequest{Mode: inventory.SearchExact, Query: exactName, Limit: 50}},
		{"descendant", inventory.SearchRequest{Mode: inventory.SearchDescendant, Query: "dev.example.com", Limit: 50}},
		{"scoped", inventory.SearchRequest{Mode: inventory.SearchBrowse, ScopeRoot: "dev.example.com", Limit: 50}},
		{"partial", inventory.SearchRequest{Mode: inventory.SearchPartial, Query: exactFragment, Limit: 50}},
	} {
		measurements := make([]time.Duration, 0, 100)
		for range 100 {
			start := time.Now()
			page, err := service.Search(ctx, scenario.request)
			if err != nil {
				t.Fatal(err)
			}
			if len(page.Items) == 0 {
				t.Fatalf("%s returned no items", scenario.name)
			}
			measurements = append(measurements, time.Since(start))
		}
		slices.Sort(measurements)
		p95 := measurements[94]
		t.Logf("%s %d assets, 100 queries, p95=%s max=%s", scenario.name, size, p95, measurements[99])
		if (scenario.name == "exact" || scenario.name == "descendant") && p95 > 100*time.Millisecond {
			t.Errorf("%s p95 %s exceeds 100ms qualification goal", scenario.name, p95)
		}
	}
	if err := <-writeDone; err != nil {
		t.Fatal(fmt.Errorf("concurrent inventory writes: %w", err))
	}
}
