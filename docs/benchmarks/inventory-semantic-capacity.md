# Exact semantic search capacity probe

Issue #31 sets a proposed warm hybrid p95 target below 500 ms at 100,000 documents and ten concurrent searches. This probe measures PostgreSQL exact semantic search and the shared application's semantic and hybrid paths with deterministic 384-dimensional vectors. It does not run real model inference, projection work, or the HTTP server, so its service latency is a lower bound on the complete request path. The 100,000-document run missed the proposed target.

## Environment and fixture

Run on 2026-10-03 on an Apple M4 Pro host (`darwin/arm64`, 14 logical CPUs, 64 GiB host RAM) with Docker Desktop. The disposable container used `pgvector/pgvector:0.8.6-pg18` at digest `sha256:2ba9ca5f2e7daa0f0e7723cba1ee9167bab54efd3640516a44ac1a928dd67e7a`. Its memory limit was 15.66 GiB. The fixture inserted one current description and one 384-dimensional vector per asset, with variation in two coordinates. Ten thousand of the 100,000 assets belonged to the `dev.example.com` scope. The vectors were generated in SQL; no model process ran.

The opt-in [qualification test](../../internal/store/postgres/inventory_semantic_qualification_test.go) uses `SearchInventorySemantic` through the Go store. It loads 10,000 then 100,000 assets into an empty disposable database, checks ten returned results and scope membership, and runs 200 queries per scenario from ten concurrent readers (20 sequential requests per reader). Each request requests ten results. This is a warm local Docker probe, with no network collection or background writer. The test reports p50, p95, and maximum wall time across successful calls.

| Current exact query path | Assets | Scope candidates | p50 | p95 | Maximum |
| --- | ---: | ---: | ---: | ---: | ---: |
| Narrow ranked IDs, default PostgreSQL parallelism | 10,000 | 10,000 | 34.8 ms | 46.3 ms | 53.1 ms |
| Narrow ranked IDs, one-time generation check, default parallelism | 100,000 | 100,000 | 513.8 ms | 541.1 ms | 567.7 ms |
| Same query | 100,000 | 10,000 | 792.3 ms | 819.4 ms | 828.3 ms |

The original query materialized descriptions and vectors for every eligible row before sorting. At 100,000 assets it measured 2.02 s p95 unscoped and 1.74 s p95 scoped. A single unscoped `EXPLAIN (ANALYZE, BUFFERS)` showed about 175 MiB of temporary CTE storage and 100,000 repeated asset and generation index lookups. Ranking narrow IDs before fetching descriptions removed the wide temporary result. Making active-generation validation a scalar lookup eliminated the repeated generation checks. These changes improved the measured path but did not meet the target.

Changing PostgreSQL `max_parallel_workers_per_gather` for the role was also measured with the same fixture. The default setting was `2`. At `1`, p95 was 555 ms unscoped and 833 ms scoped. At `0`, p95 was 656 ms unscoped and 947 ms scoped. Lowering this setting is not recommended from this evidence. A single scoped query's plan completed in about 42 ms while the ten-reader run reached 819 ms p95, indicating contention under concurrency. The test has no server-side CPU or wait-event breakdown, so the cause of the remaining latency is not fully established.

| Fixture size | Load time from previous checkpoint | `inventory_embeddings` including indexes | Whole database |
| --- | ---: | ---: | ---: |
| 10,000 | 0.47 s | 21.2 MB | 48.2 MB |
| 100,000 | 4.82 s for the next 90,000 | 211.7 MB | 352.9 MB |

One `docker stats` sample during the 100,000-row run showed about 340 MiB container memory use. This is a sample, not peak RSS. A separate [offline inference probe](inventory-inference-capacity.md) measured candidate model throughput and process peak RSS on repeated short descriptions. A later [real-model qualification](local-embedding-worker.md#real-model-indexing-and-retrieval-at-100000-assets) measured indexing, model-backed hybrid latency, and a database restore on the same synthetic fixture. Combined peak service/model memory, varied production backup size, and realistic relevance remain unmeasured. The prior [relevance probe](inventory-retrieval-evaluation-v2.md) used only 30 synthetic documents. No one-million-document claim follows from these results.

## Shared service path

The same 100,000-row fixture was also queried through `inventory.Service.Retrieve` with a deterministic, zero-cost embedder. This exercised the four service inference slots, lexical search for hybrid mode, reciprocal-rank fusion, and exact-hostname handling. Ten concurrent readers made five requests each (50 samples per mode and scope). The query text was `customer portal`, which matched the fixture descriptions lexically. The PostgreSQL container used 512 MiB of shared buffers and the default two parallel workers per gather.

| Service request | Scope | p50 | p95 | Maximum |
| --- | --- | ---: | ---: | ---: |
| Semantic | All 100,000 assets | 860 ms | 1.21 s | 1.22 s |
| Semantic | 10,000 `dev.example.com` assets | 1.38 s | 2.04 s | 2.04 s |
| Hybrid | All 100,000 assets | 915 ms | 1.28 s | 1.34 s |
| Hybrid | 10,000 `dev.example.com` assets | 1.45 s | 2.09 s | 2.13 s |

All sampled calls returned ten results without lexical-only degradation. Because the embedder returned a fixed vector immediately, actual model inference and worker queueing can only add latency. Increasing PostgreSQL `shared_buffers` from its image default to 512 MiB barely changed the unscoped database-only p95 (541 to 544 ms) and reduced scoped p95 from 819 to 780 ms. That adjustment did not bring the path near the full-service target. The remaining gap requires a query or data-layout change and a later run with the real local model.

## 100,000-row backup and restore

The 100,000-row fixture was dumped with PostgreSQL 18.6 `pg_dump -Fc`, then restored into a new database in the same pinned pgvector container with `pg_restore --no-owner --no-acl`. The archive was 8,768,167 bytes. Wall time was 0.76 s for the dump and 2.82 s for the restore on this host. `TestInventorySemanticRestoreQualification` then opened the restored database through the Go store, confirmed pgvector 0.8.6, the active generation, 100,000 assets and 100,000 vectors, and retrieved ten in-scope results through both semantic and hybrid application modes without degradation. It used the same fixed test embedder; no model process or artifact was restored.

```sh
pg_dump -U postgres -d postgres -Fc -f /tmp/cloudattrib-capacity-100k.dump
createdb -U postgres capacityrestore
pg_restore -U postgres -d capacityrestore --no-owner --no-acl /tmp/cloudattrib-capacity-100k.dump
CLOUDATTRIB_POSTGRES_TEST_DSN='postgres://postgres@127.0.0.1:5432/capacityrestore?sslmode=disable' \
CLOUDATTRIB_SEMANTIC_RESTORE_QUALIFY=1 \
go test ./internal/store/postgres -run '^TestInventorySemanticRestoreQualification$' -count=1 -v
```

The fixture repeats short descriptions and has only 17 variations in one vector coordinate and 29 in another, so its archive compresses unusually well. The drill does not establish backup size or restore time for real model output, a different server, extension upgrades, or a restarted worker. Model artifacts and generation contract files are outside PostgreSQL and must be backed up separately.

To repeat on an **empty disposable** database with the pinned pgvector image installed:

```sh
CLOUDATTRIB_POSTGRES_TEST_DSN='postgres://postgres@127.0.0.1:5432/postgres?sslmode=disable' \
CLOUDATTRIB_SEMANTIC_CAPACITY_QUALIFY=1 \
go test ./internal/store/postgres -run '^TestInventorySemanticCapacityQualification$' -count=1 -v -timeout=15m
```

The test refuses an existing inventory. `CLOUDATTRIB_SEMANTIC_CAPACITY_MAX=10000` runs only the 10,000-row checkpoint. `CLOUDATTRIB_SEMANTIC_CAPACITY_REUSE=1` reruns the 100,000-row queries against a fixture left in the same disposable database. Add `CLOUDATTRIB_SEMANTIC_CAPACITY_APP=1` to measure semantic and hybrid retrieval through the shared application service with a fixed test embedder. None of these modes deletes existing data.
