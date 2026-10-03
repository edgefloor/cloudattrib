# Local embedding worker qualification notes

The optional local worker has been exercised with a cached MiniLM ONNX candidate and a disposable pgvector PostgreSQL database. Operator commands provision vector storage, begin a pinned generation, report coverage, activate, roll back, and prune expired retained generations. Real-model indexing, query, and database restore drills have run at 10,000 and 100,000 synthetic assets. The 100,000-document path misses the proposed latency target; a separate [offline inference probe](inventory-inference-capacity.md) measured both local model candidates. An optional Compose deployment and a model-cache restore drill exist. The [new judged fixture](inventory-retrieval-evaluation-v3.md) supports MiniLM as the initial recommendation, with clear limits; target-completion latency under a large indexing load remains unmeasured.

The worker in [`scripts/embedding-worker.py`](../../scripts/embedding-worker.py) serves only a Unix socket in an operator-created `0700` directory. The socket is `0600`. It accepts a generation contract file and an explicitly provisioned FastEmbed cache. Startup requires FastEmbed 0.8.1, `local_files_only=True`, offline Hugging Face settings, the declared cache revision, and the exact SHA-256 digest of the ONNX artifact. A mismatch stops startup before any query text is accepted. It does not fetch a model or expose a TCP listener. The Go adapter checks the socket's ownership and permissions and verifies the worker's complete generation contract over `/health` before sending text.

The current description contract is format `3`. The renderer limits text to 1,024 bytes and 128 words, keeping hostname and typed product terms before DNS and HTTP summaries when it must omit content. The worker counts tokens with a separate tokenizer whose truncation is disabled, then rejects inputs above MiniLM's 256-token or BGE's 512-token model bound. A local MiniLM probe returned HTTP 200 for a short request, HTTP 422 for 300 repeated words, and served 50 simultaneous requests from ten clients at 11.2 ms p95. The bound check prevents FastEmbed's default silent truncation; an over-limit description becomes a visible failed embedding task after retries while lexical search remains available. The model revision and ONNX digest from earlier format-2 probes remain recorded as historical measurements; a new active generation must declare format `3`.

The worker accepts requests serially and has a finite Unix socket backlog of 32. The previous backlog of four refused connections during a ten-client probe. Use a short socket directory path: Unix socket path length is limited by the operating system, and a long macOS temporary-directory path failed at bind time in this probe.

## Container packaging and model recovery

The optional [Compose override](../../compose.embedding.yaml) uses a pinned pgvector PostgreSQL 18 image, a separate database volume, a 384-dimensional FastEmbed worker image with a hash-locked Python dependency set, and a private socket volume. The model cache and generation contract are explicitly provided from the host. The worker container has no network and a read-only root filesystem. The application mounts the socket volume read-only. The [operations guide](../operations.md#optional-local-semantic-search) covers fresh installation and restore; existing base PostgreSQL data is not mounted into the optional pgvector container.

On Apple arm64, the pinned Python 3.13 image built successfully from the lock file and the Compose volume initializer set the socket directory to user 65532 and mode 0700. A disposable Compose project started the worker; `/health` returned HTTP 200 with the expected generation and model. A separate client container with no network sent 50 requests from ten concurrent clients and received 384-dimensional vectors, with worker-only p95 around 12.57 ms. A duplicate worker refused to serve the same generation. After killing the serving process with SIGKILL, a replacement recovered the stale socket and served requests. These tests cover container packaging and socket ownership on this host, not other architectures.

A second disposable Compose project started the full application, Unbound, pgvector PostgreSQL, and worker. This surfaced a PostgreSQL 18 startup failure: the original Compose file mounted a volume at `/var/lib/postgresql/data`, while this image expects its cluster under `/var/lib/postgresql/18/docker`. Both Compose files now mount the parent `/var/lib/postgresql`, with separate base and embedding volumes. On a fresh volume, PostgreSQL became healthy, `/readyz` reported the inventory operation ready, `inventory embedding enable-vectors` succeeded, and a contract-based generation was begun and activated. `inventory retrieve --mode semantic --query 'customer portal'` returned an empty result with the active `probe-minilm-v2` generation and no lexical degradation. This validates the application-to-worker path at startup, but a fresh database has no descriptions to rank.

The same hash-locked Dockerfile also built for Linux amd64. An emulated amd64 worker started with its network disabled and the cache mounted read-only, then returned HTTP 200 and a 384-dimensional vector to a separate container. Native amd64 performance was not measured.

The 151 MiB cached model directory was archived with symlinks and extracted into a new host path. The generation contract was copied separately. A new network-disabled container mounted the restored cache and contract read-only and used a fresh private socket volume. A POST to `/embed` returned HTTP 200 and a 384-dimensional vector. PostgreSQL backup and restore was tested separately as described below; a combined database, model, contract, and application restore remains an operational validation case.

The candidate [MiniLM model card](https://huggingface.co/sentence-transformers/all-MiniLM-L6-v2) identifies an Apache-2.0 license and 384-dimensional vectors. The [rendered-description evaluation](inventory-retrieval-evaluation-v2.md) records the particular FastEmbed ONNX cache revision and artifact digest used in the local test. That 30-document synthetic probe does not select a production model. The test contract used the MiniLM candidate with preprocessing label `fastembed-0.8.1-default`, empty query and document prefixes, and cosine distance.

For an explicitly provisioned development environment, prepare a private directory and a contract JSON file whose fields exactly match an embedding generation in PostgreSQL. Install FastEmbed 0.8.1 and its dependencies in a local virtual environment before launch, then start:

```sh
/path/to/venv/bin/python scripts/embedding-worker.py \
  --contract /path/to/generation.json \
  --cache-dir /path/to/pinned-model-cache \
  --socket-dir /path/to/private-sockets
```

Set `embedding.enabled: true` and `embedding.socket_directory` to the absolute private directory in the service configuration. The service looks up the active generation for each semantic query and asks the matching socket for its model. The indexing loop uses the same provider for building and active generations. If a worker is unavailable, semantic-only search returns a capability error and hybrid search declares lexical-only degradation. Query text is absent from ordinary worker logs and metric labels.

After PostgreSQL has been provisioned with the pinned pgvector 0.8.6 extension and the worker contract is ready, use the CLI to manage a generation:

```sh
cloudattrib inventory embedding enable-vectors
cloudattrib inventory embedding begin --contract /path/to/generation.json
cloudattrib inventory embedding status --generation generation-id
cloudattrib inventory embedding activate --generation generation-id
cloudattrib inventory embedding rollback --generation preceding-generation-id
cloudattrib inventory embedding prune --generation expired-retained-generation-id
```

The service's embedding loop must be running to consume the queued work. `status` returns the generation state, eligible, current, failed, and pending counts, plus the rollback deadline for a retained generation. `activate` requires zero pending descriptions; exhausted failures remain visible in the failed count. Activation retains the preceding generation for seven days. Rollback requires that retained generation to be within its window, switches it atomically, and queues descriptions whose retained vectors are stale or missing. Those descriptions cannot appear as semantic hits until rebuilt; hybrid retrieval can still use lexical evidence. `prune` explicitly removes an expired retained generation and its vectors and work; it refuses active, building, and unexpired generations. The CLI never downloads a model. Operators must retain the corresponding model artifact and worker socket for any generation they may roll back to. Expired generations are not pruned automatically.

With a disposable pgvector PostgreSQL and the worker running, the integration check is:

```sh
CLOUDATTRIB_POSTGRES_TEST_DSN='postgres://postgres@127.0.0.1:5432/postgres?sslmode=disable' \
CLOUDATTRIB_EMBEDDING_TEST_CONTRACT=/path/to/generation.json \
CLOUDATTRIB_EMBEDDING_TEST_SOCKET_DIR=/path/to/private-sockets \
go test ./internal/store/postgres -run '^TestInventoryRealLocalModelLifecycle$' -count=1 -v
```

The check saves a report, projects its description, builds and activates a vector generation, then retrieves the asset by meaning through the shared application service. A separate PostgreSQL integration test exercises rollback, expiration, pruning, and rebuilding a changed description. These prove small local paths with the pinned extension. They do not measure 10,000 or 100,000 documents, concurrent query latency, or resource use.

## Warm worker concurrency probe

On 2026-10-03, the pinned MiniLM ONNX candidate served five waves of ten simultaneous clients on an Apple M4 Pro host. The [worker probe](../../scripts/qualify-embedding-worker.py) sent 50 identical short queries through the private Unix socket after one warm-up request. With the backlog raised to 32, every request returned a 384-dimensional vector. Client wall time was 6.42 ms median, 11.28 ms p95, and 12.1 ms maximum. The probe can be repeated against a running worker with:

```sh
python3 scripts/qualify-embedding-worker.py --socket /path/to/private-sockets/generation-id.sock
```

This isolates warm worker inference and socket queueing. It does not include the Go provider's health check, PostgreSQL search, network collection, cold model load, or concurrent indexing. The 100,000-document shared-service retrieval probe already exceeds the proposed latency target without inference, so this worker result does not qualify the complete search path.

The [startup probe](../../scripts/qualify-embedding-startup.py) launched three fresh MiniLM worker processes with the same verified artifact and a new private socket for each run. On the same Apple M4 Pro host, readiness took 230.89, 232.83, and 224.88 ms; the first embedding request after readiness took 1.42, 1.45, and 1.44 ms. The model file was already in the operating system's file cache, so these are process cold starts with warm disk cache, not an uncached host startup bound. To repeat with the pinned local environment:

```sh
uv run --offline --with fastembed==0.8.1 python scripts/qualify-embedding-startup.py \
  --contract /path/to/generation.json --cache-dir /path/to/pinned-model-cache
```

## Real model indexing and retrieval at 10,000 assets

The opt-in [real model capacity test](../../internal/store/postgres/inventory_real_model_qualification_test.go) loaded the 10,000-asset synthetic capacity fixture into a disposable PostgreSQL 18.6 and pgvector 0.8.6 container, then used the pinned MiniLM worker to process each durable embedding task. All 10,000 descriptions received a current vector, the generation activated with zero pending or failed tasks, and the indexing pass took 77.28 seconds (about 129.4 documents per second). This includes one local worker request and PostgreSQL claim/publication transactions per description. The `inventory_embeddings` relation, including both the existing fixed-vector generation and the new real-vector generation, occupied 42,385,408 bytes; the whole database occupied 74,523,151 bytes.

| Shared-service request with real model | Assets | Concurrent readers | Queries | p50 | p95 | Maximum |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Semantic, `example.com` scope | 10,000 | 10 | 50 | 117.72 ms | 146.18 ms | 163.40 ms |
| Hybrid, `example.com` scope | 10,000 | 10 | 50 | 105.63 ms | 153.09 ms | 154.09 ms |

The queries used the repeated synthetic description text `customer sign-in portal and DNS evidence` with unique hostnames, and the search text `customer login portal`. This measures the actual worker, generation lookup, exact pgvector search, and Go service. The current lexical query requires every term; `login` is absent from the descriptions, so this particular hybrid measurement had no lexical candidates to fuse. A separate 100,000-asset query probe uses `customer portal` and asserts that both result paths participate. The 10,000-asset run does not establish realistic ranking relevance, a 100,000-document latency result with real vectors, simultaneous indexing and query responsiveness, or cold-start behavior. The per-document indexing path is much slower than the separate batched offline inference probe (about 1,608 descriptions per second), so its transaction and request overhead needs separate qualification before sizing larger inventories.

To reproduce after loading the 10,000-row capacity fixture into an otherwise empty disposable database, start the matching private worker and run:

```sh
CLOUDATTRIB_POSTGRES_TEST_DSN='postgres://postgres@127.0.0.1:5432/postgres?sslmode=disable' \
CLOUDATTRIB_REAL_MODEL_CAPACITY_QUALIFY=1 \
CLOUDATTRIB_EMBEDDING_TEST_CONTRACT=/path/to/generation.json \
CLOUDATTRIB_EMBEDDING_TEST_SOCKET_DIR=/path/to/private-sockets \
go test ./internal/store/postgres -run '^TestInventoryRealModelCapacityQualification$' -count=1 -v -timeout=15m
```

The 10,000-real-vector database was also dumped with PostgreSQL 18.6 `pg_dump -Fc` and restored with `pg_restore --no-owner --no-acl` into another database in the same pinned container. The archive was 19,998,225 bytes. The restored database reported pgvector 0.8.6 and 10,000 vectors for the active model generation. [The restore test](../../internal/store/postgres/inventory_real_model_qualification_test.go) passed semantic and hybrid service retrieval through the still-running private worker. This validates the database archive on a compatible host; the model artifact and worker were not restored from backup and remain an outstanding operational restore case.

## Real model indexing and retrieval at 100,000 assets

The same qualification test ran on a disposable 100,000-asset fixture. All 100,000 descriptions received current MiniLM vectors; activation reported zero pending and failed tasks. The indexing pass took 13 minutes 2.66 seconds. The first several thousand claims were slow because the existing task index did not match the per-generation creation-time order. PostgreSQL's plan scanned and sorted nearly the whole pending queue for each claim. Adding `inventory_embedding_tasks_generation_claim_idx` changed the plan to an ordered index scan; subsequent checkpoints generally took about 6–8 seconds per 1,000 descriptions. The new index is in the idempotent schema migration. The total time includes the initial slow period and one local worker request plus database claim/publication transactions per description.

The `inventory_embeddings` relation, including the fixed-vector baseline generation and new real-vector generation, occupied 423,370,752 bytes. The whole database occupied 608,663,231 bytes. A single mid-run sample showed 216.3 MiB PostgreSQL container memory and about 207 MiB resident memory for the Python worker process; these are not peak measurements.

The corrected [query-only probe](../../internal/store/postgres/inventory_real_model_qualification_test.go) used `customer portal`, verified nonempty lexical and semantic candidate lists in each scope, and made 50 shared-service requests per scenario from ten concurrent readers. The first run used four shared inference/database slots:

| Shared-service request with real model | Scope candidates | p50 | p95 | Maximum |
| --- | ---: | ---: | ---: | ---: |
| Semantic, all assets | 100,000 | 1.00 s | 1.36 s | 1.37 s |
| Semantic, `dev.example.com` | 10,000 | 1.51 s | 2.20 s | 2.21 s |
| Hybrid, all assets | 100,000 | 1.13 s | 1.35 s | 1.51 s |
| Hybrid, `dev.example.com` | 10,000 | 1.62 s | 2.19 s | 2.20 s |

The service now admits ten bounded concurrent inference/database paths, matching the probe's reader count. A repeat on the same source fixture with the same worker and query used all ten slots:

| Shared-service request with real model | Scope candidates | p50 | p95 | Maximum |
| --- | ---: | ---: | ---: | ---: |
| Semantic, all assets | 100,000 | 587 ms | 663 ms | 677 ms |
| Semantic, `dev.example.com` | 10,000 | 854 ms | 912 ms | 925 ms |
| Hybrid, all assets | 100,000 | 736 ms | 859 ms | 883 ms |
| Hybrid, `dev.example.com` | 10,000 | 945 ms | 1.01 s | 1.16 s |

Increasing concurrency removed much of the queue delay but still missed the proposed warm hybrid p95 target below 500 ms. A generation/context B-tree index on the vector table was tested against the fixture and gave no improvement, so it was not retained.

Every measured request returned ten results without lexical-only degradation or an out-of-scope hostname. This fixture repeats one short description shape with unique hostnames, so it still does not establish realistic relevance or production latency across varied report text.

While real-model indexing was active at about 78,000 vectors, a separate [ordinary-search probe](../../internal/store/postgres/inventory_real_model_qualification_test.go) made 50 requests per path from ten concurrent readers. Exact-hostname search measured 7.34 ms p95; lexical evidence search measured 307.07 ms p95. Both returned the expected results. A [PostgreSQL integration test](../../internal/store/postgres/inventory_vectors_integration_test.go) also pauses embedding inference and completes an ordinary job before releasing the model call. That proves inference does not hold the job-completion transaction or lock, but it does not measure target-completion latency under a large indexing load.

A 100,000-real-vector `pg_dump -Fc` produced a 199,343,948-byte archive in 17.66 seconds. `pg_restore --no-owner --no-acl` into another database in the same pinned PostgreSQL/pgvector container took 8.05 seconds. The restored database reported pgvector 0.8.6 and 100,000 vectors for the active generation; semantic and hybrid retrieval through the running worker passed. This verifies a compatible database restore with the model still installed. It does not back up or restore the model artifact, generation contract file, or worker process, and it does not qualify cross-version restores.

To repeat the 100,000-asset run, load the full capacity fixture in a fresh disposable database, then set `CLOUDATTRIB_REAL_MODEL_CAPACITY_MAX=100000` for the indexing test. After activation, use `CLOUDATTRIB_REAL_MODEL_QUERY_QUALIFY=1` with the same database DSN and socket directory to run `TestInventoryRealModelQueryCapacityQualification`. On a restored database, set `CLOUDATTRIB_REAL_MODEL_RESTORE_QUALIFY=1` and `CLOUDATTRIB_REAL_MODEL_RESTORE_MAX=100000` to run `TestInventoryRealModelRestoreQualification`.

## Small backup and restore drill

On 2026-10-03, a disposable `pgvector/pgvector:0.8.6-pg18` container (digest `sha256:2ba9ca5f2e7daa0f0e7723cba1ee9167bab54efd3640516a44ac1a928dd67e7a`) ran PostgreSQL 18.6 on Apple arm64. After migrations and vector setup, the source database contained one explicit fixture with an active generation, a current description, a durable embedding task, and a three-dimensional vector. PostgreSQL 18.6 `pg_dump -Fc` created a 65,622-byte archive. `pg_restore` into a new database in the same container completed with exit code zero. The restored database reported extension version `0.8.6`, generation status `active`, description hash `backup-hash`, one vector with three dimensions, and cosine distance zero from the fixture vector `[1,0,0]`. The associated task row was also restored.

The database portion of the drill used these commands, with a fixture inserted before the dump:

```sh
pg_dump -U postgres -d postgres -Fc -f /tmp/cloudattrib-embedding-backup.dump
createdb -U postgres restorecheck
pg_restore -U postgres -d restorecheck --no-owner --no-acl /tmp/cloudattrib-embedding-backup.dump
psql -U postgres -d restorecheck -c "SELECT extversion FROM pg_extension WHERE extname='vector'"
psql -U postgres -d restorecheck -c "SELECT vector_dims(embedding), embedding <=> '[1,0,0]'::vector FROM inventory_embeddings WHERE generation_id='backup-generation'"
```

This verifies a tiny database archive with a compatible extension already installed on the restore host. It does not verify a large database, different PostgreSQL or pgvector versions, restore time, model artifact backup, worker restart, or application retrieval after restore. Model files and generation contracts are outside PostgreSQL and must be backed up separately.
