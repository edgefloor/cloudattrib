# Operations guide

This guide installs and runs the service. For the standalone CLI, start with the [README](../README.md#run-it).

The service uses PostgreSQL for reports and jobs, Unbound for DNS, and local source files. Operators populate those files before staging a data bundle.

- [Install with Compose](#compose-installation)
- [Optional local semantic search](#optional-local-semantic-search)
- [Import and activate data](#import-and-activate-data)
- [Schedule staging](#scheduled-staging)
- [Back up and restore](#backup-and-restore)
- [Recover from failures](#failure-and-recovery-behavior)
- [Tune resource limits](#resource-tuning)
- [Install without containers](#non-container-installation)
- [Build and update offline](#offline-build-and-update)

## Security boundary

Compose publishes the API on `127.0.0.1:8080` and requires a bearer token from the private `api_credentials` secret. The application sees a Docker bridge address, so loopback publication alone does not satisfy its authentication boundary.

Before exposing another interface, retain bearer authentication or configure a trusted authenticated reverse proxy. Set the matching authentication mode in the application configuration.

The Compose networks separate three kinds of traffic:

| Network | Access |
| --- | --- |
| `backend` | Application to PostgreSQL; the network is internal. |
| `collector` | Application to the resolver and public targets. |
| `update` | Optional updater; no access to the database network. |

The updater reads operator-populated local files. Enforce an independent egress boundary with host, platform, or network firewall rules. Collector traffic needs the configured resolver plus TCP ports 80 and 443 to public destinations. It does not need private, link-local, documentation, benchmark, or other non-public ranges. Treat the application's address policy as a second check, not as a replacement for network egress controls.

Metrics do not use domains or IPs as labels. Logs contain operation and error classes and omit target values by default. Treat stored reports as retained captures, even after sanitization.

Caller-supplied URL queries are rejected before collection and before ordinary job or report persistence. Submit a query-free URL; the service does not strip the query and analyze a different resource, and it has no secret-storage path for retryable query credentials. Installations that accepted URL queries with an earlier release may already have values in report documents or `job_targets.request`. Assess those historical records under the operator's retention policy; this release does not rewrite or delete them.

## Compose installation

Use Docker Engine with Compose v2. The pinned Unbound image needs an `amd64` runtime or emulation. See the [SBOM](../sbom/cloudattrib.cdx.json) for image and module identities.

PostgreSQL 18 stores its cluster under `/var/lib/postgresql/18/docker`; the Compose volume mounts `/var/lib/postgresql`. Back up and restore an existing deployment prepared with the older `/var/lib/postgresql/data` layout into a fresh volume before adopting this Compose file. Moving the mount path alone does not migrate the cluster.

### 1. Create secrets for a new installation

Run these commands from the repository root on a fresh installation. They create new database and API credentials; do not run them over existing secrets.

Create private secret files and an empty source directory:

```sh
umask 077
mkdir -p secrets data/sources
chmod 700 secrets
openssl rand -hex 24 > secrets/postgres-password
chmod 600 secrets/postgres-password
password=$(cat secrets/postgres-password)
printf 'postgres://cloudattrib:%s@postgres:5432/cloudattrib?sslmode=disable\n' "$password" > secrets/postgres-dsn
chmod 600 secrets/postgres-dsn
openssl rand -hex 24 > secrets/api-token
chmod 600 secrets/api-token
api_token=$(cat secrets/api-token)
printf '%s: compose-operator\n' "$api_token" > secrets/api-credentials
chmod 600 secrets/api-credentials
```

Use a password whose URI representation does not require escaping, or percent-encode it in the DSN. The application rejects an empty, oversized, non-regular, group-readable, or world-readable DSN file.

### 2. Start the stack

Validate the Compose configuration, build the image, and start the services:

```sh
docker compose config --quiet
docker compose build
docker compose up -d
api_token=$(cat secrets/api-token)
curl --fail -H "Authorization: Bearer $api_token" http://127.0.0.1:8080/livez
curl --fail -H "Authorization: Bearer $api_token" http://127.0.0.1:8080/readyz
```

### 3. Check health and coverage

All routes require the bearer token, including health and metrics.

| Route | Check |
| --- | --- |
| `/livez` | Is the process alive? |
| `/readyz` | Which operations are ready, degraded, or unavailable? |
| `/metrics` | Requests, admission rejections, queue capacity, targets, pins, resident generations, estimated retained bytes, bundle identity, source availability and age, and CT lag. |

A PostgreSQL outage disables durable operations while local lookup may remain usable. A 200 readiness response means at least one operation can run; inspect the operation you need. Before loading datasets, expect enrichment coverage to be unavailable or partial.

## Optional local semantic search

The [embedding Compose override](../compose.embedding.yaml) adds a pinned pgvector PostgreSQL image and a local embedding worker. Use it for a new installation or restore a reviewed database dump into its separate `postgres-embedding` volume. Do not switch an existing installation to this override in place: the override selects a different PostgreSQL image and data volume. Keep the base installation and its backup until the restored service and inventory retrieval have been checked.

Provision one supported FastEmbed model cache and a generation contract before startup. The worker supports `sentence-transformers/all-MiniLM-L6-v2` and `BAAI/bge-small-en-v1.5`, each with 384 dimensions and the `fastembed-0.8.1-default` preprocessing label. The contract records the exact model revision and SHA-256 of its ONNX artifact. See [local worker qualification](benchmarks/local-embedding-worker.md) for the contract fields and tested cache layout. The existing synthetic evaluation does not establish production relevance, and the 100,000-asset warm hybrid p95 exceeded the proposed 500 ms target.

On a new installation, create the base secrets as above, place the model cache and contract in operator-controlled host paths, then set absolute paths:

```sh
export COMPOSE_FILE=compose.yaml:compose.embedding.yaml
export CLOUDATTRIB_EMBEDDING_CACHE_DIR=/absolute/path/to/pinned-model-cache
export CLOUDATTRIB_EMBEDDING_CONTRACT_FILE=/absolute/path/to/generation.json
docker compose config --quiet
docker compose build
docker compose up -d
docker compose ps
```

The contract file must be readable by container user 65532. It contains model identity, revision, digest, and formatting metadata; do not put credentials in it. The cache is mounted read-only. The worker has no network, runs as user 65532 with a read-only root filesystem, and serves only a private Unix socket shared with the application. It verifies the cached artifact digest and refuses to serve if it differs from the contract. Build the image and provision the complete cache before running in an isolated environment; neither startup nor inference downloads a model. Back up the cache and contract alongside PostgreSQL. Keep the worker image available for recovery.

After the worker is serving, enable the vector extension and create a generation that matches the mounted contract:

```sh
docker compose exec app /usr/local/bin/cloudattrib inventory embedding enable-vectors
docker compose exec app /usr/local/bin/cloudattrib inventory embedding begin \
  --contract /etc/cloudattrib/embedding-contract.json
docker compose exec app /usr/local/bin/cloudattrib inventory embedding status \
  --generation GENERATION_ID
```

Wait for `status` to show current coverage and no pending or failed tasks, then run `inventory embedding activate --generation GENERATION_ID`. Use `inventory embedding rollback --generation PREVIOUS_ID` to return to a retained generation. Prune only a generation that the status and retention rules mark eligible. Semantic-only retrieval reports a capability error while its active worker is unavailable; hybrid retrieval reports lexical degradation. Check `docker compose logs embedding-worker` for startup failures and verify the model cache, contract, socket volume permissions, and worker state. A forced worker stop can leave a stale socket; the next worker instance recovers it under a per-generation lock.

For recovery, archive the model cache with symlinks intact and copy the generation contract before moving the data. Restore the PostgreSQL dump into a compatible PostgreSQL 18 and pgvector 0.8.6 installation, restore both files to their configured host paths, start the worker, and verify `/health` and an embedding request through its private socket before activating semantic traffic. A local cache-and-contract archive/restore drill returned a 384-dimensional vector from the restarted container. The larger database restore drill kept the original worker and model mounted, so it does not prove end-to-end restore at 100,000 assets.

## Import and activate data

### 1. Prepare source files

Populate `data/sources` with supported files:

- `aws-ip-ranges.json`
- `gcp-cloud.json`
- `azure-service-tags.json`
- `cdncheck-sources-data.json`
- `iptoasn-v4.tsv` and `iptoasn-v6.tsv`
- primary provider JSON files below `cloudranges/json/`
- matching `cloudranges/json/*-details.json` companion files when the pinned revision contains them

ASN files must be decompressed TSV with ordered, non-overlapping intervals. IPv4 endpoints are unsigned integers; IPv6 endpoints are textual addresses. See [source contracts](source-contracts.md) for all fields and source identities.

Keep the directory read-only to the service. Review each source's terms and retain its acquisition record outside the application.

### 2. Stage a candidate

Run the isolated updater profile:

```sh
docker compose --profile update run --rm updater
```

The JSON result contains `candidate_id`, `candidate_hash`, counts, coverage, warnings, and fetch receipts. Review the result before activation.

### 3. Activate and check loading

Replace the placeholders below with the candidate ID and exact validation hash. Activation requires PostgreSQL for durable bundle coordination:

```sh
docker compose exec app /usr/local/bin/cloudattrib datasets activate \
  --config /etc/cloudattrib/config.yaml \
  --candidate bundle-sha256-REPLACE \
  --approval-hash sha256:REPLACE
docker compose exec app /usr/local/bin/cloudattrib datasets status \
  --config /etc/cloudattrib/config.yaml
```

Check `desired`, `active`, and `process_loads` in the status output. `desired` is the committed PostgreSQL generation. `active` is the reconciled filesystem pointer. Each process load record contains the generation that the process loaded. A process builds the replacement away from request handling, then swaps its analyzer. A failed load leaves the last-known-good analyzer active and records the failure or the older generation used at startup.

Pinned jobs retain their selected bundle across restarts, including the built-in bundle. Activation and pruning acquire filesystem and database locks in the same order. This prevents pruning between validation and durable publication.

### 4. Roll back or prune

To roll back, supply the previous bundle and its reviewed hash:

```sh
docker compose exec app /usr/local/bin/cloudattrib datasets rollback \
  --config /etc/cloudattrib/config.yaml \
  --bundle bundle-sha256-PREVIOUS \
  --approval-hash sha256:PREVIOUS
```

Pruning stops if PostgreSQL cannot confirm durable references. It preserves the active bundle, recent rollback generations, and pins held by nonterminal work. To request pruning of an eligible old bundle:

```sh
docker compose exec app /usr/local/bin/cloudattrib datasets prune \
  --config /etc/cloudattrib/config.yaml \
  --candidate bundle-sha256-OLD
```

## Scheduled staging

The checked-in [updater timer](../deploy/cloudattrib-updater.timer) validates and stages local files weekly, with up to six hours of jitter. It does not download sources or activate candidates.

Fetch files in a separate operator-controlled job. Allow that job to contact only approved upstream hosts, then publish the files into the service's read-only source directory. Review and activate each candidate separately.

The specification calls for daily source checks. The supplied weekly staging timer does not implement that acquisition schedule; configure the fetch job to meet your source freshness policy.

## Backup and restore

### Back up

Back up PostgreSQL and immutable bundles close enough in time to meet your recovery-point requirement:

```sh
umask 077
docker compose exec -T postgres pg_dump -U cloudattrib -d cloudattrib -Fc > cloudattrib.dump
docker run --rm \
  -v cloudattrib_bundles:/data:ro \
  -v "$PWD":/backup \
  alpine:3.22.1@sha256:4bcff63911fcb4448bd4fdacec207030997caf25e9bea4045fa6c8c44de311d1 \
  tar -C /data -czf /backup/cloudattrib-bundles.tgz .
```

### Restore

1. Stop the application and updater.
2. Restore the bundle archive into the bundle volume.
3. Restore PostgreSQL with `pg_restore`.
4. Confirm that the committed desired generation has its matching immutable candidate directory.
5. Start the application.
6. Check `/readyz`, `datasets status`, and `cloudattrib_bundle_info` before admitting work.

Reports and retained observations have no automatic age-based deletion. Back up PostgreSQL before invoking report retention. Bundle artifact pruning has its own policy and preserves provenance embedded in reports.

### Report retention

Report history has a configurable 30-day default in `storage.report_retention`. The cutoff uses the report's database `created_at` time, so a report imported during an upgrade gets a full retention period from import. No cleanup runs at service startup or on a timer. Operators must invoke it explicitly and preview first:

```sh
docker compose exec app /usr/local/bin/cloudattrib retention preview --limit 100
```

The JSON output lists each older report, its serialized document bytes, and a protection reason when one applies. It includes the exact `cutoff` and a `next_cursor` when another page remains. Pass the same cutoff as `--before` and the returned cursor as `--cursor` on later pages. A cursor used with another cutoff is rejected. The maximum page size is 500. A preview does not remove anything.

After reviewing the selection and backing up PostgreSQL, an operator can run `retention apply` with the same flags. Each page is one cancellable transaction. An eligible report and its normalized observations, evidence, and findings are deleted together. Terminal job result links are cleared. A report still required by a retained replay, an active reclassification, a pending projection, or current inventory evidence is preserved. Protected reports can become eligible on a later run when those references are released. Repeating a page is safe; it does not restore or duplicate deleted data. Expired result and observation requests return HTTP 404 with `not_found`.

This command does not delete CT records, job history, or bundle manifests. Bundle artifact pruning remains a separate operation with its existing active, rollback, reader, and durable pin protections. Existing installations do not delete pre-existing history until an operator explicitly runs `retention apply`; there is no automatic first-run purge. Log and monitor the command's JSON counts and errors in the scheduler used to invoke it.

## Failure and recovery behavior

- A disk-full or truncated-source failure stops candidate staging before atomic publication. The active bundle remains unchanged.
- A corrupt or incompatible desired candidate fails validation or process loading. A running process keeps its last-known-good analyzer. On restart, the service tries the protected prior generations.
- Writer contention rejects the second updater instead of allowing concurrent publication.
- PostgreSQL admission and report commits fail explicitly. The service does not return an unstored success.
- On `SIGTERM`, the service stops admission and cancels workers. HTTP shutdown has a 10-second allowance. The service keeps PostgreSQL open until owned workers and the reloader stop. Terminal worker commits have a five-second bound; unfinished leases remain recoverable on restart.
- Expired work leases are recovered at startup. Reservations and bundle pins remain durable through restart and retry.

If a process stops after the database commit but before filesystem publication, startup reconciles the pointer from the committed generation. If loading fails, inspect `datasets status`. Correct the candidate or commit a rollback generation, then restart or wait for the reload loop.

`/readyz` reports `generations.desired` from the committed database activation and `generations.loaded` from this process's analyzer. The reload section gives the last attempt time, last successful load time, and whether the latest attempt failed. A failed reload leaves usable last-known-good operations available. Each process reports its own loaded generation; a rollback creates a new generation number even when it selects older bundle data. In-flight and pinned reports keep the bundle captured for their attempt.

`/metrics` exposes `cloudattrib_bundle_desired_generation`, `cloudattrib_bundle_loaded_generation`, separate desired and loaded bundle info gauges, and reload failure and timestamp gauges. `cloudattrib_loaded_dataset_unavailable_sources` and `cloudattrib_loaded_dataset_oldest_source_age_seconds` describe sources in the loaded analyzer at scrape time. The existing `cloudattrib_dataset_*` gauges describe the committed desired bundle. Bundle IDs appear only on the single desired and loaded info series per process; targets and reports are never metric labels. Filesystem `datasets status` records desired publication and process load events; it does not replace the database's committed desired activation.

## Resource tuning

HTTPS collection retains one `tls_certificate` observation per completed handshake using the same connection as the HTTP request. The fingerprint is lowercase SHA-256 of the leaf DER certificate with a `sha256:` prefix. At most 64 DNS and IP SAN names, four issuer organization strings, and 255 bytes per string field are retained; `names_omitted` and `fields_truncated` disclose omissions. The full chain, private keys, and TLS session secrets are not retained. A failed verification is marked unverified and never retried with verification disabled. TLS observations are retained through later HTTP body failures and reused without network traffic during reclassification.

Start with the limits in [config/example.yaml](../config/example.yaml). The service applies one process-level permit pool to synchronous API requests and durable workers. Loaded bundle generations share the same pool.

The `limits.target` settings apply to one admitted target execution except `http_destination_interval`, which is process-wide because every loaded generation shares one execution controller. Duration values use Go duration syntax. HTTP body byte values count decoded bytes. `http_response_headers` caps the headers that the transport accepts. `target_deadline` starts after target admission, but a shorter caller deadline also applies during the wait. `http_destination_interval` sets the minimum time between request starts to the same approved IP address and port; the default `100ms` is at most ten starts per second. `redirects: 0` collects the first HTTP response and does not follow its redirect. The other target limits must be positive.

The `concurrent_targets`, `concurrent_http`, and `concurrent_dns` settings apply to the service process. Per-target HTTP and DNS concurrency remains bounded at 4 and 8. `maximum_backlog_targets` is a separate database-wide bound for all nonterminal reservations, including retries.

Synchronous analysis and IP lookup allow at most `limits.synchronous_waiters` requests to wait for the shared target permit (default 32). Waiting longer than `limits.synchronous_admission_timeout` (default `5s`) or exceeding that waiter count returns HTTP 429 with `queue_capacity_exceeded`; collection does not start for a rejected request. The target deadline starts after the permit is acquired. The HTTP server bounds response writes with an overall write deadline equal to admission timeout plus target deadline plus `limits.response_write_grace` (default `10s`). `/metrics` exposes `cloudattrib_synchronous_admission_waiting` and `cloudattrib_synchronous_admission_rejections_total`.

### Control bundle residency

Set `limits.maximum_resident_generations` to the maximum number of active, captured, or unused bundle analyzers that the service can retain. The default is 4. The minimum is 2 because activation loads a replacement before it releases last-known-good protection.

The limit also reserves capacity for generation loads that have started but have not finished. If active or in-flight work consumes every slot, a worker waits with its claim context and continues to renew its lease. Cancellation removes the waiter without creating a resident analyzer.

`cloudattrib_bundle_resident_generations` reports completed analyzers in the runtime cache. `cloudattrib_bundle_estimated_retained_bytes` sums the source artifact sizes from their bundle manifests. This deterministic estimate covers generation-owned input data. It is not a heap or RSS measurement, and compiled indexes can use more memory than their source files.

`cloudattrib_bundle_pins` is independent of both residency gauges. Durable pins keep bundle files available on disk for nonterminal jobs. Queued pins do not keep analyzers in memory.

Monitor queue use, CT lag, database size, and free space in the bundle volume before increasing concurrency. Reports accumulate until deleted. The [measured full-source import](qualification.md#full-upstream-compatibility) used about 1.42 GB of memory; allow at least 2 GiB for that source mix and measure yours.

## Non-container installation

Install the Go 1.25-built binary at `/usr/local/bin/cloudattrib`, copy `config/example.yaml` to `/etc/cloudattrib/config.yaml`, and create:

- user and group `cloudattrib`;
- updater user `cloudattrib-update` in group `cloudattrib`;
- `/var/lib/cloudattrib/bundles` writable by that group;
- `/var/lib/cloudattrib/sources` writable only by the source-fetch process and readable by the service;
- a mode-`0600` PostgreSQL DSN file readable by the service;
- a local PostgreSQL database and an Unbound listener matching the configuration.

Set absolute paths in `/etc/cloudattrib/config.yaml`. The checked-in example uses paths relative to the working directory, which are unsuitable for these service units.

| Setting | Service value |
| --- | --- |
| `data.bundle_directory` | `/var/lib/cloudattrib/bundles` |
| `data.source_directory` | `/var/lib/cloudattrib/sources` |
| `storage.postgres_dsn_file` | Absolute path to the private DSN file |
| `resolver.address` | Address and port of your Unbound listener |

Install `deploy/cloudattrib.service`, `deploy/cloudattrib-updater.service`, and `deploy/cloudattrib-updater.timer` under `/etc/systemd/system`. Then run:

```sh
systemctl daemon-reload
systemctl enable --now cloudattrib.service cloudattrib-updater.timer
```

Use host firewall units or systemd network policy to keep updater egress separate from worker target traffic. The supplied unit hardening does not replace that host policy.

## Offline build and update

On a connected staging host, verify the checkout, vendor the locked modules, and save every pinned base image:

```sh
make check
go mod vendor
docker pull golang:1.25.1-alpine3.22@sha256:b6ed3fd0452c0e9bcdef5597f29cc1418f61672e9d3a2f55bf02e7222c014abd
docker pull alpine:3.22.1@sha256:4bcff63911fcb4448bd4fdacec207030997caf25e9bea4045fa6c8c44de311d1
docker pull postgres:18.0-alpine3.22@sha256:48c8ad3a7284b82be4482a52076d47d879fd6fb084a1cbfccbd551f9331b0e40
docker pull mvance/unbound:1.22.0@sha256:76906da36d1806f3387338f15dcf8b357c51ce6897fb6450d6ce010460927e90
docker save -o cloudattrib-base-images.tar golang:1.25.1-alpine3.22 alpine:3.22.1 postgres:18.0-alpine3.22 mvance/unbound:1.22.0
```

Transfer the reviewed source tree including `vendor/`, the image archive, the SBOM, notices, and separately reviewed data artifacts. On the isolated build host:

```sh
docker load -i cloudattrib-base-images.tar
docker build --network=none -f deploy/Dockerfile.offline -t cloudattrib:local .
```

For an offline update:

1. Transfer source files and their recorded hashes.
2. Import them with `datasets import` or the updater profile.
3. Review the candidate hash and coverage diff.
4. Activate that exact candidate with its approval hash.

The application does not need an online fetch for this procedure.
