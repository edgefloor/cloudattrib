# Operations guide

This guide installs and runs the service. For the standalone CLI, start with the [README](../README.md#run-it).

The service uses PostgreSQL for reports and jobs, Unbound for DNS, and local source files. Operators populate those files before staging a data bundle.

- [Install with Compose](#compose-installation)
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

## Compose installation

Use Docker Engine with Compose v2. The pinned Unbound image needs an `amd64` runtime or emulation. See the [SBOM](../sbom/cloudattrib.cdx.json) for image and module identities.

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
| `/metrics` | Requests, admission rejections, queue capacity, targets, pins, bundle identity, source availability and age, and CT lag. |

A PostgreSQL outage disables durable operations while local lookup may remain usable. A 200 readiness response means at least one operation can run; inspect the operation you need. Before loading datasets, expect enrichment coverage to be unavailable or partial.

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

Check both the desired bundle and each process's load status. A process builds the replacement away from request handling, then swaps its analyzer. A failed load leaves the last-known-good analyzer active and records the failure.

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
4. Confirm that the active pointer has its matching immutable candidate directory.
5. Start the application.
6. Check `/readyz`, `datasets status`, and `cloudattrib_bundle_info` before admitting work.

Reports and retained observations currently have no automatic age-based deletion. Define a backup and deletion policy for PostgreSQL. Bundle pruning preserves provenance embedded in reports. The specification's default retention requirement is not an automatic cleanup schedule in this implementation.

## Failure and recovery behavior

- A disk-full or truncated-source failure stops candidate staging before atomic publication. The active bundle remains unchanged.
- A corrupt or incompatible candidate fails validation or process loading. The last-known-good analyzer remains active.
- Writer contention rejects the second updater instead of allowing concurrent publication.
- PostgreSQL admission and report commits fail explicitly. The service does not return an unstored success.
- On `SIGTERM`, the service stops admission and cancels workers. HTTP shutdown has a 10-second allowance. The service keeps PostgreSQL open until owned workers and the reloader stop. Terminal worker commits have a five-second bound; unfinished leases remain recoverable on restart.
- Expired work leases are recovered at startup. Reservations and bundle pins remain durable through restart and retry.

If a process stops after desired-bundle publication but before reload, it loads that desired candidate on restart. If loading fails, inspect `datasets status`, correct or roll back the desired pointer, and restart or wait for the reload loop.

## Resource tuning

Start with the limits in [config/example.yaml](../config/example.yaml). The service applies one process-level permit pool to synchronous API requests and durable workers. Loaded bundle generations share the same pool.

The `limits.target` settings apply to one admitted target execution. Duration values use Go duration syntax. HTTP body byte values count decoded bytes. `http_response_headers` caps the headers that the transport accepts. `target_deadline` starts after target admission, but a shorter caller deadline also applies during the wait. `redirects: 0` collects the first HTTP response and does not follow its redirect. The other target limits must be positive.

The `concurrent_targets`, `concurrent_http`, and `concurrent_dns` settings apply to the service process. Per-target HTTP and DNS concurrency remains bounded at 4 and 8. `maximum_backlog_targets` is a separate database-wide bound for all nonterminal reservations, including retries.

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
