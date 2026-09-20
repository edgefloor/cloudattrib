# Operations guide

`cloudattrib` runs as an unprivileged service with PostgreSQL for durable reports and jobs, Unbound as its explicit recursive resolver, an immutable bundle directory, and operator-supplied source files. It does not download enrichment data during startup or request processing.

## Security boundary

The reference Compose deployment publishes the API only on `127.0.0.1:8080` and requires a bearer token from the private `api_credentials` secret. This is necessary because the application sees the Docker bridge address rather than the host loopback address. Before publishing the API on another interface, retain bearer authentication or put it behind a trusted authenticated reverse proxy and configure the corresponding mode in `config.yaml`.

The Compose networks separate database traffic, collection traffic, and updater traffic. The application can reach PostgreSQL on the internal `backend` network and targets through the `collector` network. PostgreSQL has no outbound network. The optional updater runs on `update`, reads an operator-populated source directory, and cannot reach the application database network. Apply host or platform firewall rules when the deployment requires destination or port restrictions beyond this topology.

Metrics use fixed names and no target-valued labels. Logs contain operation and error classes; the application does not log target values by default. Treat PostgreSQL reports as sensitive retained captures even when response bodies have already been bounded and sanitized.

## Compose installation

Requirements are Docker Engine with Compose v2 and an `amd64` runtime or emulation for the pinned Unbound image. Image and module identities are in `sbom/cloudattrib.cdx.json`.

Create private database and API secrets and an empty source directory:

```sh
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

Validate and start the stack:

```sh
docker compose config --quiet
docker compose build
docker compose up -d
api_token=$(cat secrets/api-token)
curl --fail -H "Authorization: Bearer $api_token" http://127.0.0.1:8080/livez
curl --fail -H "Authorization: Bearer $api_token" http://127.0.0.1:8080/readyz
```

All routes, including health and metrics, require the bearer token in the Compose configuration. `/livez` reports process liveness. `/readyz` reports each public operation. A PostgreSQL outage makes durable operations unavailable while local lookup can remain available. `/metrics` exposes request count, admission rejections, reserved and maximum target capacity, queued and running targets, durable bundle pins, active bundle identity, source age/availability, and CT checkpoint lag.

## Import and activate data

Populate `data/sources` with any supported files:

- `aws-ip-ranges.json`
- `gcp-cloud.json`
- `azure-service-tags.json`
- `cdncheck-sources-data.json`
- `iptoasn-v4.tsv` and `iptoasn-v6.tsv`
- primary provider JSON files below `cloudranges/json/`

Keep the directory read-only to the service. Review each source's terms and retain its acquisition record outside the application. Stage a candidate with the isolated updater profile:

```sh
docker compose --profile update run --rm updater
```

The JSON result contains `candidate_id`, `candidate_hash`, record counts, source coverage, warnings, and fetch receipts. Review it before activation. Activation requires the exact validation hash:

```sh
docker compose exec app /usr/local/bin/cloudattrib datasets activate \
  --config /etc/cloudattrib/config.yaml \
  --candidate bundle-sha256-REPLACE \
  --approval-hash sha256:REPLACE
docker compose exec app /usr/local/bin/cloudattrib datasets status \
  --config /etc/cloudattrib/config.yaml
```

Each process loads the desired bundle off-path and then swaps its active analyzer. A failed load records a process-load failure and retains the last-known-good analyzer. Accepted pinned jobs retain their historical analyzer and durable prune protection.

Rollback uses the same review-bound hash:

```sh
docker compose exec app /usr/local/bin/cloudattrib datasets rollback \
  --config /etc/cloudattrib/config.yaml \
  --bundle bundle-sha256-PREVIOUS \
  --approval-hash sha256:PREVIOUS
```

Pruning fails closed when PostgreSQL cannot confirm durable references. It does not remove the active bundle, recent rollback generations, or a bundle pinned by nonterminal work:

```sh
docker compose exec app /usr/local/bin/cloudattrib datasets prune \
  --config /etc/cloudattrib/config.yaml \
  --candidate bundle-sha256-OLD
```

## Scheduled staging

`deploy/cloudattrib-updater.timer` runs the local-source validation and staging command weekly with up to six hours of jitter. It does not activate a candidate. Fetch source files in a separate operator-controlled job whose egress allowlist is limited to the approved upstream hosts, then publish the files into the read-only source directory. Activation remains a separate reviewed action.

## Backup and restore

Back up PostgreSQL and immutable bundles together closely enough for the required recovery point:

```sh
umask 077
docker compose exec -T postgres pg_dump -U cloudattrib -d cloudattrib -Fc > cloudattrib.dump
docker run --rm \
  -v cloudattrib_bundles:/data:ro \
  -v "$PWD":/backup \
  alpine:3.22.1@sha256:4bcff63911fcb4448bd4fdacec207030997caf25e9bea4045fa6c8c44de311d1 \
  tar -C /data -czf /backup/cloudattrib-bundles.tgz .
```

For restore, stop the application and updater, restore the bundle archive into the bundle volume, restore the database with `pg_restore`, and then start the application. Check `/readyz`, `datasets status`, and `cloudattrib_bundle_info` before admitting work. Do not restore an active pointer without its matching immutable candidate directory.

Reports and raw retained observations have no automatic age-based deletion. Define database backup and deletion retention according to the operator's policy. Bundle pruning does not remove provenance embedded in retained reports.

## Failure and recovery behavior

- A disk-full or truncated-source failure stops candidate staging before atomic publication. The active bundle remains unchanged.
- A corrupt or incompatible candidate fails validation or process loading. The last-known-good analyzer remains active.
- Writer contention rejects the second updater instead of allowing concurrent publication.
- PostgreSQL admission and report commits fail explicitly. The service does not return an unstored success.
- `SIGTERM` stops admission, cancels workers, allows up to 10 seconds for HTTP shutdown, and leaves leases recoverable on restart.
- Expired work leases are recovered at startup. Reservations and bundle pins remain durable through restart and retry.

If a process stops after desired-bundle publication but before reload, it loads that desired candidate on restart. If loading fails, inspect `datasets status`, correct or roll back the desired pointer, and restart or wait for the reload loop.

## Resource tuning

Start with the checked-in limits. `concurrent_targets` bounds workers; DNS and HTTP budgets remain per target; `maximum_backlog_targets` bounds all nonterminal reservations, including retries. PostgreSQL disk is normally the first long-term capacity constraint because reports are retained. Monitor queue reservation ratio, CT lag when enabled, database size, and bundle-volume free space before increasing concurrency.

## Non-container installation

Install the Go 1.25-built binary at `/usr/local/bin/cloudattrib`, copy `config/example.yaml` to `/etc/cloudattrib/config.yaml`, and create:

- user and group `cloudattrib`;
- updater user `cloudattrib-update` in group `cloudattrib`;
- `/var/lib/cloudattrib/bundles` writable by that group;
- `/var/lib/cloudattrib/sources` writable only by the source-fetch process and readable by the service;
- a mode-`0600` PostgreSQL DSN file readable by the service;
- a local PostgreSQL database and an Unbound listener matching the configuration.

Install `deploy/cloudattrib.service`, `deploy/cloudattrib-updater.service`, and `deploy/cloudattrib-updater.timer` under `/etc/systemd/system`, then run:

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

For an offline data update, transfer source files with their recorded hashes, import them with `datasets import` or the updater profile, review the generated candidate hash and coverage diff, then activate that exact hash. No online source fetch is required by the application.
