# Hostname inventory

The inventory stores one asset per normalized concrete hostname in PostgreSQL. Case, a final DNS root dot, and IDNA spelling normalize to the same asset ID. A hostname can belong to overlapping scopes and can have more than one discovery source. Inventory import, search, and browsing make no DNS or HTTP requests.

Search covers names that the selected imports and local CT collection have recorded. An empty result does not show that a hostname does not exist. CT collection still follows its own explicit source and budget settings. Inventory capacity is separate from the CT candidate limit used by one analysis.

## Import names

Prepare a text file with one hostname per line. Pass a scope root that contains the names you intend to import. Wildcard patterns, invalid names, and names outside the scope appear in separate receipt counts. A chunk contains at most 1,000 lines. Split larger files into chunks and give each chunk a distinct `--chunk` value under one `--operation` value.

```sh
cloudattrib inventory import --input names.txt --scope example.com --source operator-export-2026-10 --operation import-2026-10 --chunk 0001
```

Use `--format jsonl` for lines such as `{"hostname":"api.example.com","observed_at":"2026-01-01T00:00:00Z"}`. Omit `observed_at` when the source does not provide it. The database records the receipt time separately. Repeating the same operation and chunk with identical input returns the saved counts. Reusing the identifiers with changed input returns an idempotency conflict.

The HTTP equivalent is `POST /v1/inventory/import` with `operation_id`, `chunk_id`, `source_id`, `scope_roots`, and `entries` in JSON. The API accepts one chunk per request.

## Search and browse

```sh
cloudattrib inventory search --mode exact --query api.example.com
cloudattrib inventory search --mode descendant --query example.com --limit 50
cloudattrib inventory search --mode prefix --query api. --scope example.com
cloudattrib inventory search --mode partial --query staging --format ndjson
```

Modes are `browse`, `exact`, `descendant`, `prefix`, and `partial`. A descendant search excludes the root itself. Prefix and partial search treat `%` and `_` as literal text. Unscoped partial search needs at least three characters. Use `--scope` to limit a search to a registered scope. The default page size is 50 and the maximum is 100.

Results use canonical hostname order. For JSON output, pass the returned `next_cursor` to `--cursor` on the next request. NDJSON CLI output writes one asset per line and prints the next cursor to standard error. HTTP NDJSON puts it in the `X-Next-Cursor` header. A cursor belongs to the same mode, query, scope, and archive setting. Restart from the first page if those filters change. Concurrent imports and deletions can change later pages; for a consistent snapshot, pause writes while exporting all pages.

Read one asset with `cloudattrib inventory read --hostname api.example.com` or `GET /v1/inventory/api.example.com`. Its source list shows provenance, verification state, source observation times when known, and database receipt times. Inventory sources contain compact references, not certificate bodies.

## Archive, delete, and rediscover

`inventory archive --hostname api.example.com` hides an asset from default search while retaining its source facts. Use `--archived=false` to restore it or `--include-archived` to search for it. Archiving does not claim that DNS has changed.

`inventory delete --hostname api.example.com` removes the asset and its inventory-owned source and scope links. A later sighting can create it again. Add `--suppress` to block rediscovery until an operator deletes the suppression record with a later unsuppressed delete. Existing reports and historical CT rows remain intact. The HTTP adapter exposes the same actions through `POST /v1/inventory/{hostname}/archive` and `DELETE /v1/inventory/{hostname}?suppress=true`.

## Backfill historical CT records

New CT imports and collections update the inventory in the same database transaction as their CT records and checkpoint. To copy concrete names from CT rows that existed before the inventory migration, run:

```sh
cloudattrib inventory backfill-ct --limit 1000
```

Repeat with the returned `next_cursor` until `complete` is true. A page commits before its cursor is returned; repeating a page updates the same assets and source summaries. Wildcard records remain excluded. Backfill does not remove or rewrite CT rows or reports.

## Validate known assets

Inventory imports and searches never contact the listed hosts. To collect current DNS evidence or run full analysis, submit an explicit validation job. Select up to 1,000 asset IDs or provide a bounded inventory search selection. The service resolves the selection at admission and stores each canonical hostname, asset ID, and deletion generation with the job. Later imports cannot add targets to it. Validation uses the ordinary job budgets and destination policy, with nested CT discovery disabled.

```sh
cloudattrib inventory validate --idempotency-key check-2026-10 --mode dns --selection-mode descendant --query example.com --scope example.com
cloudattrib inventory validate --idempotency-key check-api-2026-10 --mode full --asset-ids ASSET_ID
```

The HTTP equivalent is `POST /v1/inventory/validate`. A deleted and recreated asset cannot receive inventory evidence from a delayed job admitted for its previous generation. The job report remains available through the normal result route.

## Search qualification

The opt-in PostgreSQL qualification uses skewed domains (90% under the parent root, 10% under a nested root), 100 requests per search mode, and concurrent inventory inserts. On an Apple M4 Pro with PostgreSQL 18 in a local Docker container, the recorded p95 page latencies were:

| Assets | Exact | Descendant | Scoped browse | Partial |
| --- | ---: | ---: | ---: | ---: |
| 10,000 | 1.77 ms | 1.07 ms | 0.81 ms | 1.43 ms |
| 100,000 | 0.96 ms | 3.10 ms | 0.85 ms | 9.37 ms |

`EXPLAIN (ANALYZE, BUFFERS)` used `inventory_assets_hostname_prefix_idx` for exact lookup and `inventory_assets_reversed_idx` for the selective descendant page at both sizes. The 100,000 asset descendant plan read 10,000 index candidates before ordering the 50-item page. These local measurements qualify the stated 100 ms p95 goal for exact and descendant pages on this setup; run the opt-in test against each deployment's PostgreSQL hardware to confirm its limit.

```sh
CLOUDATTRIB_INVENTORY_QUALIFY=1 CLOUDATTRIB_INVENTORY_QUALIFY_SIZE=10000 CLOUDATTRIB_POSTGRES_TEST_DSN='...' go test ./internal/store/postgres -run '^TestInventorySearchQualification$' -count=1 -v
CLOUDATTRIB_INVENTORY_QUALIFY=1 CLOUDATTRIB_POSTGRES_TEST_DSN='...' go test ./internal/store/postgres -run '^TestInventorySearchQualification$' -count=1 -v
```

Run only against a disposable database: the qualification truncates inventory tables.

## Search retained evidence

Saved domain and URL reports queue durable projection work in the same transaction as report persistence. A background worker builds bounded descriptions from typed DNS outcomes, HTTP status codes, technology labels, supported findings, and coverage. It records the report, observation, and evidence IDs behind each description. Search reads these stored descriptions and makes no target requests. Raw TXT values, headers, cookies, URL queries, scripts, and page bodies are excluded. Reports do not retain page titles, so descriptions do not include them.

```sh
cloudattrib inventory search-evidence --query portal --scope example.com
cloudattrib inventory evidence --hostname api.example.com
cloudattrib inventory projection-status
```

Use `GET /v1/inventory/evidence?text=portal&scope=example.com`, `GET /v1/inventory/api.example.com/evidence`, and `GET /v1/inventory/projection-status` for the same operations. Lexical search returns a ranked window of up to 100 matches and a `truncated` flag. It does not claim a total number of relevant assets. The asset read route remains available while projection is pending.

The retrieval interface accepts `lexical`, `semantic`, and `hybrid` modes through `cloudattrib inventory retrieve --query 'customer portal' --mode lexical --scope example.com` or `POST /v1/inventory/retrieve` with JSON `{"text":"customer portal","mode":"lexical","scope_root":"example.com"}`. Query text travels in the HTTP request body. Lexical mode uses the retained description index. Hybrid mode declares `degraded_to_lexical` when no matching local model is configured; semantic-only mode returns a capability error in that case. Each result labels its match modes and retains the report and evidence references. A semantic similarity value, when present, is a ranking score rather than a classification confidence. The candidate and final truncation flags describe bounded windows, not a total number of relevant assets.

State is separate for each observation context derived from the configured resolver and destination policy. Queries default to the service's current context. Pass `--context unknown` or `?context=unknown` to inspect older reports without enough provenance to identify a resolver. A failed latest attempt does not erase the last positive DNS observation or last HTTP response. A 403 or 500 response counts as a response; it is not labeled unreachable. Coverage and timestamps remain visible beside the description. Reclassification may update findings for old evidence, but it does not advance collection time.

To index stored reports from before this feature, run `cloudattrib inventory backfill-reports --limit 1000` in pages until complete, then `cloudattrib inventory project` or leave the service projector running. Backfill and projection read retained reports only. `projection-status` shows pending, running, and failed tasks, plus the number and document bytes of distinct protected reports. The service runs one projector with a separate pool capped at two PostgreSQL connections, so indexing cannot consume the ordinary job and search pool. The projector retries failures with bounded leases; an exhausted task remains visible as failed. Repeat the relevant report backfill page to requeue exhausted failures. Pending tasks and current support references prevent their source reports from being purged. Inventory deletion removes projected state and support references, and a stale projector cannot recreate the deleted asset.
