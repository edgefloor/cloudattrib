# Certificate Transparency operations

Certificate Transparency (CT) is an optional discovery input. It supplies historical hostname leads from a local PostgreSQL index. It does not prove current DNS existence, current product use, infrastructure ownership, or exhaustive discovery. `cloudattrib analyze` never contacts a CT log or CT search service; selected concrete names go through the ordinary DNS and HTTP policy before they can support current findings.

CT is disabled by default. A request with `ct_discovery=true` reports one of five states:

- `skipped` with `reason=disabled` when CT is disabled;
- `unavailable` when the enabled local index cannot be read;
- `complete` with `reason=empty_index` when the local index has no in-scope concrete names;
- `partial` when selected records include unverified ingestion or the configured top-N limit omits candidates;
- `complete` when the selected local candidate set was fully processed.

Set `CLOUDATTRIB_CT_ENABLED=true` and `CLOUDATTRIB_POSTGRES_DSN_FILE` before running the CLI or service to enable reads from the durable local index. The DSN environment value names a file; it never contains the connection string itself.

The default selection limit is 20 names. Selection is newest logged time first, then hostname. Wildcards remain patterns in storage and are never expanded into invented hostnames.

## Local JSONL import

`ct import` reads operator-controlled normalized records. It validates the complete input before publishing any records, filters names at DNS label boundaries, and deduplicates `(name, certificate_hash)` values within the input.

```sh
cloudattrib ct import --input ct-records.jsonl --scope example.com
```

Use `--input -` for standard input. A comma-separated `--scope` value supplies multiple roots. Imports need `CLOUDATTRIB_POSTGRES_DSN_FILE` to name a private regular file containing one PostgreSQL connection string.

Imported records always become `provenance=imported_unverified`; claimed verification labels in the input cannot cross this trust boundary. The shipping JSONL contract does not carry the pinned key and full proof material needed to repeat the collector procedure. A successful parse or a trusted local file is not cryptographic verification.

## Bounded RFC 6962 collection

The collector supports only the RFC 6962 HTTP read API. It uses `github.com/google/certificate-transparency-go` v1.3.3 with an application-owned HTTP client, an explicit timeout, and a pinned DER or single `PUBLIC KEY` PEM file. HTTPS is required. Unsupported protocols fail before collection.

The configuration is strict JSON:

```json
{
  "protocol": "rfc6962",
  "log_id": "sha256:<hex SHA-256 of the DER public key>",
  "url": "https://ct-log.example",
  "public_key_file": "/etc/cloudattrib/ct-log-public-key.pem",
  "source_id": "operator-log-name",
  "roots": ["example.com"],
  "start_index": 125000000,
  "budget": {
    "maximum_entries": 256,
    "batch_size": 64,
    "maximum_proofs": 16,
    "maximum_requests": 24,
    "maximum_bytes": 8388608,
    "maximum_seconds": 60
  }
}
```

Run one bounded increment with:

```sh
cloudattrib ct collect --config ct-log.json
```

`start_index` is an explicit backfill boundary. It is required even when a durable checkpoint already exists, preventing a missing database from silently starting a global crawl. An operator may supply `trusted_checkpoint` instead, with `next_index`, `tree_size`, a 32-byte hexadecimal `root_hash`, and an RFC 3339 `tree_timestamp`. This is an explicit trust decision: continuity is `not_performed` at the initial authenticated tree and is checked on later extensions.

The collector records three independent outcomes:

1. `checkpoint_signature`: the signed tree head passed verification under the pinned key.
2. `continuity`: the new tree is consistent with the last verified tree, or records why the initial check was not performed.
3. `entry_inclusion`: the audit path includes the exact entry bytes fetched at that index.

Only entries with an authenticated tree and a passing exact-byte inclusion proof receive `verified_log`. Failed or budget-omitted proofs receive `log_unverified`. A failed check never advances the verified checkpoint. Ingestion progress is separate, so a bounded run can retain unverified history and resume without describing it as verified.

The default budget verifies at most 16 of 256 fetched entries. Therefore a full default run normally advances ingestion progress but not the verified-tree checkpoint. Increase `maximum_proofs` and the corresponding request budget when every fetched entry must be independently verified.

## Retention and operating envelope

PostgreSQL stores normalized names, certificate hashes, validity times, log positions, independent verification outcomes, and collector checkpoints. Root filtering reduces retained data only. RFC 6962 fetches entries by global index, so root filtering does not reduce downloaded log traffic.

The shipping collector was measured on 2026-09-20 with the synthetic RFC 6962 fixture on an Apple M4 Pro (`darwin/arm64`, Go 1.25), using the default 256-entry, 64-entry batch, 16-proof, 24-request, 8 MiB, 60-second envelope:

| Metric | Synthetic result |
| --- | ---: |
| Entries inspected | 256 |
| Elapsed collector time | 3.07 ms/run (five-run benchmark) |
| Approximate throughput | 83,300 entries/second |
| Requests | 21 |
| Accounted response bytes | 84,640 bytes |
| Normalized retained-field bytes | 44,800 bytes |
| Fixture ingestion lag | 1 hour |
| Backlog | 256 before, 0 after |

The command was:

```sh
go test ./internal/ctlog -run '^$' -bench '^BenchmarkCollectorShippingBudget$' -benchtime=5x -count=1
```

This fixture measures local parsing, proof verification, normalization, and budget accounting. It excludes public-network latency and PostgreSQL storage overhead. No live log was probed because no operator-approved log URL, pinned key, and starting checkpoint were supplied. Consequently, the figures are a reproducible implementation envelope, not a live capacity claim. Backlog decreases by at most `maximum_entries` per successful run and grows whenever the log adds entries faster than scheduled collection drains them.
