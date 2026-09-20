# Certificate Transparency operations

Certificate Transparency (CT) adds historical hostname candidates to domain analysis. Candidates come from a local PostgreSQL index. Analysis never contacts a public CT log or search service.

A certificate name does not prove current DNS existence, product use, or ownership. Selected concrete names must pass the ordinary DNS and HTTP collection policy before supporting current findings. Discovery is not exhaustive.

- [Enable local discovery](#enable-local-discovery)
- [Import JSONL records](#local-jsonl-import)
- [Collect a bounded log increment](#bounded-rfc-6962-collection)
- [Understand retention and measured costs](#retention-and-operating-envelope)

## Enable local discovery

CT is disabled by default. When a request asks for `ct_discovery=true`, coverage distinguishes these cases:

| Condition | Coverage |
| --- | --- |
| CT is disabled | `skipped`, with `reason=disabled` |
| The enabled index cannot be read | `unavailable` |
| No in-scope concrete names exist in the local index | `complete`, with `reason=empty_index` |
| Selected records are unverified, or the selection limit omits candidates | `partial` |
| The selected local candidate set was fully processed | `complete` |

For standalone CLI discovery, set `CLOUDATTRIB_CT_ENABLED=true` and set `CLOUDATTRIB_POSTGRES_DSN_FILE` to a private DSN file. The environment value is a path, not the connection string. Then request discovery with `cloudattrib analyze example.com --ct`.

For `serve --config`, set `ct.enabled` and `storage.postgres_dsn_file` in that command's configuration. A command-specific configuration replaces the startup configuration.

The default limit is 20 names, ordered by newest logged time and then hostname. Stored wildcards remain patterns; the application does not invent matching hostnames.

## Local JSONL import

`ct import` reads normalized records from a local file. It validates the whole input before publishing records, filters names at DNS label boundaries, and removes duplicate `(name, certificate_hash)` pairs. See the [record schema](../schema/ct-record.schema.json) for fields.

```sh
cloudattrib ct import --input ct-records.jsonl --scope example.com
```

Use `--input -` for standard input. A comma-separated `--scope` value supplies multiple roots. Imports need `CLOUDATTRIB_POSTGRES_DSN_FILE` to name a private regular file containing one PostgreSQL connection string.

Imported records always receive `provenance=imported_unverified`, regardless of labels in the file. The current JSONL format lacks the pinned key and proof material needed to repeat collector verification. Parsing a trusted file does not verify a log entry.

## Bounded RFC 6962 collection

The collector supports the RFC 6962 HTTP read API over HTTPS. It uses `github.com/google/certificate-transparency-go` v1.3.3 with an application-owned HTTP client and explicit timeout. Supply a pinned key as DER or a single `PUBLIC KEY` PEM file. Unsupported protocols fail before collection.

The configuration is strict YAML or JSON:

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

Supply either `start_index` or `trusted_checkpoint`, even when the database already has a checkpoint. This prevents a missing database from silently starting a global crawl.

`start_index` sets the backfill boundary. `trusted_checkpoint` instead supplies `next_index`, `tree_size`, a 32-byte hexadecimal `root_hash`, and an RFC 3339 `tree_timestamp`. Trust in that initial tree is an operator decision. Initial continuity is `not_performed`; later extensions require a continuity check.

### Interpret verification results

The collector records three independent outcomes:

1. `checkpoint_signature`: the signed tree head passed verification under the pinned key.
2. `continuity`: the new tree is consistent with the last verified tree, or records why the initial check was not performed.
3. `entry_inclusion`: the audit path includes the exact entry bytes fetched at that index.

An entry receives `verified_log` only when its exact bytes pass an inclusion proof in an authenticated tree. Failed or budget-omitted proofs leave the entry `log_unverified`.

A failed check never advances the verified checkpoint. Ingestion progress is separate: a run can retain unverified history and resume from it without making a verification claim.

The default budget permits 16 inclusion proofs for 256 fetched entries. A full default run normally advances ingestion progress without advancing the verified-tree checkpoint. To verify every fetched entry, increase both `maximum_proofs` and the request budget.

## Retention and operating envelope

PostgreSQL stores normalized names, certificate hashes, validity times, log positions, verification outcomes, and checkpoints.

Root filtering reduces retained data. It does not reduce log downloads: RFC 6962 retrieves entries by global index, and the collector filters them locally.

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

These measurements cover local parsing, proof verification, normalization, and budget accounting. They exclude public-network latency and PostgreSQL storage overhead. No live log was probed because no approved URL, pinned key, and starting checkpoint were supplied.

A successful run reduces backlog by at most `maximum_entries`. Backlog grows if the log adds entries faster than scheduled runs process them. Measure live throughput before choosing a collection schedule.
