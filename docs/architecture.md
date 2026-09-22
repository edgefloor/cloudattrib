# Architecture contracts

This page maps package ownership and the contracts that cross package boundaries. [SPEC.md](../SPEC.md) defines the behavior. The [qualification report](qualification.md) lists the checks that have run.

## Package boundaries

| Package | Owns | Does not own |
| --- | --- | --- |
| `model` | Normalized values and report types | Types from DNS, HTTP, BART, PostgreSQL, or fingerprint libraries |
| `target` | Input normalization and root scope | Permission to connect to a destination |
| `policy` | Address and port validation, collection budgets | Product attribution |
| `collect/dns`, `collect/http` | Typed collection observations and outcomes | Product inference or relaxed scope rules |
| `datasets` | Immutable bundle construction and publication | Changes to a view already captured by an attempt |
| `app`, detectors, and enrichment adapters | Evidence from observations and consulted records | PostgreSQL transaction details |
| `aggregate` | Findings grouped from evidence | New network collection |
| `jobs` | Admission, reservations, leases, retries, cancellation, and pins | Database-specific transaction implementation |
| `store/postgres` | Durable records and job transaction boundaries | Per-address prefix matching |
| `api`, `cli` | Input and output contracts | Alternate collection or attribution rules |

See the [package map](../internal/README.md) for paths. Updaters and CT collectors run separately from target analysis.

## Destination validation

The DNS collector validates each candidate address and publishes approved public addresses as they arrive. HTTP can start before another address family or unrelated DNS questions finish.

The HTTP collector dials the selected address exactly. It preserves the requested hostname for HTTP Host and TLS SNI. Redirects, retries, and alternate-address attempts repeat resolution and validation. The transport must never resolve and dial a different address after approval.

Mixed answers remain evidence. A prohibited address retains its observation and policy reason. It does not block an approved address. Record failed or delayed AAAA queries even when HTTP succeeds through IPv4.

Tests instrument dial attempts and require zero attempts to prohibited addresses. See SPEC sections [3.4](../SPEC.md#34-execution-order-and-consistency), [4.2](../SPEC.md#42-dns-result-semantics), and [5.2](../SPEC.md#52-request-destination-policy).

## Availability and report status

Collectors and classifiers return useful results with per-capability coverage. An unavailable source never becomes an empty successful search.

| Available work | Result | HTTP | CLI |
| --- | --- | --- | --- |
| All requested applicable work completed | Complete report, including complete no-match | 200 | 0 |
| Useful observations or results remain, but requested coverage is incomplete | Partial report with affected capabilities | 200 | 3 |
| No necessary requested execution path can run | `capability_unavailable` | 503 | 4 |

Useful evidence can include a completed negative DNS answer or an empty search of a usable source. A failed query cannot establish absence. Request validation and persistence failures remain explicit errors.

Application errors carry stable codes. Adapters report failures to the application layer, which applies [SPEC section 14.2](../SPEC.md#142-result-status). HTTP and CLI adapters map that result to their interface contracts.

## Bundle capture, pins, and pruning

An unpinned target attempt captures the active bundle when it starts. A retry may capture a newer bundle. A pinned batch uses its requested compatible bundle for every attempt.

Pinned admission and pruning share one coordination boundary:

1. Admission validates the requested bundle while pruning is excluded.
2. Admission commits the job and its durable bundle reference before returning success.
3. Pruning checks durable references under the same coordination. If it cannot check them, it stops.
4. The job releases its pin only in the transaction that makes every target terminal.

Pins cover queued work, running attempts, and pending retries across restarts. A cancellation request alone does not release a pin. Active views, in-flight readers, other jobs, and last-known-good retention can keep a bundle protected after the batch finishes.

See SPEC sections [3.4](../SPEC.md#34-execution-order-and-consistency), [12.2](../SPEC.md#122-durable-job-execution), and [13.2](../SPEC.md#132-update-transaction).

## PostgreSQL job transaction protocol

Replay-safe job lifecycle transactions acquire the transaction-scoped lifecycle advisory lock before they lock a job or a target row. Admission, claim, cancellation, completion, lease recovery, and bundle pruning use this order. The lock covers only short database transactions. DNS and HTTP work runs after the claim transaction commits.

The PostgreSQL adapter retries a complete replay-safe transaction after SQLSTATE `40001` or `40P01`. The retry count and delay are bounded, and retry waits use the caller's context. The adapter returns other commit errors without replay. Connection-level commit failures can have an ambiguous result.

Bundle activation invokes a filesystem publication callback and does not use the retry wrapper. A failed publication returns once, so a database retry cannot repeat the filesystem mutation.

## Reclassification time and provenance

Reclassification creates a new report from retained observations and reusable detector outputs. It selects a compatible bundle and records a new classification time. Collection times and original collection coverage remain unchanged. Reclassification performs no collection.

Passive web fingerprinting returns typed raw technology labels with detector identity and detector-result explanation granularity. The application retains those labels as technology observations before running product rules. Live analysis and replay therefore apply the same taxonomy to the same observation shape; human-readable evidence explanations are generated output and are never parsed as classifier input. A retained framework label can produce a providerless `web_technology` finding, but it cannot establish cloud-provider ownership.

Evidence references both observations and consulted dataset records. Each dataset record retains its source, revision or digest, record reference, and known publication and effective times. Unknown times stay unknown. A new ownership association does not imply that it existed when the observations were collected.

The `model` package owns observation occurrence IDs and report content IDs. Collectors supply run, seed, request or query, hop, attempt, and item context. Reclassification preserves the collected observation IDs. Report content IDs use the versioned canonical projection in [SPEC section 9.2](../SPEC.md#92-core-fields), while PostgreSQL keeps historical report IDs unchanged.

If one replay path lacks inputs but another works, return a partial report. If none works, return `capability_unavailable`. See SPEC sections [9.1 through 9.5](../SPEC.md#91-collected-observations-source-records-and-conclusions) and [12.3](../SPEC.md#123-history-and-retention).

## CT verification

CT records keep three checks separate: `checkpoint_signature`, `continuity`, and `entry_inclusion`. Each check records `passed`, `failed`, or `not_performed`, its procedure version, tree or key identity, and a reason when it did not run.

`verified_log` requires an authenticated tree and proof that the exact entry bytes belong to it. A valid signature or continuity proof alone is insufficient. Failed verification cannot advance a verified checkpoint or publish a verified entry.

Imports without equivalent proof use `imported_unverified`. Fetched entries without inclusion proof use `log_unverified`. CT ships as an optional module and remains disabled by default. See [SPEC section 10.1](../SPEC.md#101-supported-ingestion-paths) and [CT operations](ct-operations.md).

## Access, identity, and cancellation

All authenticated operators share result visibility and may cancel any job. Operator identity scopes idempotency keys and audit attribution. There is no tenant isolation or caller-specific result ownership.

The service derives identity from configured credentials or a trusted proxy. The proxy must strip client identity headers before adding its verified identity. Request bodies and arbitrary headers cannot select an operator. Explicit unauthenticated loopback mode uses `local-operator`.

Cancellation stops new scheduling and propagates through collection, leases, and database calls. Already-started work may finish. Shared visibility remains unchanged. See SPEC sections [11.3](../SPEC.md#113-required-http-routes), [11.4](../SPEC.md#114-shared-trusted-operator-access), and [12.2](../SPEC.md#122-durable-job-execution).

## Product relationships

Use the relationship named by the signal. SPF produces `sending_authorization`. MX records produce `mail_routing`. A generic cloud range produces a provider finding, while a product-specific CNAME can name the product. Technology-only findings omit `provider_id`. They require a product ID, the `web_technology` category, and the `web_integration` relation.

Every supported matrix row needs a dated source, canonical mapping, positive and negative fixtures, subject, scope, relation, and evidence reference. Unsupported cases must explain the missing or insufficient signal. See [rule coverage](../rules/coverage-matrix.md) and [SPEC section 8.5](../SPEC.md#85-product-and-relationship-acceptance-matrix).

## Shared invariants

- Validate scope before any live connection.
- Copy mutable slices and maps when ownership crosses a view or report boundary.
- Keep observations, dataset records, evidence, and findings as separate types.
- Record unavailable, skipped, completed, truncated, and omitted work in coverage.
- Use deterministic ordering without implying a winning provider where evidence conflicts.
