# Architecture contracts

Status: wave 0 contract record for SPEC 2.1.

This reference records the package-facing contracts that implementation must preserve. [SPEC.md](../SPEC.md) remains authoritative when this record and the specification differ.

## Package boundaries

`internal/model` owns normalized values and immutable report types. It does not expose DNS-library, HTTP-transport, BART, PostgreSQL, or fingerprint-library types.

`internal/target` parses and normalizes caller input before collection. `internal/policy` decides whether a concrete address and port may be dialed. Collection packages do not infer target scope or relax policy.

`internal/collect/dns` publishes typed observations and address candidates as answers arrive. `internal/collect/http` consumes approved candidates and dials the selected address exactly. Both packages use caller-owned budgets and contexts.

`internal/datasets` builds and publishes immutable `AttributionView` values. A target attempt captures one view. Classification and enrichment read only that captured view.

`internal/aggregate` creates evidence and findings from observations and consulted dataset records. It does not collect new data or decide lead qualification.

`internal/jobs` owns durable admission, reservations, leases, retries, cancellation, and bundle pins. `internal/store/postgres` implements its transaction boundaries. `internal/api` maps the settled application and access contracts to HTTP.

## Destination validation

The DNS collector validates each address independently. It publishes approved public addresses without waiting for another address family or unrelated DNS questions. The HTTP collector dials one approved address exactly and preserves the requested hostname for HTTP Host and TLS SNI.

Mixed answers remain mixed evidence. A prohibited address produces an observation and a policy decision, but it does not block an approved address. A failed or delayed AAAA query does not delay HTTP through an approved IPv4 address. Redirects, retries, and alternate-address attempts repeat resolution and per-address validation. No transport path may resolve and dial a different address after validation.

Package tests must instrument dial attempts and prove that prohibited addresses receive zero attempts. See [SPEC sections 3.4, 4.2, and 5.2](../SPEC.md#34-execution-order-and-consistency).

## Source availability and result status

Collectors and classifiers return useful observations and supported results together with per-capability coverage. An unavailable source never becomes an empty successful search.

If another requested path produces useful results, the report status is `partial`, HTTP returns 200, and the CLI exits with 3. If no necessary requested path can run, the operation returns `capability_unavailable`, HTTP returns 503, and the CLI exits with 4. A complete no-match requires every requested applicable source to be usable and searched.

Application errors carry stable external codes. Adapters report source failures to the application layer instead of choosing an HTTP status or CLI exit code. See [SPEC sections 7.4 and 14.2](../SPEC.md#74-unknowns-and-bounds).

## Bundle capture, pins, and pruning

Each unpinned target attempt captures the active immutable bundle when that attempt starts. A retry may capture a newer bundle. A pinned batch uses one requested compatible bundle for every target attempt.

Pinned-batch admission and pruning share one store-level coordination boundary. Admission validates the bundle and commits both the job and its durable bundle reference before returning success. Pruning checks durable references under the same coordination and fails closed when it cannot check them.

A pin protects queued, running, and retrying targets across process restarts. The job releases the pin only in the transaction that makes every target terminal. A cancellation request alone does not release the pin. Active views, in-flight readers, other jobs, and last-known-good retention can continue to protect a bundle after the batch releases its pin. See [SPEC sections 3.4, 12.2, and 13.2](../SPEC.md#34-execution-order-and-consistency).

## Reclassification time and provenance

Reclassification creates a new report from immutable collected observations and reusable detector outputs. It captures a selected compatible bundle and records a new classification time. It never changes collection times and never performs collection.

Evidence distinguishes observation references from consulted dataset-record references. Each consulted record keeps its source identity, revision or digest, record reference, publication time, and effective time when known. Unknown times remain unknown. A newly consulted ownership record does not claim that the ownership existed at the original collection time.

If one replay path lacks retained inputs but another path works, the report remains useful and is `partial`. If no requested replay path can run, admission returns `capability_unavailable`. See [SPEC sections 9.1 through 9.5 and 12.3](../SPEC.md#91-collected-observations-source-records-and-conclusions).

## CT verification

CT records store `checkpoint_signature`, `continuity`, and `entry_inclusion` as independent checks. Each check records `passed`, `failed`, or `not_performed`, plus its procedure version, authenticated tree or key identity, and a reason when the check did not run.

`verified_log` requires an authenticated tree and proof that the exact entry bytes are included in that tree. A valid checkpoint signature or continuity proof alone is insufficient. Failed verification does not advance the verified checkpoint or publish verified entries. Imports without equivalent proof use `imported_unverified`; fetched entries without inclusion proof use `log_unverified`. See [SPEC section 10.1](../SPEC.md#101-supported-ingestion-paths).

## Access, identity, and cancellation

The service uses one shared trusted-operator access model. Every authenticated operator can read results and cancel any job. Stable operator identity scopes idempotency keys and audit attribution only. It does not create tenant ownership or tenant isolation.

The server derives identity from configured credentials or from a trusted proxy that strips client identity headers. An explicit unauthenticated loopback deployment uses `local-operator`. Request bodies and arbitrary client headers cannot select an identity.

Cancellation stops new scheduling and propagates through collection, leases, and database calls. It is best effort for work already in progress. Job and result visibility remain shared after cancellation. See [SPEC sections 11.3, 11.4, and 12.2](../SPEC.md#113-required-http-routes).

## Minimum product and relationship coverage

Findings describe attribution evidence for lead enrichment. The application does not decide qualification and does not estimate spend or savings.

Rules preserve the relationship established by the signal. SPF evidence uses `sending_authorization`; it does not become mail routing or paid adoption. Provider-only output is valid when the signal supports only provider ownership, such as a generic cloud range. Provider-only output cannot replace a supported product-specific result.

Every supported row in the product-and-relationship matrix needs a dated source, canonical mapping, positive fixture, negative fixture, subject, scope, relationship, and evidence reference. An unsupported case must name the missing or insufficient signal. See [SPEC sections 8.5 and 9.1](../SPEC.md#85-product-and-relationship-acceptance-matrix).

## Stable implementation rules

- Scope validation finishes before any live connection.
- Mutable slices and maps do not cross immutable-view or report ownership boundaries without copying.
- Observations, dataset records, evidence, and findings remain separate types.
- Coverage records unavailable, skipped, completed, truncated, and omitted work explicitly.
- Deterministic ordering never implies a winning provider when evidence conflicts.
- Dataset updaters and CT collectors run separately from target-request collection.
- CT remains disabled by default, but its import, collection, verification, and discovery paths ship with the system.
