# Implementation plan: self-hosted cloud and SaaS attribution

Project: `cloudattrib`

Plan version: 2.2, dated 2026-09-20

Behavior contract: [SPEC.md](SPEC.md)

Execution rules: [Wave assignments, roles, and validation](docs/execution-plan.md)

This is the delivery and acceptance checklist used for implementation. The application now exists. The unchecked items below are retained acceptance requirements, not a current task-status ledger. Use the [qualification report](docs/qualification.md) for recorded evidence and known test limits.

P0 through P11 define deliverables. Waves 0 through 7 define execution order and ownership. Those workflow settings belong in the execution plan, not `AGENTS.md`. New work still requires an implementation instruction.

## Find a phase

- [Delivery scope and E1](#1-delivery-scope)
- [Repository structure](#2-repository-structure)
- [P0: source and dependency audit](#3-p0-verify-contracts-and-build-the-test-foundation)
- [P1: shared contracts](#4-p1-shared-model-scope-and-contracts)
- [P2: importers](#5-p2-cloud-provider-and-service-range-importers)
- [P3: indexes and bundles](#6-p3-local-indexes-asn-cdn-and-bundle-construction)
- [P4: DNS](#7-p4-dns-collection-and-local-recursion)
- [P5: HTTP and fingerprints](#8-p5-httptls-collection-and-local-web-fingerprints)
- [P6: rules and aggregation](#9-p6-product-rules-taxonomy-and-evidence-aggregation)
- [P7: analyzer and CLI](#10-p7-complete-analyzer-and-cli)
- [P8: persistence, jobs, and API](#11-p8-persistence-durable-jobs-and-http-api)
- [P9: CT](#12-p9-optional-ct-import-log-collection-and-discovery)
- [P10: operations](#13-p10-operational-updates-visibility-and-deployment)
- [P11: qualification](#14-p11-complete-system-qualification)
- [Cross-module tests](#15-cross-module-test-matrix)
- [Traceability](#16-requirement-traceability)
- [Fixed decisions](#17-decisions-that-must-not-drift-during-implementation)
- [Final checklist](#18-final-delivery-checklist)

## 1. Delivery scope

The application supplies attribution evidence for lead enrichment. Downstream users make qualification decisions. Qualification, scoring, spend estimates, and savings estimates remain outside scope.

Every specified capability is required for delivery. Runtime source failures follow SPEC section 14.2, which preserves useful evidence with explicit coverage limits.

Implement the complete pipeline agreed in the specification:

```text
domain / hostname / URL
    -> scoped DNS and HTTP collection
    -> CNAME, MX, NS, TXT and HTTP product detection
    -> local cloud/service/CDN/ASN enrichment
    -> evidence-aware aggregation
    -> persisted infrastructure and SaaS report
```

Local IP lookup is one exposed component. Delivery also requires DNS, HTTP fingerprints, service and region enrichment, local ASN, rules, aggregation, persistence, and batch processing. These capabilities must not be deferred as unspecified extensions.

Implement CT import, the supported log collector, and discovery integration. Keep CT disabled in the default deployment. Ordinary full analysis must work without CT.

Each phase lists tasks and acceptance evidence. Phases set the work order; they do not reduce the release requirements.

### 1.1 Work sequence and dependency graph

| Phase | Deliverable | Depends on |
| --- | --- | --- |
| P0 | Verified source/dependency contracts and controlled test corpus | None |
| P1 | Shared models, target policy, schemas, taxonomy and adapter contracts | P0 |
| E1 | Early integrated DNS/HTTP/classification fixture report | P1; minimal working paths from P3–P6 |
| P2 | Cloud-provider and service-range importers | P1 |
| P3 | Local IP/ASN/CDN indexes and immutable data bundles | P1, P2 |
| P4 | DNS collector and local resolver integration | P1 |
| P5 | HTTP/TLS collector and local `wappalyzergo` detector | P1; resolver contract from P4 |
| P6 | Product rules and evidence aggregation | P1; fixture contracts from P2–P5 |
| P7 | Complete analyzer, CLI, batching, and offline reclassification | P3–P6 |
| P8 | PostgreSQL persistence, durable jobs, and HTTP API | P7; storage schema can start after P1 |
| P9 | Optional local CT ingestion, collection, and discovery | P4, P7, P8 |
| P10 | Update/reload operations, observability, and deployment | P3, P8; CT integration from P9 |
| P11 | Full-system qualification and release evidence | P0–P10 |

The dependency table identifies required contracts. It does not authorize parallel agents; use the limits in the [execution workflow](docs/execution-plan.md).

Draft P1 contracts alongside the P0 audit in wave 1, then freeze them after resolving relevant findings. E1 proves a minimal path in wave 2. Wave 3 expands data and collection; wave 4 completes rules and CLI. Wave 5 adds storage and API work. Validate each integration before proceeding.

Run E1 as soon as one collection and classification path works, before completing every importer and rule. E1 checks integration within P3 through P6. It does not replace P7 or P11.

No time or staffing estimate is implied by this sequence.

### 1.2 E1: early integrated fixture milestone

- [ ] Analyze one controlled domain through real DNS and bounded HTTP collectors, one local product detector, a small pinned enrichment dataset, and aggregation.
- [ ] Produce a schema-valid report containing immutable observations, consulted dataset provenance, evidence references, typed findings, coverage, and separate collection/classification times.
- [ ] Assert a supported product relationship and the absence of unsupported qualification, spend, subscription, and hidden-origin claims.
- [ ] Run variants with a missing enrichment source, mixed approved/prohibited addresses, and delayed or failed AAAA. HTTP must start through an approved public address without waiting for AAAA; prohibited addresses must never be dialed.
- [ ] Validate the resulting complete/partial report and CLI exit contract without relying on live third-party services or requiring PostgreSQL.

E1 passes when an in-process fixture uses controlled DNS and HTTP services with real code for the chosen path. Remaining adapters stay in P2 through P6. Final delivery still requires R01 through R23 and the complete P7 and P11 scenarios.

## 2. Repository structure

This is the original responsibility map. It includes proposed paths and artifacts, not a current file inventory. The [internal package map](internal/README.md) lists the implementation paths. Acceptance requires the behavior below even where the implementation groups it differently.

```text
cmd/cloudattrib/
  main.go
internal/
  app/                     Analyze, lookup, batch, reclassify orchestration
  model/                   Targets, observations, evidence, findings, reports
  target/                  IDNA, URL/IP normalization, explicit root scopes
  policy/                  Destination policy, budgets, profile defaults
  collect/
    dns/                   Raw RR collection, chains, dependency context
    http/                  Safe dialing, redirects, TLS and response capture
  detect/
    dnsrules/              Typed DNS and TXT/SPF rules
    webtech/               Local wappalyzergo adapter
    httprules/             Product-specific header/script rules
    cdn/                   Local cdncheck-derived data adapter
  enrich/
    prefix/                BART wrapper and all/longest semantics
    asn/                   Local interval indexes
    network/               Observed-address enrichment coordinator
  taxonomy/                Canonical provider/product aliases and roles
  aggregate/               Deduplication, findings, conflicts, summaries
  ingest/
    cloudranges/           disposable/cloud-ip-ranges adapter
    aws/                   Official AWS service ranges
    gcp/                   Official GCP cloud ranges
    azure/                 Downloadable Azure Service Tags
    iptoasn/               IPv4 and IPv6 interval TSV
    cdndata/               Pinned generated cdncheck data conversion
  datasets/                Manifests, validation, bundles, activation, rollback
  jobs/                    Admission, worker leases, retries, cancellation
  store/postgres/          Migrations, repositories, immutable report writes
  ct/                      Import, supported log reads, checkpoints, local index
  api/                     HTTP handlers, authentication, pagination, errors
  cli/                     Commands and JSON/JSONL rendering
  observability/           Health, counters, structured logs
  capture/                 Redaction and opt-in restricted raw artifacts
api/
  openapi.yaml
schema/
  analyze-request.schema.json
  report.schema.json
  observation.schema.json
  evidence.schema.json
  finding.schema.json
  rule-bundle.schema.json
  data-manifest.schema.json
  ct-record.schema.json
rules/
  dns/
  http/
  technology-map.json
  providers.json
  products.json
  coverage-matrix.md
migrations/
config/
  example.yaml
  ct-logs.example.yaml
  source-selection.example.json
deploy/
  compose.yaml
  Dockerfile
  unbound.conf
  systemd/
testdata/
  upstream/                Pinned small source-format fixtures
  dns/                     Authoritative zones and query scenarios
  http/                    Sanitized headers, HTML, redirects, TLS fixtures
  ct/                      Synthetic log and certificate fixtures
  scenarios/               Complete multi-vendor target scenarios
  golden/                  Canonical report and interface outputs
scripts/
  offline-test.sh
  integration-test.sh
  reference-benchmark.sh
  release-check.sh
docs/
  architecture.md
  source-contracts.md
  dependency-audit.md
  rule-authoring.md
  operations.md
  api-examples.md
  benchmark-results.md
  accuracy-evaluation.md
SPEC.md
IMPLEMENTATION-PLAN.md
go.mod
go.sum
```

Keep BART, DNS-library, fingerprint-library, and PostgreSQL types out of the shared application model. Use internal packages until a real external Go consumer requires a stable public module. Do not split the system into microservices during this implementation.

## 3. P0: verify contracts and build the test foundation

**Covers:** R02, R07–R12, R20, R23.

### Implementation tasks

- [ ] Select a supported Go toolchain and pin it. Pin direct and transitive dependencies in `go.mod`/`go.sum`; do not ship `@latest` as the production dependency strategy.
- [ ] Compile a minimal BART contract test for insertion, exact-prefix access, covering-prefix enumeration, and longest-prefix lookup.
- [ ] Inspect the chosen DNS implementation's maintenance status and API. Record why that revision was selected and how the adapter can be replaced.
- [ ] Inspect `wappalyzergo` construction and fingerprint calls. Record the library revision, embedded-data hash, concurrency behavior, and whether the selected APIs expose individual match explanations.
- [ ] Audit transitive imports and initialization paths for network attempts, telemetry, default public resolvers, remote rule downloads, and environment-proxy behavior.
- [ ] Do not directly import unmodified `cdncheck` into the worker. Define the generated-data conversion contract and retain upstream notices. Verify data-only output can cover the intended CDN/cloud categories.
- [ ] Obtain one complete `disposable/cloud-ip-ranges` revision without running its crawler. Inventory all selected provider schemas, method strings, lifecycle/detail shapes, and special categories.
- [ ] Obtain representative official AWS, GCP, Azure and IPtoASN files. Record download URLs, timestamps, checksums, schemas, and source-specific limitations.
- [ ] Verify data-source terms separately from application code licenses. Record unresolved redistribution questions as release blockers for redistributing that data, not as permission to guess.
- [ ] Build controlled DNS, HTTP/TLS, and CT fixtures. Include invented providers and documentation address ranges for deterministic index tests.
- [ ] Run an explicitly configured bounded CT feasibility probe. Measure entries/second, downloaded bytes, retained storage, ingestion lag, and backlog trend. Record logs, checkpoint, hardware, observation window, and entry/byte/request/time budgets. Document that root-scope filtering reduces retained records but does not provide domain-filtered RFC 6962 retrieval. Use the measured limits to plan P9 without dropping its delivery requirement.
- [ ] Validate source references and signal availability for SPEC section 8.5's product-and-relationship matrix. Record exact supported signals and justified unsupported cases before treating provider-only fallback as sufficient.
- [ ] Add formatting, vet, unit-test, race-test, and build checks. Provide a network-denied test job after dependency prefetch/vendor preparation.

### Acceptance evidence

`docs/source-contracts.md` inventories the full selected source revision, not just a README or one provider. `docs/dependency-audit.md` identifies the chosen versions, licenses/notices, expected network behavior, and adapter boundaries.

Record attempted connections in startup and offline probes, including failed attempts. A hidden public-DNS check is still an audit finding if the connection fails.

### Exit gate

The selected APIs compile, source formats and provenance requirements are documented, and fixtures run without third-party web services. Unsupported source shapes fail explicitly instead of becoming empty datasets.

**References:** SPEC sections 2, 6, 7, 17. Sources S01–S14.

## 4. P1: shared model, scope, and contracts

**Covers:** R03, R12, R13, R15, R20, R22.

### Implementation tasks

- [ ] Implement normalized target types for domain/hostname, URL, and IP. Preserve original input and canonical values separately.
- [ ] Implement IDNA, case/root-dot handling, IP unmapping, zone rejection, HTTP/HTTPS-only URL parsing, and input-length limits.
- [ ] Define explicit root scopes and seed planning. Root-domain input can add `www`; hostname/URL input must not silently expand to the whole registrable domain.
- [ ] Make `kind=ip` select local-IP behavior and reject incompatible live-collection options rather than silently initiating DNS or HTTP.
- [ ] Define typed observations, evidence, findings, coverage, provider/product taxonomy, source metadata, and versioned report envelopes.
- [ ] Keep immutable collected observations distinct from versioned dataset records consulted during classification. Define collection time, classification time, source publication/effective time, and unknown-time representation independently.
- [ ] Define relationship and activity enums from the spec, including `sending_authorization` for appropriate SPF evidence. Keep sending authorization distinct from mail routing and paid adoption. Unknown products remain null; externally supplied organization labels remain unverified grouping metadata.
- [ ] Define `DNSClient`, transport/dialer, collector, detector, ASN reader, prefix reader, snapshot reader, and result-store interfaces.
- [ ] Define typed input, policy, source, timeout, budget, unavailable-data, and storage errors with stable external codes.
- [ ] Define deterministic ordering, deduplication keys, canonical serialization, and content-ID generation. Separate observation time from bundle build/activation time.
- [ ] Define schemas for API payloads, rules, source manifests, and normalized records. Treat example payloads as schema test inputs.
- [ ] Specify the local configuration contract, including resolver addresses, source paths, network policy, resource limits, and optional CT settings.
- [ ] Encode SPEC section 14.2's per-mode admission, capability degradation, readiness, report-status, HTTP-status, and CLI-exit contracts. Distinguish delivery requirements from request-time prerequisites and unavailable data from no-match.
- [ ] Specify per-address validation and early HTTP scheduling, durable optional batch pins, a 10,000-target configurable global admission reservation limit, and the shared trusted-operator identity model. Preserve caller-scoped idempotency without tenant isolation.
- [ ] Define independent CT `checkpoint_signature`, `continuity`, and `entry_inclusion` check results, including `not_performed` and documented verification procedure identity.

### Required tests

Test IDNA names, terminal dots, lookalike suffixes, a hostname outside the requested root, invalid and mapped IPs, bracketed URL IPv6, userinfo, unsupported schemes, forbidden ports, and URL fragments. Test that a public suffix is not interpreted as verified organization ownership.

Randomize input map/order and require identical canonical output. Mutate a returned result in a test and confirm the underlying shared data does not change.

Add schema/contract fixtures for partial IP results with zero associations, wholly unavailable lookup, partial replay, and complete no-match. Validate every status/error mapping against SPEC section 14.2. Reclassification fixtures must keep captured observations immutable while referencing a new bundle's dataset records without asserting historical ownership.

### Exit gate

Modules share stable types and fixtures. API and schema tests distinguish invalid input, no match, partial evidence, and system failure. Scope checks run before live connections.

**References:** SPEC sections 3, 8, 9, 11.

## 5. P2: cloud-provider and service-range importers

**Covers:** R07, R08, R17, R23.

### Implementation tasks

- [ ] Implement local-directory import first, then Git/static-file retrieval as a separate input acquisition layer. Neither requires GitHub API access.
- [ ] Select all primary files from one revision. Exclude consolidated and detail-only files from primary discovery, and preserve explicit provider selections.
- [ ] Enforce regular-file/path containment checks, total and per-file byte bounds, JSON depth/key checks, and strict handling of known fields.
- [ ] Normalize IPv4/IPv6 prefixes, reject family mismatches, mask host bits with warnings, and deduplicate without losing source references.
- [ ] Join retired-state details by provider ID and canonical prefix. Preserve exact lifecycle state and raw timestamps. Reject malformed/conflicting lifecycle information.
- [ ] Verify orphan detail entries and richer detail shapes against the full source inventory. Implement an explicit supported behavior or fail the candidate; do not invent active prefixes from unrecognized detail files.
- [ ] Preserve provider IDs, methods, role/coverage notes, source URLs, source HTTP metadata, and archived inputs. Unknown fields remain recoverable.
- [ ] Implement the AWS official adapter with all service tags, regions, and network-border groups. Preserve overlapping service rows.
- [ ] Implement the GCP adapter with raw service/scope fields and publication metadata. Do not synthesize product specificity unavailable in the source.
- [ ] Implement the Azure downloadable-file adapter with service tags, prefixes, regions, and change metadata. Support a configured static URL/local mirror without Azure authentication.
- [ ] Add reviewed source-label mappings to canonical providers/products, with direction/role limitations. Unknown labels remain source evidence.
- [ ] Produce per-source validation reports and canonical normalized association files. Include checksum, revision, adapter version, record reference, lifecycle, and provenance family.

### Required tests

Importer fixtures cover published lists and BGP-derived records, IPv4-only and dual-stack sources, and retirement joined from detail records. Include identical CIDRs across providers, multiple service tags on one CIDR, and absent service or region metadata.

Test malformed JSON, duplicate keys, trailing documents, conflicting retirement, invalid timestamp shapes, excessive files, decompression bounds, source disappearance, and moved/changed schema fields. Distinguish a legitimate empty family from an accidentally empty entire required source.

Run one import of the complete pinned upstream revision and publish its validation report. Sample fixtures alone do not establish whole-dataset compatibility.

### Exit gate

Importers produce broad provider coverage and official service and region evidence. Retirement is preserved. A failed source cannot partially replace a valid snapshot.

**References:** SPEC section 6. Sources S01, S02, S11–S14.

## 6. P3: local indexes, ASN, CDN, and bundle construction

**Covers:** R09, R10, R11, R17, R22.

### Implementation tasks

- [ ] Implement `bart.Table[[]AssociationID]` behind the prefix interface. Store descriptive metadata in immutable catalogs rather than copying it into every lookup result.
- [ ] Implement `all` by enumerating every containing prefix. Implement `longest` by filtering eligibility before selecting specificity. Keep every same-prefix tie.
- [ ] Preserve retired associations for explicit historical queries while excluding them from ordinary domain attribution.
- [ ] Implement source/category filters, deterministic sorting, result bounds, and errors distinct from no-match.
- [ ] Track source availability per address family. Return partial associations when some requested applicable sources are unavailable, even if surviving searches return no matches. Return `capability_unavailable` only when no requested applicable lookup source is usable.
- [ ] Write a test-only brute-force oracle using `netip.Prefix.Contains`, without reusing BART traversal code.
- [ ] Implement IPtoASN TSV parsing for both families, including inclusive interval bounds, unknown ASN values, source metadata, and conflict checks.
- [ ] Build sorted local ASN interval indexes with binary search. Test family separation and large IPv6 intervals without address expansion.
- [ ] Convert pinned `cdncheck` data into normalized local prefix/category records and applicable typed suffix mappings. Preserve raw upstream categories rather than trusting them as final product relations.
- [ ] Ensure mirrored range/CDN sources carry provenance-group identifiers so the aggregator can avoid double-counting.
- [ ] Build canonical source artifacts and one compatible bundle manifest containing indexes, taxonomy/rules, source revisions, and detector identities.
- [ ] Implement bounded bundle loading, checksum/schema verification, a single-writer staging store, and in-memory immutable-view publication.
- [ ] Add disk-space checks and a last-known-good bundle path. Never serialize private BART memory layouts as the persistent format.
- [ ] Define the store coordination shared by pinned-batch admission and pruning. Add the durable pin integration in P8; do not rely on process-local reference counts for accepted queued work.

### Required tests

Compare both matching modes against the oracle over randomized IPv4/IPv6 datasets and shuffled insertion orders. Include the exact four-prefix example in SPEC section 7, a retired child above an active parent, /32 and /128, a generic /0 index test, adjacent addresses, mapped IPv4, and no match.

Test ASN interval start/end addresses, gaps, ordering errors, invalid family mixing, and unknown ASN handling. Test cloud/CDN category results without any resolver or dialer activity.

Run parallel readers while loading and swapping bundles. Each captured view must remain internally consistent and race-free. Corrupt or incompatible bundles must leave the last-known-good view intact.

Remove ASN, CDN, and individual provider/service sources in availability fixtures. Verify partial results preserve every usable association and mark missing sources. Test zero surviving matches separately from zero usable sources. A failed update must retain the last-known-good view rather than partially activating malformed input.

### Exit gate

Provider, service-range, ASN, and CDN lookups work locally. Results preserve overlap provenance, and callers cannot mutate shared indexes. This completes the lookup component.

**References:** SPEC sections 2, 6, 7, 13. Sources S03, S05–S07.

## 7. P4: DNS collection and local recursion

**Covers:** R03, R04, R18, R19.

### Implementation tasks

- [ ] Implement raw A, AAAA, CNAME, MX, NS, and TXT queries through the chosen DNS adapter, with context, retries, and explicit resolver configuration.
- [ ] Supply a reference Unbound configuration without implicit forwarding to proprietary enrichment services.
- [ ] Preserve resource-record owners, complete alias chains, TTLs, MX preference, TXT chunks, answer section, resolver, response code, and observation time.
- [ ] Follow CNAME chains with cycle detection and depth/query budgets. Do not replace the chain with a final `LookupCNAME` result.
- [ ] Resolve MX/NS dependency addresses only for local enrichment. Propagate their mail/DNS context and never schedule HTTP against them automatically.
- [ ] Implement bounded applicable-zone NS discovery and label inherited results. Do not inherit root MX/TXT onto unrelated subdomains.
- [ ] Implement positive and negative caching with remaining TTL, resolver-aware keys, and TTL-zero behavior. Share in-job observations with HTTP dialing.
- [ ] Implement UDP truncation detection and TCP retry. Classify NXDOMAIN, NODATA, SERVFAIL, REFUSED, timeout, and policy/budget outcomes separately.
- [ ] Handle null MX and TXT chunks correctly. Parse SPF tokens without silently initiating recursive SPF exploration.
- [ ] Add counters for queries, outcomes, cache use, retries, chain depth, and omitted dependency work.
- [ ] Publish address candidates as answers arrive so HTTP can start on an approved public address. Continue remaining queries within budgets, retaining timeouts, private-address observations, policy decisions, and omissions independently of successful HTTP.

### Required tests

Use a controlled DNS server to test alias chains across provider domains, loops, IPv6-only hosts, and delegated subzones. Include null MX, explicit no-mail configuration versus failed lookup, split TXT chunks, and distinct TXT records. Test TTL expiry, cached negative answers, and UDP-to-TCP fallback.

Test out-of-scope dependencies and cap exhaustion. Confirm no HTTP work is created from MX/NS hosts. Deny all external network access and confirm only the configured fixture resolver is contacted.

Use explicit synchronization for a public A result followed by private AAAA or AAAA timeout. Verify candidate publication does not wait for the other family, query outcomes remain distinct from address-policy decisions, and all unfinished work respects cancellation.

### Exit gate

DNS output includes typed records, complete chains, and dependency context. Coverage identifies every failed or omitted question.

**References:** SPEC sections 3, 4, 14. Sources S08, S09, S19.

## 8. P5: HTTP/TLS collection and local web fingerprints

**Covers:** R05, R06, R18, R23.

### Implementation tasks

- [ ] Implement the application-owned HTTP transport with explicit proxy behavior, safe dialing, connection pooling, header/body limits, and deadlines.
- [ ] Resolve through P4's policy, validate each candidate IP independently, and start HTTP as soon as one approved public address is available. Dial that exact address while preserving Host/SNI. Apply the same checks to every redirect, retry, and alternate-address attempt.
- [ ] Implement default public-address/port restrictions, including IPv4-mapped forms. Exclude prohibited addresses without rejecting the entire mixed-answer hostname. A private answer or failed AAAA query must not block an approved public IPv4 address. Record blocked addresses and incomplete coverage.
- [ ] Preserve destination enforcement with connection reuse and record the actual peer address. Continue remaining DNS queries within the shared deadline and budgets.
- [ ] Implement root-page collection for domain seeds and supplied-path collection for explicit URLs. Do not fetch linked assets or execute scripts.
- [ ] Preserve redirect-hop context, response status, peer IP, selected headers, cookie names, body hash/truncation, and verified TLS metadata.
- [ ] Implement explicit HTTP fallback policy without TLS-error downgrade. Classify a useful HTTP error response separately from a transport failure.
- [ ] Pass already-collected headers and body to a pinned local `wappalyzergo` instance. Do not import its headless adapter or perform an extra fetch.
- [ ] Preserve raw technology labels and detector/data identity. Record available explanation granularity accurately.
- [ ] Redact sensitive values after local classification. Implement disabled-by-default raw capture with restricted storage metadata and expiration.
- [ ] Bound detector concurrency and handle cancellation between stages where the library has no cancellable inner API.

### Required tests

Test same-host and cross-domain redirects, metadata or private destinations, DNS changes between validation and dial, and mixed address sets.

Test expired or wrong-host certificates, useful 403 responses, slow headers and bodies, oversized headers, decompression bombs, truncated bodies, malformed HTML, and unsupported content types.

For mixed answers, assert successful collection through the approved public address, correct Host/SNI, zero prohibited dial attempts, and partial coverage with address-policy reasons. Assert HTTP starts before a deliberately delayed AAAA completion. Repeat for private AAAA, AAAA timeout, redirect targets, and reused connections. Use the controlled test transport/policy rather than real public destinations.

A multi-detector test must prove one document fetch feeds all local detectors. Changing `HTTP_PROXY`/`HTTPS_PROXY` must not silently alter the default path. Cookie values must not leak to logs or subsequent targets.

Use a separate test-only network policy for local fixture servers. Callers must not be able to enable it through the production API.

### Exit gate

The collector produces bounded HTTP and TLS observations for local technology detection. It blocks private destinations, and classifiers make no additional network calls.

**References:** SPEC section 5. Sources S04, S05, S10.

## 9. P6: product rules, taxonomy, and evidence aggregation

**Covers:** R12, R13, R20, R22.

### Implementation tasks

- [ ] Implement a versioned rule schema and loader. Compile exact-name, suffix, anchored-regex, TXT/SPF-token, header, script-URL, and technology-alias matchers before activation.
- [ ] Validate rule IDs, product/provider references, relation compatibility, allowed operations, and source references. Rules cannot execute code or initiate requests.
- [ ] Implement DNS label-boundary matching and strict case/terminal-dot handling. Add negative lookalike tests to every suffix family.
- [ ] Implement every row of SPEC section 8.5's product-and-relationship acceptance matrix. Record dated vendor references, exact supported signals, canonical relations, positive/negative fixtures, and justified unsupported cases per named product. Provider-only fallback cannot pass where the agreed signal identifies a product.
- [ ] Distinguish authoritative DNS, web delivery, mail routing, sending authorization, web integration, domain verification, service range, and network origin.
- [ ] Map raw Wappalyzer technology names to canonical products/frameworks without assuming all web technologies are cloud products.
- [ ] Implement evidence IDs, observation links, rule/source identities, sanitized explanations, activity labels, and strength categories.
- [ ] Aggregate only compatible subject/product/relation groups. Preserve external-redirect scope and dependency scope.
- [ ] Deduplicate correlated evidence. Do not sum arbitrary detector weights into probabilities. Only reviewed combination rules can increase support.
- [ ] Preserve conflicting candidates, ambiguous provider-only matches, unknown products, lifecycle state, and source-age limitations.
- [ ] Implement infrastructure/product summary projections from the same findings rather than maintaining a separate inconsistent summary engine.
- [ ] Implement reclassification as reinterpretation of immutable collected observations using a selected bundle, not historical ownership reconstruction. Keep newly consulted dataset records and classification time separate from original collection times; retain source publication/effective times when known.
- [ ] Reuse supported normalized observations and raw technology labels with their original detector identity. Mark unavailable replay paths explicitly, preserve supported results as partial, and fail with `capability_unavailable` only when no requested replay path is usable.

### Required tests

Positive cases must cover a CNAME-based CDN, a hosting platform, authoritative DNS, visible email routing, and an HTTP SaaS integration. Required negative cases include:

- TXT-only Google verification must not yield Google Workspace.
- Cloudflare NS must not imply proxying.
- An AWS ASN or generic EC2 range must not imply a direct EC2 customer deployment.
- A third-party mail gateway must not reveal a hidden mailbox backend.
- A script reference and a paid SaaS subscription must not be treated as equivalent claims.
- SPF authorization must yield `sending_authorization` at supported specificity, never imply inbound mail routing or paid adoption.
- A technology found only on an external redirected site must not become an in-scope product.
- Retired-only or CT-only historical evidence must not become active infrastructure.

Shuffled observations and duplicate source data must produce identical findings. Every finding must reference actual evidence, and every application-authored rule must identify the matched field.

Replay the same capture against bundles with different IP associations. Verify unchanged collection times, new classification time and dataset references, unknown effective times preserved as unknown, and no claim that new associations existed when the capture was collected. Test missing raw bytes with another replay path available and with none available.

### Exit gate

The matrix passes SPEC section 8.5 for every required product family. Tests assert the expected product and relation and reject unsupported conclusions.

Multi-vendor evidence produces separate relationships with supporting evidence, without inflated confidence or lead qualification claims. E1 must have passed before P3 through P6 are complete.

**References:** SPEC sections 8, 9. Sources S11–S15 for range/product limitations and examples.

## 10. P7: complete analyzer and CLI

**Covers:** R01, R03–R13, R15, R18, R20.

### Implementation tasks

- [ ] Implement the end-to-end `Analyzer` using one captured immutable view per target. Expose full, DNS-only, local-IP, and reclassification modes.
- [ ] Build a bounded dependency graph: seeds -> DNS -> eligible HTTP; collected addresses -> local network enrichment; observations -> rules/fingerprints -> findings.
- [ ] Share DNS results and HTTP captures between stages. Avoid duplicate resolutions or website fetches introduced by separate detectors.
- [ ] Preserve root, subdomain, CNAME-target, mail, DNS, redirect, and connected-peer contexts through aggregation.
- [ ] Implement total target deadlines, shared DNS/HTTP/byte budgets, worker pools, and per-destination rate limiting. Stop scheduling new work after cancellation or budget exhaustion.
- [ ] Implement SPEC section 14.2's full per-mode decision table. Missing ASN, CDN, or any provider/service feed must preserve working collection/detection/enrichment results. Return partial reports with HTTP 200/CLI exit 3 where useful results remain, and explicit unavailable-operation errors with HTTP 503/CLI exit 4 where no necessary execution path is usable.
- [ ] Implement every analysis, lookup, batch, and reclassification CLI command in SPEC section 11, with stable exit codes and stderr-only diagnostics.
- [ ] Implement bounded streaming JSONL, input-index tracking, deterministic ordered output, explicit unordered mode, and backpressure.
- [ ] Implement report schemas, canonical output ordering, evidence cross-reference validation, and version metadata.
- [ ] Implement offline reinterpretation with separate collection/classification/source times and links to immutable original inputs. Export normalized replay inputs with standalone reports or explicitly identify unavailable inputs. Keep replay coverage separate from original collection coverage.

### Required integrated scenario

Use one controlled fixture domain with different products at different layers:

```text
www -> CDN CNAME and controlled HTTP response
root NS -> authoritative DNS provider
root MX -> mail-routing provider
root TXT -> verification-only vendor signal
HTML -> SaaS script and an ordinary frontend framework
connected/DNS IPs -> local provider/service/CDN/ASN records
```

The report must identify each relationship separately. It must not claim the verification vendor supplies mail, the authoritative DNS provider proxies the website, or the CDN reveals the hidden origin. The framework must remain a web technology.

Run a second variant where HTTP times out and a third where a narrower IP association is retired. Existing valid DNS findings and active covering-prefix associations must survive.

Run the missing-ASN, missing-CDN, missing-provider, mixed-address, and failed-AAAA variants. Test IP partial zero-match versus wholly unavailable lookup and partial versus unavailable replay. Verify CLI exit codes and report coverage for every applicable decision-table row. Do not infer qualification, spend, or savings from any report.

### Exit gate

The CLI produces the R01 domain report without proprietary enrichment services. Full, DNS, IP, and reclassification operations work. Offline operations perform no collection.

**References:** SPEC sections 3–9, 11, 14, 16.

## 11. P8: persistence, durable jobs, and HTTP API

**Covers:** R15, R16, R18, R19, R20.

### Implementation tasks

- [ ] Implement migrations for jobs, target attempts, reports, observations, evidence with retained consulted dataset provenance, findings, finding/evidence links, and bundle metadata. Include durable job bundle references and target admission reservations. Add CT tables for P9.
- [ ] Use indexed typed fields for domain, provider, product, relation, strength, and time, with JSONB only for evolving payload details.
- [ ] Persist terminal reports and their referenced evidence/observations in one transaction. Keep reports immutable.
- [ ] Implement short queue-claim transactions using row locks, bounded leases, attempt tokens, renewal, retry limits, and abandoned-work recovery.
- [ ] Keep network operations outside transactions. Require the current attempt token for final commits so an expired worker cannot overwrite a later attempt.
- [ ] Implement cancellation, per-target result states, per-job terminal aggregation, idempotent submission, and caller-scoped idempotency conflicts.
- [ ] Coordinate pinned admission with pruning. Validate bundle availability, integrity, and compatibility, then commit the reference with the job before acceptance. Protect queued work and retries across restarts. Reject unavailable or incompatible pins without inserting a job or substituting a bundle.
- [ ] Release the durable pin only after every target becomes terminal, including on cancellation. A cancellation request alone must not release it. Restore/check durable references before pruning after restart; fail pruning closed when the reference store is unavailable.
- [ ] Limit nonterminal target reservations globally to an operator-configurable default of 10,000. Reserve capacity atomically with insertion. Keep reservations through running and retry states; release them on terminal transitions. Reject excess submissions before insertion with HTTP 429 and `queue_capacity_exceeded`. Idempotent resubmission consumes no new capacity.
- [ ] Implement all routes from SPEC section 11 and generate an OpenAPI document from the tested contracts.
- [ ] Add stable validation/error envelopes, request body limits, synchronous admission limits, and bounded cursor pagination.
- [ ] Preserve the local-IP endpoint's no-PostgreSQL path. Do not hide storage failures behind a successful durable-job response.
- [ ] Add provider/product alias search and structured finding filters using ordinary indexes, not semantic vectors.
- [ ] Implement retention and reclassification links. Keep observations and consulted dataset provenance while any retained report references them. Compare history only across sufficiently comparable collection outcomes and distinguish source/rule changes from target changes.
- [ ] Bind to loopback by default and implement shared trusted-operator access. Authenticated operators share results and may cancel any job. Identity scopes idempotency and audit attribution, without tenant isolation. Map credentials to stable IDs or trust only a configured proxy that strips untrusted identity headers. Explicit unauthenticated loopback mode uses `local-operator`. Keep dataset activation off the public API.
- [ ] Implement operation-level readiness and source degradation from SPEC section 14.2, including persistence-dependent operations unavailable while local-IP lookup remains usable. Keep storage failures explicit rather than returning an unstored success.

### Required tests

Test a successful domain report through API -> worker -> PostgreSQL -> retrieval, including observation/evidence references. Compare its normalized findings with the equivalent CLI result.

Kill a worker after claim, during collection, and before/after result commit. Verify lease recovery, bounded repeat attempts, no late overwrite, and no duplicate terminal result for one attempt. Test cancellation races and same-idempotency-key/different-payload conflicts.

Test database unavailability before admission and during persistence. Confirm the local-IP endpoint still works when its bundle is valid. Test pagination stability, large request rejection, redacted data, and history after an incomplete follow-up analysis.

Accept a pinned batch and leave its targets queued through multiple activations. Attempt pruning, then restart and resume. Repeat with expired leases and pending retries. Every attempt must use the pin, which remains protected until all targets are terminal.

Race admission against pruning. The result must be either protected acceptance or explicit rejection. Test unavailable and incompatible pins, plus crashes before and after reference commit.

Test completed and cancelled batches releasing pins only after terminal target state commits; verify a cancellation request alone cannot release protection. After release, prune only if active, reader, other-job, and last-known-good protections no longer apply. Block pruning when durable references cannot be checked.

Race submissions near backlog capacity. Verify no partial insertion or limit overrun, and recover reservations after restart. Delayed retries keep their reservations. Repeated idempotency keys at capacity return the original job.

Test two operators reading shared results and cancelling each other's jobs while keeping separate idempotency namespaces. Reject spoofed identity headers.

### Exit gate

Single-target and batch API workflows persist and retrieve complete evidence-backed reports. Job state and coverage expose crashes and partial collection. The API supports the same product discovery as the CLI.

**References:** SPEC sections 11, 12, 14. Source S18.

## 12. P9: optional CT import, log collection, and discovery

**Covers:** R14, R03, R16, R18, R20.

### Implementation tasks

- [ ] Implement the normalized CT JSONL schema and local-file importer, including root-scope filtering, certificate hashes, log metadata, validity times, wildcard handling, and provenance status.
- [ ] Implement the `ct collect` command against explicitly configured supported RFC 6962-compatible logs using a pinned audited Go client.
- [ ] Require a configured starting checkpoint or bounded backfill boundary. Add per-run entry, byte, request, and elapsed-time budgets. Do not initiate an unbounded global crawl.
- [ ] Persist collector checkpoints transactionally. Record checkpoint-signature, continuity, and entry-inclusion checks separately as `passed`, `failed`, or `not_performed`, with procedure/version and authenticated tree/key identity. Document initial-checkpoint trust and why continuity was not performed there.
- [ ] Use `verified_log` only when the documented procedure authenticates the tree and establishes inclusion of the exact entry bytes. Use `log_unverified` for unchecked fetched entries and `imported_unverified` for imports without equivalent verified proof material. A failed check must not advance a verified checkpoint or publish verified entries. Reject unsupported protocols explicitly.
- [ ] Deduplicate certificate/precertificate repeats and normalize names. Preserve wildcard patterns as patterns rather than manufacturing concrete hosts.
- [ ] Build indexed local hostname retrieval by root scope and observation time. Capture a deterministic selected candidate set and its source/checkpoint identity for each analysis.
- [ ] Add bounded CT seed discovery to `Analyze`; send concrete candidates through the ordinary DNS and HTTP path rather than a weaker alternate collector.
- [ ] Expose disabled, unavailable, empty, partial, and fully processed requested CT coverage states separately.
- [ ] Document supported protocols, configured-log coverage, retention, storage growth, and the distinction between local import and running a log reader.
- [ ] Repeat P0's throughput, bandwidth, retained-storage, and ingestion-lag measurements for the shipping collector under explicit budgets. Publish the supported operating envelope and backlog behavior. Root-scope filtering does not provide domain-filtered log retrieval; do not describe scoped retention as scoped download cost.

### Required tests

Use a synthetic log fixture for normal reads, checkpoint persistence, interruption/restart, duplicate entries, inconsistent continuity, bad signatures, invalid certificates, malformed names, old certificates, wildcard names, and unsupported protocol declarations.

Pair valid signed checkpoints and continuity proofs with altered entry bytes. Require entry-inclusion failure, no `verified_log` label, and no verified checkpoint advancement. Test valid inclusion, each `not_performed` state, and local imports with and without verifiable proof material.

Test suffix-boundary scope enforcement and deterministic top-N selection. A CT hostname without current DNS must not become active infrastructure. A CT service outage must not disable ordinary full domain analysis.

Run with CT off and assert zero log-service traffic. Run analysis with CT on and an already-populated local index, and assert that request-time discovery performs no public CT-search request.

### Exit gate

CT import, supported log collection, and local discovery work when configured. Default full analysis works with CT disabled. No crt.sh or proprietary search API is required.

**References:** SPEC section 10. Sources S16, S17.

## 13. P10: operational updates, visibility, and deployment

**Covers:** R17, R18, R19, R21, R23.

### Implementation tasks

- [ ] Finish `datasets sync/import/validate/activate/rollback/status` commands and their configuration. All source adapters must support local-file inputs.
- [ ] Implement fetch receipts, source publication times, validation reports, coverage diffs, review-required candidates, and candidate-hash-bound approvals.
- [ ] Keep a failed source refresh from corrupting the active bundle. Make freshness and disabled-source conditions visible by capability.
- [ ] Separate publication of a desired bundle from successful loading by each running process. Atomically publish the on-disk pointer; load/validate off the request path; then swap the in-memory view.
- [ ] Preserve last-known-good compatibility per running detector build. A failed reload must not discard the current view, and a restart must have an explicit recovery path.
- [ ] Implement single-writer locking, same-filesystem staging/rename, file/directory durability, disk-full handling, pruning, and rollback.
- [ ] Protect active and in-flight bundle references plus durable batch pins from pruning, including queued targets and pending retries across restarts. Share coordination with admission, fail closed when references cannot be checked, and release job protection only after all targets are terminal. Keep manifests and consulted record provenance needed to interpret retained reports after old indexes are removed.
- [ ] Provide updater timer/cron examples with jitter and separate egress policy. Do not add request-time downloads or automatic remote rule execution.
- [ ] Implement SPEC section 14.2's operation readiness and per-capability degradation, low-cardinality metrics, redacted logs, source-age warnings, and activation/rollback audit records. Include backlog reservations, admission rejections, bundle-pin counts, and CT lag without target-valued metric labels.
- [ ] Supply container images and Compose for the application, PostgreSQL, and Unbound, plus a non-container deployment guide.
- [ ] Document loopback binding, authentication, updater/worker network isolation, graceful shutdown, backup/restore, raw-capture retention, and resource tuning.
- [ ] Produce pinned image/dependency manifests, notices, and a software bill of materials. Document the offline build and offline-update import procedure.

### Required tests

Test malformed, incompatible, truncated, stale, and extreme-delta updates. Activate during concurrent analyses and verify that reports never mix views.

Restart after publication but before reload, and after reload but before audit persistence. Test rollback to a compatible previous bundle.

Simulate disk-full, file corruption, writer contention, missing source files, PostgreSQL outage, and abrupt termination. Check that health endpoints report the actual available capabilities.

Deploy the complete Compose stack in a clean environment with no enrichment credentials. Permit only the configured resolver/target traffic for workers and separate explicit updater destinations.

### Exit gate

An operator can install, populate, run, monitor, update, recover, and back up the system using the written commands. Status distinguishes publication from successful process loading.

**References:** SPEC sections 12–15.

## 14. P11: complete-system qualification

**Covers:** All requirements, especially R01, R20, R21, R23.

### Implementation tasks

- [ ] Run every component and integration test under the selected toolchain, including race tests and schema/output compatibility tests.
- [ ] Run the complete multi-vendor scenarios through CLI, synchronous API, and durable batch jobs. Compare normalized findings and provenance.
- [ ] Run network-denied startup/local lookup/reclassification tests and instrumented live-mode egress tests. Audit the full dependency graph again at the release revision.
- [ ] Re-run the complete selected upstream import and official-feed compatibility suite. Publish source counts, lifecycle counts, method/role coverage, and validation exceptions.
- [ ] Evaluate provider, product, and relationship accuracy on a labeled controlled corpus. Separate insufficient evidence from false conclusions and report dataset limitations.
- [ ] Require every supported positive/negative fixture in SPEC section 8.5 to pass. Publish signal-specific unsupported cases; do not accept provider-only fallback for a product-identifying signal. Evaluation concerns attribution evidence, not lead qualification or commercial estimates.
- [ ] Benchmark local prefix/ASN/CDN lookup, bundle build/load, memory, rules/fingerprints, and controlled end-to-end analysis independently.
- [ ] Record hardware, corpus/source hashes, versions, concurrency, p50/p95/p99, allocations, and peak memory. Clearly distinguish measured results from initial targets.
- [ ] Load-test queue admission, bounded concurrency, per-destination rate limits, cancellation, slow targets, oversized responses, and large CLI inputs.
- [ ] Exercise the full per-mode degraded-operation table, durable pinned-batch admission/pruning and restart/retry tests, global backlog reservations, shared operator access, and temporal reclassification provenance through the final interfaces.
- [ ] Exercise optional CT end-to-end, plus a default deployment with CT completely disabled.
- [ ] Perform clean deployment, backup/restore, update, rollback, and offline-source-import drills using only the written operations guide.
- [ ] Verify no outstanding rule/source license question is disguised as an unrestricted redistribution claim.
- [ ] Complete the requirement traceability table below and record the release revision/artifact digests.

### Exit gate

Every SPEC section 1 capability has passing evidence or a documented, accepted operational limit consistent with the specification. Section 16's complete-system gate passes. Missing collectors, service or region adapters, persistence, or job workflows cannot be accepted as future extensions.

Optional CT may be disabled at runtime, but its supported ingestion/discovery implementation and tests must ship.

## 15. Cross-module test matrix

| Scenario | Required outcome |
| --- | --- |
| CDN + different DNS vendor + mail provider + SaaS script | Distinct typed findings with subject, relationship, and evidence. |
| Cloudflare NS with non-Cloudflare website | DNS finding only; no inferred Cloudflare proxy. |
| Google verification token only | Verification association; no Google Workspace claim. |
| AWS-owned IP and generic EC2 service range | Network/range evidence; no proven direct EC2 customer deployment. |
| Several providers/services share one CIDR | All eligible ties preserved with source provenance. |
| Retired narrower prefix and active broader prefix | Default result keeps active broader association. |
| External landing-page redirect | Landing-page technologies keep external scope and do not contaminate root summary. |
| Mail/NS target on a cloud IP | Cloud evidence belongs to that dependency context, not automatically the web origin. |
| HTTP timeout with usable DNS | Partial report retains DNS-backed findings. |
| Unavailable ASN source | Other findings survive; ASN coverage is explicitly unavailable. |
| Missing CDN or one provider/service feed | Retain usable DNS/HTTP/enrichment evidence; partial coverage identifies the missing source. |
| IP lookup with some sources missing and zero surviving matches | HTTP 200/CLI exit 3 with partial coverage, never a complete no-match. |
| IP lookup with no applicable usable source | Explicit `capability_unavailable`, HTTP 503/CLI exit 4. |
| Body truncated at limit | Local partial fingerprint result and truncation warning; no unlimited read. |
| DNS rebinding or metadata redirect | Connection blocked by the same final-dial policy. |
| Mixed public/private DNS answer | Dial only an approved public address with preserved Host/SNI; record prohibited addresses and partial coverage. |
| Public A before private/failed/delayed AAAA | HTTP starts without waiting for AAAA; later DNS outcomes remain visible and prohibited addresses are never dialed. |
| Update during a target analysis | One coherent captured data/rule view for the report. |
| Old worker finishes after lease expiry/reclaim | Attempt-token check rejects stale final commit. |
| CT wildcard or expired historical name | No invented hostname or unverified active-product finding. |
| Reclassification without raw HTTP capture | Reuse available evidence; mark unavailable detector replay honestly. |
| Reclassification with new ownership data | Preserve captured observations/time, record new dataset provenance/classification time, and do not assert historical ownership. |
| Reclassification with no usable requested replay path | Explicit `capability_unavailable`, HTTP 503/CLI exit 4. |
| Pinned queued batch across activations/restart/retries | Same bundle remains protected and used until every target is terminal. |
| Admission racing bundle pruning | Either atomically protected acceptance or explicit unavailable/incompatible rejection; no accepted dangling pin. |
| Completed or cancelled pinned batch | Release pin after every target is terminal; prune only when no other protection remains. |
| Global backlog capacity with concurrent submissions | Atomic reservations, no partial insertion; excess new requests receive 429, idempotent repeats consume no capacity. |
| Two authenticated operators | Shared results/cancellation, separate caller-scoped idempotency, no client-spoofed identity. |
| Valid CT checkpoint with altered entry bytes | Inclusion verification fails; no verified entry publication or checkpoint advancement. |
| SPF-only authorization | `sending_authorization` at justified specificity, no mail-routing or paid-adoption claim. |
| Empty findings after complete versus failed collection | Distinct coverage and report states. |
| No Internet, local data populated | Local IP lookup and supported offline reclassification work. |

## 16. Requirement traceability

| Requirement | Implemented in | Minimum acceptance evidence |
| --- | --- | --- |
| R01 Full attribution | E1, P7, P8, P11 | Early integrated fixture, then complete evidence reports supporting lead enrichment through CLI and API. |
| R02 No proprietary APIs | P0, P3–P5, P9–P11 | Dependency audit and network-attempt tests without enrichment credentials. |
| R03 Targets and scope | P1, P4, P5, P7, P9 | Normalization, boundary, redirect, and CT-scope fixtures. |
| R04 DNS | P4, P7 | Raw records, chains, TTL, delegation, and failure-state tests. |
| R05 HTTP/TLS | E1, P5, P7 | Exact approved-address dialing, early HTTP with remaining DNS queries, redirect/TLS/body-limit fixtures. |
| R06 Web fingerprints | P5, P6 | Local detection, single-fetch proof, detector identity in report. |
| R07 Cloud dataset | P0, P2 | Complete pinned revision import and lifecycle report. |
| R08 Service/region | P2, P6 | AWS/GCP/Azure fixtures plus conservative product interpretation tests. |
| R09 Prefix lookup | P3 | Randomized oracle agreement and overlap/retirement goldens. |
| R10 ASN | P3 | IPv4/IPv6 interval boundary and unknown-source tests. |
| R11 CDN adapter | P0, P3, P6 | Local-data classification, source hash, and no-egress proof. |
| R12 Rules/taxonomy | P1, P6, P11 | SPEC 8.5 product/relation matrix, justified unsupported cases, sending-authorization and product-specific fixtures. |
| R13 Evidence/findings | P1, P6, P7 | Reference integrity, relation separation, deduplication, ambiguity tests. |
| R14 Optional CT | P0, P9, P11 | Early/final resource measurements, separate signature/continuity/inclusion checks, altered-entry test, bounded discovery. |
| R15 Interfaces | P7, P8 | CLI/API contract tests, JSONL stability, OpenAPI examples. |
| R16 Persistence | P8 | Atomic reports, durable pins/reservations, queue/retry recovery, retained provenance and shared operator tests. |
| R17 Update lifecycle | P2, P3, P8, P10 | Invalid update, atomic reload, rollback, admission/pruning coordination and pin recovery tests. |
| R18 Bounds/isolation | P1, P4, P5, P7–P11 | Per-address enforcement, global backlog admission, load/cancellation and byte-limit tests. |
| R19 Observability | P4, P8, P10 | Per-mode readiness/degradation table, source-age signals, low-cardinality metrics. |
| R20 Reproducibility | P0, P1, E1, P6–P11 | Offline reinterpretation with distinct temporal provenance, durable batch pins, fixtures/race tests. |
| R21 Deployment | P10, P11 | Clean self-hosted deployment and recovery drill. |
| R22 Deterministic search | P1, P3, P6, P8 | CIDR/suffix/alias/filter tests; no embedding dependency. |
| R23 Governance | P0, P2, P5, P10, P11 | Pinned builds/data, source notices, SBOM, final egress audit. |

## 17. Decisions that must not drift during implementation

The following are fixed architectural constraints unless the specification is deliberately revised:

- Go owns collection and orchestration. Do not shell out to `httpx`, `dnsx`, `edge`, or `asnmap` for each target.
- Reuse local `wappalyzergo` fingerprints and audited `cdncheck` data. Do not confuse an open-source package with a guarantee of zero network side effects.
- Keep `disposable/cloud-ip-ranges` for breadth and official service feeds for depth. Do not discard service/region enrichment to finish the IP component sooner.
- Use exact prefix and interval matching, not embeddings. Preserve all covering associations before making relation-aware conclusions.
- Store evidence and coverage, not just a flat technology list. Never hide ambiguity with invented confidence percentages.
- Supply attribution evidence for lead enrichment; keep qualification, spend, and savings decisions outside the application.
- Validate addresses independently, start HTTP on an approved public address, and preserve later DNS failures/blocked addresses as coverage. Never dial prohibited addresses.
- Treat missing enrichment as degraded capability, not a reason to erase useful evidence. Apply SPEC section 14.2 consistently, including IP lookup and replay.
- Reclassification uses a selected bundle to reinterpret immutable captures, without reconstructing historical ownership. Keep source records and times distinct.
- Protect accepted batch pins durably until all targets are terminal. Coordinate admission/pruning and bound all nonterminal target reservations, including retries.
- Use one shared trusted-operator access model with caller-scoped idempotency. Do not add tenant isolation.
- Treat DNS, HTTP, ASN, rules, persistence, and API/job operation as core deliverables. CT alone is optional at runtime.
- Use one coherent immutable view per target. Keep updater traffic and live collection separate.
- Prefer the simple deployment: one Go application, PostgreSQL, and Unbound. Introduce additional infrastructure only for a measured requirement.

## 18. Final delivery checklist

- [ ] All R01–R23 traceability entries have implementation evidence.
- [ ] Full domain analysis works through CLI, API, and durable batch workflows.
- [ ] All selected upstream and official service/ASN data paths work from local imports.
- [ ] Rules cover the agreed product families with documented blind spots and negative tests.
- [ ] Findings expose evidence, relationships, coverage, versions, and limitations.
- [ ] E1 passed early and the final product-and-relationship acceptance matrix passes without substituting provider-only results for supported product signals.
- [ ] Per-address collection, every degraded-operation decision-table row, and temporal replay provenance are verified.
- [ ] Durable pins survive queued work/restarts/retries; concurrent admission/pruning, terminal pin release, and global backlog limits pass.
- [ ] Shared operator identity/access and explicit CT verification states are tested; CT operating costs and ingestion lag are measured.
- [ ] Offline lookup/reclassification and no-proprietary-API tests pass.
- [ ] CT's supported optional implementation ships and is disabled by default.
- [ ] Update/reload/rollback, crash recovery, resource bounds, and retention pass tests.
- [ ] OpenAPI, schemas, configuration, deployment, operations, notices, SBOM, and measured evaluation reports are complete.

Completion requires the full attribution system defined in SPEC.md.

### Source use

External references are listed in [SPEC section 17](SPEC.md#17-sources-and-verification-notes). They establish source contracts. P0, P2, and P11 still require implementation and full-dataset compatibility checks with recorded evidence.
