# Qualification report

This report records the Wave 7 release-candidate evidence collected on 2026-09-20. It evaluates attribution evidence, not lead quality, commercial adoption, spend, or savings. Routine acceptance uses controlled, pinned fixtures; the full-source import is a compatibility and scale check, not a redistributable artifact.

## Release environment

- Host: Apple M4 Pro, macOS, `darwin/arm64`.
- Local qualification toolchain: Go 1.26.4. The shipping container build uses pinned Go 1.25.1.
- Deployment: Docker Desktop with the pinned images in `sbom/cloudattrib.cdx.json`. The pinned Unbound image is `linux/amd64` and requires emulation on this host.
- Default CT mode: disabled. Synthetic RFC 6962 verification tests exercise the optional implementation.
- Concurrency: local latency distributions are single-threaded. Worker and admission concurrency use the configured bounds and explicit synchronization in tests.

## Controlled corpus results

The deterministic rule corpus has 21 supported positive product/relationship cases and seven negative or misleading cases. All pass. On this corpus only, product/relation precision and recall are both 100%: 21 expected positives were found, no expected positive was missed, and none of the seven forbidden product conclusions was emitted. This is not an estimate for arbitrary Internet domains.

The multi-vendor fixture keeps Cloudflare authoritative DNS, AWS CloudFront web delivery, Google-hosted mail routing, and Segment web integration as four distinct relationships. The E1 controlled-network fixtures prove that useful DNS and HTTP evidence survives a missing prefix source and that HTTP can start on an approved public address while a delayed or prohibited AAAA result remains visible. The complete matrix and signal-specific limitations are in `rules/coverage-matrix.md`.

Known evidence limits include:

- generic provider ranges and ASNs do not identify a customer deployment or paid product;
- service tags retain upstream service and region claims, but empty Azure `systemService` values conservatively use the service-tag name and emit a warning;
- verification records prove only domain association;
- SPF expresses sending authorization, not inbound routing or subscription;
- gateway MX records do not reveal the mailbox backend;
- external redirects remain external scope;
- CT names are historical discovery candidates until ordinary collection produces current evidence.

## Full upstream compatibility

The selected source snapshot imported successfully from local files with no request-time network access:

| Source | Pinned identity |
| --- | --- |
| AWS `ip-ranges.json` | SHA-256 `3b8580168cd1491fb1e7f923e2e5912a925bc2e27184aa84755527055021783b` |
| GCP `cloud.json` | SHA-256 `bf9379d98f683174f29d0bb7d9ad085d8119b899d1a357482b705f2629d080b2` |
| Azure public service tags | `ServiceTags_Public_20260914.json`, SHA-256 `238141eec0d82ed23402be7107c5d23ed9377fb6b085b24b28254b5c7487805f` |
| `cdncheck` source data | commit `a06260a272dc92cec0747f2f369b697088899bc7`, SHA-256 `64641dd6d6af84c8d240a5860fe7cf05cad6d7634f8892bf007cbadb8c2670a5` |
| IPtoASN IPv4 | SHA-256 `6eadf717cb621270e4a9a5c9b17ea0752b0533379721d800232f349496fc27ed` |
| IPtoASN IPv6 | SHA-256 `74b2a2847fc8bff14175d5d704dfe7027400ef6f7168519c5c095fbb80d8bac6` |
| `cloud-ip-ranges` | commit `0c4c204e650a47a6f57d3709893a9dc96f942ed9`, 91 provider JSON files |

The deterministic compiled bundle was `bundle-sha256-1a5900754842dc811a6d24fffcc74a989482c312d903717e67fd780dd60fc3f3`. It contained 685,784 prefix associations, all active in this snapshot; 685,784 service associations; 65,565 region associations; 115,670 role/method associations; 720,051 ASN intervals; and 103 CDN suffixes. The importer produced 80 warnings for current Azure entries whose `systemService` field was empty; those records were retained with the service-tag name rather than discarded or promoted to unsupported specificity.

The final full import took 3.70 seconds wall time in the measured test process. Peak resident memory was 1,421,426,688 bytes. The release therefore does not claim a sub-gigabyte full-bundle build. Operators should budget at least 2 GiB for update/import work and validate their own source mix.

## Local latency

The latency test constructs 4,096 disjoint prefixes and ASN intervals, uses one representative hit, evaluates a CloudFront rule observation, and repeatedly loads the checked-in six-file fixture bundle. These are in-process classifier timings, not end-to-end Internet latency.

| Operation | Samples | p50 | p95 | p99 |
| --- | ---: | ---: | ---: | ---: |
| Prefix lookup | 20,000 | 208 ns | 583 ns | 1.875 µs |
| ASN lookup | 20,000 | 83 ns | 125 ns | 250 ns |
| Rule evaluation, one observation | 5,000 | 14.542 µs | 19.458 µs | 25.792 µs |
| Six-file fixture bundle load | 1,000 | 111.5 µs | 129.375 µs | 259.458 µs |

Separate Go benchmarks measured a 4,096-record prefix hit at 194–208 ns/op, 608 B/op, two allocations; ASN at 50–51 ns/op, 112 B/op, one allocation; five-observation rule evaluation at 59–62 µs/op, about 39 KiB/op and 666 allocations; and fixture bundle load at 114–122 µs/op, about 58.5 KiB/op and 743 allocations. The combined network-lookup p95 is below the initial one-millisecond local target for this distribution. No claim is made about adversarial overlap distributions or live collection latency.

## Operational qualification

The clean Compose drill uses no enrichment credentials. It builds the static unprivileged application image, initializes PostgreSQL, starts the pinned recursive resolver, mounts source data read-only, and requires bearer authentication even on the loopback-published port. The drill checks authenticated liveness, operation-level readiness, bounded metrics, synchronous local IP lookup, CLI lookup inside the application container, candidate import, reviewed activation, rollback, and status. PostgreSQL integration runs against a fresh pinned PostgreSQL 18 container and covers migrations, atomic admission, work claims, terminal completion, durable pins, and operational metrics.

The dataset repository tests cover malformed and corrupt artifacts, stale sources, single-writer contention, approval-hash-bound activation, rollback, immutable candidates, durable publication, and pruning. Manager, job, and PostgreSQL tests cover coherent readers during activation, retained last-known-good views, retry/restart recovery, stale attempt rejection, terminal pin release, capacity reservations, and fail-closed reference checks. Health tests distinguish process liveness, durable-operation storage health, and actual local lookup-index availability.

Offline classification paths do not initialize an enrichment client. Local lookup, bundle loading, rules, Wappalyzer passive fingerprinting, and reclassification consume supplied data only. Live DNS and HTTP collectors use the configured resolver and exact approved destination addresses; tests instrument those boundaries, including redirects, mixed answers, timeouts, response limits, and cancellation.

## Repair acceptance evidence

The acceptance repair at `2e52440` and its reload-cancellation follow-up cover these findings:

| Finding | Maintained evidence |
| --- | --- |
| 1. Historical built-in pins after restart | `TestBundleAnalyzerFactoryReconstructsBuiltinAfterDatasetActivation`, `TestRunnerUsesPinnedBundleAndCommitsTerminalReport`, and the PostgreSQL pin-lifecycle integration test cover analyzer reconstruction, pinned execution, and terminal pin release. |
| 2. Missing sources and false complete results | `TestLoadSourcesPreservesMissingFeedCoverage`, `TestLookupIPIsPartialWhenConfiguredProviderFeedsAreMissing`, `TestLookupIPRejectsAddressFamilyWithNoUsableSource`, `TestLookupIPDoesNotRequireDurableStore`, and the E1 CLI rendering assertion cover source state, address-family applicability, HTTP 200 partial results, and CLI exit 3. |
| 3. HTTP peer enrichment | `TestE1DomainAnalysisStartsHTTPBeforeAAAAAndKeepsPartialEvidence` proves that fresh evidence references the HTTP peer. `TestReclassifyEnrichesHTTPRedirectPeerWithNewPrefixAndASNData` proves replay enrichment and external-redirect scope. |
| 4. Activation and pruning | `TestActivateCoordinatedExcludesPruneAndRestoresPointerOnFailure` covers the filesystem lock and pointer compensation. `TestPostgresAdmissionClaimCompletionAndPinLifecycle` ran against a fresh PostgreSQL 18 instance and covers the lifecycle advisory lock, durable activation, and prune protection. |
| 5. Replay parity | `TestReclassifyPreservesCaptureAndUsesNewClassificationProvenance`, `TestReclassifyEnrichesHTTPRedirectPeerWithNewPrefixAndASNData`, `TestReclassifyRequiresUsableReplayPath`, and `TestReclassifyRejectsFindingsWithoutRetainedInputs` cover selected-bundle provenance, prefix and ASN replay, partial paths, and rejection when no replay path applies. |
| 6. Bundle acquisition cancellation | `TestRunnerRenewsLeaseAndCancelsDuringBundleAcquisition` covers lease renewal before acquisition. `TestBundleAnalyzerFactoryLoadsDifferentBundlesConcurrently` covers per-bundle load isolation. `TestBundleAnalyzerFactoryReloadLoopCancelsBlockedLoad` covers cancellation through the production reload loop. |
| 7. Shutdown ownership | `TestSupervisorJoinsWorkerTerminalCommitOnShutdown` proves that the supervisor waits for a bounded terminal commit. `TestBundleAnalyzerFactoryReloadLoopCancelsBlockedLoad` proves that the reloader stops on cancellation. The service waits for both goroutines before `Store.Close`. |

The repair did not exercise these full production compositions:

- No single test restarts the complete service with a queued `builtin-rules-v1` PostgreSQL job and then runs that job through the production worker. The factory, runner, and durable pin behavior are tested separately.
- No single test races the production `datasets activate` and `datasets prune` CLI commands across both the filesystem and PostgreSQL. Repository exclusion and PostgreSQL lifecycle serialization are tested separately.
- No test sends a process signal to `Serve` while a real HTTP listener, a blocked reload, a worker terminal commit, and PostgreSQL are all active. The HTTP, supervisor, reload-loop, and store-lifetime boundaries are tested separately.
- The temporary external acceptance overlay was not available for the repair run. Maintained repository tests cover its built-in pin and missing-feed cases.

## CT qualification

The optional RFC 6962 collector passes synthetic tests for checkpoint signatures, initial and continued tree consistency, exact-entry inclusion, altered entry bytes, proof budgets, invalid certificates, checkpoint retention after failure, and durable ingestion resume. The shipping 256-entry synthetic benchmark completed in 3.07 ms/run, accounted for 21 requests, 84,640 response bytes, 44,800 retained-field bytes, one-hour fixture lag, and reduced the fixture backlog from 256 to zero. See `docs/ct-operations.md` for the budget and interpretation.

A live public-log probe was not run because no operator-approved log URL, public key, and starting checkpoint were supplied. This is an accepted operational limit: the collector and verification boundary ship and are tested, but the synthetic throughput is not presented as public-network capacity.

## Requirement traceability

| Requirement | Release evidence |
| --- | --- |
| R01 End-to-end attribution | `internal/app/e1_test.go`, multi-vendor rule fixture, CLI and API report tests. |
| R02 No proprietary APIs | Dependency boundary tests, local-file importers, passive Wappalyzer use, no-credential Compose drill. |
| R03 Targets and scope | `internal/target/normalize_test.go`, redirect-scope, CT-scope, CLI batch tests. |
| R04 DNS | Controlled UDP/TCP retry, TTL/record payload, chain, failure, and E1 DNS fixtures. |
| R05 HTTP/TLS | Exact-address dialing, redirect revalidation, Host/SNI preservation, timeout/body-limit/cancellation tests. |
| R06 Web fingerprints | Supplied-response-only detector test, retained sanitized HTTP capture, detector identity in reports. |
| R07 Cloud dataset | Full 91-file `cloud-ip-ranges` import plus immutable manifest and lifecycle tests. |
| R08 Service/region | Full AWS/GCP/Azure imports and conservative metadata fixtures, including empty Azure service handling. |
| R09 Prefix lookup | BART adapter oracle, overlap/tie, lifecycle, copy-ownership, and latency tests. |
| R10 ASN | IPv4/IPv6 inclusive intervals, overlap rejection, unknown/zero ASN, and latency tests. |
| R11 CDN adapter | Pinned data-only `cdncheck` conversion, digest provenance, local suffix/prefix lookup. |
| R12 Rules/taxonomy | 21 positive and seven negative deterministic cases plus the published coverage matrix. |
| R13 Evidence/findings | Reference validation, deterministic aggregation, relation separation, ambiguity and deduplication tests. |
| R14 Optional CT | Independent signature/continuity/inclusion tests, altered-entry rejection, bounded synthetic measurement; live-probe limit above. |
| R15 Interfaces | CLI JSON/JSONL and exit contracts, synchronous API, durable job/reclassification endpoints, OpenAPI/schema validation. |
| R16 Persistence | Fresh PostgreSQL integration, atomic reports, reservations, leases, pins, shared access, migrations. |
| R17 Update lifecycle | Immutable import/validate/activate/rollback/status/prune, atomic pointers, reload and retained pinned analyzers. |
| R18 Bounds/isolation | Request and source size caps, collection budgets, destination policy, backlog admission, cancellation and race tests. |
| R19 Observability | Per-operation readiness with capability reasons; bounded metrics for queue, pins, CT lag, source age, and bundle identity. |
| R20 Reproducibility | Canonical reports, immutable captures, temporal reclassification provenance, pinned-bundle runner and race tests. |
| R21 Deployment | Pinned unprivileged Compose and systemd artifacts, clean-stack drill, backup/restore and offline procedures. |
| R22 Deterministic search | Prefix, interval, suffix, alias, structured PostgreSQL filters; no vector or embedding dependency. |
| R23 Governance | Locked modules/images/source revisions, notices, CycloneDX SBOM check, dependency and redistribution audit. |

## Accepted limits and release conditions

- Full-source import memory is about 1.42 GB on the reference host; update jobs need a documented memory allowance.
- The Unbound image is pinned but available as `linux/amd64`; Apple Silicon uses emulation.
- The rule accuracy figures apply only to the controlled corpus. Unsupported and insufficient-evidence states are intentional and are not false negatives in that corpus.
- Live CT performance remains unmeasured until an operator approves a log identity, key, and checkpoint.
- Rights to redistribute Wappalyzer fingerprint data, converted `cdncheck` data, `cloud-ip-ranges`, and official feed snapshots remain unresolved. The application supports local operator imports; this repository does not claim unrestricted redistribution.
- Compose secret ownership and mode fields depend on the Docker Compose implementation. The application independently rejects group/world-readable credential and DSN files.
- Deployment was qualified on Docker Desktop/macOS with an emulated Unbound image, not on every Linux distribution or systemd host. The systemd units and offline build recipe were statically validated but not installed on this macOS host.
