# Dependency audit

Status: wave 1 audit at repository revision `4b7a5030976f397aaab2a180a466d1e8e2c3bb0a`, with a release-candidate linked-dependency recheck on 2026-09-20.

This reference records the selected dependency revisions and their runtime boundaries. It does not grant rights to redistribute third-party datasets. Dataset terms remain separate from Go module licenses.

## Selected Go modules

| Module | Selected version and revision | License | Runtime contract |
| --- | --- | --- | --- |
| `github.com/gaissmai/bart` | `v0.29.1`, `d2ff02bd997024508238e443f15db686f255d408` | MIT | No initialization-time network behavior found. Build a table before publication and do not mutate a published table. Keep BART types inside the prefix adapter. |
| `github.com/miekg/dns` | `v1.1.73`, `d854399da1ee385b432e8b07f79e53bbfc1ab1b0` | BSD-3-Clause | `Client.ExchangeContext` supports application-controlled raw queries. The adapter supplies the resolver address and transport. No initialization-time network behavior was found. |
| `github.com/projectdiscovery/wappalyzergo` | `v0.3.2`, `ded8f3a4fef04dce413e5b6340880de87507ee0a` | MIT for code | `New` compiles embedded fingerprints. `Fingerprint` and `FingerprintWithInfo` consume supplied headers and body bytes. The passive path does not fetch or run browser detection. |
| `golang.org/x/net` | `v0.58.0`, `acc78e0d2b2c855c0c4fbdcfe5f42a9e3d0f9778` | BSD-3-Clause style | `idna.Lookup` and the embedded public-suffix list perform no runtime fetch. `v0.59.0` requires Go 1.26 and is outside the selected Go 1.25 toolchain. |
| `github.com/google/certificate-transparency-go` | `v1.3.3`, `e8f93173135c7817ebd7133dab729c4576ce9a21` | Apache-2.0 | The caller supplies the HTTP client, proxy policy, deadlines, and log key. Construction performs no request. A missing verifier cannot support a verification claim. |
| `github.com/transparency-dev/merkle` | `v0.0.2`, `036047b5d2f7faf3b1ee643d391e60fe5b1defcf` | Apache-2.0 | The CT adapter uses the RFC 6962 hasher and inclusion/consistency proof verification only. It performs no network activity. |
| `github.com/jackc/pgx/v5` | `v5.11.0` | MIT | The application supplies one PostgreSQL DSN from a private file, pings explicitly, runs embedded migrations, and owns all query deadlines through caller contexts. The pool does not provide an enrichment path. |
| `go.yaml.in/yaml/v3` | `v3.0.5` | MIT or Apache-2.0 | Strict known-field decoding is used for local operator configuration only. Input files are capped at 1 MiB. The decoder performs no network access. |

The linked executable also contains `pgpassfile v1.0.0`, `pgservicefile` at `5a60cdf6a761`, `puddle/v2 v2.2.2`, `golang.org/x/crypto v0.55.0`, `x/sync v0.22.0`, `x/sys v0.47.0`, `x/text v0.41.0`, and `google.golang.org/protobuf v1.36.11`. These versions are pinned by `go.mod` and `go.sum`, listed in the CycloneDX SBOM, and checked against `go list -deps` by `scripts/verify-sbom.py`. None is an attribution data source or an independent enrichment client.

The selected `miekg/dns` GitHub v1 line receives only specific fixes while v2 development occurs on Codeberg. The narrow `DNSClient` adapter contains this maintenance risk. A later migration assessment can replace the implementation without changing the application contract.

## Fingerprint data

The selected `wappalyzergo` revision embeds these assets:

- `fingerprints_data.json`: SHA-256 `c662ae9244c255b35ccc6d5e92c05aa0f9ca95af5f6cd552217524e6f7e464e5`
- `categories_data.json`: SHA-256 `195f9a946c5b3a855839882cb8365a4d9758e8054fbec77f8bfd662f2211ddf3`

The passive API returns technology results, not a stable per-regular-expression proof contract. Reports use `explanation_granularity=detector_result`, preserve raw technology names, and reference the HTTP observation. Review the embedded fingerprint data's provenance before redistributing it independently from the binary.

## `cdncheck` is data-only

Do not import `github.com/projectdiscovery/cdncheck` into the worker. At revision `a06260a272dc92cec0747f2f369b697088899bc7`, `cdncheck.go` blob `2c8e268bc24ade402afbe7eceef88517ffda3812` performs an initialization-time UDP dial to Google's IPv6 DNS service with a three-second timeout. The package also contains default Cloudflare and Google resolver addresses. `other.go` blob `946954e2d6bf2807629af9bb2f3852de8c39499f` adds a separate public-suffix dependency.

The updater converts pinned `sources_data.json` content into application-owned normalized records. The source file groups CIDR and suffix data under `cdn`, `waf`, `cloud`, and `common`. Each converted record keeps the upstream revision, source-file digest, raw category, provider key, and notice. The code license is MIT. Rights for every generated-data source remain unresolved and block redistribution of a bundled converted dataset until reviewed.

## Network and proxy behavior

The selected passive BART, DNS, IDNA, public-suffix, and Wappalyzer construction paths do not need network access. The application still instruments startup and classifier tests for attempted connections.

The CT client must receive an application-owned `http.Client`. A nil client would use standard defaults, including environment proxy behavior and no application deadline. Target HTTP collection also disables environment-derived proxies unless the operator configures an equivalent policy-enforcing proxy.

## CT proof boundary

The collector evaluates three checks independently:

1. Verify the signed tree head with the configured log key.
2. Verify consistency between the stored and new tree heads when a previous checkpoint exists.
3. Fetch and verify an audit path that proves inclusion of the exact entry bytes in the authenticated tree.

`GetRawEntries` supplies indexed entry bytes. `GetEntryAndProof` supplies the audit path for a selected entry and tree size. `GetSTHConsistency` supplies a consistency proof. Successful parsing or transport proves none of these properties.

A bounded live feasibility probe still needs an operator-approved log URL, pinned public key, and starting checkpoint. The prepared probe budget is 256 entries in four batches, at most 16 deterministic inclusion proofs, one tree-head request, at most one consistency request, 24 total HTTP requests, 8 MiB of response bytes, 60 seconds elapsed, a 10-second request deadline, and concurrency one. Record throughput, response bytes, retained bytes, observed ingestion lag, and backlog trend. The probe does not establish exhaustive or domain-filtered retrieval.

## Open release questions

- Review the provenance and redistribution terms for Wappalyzer's embedded fingerprint data.
- Review each upstream source represented in the converted `cdncheck` data.
- Resolve the absence of a top-level license in the pinned `disposable/cloud-ip-ranges` revision before redistributing its data.
- Record the source-specific terms for downloaded AWS, GCP, and Azure artifacts before bundling them.
- Run the bounded CT probe only after an operator supplies or approves the log identity, key, and starting checkpoint.

These questions do not prevent local import and testing. They prevent unsupported redistribution claims.
