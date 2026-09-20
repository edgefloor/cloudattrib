# Specification: self-hosted cloud and SaaS attribution

**Project:** `cloudattrib` (working name)  
**Version:** 2.1\
**Date:** 2026-09-20  
**Status:** Implementation contract  
**Companion:** [IMPLEMENTATION-PLAN.md](IMPLEMENTATION-PLAN.md)

## 1. Purpose and complete scope

Build a self-hosted Go application that answers:

> Given a domain, hostname, URL, or IP address, which cloud infrastructure and SaaS products are publicly associated with it, and what evidence supports each association?

The primary use case is evidence collection for lead enrichment by a cloud optimization business. The system supplies attribution evidence to support downstream lead qualification. Qualification decisions, lead scoring, spend estimates, and savings estimates are outside scope. Preserve useful evidence when individual collection or enrichment capabilities are unavailable, and expose the resulting limits.

This specification covers the **complete domain-to-product system**, not an initial IP-lookup component. A complete implementation includes DNS collection, CNAME classification, bounded HTTP collection, local web-technology fingerprinting, cloud and CDN attribution, local ASN enrichment, provider service/region metadata, evidence aggregation, persistent results, batch processing, and operational tooling. Certificate Transparency (CT) is an implemented, optional discovery module that is disabled by default.

The system reports observed associations. It must not turn an AWS-hosted endpoint into a claim that the domain owner buys AWS directly, or turn a verification token into proof of a paid SaaS subscription.

### 1.1 Required capabilities

| ID | Capability | Completion requirement |
| --- | --- | --- |
| R01 | End-to-end attribution | A domain produces a combined, evidence-backed infrastructure and product report. |
| R02 | No proprietary enrichment APIs | No commercial lookup service, vendor account, enrichment API key, or telemetry is required. |
| R03 | Target normalization and scope | Support domains, hostnames, HTTP/HTTPS URLs, IPs, and bounded batches with explicit scope. |
| R04 | DNS collection | Collect A, AAAA, CNAME, MX, NS, and TXT with record ownership, TTLs, chain relationships, and per-query outcomes. |
| R05 | HTTP and TLS collection | Make bounded website requests and record headers, redirects, selected HTML signals, peer IPs, and TLS metadata. |
| R06 | Web-technology detection | Run `wappalyzergo` locally against collected headers and bodies. |
| R07 | Upstream cloud dataset | Import `disposable/cloud-ip-ranges` with provenance, overlaps, and retirement handling. |
| R08 | Service/region enrichment | Import official AWS, GCP, and Azure range metadata without claiming that every range identifies a customer product. |
| R09 | Exact IP-prefix matching | Use Go `net/netip` and BART. Preserve all eligible covering associations by default. |
| R10 | Local ASN enrichment | Import downloadable IP-to-ASN data and perform local IPv4/IPv6 lookups. |
| R11 | CDN/cloud classification | Reuse audited `cdncheck` data through a local-only adapter. |
| R12 | Product fingerprint rules | Maintain versioned DNS and HTTP rules, product IDs, aliases, categories, and tests. |
| R13 | Evidence and conclusions | Keep observations, detector evidence, and inferred findings separate. |
| R14 | Optional CT discovery | Support local CT import and bounded collection from explicitly configured supported public logs. |
| R15 | Go, CLI, and HTTP interfaces | Expose the same behavior through an application interface, CLI, synchronous API, and durable batch jobs. |
| R16 | Persistence and retrieval | Store reports, evidence, job state, and finding history in self-hosted PostgreSQL. |
| R17 | Dataset operations | Build immutable bundles, validate, activate atomically, refresh, and roll back. |
| R18 | Collection limits and isolation | Enforce scope, network destination policy, timeouts, byte limits, and concurrency limits. |
| R19 | Observability | Expose health, coverage, data freshness, errors, and low-cardinality metrics. |
| R20 | Reproducibility and testing | Reclassify stored evidence and test against fixtures, an IP oracle, and controlled network services. |
| R21 | Self-hosted deployment | Supply a Go application, PostgreSQL, a local recursive resolver, and operator-run update jobs. |
| R22 | Deterministic search | Use CIDR, suffix, alias, and structured database indexes. No embeddings or vector database. |
| R23 | Dependency and data governance | Pin dependencies and source revisions, retain notices, and audit network side effects. |

Implementation phases order the work. They do not reduce these requirements to a smaller release.

Every listed capability is required for delivery. Runtime availability is a separate contract: section 14.2 defines which unavailable capabilities allow partial results and which prevent an operation from executing. Missing enrichment data must never be reported as a successful no-match.

### 1.2 Network policy: no enrichment APIs does not mean no collection

Live domain analysis necessarily contacts a configured DNS resolver and the target's public website. All attribution and fingerprint matching happen locally.

| Process or action | Permitted network access |
| --- | --- |
| Offline IP lookup and evidence reclassification | None. |
| Live analysis worker | Operator-controlled recursive DNS, public HTTP/HTTPS targets admitted by policy, and local PostgreSQL. |
| Dataset updater | Explicitly configured public static downloads, public Git transport, or an operator-controlled mirror. Local-file import must also work. |
| CT collector, when enabled | Explicitly configured public log read endpoints, using supported open protocols. |
| Build pipeline | Pinned source and dependency retrieval. An offline build path must be documented. |

Do not use IPinfo, Censys, Shodan, SecurityTrails, BuiltWith, the Wappalyzer SaaS API, ProjectDiscovery Cloud, crt.sh search, VirusTotal, or a hosted DNS-enrichment API. Do not add public DNS fallback servers implicitly. A public static JSON download is an update input, not a per-target enrichment dependency.

Upstream metadata can mention APIs used by the upstream crawler. Preserve those URLs as provenance, but never follow them automatically. Do not execute the upstream crawler.

### 1.3 Non-goals

No vulnerability assessment, port scanning, exploitation, SMTP interrogation, exhaustive subdomain brute force, authenticated website crawling, JavaScript execution, or browser automation. No inference of contracts, spend, employee counts, private architecture, or hidden origin servers. No promise to discover every product a company uses.

No embedding model, vector index, distributed message broker, graph database, or Kubernetes requirement. A complete copy of every public CT log and a raw BGP collector are not prerequisites for the supported local CT and ASN paths.

## 2. Architecture and engineering choices

The component selections and boundaries in this section are requirements. Explanatory notes identify their rationale; external library observations remain subject to the P0 dependency audit.

```text
                                       PUBLIC DATA UPDATES
                              Git mirror / static files / local imports
                                                |
                                    normalize, validate, version
                                                |
                                      immutable data bundle
                                                |
INPUT                                           v
 domain / hostname / URL / IP ---> capture AttributionView once
            |
     normalize and scope
            |
     plan seed hostnames <---- optional local CT index
            |
       DNS collector --------> A / AAAA / full CNAME chains / MX / NS / TXT
            |                                      |
            |                               DNS product rules
            |
       HTTP collector -------> headers / redirects / HTML / TLS / peer IP
            |                                      |
            |                                  wappalyzergo
            |
       observed IPs ----------> BART cloud and service ranges
            |                  local ASN interval index
            |                  local cdncheck-derived classifications
            |
       observations + detector evidence
            |
       relation-aware aggregation
            |
       normalized findings + coverage + provenance
            |
       JSON / JSONL / API / PostgreSQL
```

### 2.1 Selected components

| Concern | Selection | Boundary |
| --- | --- | --- |
| Language | Go | One application codebase and executable. |
| DNS | Raw-record Go DNS adapter using a pinned `miekg/dns` implementation | Send only to configured resolvers. Preserve intermediate CNAMEs and TTLs. |
| Recursive resolver | Self-hosted Unbound | Run alongside the application, without commercial DNS enrichment. |
| HTTP | `net/http`, `crypto/tls`, `crypto/x509` | The application owns every request and redirect. |
| HTTP fingerprints | `projectdiscovery/wappalyzergo` | Input is already-collected headers and bytes. No second fetch. |
| IP representation | `net/netip` | Canonical address and prefix values. |
| Prefix index | `github.com/gaissmai/bart` | Local all-covering and longest-prefix lookups. |
| Provider breadth | `disposable/cloud-ip-ranges` | Import individual provider documents from one revision. |
| Product/region detail | Official AWS, GCP, and Azure downloadable range files | Separate source-specific adapters. |
| CDN metadata | `projectdiscovery/cdncheck` generated data | Data-only, locally evaluated adapter, not an uncontrolled runtime resolver. |
| ASN | Locally mirrored IPtoASN TSV files | Ordered interval indexes, no lookup API. |
| Product rules | Application-owned, versioned YAML or JSON | Compile to deterministic matchers. JSON is the canonical interchange form. |
| Persistent application state | PostgreSQL | Jobs, reports, evidence, history, and structured finding retrieval. |
| Large update artifacts | Local filesystem or operator-controlled object store | The reference deployment uses local storage. |
| IDNA and domain boundaries | Pinned Go IDNA and public-suffix data | Validation and scope helpers, not ownership inference. |

Select and pin a supported raw-record DNS implementation during the dependency audit, behind the same `DNSClient` interface. Do not silently track a default branch.

**Rationale.** The collector needs exact resource records and intermediate aliases. The inspected GitHub `miekg/dns` project points to a v2 on Codeberg and describes the GitHub version as receiving limited fixes. This maintenance observation motivates the audit; it does not replace revision selection. [S08, S09]

BART supports prefix lookup and covering-prefix iteration. The application must publish immutable tables rather than mutate a table that workers are reading. [S03]

### 2.2 Important `cdncheck` integration constraint

The inspected `cdncheck.go` includes default public resolvers and an initialization-time IPv6 connectivity check. Merely avoiding its domain-lookup method does not establish that importing the package has no network side effects. [S05]

The reference implementation therefore **imports the pinned generated data during the build/update process and evaluates it through a small local adapter**. Preserve its notices, category labels, source revision, and data hash. Do not import the unmodified runtime package into the default worker binary. A later audited package or maintained patch may replace this adapter only after passing the same no-egress tests.

This retains the agreed CDN/cloud classification capability. It does not require running another scanner or duplicating network collection. `cdncheck` data and the upstream cloud dataset may derive from the same sources, so matching both is not automatically independent corroboration.

### 2.3 One deployment, separate responsibilities

Start with one Go application service with bounded worker pools. Run `datasets` and `ct` updater commands as separate processes on an operator-controlled schedule. Use PostgreSQL for durable batch jobs rather than introducing Redis or Kafka.

The CLI can analyze a target without PostgreSQL and emit JSON directly. Production service mode uses PostgreSQL for jobs and stored reports. Local IP lookup never needs PostgreSQL.

## 3. Targets, modes, and scope

### 3.1 Request model

Each request includes `target`, `kind` (`domain`, `url`, or `ip`), optional additional hostnames, and explicit analysis options. A caller may provide an `organization_label` for grouping. This label is caller-supplied, not a verified company identity.

Normalize DNS names to lowercase IDNA ASCII, preserve the original input, and remove one terminal DNS root dot. Reject invalid labels, embedded credentials, control characters, unsupported schemes, URL zones, and excessive input lengths. Store the IDNA/public-suffix data version used.

Parse IPs with `netip.ParseAddr`. Unmap IPv4-mapped IPv6 addresses for lookup, reject zone identifiers, and distinguish invalid input from a valid address with no matches. An `ip` request does not cause DNS, HTTP, or certificate requests.

For `url`, accept HTTP and HTTPS only. Fetch the supplied path and query, without a fragment, under the HTTP policy. Do not retain query values in routine logs. DNS collection uses its hostname. URL input must not become permission to crawl other links.

### 3.2 Seed selection

A registrable root-domain request analyzes that hostname and, by default, `www.<domain>`. A subdomain or URL request analyzes the supplied hostname only. An explicit `include_www=false` disables the additional root-domain seed.

Additional hostnames must lie within an explicitly declared root scope. CNAME targets, MX exchanges, and NS hosts may lie outside that scope, but are processed only as referenced dependencies. Do not recursively treat their domains as new organizations.

Optional CT names must be below an explicit root scope. A public-suffix boundary is not proof that two hosts have the same owner. An external HTTP redirect may be followed within the bounded policy, but findings from its landing page retain `scope=external_redirect` and are excluded from the original-domain product summary unless independent in-scope evidence supports the association.

### 3.3 Modes

- `full`: DNS, HTTP, fingerprints, local range, CDN, ASN, and product aggregation. This is the default for domains and URLs.
- `dns`: DNS and the same local enrichment/rule engine, without website requests.
- `ip`: Local provider, service-range, CDN, and ASN lookup only.
- `reclassify`: Re-evaluate stored observations and detector evidence with a selected rule/data bundle, without collection.

CT discovery is an independent option on a scoped domain analysis. It is not silently enabled by `full`.

### 3.4 Execution order and consistency

At target-job execution start, capture one immutable `AttributionView`, containing data indexes, rules, taxonomy, policy version, and detector build identities. Retain that view until the report is complete. Do not mix old range data with new rules midway through a job.

Normalize targets, select seeds, and collect DNS. Start HTTP as soon as one address has passed the per-address destination policy. Dial that exact address while preserving the requested hostname for Host/SNI. Do not wait for the other address family or MX/TXT queries. A private address, failed AAAA query, or later blocked answer must not prevent or invalidate collection from an approved public IPv4 address. Apply the same scheduling and validation rules to each redirect.

Continue the remaining DNS queries within the target's deadline and budgets. Record their outcomes, blocked addresses, and incomplete coverage independently of HTTP success. Enrich relevant DNS addresses and actual HTTP peer addresses locally where sources are usable. Run available DNS rules and HTTP fingerprinting, then aggregate all useful evidence under section 14.2.

Use one in-job resolver cache and one collection result per equivalent request. Detectors consume observations. They must not independently re-resolve or re-fetch the target.

An unpinned batch can span multiple data activations. Each target captures the active view when that target attempt starts and records its bundle; a retry may capture a newer view. A caller may instead pin an available compatible bundle for the entire batch. Before accepting a pinned batch, persist its bundle reference and protect it against pruning. Protection covers queued targets and pending retries, survives restarts, and lasts until every target is terminal. Admission and pruning must coordinate as specified in section 12.2. Reject an unavailable or incompatible requested bundle explicitly; never substitute the active bundle.

## 4. DNS collection

### 4.1 Records and observations

For each original seed hostname, query A, AAAA, CNAME, MX, NS, and TXT. Record question name, type, response code, resolver identity, transport, observation time, resource-record owner, value, TTL, and answer section. Preserve MX preference and individual TXT resource records.

Follow CNAME chains explicitly, retaining every link and owner. Query A/AAAA at terminal names. Detect loops and cap chain depth. Do not substitute a single final canonical name for the complete chain.

Resolve MX and NS target addresses only for dependency attribution, within the DNS budget. Do not open HTTP or SMTP connections to those hosts. Label their address evidence `mail_dependency` or `dns_dependency`, not `web_endpoint`.

When a hostname has no NS records, discover its applicable DNS zone through bounded SOA/NS resolution and label the result `inherited_zone`. Do not pretend parent-zone NS records were answered directly for the hostname. Do not inherit a parent's MX or TXT records automatically.

### 4.2 DNS result semantics

Distinguish `answered`, `nodata`, `nxdomain`, `timeout`, `servfail`, `refused`, `policy_blocked`, and `budget_exhausted`. DNS absence and DNS failure are not interchangeable.

Keep query outcomes separate from address-policy decisions. A successful DNS answer containing a private address remains an observed answer; record that address as prohibited for live connections with its policy reason. Record address-family timeouts and omitted queries even when HTTP succeeds through another address. Blocked connection candidates and incomplete requested queries contribute coverage limitations and a partial report when useful observations remain. Do not replace the whole hostname's outcome with `policy_blocked` merely because one address is prohibited.

Cache positive records no longer than their remaining TTL. Record original observation time on cache hits. Honor negative-cache semantics from the response where available. Cache keys include resolver identity, class, normalized name, and type. TTL zero is not reusable across jobs.

Retry a truncated UDP response over TCP to the same configured resolver. Never fail over to public resolvers unless the operator explicitly configured them, which the reference self-hosted deployment does not do.

TXT matching joins chunks within a single TXT record, never across distinct records. Parse SPF mechanisms separately from verification-token prefixes. Do not recursively expand SPF includes by default. An SPF include indicates sending authorization, not general SaaS adoption.

Treat a null MX as an explicit no-mail configuration. [S19] A CNAME or MX proves a DNS configuration at observation time, not successful application use. A flattened apex alias may expose no CNAME at all; report missing evidence rather than inventing it.

### 4.3 Resolver ownership

Inject the same resolver policy into DNS collection and HTTP dialing. Do not use `net.DefaultResolver` in a way that bypasses the configured resolver. Run Unbound with recursion, bounded caching, and no query-name telemetry to an external enrichment service.

## 5. HTTP, TLS, and local fingerprinting

### 5.1 Collection behavior

Use a shared, explicitly configured `http.Transport`. For a domain seed, request `https://<hostname>/`. HTTP fallback is off by default. When explicitly enabled, allow it only after a connection failure, not after a certificate-validation failure or an HTTP error response.

Follow at most five redirects and retain every hop. Record URL with redacted query values, status, selected headers, cookie names, content type, body length/hash, connected peer IP, TLS certificate hash and SANs, validity period, and verified TLS status. Certificate names are evidence, not automatic new crawl targets.

Fetch one document per seed plus its redirect chain. Do not download referenced scripts, styles, images, favicons, or linked pages. Static script URLs and HTML attributes can still be fingerprint signals. Do not execute JavaScript.

Run local detection before discarding sensitive response values. The default persistent report retains cookie names, not cookie values; verification-token types and hashes, not full tokens; and selected sanitized headers, not authorization data. Raw response capture is an explicit restricted diagnostic option.

An HTTP 403, 404, or 500 can still contain useful public technology evidence. Treat it as an observed response rather than a network failure. Mark truncated bodies so consumers know the detector did not see the entire document.

### 5.2 Request destination policy

For every connection and redirect, resolve through the configured resolver and validate each candidate address independently. Start a connection when an approved public address is available, dial that exact address directly, and preserve the requested hostname for HTTP Host and TLS SNI. Never connect to a prohibited address. Do not validate one resolution and then allow the transport to perform a different one. Any connection retry or alternate-address attempt must use an independently approved address.

The default live policy rejects loopback, private, link-local, unspecified, multicast, documentation, benchmark, and other non-public destination addresses, including IPv4-mapped forms and cloud metadata destinations. A mixed public/private answer does not block the hostname: discard prohibited addresses from connection candidates, retain their observations and policy reasons, and continue with approved addresses. A failed AAAA query does not block an approved public IPv4 address. If no approved address becomes available within the resolution budget, omit that HTTP request and record why. Continue collecting other usable evidence.

Connection reuse must preserve destination enforcement: record the actual peer address and reuse only a connection admitted under a compatible policy. Disable environment-derived proxy behavior unless an explicit operator-controlled proxy is configured and provides equivalent destination enforcement.

Use only ports 80 and 443 by default. Do not forward user-supplied authorization, cookies, or arbitrary headers. Do not retain a cookie jar between targets. Keep TLS certificate verification enabled. A dedicated loopback-capable test policy is available only in the test harness, not through a caller's API request.

Go's HTTP transport exposes custom dialing, timeout, proxy, and connection controls needed for this collector. These controls must be set explicitly rather than inferred from defaults. [S10]

### 5.3 `wappalyzergo` adapter

Construct the pinned local fingerprint engine once per compatible detector build. Pass the already-collected headers and bounded body to it. The documented `Fingerprint` path consumes headers and body; runtime/browser detection is a separate optional capability that this design does not use. [S04]

Persist raw detector technology names separately from canonical product IDs. Map technologies through the application's versioned taxonomy. Keep frameworks such as React as `web_technology`; do not promote them into cloud products.

Record the library revision and fingerprint-data digest. Do not promise per-regex proof if the selected API returns only technology names. In that case, reference the response observation and disclose `explanation_granularity=detector_result`. Application-owned rules must provide exact matched fields and rule IDs.

A fingerprint update bundled in a new library build is a deployment, not automatically a hot-swappable data file. Bundle compatibility checks must account for this distinction.

## 6. Dataset ingestion and source semantics

### 6.1 `disposable/cloud-ip-ranges`

Use the upstream repository for broad provider coverage. Resolve one Git revision, then read the selected files from that revision. Also accept an already-populated local directory with a supplied provenance manifest. Do not require the GitHub REST API or an account.

Discover regular primary provider files under `json/`. Exclude `all-providers.json` and `*-details.json` from primary-provider discovery. Exclude `misc/` by default. An operator may explicitly select additional providers; record that selection in bundle identity. Do not silently skip a selected malformed file.

The inspected upstream documents use provider metadata and `ipv4`/`ipv6` lists. Some retired prefixes remain in those lists, with lifecycle annotations in detail records. The README explicitly describes retained retired ranges. Importing every base-array entry as active is incorrect. [S01, S02]

The adapter must:

1. Preserve `provider`, `provider_id`, `method`, `coverage_notes`, raw timestamps, `source`, and `source_http` when present.
2. Parse, mask, and deduplicate CIDRs without expanding them into addresses. Reject invalid family placement and malformed known fields.
3. Join retirement information by provider ID and canonical prefix. Apply retirement only to that association, not to every other record sharing the prefix.
4. Preserve unknown source fields in archived input. Unknown method labels remain source metadata rather than causing invented classifications.
5. Fail validation for malformed or conflicting lifecycle metadata. Never turn an unsupported lifecycle state into active data.
6. Treat the base-array/detail relationship as an adapter contract verified across the complete selected revision, not as an assumption inferred from one sample.
7. Retain source paths, record references, file hashes, adapter version, and Git revision.

Base lists and any richer `*-details.json` files are different input contracts. Rich details may be imported only by an explicit tested adapter; do not assume every provider has them. The required product-depth path uses the official feeds below, so service/region support does not depend on unverified detail formats.

A selected provider file disappearing, an empty required family, or a large coverage change must be surfaced in the update report. An empty family is not itself invalid when that provider legitimately publishes only the other family.

### 6.2 Official service-range adapters

Implement all three adapters as part of the complete system. They run in the updater and also accept local files.

| Source | Preserve | Interpretation limits |
| --- | --- | --- |
| AWS `ip-ranges.json` | IPv4/IPv6 prefix, `service`, `region`, `network_border_group`, publication metadata | A prefix may have several service tags. An EC2 tag is not proof of an EC2 instance owned by the analyzed organization. |
| GCP `cloud.json` | Prefix, `service`, `scope`, creation metadata | Generic Google Cloud ranges do not distinguish every GCP product. Do not infer BigQuery, GKE, or Cloud Run from generic ownership. |
| Azure downloadable Service Tags JSON | Tag name, prefix list, region, system service, change metadata | Preserve the tag's direction and purpose where mapped. A control-plane or egress range is not automatically a customer-facing deployment. |

AWS documents overlapping service sets, incomplete coverage, and exclusions such as BYOIP. Google distinguishes its customer-cloud range file from broader Google-owned ranges. Azure service tags describe groups of addresses with service-specific purposes. These are reasons to preserve source meaning, not to discard useful metadata. [S11, S12, S13, S14]

For Azure, configure a vetted public download URL or local mirror and implement explicit download-page discovery only if tested. Do not require an Azure subscription, SDK authentication, or the Service Tag Discovery API. Never hard-code a dated download URL as permanently current.

Normalize each source record independently. Do not merge away service tags merely because their prefixes are identical. Use reviewed mappings from raw service labels to product IDs. Unmapped labels remain visible as `service_range` evidence.

Provider breadth and official service detail may disagree or have different source times. Preserve both, their revisions, and any conflict. The aggregator can prefer a more direct source for a particular claim without erasing the other observation.

### 6.3 Local ASN data

The default ASN adapter imports IPtoASN IPv4 and IPv6 TSV downloads. The published schema is an inclusive address interval, ASN, country code, and description. These files are a local data source, not a live API. [S07]

Parse and validate ordered, disjoint intervals for each family. Build a sorted immutable interval index and use binary search. Do not treat interval endpoints as CIDR boundaries or expand them into single addresses. Reject conflicting overlaps within this adapter's input contract.

Keep raw ASN descriptions and country codes as source metadata. Do not use them as physical server location, `is_hosting`, or product labels. An unknown/zero ASN must not become a provider. A separate reviewed ASN-to-provider alias can supply weak network evidence.

The normalized ASN model permits multiple origin ASNs for future or operator-supplied routing snapshots. The IPtoASN adapter must not manufacture multiple origins that its source does not contain. Importing raw MRT/RIB data is not required for this default path.

### 6.4 Source validation and freshness

Every importer must enforce file-size, decompression, nesting, record-count, and string-length limits. Reject path traversal, symlinks outside the input root, duplicate JSON object keys, invalid UTF-8, trailing JSON documents, and invalid known-field types. Checksums prove artifact identity, not source trust.

Preserve source publication time, last successful retrieval time, and local activation time separately. Re-fetching an unchanged file does not change when that source last published data. A timestamp without a timezone remains explicitly timezone-unknown rather than silently being labeled UTC.

Network/range sources receive a freshness warning after seven days without a successful check by default. Freshness settings are per source. A warning does not automatically remove all results or turn an old record into a retired one. An operator may configure a hard maximum age. Required data that exceeds a hard age limit must make the relevant capability unavailable explicitly.

### 6.5 Provider categories and direction

The upstream set includes more than general-purpose hosting. Local taxonomy must distinguish cloud infrastructure, CDN, managed hosting, SaaS endpoints, mail services, crawlers, client egress, and unknown network roles.

A match to a crawler or private-relay egress list is not evidence that a website is hosted by that service. Store the network association, but require role-compatible evidence before putting a product in the website-infrastructure summary.

## 7. Local IP matching

### 7.1 Index shape

Use an immutable `bart.Table[[]AssociationID]`. Store provider, service, region, role, lifecycle, and provenance in a separate immutable association catalog. Merge all association IDs for the same canonical prefix before publishing the table.

Do not store a single winning provider at a prefix. Different sources, providers, or service tags can legitimately share it.

### 7.2 Lookup semantics

`mode=all` is the default for attribution. Enumerate every indexed prefix containing the address and return all eligible associations, ordered by decreasing prefix length, canonical prefix, provider ID, product/service key, and source ID.

`mode=longest` is a convenience for callers who explicitly request it. First filter associations by lifecycle and requested categories, then choose the most specific prefix that still has eligible associations. Retain every eligible association tied at that prefix.

A retired /24 must not hide an active /16. A narrower third-party service must not make the broader cloud-provider association disappear from an `all` result. Longest-prefix matching answers specificity, not which business relationship is true.

An `include_retired=true` option exposes historical records with a historical label. Domain-product aggregation excludes retired-only evidence by default. Lifecycle is evaluated from the captured snapshot, not changed unpredictably by the lookup wall clock.

### 7.3 Required synthetic example

For test address `198.51.100.7`, use:

| Prefix | Association | State |
| --- | --- | --- |
| `198.51.0.0/16` | Example Cloud | Active in snapshot |
| `198.51.100.0/24` | Example CDN | Active in snapshot |
| `198.51.100.0/24` | Example Service | Active in snapshot |
| `198.51.100.0/25` | Former Service | Retired |

Default `all` returns the /24's two associations and the /16. Default `longest` returns the /24's two associations. `longest` with retired records included returns the retired /25. Every result carries its prefix and lifecycle.

These are invented associations using documentation addresses. They are index fixtures, not targets for live collection.

### 7.4 Unknowns and bounds

No match means “not found in these datasets,” not “not in the cloud.” A successful complete no-match requires all requested applicable lookup sources to be usable and searched. With some sources unavailable, return available associations and `status=partial`, even if the searched sources found none. With no applicable usable source, return `capability_unavailable`, HTTP 503 and CLI exit 4. Never collapse unavailable sources into an empty successful result. Malformed input is a validation error. A valid private address can be queried locally, but live fetching that address is blocked by the separate collection policy.

Bound associations returned per address. If the limit is exceeded, return an explicit error or a marked truncated evidence set with `coverage=partial`; never silently pick a provider. On association-limit overflow, the default local lookup API returns an explicit limit error. This overflow rule does not change the partial-result behavior for unavailable sources.

Keep BART behind an application-owned interface and test it against a brute-force `Prefix.Contains` oracle. Do not expose its mutable tables to callers.

## 8. Product taxonomy and fingerprint rules

### 8.1 Canonical entities

A provider has a stable application ID, display name, aliases, and reviewed categories. A product has a stable ID, parent provider, category, aliases, and supported evidence relationships. Preserve upstream IDs separately from canonical IDs.

Initial release coverage must satisfy the product-and-relationship acceptance matrix in section 8.5 for AWS CloudFront, ELB, S3 and Route 53; Azure App Service, Blob Storage and Azure DNS; GCP infrastructure; Cloudflare, Fastly, Vercel and Netlify; Google-hosted mail, Microsoft-hosted mail, Proofpoint and Mimecast; and visible HubSpot, Segment and Atlassian associations. Provider-only results are appropriate when a signal cannot establish a product. They must not replace product detection where the agreed signal supports it.

This is a rule-development and validation requirement, not a claim that every one of these products is detectable from every domain. The implementation must maintain a coverage matrix identifying signal types and known blind spots. Do not create a broad false-positive rule merely to fill a coverage cell.

### 8.2 Supported matching operations

Support exact DNS-name matching, label-boundary suffix matching, anchored Go-compatible regular expressions, parsed TXT/SPF token matching, header-field matching, script-URL host/path matching, and raw technology-name mapping.

For suffix matching, normalize both names and require equality or a `.` boundary, subject to the rule's `include_apex` flag. `cloudfront.net.evil.example` and `notcloudfront.net` must never match `cloudfront.net`.

Prefer exact documented MX patterns over broad rules such as “every name ending in google.com.” Prefer constrained NS label patterns over an unbounded substring such as “awsdns.” Use vendor documentation and captured positive/negative fixtures for each rule.

Rule bundles contain stable IDs, version, signal and field, matching condition, provider/product mapping, relationship, evidence strength, source references, review date, and tests. Rules do not execute code or make network requests. Compile all matchers before activation.

### 8.3 Example rule

This rule illustrates the contract. Its positive example follows the CloudFront distribution-domain convention documented by AWS. [S15]

```yaml
schema_version: 1
rules:
  - id: aws.cloudfront.cname.v1
    signal: dns
    rrtype: CNAME
    field: rdata.target
    match:
      fqdn_suffix: cloudfront.net
      include_apex: false
    emit:
      provider_id: aws
      product_id: aws.cloudfront
      category: cdn
      relation: web_delivery
      strength: strong
      activity: configured
    source_refs:
      - S15
    tests:
      positive:
        - d111111abcdef8.cloudfront.net
      negative:
        - notcloudfront.net
        - cloudfront.net.evil.example
```

A rule's relationship is constrained by the observed edge. A CloudFront match reached through a mail dependency cannot be relabeled as the original website's web-delivery path.

### 8.4 Required conservative mappings

`google-site-verification` maps to Google domain-verification evidence, not automatically Google Workspace. A Microsoft verification token does not prove a Microsoft 365 subscription. An MX gateway identifies the visible routing layer, not necessarily the mailbox backend. A Cloudflare NS identifies authoritative DNS, not necessarily Cloudflare's reverse proxy.

A generic AWS, Azure, or Google-owned IP yields provider-level network evidence. A CDN's visible peer IP does not reveal its customer origin. A frontend framework does not prove the hosting vendor. An external script is an observed web integration, not proof that a subscription remains active.

### 8.5 Product-and-relationship acceptance matrix

Each named product in a grouped row requires its own dated signal reference, canonical mapping, positive fixture, and negative fixture in `rules/coverage-matrix.md`. These are required test contracts, not claims that every target exposes the signal. Validate exact vendor patterns during P0/P6 before authoring rules. Unsupported cases must identify the missing or insufficient signal and its reason; they cannot waive detection where the agreed signal is available. Every positive fixture must assert subject, product/provider specificity, relation, evidence references, and scope. Every negative fixture must assert the unsupported conclusion is absent.

| Product or family | Required signal and relationship | Positive fixture | Negative fixture and justified limit |
| --- | --- | --- | --- |
| AWS CloudFront | Reviewed distribution CNAME; `web_delivery` | In-scope CNAME to a documented distribution name identifies CloudFront. | Lookalike suffix and mail-dependency context do not produce website delivery; hidden origin remains unknown. |
| AWS ELB and S3 | Product-specific DNS endpoint pattern; `web_delivery` | Separate supported ELB and S3 endpoint fixtures identify the corresponding product. | Generic AWS IP/EC2 range alone does not identify ELB, S3, or a customer deployment. |
| AWS Route 53 | Reviewed authoritative NS pattern; `authoritative_dns` | NS fixture identifies Route 53 authoritative DNS. | AWS web IP or SPF signal does not establish Route 53 DNS. |
| Azure App Service and Blob Storage | Product-specific DNS endpoint pattern; `web_delivery` | Separate supported App Service and Blob endpoint fixtures identify each product. | Generic Azure service ranges do not establish either product. |
| Azure DNS | Reviewed authoritative NS pattern; `authoritative_dns` | NS fixture identifies Azure DNS. | Azure-hosted website alone does not establish its DNS provider. |
| GCP infrastructure | Official range/ASN evidence; `service_range` or `network_provider` | Preserve raw service/scope and provider-level association. | Generic ranges cannot identify BigQuery, GKE, or Cloud Run; provider-only output is appropriate. |
| Cloudflare | Reviewed NS and delivery signals; `authoritative_dns` and `web_delivery` separately | Separate DNS-only and independently supported delivery fixtures. | NS-only fixture must not yield proxying; no hidden-origin inference. |
| Fastly, Vercel, and Netlify | Reviewed service CNAME or product-specific HTTP signal; `web_delivery` | One product-specific fixture for each provider's supported delivery signal. | Generic shared addresses and suffix lookalikes cannot replace product evidence. |
| Google-hosted and Microsoft-hosted mail | Reviewed MX pattern; `mail_routing` | Separate fixtures identify the supported visible mail-routing product. | Verification-only TXT and SPF-only records do not establish mailbox hosting or subscriptions. |
| Proofpoint and Mimecast | Reviewed gateway MX pattern; `mail_routing` | Separate gateway fixtures identify each visible routing layer. | Do not infer the mailbox backend hidden behind the gateway. |
| Reviewed SPF provider rules | Parsed provider-specific SPF authorization; `sending_authorization` | A documented authorization mechanism identifies the supported provider/product at the justified specificity. | Mere substring, unrelated TXT, or MX-only signal must not yield sending authorization; no paid-adoption claim. |
| HubSpot, Segment, and Atlassian | Reviewed product-specific DNS or static HTTP integration signal; relation fixed by that signal | One supported product fixture per family, using a documented integration, endpoint, or verification signal. | External-redirect-only evidence stays external; verification remains `domain_verification`; script presence does not prove a subscription. |
| Web frameworks such as React | Local fingerprint result; `web_technology` category | Captured response yields a raw technology label and canonical technology mapping. | Framework detection must not imply a cloud vendor or SaaS purchase. |

Release acceptance requires every supported positive and negative fixture above to pass. Provider-only fallback is accepted only for documented signal limitations, such as generic cloud ranges. Broader corpus measurements in section 15.2 report accuracy and blind spots separately from these deterministic acceptance cases. Findings support lead enrichment; the matrix does not define lead qualification, spend, or savings decisions.

## 9. Evidence and aggregation

### 9.1 Collected observations, source records, and conclusions

**Observation:** An immutable collected fact, such as a DNS record, an HTTP response, or a connected peer address, with its original collection time.

**Dataset record:** Versioned source data consulted during classification, such as a prefix association or ASN interval. Keep its source identity, record reference, publication time, and effective time when supplied. Dataset records supply provenance to evidence. They are distinct from collected observations and are not assigned the target's collection time.

**Evidence:** A detector's interpretation of observations, such as “this CNAME matches rule `aws.cloudfront.cname.v1`.” Evidence references its input observations, any consulted dataset records, and the exact rule/data versions used.

**Finding:** A grouped conclusion about a subject, provider/product, and relationship, with supporting and conflicting evidence.

Use explicit relations: `web_delivery`, `authoritative_dns`, `mail_routing`, `sending_authorization`, `web_integration`, `domain_verification`, `network_provider`, `network_origin`, and `service_range`. Appropriate parsed SPF evidence yields `sending_authorization`, distinct from inbound mail routing and paid-product adoption. Infrastructure and SaaS summaries are projections of findings, not unrelated free-text lists.

### 9.2 Core fields

| Entity | Required fields |
| --- | --- |
| Observation | ID, type, subject, relation/context, observed time, collector version, status, sanitized typed payload, content hash where applicable |
| Dataset record | Source ID, revision/digest, record reference, consulted normalized fields, publication time and effective time when known |
| Evidence | ID, observation IDs, dataset-record references, classification time, detector ID, rule ID if applicable, source revision/digest, subject, provider/product IDs when known, relation, strength, activity, explanation |
| Finding | ID, subject, provider ID, optional product ID, category, relation, strength, activity, evidence IDs, conflict IDs, limitations |
| Report | Schema version, report ID, normalized target, mode, start/end times, collection times, classification time, bundle/build identity, status, findings, evidence, dataset-record provenance, coverage, warnings |
| Coverage entry | Capability, status, attempted/completed counts, error codes, truncation/omission counts, relevant data age |

Provider-only evidence has a null product. Unknown fields, including source publication/effective times, remain unknown rather than receiving fabricated defaults. All references must resolve within the report or its retained supporting records. Retain the consulted dataset fields and provenance needed to explain findings even after a bundle's large indexes are pruned.

### 9.3 Strength is not a probability

Use `strong`, `moderate`, and `weak` as documented evidence categories, not calibrated probabilities. Do not emit fabricated values such as 0.98. Do not add arbitrary weights from correlated detectors and present the sum as confidence.

A product-specific configured CNAME can support a strong configuration finding. A published generic prefix or ASN usually supports a weaker network association. A service-range match can be strong evidence of range membership while remaining insufficient proof of a particular customer deployment.

Within the same `(subject, provider, product, relation)` group, start from the strongest applicable rule. Increase support only through explicitly reviewed combination rules. Deduplicate evidence that has the same underlying response, prefix source, or fingerprint. ASN, `cdncheck`, and official range matches may overlap in provenance and must not automatically count as three independent confirmations.

Preserve conflicts and ambiguity. Never resolve a same-prefix provider tie by input order. Choose deterministic display order without implying a single verified owner.

### 9.4 Time and activity

Use activity labels `configured`, `responding`, `verification_only`, `historical`, and `unknown`. DNS is configuration evidence at its observation time. A successful HTTP connection is responding-endpoint evidence. A retired range or old CT record is historical context.

A complete analysis with no findings is different from an incomplete analysis. “Not detected” never means “not used.” A failed or partial follow-up run must not remove an earlier finding from history as though it had been disproved.

### 9.5 Reclassification

Reclassification means reinterpretation of existing collected observations using a selected compatible bundle. It does not reconstruct historical ownership. Create a new report linked to the original report and immutable collected observations. Preserve their original collection times and collection coverage. Record a new classification time, the selected bundle, and the versioned dataset records consulted by the new classification.

Record source publication and effective times separately when supplied, and leave unknown times unknown. A new association must not imply that it was valid at the original collection time. A difference between reports may reflect changed source data or rules rather than a change in the target's infrastructure. Keep original detector outputs with their original detector identity when reusing them as replay inputs.

When a new detector requires bytes that were not retained, mark that detector `unavailable_for_replay`. Do not silently fetch the website or claim full replay. Replaying `wappalyzergo` requires an explicitly retained suitable response capture; applying new canonical mappings to stored raw technology names does not.

Preserve all supported replay results. If a requested detector or source cannot replay but another applicable path can, return partial classification coverage under section 14.2. If no requested replay path is usable, return `capability_unavailable`. A standalone report export must include its normalized replay inputs or identify missing inputs explicitly; a report containing findings alone does not promise replay support. Retention must preserve shared observations while a retained reclassification report references them.

## 10. Optional Certificate Transparency discovery

CT remains optional at runtime, but its integration and implementation are required deliverables. Disabling it must leave the complete DNS/HTTP attribution pipeline usable.

### 10.1 Supported ingestion paths

Implement `ct import` for normalized JSONL records from an operator-controlled local CT source. Each record contains hostname or wildcard pattern, certificate hash, log ID when known, log entry index when known, logged time, certificate validity bounds, source identity, and verification status.

Also implement a bounded background `ct collect` command for explicitly configured RFC 6962-compatible logs, using an audited open-source Go CT client where appropriate. Persist log checkpoints and support restart. Require an explicit starting checkpoint or backfill boundary; do not start reading the entire global CT history automatically. RFC 6962 defines log read and proof interfaces, and the Google CT Go repository provides relevant client code. [S16, S17]

Verify configured log identity. Record `checkpoint_signature`, `continuity`, and `entry_inclusion` verification separately, each with `passed`, `failed`, or `not_performed`, the procedure/version, and a reason when not performed. Retain the log key identity and authenticated tree size/root used by a check. A valid checkpoint signature or continuity proof alone does not establish inclusion of fetched entry bytes.

Use `verified_log` only when a documented procedure authenticates the tree and establishes that the exact entry is included, through an inclusion proof or equivalent verified tree reconstruction. Continuity must pass when extending an existing checkpoint; at an initial trusted checkpoint, record why continuity was not performed. Data fetched without inclusion verification remains `log_unverified`; local imports remain `imported_unverified` unless their supplied proof material passes the same procedure. Never infer verification from successful parsing or transport. Failed verification must not advance the verified checkpoint or publish verified entries. Unsupported protocols are explicit errors. [S16]

Measure collector throughput, downloaded bytes, retained storage, and ingestion lag during P0 under explicit entry, byte, request, and elapsed-time budgets. Record the configured logs, starting checkpoint, observation window, hardware, and backlog trend. Root-scope filtering reduces retained data but does not provide domain-filtered retrieval from RFC 6962 logs: entries are fetched by index and inspected locally. Document the measured operating envelope and limits without claiming exhaustive discovery. Repeat the measurements for the shipping collector in P9.

Newer log protocols can be added through this adapter boundary. Supporting every log protocol is not a condition for the scoped local-import capability, and documentation must identify exactly which collector protocols ship.

### 10.2 Discovery semantics

Build a local hostname index filtered to configured root scopes. During an analysis, read a consistent bounded candidate set, record the index/checkpoint identity, and pass those concrete hostnames through the ordinary DNS and HTTP policy.

Deduplicate precertificate/certificate repeats. Do not expand wildcard names into invented hosts. A certificate name does not prove current DNS existence, current product use, or business ownership. It is a discovery lead until revalidated.

Default to a maximum of 20 CT-derived hostnames per target, selected deterministically by most recent logged time and then hostname. Report the available, selected, and omitted counts. Do not query crt.sh or any commercial CT-search service.

An empty local index, disabled CT, unavailable index, and partially ingested logs must have different coverage states. CT cannot support a claim of exhaustive discovery.

## 11. Application, CLI, and HTTP contracts

### 11.1 Application boundaries

Use application-owned interfaces so collectors, classifiers, storage, and upstream libraries remain replaceable. The following is an interface sketch, not a complete source file:

```go
type Analyzer interface {
    Analyze(ctx context.Context, req AnalyzeRequest) (Report, error)
    LookupIP(ctx context.Context, req IPLookupRequest) (IPLookupResult, error)
    Reclassify(ctx context.Context, req ReclassifyRequest) (Report, error)
}

type Collector interface {
    Collect(ctx context.Context, plan CollectionPlan) (Observations, Coverage)
}

type Detector interface {
    Detect(ctx context.Context, obs Observations, view AttributionView) (EvidenceSet, Coverage)
}

type SnapshotStore interface {
    Load(ctx context.Context, bundleID string) (*AttributionView, error)
    Activate(ctx context.Context, bundleID string) error
}
```

`AttributionView` is read-only to consumers. Exposed results own their slices/maps or return immutable wrappers. A caller must not be able to mutate published indexes through an API result.

Collection errors and unavailable individual enrichment sources normally become per-capability coverage entries. Apply section 14.2 to distinguish partial results from unavailable operations. Invalid requests, unavailable necessary execution capabilities, and storage failures remain typed application errors. Cancellation must propagate through DNS, HTTP, queue leases, and database calls.

### 11.2 Required CLI commands

```text
cloudattrib analyze example.com --kind domain --format json
cloudattrib analyze https://app.example.com/ --kind url --format json
cloudattrib analyze example.com --mode dns
cloudattrib analyze example.com --ct --scope example.com
cloudattrib batch --input domains.txt --format jsonl
cloudattrib lookup-ip 198.51.100.7 --match all
cloudattrib reclassify --report report.json --bundle <bundle-id>
cloudattrib serve --config config.yaml

cloudattrib datasets sync --config config.yaml
cloudattrib datasets import --source-dir ./upstream --config config.yaml
cloudattrib datasets validate --candidate <candidate-id>
cloudattrib datasets activate --candidate <candidate-id>
cloudattrib datasets rollback --bundle <bundle-id>
cloudattrib datasets status

cloudattrib ct import --input ct-records.jsonl --scope example.com
cloudattrib ct collect --config ct-logs.yaml
```

Angle-bracket values are operator-supplied identifiers, not literal arguments. The documentation IP is for offline examples only.

JSONL emits one envelope per input row, including failures, and carries `input_index`. Bound memory while streaming large CLI inputs. Preserve input order by default using a bounded reorder buffer that applies backpressure. An explicit unordered option may emit completed rows immediately.

Exit codes: 0 means all requested results completed, including complete no-match results. 2 means command/configuration/input-envelope error, idempotency conflict, or capacity rejection. 3 means at least one accepted target was partial, failed collection, or cancelled. 4 means unavailable necessary execution capability, unavailable/incompatible requested bundle, startup failure, or persistent-store failure. For mixed CLI batch outcomes, 4 takes precedence over 3; retain every per-row outcome. Do not use exit 4 merely because an enrichment source is missing when useful results remain. Diagnostics go to stderr, never into the JSON stream.

### 11.3 Required HTTP routes

| Method and path | Behavior |
| --- | --- |
| `POST /v1/analyze` | Analyze one target synchronously, persist the terminal report in service mode, and return it. |
| `POST /v1/lookup/ip` | Perform local IP enrichment without DNS, HTTP, or PostgreSQL dependency. |
| `POST /v1/jobs` | Validate and enqueue a bounded target batch. Return 202 with job ID. |
| `GET /v1/jobs/{id}` | Return job state, per-target counts, and result links. |
| `POST /v1/jobs/{id}/cancel` | Request cancellation and stop scheduling new work. |
| `GET /v1/results/{id}` | Return a stored report with evidence and coverage. |
| `GET /v1/results/{id}/observations` | Paginate sanitized supporting observations. |
| `POST /v1/results/{id}/reclassify` | Create a reclassification job using existing captures/evidence. |
| `GET /v1/findings` | Filter stored findings by domain, provider, product, relation, strength, and observation time. |
| `GET /v1/providers` and `GET /v1/products` | Search canonical IDs, names, aliases, and categories deterministically. |
| `GET /livez` | Process liveness only. |
| `GET /readyz` | Report per-operation readiness and per-capability degradation using section 14.2; 200 if at least one enabled public operation can execute, otherwise 503. |
| `GET /metrics` | Local operational metrics. |

Dataset activation is an operator CLI action, not a public unauthenticated HTTP endpoint. All list routes use bounded cursor pagination with deterministic ordering. Produce an OpenAPI contract and JSON schemas during implementation.

Return 400 for malformed request syntax, 422 for invalid target/options, 413 for oversized input, 429 for admission limits, and 503 with an explicit error code for unavailable necessary execution capabilities or persistence unavailability. A valid analysis with useful results and incomplete requested coverage returns 200 and `status=partial`. A syntactically valid IP with no matches is a complete 200 result only when all requested applicable sources were usable and searched. Apply the full decision table in section 14.2.

For a batch, reject a malformed envelope before insertion. Syntactically valid envelopes may contain individual invalid targets; persist those rows as terminal validation failures so one bad row does not erase other requested results.

Support client-supplied idempotency keys on job creation. The key is scoped to the local caller identity and a canonical request digest. The same key with a different request returns 409. It is not a guarantee of exactly-once network collection.

Bound the total accepted nonterminal target backlog across jobs, including queued targets, running targets that may retry, and delayed retries. Default to 10,000 target reservations, configurable by the operator. A reservation lasts until the target is terminal, so retries do not bypass or compete again for admission. Validate and reserve capacity atomically with job insertion. Reject a submission that exceeds the limit before inserting any of its rows, with HTTP 429, `queue_capacity_exceeded`, and CLI exit 2 where applicable. Concurrent submissions must not overrun the limit. Replays of an existing idempotent submission consume no new reservations; check them before rejecting for capacity. This limit is separate from the 1,000-row per-batch limit and the active-worker limits.

### 11.4 Shared trusted-operator access

The initial service has one shared trusted-operator model. Authenticated operators share visibility of all results and may cancel any job. Do not introduce tenant isolation or caller-specific result ownership. Caller identity scopes idempotency and supplies audit attribution only.

The application derives a stable operator ID from an operator-configured credential mapping, or from an authenticated reverse proxy's trusted identity assertion. Never accept identity from request bodies or arbitrary client-supplied headers. In proxy mode, restrict direct backend access and require the proxy to strip incoming identity headers before setting its verified identity. An explicitly unauthenticated loopback-only deployment uses one configured `local-operator` identity. Reject unauthenticated requests with HTTP 401 when authentication is enabled. Document credential rotation and stable identity mapping without logging credentials.

### 11.5 Example domain request

```json
{
  "target": "example.com",
  "kind": "domain",
  "mode": "full",
  "include_www": true,
  "additional_hostnames": ["app.example.com"],
  "scope_roots": ["example.com"],
  "ct_discovery": false
}
```

### 11.6 Example finding projection

This synthetic projection illustrates the required user-facing distinctions. The stored report also contains the referenced evidence, observations, versions, and coverage.

```json
{
  "target": "example.com",
  "findings": [
    {
      "subject": "www.example.com",
      "provider_id": "aws",
      "product_id": "aws.cloudfront",
      "category": "cdn",
      "relation": "web_delivery",
      "strength": "strong",
      "activity": "configured",
      "evidence_ids": ["fixture-cname-cloudfront"],
      "limitations": ["Does not identify the customer origin or contracting party."]
    },
    {
      "subject": "example.com",
      "provider_id": "cloudflare",
      "product_id": "cloudflare.dns",
      "category": "dns",
      "relation": "authoritative_dns",
      "strength": "strong",
      "activity": "configured",
      "evidence_ids": ["fixture-ns-cloudflare"],
      "limitations": ["Does not imply that the website uses Cloudflare proxying."]
    },
    {
      "subject": "example.com",
      "provider_id": "google",
      "product_id": null,
      "category": "verification",
      "relation": "domain_verification",
      "strength": "weak",
      "activity": "verification_only",
      "evidence_ids": ["fixture-txt-google"],
      "limitations": ["Does not establish Google Workspace use."]
    }
  ]
}
```

## 12. Persistence, jobs, and history

### 12.1 PostgreSQL responsibilities

Persist these logical tables with migrations and foreign keys:

| Table | Purpose |
| --- | --- |
| `jobs` | Batch request, caller identity, options, optional durable pinned-bundle reference, status, idempotency key, timestamps. |
| `job_targets` | Input order, normalized target, per-target state, attempts, lease owner/expiry, report ID. |
| `reports` | Immutable result envelope, original/reclassified relationship, bundle/build IDs, coverage. |
| `observations` | Sanitized typed observation payloads, hashes, collection time, report linkage. |
| `evidence` | Detector/rule interpretation, classification time, supporting observation references, and retained dataset-record provenance. |
| `findings` | Canonical provider/product relationship and searchable fields. |
| `finding_evidence` | Many-to-many finding/evidence links. |
| `dataset_bundles` | Manifest metadata and activation/audit history. |
| `ct_names` and `ct_checkpoints` | Optional local CT index and collector progress. |

Use typed indexed columns for target, provider/product ID, relation, strength, and time. JSONB may retain evolving typed payloads, but must not replace all useful relational indexes. Do not query PostgreSQL for each cloud-prefix match.

Store final reports and their evidence/observations atomically. A report must not point at evidence that failed to persist. Treat stored reports as immutable; reclassification creates a new one.

### 12.2 Durable job execution

Use PostgreSQL row locking and bounded worker leases to claim work. `FOR UPDATE SKIP LOCKED` is suitable for avoiding blocked consumers in a queue-like table; it is not a general consistency mechanism for reporting queries. [S18]

A claim transaction ends before any DNS or HTTP request begins. Renew leases while processing. Persist an attempt/generation token and require it when committing a terminal result so an expired worker cannot overwrite a newer attempt. Recover abandoned work after lease expiry with a bounded retry count.

Accepted batch jobs are durable. Whole-target execution is at-least-once after crashes; network requests can repeat. Idempotent result commits prevent duplicate final reports for one attempt. Cancellation is best effort for already-started requests and prevents new ones.

States are `queued`, `running`, `completed`, `partial`, `failed`, and `cancelled`, with per-target equivalents. A job is complete only when every target is terminal. Persist counts by state rather than concealing failed rows.

For a pinned batch, persist the bundle ID and durable pruning protection before returning acceptance. Admission must validate availability, integrity, and detector/schema compatibility while holding the same store-level coordination used by pruning, and keep that protection until the job and reference commit. Pruning acquires the same coordination, checks durable job references, and deletes only unreferenced eligible bundles. Use a consistent lock order. A crash must leave either a committed protected job or no accepted job; a temporary protective reservation may be reclaimed only after proving no committed job references it. If the reference store cannot be checked, pruning must fail closed.

Return HTTP 503 and CLI exit 4 with `bundle_unavailable` or `bundle_incompatible` when the requested pin cannot be honored. Do not insert the job or silently choose another bundle. Preserve protection through queue waits, lease expiry, retries, and process restarts. Release it only after the transaction that makes every target terminal. A cancellation request alone does not release the pin; cancellation must reach terminal target states. Completed or cancelled batches may release their pins, but active-view, in-flight-reader, and last-known-good protections still apply. Restore durable references before enabling pruning after restart.

### 12.3 History and retention

Keep observations and findings for 30 days by default, configurable by the operator. Retain observations and consulted dataset-record provenance while referenced by any retained report, including reclassification reports. Keep the bundle manifests needed to interpret retained reports even after a large old index is pruned. Preserve the active bundle, at least two last-known-good bundles, in-flight readers' bundles, and every durable batch pin whose targets are not all terminal.

Raw HTTP captures are disabled by default. When enabled, store them in restricted artifact storage, protect them at rest, and expire them after 24 hours by default. Do not place arbitrary response bodies or secrets in general-purpose logs.

A history diff may say a previously observed finding was not observed in a later comparable complete run. It must not label a product “removed” after an HTTP timeout, CT index outage, rule removal, or incomplete DNS collection. Record whether a change came from new observations, new rules, or new upstream data.

## 13. Immutable bundles and update lifecycle

### 13.1 Bundle contents

The full reference bundle contains normalized provider and service associations, ASN intervals, CDN metadata, product taxonomy, rule definitions, source manifests, validation reports, and artifact hashes. Every bundle declares its source/capability inventory, compatible detector builds, and schema versions. BART tables are reconstructed from canonical records rather than serialized through private library memory layouts.

The immutable execution view also records which sources and detectors are usable, disabled, missing, incompatible, or beyond their configured hard age limits. Load available validated components without treating an absent component as an empty successful source. A valid policy/schema view may support collection with enrichment components unavailable. If no valid execution view can be constructed, the operation is unavailable. Do not partially activate a malformed update or mix records from failed and successful revisions of one source; retain the last-known-good view on update failure.

Canonical bundle identity includes content hashes, selected upstream revisions, adapter versions, provider selection, rule/taxonomy versions, and required detector identity. Fetch/build timestamps are receipts, not inputs that create a different identity for identical content.

Record the `wappalyzergo` engine and embedded fingerprint digest in the detector-build identity. Reject a bundle requiring an incompatible engine. CT indexing has its own checkpoint; record the exact candidate-set identity used by a report.

### 13.2 Update transaction

1. Fetch into a private staging area, or ingest explicitly supplied local files.
2. Parse and normalize every required source. Never silently combine old and new records within one source snapshot.
3. Validate structure, lifecycle, cross-references, data roles, counts, and rule tests.
4. Compare against the active bundle. Quarantine unexplained provider removals or extreme coverage changes for review.
5. Build all indexes and execute smoke checks, including overlap/retirement cases.
6. Write canonical artifacts, checksums, and a manifest. Sync and rename on the same filesystem.
7. Activate a complete compatible `AttributionView` through an atomic pointer swap. Persist activation history separately.
8. Leave old views alive while in-flight jobs reference them. Keep on-disk bundles protected by durable batch pins, including queued targets and pending retries. Reclaim only after all applicable protections are released.

The separate updater atomically writes a durable `current.json` pointer naming the desired bundle. A service-side loader watches or polls that pointer, builds and verifies the replacement view off the request path, and only then swaps the in-memory view. Publication and successful activation are different states: expose both the desired ID and the actually loaded ID. Preserve a durable last-known-good reference compatible with the detector build for restart recovery. A failed reload keeps the currently loaded view. Do not require a target request to trigger loading.

Use a single-writer lock for the snapshot store. Revalidate approvals against the active baseline at activation. An invalid candidate cannot be forced into service. A review-required candidate needs an explicit operator approval bound to its content hash.

Coordinate bundle pruning with pinned-batch admission under section 12.2. Publication of a newer bundle never invalidates an accepted pin. After terminal completion or cancellation, pruning may remove the formerly pinned bundle only if no other retention protection applies.

On update failure, retain the active bundle and report the failure. Startup loads the last-known-good local bundle without downloading data. Rollback reactivates a validated compatible older bundle. Avoid a startup dependency on the upstream repository being available.

### 13.3 Defaults for update scheduling

The reference operations configuration checks cloud ranges and ASN files daily with jitter. Check locally mirrored rule/CDN data daily, but require rule tests and review policy before activation. Fingerprint-engine updates use a reviewed build/release path when the data is embedded.

A scheduler invokes updater commands. The worker never downloads datasets on a target request. Sources can be disabled explicitly. If a requested source is unavailable or disabled by the operator, expose that capability as unavailable and apply section 14.2. Do not claim full coverage or redefine the delivery requirements. Capabilities intentionally excluded by the request's mode or options are `skipped`.

## 14. Bounds, failure behavior, and observability

### 14.1 Initial configurable bounds

These values are design defaults to validate, not measured throughput claims.

| Limit | Default |
| --- | --- |
| Target-job wall-clock deadline | 60 seconds from execution start, excluding queue wait |
| DNS query timeout | 3 seconds per attempt; at most 2 attempts |
| CNAME chain depth | 16 links |
| DNS questions per target job | 512, including retries and dependency resolution |
| HTTP request timeout | 10 seconds within the target deadline |
| Redirect count | 5 per seed |
| HTTP response headers | 64 KiB |
| Decoded response body | 2 MiB per document; read at most one extra byte to detect truncation |
| Cumulative decoded HTTP body bytes per target job | 16 MiB |
| HTTP requests per target job | 64, including redirects and fallback |
| Seed hostnames per target job | 32 total, including at most 20 CT-derived names |
| Resolved IP addresses per target job | 128 |
| Concurrent target jobs per service | 32 |
| Concurrent HTTP requests per target / service | 4 / 32 |
| Concurrent DNS questions per target / service | 8 / 128 |
| Maximum API request body | 1 MiB |
| Target rows in one API batch | 1,000 |
| Total accepted nonterminal target reservations across jobs | 10,000, including running targets and pending retries |
| Prefix associations returned per IP | 1,024 |

Apply an operator-configurable per-destination request rate limit, including across different target jobs. Budget exhaustion produces explicit omitted counts and partial coverage. Do not create an unbounded goroutine for every hostname, record, or prefix.

Bound decompressed content, not merely `Content-Length`. Enforce network and parsing deadlines. Bounded input and worker pools are still required where a detector API has no cancellable inner loop.

### 14.2 Result status

`complete` means the requested supported capabilities finished within the stated coverage. It does not mean that all real-world infrastructure was discovered.

`partial` means at least one requested capability could not complete, but useful observations or supported classification results remain. `failed` means an admitted target's collection produced no useful analysis. `cancelled` is explicit. Optional capabilities deliberately excluded by the request are `skipped`, not failures. A missing necessary execution capability is an explicit operation error, not a successful empty report.

Useful results do not require a positive finding. A completed DNS negative answer, a collected HTTP error response, or a completed search of a usable source can establish useful scoped evidence. A failed DNS query alone or an unsearched source cannot establish absence. For `ip`, a completed search of remaining sources with zero associations and other requested sources unavailable is partial, not a successful complete no-match.

The following table is normative for execution admission, readiness, and synchronous results. All modes need valid input, the applicable policy/schema configuration, and a compatible execution view. A compatible view may contain unavailable enrichment components. Full/dns CLI execution and local IP lookup do not require PostgreSQL. Service operations that promise report persistence or durable work also require writable storage.

| Mode or condition | Admission and necessary execution capabilities | Missing capabilities that allow partial results | Operation readiness | Report / error | HTTP result | CLI exit |
| --- | --- | --- | --- | --- | --- | --- |
| `full` | Admit when at least one applicable collection path can run safely. Hostname HTTP requires the configured resolver and address policy; literal-IP URL HTTP still requires address policy. | DNS or HTTP collection, a requested detector, ASN, CDN, any provider/service feed, or requested CT may be unavailable if another path produces useful observations/results. | `ready` with full capability availability; `degraded` when a useful path remains. | `complete` if requested coverage completes; otherwise `partial` with retained evidence and affected coverage. | 200 | 0 / 3 |
| `dns` | Admit when the configured DNS collector/resolver and policy can execute. | ASN, CDN, any provider/service feed, or requested DNS detector/CT may be unavailable; preserve collected DNS evidence. | `ready` or `degraded`. | `complete` / `partial` | 200 | 0 / 3 |
| `ip` | Admit when at least one requested lookup source applicable to the address family is usable. | Missing ASN, CDN, provider or service feeds; return all available associations and explicit missing-source coverage, including when the available searches find none. | `ready` or `degraded`. | `complete` / `partial`; complete no-match only after all requested applicable sources were searched. | 200 | 0 / 3 |
| `reclassify` | Admit with retained inputs, a compatible selected bundle, and at least one usable requested replay path. | Missing sources, detector incompatibility within an otherwise compatible view, or missing raw capture may leave other replay paths usable. | `ready` or `degraded`; evaluate input-specific replay availability at admission. | New `complete` / `partial` report; preserve original collection coverage and mark `unavailable_for_replay` separately. | 200 synchronously | 0 / 3 |
| Any mode with no necessary execution path | Reject admission, or return the error if the capability is lost before execution can proceed. Examples: no usable applicable IP source; no DNS execution path in `dns`; no requested replay path; invalid/unavailable execution view. | None sufficient to execute the requested operation. | `unavailable` for that operation. | `capability_unavailable`; never no-match. | 503 | 4 |
| Requested pinned bundle unavailable/incompatible | Reject before accepting or inserting the batch. | No fallback bundle. | That pin is unavailable; other operations may remain ready. | `bundle_unavailable` / `bundle_incompatible` | 503 | 4 |
| Invalid request | Reject malformed syntax, target/options, or oversized input. | Not a partial result. | Unchanged. | Explicit validation error. | 400 / 422 / 413 | 2 |
| Queue admission limit | Reject the whole new submission before insertion. | No partial insertion. | Execution capabilities remain usable; admission is saturated. | `queue_capacity_exceeded` | 429 | 2 |
| Persistence unavailable or commit fails | Reject durable admission or return an explicit storage error; do not claim a stored result or accepted job. | Standalone CLI and local-IP operations remain independent of storage. | Persistence-dependent operations `unavailable`. | `persistence_unavailable` / `persistence_failed` | 503 | 4 |
| Admitted collection fails with no useful observations | Retain actual query/request failure coverage. This is distinct from a missing execution capability. | No useful result remains. | A target failure alone does not change service readiness. | `failed` | 200 with terminal report if persisted as required | 3 |

For reclassification, `complete` means every requested replay path completed. It does not upgrade an originally partial collection to complete collection coverage. For durable jobs, successful admission returns 202; polling a persisted job returns 200 and exposes each target's report or explicit error code, including unavailable-capability and persistence failures. Those envelope statuses do not turn a failed target into a successful result. The result-creation route in section 11.3 enqueues reclassification and therefore follows this asynchronous contract.

Report readiness per enabled operation as `ready`, `degraded`, or `unavailable`, with capability-level reasons and source age. `/readyz` returns 200 when at least one enabled public operation can execute and 503 when none can. Its overall state is `ready` only when all enabled operations have full capability availability; otherwise it is `degraded` while any remain executable. Thus PostgreSQL failure can disable durable analysis and jobs while local-IP lookup remains available. Configured deployment checks may require a particular operation's readiness. `/livez` reports process liveness independently. Request-specific invalid inputs, unavailable pins, and missing replay captures do not by themselves mark unrelated operations unavailable.

### 14.3 Metrics and logs

Expose request/job counts and latency, queue depth, active workers, DNS outcomes, HTTP outcomes, detector outcomes, findings by broad category, current bundle ID via an info metric, source freshness, last update status, and update validation failures.

Do not use domain names, IPs, arbitrary URLs, rule values, or report IDs as metric labels. Structured logs carry request/attempt IDs, capability, error class, and duration. Sensitive target logging is opt-in and redacted.

Health uses section 14.2's operation states and capability reasons. Expose reserved backlog capacity, admission rejections, durable bundle-pin counts, and CT ingestion lag alongside the existing metrics. PostgreSQL failure blocks durable job acceptance while usable local lookup can remain available; source degradation must be visible without hiding useful operations.

## 15. Testing, evaluation, and deployment

### 15.1 Required validation layers

Use local authoritative DNS fixtures, a recursive-resolver fixture, controlled HTTP/TLS servers, sanitized captures, and pinned miniature upstream datasets. Routine tests must not depend on live third-party websites.

Prefix matching must pass a brute-force oracle for IPv4, IPv6, nested ranges, duplicate prefixes, multiple providers, retired children, mapped addresses, boundary addresses, and no-match cases.

DNS tests must cover chain preservation, loops, delegation, null MX, TXT chunk boundaries, negative caching, timeouts, UDP truncation/TCP fallback, and malformed records. HTTP tests must cover redirects, changed DNS answers, per-address validation, TLS validation, body limits, slow responses, and cancellation. A controlled mixed-answer fixture must prove that the approved public address is dialed with correct Host/SNI and prohibited addresses are never dialed. Use explicit synchronization to prove HTTP starts before a delayed AAAA query finishes. Test private AAAA and AAAA timeout variants, including redirect destinations, and assert blocked-address and incomplete-query coverage while useful HTTP evidence survives. Fixture dialing must remain controlled by the test-only policy. Null MX semantics follow RFC 7505. [S19]

Rules require positive, negative, and misleading lookalike fixtures. Integration tests must cover a combined CDN + authoritative-DNS + mail-routing + SaaS-script report. Assertions must verify the absence of unsupported conclusions, not merely the presence of expected labels.

Before completing all adapters, pass the E1 early integrated fixture milestone defined in the implementation plan: one controlled domain through DNS, bounded HTTP, local classification, and a schema-valid evidence-backed report. Use small pinned datasets and real collection/detection code for the selected path. Include a missing-source variant and an approved-public-address plus delayed/blocked-AAAA variant. This milestone validates the shared model early and does not reduce final delivery scope.

Run tests that deny all external network access during application startup, local IP lookup, reclassification, and classifier execution. Live-mode tests allow only the configured local test services. Instrument DNS/dial attempts so unintended calls cannot hide behind a failed connection.

Use race tests and concurrent activation tests. A report must use one bundle even while other requests use a newly activated bundle. Test corrupted artifacts, process restart, failed update, database outage, expired leases, late attempt commits, and rollback.

Test pinned batches queued across multiple activations, process restart recovery, expired leases and pending retries, concurrent admission/pruning, and rejection of unavailable/incompatible pins. After completion or terminal cancellation, verify pruning becomes eligible only when no other protections remain. A cancellation request with nonterminal targets must preserve the pin. Simulate an unavailable reference store and require pruning to stop.

Exercise every section 14.2 decision-table row through applicable CLI/API paths. Remove ASN, CDN, and individual provider feeds independently and together; retain available evidence and partial coverage. Test an IP lookup with zero matches in surviving sources separately from one with no usable sources. Test partially replayable reports, changed dataset ownership with preserved collection times, and wholly unavailable replay. Verify explicit persistence errors, operation-level health, concurrent backlog admission, idempotent retries at capacity, and retry reservations after restart.

CT tests must pair valid signed checkpoints with altered entry bytes and require entry-inclusion verification to fail. Check `not_performed` states, initial-checkpoint continuity handling, and prevention of verified-checkpoint advancement after a failed check. Access tests must demonstrate shared operator visibility/cancellation, caller-scoped idempotency, and rejection of spoofed identity headers.

### 15.2 Accuracy and performance evaluation

Maintain a labeled, consented or synthetic corpus with separate metrics for provider, product, and relationship detection. Report precision and recall on that corpus only, including unresolved/unsupported cases and per-signal error categories. Do not publish an overall “80–90% coverage” estimate without evidence.

Section 8.5's per-product and per-relationship fixtures are the minimum deterministic acceptance criteria. Publish unsupported cases with signal-specific reasons. A provider-only result cannot pass a fixture whose supported signal establishes a product. Accuracy measurements describe evidence attribution, not lead quality or estimated commercial value.

Benchmark local lookup, dataset build, memory, and end-to-end controlled collection separately. Record hardware, Go/library versions, artifact sizes, input distribution, concurrency, p50/p95/p99 latency, allocations, and peak memory. Live Internet latency is not a stable classifier benchmark.

Initial engineering targets are a sub-millisecond p95 local combined network lookup on a documented reference machine, no additional collection request per detector, and successful bounded processing under the configured worker limits. These are targets to measure and revise, not claimed results.

### 15.3 Reference deployment

Supply a Docker Compose deployment with the Go service, PostgreSQL, Unbound, and persistent volumes for reports and bundles. Supply an alternative systemd-style deployment guide for operators who do not use containers. A timer or cron invokes updater commands.

Run the application unprivileged. Bind the API to loopback by default. Require operator-controlled authentication or a trusted authenticated reverse proxy before exposing it beyond loopback. Apply the shared trusted-operator identity and access contract in section 11.4. This local authentication is not a proprietary enrichment API key.

Separate updater egress from collection-worker egress where practical. The worker does not need access to GitHub, public dataset servers, commercial enrichment domains, or arbitrary outbound ports. Document backup/restore of PostgreSQL and bundle manifests, disk-full behavior, graceful shutdown, and rollback.

Pin build dependencies, container images, and source revisions. Produce a dependency/data notice inventory and a software bill of materials. Review fingerprint-data and upstream-source terms separately from a Go library's code license. Public availability is not proof of unrestricted redistribution.

## 16. Complete-system acceptance gate

The project is complete only when all required capabilities in section 1 work together and have the evidence in the implementation plan. In particular:

1. A domain request collects DNS and HTTP once, runs local web fingerprints, enriches addresses with cloud/service/CDN/ASN data, and returns normalized product and infrastructure findings with provenance.
2. A fixture using different vendors for DNS, CDN, mail, and web integrations produces those separate relationships without collapsing them into a single hosting vendor.
3. Service/region adapters work, and unsupported service specificity remains unknown. Cloud-range matching alone cannot claim a commercial customer relationship.
4. TXT-only verification, external redirects, retired prefixes, generic cloud ASNs, and historical CT names cannot produce unsupported active-product claims.
5. Full analysis, DNS-only analysis, local IP lookup, batch jobs, stored report retrieval, and offline reclassification are implemented.
6. Optional CT import/collection/discovery is usable when configured, reports its limits, and makes no proprietary search calls. The ordinary full pipeline works with CT disabled.
7. Updates, rollback, restart, persistence, resource bounds, and dependency network audits pass their tests.
8. CLI documentation, API schemas, deployment files, operations guides, rule coverage, and measured benchmark/accuracy reports are delivered.
9. The product-and-relationship matrix passes with documented unsupported signals. Evidence supports downstream lead enrichment without producing qualification, spend, or savings estimates.
10. Per-address collection and every degraded-operation decision-table case pass, including partial IP lookup and replay. Unavailable data never becomes a successful no-match.
11. Pinned batches survive queue waits, activations, retries, and restart; admission/pruning races cannot lose an accepted bundle. Backlog admission is bounded and shared operator identity is enforced.
12. CT verification distinguishes checkpoint signatures, continuity, and entry inclusion. The shipping collector has measured throughput, bandwidth, storage, and lag under documented budgets.

A working BART index, dataset importer, or IP API alone does not satisfy this specification.

## 17. Sources and verification notes

The sources below support external library behavior, data formats, and protocol semantics. Architecture choices and default limits above are design decisions. Documentation was checked on 2026-09-20. Repository default branches may change; implementation must pin exact revisions and validate complete datasets before claiming compatibility.

- **S01:** [Cloud IP Ranges repository and data notes](https://github.com/disposable/cloud-ip-ranges). Provider metadata, consolidated exports, miscellaneous-provider separation, and retired-range retention.
- **S02:** [Inspected A2Hosting provider document at a fixed revision](https://github.com/disposable/cloud-ip-ranges/blob/0c4c204e650a47a6f57d3709893a9dc96f942ed9/json/a2hosting.json). Example of lifecycle details accompanying base arrays. This is evidence of one shape, not a complete schema audit.
- **S03:** [BART package documentation](https://pkg.go.dev/github.com/gaissmai/bart). Prefix operations and covering-prefix iteration.
- **S04:** [Wappalyzergo README](https://github.com/projectdiscovery/wappalyzergo). Header/body fingerprinting and separate runtime-detection behavior.
- **S05:** [cdncheck runtime source](https://github.com/projectdiscovery/cdncheck/blob/main/cdncheck.go). Resolver defaults, initialization behavior, and local check methods. Inspected file blob: `2c8e268bc24ade402afbe7eceef88517ffda3812`.
- **S06:** [cdncheck suffix and technology-mapping source](https://github.com/projectdiscovery/cdncheck/blob/main/other.go). Inspected file blob: `946954e2d6bf2807629af9bb2f3852de8c39499f`.
- **S07:** [IPtoASN downloadable data](https://iptoasn.com/). IPv4/IPv6 interval TSV schema and stated data license.
- **S08:** [Go net package](https://pkg.go.dev/net). Standard DNS/resolver interfaces.
- **S09:** [miekg/dns repository](https://github.com/miekg/dns). Raw DNS library and project-maintenance notice.
- **S10:** [Go HTTP transport documentation](https://pkg.go.dev/net/http#Transport). Dialing, proxy, header, and connection controls.
- **S11:** [AWS range JSON syntax and overlap notes](https://docs.aws.amazon.com/vpc/latest/userguide/aws-ip-syntax.html).
- **S12:** [AWS IP range considerations](https://docs.aws.amazon.com/vpc/latest/userguide/aws-ip-ranges.html). Incomplete service coverage and BYOIP exclusions.
- **S13:** [Google range-file distinctions](https://docs.cloud.google.com/vpc/docs/configure-private-google-access#ip-addr-defaults). Google-owned ranges versus customer Google Cloud ranges.
- **S14:** [Azure service tag overview](https://learn.microsoft.com/en-us/azure/virtual-network/service-tags-overview). Service/region and direction-specific meanings.
- **S15:** [CloudFront alternate domain names](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/CNAMEs.html). Distribution domains and CNAME relationships.
- **S16:** [RFC 6962](https://datatracker.ietf.org/doc/html/rfc6962). Supported CT log protocol foundation.
- **S17:** [Certificate Transparency Go](https://github.com/google/certificate-transparency-go). Candidate open-source CT client implementation.
- **S18:** [PostgreSQL SELECT documentation](https://www.postgresql.org/docs/current/sql-select.html). Row locking and `SKIP LOCKED` semantics.
- **S19:** [RFC 7505](https://datatracker.ietf.org/doc/html/rfc7505). Null MX semantics.
