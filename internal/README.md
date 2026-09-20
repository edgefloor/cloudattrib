# Internal package map

`cmd/cloudattrib` loads configuration and connects the packages under `internal/`.

| Package | Responsibility |
| --- | --- |
| `app` | Domain analysis, local IP lookup, and reclassification. |
| `model` | Targets, observations, dataset references, evidence, findings, reports, and error contracts. |
| `target`, `policy` | Normalize input, bound scope, validate destinations, and track collection budgets. |
| `collect/dns`, `collect/http` | Collect DNS records and bounded HTTP responses with TLS metadata. |
| `detect/dnsrules`, `detect/webtech`, `rules` | Interpret DNS and HTTP signals with local rules and fingerprints. |
| `enrich/prefix`, `enrich/asn` | Query immutable prefix and ASN indexes. |
| `ingest` | Parse provider, service-range, CDN, and IPtoASN source formats. |
| `datasets` | Validate source data and manage immutable bundles, activation, and pruning. |
| `aggregate` | Group evidence into findings without merging incompatible relationships. |
| `jobs`, `store/postgres` | Admit durable work, manage attempts and pins, and store reports. |
| `ctlog` | Import CT records, collect bounded log increments, and query the local index. |
| `api`, `cli` | Expose application operations through HTTP and command-line interfaces. |
| `runtime`, `config` | Construct local and service runtimes from operator configuration. |
| `observability` | Expose operational metrics. |
| `dependency`, `qualification` | Test dependency boundaries and measured behavior. |

Keep library-specific types inside their adapters. Shared models must not expose BART tables, DNS-library records, fingerprint-engine types, or PostgreSQL types. Add a public package only when an external Go consumer needs one.

See [architecture](../docs/architecture.md) for cross-package contracts and [IMPLEMENTATION-PLAN.md](../IMPLEMENTATION-PLAN.md) for acceptance cases.
