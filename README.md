# cloudattrib

cloudattrib identifies cloud providers, SaaS services, and web technologies associated with a domain. It collects DNS records and website responses, then matches them against local rules and IP datasets. Each finding includes the relationship detected and references to the evidence that supports it.

Use it to inspect a domain's public infrastructure, process lists of domains, or look up IP addresses in local provider and ASN data. The CLI writes JSON. The HTTP API stores reports and runs durable batch jobs in PostgreSQL.

Attribution runs locally and requires no commercial enrichment API or API key. Domain analysis contacts your configured DNS resolver and the target's public website. IP lookup and reclassification of saved reports require no target requests.

## What it detects

Findings distinguish relationships that a single provider label would hide:

| Observed signal | Reported relationship |
| --- | --- |
| A CNAME pointing to a CloudFront distribution | CloudFront web delivery |
| Cloudflare authoritative nameservers | Cloudflare DNS |
| A supported Google MX record | Google-hosted mail routing |
| A supported SPF include | Authorization for a service to send mail |
| A supported verification TXT record | Domain verification with that service |
| A recognized website script or framework fingerprint | A web integration or technology |
| An IP address in a local provider dataset | A provider association, with service or region metadata when available |

Findings describe the public evidence. A CDN match does not reveal the origin server, and a verification record does not establish active use of a paid product. See the [rule coverage matrix](rules/coverage-matrix.md) for supported products, matching signals, and their limits.

## Run it

To build from source, install Go 1.25 or later, Git, and Make:

```sh
git clone https://github.com/edgefloor/cloudattrib.git
cd cloudattrib
make build
```

Domain analysis requires a reachable recursive DNS resolver. The default is `127.0.0.1:53`. If you already run a resolver there, analyze a domain with:

```sh
./bin/cloudattrib analyze example.com
```

To use another resolver, replace `192.168.1.1:53` with its address and port:

```sh
CLOUDATTRIB_RESOLVER=192.168.1.1:53 ./bin/cloudattrib analyze example.com
```

The standalone CLI works without PostgreSQL when Certificate Transparency discovery is disabled, as it is by default. Product rules and web fingerprints are included in the binary. Cloud, CDN, and ASN datasets are separate inputs. Without those datasets, domain analysis can still return findings, but IP enrichment is unavailable.

The command writes a report to standard output. Expect `status: "partial"` when useful results remain but a required data source or collection step is unavailable. Current full HTTPS analysis also reports unavailable TLS certificate evidence, even when the website request succeeds. A partial report exits with code `3`.

For a service installation with PostgreSQL and an Unbound resolver, follow the [Compose setup guide](docs/operations.md#compose-installation).

## Read a report

Reports contain collected observations, evidence from matching rules and datasets, findings, and coverage for each capability.

This illustrative excerpt shows a CloudFront finding for a hostname with a matching CNAME. It is not live output from `example.com`. Other report fields are omitted:

```json
{
	"target": {
		"canonical": "example.com"
	},
	"status": "partial",
	"findings": [
		{
			"subject": "www.example.com",
			"provider_id": "aws",
			"product_id": "aws.cloudfront",
			"relation": "web_delivery",
			"strength": "strong",
			"evidence_ids": ["illustrative-cname-evidence"]
		}
	],
	"coverage": [
		{
			"capability": "tls_certificate",
			"status": "unavailable",
			"reason": "TLS certificate evidence collection is unsupported"
		}
	]
}
```

Use `evidence_ids` to find the supporting entries in the full report's `evidence` array. `strength` describes the evidence supporting a finding, not a probability. Inspect `coverage` before interpreting an empty findings list. `complete` means the requested work completed within its reported coverage, not that every real-world service was discovered.

The CLI uses these exit codes:

| Code | Meaning |
| --- | --- |
| `0` | Requested results completed, including a completed search with no matches. |
| `2` | Invalid command, configuration, or input; an idempotency conflict; or a capacity rejection. |
| `3` | At least one accepted target returned a partial, failed, or cancelled report. |
| `4` | A required capability, bundle, startup step, or persistence operation was unavailable or failed. |

See the [report schema](schema/report.schema.json) for all fields and the [result-status contract](SPEC.md#142-result-status) for failure behavior.

## Common commands

Analyze DNS without fetching the website:

```sh
./bin/cloudattrib analyze example.com --mode dns
```

Analyze a URL. URLs containing a query string are rejected:

```sh
./bin/cloudattrib analyze https://example.com/ --kind url
```

Analyze a text file containing one target per line. JSONL output contains one result or error envelope per input, with its `input_index`:

```sh
./bin/cloudattrib batch --input domains.txt --format jsonl
```

After loading local IP data, look up an address. Replace this documentation address with the IP you want to inspect:

```sh
./bin/cloudattrib lookup-ip 198.51.100.7 --match all
```

Reclassify a saved report using the built-in rule bundle, without collecting new observations:

```sh
./bin/cloudattrib reclassify --report report.json --bundle builtin-rules-v1
```

Replay requires retained inputs that the selected bundle can classify. To use another compatible bundle, replace `builtin-rules-v1` with its ID.

## Local data and configuration

Place supported source files in `data/sources`, or set `data.source_directory` in your configuration. Sources include cloud provider ranges, official AWS, GCP, and Azure metadata, CDN data, and IP-to-ASN records. Production datasets are not included in the repository.

The standalone CLI loads these files when no active bundle is selected. The service supports versioned data bundles with activation and rollback. Missing sources are reported in coverage. IP lookup requires at least one usable local IP source.

Use the [source format reference](docs/source-contracts.md) to prepare files and the [bundle operations guide](docs/operations.md#import-and-activate-data) to import and activate them. These guides cover source revisions, retired ranges, and update procedures.

Set `CLOUDATTRIB_CONFIG` to a YAML or JSON configuration file. `CLOUDATTRIB_RESOLVER` overrides the resolver loaded through that environment variable. Start with the [example configuration](config/example.yaml). For service setup, authentication, and resource limits, see the [operations guide](docs/operations.md).

## Current limits

- HTTPS requests verify server certificates, but reports do not retain certificate evidence. Applicable reports mark `tls_certificate` as unavailable.
- Certificate Transparency discovery is experimental and disabled by default. It uses a local PostgreSQL index. Live log collection has not yet been tested against public CT logs. See [CT operations](docs/ct-operations.md).
- Collection does not execute JavaScript, authenticate to websites, or discover hidden origin servers. Results depend on public observations, supported rules, and the datasets you load.

The [qualification report](docs/qualification.md) records tested behavior, operating environments, and remaining release conditions.

## Documentation

| Topic | Reference |
| --- | --- |
| Install, operate, and update the service | [Operations guide](docs/operations.md) |
| Integrate with the HTTP API | [OpenAPI definition](schema/openapi.yaml) |
| Understand collection and classification | [Architecture](docs/architecture.md) |
| Inspect supported rules | [Rule coverage matrix](rules/coverage-matrix.md) |
| Review required behavior | [Specification](SPEC.md) |
| Review dependencies and data provenance | [Dependency audit](docs/dependency-audit.md) and [third-party notices](NOTICE.md) |

Historical network measurements from 2026-09-21 cover [discovery and DNS enrichment](docs/benchmarks/2026-09-21-company-api-measurements.json) and a [DNS-only versus full-analysis comparison](docs/benchmarks/2026-09-21-subdomain-full-measurements.json). They used crt.name for discovery and commit `a504ec0` for analysis. These single-run measurements do not establish current performance, detection accuracy, or built-in CT coverage.

## Contributing

Report bugs and propose changes through [GitHub issues](https://github.com/edgefloor/cloudattrib/issues). Include the command, configuration relevant to the problem, expected behavior, and actual result. Remove credentials and sensitive report data from examples.

Before submitting a pull request, run:

```sh
make check
```

This runs formatting checks, static analysis, tests, race detection, repository validation, and a build. PostgreSQL integration tests require a separate disposable database. Set `CLOUDATTRIB_POSTGRES_TEST_DSN` to its connection string, then run:

```sh
make test-postgres
```

CI runs both commands. Changes to attribution rules need positive fixtures and negative cases that check unsupported conclusions. Follow the [repository contribution rules](AGENTS.md).

## License

cloudattrib is licensed under the [MIT License](LICENSE). Third-party components and imported datasets have their own terms. See [NOTICE.md](NOTICE.md).
