# Third-party notices

This inventory lists the Go modules linked into `cloudattrib` and the reference deployment images. License texts remain with their source distributions. This inventory does not grant rights to redistribute imported data.

## Linked Go modules

| Component | Version | License or notice |
| --- | --- | --- |
| `github.com/gaissmai/bart` | v0.29.1 | MIT |
| `github.com/google/certificate-transparency-go` | v1.3.3 | Apache-2.0 |
| `github.com/jackc/pgx/v5`, `pgpassfile`, `pgservicefile`, `puddle/v2` | versions in `go.mod`/SBOM | MIT |
| `github.com/miekg/dns` | v1.1.73 | BSD-3-Clause |
| `github.com/projectdiscovery/wappalyzergo` | v0.3.2 | MIT code; embedded fingerprint-data provenance requires separate review |
| `github.com/transparency-dev/merkle` | v0.0.2 | Apache-2.0 |
| `go.yaml.in/yaml/v3` | v3.0.5 | MIT and Apache-2.0 dual notice |
| `golang.org/x/crypto`, `x/net`, `x/sync`, `x/sys`, `x/text` | versions in `go.mod`/SBOM | BSD-3-Clause style Go project terms |
| `google.golang.org/protobuf` | v1.36.11 | BSD-3-Clause |

For full license texts, use the exact module version in the Go module cache or source distribution. The [dependency audit](docs/dependency-audit.md) records reviewed network behavior and unresolved data rights.

## Reference deployment images

The [SBOM](sbom/cloudattrib.cdx.json) and [Compose file](compose.yaml) pin the Go, Alpine, PostgreSQL, and Unbound images. Each image contains packages with their own notices. Retain those notices and scan the exact image digest you deploy.

## Imported datasets

Production cloud ranges, ASN data, CDN data, and Certificate Transparency records are operator-supplied local inputs. They are not included in this repository. Public access to a file does not establish unrestricted redistribution rights. Before sharing a bundle, review its source terms and retain each artifact's provenance, revision, and digest.
