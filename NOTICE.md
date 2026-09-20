# Third-party notices

This inventory covers the modules linked into the `cloudattrib` executable and the reference deployment images. It is not legal advice, and it does not grant rights to redistribute imported datasets.

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

The authoritative license texts remain in each module version in the Go module cache or source distribution. `docs/dependency-audit.md` records the reviewed runtime behavior and unresolved data questions.

## Reference deployment images

The pinned Go, Alpine, PostgreSQL, and Unbound image identities are recorded in `sbom/cloudattrib.cdx.json` and `compose.yaml`. Each image contains packages under its own notices. Operators should retain the image filesystem notices and scan the exact digest they deploy.

## Imported datasets

`cloudattrib` does not ship production cloud ranges, ASN data, CDN data, or Certificate Transparency records. Operators import those artifacts locally. Public availability is not evidence of unrestricted redistribution. Review and preserve the terms, provenance, revision, and digest for each imported artifact before sharing a bundle.
