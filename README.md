# cloudattrib

`cloudattrib` is a self-hosted Go application for collecting public evidence about cloud infrastructure and SaaS products associated with a domain, hostname, URL, or IP address.

The behavior and delivery boundaries live in [SPEC.md](SPEC.md). The staged repository structure and implementation gates live in [IMPLEMENTATION-PLAN.md](IMPLEMENTATION-PLAN.md).

## Development

Install Go 1.25 or later and Make. Run the full local check with:

```sh
make check
```

Useful individual targets are `make build`, `make test`, `make race`, `make lint`, and `make fmt`.

The executable is written to `bin/cloudattrib`. Domain analysis uses the explicit resolver at
`127.0.0.1:53` by default. Set `CLOUDATTRIB_RESOLVER` to another `host:port` when the operator
has configured a different recursive resolver. Target HTTP connections use only concrete
addresses returned by that resolver and apply the public-destination policy.

```sh
cloudattrib analyze example.com --mode dns
cloudattrib analyze example.com
cloudattrib batch --input domains.txt --format jsonl
cloudattrib lookup-ip 198.51.100.7 --match all
cloudattrib reclassify --report report.json --bundle builtin-rules-v1
```

The built-in execution view supports DNS, bounded HTTP, reviewed product rules, passive web
fingerprints, and offline reinterpretation of a standalone report. Local prefix and ASN lookup
require an activated dataset bundle; without one, `lookup-ip` returns
`capability_unavailable` instead of an empty successful result. Reclassification preserves the
original observations and collection coverage while recording a new classification time and
bundle identity.

## Agent skills

Go development guidance lives in `.agents/skills`. Run `make skills-check` to verify the package inventory and recorded content hashes.
