# cloudattrib

`cloudattrib` is a self-hosted Go application for collecting public evidence about cloud infrastructure and SaaS products associated with a domain, hostname, URL, or IP address.

The behavior and delivery boundaries live in [SPEC.md](SPEC.md). The staged repository structure and implementation gates live in [IMPLEMENTATION-PLAN.md](IMPLEMENTATION-PLAN.md).

## Development

Install Go 1.25 or later and Make. Run the full local check with:

```sh
make check
```

Useful individual targets are `make build`, `make test`, `make race`, `make lint`, and `make fmt`.

The executable is written to `bin/cloudattrib`. The current command is only a buildable entry point; feature work follows the implementation plan.

## Agent skills

Go development guidance lives in `.agents/skills`. Run `make skills-check` to verify the package inventory and recorded content hashes.
