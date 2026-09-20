# Internal packages

Keep implementation packages under `internal/` until an external Go consumer needs a stable public API. Shared domain types should stay independent of DNS, HTTP, database, and dataset-library types.

The package boundaries planned for this repository are documented in [IMPLEMENTATION-PLAN.md](../IMPLEMENTATION-PLAN.md). Add a package when its contract is ready instead of introducing broad utility packages.
