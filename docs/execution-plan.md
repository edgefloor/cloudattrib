# Development workflow

[SPEC.md](../SPEC.md) defines behavior. [IMPLEMENTATION-PLAN.md](../IMPLEMENTATION-PLAN.md) lists the acceptance work. [AGENTS.md](../AGENTS.md) contains the repository rules.

Use the [qualification report](qualification.md) to see which checks have run and which combinations remain untested.

## Before editing

Record the starting revision and inspect the working tree. Preserve unrelated changes.

Read the specification sections, package documentation, and tests for the behavior you will change. Settle shared interfaces before splitting work across packages.

For concurrent work, give each worker:

- owned files or packages;
- the contract revision;
- acceptance cases;
- focused test commands;
- the expected handoff.

Use separate worktrees when concurrent tasks produce commits. Never share a Git index between writers.

## Integration order

The original implementation used this order:

| Stage | Work |
| --- | --- |
| Contracts | Models, errors, scope, policy, schemas, and package boundaries |
| First fixture | One controlled domain through DNS, HTTP, classification, and CLI output |
| Data and collection | Importers, indexes, bundles, DNS, HTTP, TLS, and destination policy |
| Classification | Rules, aggregation, reports, and CLI commands |
| Service | PostgreSQL, jobs, API routes, access, cancellation, and bundle pins |
| Certificate Transparency | Import, bounded collection, verification, and local discovery |
| Release | Operations, deployment, qualification, and requirement traceability |

Keep that dependency order for later changes. A storage or API change may start early only after its application contract is stable.

## Contracts that cross packages

| Contract | Rule | SPEC sections |
| --- | --- | --- |
| Destination safety | Validate each address. Dial the approved address with the original Host and SNI. Apply the same checks to redirects. | 3.4, 4.2, 5.2 |
| Missing sources | Keep usable results and mark missing work as partial. Return `capability_unavailable` when no requested path can run. | 7.4, 14.2 |
| Bundle pins | Persist a pin with job admission. Keep it through queueing, retries, restart, and terminal completion. | 3.4, 12.2, 13.2 |
| Reclassification | Reuse retained observations with a selected bundle. Keep collection and classification times separate. | 9.1–9.5, 12.3 |
| CT verification | Record checkpoint signature, continuity, and entry inclusion separately. | 10.1 |
| Access | Authenticated operators share results and cancellation. Caller identity scopes idempotency. | 11.3–11.4, 12.2 |
| Rule coverage | Use the relationship supported by the signal. Product-specific signals must produce product-specific fixtures. | 8.5, 9.1 |

Keep changes to these contracts with the integrator. A package task should stop and report a conflict before changing behavior owned by another package.

## Validate changes

Run focused tests while editing:

```sh
go test ./path/to/package -run TestName
go test ./path/to/package
```

Run the full repository check after integration:

```sh
make check
```

`make check` runs formatting, vet, tests, GolangCI-Lint, the SBOM check, race tests, and the build. PostgreSQL integration tests also need `CLOUDATTRIB_POSTGRES_TEST_DSN`.

Run the mandatory PostgreSQL lifecycle and contention suite separately:

```sh
CLOUDATTRIB_POSTGRES_TEST_DSN='postgres://...' make test-postgres
```

The command fails if `CLOUDATTRIB_POSTGRES_TEST_DSN` is unset. Ordinary `go test` runs keep the optional skip for local development without PostgreSQL.

For lifecycle, synchronization, cancellation, or worker changes, run the focused race tests before the full check. For documentation-only changes, validate links, examples, and referenced paths.

Record the commands and results. Name any skipped integration test or untested platform.

## Finish the task

A completed change has:

- the requested behavior;
- tests for the changed behavior and its failure path;
- updated schemas or documentation when the interface changed;
- no unrelated cleanup;
- a clean focused test run;
- the applicable repository checks.

Publishing, pushing, and deployment require separate authorization.
