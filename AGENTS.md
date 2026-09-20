# Go repository rules

## Repository context

- Change work requires review of `README.md`, `SPEC.md`, relevant files under
  `docs/`, and applicable design records. Missing files do not require replacement.
- The module definition, build files, CI configuration, and tests next to affected
  code define the repository's current conventions.
- A more specific `AGENTS.md` applies to files in its directory tree.
- Existing package boundaries, names, error contracts, and test patterns take
  precedence over new local conventions.
- Documentation describes design intent. Current code and tests establish actual
  behavior.

## Change scope

- Changes must be the smallest changes that satisfy the request and its acceptance
  cases.
- A reported bug requires the cheapest useful reproduction before the fix. A clear
  static violation is sufficient when runtime reproduction is unsafe or expensive.
- Shared code must not be refactored for one caller unless the narrow fix is unsafe or
  the shared defect is confirmed.
- A fix may extend to another package or platform only after the same defect is
  confirmed there.
- Behavior outside the affected path must remain unchanged unless the contract changes.
- Unrelated cleanup does not belong in the same change.

## Package design

- Each package has one clear responsibility.
- `cmd/<name>` packages remain thin. Reusable behavior belongs in importable packages.
- Code private to the module belongs under `internal/`. A `pkg/` directory requires a
  real external consumer.
- Import cycles, catch-all utility packages, and vague packages named `common`,
  `shared`, or `helpers` are not permitted.
- Concrete types are preferred. Interfaces belong at consumer boundaries when callers
  need multiple implementations or a test seam.
- Interfaces remain small. Constructors return concrete types unless substitution is
  part of the API.
- Useful zero values remain valid when practical. Constructors enforce required
  invariants and establish ownership of resources.

## Go code

- Every changed Go file must pass `gofmt`.
- Names follow standard Go conventions. Initialisms remain consistent, receiver names
  stay short, and package names use lowercase letters without underscores.
- Request-scoped blocking work accepts `context.Context` as its first parameter.
  Contexts are not stored in structs unless the API requires it.
- Code honors cancellation and earlier caller deadlines. Internal timeouts must not
  replace a shorter caller deadline.
- Errors include useful operation context and use `%w` when callers need
  `errors.Is` or `errors.As` to preserve identity.
- Expected runtime errors return as errors. Library and server code does not use
  `panic` for them.
- APIs document ownership of slices, maps, byte buffers, channels, and closers. Mutable
  data is copied when ownership crosses a boundary.
- Cleanup stays near acquisition. Cleanup errors are checked when they can change the
  result.
- Package-global mutable state is avoided. Clocks, randomness, filesystems, and
  network boundaries are injected when deterministic behavior requires them.
- Every goroutine has a clear owner, cancellation path, and completion condition.
- The goroutine that creates a channel normally owns closing it. No sender may outlive
  the channel owner.

## Tests

- Changed behavior requires corresponding tests.
- Deterministic in-process tests are preferred. Subprocesses are reserved for behavior
  that depends on process boundaries, such as CLI execution, signals, file locks, or
  environment inheritance.
- Table-driven tests are used when cases share setup and assertions. Unrelated
  scenarios are not forced into one table.
- Test helpers call `t.Helper()`. Resources use `t.Cleanup()` for cleanup.
- `t.Parallel()` is limited to tests that do not share mutable process state, ports,
  environment variables, or filesystem paths.
- Tests use observable state or explicit synchronization instead of arbitrary sleeps.
- Tests cover public behavior and important failure paths. Assertions do not depend on
  internal details that make harmless refactors expensive.

Repository-provided commands take precedence. Without a wrapper, focused iteration
uses:

```sh
go test ./path/to/package -run TestName
go test ./path/to/package
```

Before a code change is complete, the applicable checks include:

```sh
gofmt -w <changed-go-files>
go test ./...
go vet ./...
go test -race ./...
```

The race suite is required for changes involving goroutines, synchronization, shared
state, process lifecycle, or cancellation. `golangci-lint run` is required when the
repository contains a GolangCI-Lint configuration. Focused package tests are preferred
over a slow full suite during small edit cycles.

## Dependencies and generated files

- The standard library is preferred when it is clear and maintainable. An established
  dependency is preferred over a fragile replacement.
- A production dependency requires a clear benefit that justifies its maintenance and
  security cost.
- `go mod tidy` runs when imports or module requirements change. Changes to `go.mod`
  and `go.sum` require review.
- Generated files are changed through their source or generator, never by hand.
- `go generate` runs only for packages whose generated output is affected.

## Comments and documentation

- Comments explain constraints, invariants, ownership, and non-obvious reasons. They
  do not narrate the code.
- Exported identifiers require doc comments when the package exposes a public API or
  repository lint requires them.
- User documentation is updated when flags, configuration, output, defaults, or public
  behavior changes.
- Examples remain executable when practical.

## Security and external effects

- Credentials and secret values must not appear in source, command arguments, logs,
  fixtures, or reports.
- Filesystem paths, permissions, ownership, and symlink behavior are validated at trust
  boundaries.
- Subprocesses use argument arrays. Shell commands must not be assembled from
  untrusted input.
- Network operations use explicit timeouts or caller-controlled deadlines.
- Response bodies, files, sockets, processes, and temporary resources are closed on
  every path.
- A local implementation request does not grant permission for deployment, pushing,
  destructive cleanup, or live service changes.

## Workspace preservation

- Unrelated user changes in a dirty checkout are preserved.
- Destructive Git commands must not remove work that the current change did not create.
- Formatting and mechanical rewrites are limited to files involved in the task.
- Completion reports name the checks that ran and their results. Unrun checks and
  untested platforms are not claimed as verified.
