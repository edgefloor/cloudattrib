# Go repository rules

## Read the repository context

- Before a change, read `README.md`, `SPEC.md`, relevant `docs/` pages, and applicable
  design records. Do not create replacements for missing documents.
- Follow the conventions in the module definition, build files, CI configuration,
  and nearby tests.
- Apply any more specific `AGENTS.md` within the files' directory tree.
- Prefer existing package boundaries, names, error contracts, and test patterns
  over new conventions.
- Treat documentation as design intent. Use code and tests to establish actual behavior.

## Keep changes scoped

- Make the smallest change that meets the request and its acceptance cases.
- Reproduce a reported bug before fixing it. Use the cheapest useful check. A clear
  static violation is sufficient when a runtime reproduction is unsafe or expensive.
- Do not refactor shared code for one caller unless a narrow fix is unsafe or the
  shared defect is confirmed.
- Extend a fix to another package or platform only after confirming the same defect there.
- Preserve behavior outside the affected path unless the contract changes.
- Keep unrelated cleanup out of the change.

## Design packages

- Give each package one clear responsibility.
- Keep `cmd/<name>` thin. Put reusable behavior in importable packages.
- Put module-private code under `internal/`. A `pkg/` directory requires a real
  external consumer.
- Avoid import cycles, catch-all utilities, and vague package names such as `common`,
  `shared`, or `helpers`.
- Prefer concrete types. Define interfaces at consumer boundaries when callers need
  multiple implementations or a test seam.
- Keep interfaces small. Constructors return concrete types unless substitution is
  part of the API.
- Preserve useful zero values where practical. Constructors enforce required
  invariants and establish resource ownership.

## Write Go code

- Run `gofmt` on every changed Go file.
- Follow Go naming conventions. Keep initialisms consistent, receiver names short,
  and package names lowercase without underscores.
- Give request-scoped blocking work a `context.Context` as its first parameter.
  Store contexts in structs only when the API requires it.
- Honor cancellation and the caller's deadline. An internal timeout must not replace
  a shorter caller deadline.
- Add useful operation context to errors. Use `%w` when callers need `errors.Is` or
  `errors.As` to preserve error identity.
- Return expected runtime failures as errors. Do not panic for them in library or server code.
- Document ownership of slices, maps, byte buffers, channels, and closers. Copy mutable
  data when it crosses an ownership boundary.
- Keep cleanup near acquisition. Check cleanup errors when they can affect the result.
- Avoid mutable package-global state. Inject clocks, randomness, filesystems, and
  network boundaries where deterministic behavior requires them.
- Give every goroutine an owner, a cancellation path, and a completion condition.
- The goroutine that creates a channel normally closes it. No sender may outlive
  the channel owner.

## Test behavior

- Add corresponding tests for changed behavior.
- Prefer deterministic in-process tests. Use subprocesses for behavior that depends
  on process boundaries, such as CLI execution, signals, file locks, or environment inheritance.
- Use table-driven tests when cases share setup and assertions. Keep unrelated
  scenarios separate.
- Call `t.Helper()` in test helpers. Register resource cleanup with `t.Cleanup()`.
- Use `t.Parallel()` only when tests do not share mutable process state, ports,
  environment variables, or filesystem paths.
- Synchronize through observable state or explicit signals, not arbitrary sleeps.
- Assert public behavior and important failure paths. Avoid assertions tied to
  internals that harmless refactors would change.

Use repository commands when available. Without a wrapper, run focused tests during edits:

```sh
go test ./path/to/package -run TestName
go test ./path/to/package
```

Before completing a code change, run the applicable checks. Replace the example
path with the changed Go files:

```sh
gofmt -w path/to/changed.go
go test ./...
go vet ./...
go test -race ./...
```

The race suite is required for changes to goroutines, synchronization, shared state,
process lifecycle, or cancellation. Run `golangci-lint run` when the repository has a
GolangCI-Lint configuration. Prefer focused package tests during small edit cycles.

## Manage dependencies and generated files

- Prefer the standard library when it is clear and maintainable. Prefer an established
  dependency over a fragile replacement.
- Add a production dependency only when its benefit justifies its maintenance and
  security cost.
- Run `go mod tidy` when imports or module requirements change. Review changes to
  `go.mod` and `go.sum`.
- Change generated files through their source or generator, never by hand.
- Run `go generate` only for packages whose generated output is affected.

## Write comments and documentation

- Explain constraints, invariants, ownership, and non-obvious reasons. Do not narrate code.
- Document exported identifiers when the package exposes a public API or lint requires it.
- Update user documentation when flags, configuration, output, defaults, or public
  behavior changes.
- Keep examples executable where practical.

## Protect security boundaries

- Keep credentials and secret values out of source, command arguments, logs, fixtures,
  and reports.
- Validate filesystem paths, permissions, ownership, and symlink behavior at trust boundaries.
- Pass subprocess arguments as arrays. Do not assemble shell commands from untrusted input.
- Give network operations explicit timeouts or caller-controlled deadlines.
- Close response bodies, files, sockets, processes, and temporary resources on every path.
- A local implementation request does not authorize deployment, pushing, destructive
  cleanup, or changes to live services.

## Preserve the workspace

- Preserve unrelated user changes in a dirty checkout.
- Do not use destructive Git commands to remove work this change did not create.
- Limit formatting and mechanical rewrites to files involved in the task.
- Report the checks that ran and their results. Do not claim unrun checks or untested
  platforms as verified.
