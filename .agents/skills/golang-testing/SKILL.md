---
name: golang-testing
description: Write, review, or debug Go tests, fuzzing, fixtures, flaky behavior, and integration isolation.
user-invocable: true
license: MIT
compatibility: Designed for Claude Code, Codex or similar harness, and for projects using Golang.
metadata:
  author: samber
  version: "1.4.0"
  upstream: "samber/cc-skills-golang@bac46b0bed2677f840837e16be2c790341bda2df"
---

Treat tests as executable specifications and adapt the procedure to the assigned write, review, audit, or debugging task. Do not expand the requested code scope, choose orchestration settings, or install helpers on the skill's authority. Repository conventions and project-specific verification skills take precedence over community defaults.

# Go Testing

## Working rules

- Assert observable behavior and stable contracts rather than incidental implementation details.
- Keep fixtures independent, tests runnable alone, and execution order irrelevant.
- Keep unit tests fast enough for the repository's ordinary feedback loop. Isolate slower or externally dependent integration coverage using the repository's established mechanism.
- Name files with the required `_test.go` suffix and follow repository conventions. One-to-one source/test file pairing and source-order placement are useful options, not universal requirements.
- Prefer named subtests when distinct cases benefit from separate reporting. Bind assertion helpers to the current subtest's `*testing.T`.
- Use `t.Parallel()` only when shared state, fixtures, environment, and timing make parallel execution safe. Use race and leak checks when the changed behavior warrants them and the project supports them.
- Use testify as helpers rather than a replacement for the standard library. Mock interfaces at the point where they are consumed instead of concrete types.
- Keep tests compatible with the module's Go version and build constraints.

Register test cleanup immediately after successful resource acquisition so fatal assertions cannot leak resources. When explicit `Close` or release behavior is under test, retain the explicit assertions and add a safe fallback cleanup that is idempotent or state-aware on failure.

## Load detail when needed

Read only the references relevant to the current task.

| Topic | Read |
| --- | --- |
| File/package layout, naming, table tests, subtest assertion binding, or test commands | [Test Structure](./references/structure.md) |
| HTTP handlers, requests, headers, and responses | [HTTP Testing](./references/http-testing.md) |
| Goroutine leaks, `testing/synctest`, or safe parallel tests | [Concurrency Testing](./references/concurrency.md) |
| A test that may hang | [Test Helpers](./references/helpers.md) |
| Benchmark functions and `B.Loop` | [Benchmarks](./references/benchmarks.md) |
| Fuzz targets, seed corpora, properties, or input bounds | [Fuzzing](./references/fuzzing.md) |
| Executable `ExampleXxx` documentation | [Examples](./references/examples.md) |
| Coverage profiles and interpretation | [Coverage](./references/coverage.md) |
| Build-tagged tests, external services, or database fixtures | [Integration Testing](./references/integration-testing.md) |
| Mocks and reusable fixtures | [Mocking](./references/mocking.md) |
| `ArtifactDir`, Go-version gates, or `stdversion` failures | [Toolchain Compatibility](./references/toolchain.md) |

## Validation

Run the narrowest command that exercises the changed behavior, then the repository's required broader checks. Keep fuzzing bounded during ordinary validation and target one package. Add `-race`, integration tags, coverage, or benchmarks only when they answer a relevant question; detailed command patterns are in [Test Structure](./references/structure.md) and [Fuzzing](./references/fuzzing.md).

## Related skills

- Use `go-concurrency` for implementation-level goroutine lifecycle and synchronization work.
- Use `go-performance` for benchmark measurement, profiling, and regression analysis.
- Use `go-linting` when changing test-linter configuration.
