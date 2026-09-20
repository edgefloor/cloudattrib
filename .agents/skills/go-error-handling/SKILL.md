---
name: go-error-handling
description: Design Go error contracts, wrapping, errors.Is/As, and propagation.
allowed-tools: Bash(bash:*)
---

# Go Error Handling

> Compatibility: `errors.Is`, `errors.As`, and `%w` wrapping require Go 1.13+; structured logging examples may use `log/slog` from Go 1.21+.

## Resource Routing

- `scripts/check-errors.sh` - Run when checking string-based error matching, bare error propagation, and log-and-return patterns.
- `scripts/check-errors-ast.go` - Implementation helper invoked by `check-errors.sh`; patch this when changing error-flow analysis behavior.
- `scripts/check-errors-baseline.py` - Compare findings for selected tracked Go files at a base and candidate commit without changing the scanner.
- `references/ERROR-FLOW.md` - Read when deciding where to handle, wrap, log, or return errors.
- `references/ERROR-TYPES.md` - Read when choosing sentinel errors, typed errors, or opaque errors.
- `references/WRAPPING.md` - Read when choosing `%w` versus `%v` or crossing package boundaries.

In Go, [errors are values](https://go.dev/blog/errors-are-values) — they are
created by code and consumed by code.

## Choosing an Error Strategy

1. System boundary (RPC, IPC, storage)? → Wrap with `%v` to avoid leaking internals
2. Caller needs to match specific conditions? → Sentinel or typed error, wrap with `%w`
3. Caller just needs debugging context? → `fmt.Errorf("...: %w", err)`
4. Leaf function, no wrapping needed? → Return the error directly

**Default**: wrap with `%w` and place it at the end of the format string.

---

## Core Rules

### Never Return Concrete Error Types

**Never return concrete error types from exported functions** — a concrete `nil`
pointer can become a non-nil interface:

```go
// Bad: Concrete type can cause subtle bugs
func Bad() *os.PathError { /*...*/ }

// Good: Always return the error interface
func Good() error { /*...*/ }
```

### Error Strings

Error strings should **not** be capitalized and should **not** end with
punctuation. Exception: exported names, proper nouns, or acronyms.

```go
// Bad
err := fmt.Errorf("Something bad happened.")

// Good
err := fmt.Errorf("something bad happened")
```

For displayed messages (logs, test failures, API responses), capitalization is
appropriate.

### Return Values on Error

When a function returns an error, callers must treat all non-error return values
as unspecified unless explicitly documented.

**Tip**: Functions taking a `context.Context` should usually return an `error`
so callers can determine if the context was cancelled.

---

## Handling Errors

When encountering an error, make a **deliberate choice** — do not discard
with `_`:

1. **Handle immediately** — address the error and continue
2. **Return to caller** — optionally wrapped with context
3. **In exceptional cases** — `log.Fatal` or `panic`

To intentionally ignore: add a comment explaining why.

```go
n, _ := b.Write(p) // never returns a non-nil error
```

For related concurrent operations, use
[`errgroup`](https://pkg.go.dev/golang.org/x/sync/errgroup):

```go
g, ctx := errgroup.WithContext(ctx)
g.Go(func() error { return task1(ctx) })
g.Go(func() error { return task2(ctx) })
if err := g.Wait(); err != nil { return err }
```

### Avoid In-Band Errors

Don't return `-1`, `nil`, or empty string to signal errors. Use multiple
returns:

```go
// Bad: In-band error value
func Lookup(key string) int  // returns -1 for missing

// Good: Explicit error or ok value
func Lookup(key string) (string, bool)
```

This prevents callers from writing `Parse(Lookup(key))` — it causes a
compile-time error since `Lookup(key)` has 2 outputs.

---

## Error Flow

Handle errors before normal code. Early returns keep the happy path unindented:

```go
// Good: Error first, normal code unindented
if err != nil {
    return err
}
// normal code
```

**Handle errors once** — either log or return, never both:

```
Error encountered?
├─ Caller can act on it? → Return (with context via %w)
├─ Top of call chain? → Log and handle
└─ Neither? → Log at appropriate level, continue
```

---

## Error Types

> **Advisory**: Recommended best practice.

| Caller needs to match? | Message type | Use |
|------------------------|--------------|-----|
| No | static | `errors.New("message")` |
| No | dynamic | `fmt.Errorf("msg: %v", val)` |
| Yes | static | `var ErrFoo = errors.New("...")` |
| Yes | dynamic | custom `error` type |

**Default**: Wrap with `fmt.Errorf("...: %w", err)`. Escalate to sentinels for
`errors.Is()`, to custom types for `errors.As()`.

---

## Error Wrapping

> **Advisory**: Recommended best practice.

- **Use `%v`**: At system boundaries, for logging, to hide internal details
- **Use `%w`**: To preserve error chain for `errors.Is`/`errors.As`

**Key rules**: Place `%w` at the end. Add context callers don't have. If
annotation adds nothing, return `err` directly.

> **Validation**: Choose the check scope before running it. From the repository root, run `bash .agents/skills/go-error-handling/scripts/check-errors.sh ./...` for a full scan. Run `go vet ./...` when the selected validation requires it.

Run a full scan to report every finding at one revision. Run the baseline comparator when the check should reject only new findings. Choose the exact paths and comparison criterion before implementation:

```bash
python3 -B .agents/skills/go-error-handling/scripts/check-errors-baseline.py \
  --base <full-base-sha> --candidate <full-candidate-sha> \
  --path internal/example.go
```

Run it from the candidate repository top level. It accepts only selected tracked regular non-test Go files present at both commits. It verifies the scanner and wrapper blobs, then exits 0 when no finding is added, 1 when a finding is added, and 2 when it cannot make a usable comparison. Each path reports raw `base_scan.exit_status` and `candidate_scan.exit_status`; raw exit 1 means the full scan found existing findings, so comparison exit 0 does not mean a clean full scan.

---

## Related Skills

- **Error naming**: See [go-naming](../go-naming/SKILL.md) when naming sentinel errors (`ErrFoo`) or custom error types
- **Testing errors**: See [golang-testing](../golang-testing/SKILL.md) when testing error semantics with `errors.Is`/`errors.As` or writing error-checking helpers
- **Panic handling**: See [go-defensive](../go-defensive/SKILL.md) when deciding between panic and error returns, or writing recover guards
- **Guard clauses**: See [go-control-flow](../go-control-flow/SKILL.md) when structuring early-return error flow or reducing nesting
- **Logging decisions**: See [go-logging](../go-logging/SKILL.md) when choosing log levels, configuring structured logging, or deciding what context to include in log messages
