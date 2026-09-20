---
name: go-performance
description: Profile and benchmark Go performance; optimize measured runtime and allocation costs.
allowed-tools: Bash(bash:*)
---

# Go Performance Patterns

## Resource Routing

- `scripts/bench-compare.sh` - Run when comparing benchmark results, saving baselines, or producing JSON benchmark metadata.
- `references/BENCHMARKS.md` - Read when writing benchmarks, using benchstat, or profiling with pprof.
- `references/STRING-OPTIMIZATION.md` - Read when optimizing string conversion, concatenation, or byte/string boundaries.

Performance-specific guidelines apply only to the **hot path**. Don't prematurely optimize—focus these patterns where they matter most.

---

## Prefer strconv over fmt

For primitive conversions on a measured hot path, consider `strconv` instead of
`fmt` and retain the change only when it improves the actual workload:

```go
s := strconv.Itoa(rand.Int())
```

---

## Avoid Repeated String-to-Byte Conversions

Convert a fixed string to `[]byte` once outside the loop:

```go
data := []byte("Hello world")
for b.Loop() { // Go 1.24+; use b.N loops only for older Go
    w.Write(data)
}
```

---

## Prefer Specifying Container Capacity

Specify container capacity where possible to allocate memory up front. This minimizes subsequent allocations from copying and resizing as elements are added.

### Map Capacity Hints

Provide capacity hints when initializing maps with `make()`:

```go
m := make(map[string]os.DirEntry, len(files))
```

**Note**: Unlike slices, map capacity hints do not guarantee complete preemptive allocation—they approximate the number of hashmap buckets required.

### Slice Capacity

Provide capacity hints when initializing slices with `make()`, particularly when appending:

```go
data := make([]int, 0, size)
```

Slice capacity is a count of elements before appending must grow the backing
array. Appends that remain within capacity do not need that growth, but upfront
capacity also retains memory; measure the relevant workload before choosing it.

---

## Pass Values

Don't pass pointers as function arguments just to save a few bytes. If a function refers to its argument `x` only as `*x` throughout, then the argument shouldn't be a pointer.

```go
func process(s string) { // not *string — strings are small fixed-size headers
    fmt.Println(s)
}
```

**Common pass-by-value types**: `string`, `io.Reader`, small structs.

**Exceptions**:
- Large structs where copying is expensive
- Small structs that might grow in the future

---

## String Concatenation

Choose the right strategy based on complexity:

| Method | Best For |
|--------|----------|
| `+` | Few strings, simple concat |
| `fmt.Sprintf` | Formatted output with mixed types |
| `strings.Builder` | Loop/piecemeal construction |
| `strings.Join` | Joining a slice |
| Backtick literal | Constant multi-line text |

---

## Benchmarking and Profiling

Always measure before and after optimizing. Use Go's built-in benchmark framework and profiling tools.

```bash
go test -bench=. -benchmem -count=10 ./...
```

`-count=10` is an example, not a significance guarantee; choose repetitions
that fit the benchmark's cost and observed variance. Compare like-for-like
before and after runs. A p-value is evidence from the comparison model, not
proof that a change matters in production.

> **Validation**: From the repository root, run `bash .agents/skills/go-performance/scripts/bench-compare.sh ./...` to measure the actual impact. Keep an optimization only when it improves the relevant workload enough to justify its cost.

---

## Quick Reference

| Pattern | Consider |
|---------|----------|
| Primitive conversion | `strconv` when measurement supports it |
| Repeated `[]byte` | Convert a fixed string once when it avoids relevant work |
| Map or slice initialization | A map capacity hint or known initial slice capacity when memory trade-offs fit |
| Small fixed-size arguments | Passing by value unless copying is a demonstrated cost |
| Simple string join | `+` for a few strings |
| Loop string build | `strings.Builder` |

---

## Related Skills

- **Data structures**: See [go-data-structures](../go-data-structures/SKILL.md) when choosing between slices, maps, and arrays, or understanding allocation semantics
- **Declaration patterns**: See [go-declarations](../go-declarations/SKILL.md) when using `make` with capacity hints or initializing maps and slices
- **Concurrency**: See [go-concurrency](../go-concurrency/SKILL.md) when parallelizing work across goroutines or using sync.Pool for buffer reuse
- **Style principles**: See [go-style-core](../go-style-core/SKILL.md) when deciding whether an optimization is worth the readability cost
