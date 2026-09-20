# Test Structure

Use the repository's established test layout. These patterns are choices for cases where the repository does not already decide.

## Files, packages, and names

Go discovers tests only in files ending in `_test.go`. Tests may use the implementation package for access to unexported details or an external `_test` package to exercise only the public API:

```go
// store_test.go
package store

// api_test.go
package store_test
```

Pairing `foo.go` with `foo_test.go` often helps navigation, but a concern-based split such as `validation_test.go` can be clearer in a large package. Similarly, source-order placement is useful when it makes implementation and tests easy to correlate; follow a repository's concern or API grouping when that is clearer.

Use the names recognized by the testing tool:

```go
func TestAdd(t *testing.T) { /* ... */ }
func TestStore_Get(t *testing.T) { /* ... */ }
func BenchmarkAdd(b *testing.B) { /* ... */ }
func ExampleAdd() { /* ... */ }
func FuzzAdd(f *testing.F) { /* ... */ }
```

## Table-driven tests

Use a table when cases share setup and assertions. Name cases when separate reporting helps identify the failing behavior.

```go
func TestCalculatePrice(t *testing.T) {
    tests := []struct {
        name      string
        quantity  int
        unitPrice float64
        want      float64
    }{
        {name: "single item", quantity: 1, unitPrice: 10, want: 10},
        {name: "bulk discount", quantity: 100, unitPrice: 10, want: 900},
        {name: "zero quantity", quantity: 0, unitPrice: 10, want: 0},
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            got := CalculatePrice(tt.quantity, tt.unitPrice)
            if got != tt.want {
                t.Errorf("CalculatePrice(%d, %v) = %v, want %v",
                    tt.quantity, tt.unitPrice, got, tt.want)
            }
        })
    }
}
```

Each case should own or safely share its fixtures. Do not make a case depend on a prior case having run.

## Bind assertion helpers to the subtest

`assert.New(t)` and `require.New(t)` capture the exact test handle. Creating an instance in the parent and using it inside `t.Run` attributes failures to the parent, so the failing subtest can still appear to pass.

```go
// Wrong: is reports through the parent t.
func TestCalculatePrice(t *testing.T) {
    is := assert.New(t)
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            is.Equal(tt.want, CalculatePrice(tt.quantity, tt.unitPrice))
        })
    }
}

// Right: each subtest binds its own helper.
func TestCalculatePrice(t *testing.T) {
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            is := assert.New(t)
            is.Equal(tt.want, CalculatePrice(tt.quantity, tt.unitPrice))
        })
    }
}
```

To diagnose suspected leakage, deliberately break one case and run it verbosely. If the parent fails while that subtest is reported as passing, check where the assertion instance was created.

## Focused commands

Replace package paths and names with the repository's actual targets.

```bash
go test ./path/to/package
go test -run '^TestName$' ./path/to/package
go test -run '^TestName$/^case_name$' ./path/to/package
go test -run 'Test(Add|Sub)' ./path/to/package
go test -race ./path/to/package
go test -cover ./path/to/package
go test -run '^$' -bench '^BenchmarkName$' -benchmem ./path/to/package
go test -tags=integration ./...
```

An anchored `-run '^TestName$'` selects that exact top-level test. Slash-separated expressions select successive test and subtest name components. Run `go test ./...` when repository policy requires the full suite or the change crosses package boundaries.
