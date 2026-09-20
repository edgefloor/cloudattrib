# Concurrency Testing

Use concurrency-specific tools when the behavior under test has goroutine, synchronization, deadline, or timer semantics. They supplement assertions about the public behavior; they do not make shared fixtures safe automatically.

## Goroutine leak checks

Consider `go.uber.org/goleak` for packages whose goroutine ownership makes leak detection valuable and whose dependency policy permits it. A package-wide check belongs in `TestMain`:

```go
func TestMain(m *testing.M) {
    goleak.VerifyTestMain(m)
}
```

Use a per-test check when only a focused lifecycle test needs it:

```go
func TestWorkerPool(t *testing.T) {
    defer goleak.VerifyNone(t)
    // Exercise startup and shutdown.
}
```

Ignore known runtime or library goroutines only after identifying their ownership. Broad ignore rules can hide the leak the test is meant to find.

## `testing/synctest`

[`testing/synctest`](https://pkg.go.dev/testing/synctest) runs a group of goroutines in an isolated bubble with a fake clock. Use it for code whose observable behavior depends on timers, deadlines, or cancellation and whose operations fit the bubble's semantics.

`synctest.Test` is available in Go 1.25 and later. The Go 1.24 experimental fallback used `synctest.Run` with `GOEXPERIMENT=synctest`; keep that form only in a module intentionally remaining on the experimental API.

```go
func TestContextTimeout(t *testing.T) {
    synctest.Test(t, func(t *testing.T) {
        const timeout = 5 * time.Second

        ctx, cancel := context.WithTimeout(t.Context(), timeout)
        defer cancel()

        time.Sleep(timeout - time.Nanosecond)
        synctest.Wait()
        if err := ctx.Err(); err != nil {
            t.Fatalf("before timeout: %v", err)
        }

        time.Sleep(time.Nanosecond)
        synctest.Wait()
        if err := ctx.Err(); err != context.DeadlineExceeded {
            t.Fatalf("after timeout: got %v, want DeadlineExceeded", err)
        }
    })
}
```

The fake clock advances when every goroutine in the bubble is durably blocked. Waiting on channels, timers, and `sync.WaitGroup` can be durable; mutex acquisition and external I/O or syscalls are not. `synctest.Wait` waits for the other bubble goroutines to become durably blocked and establishes synchronization for race-detector purposes. It does not make arbitrary scheduling bugs reproducible.

Go 1.27 adds `synctest.Sleep(d)`, equivalent to `time.Sleep(d)` followed by `synctest.Wait()`. Go 1.27 also adds [`httptest.NewTestServer(t, handler)`](https://pkg.go.dev/net/http/httptest#NewTestServer), whose in-memory network can be used inside a synctest bubble. Gate both APIs on the module's Go version.

## Parallel subtests

Use `t.Parallel()` only when each case owns its mutable inputs and the code does not share unsafe global state, environment variables, ports, clocks, or external fixtures.

```go
func TestParallelOperations(t *testing.T) {
    tests := []struct {
        name string
        data []byte
    }{
        {name: "small", data: make([]byte, 1024)},
        {name: "medium", data: make([]byte, 1024*1024)},
    }

    for _, tt := range tests {
        tt := tt
        t.Run(tt.name, func(t *testing.T) {
            t.Parallel()

            got := Process(tt.data)
            if got == nil {
                t.Fatal("Process returned nil")
            }
        })
    }
}
```

Run the relevant package under `go test -race` when concurrency behavior changes. Treat a clean race run as evidence about the executed paths, not proof that all schedules are safe.
