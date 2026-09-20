# Fuzzing

Use fuzzing when a property should hold across a broad input space, especially for parsers, encoders, decoders, state transitions, and recovery code. Seeds should cover meaningful boundaries and known regressions.

```go
func FuzzReverse(f *testing.F) {
    f.Add("hello")
    f.Add("")
    f.Add("a")

    f.Fuzz(func(t *testing.T, input string) {
        if len(input) > 1<<20 {
            t.Skip()
        }

        reversed := Reverse(input)
        got := Reverse(reversed)
        if got != input {
            t.Errorf("Reverse(Reverse(%q)) = %q, want %q", input, got, input)
        }
    })
}
```

The target must bound per-input work and resource use. Limit sizes before expensive allocations, avoid unbounded recursion or waits, and give external resources explicit cleanup. A skip is appropriate for inputs outside the contract; do not skip inputs merely because they expose an unexpected failure.

Keep corpus-level resources outside the fuzz callback only when they are safe to reuse across inputs. Resources acquired for one input should be released for that input, including on fatal assertions.

During ordinary validation, target one package and bound the run:

```bash
go test -run '^$' -fuzz '^FuzzName$' -fuzztime=30s ./path/to/package
```

Use longer campaigns deliberately, with a known place for generated corpus artifacts and a stopping condition appropriate to the task.
