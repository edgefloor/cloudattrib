# Toolchain Compatibility

Check the module's `go` directive and relevant per-file build constraints before using a recently added testing API.

## Test artifacts

[`ArtifactDir`](https://pkg.go.dev/testing#T.ArtifactDir) is available on `testing.T`, `testing.B`, and `testing.F` in Go 1.26 and later. Write inspectable test output there instead of using repository-local paths:

```go
func TestRenderGoldenArtifact(t *testing.T) {
    out := filepath.Join(t.ArtifactDir(), "rendered.json")
    if err := os.WriteFile(out, renderedBytes, 0o644); err != nil {
        t.Fatal(err)
    }
}
```

The tool retains artifacts when `go test` is run with `-artifacts`; without that flag the artifact directory is temporary. Use `t.TempDir()` for transient fixtures that never need to be retained for inspection.

## API version checks

For Go 1.27 modules, `go test` runs the `stdversion` vet analyzer by default. It reports uses of standard-library APIs newer than the applicable Go version, considering the module directive and per-file build constraints. Resolve such a failure by using a compatible API, adding an appropriate version build constraint, or intentionally updating the module version; do not suppress it without understanding the compatibility contract.

Relevant version gates in this skill:

| API | First supported version |
| --- | --- |
| `testing.B.Loop` | Go 1.24 |
| `testing/synctest.Test` | Go 1.25 |
| `testing.T/B/F.ArtifactDir` | Go 1.26 |
| `testing/synctest.Sleep` | Go 1.27 |
| `httptest.NewTestServer(testing.TB, http.Handler)` | Go 1.27 |

Use the [Go 1.27 release notes](https://go.dev/doc/go1.27) and package documentation when a repository targets a different version.
