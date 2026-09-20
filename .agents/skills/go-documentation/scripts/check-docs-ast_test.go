package main

import (
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

type checkerResult struct {
	Missing []struct {
		Kind string `json:"kind"`
		Name string `json:"name"`
	} `json:"missing"`
	Total     int  `json:"total"`
	Truncated bool `json:"truncated"`
}

func TestCheckDocsWrapperAcceptsDocumentedExportsAndIgnoresUnexported(t *testing.T) {
	fixture := writeFixture(t, `// Package fixture provides test declarations.
package fixture

// DocumentedType is an exported type with documentation.
type DocumentedType struct{}

// DocumentedFunc is an exported function with documentation.
func DocumentedFunc() {}

func undocumentedPrivate() {}
`)

	output, err := runChecker(t, fixture)
	if err != nil {
		t.Fatalf("check-docs.sh returned an error: %v\noutput: %s", err, output)
	}
	if output != "All exported symbols are documented.\n" {
		t.Fatalf("check-docs.sh output = %q, want clean result", output)
	}
}

func TestCheckDocsWrapperJSONReportsUndocumentedExportAndExitStatus(t *testing.T) {
	fixture := writeFixture(t, `// Package fixture provides test declarations.
package fixture

func MissingDoc() {}
`)

	output, err := runChecker(t, "--json", fixture)
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("check-docs.sh error = %v, want exit status 1\noutput: %s", err, output)
	}
	if exitErr.ExitCode() != 1 {
		t.Fatalf("check-docs.sh exit status = %d, want 1\noutput: %s", exitErr.ExitCode(), output)
	}

	var result checkerResult
	if err := json.Unmarshal([]byte(output), &result); err != nil {
		t.Fatalf("check-docs.sh JSON output is invalid: %v\noutput: %s", err, output)
	}
	if result.Total != 1 || result.Truncated || len(result.Missing) != 1 {
		t.Fatalf("check-docs.sh JSON result = %+v, want one untruncated finding", result)
	}
	if result.Missing[0].Kind != "function" || result.Missing[0].Name != "MissingDoc" {
		t.Fatalf("check-docs.sh finding = %+v, want function MissingDoc", result.Missing[0])
	}
}

func TestCheckDocsStrictHelpAndDeclarationScope(t *testing.T) {
	var wrapperHelp string
	for _, runHelp := range []struct {
		name string
		run  func(*testing.T) (string, error)
	}{
		{name: "wrapper", run: func(t *testing.T) (string, error) { return runChecker(t, "--help") }},
		{name: "direct", run: func(t *testing.T) (string, error) { return runCheckerDirect(t, "--help") }},
	} {
		t.Run(runHelp.name+" help", func(t *testing.T) {
			output, err := runHelp.run(t)
			if err != nil {
				t.Fatalf("--help returned an error: %v\noutput: %s", err, output)
			}
			if !strings.Contains(output, "--strict         Also check unexported functions, methods, types, constants, and variables") {
				t.Fatalf("--help output does not describe strict declaration coverage:\n%s", output)
			}
			if runHelp.name == "wrapper" {
				wrapperHelp = output
				return
			}
			if output != wrapperHelp {
				t.Fatalf("direct --help output differs from wrapper output:\ndirect:\n%s\nwrapper:\n%s", output, wrapperHelp)
			}
		})
	}

	fixture := writeFixture(t, `// Package fixture provides test declarations.
package fixture

type privateType struct {
	privateField string
}

func privateFunction() {
	localVariable := 1
	_ = localVariable
}

func (privateType) privateMethod() {}

const privateConstant = "value"

var privateVariable = "value"
`)

	output, err := runChecker(t, fixture)
	if err != nil {
		t.Fatalf("default check-docs.sh returned an error: %v\noutput: %s", err, output)
	}
	if output != "All exported symbols are documented.\n" {
		t.Fatalf("default check-docs.sh output = %q, want clean result", output)
	}

	output, err = runChecker(t, "--json", "--strict", fixture)
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitCode() != 1 {
		t.Fatalf("strict check-docs.sh error = %v, want exit status 1\noutput: %s", err, output)
	}

	var result checkerResult
	if err := json.Unmarshal([]byte(output), &result); err != nil {
		t.Fatalf("strict check-docs.sh JSON output is invalid: %v\noutput: %s", err, output)
	}
	want := []struct{ kind, name string }{
		{kind: "type", name: "privateType"},
		{kind: "function", name: "privateFunction"},
		{kind: "method", name: "privateMethod"},
		{kind: "const", name: "privateConstant"},
		{kind: "var", name: "privateVariable"},
	}
	if result.Total != len(want) || len(result.Missing) != len(want) {
		t.Fatalf("strict check-docs.sh result = %+v, want exactly %d findings", result, len(want))
	}
	for i, finding := range result.Missing {
		if finding.Kind != want[i].kind || finding.Name != want[i].name {
			t.Fatalf("strict finding %d = %+v, want %s %s", i, finding, want[i].kind, want[i].name)
		}
	}
}

func writeFixture(t *testing.T, source string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "fixture.go")
	if err := os.WriteFile(path, []byte(source), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	return dir
}

func runChecker(t *testing.T, args ...string) (string, error) {
	t.Helper()
	wrapper, err := filepath.Abs("check-docs.sh")
	if err != nil {
		t.Fatalf("resolve check-docs.sh: %v", err)
	}
	command := exec.Command("bash", append([]string{wrapper}, args...)...)
	command.Env = append(os.Environ(), "XDG_CACHE_HOME="+t.TempDir(), "GOCACHE="+t.TempDir())
	output, err := command.CombinedOutput()
	return string(output), err
}

func runCheckerDirect(t *testing.T, args ...string) (string, error) {
	t.Helper()
	command := exec.Command("go", append([]string{"run", "check-docs-ast.go"}, args...)...)
	command.Env = append(os.Environ(), "GOCACHE="+t.TempDir())
	output, err := command.CombinedOutput()
	return string(output), err
}
