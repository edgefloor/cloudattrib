package main

import (
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestInterfaceComplianceAssignments(t *testing.T) {
	tests := []struct {
		name        string
		declaration string
		wantExit    int
		wantMissing int
	}{
		{
			name:        "named initialized typed assignment",
			declaration: "var provider Sink = (*SinkImpl)(nil)",
			wantExit:    0,
			wantMissing: 0,
		},
		{
			name:        "named_initialized_nil_interface",
			declaration: "var provider Sink = nil",
			wantExit:    1,
			wantMissing: 1,
		},
		{
			name:        "named_initialized_parenthesized_nil_interface",
			declaration: "var provider Sink = (nil)",
			wantExit:    1,
			wantMissing: 1,
		},
		{
			name:        "blank initialized assertion",
			declaration: "var _ Sink = (*SinkImpl)(nil)",
			wantExit:    0,
			wantMissing: 0,
		},
		{
			name:        "uninitialized named interface variable",
			declaration: "var provider Sink",
			wantExit:    1,
			wantMissing: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			source := "package sample\n\n" +
				"type Sink interface { Send() }\n\n" +
				"type SinkImpl struct{}\n\n" +
				"func (*SinkImpl) Send() {}\n\n" +
				tt.declaration + "\n"
			if err := os.WriteFile(filepath.Join(dir, "sample.go"), []byte(source), 0o600); err != nil {
				t.Fatalf("write fixture: %v", err)
			}

			workingDir, err := os.Getwd()
			if err != nil {
				t.Fatalf("get working directory: %v", err)
			}
			command := exec.Command("go", "run", filepath.Join(workingDir, "check-interface-compliance.go"), "--json", dir)
			output, err := command.Output()
			if gotExit := commandExitCode(err); gotExit != tt.wantExit {
				t.Fatalf("exit code = %d, want %d; error = %v", gotExit, tt.wantExit, err)
			}

			var got result
			if err := json.Unmarshal(output, &got); err != nil {
				t.Fatalf("decode JSON output %q: %v", output, err)
			}
			if got.CountMissing != tt.wantMissing {
				t.Errorf("count_missing = %d, want %d", got.CountMissing, tt.wantMissing)
			}
			if len(got.Missing) != tt.wantMissing {
				t.Errorf("missing entries = %d, want %d", len(got.Missing), tt.wantMissing)
			}
		})
	}
}

func commandExitCode(err error) int {
	if err == nil {
		return 0
	}
	var exitError *exec.ExitError
	if errors.As(err, &exitError) {
		return exitError.ExitCode()
	}
	return -1
}
