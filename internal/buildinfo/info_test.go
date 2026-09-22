package buildinfo

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime/debug"
	"strings"
	"testing"
)

func TestFromSettingsUsesExplicitUnknowns(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		settings []debug.BuildSetting
		want     Info
	}{
		{name: "unavailable", want: Info{Dirty: DirtyUnknown}},
		{
			name: "clean", settings: []debug.BuildSetting{{Key: "vcs.revision", Value: "abcdef"}, {Key: "vcs.modified", Value: "false"}},
			want: Info{Revision: "abcdef", RevisionKnown: true, Dirty: Clean},
		},
		{
			name: "dirty", settings: []debug.BuildSetting{{Key: "vcs.revision", Value: "abcdef"}, {Key: "vcs.modified", Value: "true"}},
			want: Info{Revision: "abcdef", RevisionKnown: true, Dirty: Dirty},
		},
		{
			name: "invalid dirty value", settings: []debug.BuildSetting{{Key: "vcs.revision", Value: "abcdef"}, {Key: "vcs.modified", Value: "sometimes"}},
			want: Info{Revision: "abcdef", RevisionKnown: true, Dirty: DirtyUnknown},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if got := fromSettings(test.settings); got != test.want {
				t.Fatalf("fromSettings() = %#v, want %#v", got, test.want)
			}
		})
	}
}

func TestCurrentReadsCleanAndDirtyTemporaryGitBuilds(t *testing.T) {
	if testing.Short() {
		t.Skip("builds temporary binaries")
	}
	for _, command := range []string{"git", "go"} {
		if _, err := exec.LookPath(command); err != nil {
			t.Skipf("%s is unavailable: %v", command, err)
		}
	}

	directory := t.TempDir()
	writeFixtureModule(t, directory)
	run(t, directory, "git", "init", "--quiet")
	run(t, directory, "git", "config", "user.email", "buildinfo-test@example.invalid")
	run(t, directory, "git", "config", "user.name", "buildinfo test")
	run(t, directory, "git", "add", ".")
	run(t, directory, "git", "commit", "--quiet", "-m", "fixture")
	revision := strings.TrimSpace(run(t, directory, "git", "rev-parse", "HEAD"))

	clean := buildAndRead(t, directory, "clean")
	if !clean.RevisionKnown || clean.Revision != revision || clean.Dirty != Clean {
		t.Fatalf("clean build provenance = %#v, want revision %q and clean", clean, revision)
	}
	mainPath := filepath.Join(directory, "cmd", "probe", "main.go")
	mainData, err := os.ReadFile(mainPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(mainPath, append(mainData, []byte("\n")...), 0o600); err != nil {
		t.Fatal(err)
	}
	dirty := buildAndRead(t, directory, "dirty")
	if !dirty.RevisionKnown || dirty.Revision != revision || dirty.Dirty != Dirty {
		t.Fatalf("dirty build provenance = %#v, want revision %q and dirty", dirty, revision)
	}
}

func writeFixtureModule(t *testing.T, directory string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(directory, "internal", "buildinfo"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(directory, "cmd", "probe"), 0o700); err != nil {
		t.Fatal(err)
	}
	infoSource, err := os.ReadFile("info.go")
	if err != nil {
		t.Fatal(err)
	}
	files := map[string][]byte{
		"go.mod":                     []byte("module cloudattrib\n\ngo 1.25\n"),
		"internal/buildinfo/info.go": infoSource,
		"cmd/probe/main.go":          []byte("package main\n\nimport (\n\t\"encoding/json\"\n\t\"os\"\n\n\t\"cloudattrib/internal/buildinfo\"\n)\n\nfunc main() { _ = json.NewEncoder(os.Stdout).Encode(buildinfo.Current()) }\n"),
	}
	for name, content := range files {
		path := filepath.Join(directory, filepath.FromSlash(name))
		if err := os.WriteFile(path, content, 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func buildAndRead(t *testing.T, directory, name string) Info {
	t.Helper()
	binary := filepath.Join(directory, name)
	run(t, directory, "go", "build", "-o", binary, "./cmd/probe")
	command := exec.Command(binary)
	command.Dir = directory
	output, err := command.Output()
	if err != nil {
		t.Fatalf("run %s: %v", name, err)
	}
	var info Info
	if err := json.Unmarshal(output, &info); err != nil {
		t.Fatalf("decode %s output %q: %v", name, output, err)
	}
	return info
}

func run(t *testing.T, directory, name string, arguments ...string) string {
	t.Helper()
	command := exec.Command(name, arguments...)
	command.Dir = directory
	var stdout, stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		t.Fatalf("run %s %v: %v\n%s", name, arguments, err, stderr.String())
	}
	return stdout.String()
}
