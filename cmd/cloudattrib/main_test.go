package main

import (
	"path/filepath"
	"testing"

	"cloudattrib/internal/config"
	"cloudattrib/internal/model"
)

func TestRequiresLocalAnalyzer(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		args []string
		want bool
	}{
		{[]string{"analyze", "example.com"}, true},
		{[]string{"lookup-ip", "192.0.2.1"}, true},
		{[]string{"serve"}, false},
		{[]string{"datasets", "sync"}, false},
		{[]string{"ct", "collect"}, false},
		{nil, false},
	} {
		if got := requiresLocalAnalyzer(test.args); got != test.want {
			t.Fatalf("requiresLocalAnalyzer(%v) = %v, want %v", test.args, got, test.want)
		}
	}
}

func TestResolveConfigurationClassifiesLoadFailure(t *testing.T) {
	t.Parallel()

	_, err := resolveConfiguration(config.Default(), filepath.Join(t.TempDir(), "missing.yaml"))
	if got := model.ErrorCodeOf(err); got != model.CodeInvalidSyntax {
		t.Fatalf("ErrorCodeOf(resolveConfiguration()) = %q, want %q", got, model.CodeInvalidSyntax)
	}
}
