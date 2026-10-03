package cli

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"cloudattrib/internal/retention"
)

func TestReportRetentionCLIRequiresExplicitApply(t *testing.T) {
	t.Parallel()
	var output, errors bytes.Buffer
	called := 0
	dependencies := Dependencies{Stdout: &output, Stderr: &errors,
		ReportRetention: func(_ context.Context, configPath string, request retention.Request) (retention.Page, error) {
			called++
			if configPath != "custom.yaml" || request.Limit != 10 || request.Cutoff.IsZero() {
				t.Fatalf("retention request = %q %#v", configPath, request)
			}
			return retention.Page{Cutoff: request.Cutoff, Applied: request.Apply, Complete: true}, nil
		},
	}
	before := time.Now().UTC().Add(-31 * 24 * time.Hour).Format(time.RFC3339)
	flags := []string{"--config", "custom.yaml", "--before", before, "--limit", "10"}
	if exit := Run(t.Context(), append([]string{"retention", "preview"}, flags...), dependencies); exit != 0 || !strings.Contains(output.String(), `"applied":false`) {
		t.Fatalf("preview exit=%d output=%q errors=%q", exit, output.String(), errors.String())
	}
	output.Reset()
	if exit := Run(t.Context(), append([]string{"retention", "apply"}, flags...), dependencies); exit != 0 || !strings.Contains(output.String(), `"applied":true`) || called != 2 {
		t.Fatalf("apply exit=%d calls=%d output=%q errors=%q", exit, called, output.String(), errors.String())
	}
	output.Reset()
	if exit := Run(t.Context(), []string{"retention", "apply", "--before", "bad-date"}, dependencies); exit != 2 || called != 2 {
		t.Fatalf("bad cutoff exit=%d calls=%d", exit, called)
	}
}
