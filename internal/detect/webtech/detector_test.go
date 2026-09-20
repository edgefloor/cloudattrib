package webtech

import (
	"context"
	"net/http"
	"testing"

	"cloudattrib/internal/model"
)

func TestDetectUsesSuppliedResponse(t *testing.T) {
	t.Parallel()

	detector, err := New(nil)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	evidence, coverage := detector.Detect(
		context.Background(),
		"http-observation",
		"example.com",
		model.ScopeRoot,
		http.Header{"Server": {"nginx"}},
		[]byte("<html><body></body></html>"),
		model.AttributionView{},
	)
	if coverage.Status != model.CoverageComplete {
		t.Fatalf("Detect() coverage = %#v", coverage)
	}
	found := false
	for _, item := range evidence {
		if item.Category == "web_technology" && item.ProductID == "webtech.nginx" {
			found = true
		}
	}
	if !found {
		t.Fatalf("Detect() evidence = %#v, want nginx web technology", evidence)
	}
}
