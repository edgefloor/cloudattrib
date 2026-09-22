package webtech

import (
	"context"
	"net/http"
	"testing"

	"cloudattrib/internal/model"
)

func TestDetectUsesSuppliedResponse(t *testing.T) {
	t.Parallel()

	detector, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	detections, coverage := detector.Detect(
		context.Background(),
		http.Header{"Server": {"nginx"}},
		[]byte("<html><body></body></html>"),
	)
	if coverage.Status != model.CoverageComplete {
		t.Fatalf("Detect() coverage = %#v", coverage)
	}
	found := false
	for _, item := range detections {
		if item.Name == "Nginx" && item.DetectorID == "wappalyzergo-v0.3.2" && item.ExplanationGranularity == model.ExplanationGranularityDetectorResult {
			found = true
		}
	}
	if !found {
		t.Fatalf("Detect() detections = %#v, want typed nginx result", detections)
	}
}
