package app

import (
	"encoding/json"
	"testing"

	"cloudattrib/internal/model"
)

func TestTLSCertificateCoverageDisclosesUnsupportedAndInapplicablePaths(t *testing.T) {
	t.Parallel()

	httpsPayload, err := json.Marshal(model.HTTPPayload{URL: "https://redirect.example/"})
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name         string
		request      model.NormalizedRequest
		observations []model.Observation
		tlsAttempted bool
		fallback     string
		status       model.CoverageStatus
	}{
		{
			name: "DNS-only request", request: model.NormalizedRequest{Mode: model.ModeDNS, SeedHostnames: []string{"example.com"}},
			fallback: "https", status: model.CoverageSkipped,
		},
		{
			name: "HTTPS domain", request: model.NormalizedRequest{Mode: model.ModeFull, Target: model.Target{Kind: model.TargetDomain}, SeedHostnames: []string{"example.com"}},
			fallback: "https", status: model.CoverageUnavailable,
		},
		{
			name: "plain HTTP URL", request: model.NormalizedRequest{Mode: model.ModeFull, Target: model.Target{Kind: model.TargetURL, Canonical: "http://example.com/"}, SeedHostnames: []string{"example.com"}},
			fallback: "https", status: model.CoverageSkipped,
		},
		{
			name: "redirect from HTTP to HTTPS", request: model.NormalizedRequest{Mode: model.ModeFull, Target: model.Target{Kind: model.TargetURL, Canonical: "http://example.com/"}, SeedHostnames: []string{"example.com"}},
			observations: []model.Observation{{Type: "http_response", Payload: httpsPayload}}, fallback: "https", status: model.CoverageUnavailable,
		},
		{
			name: "failed redirect from HTTP to HTTPS", request: model.NormalizedRequest{Mode: model.ModeFull, Target: model.Target{Kind: model.TargetURL, Canonical: "http://example.com/"}, SeedHostnames: []string{"example.com"}},
			tlsAttempted: true, fallback: "https", status: model.CoverageUnavailable,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			coverage := tlsCertificateCoverage(tt.request, tt.observations, tt.fallback, tt.tlsAttempted)
			if coverage.Status != tt.status || coverage.Reason == "" {
				t.Fatalf("coverage = %#v, want %q with reason", coverage, tt.status)
			}
		})
	}
}
