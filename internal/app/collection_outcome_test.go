package app

import (
	"context"
	"testing"
	"time"

	collectdns "cloudattrib/internal/collect/dns"
	"cloudattrib/internal/model"
	"cloudattrib/internal/policy"
)

func TestAnalyzeInterpretsDNSAbsenceAndProtocolFailure(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		response   int
		wantStatus model.ReportStatus
		wantQuery  string
	}{
		{name: "nodata is completed absence", response: 0, wantStatus: model.StatusComplete, wantQuery: "nodata"},
		{name: "nxdomain is completed absence", response: 3, wantStatus: model.StatusComplete, wantQuery: "nxdomain"},
		{name: "servfail cannot establish absence", response: 2, wantStatus: model.StatusFailed, wantQuery: "servfail"},
		{name: "refused cannot establish absence", response: 5, wantStatus: model.StatusFailed, wantQuery: "refused"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			collector := collectdns.New(func(_ context.Context, question model.DNSQuestion) (model.DNSResult, error) {
				return model.DNSResult{Question: question, ResponseCode: tt.response}, nil
			}, policy.PublicDestinationPolicy())
			service := NewService(Dependencies{DNS: collector, View: model.NewAttributionView("bundle", "policy", nil, nil)})
			includeWWW := false
			report, err := service.Analyze(t.Context(), model.AnalyzeRequest{Target: "example.com", Kind: model.TargetDomain, Mode: model.ModeDNS, IncludeWWW: &includeWWW})
			if err != nil {
				t.Fatalf("Analyze() error = %v", err)
			}
			if report.Status != tt.wantStatus {
				t.Fatalf("report status = %q, coverage = %#v", report.Status, report.Coverage)
			}
			for _, observation := range report.Observations {
				if observation.Type == "dns_query" && observation.Status != tt.wantQuery {
					t.Fatalf("DNS query status = %q, want %q", observation.Status, tt.wantQuery)
				}
			}
		})
	}
}

func TestReportStatusSeparatesCancellationFromDeadlineFailure(t *testing.T) {
	t.Parallel()

	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	if got := reportStatus(cancelled, nil, []model.Coverage{{Capability: "dns", Status: model.CoveragePartial}}); got != model.StatusCancelled {
		t.Fatalf("cancelled status = %q", got)
	}
	deadline, cancelDeadline := context.WithDeadline(t.Context(), time.Now().Add(-time.Second))
	defer cancelDeadline()
	observations := []model.Observation{{Type: "dns_query", Status: string(model.DNSOutcomeNoData)}}
	if got := reportStatus(deadline, observations, []model.Coverage{{Capability: "dns", Status: model.CoveragePartial}}); got != model.StatusPartial {
		t.Fatalf("deadline status = %q", got)
	}
}
