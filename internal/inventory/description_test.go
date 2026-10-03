package inventory

import (
	"strings"
	"testing"
	"time"

	"cloudattrib/internal/model"
)

func TestDescriptionKeepsTypedEvidenceAndExcludesRawSecrets(t *testing.T) {
	t.Parallel()
	observed := time.Unix(10, 0).UTC()
	report := model.Report{ID: "report-1", EndedAt: observed, Target: model.Target{Canonical: "api.example.com"},
		Observations: []model.Observation{
			{ID: "dns-a", Type: "dns_query", Subject: "api.example.com", ObservedAt: observed, Status: "nodata", Payload: model.JSONValue(`{"rrtype":"A","value":"secret-txt"}`)},
			{ID: "http-1", Type: "http_response", Subject: "api.example.com", ObservedAt: observed, Status: "responded", Payload: model.JSONValue(`{"url":"https://api.example.com/?token=secret-token","status_code":403,"headers":[{"name":"set-cookie","values":["secret-cookie"]}]}`)},
			{ID: "external", Type: "http_response", Subject: "api.example.com", Scope: model.ScopeExternalRedirect, ObservedAt: observed, Payload: model.JSONValue(`{"status_code":200}`)},
		},
		Findings: []model.Finding{{Subject: "api.example.com", ProviderID: "provider.safe", Relation: model.RelationWebDelivery, EvidenceIDs: []string{"evidence-1"}}},
		Coverage: []model.Coverage{{Capability: "dns", Status: model.CoveragePartial}},
	}
	description := DescribeReport(report, "api.example.com")
	if !strings.Contains(description.Text, "DNS a nodata") || !strings.Contains(description.Text, "HTTP 403 response") || !strings.Contains(description.Text, "provider.safe") ||
		strings.Contains(description.Text, "secret") || strings.Contains(description.Text, "HTTP 200") || len(description.EvidenceIDs) != 1 || len(description.ObservationIDs) != 2 || !description.Positive {
		t.Fatalf("description = %#v", description)
	}
	if again := DescribeReport(report, "api.example.com"); again.ContentHash != description.ContentHash || again.Text != description.Text {
		t.Fatalf("description changed across replay: %#v", again)
	}
}

func TestDescriptionIndexesMultiwordTechnologyName(t *testing.T) {
	t.Parallel()
	hostname := "analytics.example.com"
	report := model.Report{ID: "technology-report", Observations: []model.Observation{
		{ID: "technology", Type: "technology", Subject: hostname, Payload: model.JSONValue(`{"name":"Google Analytics"}`)},
		{ID: "unsafe", Type: "technology", Subject: hostname, Payload: model.JSONValue(`{"name":"https://secret.example/path?token=private"}`)},
	}}
	description := DescribeReport(report, hostname)
	if !strings.Contains(description.Text, "technology google analytics") || strings.Contains(description.Text, "secret") {
		t.Fatalf("description = %#v", description)
	}
}
