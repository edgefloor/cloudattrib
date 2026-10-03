package cdnsuffix

import (
	"context"
	"encoding/json"
	"testing"

	"cloudattrib/internal/model"
)

func TestDetectMatchesOnlyCNAMEDestinationAtLabelBoundary(t *testing.T) {
	records := []Record{
		{ID: "suffix-a", Suffix: "edge.example.net", Category: "cdn", ProviderID: "edge", SourceID: "cdncheck-data", RecordRef: "#/cdn/edge/0"},
		{ID: "suffix-b", Suffix: "example.net", Category: "cloud", ProviderID: "cloud", SourceID: "cdncheck-data", RecordRef: "#/cloud/cloud/0"},
	}
	detector := New(records)
	for _, test := range []struct {
		name, target string
		scope        model.Scope
		want         int
	}{
		{"exact", "edge.example.net", model.ScopeRoot, 2},
		{"descendant", "host.edge.example.net.", model.ScopeSubdomain, 2},
		{"CNAME dependency", "host.edge.example.net", model.ScopeCNAME, 2},
		{"DNS dependency", "host.edge.example.net", model.ScopeDNSDependency, 2},
		{"external redirect", "host.edge.example.net", model.ScopeExternalRedirect, 2},
		{"lookalike", "notedge.example.net", model.ScopeRoot, 1},
		{"false suffix", "edge.example.net.evil.test", model.ScopeRoot, 0},
		{"malformed name", "bad..edge.example.net", model.ScopeRoot, 0},
		{"mail dependency", "edge.example.net", model.ScopeMailDependency, 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			payload, err := json.Marshal(model.DNSPayload{RRType: "CNAME", Value: test.target})
			if err != nil {
				t.Fatal(err)
			}
			got, coverage := detector.Detect(context.Background(), []model.Observation{{ID: "obs", Type: "dns_record", Status: "answered", Scope: test.scope, Payload: payload}}, model.AttributionView{})
			if len(got) != test.want || coverage[0].Status != model.CoverageComplete {
				t.Fatalf("evidence = %#v, coverage = %#v, want %d matches", got, coverage, test.want)
			}
			for _, item := range got {
				if item.Scope != test.scope || item.ProductID != "" || item.Relation != model.RelationWebDelivery || item.DatasetRecords[0].RecordRef == "" {
					t.Fatalf("unsupported claim or lost scope/provenance: %#v", item)
				}
			}
		})
	}
}

func TestDetectReportsUnmappedCategory(t *testing.T) {
	detector := New([]Record{{ID: "common", Suffix: "common.example", Category: "common"}})
	got, coverage := detector.Detect(context.Background(), nil, model.AttributionView{})
	if len(got) != 0 || coverage[0].Status != model.CoverageUnavailable || coverage[0].Omitted != 1 || detector.Capability().Status != model.CoverageUnavailable {
		t.Fatalf("evidence = %#v, coverage = %#v", got, coverage)
	}
}

func TestDetectReportsPartialCoverageWhenCategoryIsOmitted(t *testing.T) {
	detector := New([]Record{
		{ID: "cdn", Suffix: "edge.example", Category: "cdn", ProviderID: "edge", SourceID: "cdncheck-data", RecordRef: "#/cdn/edge/0"},
		{ID: "common", Suffix: "edge.example", Category: "common", ProviderID: "common"},
	})
	payload, err := json.Marshal(model.DNSPayload{RRType: "CNAME", Value: "host.edge.example"})
	if err != nil {
		t.Fatal(err)
	}
	evidence, coverage := detector.Detect(t.Context(), []model.Observation{{ID: "cname", Type: "dns_record", Status: "answered", Payload: payload}}, model.AttributionView{})
	if len(evidence) != 1 || evidence[0].ProviderID != "edge" || len(coverage) != 1 ||
		coverage[0].Status != model.CoveragePartial || coverage[0].Omitted != 1 ||
		detector.Capability().Status != model.CoveragePartial {
		t.Fatalf("evidence = %#v, coverage = %#v", evidence, coverage)
	}
}
