package model

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"
)

func TestReportCanonicalJSONIsDeterministic(t *testing.T) {
	t.Parallel()

	observed := time.Date(2026, 9, 20, 8, 0, 0, 0, time.UTC)
	base := Report{
		SchemaVersion: "1",
		ID:            "report-1",
		Target:        Target{Original: "example.com", Canonical: "example.com", Kind: TargetDomain},
		Mode:          ModeFull,
		Status:        StatusComplete,
		Observations: []Observation{
			{ID: "obs-b", Type: "dns", Subject: "www.example.com", ObservedAt: observed, Status: "answered", Payload: JSONValue(`{"rrtype":"CNAME"}`)},
			{ID: "obs-a", Type: "dns", Subject: "example.com", ObservedAt: observed, Status: "answered", Payload: JSONValue(`{"rrtype":"NS"}`)},
		},
		Evidence: []Evidence{
			{ID: "ev-b", ObservationIDs: []string{"obs-b"}, Subject: "www.example.com", ProviderID: "aws", ProductID: "aws.cloudfront", Relation: RelationWebDelivery, Strength: StrengthStrong},
			{ID: "ev-a", ObservationIDs: []string{"obs-a"}, Subject: "example.com", ProviderID: "example-dns", Relation: RelationAuthoritativeDNS, Strength: StrengthStrong},
		},
		Findings: []Finding{
			{ID: "finding-b", Subject: "www.example.com", ProviderID: "aws", ProductID: "aws.cloudfront", Relation: RelationWebDelivery, EvidenceIDs: []string{"ev-b"}},
			{ID: "finding-a", Subject: "example.com", ProviderID: "example-dns", Relation: RelationAuthoritativeDNS, EvidenceIDs: []string{"ev-a"}},
		},
		Coverage: []Coverage{{Capability: "http", Status: CoverageComplete}, {Capability: "dns", Status: CoverageComplete}},
	}

	a, err := base.CanonicalJSON()
	if err != nil {
		t.Fatalf("CanonicalJSON() error = %v", err)
	}
	shuffled := base.Clone()
	shuffled.Observations[0], shuffled.Observations[1] = shuffled.Observations[1], shuffled.Observations[0]
	shuffled.Evidence[0], shuffled.Evidence[1] = shuffled.Evidence[1], shuffled.Evidence[0]
	shuffled.Findings[0], shuffled.Findings[1] = shuffled.Findings[1], shuffled.Findings[0]
	shuffled.Coverage[0], shuffled.Coverage[1] = shuffled.Coverage[1], shuffled.Coverage[0]
	b, err := shuffled.CanonicalJSON()
	if err != nil {
		t.Fatalf("CanonicalJSON() shuffled error = %v", err)
	}
	if !bytes.Equal(a, b) {
		t.Fatalf("canonical output differs:\n%s\n%s", a, b)
	}
}

func TestReportCloneOwnsMutableData(t *testing.T) {
	t.Parallel()

	original := Report{
		Warnings:     []string{"one"},
		Observations: []Observation{{ID: "obs", Payload: JSONValue(`{"value":"original"}`)}},
		Evidence:     []Evidence{{ID: "ev", ObservationIDs: []string{"obs"}}},
		Findings:     []Finding{{ID: "finding", EvidenceIDs: []string{"ev"}, Limitations: []string{"limit"}}},
	}
	clone := original.Clone()
	clone.Warnings[0] = "changed"
	clone.Observations[0].Payload[0] = '['
	clone.Evidence[0].ObservationIDs[0] = "changed"
	clone.Findings[0].Limitations[0] = "changed"

	if original.Warnings[0] != "one" || original.Observations[0].Payload[0] != '{' || original.Evidence[0].ObservationIDs[0] != "obs" || original.Findings[0].Limitations[0] != "limit" {
		t.Fatalf("mutating clone changed original: %#v", original)
	}
}

func TestReportValidatesReferences(t *testing.T) {
	t.Parallel()

	report := Report{
		Observations: []Observation{{ID: "obs"}},
		Evidence:     []Evidence{{ID: "ev", ObservationIDs: []string{"missing"}}},
		Findings:     []Finding{{ID: "finding", EvidenceIDs: []string{"ev"}}},
	}
	if err := report.ValidateReferences(); err == nil {
		t.Fatal("ValidateReferences() error = nil, want unresolved observation error")
	}
}

func TestContentIDIgnoresInputOrder(t *testing.T) {
	t.Parallel()

	a := Report{Observations: []Observation{{ID: "b"}, {ID: "a"}}}
	b := Report{Observations: []Observation{{ID: "a"}, {ID: "b"}}}
	idA, err := a.ContentID()
	if err != nil {
		t.Fatalf("ContentID() first error = %v", err)
	}
	idB, err := b.ContentID()
	if err != nil {
		t.Fatalf("ContentID() second error = %v", err)
	}
	if idA != idB {
		t.Fatalf("ContentID() = %q and %q, want equal", idA, idB)
	}
}

func TestReportCanonicalJSONEmitsRequiredCollectionsAsArrays(t *testing.T) {
	t.Parallel()

	emptyEncoded, err := (Report{}).CanonicalJSON()
	if err != nil {
		t.Fatalf("empty CanonicalJSON() error = %v", err)
	}
	var emptyDocument map[string]json.RawMessage
	if err := json.Unmarshal(emptyEncoded, &emptyDocument); err != nil {
		t.Fatalf("decode empty report: %v", err)
	}
	for _, field := range []string{"observations", "evidence", "findings", "coverage", "warnings"} {
		if !bytes.Equal(emptyDocument[field], []byte("[]")) {
			t.Errorf("empty %s = %s, want []", field, emptyDocument[field])
		}
	}

	report := Report{
		Evidence: []Evidence{{ID: "evidence-1"}},
		Findings: []Finding{{
			ID: "finding-1", Subject: "example.com", ProductID: "webtech.react", Category: "web_technology",
			Relation: RelationWebIntegration, Strength: StrengthModerate, EvidenceIDs: []string{"evidence-1"},
		}},
	}
	encoded, err := report.CanonicalJSON()
	if err != nil {
		t.Fatalf("CanonicalJSON() error = %v", err)
	}
	var document map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &document); err != nil {
		t.Fatalf("decode report: %v", err)
	}
	var evidence []map[string]json.RawMessage
	if err := json.Unmarshal(document["evidence"], &evidence); err != nil {
		t.Fatalf("decode evidence: %v", err)
	}
	for _, field := range []string{"observation_ids", "dataset_records"} {
		if bytes.Equal(evidence[0][field], []byte("null")) {
			t.Errorf("evidence.%s = null, want array", field)
		}
	}
	var findings []map[string]json.RawMessage
	if err := json.Unmarshal(document["findings"], &findings); err != nil {
		t.Fatalf("decode findings: %v", err)
	}
	if _, exists := findings[0]["provider_id"]; exists {
		t.Errorf("technology-only finding has provider_id: %s", findings[0]["provider_id"])
	}
}

func TestReportValidatesFindingProviderContract(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		finding Finding
		valid   bool
	}{
		{name: "provider finding", finding: Finding{ID: "finding-1", ProviderID: "aws", EvidenceIDs: []string{"evidence-1"}}, valid: true},
		{name: "technology-only finding", finding: Finding{ID: "finding-1", ProductID: "webtech.react", Category: "web_technology", Relation: RelationWebIntegration, EvidenceIDs: []string{"evidence-1"}}, valid: true},
		{name: "missing product", finding: Finding{ID: "finding-1", Category: "web_technology", Relation: RelationWebIntegration, EvidenceIDs: []string{"evidence-1"}}},
		{name: "wrong category", finding: Finding{ID: "finding-1", ProductID: "webtech.react", Category: "framework", Relation: RelationWebIntegration, EvidenceIDs: []string{"evidence-1"}}},
		{name: "wrong relation", finding: Finding{ID: "finding-1", ProductID: "webtech.react", Category: "web_technology", Relation: RelationWebDelivery, EvidenceIDs: []string{"evidence-1"}}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			report := Report{Evidence: []Evidence{{ID: "evidence-1"}}, Findings: []Finding{test.finding}}
			err := report.ValidateReferences()
			if test.valid && err != nil {
				t.Fatalf("ValidateReferences() error = %v", err)
			}
			if !test.valid && err == nil {
				t.Fatal("ValidateReferences() error = nil")
			}
		})
	}
}
