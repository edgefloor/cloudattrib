package model

import (
	"bytes"
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
