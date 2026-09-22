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

func TestReportRejectsDuplicateAndDanglingReferences(t *testing.T) {
	t.Parallel()

	validObservation := Observation{ID: "observation-1"}
	validEvidence := Evidence{ID: "evidence-1", ObservationIDs: []string{"observation-1"}}
	validFinding := Finding{ID: "finding-1", ProviderID: "provider-1", EvidenceIDs: []string{"evidence-1"}}
	tests := []struct {
		name   string
		report Report
	}{
		{name: "duplicate observation", report: Report{Observations: []Observation{validObservation, validObservation}}},
		{name: "duplicate evidence", report: Report{Observations: []Observation{validObservation}, Evidence: []Evidence{validEvidence, validEvidence}}},
		{name: "duplicate finding", report: Report{Observations: []Observation{validObservation}, Evidence: []Evidence{validEvidence}, Findings: []Finding{validFinding, validFinding}}},
		{
			name:   "dangling observation",
			report: Report{Evidence: []Evidence{{ID: "evidence-1", ObservationIDs: []string{"missing"}}}},
		},
		{
			name:   "dangling evidence",
			report: Report{Findings: []Finding{{ID: "finding-1", ProviderID: "provider-1", EvidenceIDs: []string{"missing"}}}},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if err := test.report.ValidateReferences(); err == nil {
				t.Fatal("ValidateReferences() error = nil")
			}
		})
	}
}

func TestLegacyReportJSONRetainsHistoricalID(t *testing.T) {
	t.Parallel()

	const legacy = `{"schema_version":"1","report_id":"sha256:legacy","target":{"original":"example.com","canonical":"example.com","kind":"domain"},"mode":"full","started_at":"2026-09-22T08:00:00Z","ended_at":"2026-09-22T08:00:01Z","classified_at":"2026-09-22T08:00:01Z","bundle_id":"bundle-1","build_id":"build-1","status":"complete","observations":[],"evidence":[],"findings":[],"coverage":[],"warnings":[]}`
	var report Report
	if err := json.Unmarshal([]byte(legacy), &report); err != nil {
		t.Fatalf("decode legacy report: %v", err)
	}
	if report.ID != "sha256:legacy" || report.ContentIDVersion != "" {
		t.Fatalf("legacy identity changed: %#v", report)
	}
	encoded, err := report.CanonicalJSON()
	if err != nil {
		t.Fatalf("CanonicalJSON() error = %v", err)
	}
	if !bytes.Contains(encoded, []byte(`"report_id":"sha256:legacy"`)) || bytes.Contains(encoded, []byte(`"content_id_version"`)) {
		t.Fatalf("legacy report identity was rewritten: %s", encoded)
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

func TestContentIDIsStableAfterAssignment(t *testing.T) {
	t.Parallel()

	report := Report{
		SchemaVersion: SchemaVersion,
		Target:        Target{Original: "example.com", Canonical: "example.com", Kind: TargetDomain},
		Mode:          ModeFull,
		StartedAt:     time.Date(2026, 9, 22, 8, 0, 0, 0, time.UTC),
		EndedAt:       time.Date(2026, 9, 22, 8, 0, 1, 0, time.UTC),
		ClassifiedAt:  time.Date(2026, 9, 22, 8, 0, 1, 0, time.UTC),
		Status:        StatusComplete,
	}
	first, err := report.ContentID()
	if err != nil {
		t.Fatalf("ContentID() before assignment error = %v", err)
	}
	report.ID = first
	second, err := report.ContentID()
	if err != nil {
		t.Fatalf("ContentID() after assignment error = %v", err)
	}
	if first != second {
		t.Fatalf("ContentID() changed after assignment: %q != %q", first, second)
	}
}

func TestContentIDCanonicalizesNestedJSONNumbersAndObjectKeys(t *testing.T) {
	t.Parallel()

	a := Report{Observations: []Observation{{
		ID: "observation-1", Payload: JSONValue(`{"outer":{"first":1.00,"nested":{"a":1e3,"b":0.0100}},"second":2}`),
	}}}
	b := Report{Observations: []Observation{{
		ID: "observation-1", Payload: JSONValue(`{"second":2.0,"outer":{"nested":{"b":1e-2,"a":1000.0},"first":1}}`),
	}}}
	idA, err := a.ContentID()
	if err != nil {
		t.Fatalf("ContentID() first error = %v", err)
	}
	idB, err := b.ContentID()
	if err != nil {
		t.Fatalf("ContentID() second error = %v", err)
	}
	if idA != idB {
		t.Fatalf("ContentID() = %q and %q, want recursively equivalent JSON to match", idA, idB)
	}
}

func TestContentIDNormalizesEquivalentTimestamps(t *testing.T) {
	t.Parallel()

	utc := time.Date(2026, 9, 22, 8, 0, 0, 123456000, time.UTC)
	offset := time.FixedZone("fixture", 2*60*60)
	local := utc.In(offset)
	a := Report{StartedAt: utc, Observations: []Observation{{ID: "observation-1", ObservedAt: utc}}}
	b := Report{StartedAt: local, Observations: []Observation{{ID: "observation-1", ObservedAt: local}}}
	idA, err := a.ContentID()
	if err != nil {
		t.Fatalf("ContentID() UTC error = %v", err)
	}
	idB, err := b.ContentID()
	if err != nil {
		t.Fatalf("ContentID() offset error = %v", err)
	}
	if idA != idB {
		t.Fatalf("ContentID() = %q and %q, want equivalent timestamps to match", idA, idB)
	}
}

func TestContentIDChangesWhenParticipatingFieldChanges(t *testing.T) {
	t.Parallel()

	a := Report{Target: Target{Canonical: "example.com"}}
	b := Report{Target: Target{Canonical: "www.example.com"}}
	idA, err := a.ContentID()
	if err != nil {
		t.Fatalf("ContentID() first error = %v", err)
	}
	idB, err := b.ContentID()
	if err != nil {
		t.Fatalf("ContentID() second error = %v", err)
	}
	if idA == idB {
		t.Fatalf("ContentID() = %q for reports with different targets", idA)
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
