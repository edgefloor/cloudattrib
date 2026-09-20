package app

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"cloudattrib/internal/model"
)

func TestReclassifyPreservesCaptureAndUsesNewClassificationProvenance(t *testing.T) {
	t.Parallel()

	observedAt := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	original := model.Report{
		ID: "original-report", Target: model.Target{Canonical: "example.com", Kind: model.TargetDomain}, Mode: model.ModeFull,
		BundleID: "old-bundle", ClassifiedAt: observedAt, Observations: []model.Observation{{ID: "obs-1", Type: "dns_record", Subject: "example.com", ObservedAt: observedAt, Status: "answered", Payload: model.JSONValue(`{"rrtype":"TXT","owner":"example.com","value":"fixture"}`)}},
		Coverage: []model.Coverage{{Capability: "dns", Status: model.CoverageComplete, Attempted: 1, Completed: 1}},
	}
	classifiedAt := time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC)
	service := NewService(Dependencies{
		Detectors: []Detector{fixtureReplayDetector{}},
		Store:     fixtureResultStore{report: original},
		View:      model.NewAttributionView("new-bundle", "policy-v1", []string{"fixture-v2"}, nil),
		Now:       func() time.Time { return classifiedAt },
	})

	replayed, err := service.Reclassify(context.Background(), model.ReclassifyRequest{ReportID: original.ID, BundleID: "new-bundle"})
	if err != nil {
		t.Fatalf("Reclassify() error = %v", err)
	}
	if replayed.OriginalReportID != original.ID || replayed.BundleID != "new-bundle" || replayed.ClassifiedAt != classifiedAt {
		t.Fatalf("replayed provenance = %#v", replayed)
	}
	if len(replayed.Observations) != 1 || replayed.Observations[0].ObservedAt != observedAt || string(replayed.Observations[0].Payload) != string(original.Observations[0].Payload) {
		t.Fatalf("replayed observations changed: %#v", replayed.Observations)
	}
	if len(replayed.Evidence) != 1 || replayed.Evidence[0].ClassifiedAt != classifiedAt || replayed.Evidence[0].DatasetRecords[0].Revision != "new-revision" || replayed.Evidence[0].DatasetRecords[0].EffectiveAt != nil {
		t.Fatalf("replayed evidence = %#v", replayed.Evidence)
	}
}

func TestReclassifyRequiresUsableReplayPath(t *testing.T) {
	t.Parallel()

	service := NewService(Dependencies{Store: fixtureResultStore{report: model.Report{ID: "original"}}, View: model.NewAttributionView("bundle", "policy", nil, nil)})
	_, err := service.Reclassify(context.Background(), model.ReclassifyRequest{ReportID: "original", BundleID: "bundle"})
	if model.ErrorCodeOf(err) != model.CodeCapabilityUnavailable {
		t.Fatalf("Reclassify() error = %v, want capability_unavailable", err)
	}
}

func TestReclassifyReusesRetainedRawTechnologyLabel(t *testing.T) {
	t.Parallel()

	payload, _ := json.Marshal(model.TechnologyPayload{Name: "Vue.js", DetectorID: "wappalyzergo-v0.3.2"})
	original := model.Report{
		ID: "technology-report", Target: model.Target{Canonical: "example.com", Kind: model.TargetDomain},
		Observations: []model.Observation{{ID: "tech-1", Type: "technology", Subject: "example.com", Scope: model.ScopeRoot, Status: "detected", Payload: payload}},
	}
	service := NewService(Dependencies{
		Detectors: []Detector{emptyReplayDetector{}}, Store: fixtureResultStore{report: original},
		View: model.NewAttributionView("bundle", "policy", nil, nil),
	})
	replayed, err := service.Reclassify(context.Background(), model.ReclassifyRequest{ReportID: original.ID, BundleID: "bundle"})
	if err != nil {
		t.Fatalf("Reclassify() error = %v", err)
	}
	if len(replayed.Evidence) != 1 || replayed.Evidence[0].ProductID != "webtech.vue-js" || replayed.Evidence[0].ObservationIDs[0] != "tech-1" {
		t.Fatalf("replayed evidence = %#v", replayed.Evidence)
	}
}

type fixtureResultStore struct{ report model.Report }

func (s fixtureResultStore) SaveReport(context.Context, model.Report) error { return nil }
func (s fixtureResultStore) LoadReport(context.Context, string) (model.Report, error) {
	return s.report, nil
}

type fixtureReplayDetector struct{}

func (fixtureReplayDetector) Detect(_ context.Context, observations []model.Observation, _ model.AttributionView) ([]model.Evidence, []model.Coverage) {
	return []model.Evidence{{
		ID: "replayed-evidence", ObservationIDs: []string{observations[0].ID}, DetectorID: "fixture-v2", Subject: observations[0].Subject,
		ProductID: "fixture.product", Relation: model.RelationDomainVerification, Strength: model.StrengthWeak, Activity: model.ActivityVerificationOnly,
		DatasetRecords: []model.DatasetRecord{{SourceID: "fixture", Revision: "new-revision", Digest: "sha256:new", RecordRef: "fixture#/1"}},
	}}, []model.Coverage{{Capability: "fixture-replay", Status: model.CoverageComplete, Attempted: 1, Completed: 1}}
}

type emptyReplayDetector struct{}

func (emptyReplayDetector) Detect(context.Context, []model.Observation, model.AttributionView) ([]model.Evidence, []model.Coverage) {
	return nil, []model.Coverage{{Capability: "rules", Status: model.CoverageComplete}}
}
