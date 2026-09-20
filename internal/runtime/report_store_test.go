package runtime

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"cloudattrib/internal/model"
)

func TestStandaloneReportStoreLoadsValidatedReport(t *testing.T) {
	t.Parallel()

	report := model.Report{
		SchemaVersion: model.SchemaVersion, ID: "fixture-report", Target: model.Target{Original: "example.com", Canonical: "example.com", Kind: model.TargetDomain},
		Mode: model.ModeFull, StartedAt: time.Unix(0, 0).UTC(), EndedAt: time.Unix(0, 0).UTC(), ClassifiedAt: time.Unix(0, 0).UTC(),
		BundleID: "old", BuildID: "fixture", Status: model.StatusComplete, Observations: []model.Observation{}, Evidence: []model.Evidence{}, Findings: []model.Finding{}, Coverage: []model.Coverage{}, Warnings: []string{},
	}
	encoded, err := report.CanonicalJSON()
	if err != nil {
		t.Fatalf("CanonicalJSON() error = %v", err)
	}
	path := filepath.Join(t.TempDir(), "report.json")
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		t.Fatalf("write report: %v", err)
	}
	loaded, err := (standaloneReportStore{}).LoadReport(t.Context(), path)
	if err != nil {
		t.Fatalf("LoadReport() error = %v", err)
	}
	if loaded.ID != report.ID {
		t.Fatalf("loaded ID = %q", loaded.ID)
	}
}
