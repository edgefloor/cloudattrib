package datasets

import (
	"context"
	"os"
	"testing"
)

func TestFullUpstreamImport(t *testing.T) {
	directory := os.Getenv("CLOUDATTRIB_FULL_DATASET_DIR")
	if directory == "" {
		t.Skip("CLOUDATTRIB_FULL_DATASET_DIR is not set")
	}
	loaded, err := LoadSources(context.Background(), directory, "qualification-build")
	if err != nil {
		t.Fatalf("LoadSources() error = %v", err)
	}
	if loaded.Counts.PrefixAssociations == 0 || loaded.Counts.ASNIntervals == 0 {
		t.Fatalf("full import counts = %#v", loaded.Counts)
	}
	t.Logf("bundle=%s counts=%+v warnings=%d", loaded.Candidate.Manifest.BundleID, loaded.Counts, len(loaded.Warnings))
	for _, source := range loaded.Candidate.Manifest.Sources {
		t.Logf("source=%s status=%s records=%d revision=%s", source.ID, source.Status, source.Records, source.Revision)
	}
}
