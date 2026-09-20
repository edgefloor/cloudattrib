package datasets

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"cloudattrib/internal/model"
)

func BenchmarkLoadSources(b *testing.B) {
	directory := b.TempDir()
	fixtures := map[string]string{
		"aws-ip-ranges.json":         "../../testdata/upstream/aws-ip-ranges.json",
		"gcp-cloud.json":             "../../testdata/upstream/gcp-cloud.json",
		"azure-service-tags.json":    "../../testdata/upstream/azure-service-tags.json",
		"cdncheck-sources-data.json": "../../testdata/upstream/cdncheck-sources-data.json",
		"iptoasn-v4.tsv":             "../../testdata/upstream/iptoasn-v4.tsv",
		"iptoasn-v6.tsv":             "../../testdata/upstream/iptoasn-v6.tsv",
	}
	for target, source := range fixtures {
		data, err := os.ReadFile(source)
		if err != nil {
			b.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(directory, target), data, 0o600); err != nil {
			b.Fatal(err)
		}
	}
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if _, err := LoadSources(context.Background(), directory, "benchmark-build"); err != nil {
			b.Fatal(err)
		}
	}
}

func TestLoadSourcesBuildsOfflinePrefixAndASNIndexes(t *testing.T) {
	t.Parallel()

	directory := t.TempDir()
	fixtures := map[string]string{
		"aws-ip-ranges.json":         "../../testdata/upstream/aws-ip-ranges.json",
		"gcp-cloud.json":             "../../testdata/upstream/gcp-cloud.json",
		"azure-service-tags.json":    "../../testdata/upstream/azure-service-tags.json",
		"cdncheck-sources-data.json": "../../testdata/upstream/cdncheck-sources-data.json",
		"iptoasn-v4.tsv":             "../../testdata/upstream/iptoasn-v4.tsv",
		"iptoasn-v6.tsv":             "../../testdata/upstream/iptoasn-v6.tsv",
	}
	for target, source := range fixtures {
		data, err := os.ReadFile(source)
		if err != nil {
			t.Fatalf("read fixture %s: %v", source, err)
		}
		if err := os.WriteFile(filepath.Join(directory, target), data, 0o600); err != nil {
			t.Fatalf("write fixture %s: %v", target, err)
		}
	}
	loaded, err := LoadSources(context.Background(), directory, "build-a")
	if err != nil {
		t.Fatalf("LoadSources() error = %v", err)
	}
	if loaded.Prefixes == nil || loaded.ASN == nil || loaded.Counts.PrefixAssociations < 3 || loaded.Counts.ASNIntervals < 2 {
		t.Fatalf("LoadSources() = %#v", loaded.Counts)
	}
	if loaded.Candidate.Manifest.BundleID == "" || loaded.Candidate.View.BundleID() != loaded.Candidate.Manifest.BundleID {
		t.Fatalf("candidate identity = %#v", loaded.Candidate.Manifest)
	}
	associations, coverage, err := loaded.Prefixes.LookupPrefixes(context.Background(), model.IPLookupRequest{
		Address: mustAddress(t, "192.0.2.1"), Match: "all",
	}, loaded.Candidate.View)
	if err != nil || len(associations) == 0 || coverage.Status != model.CoverageComplete {
		t.Fatalf("LookupPrefixes() = %#v, %#v, %v", associations, coverage, err)
	}
	records, coverage, err := loaded.ASN.LookupASN(context.Background(), mustAddress(t, "192.0.2.1"), loaded.Candidate.View)
	if err != nil || len(records) == 0 || coverage.Status != model.CoverageComplete {
		t.Fatalf("LookupASN() = %#v, %#v, %v", records, coverage, err)
	}
}

func TestLoadSourcesRejectsMalformedPresentSource(t *testing.T) {
	t.Parallel()

	directory := t.TempDir()
	if err := os.WriteFile(filepath.Join(directory, "aws-ip-ranges.json"), []byte(`{"truncated":`), 0o600); err != nil {
		t.Fatalf("write source: %v", err)
	}
	if _, err := LoadSources(context.Background(), directory, "build-a"); err == nil {
		t.Fatal("LoadSources() error = nil, want malformed-source error")
	}
}

func mustAddress(t *testing.T, value string) netip.Addr {
	t.Helper()
	address, err := netip.ParseAddr(value)
	if err != nil {
		t.Fatalf("parse address: %v", err)
	}
	return address
}
