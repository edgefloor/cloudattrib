package datasets

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"cloudattrib/internal/model"
)

func TestLoadSourcesJoinsCloudRangeLifecycleMetadata(t *testing.T) {
	directory := t.TempDir()
	writeCloudRangeFile(t, directory, "example.json", `{
		"provider":"Example Cloud",
		"provider_id":"example-cloud",
		"method":"published_list",
		"coverage_notes":"fixture",
		"generated_at":"2026-09-20T03:31:00.000000",
		"source":["https://example.test/ranges"],
		"ipv4":["192.0.2.1/24","198.51.100.0/24"],
		"ipv6":["2001:db8:1::1/48","2001:db8:2::/48"],
		"details_ipv4":[
			{"address":"192.0.2.0/24","retired_at":"2026-09-20T03:30:53.116812+00:00"},
			{"address":"198.51.100.0/24","region":"active-region"}
		],
		"details_ipv6":[{"address":"2001:db8:2::/48","region":"active-region"}]
	}`)
	writeCloudRangeFile(t, directory, "example-details.json", `{
		"provider":"Example Cloud",
		"provider_id":"example-cloud",
		"method":"published_list",
		"ipv4":[{"address":"198.51.100.0/24","service":"active-service"}],
		"ipv6":[{"address":"2001:db8:1::/48","retired_at":"2026-09-20T03:30:54.000001Z"}]
	}`)

	loaded, err := LoadSources(t.Context(), directory, "build-a")
	if err != nil {
		t.Fatalf("LoadSources() error = %v", err)
	}
	if loaded.Counts.PrefixAssociations != 4 || loaded.Counts.ActiveAssociations != 2 || loaded.Counts.RetiredAssociations != 2 {
		t.Fatalf("LoadSources() counts = %#v", loaded.Counts)
	}
	artifactPaths := make([]string, 0, len(loaded.Candidate.Manifest.Artifacts))
	for _, artifact := range loaded.Candidate.Manifest.Artifacts {
		artifactPaths = append(artifactPaths, artifact.Path)
	}
	if !slices.Contains(artifactPaths, "cloudranges/json/example.json") || !slices.Contains(artifactPaths, "cloudranges/json/example-details.json") {
		t.Fatalf("manifest artifacts = %v", artifactPaths)
	}

	assertLifecycleLookup(t, loaded, "192.0.2.7", "2026-09-20T03:30:53.116812+00:00", "json/example.json#/details_ipv4/0")
	assertLifecycleLookup(t, loaded, "2001:db8:1::7", "2026-09-20T03:30:54.000001Z", "json/example-details.json#/ipv6/0")

	active, _, err := loaded.Prefixes.LookupPrefixes(t.Context(), model.IPLookupRequest{
		Address: mustAddress(t, "198.51.100.7"), Match: "all",
	}, loaded.Candidate.View)
	if err != nil {
		t.Fatalf("LookupPrefixes(active) error = %v", err)
	}
	if len(active) != 1 || active[0].Lifecycle != "active" || active[0].Prefix.String() != "198.51.100.0/24" {
		t.Fatalf("LookupPrefixes(active) = %#v", active)
	}
}

func TestLoadSourcesRejectsInvalidCloudRangeLifecycleJoins(t *testing.T) {
	tests := []struct {
		name      string
		primary   string
		companion string
		want      string
	}{
		{
			name: "invalid known field type",
			primary: `{"provider":"Example","provider_id":"example","ipv4":["192.0.2.0/24"],"ipv6":[],` +
				`"details_ipv4":[{"address":"192.0.2.0/24","retired_at":42}]}`,
			want: "retired_at must be a string",
		},
		{
			name:    "invalid source field type",
			primary: `{"provider":"Example","provider_id":"example","source":42,"ipv4":["192.0.2.0/24"],"ipv6":[]}`,
			want:    "source must be a string or an array of strings",
		},
		{
			name: "malformed retirement timestamp",
			primary: `{"provider":"Example","provider_id":"example","ipv4":["192.0.2.0/24"],"ipv6":[],` +
				`"details_ipv4":[{"address":"192.0.2.0/24","retired_at":"yesterday"}]}`,
			want: "invalid retired_at",
		},
		{
			name: "unsupported lifecycle state",
			primary: `{"provider":"Example","provider_id":"example","ipv4":["192.0.2.0/24"],"ipv6":[],` +
				`"details_ipv4":[{"address":"192.0.2.0/24","lifecycle":"unknown"}]}`,
			want: "unsupported lifecycle state",
		},
		{
			name: "orphan lifecycle record",
			primary: `{"provider":"Example","provider_id":"example","ipv4":["192.0.2.0/24"],"ipv6":[],` +
				`"details_ipv4":[{"address":"198.51.100.0/24","retired_at":"2026-09-20T03:30:53Z"}]}`,
			want: "has no matching primary prefix",
		},
		{
			name:      "companion provider mismatch",
			primary:   `{"provider":"Example","provider_id":"example","ipv4":["192.0.2.0/24"],"ipv6":[]}`,
			companion: `{"provider":"Other","provider_id":"other","ipv4":[{"address":"192.0.2.0/24","retired_at":"2026-09-20T03:30:53Z"}],"ipv6":[]}`,
			want:      "provider mismatch",
		},
		{
			name: "conflicting lifecycle records",
			primary: `{"provider":"Example","provider_id":"example","ipv4":["192.0.2.0/24"],"ipv6":[],` +
				`"details_ipv4":[{"address":"192.0.2.0/24","retired_at":"2026-09-20T03:30:53Z"}]}`,
			companion: `{"provider":"Example","provider_id":"example","ipv4":[` +
				`{"address":"192.0.2.0/24","retired_at":"2026-09-20T03:30:54Z"}],"ipv6":[]}`,
			want: "conflicting retired_at",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			directory := t.TempDir()
			writeCloudRangeFile(t, directory, "example.json", test.primary)
			if test.companion != "" {
				writeCloudRangeFile(t, directory, "example-details.json", test.companion)
			}
			_, err := LoadSources(t.Context(), directory, "build-a")
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("LoadSources() error = %v, want containing %q", err, test.want)
			}
		})
	}
}

func assertLifecycleLookup(t *testing.T, loaded LoadedBundle, address, lifecycleTime, detailRef string) {
	t.Helper()
	current, _, err := loaded.Prefixes.LookupPrefixes(t.Context(), model.IPLookupRequest{
		Address: mustAddress(t, address), Match: "all",
	}, loaded.Candidate.View)
	if err != nil {
		t.Fatalf("LookupPrefixes(%s) error = %v", address, err)
	}
	if len(current) != 0 {
		t.Fatalf("LookupPrefixes(%s) current = %#v, want no retired association", address, current)
	}
	historical, _, err := loaded.Prefixes.LookupPrefixes(t.Context(), model.IPLookupRequest{
		Address: mustAddress(t, address), Match: "all", IncludeRetired: true,
	}, loaded.Candidate.View)
	if err != nil {
		t.Fatalf("LookupPrefixes(%s, include retired) error = %v", address, err)
	}
	if len(historical) != 1 || historical[0].Lifecycle != "retired" || historical[0].LifecycleTime != lifecycleTime {
		t.Fatalf("LookupPrefixes(%s, include retired) = %#v", address, historical)
	}
	if !slices.Contains(historical[0].RecordRefs, detailRef) || historical[0].SourceDigest == "" ||
		historical[0].LifecycleSourceDigest == "" || historical[0].LifecycleRecordRef != detailRef {
		t.Fatalf("LookupPrefixes(%s) provenance = %#v", address, historical[0])
	}
}

func writeCloudRangeFile(t *testing.T, directory, name, content string) {
	t.Helper()
	cloudRanges := filepath.Join(directory, "cloudranges", "json")
	if err := os.MkdirAll(cloudRanges, 0o700); err != nil {
		t.Fatalf("create cloud range directory: %v", err)
	}
	if err := os.WriteFile(filepath.Join(cloudRanges, name), []byte(content), 0o600); err != nil {
		t.Fatalf("write cloud range file: %v", err)
	}
}

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

func TestLoadSourcesPreservesMissingFeedCoverage(t *testing.T) {
	t.Parallel()

	directory := t.TempDir()
	for _, name := range []string{"aws-ip-ranges.json", "iptoasn-v4.tsv", "iptoasn-v6.tsv"} {
		data, err := os.ReadFile(filepath.Join("..", "..", "testdata", "upstream", name))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(directory, name), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	loaded, err := LoadSources(t.Context(), directory, "build-a")
	if err != nil {
		t.Fatalf("LoadSources() error = %v", err)
	}
	states := make(map[string]model.CoverageStatus)
	for _, capability := range loaded.Candidate.View.Capabilities() {
		states[capability.Name] = capability.Status
	}
	if states["prefix"] != model.CoveragePartial || states["prefix_source/gcp-cloud-ranges"] != model.CoverageUnavailable || states["asn"] != model.CoverageComplete {
		t.Fatalf("capability states = %#v", states)
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
