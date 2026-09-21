package datasets

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"cloudattrib/internal/ingest/cloudranges"
	"cloudattrib/internal/model"
)

func TestPinnedCloudRangesLifecycleReconciliation(t *testing.T) {
	directory := os.Getenv("CLOUDATTRIB_PINNED_DATASET_DIR")
	if directory == "" {
		t.Skip("CLOUDATTRIB_PINNED_DATASET_DIR is not set")
	}

	loaded, err := LoadSources(context.Background(), directory, "qualification-build")
	if err != nil {
		t.Fatalf("LoadSources() error = %v", err)
	}
	expected := readExpectedCloudRangeLifecycle(t, directory)
	sourceRecords := make(map[string]int)
	for _, source := range loaded.Candidate.Manifest.Sources {
		sourceRecords[source.ID] = source.Records
	}

	providerIDs := make([]string, 0, len(expected))
	for providerID := range expected {
		providerIDs = append(providerIDs, providerID)
	}
	slices.Sort(providerIDs)
	retiredTotal := 0
	activeTotal := 0
	for _, providerID := range providerIDs {
		provider := expected[providerID]
		active := 0
		retired := 0
		for key, prefix := range provider.prefixes {
			matches, _, err := loaded.Prefixes.LookupPrefixes(t.Context(), model.IPLookupRequest{
				Address: prefix.Addr(), Match: "all", IncludeRetired: true,
			}, loaded.Candidate.View)
			if err != nil {
				t.Fatalf("lookup %s %s: %v", providerID, key, err)
			}
			association, found := exactCloudRangeAssociation(matches, providerID, prefix)
			if !found {
				t.Fatalf("provider %s prefix %s was not imported", providerID, key)
			}
			if association.SourceDigest != provider.primaryDigest || association.SourceRevision != provider.primaryDigest {
				t.Fatalf("provider %s prefix %s primary provenance = %#v", providerID, key, association)
			}
			lifecycle, wantRetired := provider.retired[key]
			if !wantRetired {
				if association.Lifecycle != "active" || association.LifecycleTime != "" {
					t.Fatalf("provider %s prefix %s lifecycle = %q at %q, want active", providerID, key, association.Lifecycle, association.LifecycleTime)
				}
				active++
				continue
			}
			if association.Lifecycle != "retired" || association.LifecycleTime != lifecycle.retiredAt {
				t.Fatalf("provider %s prefix %s lifecycle = %q at %q, want retired at %q", providerID, key, association.Lifecycle, association.LifecycleTime, lifecycle.retiredAt)
			}
			if association.LifecycleSourceDigest != lifecycle.digest || association.LifecycleRecordRef != lifecycle.recordRef ||
				!slices.Contains(association.RecordRefs, lifecycle.recordRef) {
				t.Fatalf("provider %s prefix %s lifecycle provenance = %#v, want digest %s ref %s", providerID, key, association, lifecycle.digest, lifecycle.recordRef)
			}
			retired++
		}
		if got := sourceRecords["disposable/cloud-ip-ranges/"+providerID]; got != len(provider.prefixes) {
			t.Fatalf("provider %s manifest records = %d, want %d", providerID, got, len(provider.prefixes))
		}
		if retired != len(provider.retired) || active+retired != len(provider.prefixes) {
			t.Fatalf("provider %s totals: active=%d retired=%d source_retired=%d total=%d", providerID, active, retired, len(provider.retired), len(provider.prefixes))
		}
		activeTotal += active
		retiredTotal += retired
		t.Logf("provider=%s total=%d active=%d retired=%d", providerID, len(provider.prefixes), active, retired)
	}
	if retiredTotal != loaded.Counts.RetiredAssociations || activeTotal+retiredTotal != 449320 {
		t.Fatalf("broad totals: active=%d retired=%d; bundle counts=%+v", activeTotal, retiredTotal, loaded.Counts)
	}

	assertPinnedRetiredExample(t, loaded)
	t.Logf("broad totals: providers=%d total=%d active=%d retired=%d bundle_prefixes=%d warnings=%d", len(providerIDs), activeTotal+retiredTotal, activeTotal, retiredTotal, loaded.Counts.PrefixAssociations, len(loaded.Warnings))
}

type expectedCloudProvider struct {
	prefixes      map[string]netip.Prefix
	retired       map[string]expectedRetirement
	primaryDigest string
}

type expectedRetirement struct {
	retiredAt string
	digest    string
	recordRef string
}

type rawCloudDocument struct {
	ProviderID  string            `json:"provider_id"`
	IPv4        []json.RawMessage `json:"ipv4"`
	IPv6        []json.RawMessage `json:"ipv6"`
	DetailsIPv4 []rawCloudDetail  `json:"details_ipv4"`
	DetailsIPv6 []rawCloudDetail  `json:"details_ipv6"`
}

type rawCloudDetail struct {
	Address   string  `json:"address"`
	RetiredAt *string `json:"retired_at"`
}

func readExpectedCloudRangeLifecycle(t *testing.T, directory string) map[string]expectedCloudProvider {
	t.Helper()
	jsonDirectory := filepath.Join(directory, "cloudranges", "json")
	entries, err := os.ReadDir(jsonDirectory)
	if err != nil {
		t.Fatalf("read cloud range directory: %v", err)
	}
	providers := make(map[string]expectedCloudProvider)
	for _, entry := range entries {
		relative := filepath.ToSlash(filepath.Join("json", entry.Name()))
		if entry.IsDir() || !cloudranges.PrimaryFile(relative) {
			continue
		}
		primaryPath := filepath.Join(jsonDirectory, entry.Name())
		primaryData, primaryDigest := readLifecycleFixture(t, primaryPath)
		var document rawCloudDocument
		if err := json.Unmarshal(primaryData, &document); err != nil {
			t.Fatalf("parse %s: %v", primaryPath, err)
		}
		provider := expectedCloudProvider{
			prefixes: make(map[string]netip.Prefix), retired: make(map[string]expectedRetirement), primaryDigest: primaryDigest,
		}
		addRawPrefixes(t, provider.prefixes, document.IPv4, true, primaryPath)
		addRawPrefixes(t, provider.prefixes, document.IPv6, false, primaryPath)
		addExpectedRetirements(t, provider, document.DetailsIPv4, true, primaryDigest, relative+"#/details_ipv4/")
		addExpectedRetirements(t, provider, document.DetailsIPv6, false, primaryDigest, relative+"#/details_ipv6/")

		companionName := strings.TrimSuffix(entry.Name(), ".json") + "-details.json"
		companionPath := filepath.Join(jsonDirectory, companionName)
		companionData, companionDigest, err := readOptionalLifecycleFixture(companionPath)
		if err != nil {
			t.Fatalf("read %s: %v", companionPath, err)
		}
		if companionData != nil {
			var companion rawCloudDocument
			if err := json.Unmarshal(companionData, &companion); err != nil {
				t.Fatalf("parse %s: %v", companionPath, err)
			}
			if companion.ProviderID != document.ProviderID {
				t.Fatalf("companion provider %q does not match %q", companion.ProviderID, document.ProviderID)
			}
			ipv4 := rawDetailsFromMessages(t, companion.IPv4, companionPath)
			ipv6 := rawDetailsFromMessages(t, companion.IPv6, companionPath)
			companionRelative := filepath.ToSlash(filepath.Join("json", companionName))
			addExpectedRetirements(t, provider, ipv4, true, companionDigest, companionRelative+"#/ipv4/")
			addExpectedRetirements(t, provider, ipv6, false, companionDigest, companionRelative+"#/ipv6/")
		}
		providers[document.ProviderID] = provider
	}
	return providers
}

func addRawPrefixes(t *testing.T, prefixes map[string]netip.Prefix, entries []json.RawMessage, wantV4 bool, path string) {
	t.Helper()
	for number, entry := range entries {
		var address string
		if err := json.Unmarshal(entry, &address); err != nil {
			var detail rawCloudDetail
			if objectErr := json.Unmarshal(entry, &detail); objectErr != nil {
				t.Fatalf("parse %s entry %d: %v", path, number, err)
			}
			address = detail.Address
		}
		prefix, err := netip.ParsePrefix(address)
		if err != nil || prefix.Addr().Is4() != wantV4 {
			t.Fatalf("parse %s prefix %q: %v", path, address, err)
		}
		prefix = prefix.Masked()
		prefixes[prefix.String()] = prefix
	}
}

func addExpectedRetirements(t *testing.T, provider expectedCloudProvider, details []rawCloudDetail, wantV4 bool, digest, refPrefix string) {
	t.Helper()
	for number, detail := range details {
		prefix, err := netip.ParsePrefix(detail.Address)
		if err != nil || prefix.Addr().Is4() != wantV4 {
			t.Fatalf("parse lifecycle prefix %q: %v", detail.Address, err)
		}
		key := prefix.Masked().String()
		if _, ok := provider.prefixes[key]; !ok {
			t.Fatalf("lifecycle prefix %s has no primary association", key)
		}
		if detail.RetiredAt == nil {
			continue
		}
		next := expectedRetirement{retiredAt: *detail.RetiredAt, digest: digest, recordRef: fmt.Sprintf("%s%d", refPrefix, number)}
		if current, exists := provider.retired[key]; exists && current.retiredAt != next.retiredAt {
			t.Fatalf("conflicting lifecycle for %s: %#v and %#v", key, current, next)
		}
		if _, exists := provider.retired[key]; !exists {
			provider.retired[key] = next
		}
	}
}

func rawDetailsFromMessages(t *testing.T, entries []json.RawMessage, path string) []rawCloudDetail {
	t.Helper()
	details := make([]rawCloudDetail, 0, len(entries))
	for number, entry := range entries {
		var detail rawCloudDetail
		if err := json.Unmarshal(entry, &detail); err != nil {
			t.Fatalf("parse %s detail %d: %v", path, number, err)
		}
		details = append(details, detail)
	}
	return details
}

func readLifecycleFixture(t *testing.T, path string) ([]byte, string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	digest := sha256.Sum256(data)
	return data, "sha256:" + hex.EncodeToString(digest[:])
}

func readOptionalLifecycleFixture(path string) ([]byte, string, error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, "", nil
	}
	if err != nil {
		return nil, "", err
	}
	digest := sha256.Sum256(data)
	return data, "sha256:" + hex.EncodeToString(digest[:]), nil
}

func exactCloudRangeAssociation(matches []model.Association, providerID string, prefix netip.Prefix) (model.Association, bool) {
	var found model.Association
	count := 0
	for _, association := range matches {
		if association.SourceID == "disposable/cloud-ip-ranges" && association.ProviderID == providerID && association.Prefix == prefix {
			found = association
			count++
		}
	}
	return found, count == 1
}

func assertPinnedRetiredExample(t *testing.T, loaded LoadedBundle) {
	t.Helper()
	prefix := netip.MustParsePrefix("103.204.128.0/23")
	request := model.IPLookupRequest{Address: netip.MustParseAddr("103.204.128.1"), Match: "all"}
	current, _, err := loaded.Prefixes.LookupPrefixes(t.Context(), request, loaded.Candidate.View)
	if err != nil {
		t.Fatal(err)
	}
	if _, found := exactCloudRangeAssociation(current, "a2hosting", prefix); found {
		t.Fatal("retired a2hosting association appeared in current lookup")
	}
	request.IncludeRetired = true
	historical, _, err := loaded.Prefixes.LookupPrefixes(t.Context(), request, loaded.Candidate.View)
	if err != nil {
		t.Fatal(err)
	}
	association, found := exactCloudRangeAssociation(historical, "a2hosting", prefix)
	if !found || association.Lifecycle != "retired" || association.LifecycleTime != "2026-09-20T03:30:53.116812+00:00" {
		t.Fatalf("historical a2hosting association = %#v, found=%t", association, found)
	}
}
