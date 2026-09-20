package prefix

import (
	"context"
	"net/netip"
	"testing"

	"cloudattrib/internal/model"
)

func TestLookupAllAndLongestPreserveTiesAndSkipRetired(t *testing.T) {
	t.Parallel()

	index := New([]model.Association{
		{ID: "cloud", Prefix: netip.MustParsePrefix("198.51.0.0/16"), ProviderID: "example-cloud", Lifecycle: "active", SourceID: "fixture"},
		{ID: "cdn", Prefix: netip.MustParsePrefix("198.51.100.0/24"), ProviderID: "example-cdn", ProductID: "example-cdn.delivery", Lifecycle: "active", SourceID: "fixture"},
		{ID: "service", Prefix: netip.MustParsePrefix("198.51.100.0/24"), ProviderID: "example-cloud", ProductID: "example.service", Lifecycle: "active", SourceID: "fixture"},
		{ID: "retired", Prefix: netip.MustParsePrefix("198.51.100.0/25"), ProviderID: "former", Lifecycle: "retired", SourceID: "fixture"},
	})
	address := netip.MustParseAddr("198.51.100.7")
	all, _, err := index.LookupPrefixes(context.Background(), model.IPLookupRequest{Address: address, Match: "all"}, model.AttributionView{})
	if err != nil {
		t.Fatalf("LookupPrefixes(all) error = %v", err)
	}
	if len(all) != 3 {
		t.Fatalf("LookupPrefixes(all) count = %d, want 3", len(all))
	}
	longest, _, err := index.LookupPrefixes(context.Background(), model.IPLookupRequest{Address: address, Match: "longest"}, model.AttributionView{})
	if err != nil {
		t.Fatalf("LookupPrefixes(longest) error = %v", err)
	}
	if len(longest) != 2 || longest[0].Prefix.Bits() != 24 || longest[1].Prefix.Bits() != 24 {
		t.Fatalf("LookupPrefixes(longest) = %#v", longest)
	}
	historical, _, err := index.LookupPrefixes(context.Background(), model.IPLookupRequest{Address: address, Match: "longest", IncludeRetired: true}, model.AttributionView{})
	if err != nil {
		t.Fatalf("LookupPrefixes(historical) error = %v", err)
	}
	if len(historical) != 1 || historical[0].ID != "retired" {
		t.Fatalf("LookupPrefixes(historical) = %#v", historical)
	}
}

func TestIndexCopiesAssociations(t *testing.T) {
	t.Parallel()

	associations := []model.Association{{ID: "one", Prefix: netip.MustParsePrefix("203.0.113.0/24"), ProviderID: "original", Lifecycle: "active"}}
	index := New(associations)
	associations[0].ProviderID = "changed"
	result, _, err := index.LookupPrefixes(context.Background(), model.IPLookupRequest{Address: netip.MustParseAddr("203.0.113.1")}, model.AttributionView{})
	if err != nil {
		t.Fatalf("LookupPrefixes() error = %v", err)
	}
	result[0].ProviderID = "changed-again"
	second, _, err := index.LookupPrefixes(context.Background(), model.IPLookupRequest{Address: netip.MustParseAddr("203.0.113.1")}, model.AttributionView{})
	if err != nil {
		t.Fatalf("LookupPrefixes() second error = %v", err)
	}
	if second[0].ProviderID != "original" {
		t.Fatalf("stored provider = %q, want original", second[0].ProviderID)
	}
}
