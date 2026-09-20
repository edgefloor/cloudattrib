package prefix

import (
	"context"
	"fmt"
	"math/rand"
	"net/netip"
	"slices"
	"testing"

	"cloudattrib/internal/model"
)

func BenchmarkLookupPrefixes(b *testing.B) {
	associations := make([]model.Association, 0, 4096)
	for index := 0; index < 4096; index++ {
		prefix := netip.MustParsePrefix(fmt.Sprintf("10.%d.%d.0/24", index/256, index%256))
		associations = append(associations, model.Association{ID: fmt.Sprintf("record-%d", index), Prefix: prefix, ProviderID: "fixture", Lifecycle: "active"})
	}
	index := New(associations)
	request := model.IPLookupRequest{Address: netip.MustParseAddr("10.15.255.7"), Match: "all"}
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if _, _, err := index.LookupPrefixes(context.Background(), request, model.AttributionView{}); err != nil {
			b.Fatal(err)
		}
	}
}

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

func TestLookupLongestWithoutEligibleMatches(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name         string
		associations []model.Association
	}{
		{name: "empty index"},
		{name: "nonmatching prefix", associations: []model.Association{{ID: "other", Prefix: netip.MustParsePrefix("203.0.113.0/24"), Lifecycle: "active"}}},
		{name: "retired match excluded", associations: []model.Association{{ID: "retired", Prefix: netip.MustParsePrefix("198.51.100.0/24"), Lifecycle: "retired"}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			index := New(test.associations)
			matches, coverage, err := index.LookupPrefixes(context.Background(), model.IPLookupRequest{
				Address: netip.MustParseAddr("198.51.100.7"), Match: "longest",
			}, model.AttributionView{})
			if err != nil {
				t.Fatalf("LookupPrefixes(longest) error = %v", err)
			}
			if len(matches) != 0 || coverage.Status != model.CoverageComplete {
				t.Fatalf("LookupPrefixes(longest) = %v, coverage = %v; want no matches and complete lookup coverage", matches, coverage)
			}
		})
	}
}

func TestLookupPrefixesRejectsUnknownMatchMode(t *testing.T) {
	t.Parallel()

	index := New(nil)
	_, _, err := index.LookupPrefixes(context.Background(), model.IPLookupRequest{
		Address: netip.MustParseAddr("198.51.100.7"), Match: "shortest",
	}, model.AttributionView{})
	if model.ErrorCodeOf(err) != model.CodeInvalidOptions {
		t.Fatalf("LookupPrefixes() error = %v, want invalid options", err)
	}
}

func TestIndexAgreesWithBruteForceOracle(t *testing.T) {
	t.Parallel()

	random := rand.New(rand.NewSource(20260920))
	associations := make([]model.Association, 0, 500)
	for number := range 500 {
		var address netip.Addr
		var bits int
		if number%2 == 0 {
			address = netip.AddrFrom4([4]byte{byte(random.Uint32()), byte(random.Uint32()), byte(random.Uint32()), byte(random.Uint32())})
			bits = random.Intn(33)
		} else {
			var raw [16]byte
			_, _ = random.Read(raw[:])
			address = netip.AddrFrom16(raw)
			bits = random.Intn(129)
		}
		associations = append(associations, model.Association{
			ID: fmt.Sprintf("oracle-%03d", number), Prefix: netip.PrefixFrom(address, bits).Masked(),
			ProviderID: "fixture", Lifecycle: "active",
		})
	}
	index := New(associations)
	for sample := range 1000 {
		var address netip.Addr
		if sample%2 == 0 {
			address = netip.AddrFrom4([4]byte{byte(random.Uint32()), byte(random.Uint32()), byte(random.Uint32()), byte(random.Uint32())})
		} else {
			var raw [16]byte
			_, _ = random.Read(raw[:])
			address = netip.AddrFrom16(raw)
		}
		for _, mode := range []string{"all", "longest"} {
			got, _, err := index.LookupPrefixes(context.Background(), model.IPLookupRequest{Address: address, Match: mode}, model.AttributionView{})
			if err != nil {
				t.Fatalf("sample %d mode %s: %v", sample, mode, err)
			}
			want := bruteForceIDs(associations, address, mode)
			gotIDs := make([]string, len(got))
			for position, association := range got {
				gotIDs[position] = association.ID
			}
			slices.Sort(gotIDs)
			if !slices.Equal(gotIDs, want) {
				t.Fatalf("sample %d address %s mode %s: got %v, want %v", sample, address, mode, gotIDs, want)
			}
		}
	}
}

func bruteForceIDs(associations []model.Association, address netip.Addr, mode string) []string {
	longest := -1
	for _, association := range associations {
		if association.Prefix.Contains(address) && association.Prefix.Bits() > longest {
			longest = association.Prefix.Bits()
		}
	}
	var result []string
	for _, association := range associations {
		if !association.Prefix.Contains(address) || mode == "longest" && association.Prefix.Bits() != longest {
			continue
		}
		result = append(result, association.ID)
	}
	slices.Sort(result)
	return result
}
