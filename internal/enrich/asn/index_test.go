package asn

import (
	"context"
	"fmt"
	"net/netip"
	"testing"

	"cloudattrib/internal/ingest/iptoasn"
	"cloudattrib/internal/model"
)

func BenchmarkLookupASN(b *testing.B) {
	intervals := make([]iptoasn.Interval, 0, 4096)
	for index := 0; index < 4096; index++ {
		prefix := netip.MustParsePrefix(fmt.Sprintf("10.%d.%d.0/24", index/256, index%256))
		intervals = append(intervals, iptoasn.Interval{Start: prefix.Addr(), End: netip.MustParseAddr(fmt.Sprintf("10.%d.%d.255", index/256, index%256)), ASN: uint32(64512 + index), SourceID: "fixture"})
	}
	index, err := New(intervals)
	if err != nil {
		b.Fatal(err)
	}
	address := netip.MustParseAddr("10.15.255.7")
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if _, _, err := index.LookupASN(context.Background(), address, model.AttributionView{}); err != nil {
			b.Fatal(err)
		}
	}
}

func TestIndexFindsEndpointsAndLeavesGapUnmatched(t *testing.T) {
	index, err := New([]iptoasn.Interval{{Start: netip.MustParseAddr("192.0.2.0"), End: netip.MustParseAddr("192.0.2.1"), ASN: 64512, SourceID: "fixture", RecordRef: "1"}})
	if err != nil {
		t.Fatal(err)
	}
	for _, address := range []string{"192.0.2.0", "192.0.2.1"} {
		records, _, err := index.LookupASN(context.Background(), netip.MustParseAddr(address), model.AttributionView{})
		if err != nil || len(records) != 1 {
			t.Fatalf("LookupASN(%s) = %#v, %v", address, records, err)
		}
	}
	records, _, err := index.LookupASN(context.Background(), netip.MustParseAddr("192.0.2.2"), model.AttributionView{})
	if err != nil || len(records) != 0 {
		t.Fatalf("gap lookup = %#v, %v", records, err)
	}
}

func TestIndexPreservesZeroASN(t *testing.T) {
	index, err := New([]iptoasn.Interval{{Start: netip.MustParseAddr("2001:db8::"), End: netip.MustParseAddr("2001:db8::1"), SourceID: "fixture", RecordRef: "1"}})
	if err != nil {
		t.Fatal(err)
	}
	records, _, err := index.LookupASN(context.Background(), netip.MustParseAddr("2001:db8::"), model.AttributionView{})
	if err != nil || len(records) != 1 || records[0].ASN != 0 {
		t.Fatalf("LookupASN = %#v, %v", records, err)
	}
}
