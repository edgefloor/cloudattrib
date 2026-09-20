package asn

import (
	"context"
	"net/netip"
	"testing"

	"cloudattrib/internal/ingest/iptoasn"
	"cloudattrib/internal/model"
)

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
