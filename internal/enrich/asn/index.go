// Package asn provides immutable local IP-to-ASN lookups.
package asn

import (
	"context"
	"fmt"
	"net/netip"
	"sort"

	"cloudattrib/internal/ingest/iptoasn"
	"cloudattrib/internal/model"
)

// Index is an immutable family-separated interval index.
type Index struct{ v4, v6 []iptoasn.Interval }

// New validates, sorts, and copies IPtoASN intervals.
func New(intervals []iptoasn.Interval) (*Index, error) {
	index := &Index{}
	for _, item := range intervals {
		if !item.Start.IsValid() || !item.End.IsValid() || item.Start.Is4() != item.End.Is4() || item.Start.Compare(item.End) > 0 {
			return nil, fmt.Errorf("invalid ASN interval %q..%q", item.Start, item.End)
		}
		if item.Start.Is4() {
			index.v4 = append(index.v4, item)
		} else {
			index.v6 = append(index.v6, item)
		}
	}
	for _, list := range [][]iptoasn.Interval{index.v4, index.v6} {
		sort.Slice(list, func(i, j int) bool { return list[i].Start.Compare(list[j].Start) < 0 })
		for i := 1; i < len(list); i++ {
			if list[i-1].End.Compare(list[i].Start) >= 0 {
				return nil, fmt.Errorf("overlapping ASN intervals")
			}
		}
	}
	return index, nil
}

// LookupASN returns the local interval containing address, when one exists.
func (i *Index) LookupASN(ctx context.Context, address netip.Addr, _ model.AttributionView) ([]model.ASNRecord, model.Coverage, error) {
	if err := ctx.Err(); err != nil {
		return nil, model.Coverage{}, err
	}
	address = address.Unmap()
	if !address.IsValid() {
		return nil, model.Coverage{}, model.NewError(model.CodeInvalidTarget, "IP address is invalid", nil)
	}
	list := i.v6
	if address.Is4() {
		list = i.v4
	}
	position := sort.Search(len(list), func(n int) bool { return list[n].Start.Compare(address) > 0 }) - 1
	if position >= 0 && list[position].End.Compare(address) >= 0 {
		item := list[position]
		return []model.ASNRecord{{ASN: item.ASN, Description: item.Description, CountryCode: item.CountryCode, SourceID: item.SourceID, SourceRevision: item.Revision, SourceDigest: item.Digest, RecordRef: item.RecordRef}}, model.Coverage{Capability: "asn", Status: model.CoverageComplete, Attempted: 1, Completed: 1}, nil
	}
	return nil, model.Coverage{Capability: "asn", Status: model.CoverageComplete, Attempted: 1, Completed: 1}, nil
}
