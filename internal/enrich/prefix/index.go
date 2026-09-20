// Package prefix implements immutable local prefix association lookup.
package prefix

import (
	"context"
	"fmt"
	"net/netip"
	"slices"

	"github.com/gaissmai/bart"

	"cloudattrib/internal/model"
)

// Index is immutable after construction and safe for concurrent lookups.
type Index struct {
	table        *bart.Table[[]string]
	associations map[string]model.Association
}

// New copies associations into an immutable lookup index.
func New(associations []model.Association) *Index {
	table := &bart.Table[[]string]{}
	catalog := make(map[string]model.Association, len(associations))
	for _, association := range associations {
		association.Prefix = association.Prefix.Masked()
		association.RecordRefs = slices.Clone(association.RecordRefs)
		catalog[association.ID] = association
		ids, _ := table.Get(association.Prefix)
		ids = append(slices.Clone(ids), association.ID)
		slices.Sort(ids)
		table.Insert(association.Prefix, ids)
	}
	return &Index{table: table, associations: catalog}
}

// LookupPrefixes returns every eligible containing association by default.
func (i *Index) LookupPrefixes(ctx context.Context, request model.IPLookupRequest, _ model.AttributionView) ([]model.Association, model.Coverage, error) {
	if err := ctx.Err(); err != nil {
		return nil, model.Coverage{}, err
	}
	address := request.Address.Unmap()
	if !address.IsValid() {
		return nil, model.Coverage{}, model.NewError(model.CodeInvalidTarget, "IP address is invalid", nil)
	}
	switch request.Match {
	case "", "all", "longest":
	default:
		return nil, model.Coverage{}, model.NewError(model.CodeInvalidOptions, fmt.Sprintf("unsupported prefix match mode %q", request.Match), nil)
	}
	bits := 128
	if address.Is4() {
		bits = 32
	}
	type match struct {
		prefix      netip.Prefix
		association model.Association
	}
	var matches []match
	for matchedPrefix, ids := range i.table.Supernets(netip.PrefixFrom(address, bits)) {
		for _, id := range ids {
			association := i.associations[id]
			if !request.IncludeRetired && association.Lifecycle == "retired" {
				continue
			}
			matches = append(matches, match{prefix: matchedPrefix, association: association})
		}
	}
	if request.Match == "longest" && len(matches) > 0 {
		longest := matches[0].prefix.Bits()
		for _, item := range matches[1:] {
			if item.prefix.Bits() > longest {
				longest = item.prefix.Bits()
			}
		}
		matches = slices.DeleteFunc(matches, func(item match) bool { return item.prefix.Bits() != longest })
	}
	slices.SortFunc(matches, func(a, b match) int {
		if a.prefix.Bits() != b.prefix.Bits() {
			return b.prefix.Bits() - a.prefix.Bits()
		}
		if c := a.prefix.Addr().Compare(b.prefix.Addr()); c != 0 {
			return c
		}
		return compareAssociation(a.association, b.association)
	})
	result := make([]model.Association, 0, len(matches))
	for _, item := range matches {
		association := item.association
		association.RecordRefs = slices.Clone(item.association.RecordRefs)
		result = append(result, association)
	}
	return result, model.Coverage{Capability: "prefix", Status: model.CoverageComplete, Attempted: 1, Completed: 1}, nil
}

func compareAssociation(a, b model.Association) int {
	if a.ProviderID != b.ProviderID {
		return compareString(a.ProviderID, b.ProviderID)
	}
	if a.ProductID != b.ProductID {
		return compareString(a.ProductID, b.ProductID)
	}
	if a.Service != b.Service {
		return compareString(a.Service, b.Service)
	}
	return compareString(a.SourceID, b.SourceID)
}

func compareString(a, b string) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	default:
		return 0
	}
}
