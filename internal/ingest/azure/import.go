// Package azure imports Azure downloadable Service Tags documents.
package azure

import (
	"fmt"
	"net/netip"

	"cloudattrib/internal/ingest/cloudranges"
	"cloudattrib/internal/model"
)

// Result contains normalized Azure service-tag associations.
type Result struct {
	ChangeNumber string
	Cloud        string
	Associations []model.Association
	Warnings     []string
}
type document struct {
	ChangeNumber string  `json:"changeNumber"`
	Cloud        string  `json:"cloud"`
	Values       []value `json:"values"`
}
type value struct {
	Name       string     `json:"name"`
	ID         string     `json:"id"`
	Properties properties `json:"properties"`
}
type properties struct {
	ChangeNumber    string   `json:"changeNumber"`
	Region          string   `json:"region"`
	SystemService   string   `json:"systemService"`
	Platform        string   `json:"platform"`
	AddressPrefixes []string `json:"addressPrefixes"`
}

// Parse validates and normalizes one complete Azure service-tag document.
func Parse(data []byte, revision, digest string) (Result, error) {
	var doc document
	if err := cloudranges.DecodeStrict(data, &doc); err != nil {
		return Result{}, fmt.Errorf("parse Azure service tags: %w", err)
	}
	if doc.ChangeNumber == "" || doc.Cloud == "" {
		return Result{}, fmt.Errorf("parse Azure service tags: changeNumber and cloud are required")
	}
	if doc.Values == nil {
		return Result{}, fmt.Errorf("parse Azure service tags: values are absent")
	}
	result := Result{ChangeNumber: doc.ChangeNumber, Cloud: doc.Cloud}
	for n, item := range doc.Values {
		if item.Name == "" || item.ID == "" || item.Properties.SystemService == "" || item.Properties.AddressPrefixes == nil {
			return Result{}, fmt.Errorf("parse Azure values[%d]: name, id, systemService, and addressPrefixes are required", n)
		}
		for pnum, raw := range item.Properties.AddressPrefixes {
			p, w, e := normalize(raw)
			if e != nil {
				return Result{}, fmt.Errorf("parse Azure values[%d] addressPrefixes[%d]: %w", n, pnum, e)
			}
			if w != "" {
				result.Warnings = append(result.Warnings, fmt.Sprintf("values[%d] addressPrefixes[%d]: %s", n, pnum, w))
			}
			recordRef := fmt.Sprintf("#/values/%d/properties/addressPrefixes/%d", n, pnum)
			result.Associations = append(result.Associations, model.Association{ID: fmt.Sprintf("azure:%s:%s:%d", item.ID, p, pnum), Prefix: p, ProviderID: "azure", Service: item.Properties.SystemService, Region: item.Properties.Region, Role: item.Properties.Platform, Lifecycle: "active", SourceID: "azure-service-tags", SourceRevision: revision, SourceDigest: digest, RecordRef: recordRef, RecordRefs: []string{recordRef}, ProvenanceGroup: "azure-official-service-tags"})
		}
	}
	if len(result.Associations) == 0 {
		return Result{}, fmt.Errorf("parse Azure service tags: required source contains no prefixes")
	}
	return result, nil
}
func normalize(raw string) (netip.Prefix, string, error) {
	p, e := netip.ParsePrefix(raw)
	if e != nil {
		return netip.Prefix{}, "", fmt.Errorf("invalid CIDR %q: %w", raw, e)
	}
	m := p.Masked()
	if m != p {
		return m, "host bits were masked", nil
	}
	return p, "", nil
}
