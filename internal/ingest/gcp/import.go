// Package gcp imports the official Google Cloud range document.
package gcp

import (
	"fmt"
	"net/netip"

	"cloudattrib/internal/ingest/cloudranges"
	"cloudattrib/internal/model"
)

// Result contains normalized Google Cloud associations and source metadata.
type Result struct {
	SyncToken    string
	CreationTime string
	Associations []model.Association
	Warnings     []string
}
type document struct {
	SyncToken    string   `json:"syncToken"`
	CreationTime string   `json:"creationTime"`
	Prefixes     []prefix `json:"prefixes"`
}
type prefix struct {
	IPv4Prefix string `json:"ipv4Prefix"`
	IPv6Prefix string `json:"ipv6Prefix"`
	Service    string `json:"service"`
	Scope      string `json:"scope"`
}

// Parse validates and normalizes one complete Google Cloud range document.
func Parse(data []byte, revision, digest string) (Result, error) {
	var doc document
	if err := cloudranges.DecodeStrict(data, &doc); err != nil {
		return Result{}, fmt.Errorf("parse GCP ranges: %w", err)
	}
	if doc.SyncToken == "" || doc.CreationTime == "" {
		return Result{}, fmt.Errorf("parse GCP ranges: syncToken and creationTime are required")
	}
	if doc.Prefixes == nil {
		return Result{}, fmt.Errorf("parse GCP ranges: prefixes are absent")
	}
	result := Result{SyncToken: doc.SyncToken, CreationTime: doc.CreationTime}
	for n, entry := range doc.Prefixes {
		if (entry.IPv4Prefix == "") == (entry.IPv6Prefix == "") {
			return Result{}, fmt.Errorf("parse GCP prefixes[%d]: exactly one address prefix is required", n)
		}
		raw := entry.IPv4Prefix
		v4 := true
		if raw == "" {
			raw = entry.IPv6Prefix
			v4 = false
		}
		p, w, e := normalize(raw, v4)
		if e != nil {
			return Result{}, fmt.Errorf("parse GCP prefixes[%d]: %w", n, e)
		}
		if entry.Service == "" || entry.Scope == "" {
			return Result{}, fmt.Errorf("parse GCP prefixes[%d]: service and scope are required", n)
		}
		if w != "" {
			result.Warnings = append(result.Warnings, fmt.Sprintf("prefixes[%d]: %s", n, w))
		}
		recordRef := fmt.Sprintf("#/prefixes/%d", n)
		result.Associations = append(result.Associations, model.Association{ID: fmt.Sprintf("gcp:%s:%s:%s:%d", entry.Service, entry.Scope, p, n), Prefix: p, ProviderID: "gcp", Service: entry.Service, Region: entry.Scope, Lifecycle: "active", SourceID: "gcp-cloud-ranges", SourceRevision: revision, SourceDigest: digest, RecordRef: recordRef, RecordRefs: []string{recordRef}, ProvenanceGroup: "gcp-official-ranges"})
	}
	if len(result.Associations) == 0 {
		return Result{}, fmt.Errorf("parse GCP ranges: required source contains no prefixes")
	}
	return result, nil
}
func normalize(raw string, v4 bool) (netip.Prefix, string, error) {
	p, e := netip.ParsePrefix(raw)
	if e != nil {
		return netip.Prefix{}, "", fmt.Errorf("invalid CIDR %q: %w", raw, e)
	}
	if p.Addr().Is4() != v4 {
		return netip.Prefix{}, "", fmt.Errorf("CIDR %q is in wrong address family", raw)
	}
	m := p.Masked()
	if m != p {
		return m, "host bits were masked", nil
	}
	return p, "", nil
}
