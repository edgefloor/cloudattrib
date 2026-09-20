// Package aws imports the official AWS IP ranges document.
package aws

import (
	"fmt"
	"net/netip"

	"cloudattrib/internal/ingest/cloudranges"
	"cloudattrib/internal/model"
)

const maxInputBytes = 16 << 20

type Result struct {
	SyncToken    string
	CreateDate   string
	Associations []model.Association
	Warnings     []string
}

type document struct {
	SyncToken    string   `json:"syncToken"`
	CreateDate   string   `json:"createDate"`
	Prefixes     []prefix `json:"prefixes"`
	IPv6Prefixes []prefix `json:"ipv6_prefixes"`
}
type prefix struct {
	IPPrefix           string `json:"ip_prefix"`
	IPv6Prefix         string `json:"ipv6_prefix"`
	Region             string `json:"region"`
	Service            string `json:"service"`
	NetworkBorderGroup string `json:"network_border_group"`
}

func Parse(data []byte, revision, digest string) (Result, error) {
	if len(data) > maxInputBytes {
		return Result{}, fmt.Errorf("AWS input exceeds %d byte limit", maxInputBytes)
	}
	var doc document
	if err := cloudranges.DecodeStrict(data, &doc); err != nil {
		return Result{}, fmt.Errorf("parse AWS ranges: %w", err)
	}
	if doc.SyncToken == "" || doc.CreateDate == "" {
		return Result{}, fmt.Errorf("parse AWS ranges: syncToken and createDate are required")
	}
	if doc.Prefixes == nil && doc.IPv6Prefixes == nil {
		return Result{}, fmt.Errorf("parse AWS ranges: both prefix lists are absent")
	}
	result := Result{SyncToken: doc.SyncToken, CreateDate: doc.CreateDate}
	for _, list := range []struct {
		values []prefix
		v4     bool
		name   string
	}{{doc.Prefixes, true, "prefixes"}, {doc.IPv6Prefixes, false, "ipv6_prefixes"}} {
		for n, entry := range list.values {
			raw := entry.IPPrefix
			if !list.v4 {
				raw = entry.IPv6Prefix
			}
			p, warning, err := normalize(raw, list.v4)
			if err != nil {
				return Result{}, fmt.Errorf("parse AWS %s[%d]: %w", list.name, n, err)
			}
			if entry.Service == "" || entry.Region == "" || entry.NetworkBorderGroup == "" {
				return Result{}, fmt.Errorf("parse AWS %s[%d]: service, region, and network_border_group are required", list.name, n)
			}
			if warning != "" {
				result.Warnings = append(result.Warnings, fmt.Sprintf("%s[%d]: %s", list.name, n, warning))
			}
			recordRef := fmt.Sprintf("#/%s/%d", list.name, n)
			result.Associations = append(result.Associations, model.Association{ID: fmt.Sprintf("aws:%s:%s:%s:%d", entry.Service, entry.Region, p, n), Prefix: p, ProviderID: "aws", Service: entry.Service, Region: entry.Region, Role: entry.NetworkBorderGroup, Lifecycle: "active", SourceID: "aws-ip-ranges", SourceRevision: revision, SourceDigest: digest, RecordRef: recordRef, RecordRefs: []string{recordRef}, ProvenanceGroup: "aws-official-ranges"})
		}
	}
	if len(result.Associations) == 0 {
		return Result{}, fmt.Errorf("parse AWS ranges: required source contains no prefixes")
	}
	return result, nil
}

func normalize(raw string, v4 bool) (netip.Prefix, string, error) {
	p, err := netip.ParsePrefix(raw)
	if err != nil {
		return netip.Prefix{}, "", fmt.Errorf("invalid CIDR %q: %w", raw, err)
	}
	if p.Addr().Is4() != v4 {
		return netip.Prefix{}, "", fmt.Errorf("CIDR %q is in wrong address family", raw)
	}
	masked := p.Masked()
	if masked != p {
		return masked, "host bits were masked", nil
	}
	return p, "", nil
}
