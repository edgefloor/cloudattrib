// Package cdndata converts pinned cdncheck generated data without importing its runtime.
package cdndata

import (
	"fmt"
	"net/netip"
	"strings"

	"cloudattrib/internal/ingest/cloudranges"
)

// Metadata identifies the exact converted upstream data artifact.
type Metadata struct{ Revision, Digest, ProvenanceGroup string }

// CIDRRecord is one normalized CDN, WAF, or cloud prefix record.
type CIDRRecord struct {
	Prefix                                                                     netip.Prefix
	Category, Provider, SourceID, RecordRef, Revision, Digest, ProvenanceGroup string
}

// SuffixRecord is one normalized local DNS suffix classification.
type SuffixRecord struct{ Suffix, Category, Provider, SourceID, RecordRef, Revision, Digest, ProvenanceGroup string }

// Result contains every converted CIDR and suffix record.
type Result struct {
	CIDRs    []CIDRRecord
	Suffixes []SuffixRecord
}

// Parse validates and converts pinned cdncheck-style generated data.
func Parse(data []byte, metadata Metadata) (Result, error) {
	var source map[string]map[string][]string
	if err := cloudranges.DecodeStrict(data, &source); err != nil {
		return Result{}, fmt.Errorf("parse cdn data: %w", err)
	}
	if len(source) == 0 {
		return Result{}, fmt.Errorf("parse cdn data: source is empty")
	}
	group := metadata.ProvenanceGroup
	if group == "" {
		group = "cdncheck"
	}
	result := Result{}
	for category, providers := range source {
		if providers == nil {
			return Result{}, fmt.Errorf("parse cdn data: category %q is not an object", category)
		}
		for provider, values := range providers {
			if provider == "" || values == nil {
				return Result{}, fmt.Errorf("parse cdn data: invalid provider %q", provider)
			}
			for number, value := range values {
				ref := fmt.Sprintf("#/%s/%s/%d", category, provider, number)
				if strings.Contains(value, "/") {
					prefix, err := netip.ParsePrefix(value)
					if err != nil {
						return Result{}, fmt.Errorf("parse cdn data %s: invalid CIDR: %w", ref, err)
					}
					result.CIDRs = append(result.CIDRs, CIDRRecord{Prefix: prefix.Masked(), Category: category, Provider: provider, SourceID: "cdncheck-data", RecordRef: ref, Revision: metadata.Revision, Digest: metadata.Digest, ProvenanceGroup: group})
					continue
				}
				suffix, err := normalizeSuffix(value)
				if err != nil {
					return Result{}, fmt.Errorf("parse cdn data %s: %w", ref, err)
				}
				result.Suffixes = append(result.Suffixes, SuffixRecord{Suffix: suffix, Category: category, Provider: provider, SourceID: "cdncheck-data", RecordRef: ref, Revision: metadata.Revision, Digest: metadata.Digest, ProvenanceGroup: group})
			}
		}
	}
	if len(result.CIDRs) == 0 && len(result.Suffixes) == 0 {
		return Result{}, fmt.Errorf("parse cdn data: source contains no records")
	}
	return result, nil
}
func normalizeSuffix(value string) (string, error) {
	value = strings.ToLower(strings.TrimSuffix(value, "."))
	if value == "" || len(value) > 253 || !strings.Contains(value, ".") {
		return "", fmt.Errorf("invalid suffix %q", value)
	}
	for _, label := range strings.Split(value, ".") {
		if label == "" || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return "", fmt.Errorf("invalid suffix %q", value)
		}
		for _, r := range label {
			if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' {
				return "", fmt.Errorf("invalid suffix %q", value)
			}
		}
	}
	return value, nil
}
