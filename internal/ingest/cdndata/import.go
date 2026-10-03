// Package cdndata converts pinned cdncheck generated data without importing its runtime.
package cdndata

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"cloudattrib/internal/ingest/cloudranges"
)

// Metadata identifies the exact converted upstream data artifact.
type Metadata struct{ Revision, Digest, ProvenanceGroup string }

// CIDRRecord is one normalized CDN, WAF, or cloud prefix record.
type CIDRRecord struct {
	Prefix          netip.Prefix
	Category        string
	Provider        string
	SourceID        string
	ID              string
	RecordRef       string
	RecordRefs      []string
	Revision        string
	Digest          string
	ProvenanceGroup string
}

// SuffixRecord is one normalized local DNS suffix classification.
type SuffixRecord struct {
	Suffix, Category, Provider, SourceID, ID, RecordRef, Revision, Digest, ProvenanceGroup string
	RecordRefs                                                                             []string
}

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
					canonical := prefix.Masked()
					result.CIDRs = append(result.CIDRs, CIDRRecord{Prefix: canonical, Category: category, Provider: provider, SourceID: "cdncheck-data", ID: cidrID("cdncheck-data", provider, category, canonical), RecordRef: ref, RecordRefs: []string{ref}, Revision: metadata.Revision, Digest: metadata.Digest, ProvenanceGroup: group})
					continue
				}
				suffix, err := normalizeSuffix(value)
				if err != nil {
					return Result{}, fmt.Errorf("parse cdn data %s: %w", ref, err)
				}
				result.Suffixes = append(result.Suffixes, SuffixRecord{Suffix: suffix, Category: category, Provider: provider, SourceID: "cdncheck-data", ID: suffixID("cdncheck-data", provider, category, suffix), RecordRef: ref, RecordRefs: []string{ref}, Revision: metadata.Revision, Digest: metadata.Digest, ProvenanceGroup: group})
			}
		}
	}
	if len(result.CIDRs) == 0 && len(result.Suffixes) == 0 {
		return Result{}, fmt.Errorf("parse cdn data: source contains no records")
	}
	slices.SortFunc(result.CIDRs, func(a, b CIDRRecord) int {
		return strings.Compare(a.ID, b.ID)
	})
	unique := result.CIDRs[:0]
	for _, record := range result.CIDRs {
		if len(unique) > 0 && unique[len(unique)-1].ID == record.ID {
			unique[len(unique)-1].RecordRefs = append(unique[len(unique)-1].RecordRefs, record.RecordRef)
			continue
		}
		unique = append(unique, record)
	}
	result.CIDRs = unique
	for i := range result.CIDRs {
		slices.Sort(result.CIDRs[i].RecordRefs)
		result.CIDRs[i].RecordRef = result.CIDRs[i].RecordRefs[0]
	}
	slices.SortFunc(result.Suffixes, func(a, b SuffixRecord) int { return strings.Compare(a.ID, b.ID) })
	uniqueSuffixes := result.Suffixes[:0]
	for _, record := range result.Suffixes {
		if len(uniqueSuffixes) > 0 && uniqueSuffixes[len(uniqueSuffixes)-1].ID == record.ID {
			uniqueSuffixes[len(uniqueSuffixes)-1].RecordRefs = append(uniqueSuffixes[len(uniqueSuffixes)-1].RecordRefs, record.RecordRef)
			continue
		}
		uniqueSuffixes = append(uniqueSuffixes, record)
	}
	result.Suffixes = uniqueSuffixes
	for i := range result.Suffixes {
		slices.Sort(result.Suffixes[i].RecordRefs)
		result.Suffixes[i].RecordRef = result.Suffixes[i].RecordRefs[0]
	}
	return result, nil
}

func cidrID(sourceID, provider, category string, prefix netip.Prefix) string {
	semantic := fmt.Sprintf("%q\x00%q\x00%q\x00%q", sourceID, provider, category, prefix.String())
	sum := sha256.Sum256([]byte(semantic))
	return "cdn:" + hex.EncodeToString(sum[:])
}

func suffixID(sourceID, provider, category, suffix string) string {
	semantic := fmt.Sprintf("%q\x00%q\x00%q\x00%q", sourceID, provider, category, suffix)
	sum := sha256.Sum256([]byte(semantic))
	return "cdn-suffix:" + hex.EncodeToString(sum[:])
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
