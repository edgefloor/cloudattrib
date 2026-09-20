package cloudranges

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"

	"cloudattrib/internal/model"
)

// Input identifies one archived provider document.
type Input struct {
	Revision string
	Digest   string
	Path     string
}

// Result is the normalized data and non-fatal normalization notices.
type Result struct {
	Associations  []model.Association
	Warnings      []string
	Provider      string
	ProviderID    string
	Method        string
	CoverageNotes string
	Source        json.RawMessage
	SourceHTTP    json.RawMessage
	// RecordReferences retains all source entries collapsed into an association.
	RecordReferences map[string][]string
}

type document struct {
	Provider      string          `json:"provider"`
	ProviderID    string          `json:"provider_id"`
	Method        string          `json:"method"`
	CoverageNotes string          `json:"coverage_notes"`
	Source        json.RawMessage `json:"source"`
	SourceHTTP    json.RawMessage `json:"source_http"`
	IPv4          json.RawMessage `json:"ipv4"`
	IPv6          json.RawMessage `json:"ipv6"`
}

// Parse normalizes one regular primary provider file. Unknown fields remain in
// the caller's archived input; this adapter only interprets documented fields.
func Parse(data []byte, input Input) (Result, error) {
	var document document
	if err := DecodeStrict(data, &document); err != nil {
		return Result{}, fmt.Errorf("parse cloud ranges %q: %w", input.Path, err)
	}
	if document.ProviderID == "" || document.Provider == "" {
		return Result{}, fmt.Errorf("parse cloud ranges %q: provider and provider_id are required", input.Path)
	}
	if document.IPv4 == nil && document.IPv6 == nil {
		return Result{}, fmt.Errorf("parse cloud ranges %q: both address families are absent", input.Path)
	}
	result := Result{Provider: document.Provider, ProviderID: document.ProviderID, Method: document.Method, CoverageNotes: document.CoverageNotes, Source: document.Source, SourceHTTP: document.SourceHTTP, RecordReferences: map[string][]string{}}
	seen := map[string]string{}
	lifecycles := map[string]string{}
	for _, family := range []struct {
		name     string
		prefixes json.RawMessage
		is4      bool
	}{{"ipv4", document.IPv4, true}, {"ipv6", document.IPv6, false}} {
		entries, err := parseEntries(family.prefixes)
		if err != nil {
			return Result{}, fmt.Errorf("parse cloud ranges %q %s: %w", input.Path, family.name, err)
		}
		for number, entry := range entries {
			prefix, warning, err := normalizePrefix(entry.address, family.is4)
			if err != nil {
				return Result{}, fmt.Errorf("parse cloud ranges %q %s[%d]: %w", input.Path, family.name, number, err)
			}
			if warning != "" {
				result.Warnings = append(result.Warnings, fmt.Sprintf("%s %s[%d]: %s", input.Path, family.name, number, warning))
			}
			key := prefix.String()
			recordRef := fmt.Sprintf("%s#/%s/%d", input.Path, family.name, number)
			lifecycle := "active"
			if entry.retiredAt != "" {
				if _, err := time.Parse(time.RFC3339, entry.retiredAt); err != nil {
					return Result{}, fmt.Errorf("parse cloud ranges %q %s[%d]: invalid retired_at: %w", input.Path, family.name, number, err)
				}
				lifecycle = "retired"
			}
			if id, ok := seen[key]; ok {
				if lifecycles[key] != lifecycle {
					return Result{}, fmt.Errorf("parse cloud ranges %q %s[%d]: conflicting lifecycle for %s", input.Path, family.name, number, key)
				}
				result.RecordReferences[id] = append(result.RecordReferences[id], recordRef)
				continue
			}
			id := "cloudranges:" + document.ProviderID + ":" + key
			seen[key] = id
			lifecycles[key] = lifecycle
			result.Associations = append(result.Associations, model.Association{
				ID:             id,
				Prefix:         prefix,
				ProviderID:     document.ProviderID,
				Service:        document.Method,
				Lifecycle:      lifecycle,
				LifecycleTime:  entry.retiredAt,
				SourceID:       "disposable/cloud-ip-ranges",
				SourceRevision: input.Revision,
				SourceDigest:   input.Digest,
				RecordRef:      recordRef,
				RecordRefs:     []string{recordRef},
				CoverageNotes:  document.CoverageNotes,
			})
			result.RecordReferences[id] = []string{recordRef}
		}
	}
	for index := range result.Associations {
		result.Associations[index].RecordRefs = append([]string(nil), result.RecordReferences[result.Associations[index].ID]...)
	}
	if len(result.Associations) == 0 {
		return Result{}, fmt.Errorf("parse cloud ranges %q: required provider source contains no prefixes", input.Path)
	}
	sort.Slice(result.Associations, func(i, j int) bool {
		return result.Associations[i].Prefix.String() < result.Associations[j].Prefix.String()
	})
	return result, nil
}

type rangeEntry struct {
	address   string
	retiredAt string
}

func parseEntries(raw json.RawMessage) ([]rangeEntry, error) {
	var values []json.RawMessage
	if err := json.Unmarshal(raw, &values); err != nil {
		return nil, fmt.Errorf("must be an array: %w", err)
	}
	entries := make([]rangeEntry, 0, len(values))
	for number, value := range values {
		var address string
		if err := json.Unmarshal(value, &address); err == nil {
			entries = append(entries, rangeEntry{address: address})
			continue
		}
		var object struct {
			Address   string  `json:"address"`
			RetiredAt *string `json:"retired_at"`
		}
		if err := json.Unmarshal(value, &object); err != nil || object.Address == "" {
			return nil, fmt.Errorf("entry %d must be a CIDR string or object with address", number)
		}
		entry := rangeEntry{address: object.Address}
		if object.RetiredAt != nil {
			entry.retiredAt = *object.RetiredAt
		}
		entries = append(entries, entry)
	}
	return entries, nil
}

func normalizePrefix(raw string, wantV4 bool) (netip.Prefix, string, error) {
	prefix, err := netip.ParsePrefix(raw)
	if err != nil {
		return netip.Prefix{}, "", fmt.Errorf("invalid CIDR %q: %w", raw, err)
	}
	if prefix.Addr().Is4() != wantV4 {
		return netip.Prefix{}, "", fmt.Errorf("CIDR %q is in wrong address family", raw)
	}
	masked := prefix.Masked()
	if masked != prefix {
		return masked, "host bits were masked", nil
	}
	return prefix, "", nil
}

// PrimaryFile reports whether a path is a primary provider candidate.
func PrimaryFile(path string) bool {
	base := path[strings.LastIndex(path, "/")+1:]
	return strings.HasPrefix(path, "json/") && strings.HasSuffix(base, ".json") && base != "all-providers.json" && !strings.HasSuffix(base, "-details.json")
}
