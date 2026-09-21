package cloudranges

import (
	"bytes"
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
	Revision  string
	Digest    string
	Path      string
	Companion *CompanionInput
}

// CompanionInput identifies a provider detail document associated with one
// primary provider document. It enriches existing primary prefixes and never
// creates associations on its own.
type CompanionInput struct {
	Data     []byte
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
	DetailsIPv4   json.RawMessage `json:"details_ipv4"`
	DetailsIPv6   json.RawMessage `json:"details_ipv6"`
}

// Parse normalizes one regular primary provider file. Unknown fields remain in
// the caller's archived input; this adapter only interprets documented fields.
func Parse(data []byte, input Input) (Result, error) {
	var document document
	if err := DecodeStrict(data, &document); err != nil {
		return Result{}, fmt.Errorf("parse cloud ranges %q: %w", input.Path, err)
	}
	if err := validateDocumentFields(data, false); err != nil {
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
	lifecycles := map[string]lifecycleRecord{}
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
			var lifecycle lifecycleRecord
			if entry.lifecycle != "" {
				lifecycle = lifecycleRecord{
					state: entry.lifecycle, retiredAt: entry.retiredAt, revision: input.Revision, digest: input.Digest,
					recordRef: recordRef, refs: []string{recordRef},
				}
			}
			if id, ok := seen[key]; ok {
				if lifecycle.state != "" {
					if err := mergeLifecycle(lifecycles, key, lifecycle); err != nil {
						return Result{}, fmt.Errorf("parse cloud ranges %q %s[%d]: %w", input.Path, family.name, number, err)
					}
				}
				result.RecordReferences[id] = append(result.RecordReferences[id], recordRef)
				continue
			}
			id := "cloudranges:" + document.ProviderID + ":" + key
			seen[key] = id
			if lifecycle.state != "" {
				lifecycles[key] = lifecycle
			}
			result.Associations = append(result.Associations, model.Association{
				ID:             id,
				Prefix:         prefix,
				ProviderID:     document.ProviderID,
				Service:        document.Method,
				Lifecycle:      "active",
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
	for _, family := range []struct {
		name    string
		details json.RawMessage
		is4     bool
	}{{"details_ipv4", document.DetailsIPv4, true}, {"details_ipv6", document.DetailsIPv6, false}} {
		if err := joinLifecycleDetails(family.details, input.Path, family.name, family.is4, input.Revision, input.Digest, seen, lifecycles, &result); err != nil {
			return Result{}, fmt.Errorf("join embedded lifecycle details: %w", err)
		}
	}
	if input.Companion != nil {
		if err := joinCompanion(document, *input.Companion, seen, lifecycles, &result); err != nil {
			return Result{}, fmt.Errorf("join companion details: %w", err)
		}
	}
	for index := range result.Associations {
		association := &result.Associations[index]
		if lifecycle, ok := lifecycles[association.Prefix.String()]; ok {
			association.Lifecycle = lifecycle.state
			association.LifecycleTime = lifecycle.retiredAt
			association.LifecycleSourceRevision = lifecycle.revision
			association.LifecycleSourceDigest = lifecycle.digest
			association.LifecycleRecordRef = lifecycle.recordRef
			for _, ref := range lifecycle.refs {
				result.RecordReferences[association.ID] = appendUnique(result.RecordReferences[association.ID], ref)
			}
		}
		association.RecordRefs = append([]string(nil), result.RecordReferences[association.ID]...)
	}
	if len(result.Associations) == 0 {
		return Result{}, fmt.Errorf("parse cloud ranges %q: required provider source contains no prefixes", input.Path)
	}
	sort.Slice(result.Associations, func(i, j int) bool {
		return result.Associations[i].Prefix.String() < result.Associations[j].Prefix.String()
	})
	return result, nil
}

type lifecycleRecord struct {
	state     string
	retiredAt string
	revision  string
	digest    string
	recordRef string
	refs      []string
}

func joinCompanion(primary document, input CompanionInput, seen map[string]string, lifecycles map[string]lifecycleRecord, result *Result) error {
	var companion document
	if err := DecodeStrict(input.Data, &companion); err != nil {
		return fmt.Errorf("parse cloud range details %q: %w", input.Path, err)
	}
	if err := validateDocumentFields(input.Data, true); err != nil {
		return fmt.Errorf("parse cloud range details %q: %w", input.Path, err)
	}
	if companion.Provider == "" || companion.ProviderID == "" {
		return fmt.Errorf("parse cloud range details %q: provider and provider_id are required", input.Path)
	}
	if companion.Provider != primary.Provider || companion.ProviderID != primary.ProviderID {
		return fmt.Errorf("parse cloud range details %q: provider mismatch: got %q (%q), want %q (%q)", input.Path, companion.Provider, companion.ProviderID, primary.Provider, primary.ProviderID)
	}
	for _, family := range []struct {
		name    string
		details json.RawMessage
		is4     bool
	}{{"ipv4", companion.IPv4, true}, {"ipv6", companion.IPv6, false}} {
		if err := joinLifecycleDetails(family.details, input.Path, family.name, family.is4, input.Revision, input.Digest, seen, lifecycles, result); err != nil {
			return fmt.Errorf("join companion %s details: %w", family.name, err)
		}
	}
	return nil
}

func joinLifecycleDetails(raw json.RawMessage, path, family string, is4 bool, revision, digest string, seen map[string]string, lifecycles map[string]lifecycleRecord, result *Result) error {
	if raw == nil {
		return nil
	}
	var values []json.RawMessage
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return fmt.Errorf("parse cloud ranges %q %s: must be an array", path, family)
	}
	if err := json.Unmarshal(raw, &values); err != nil {
		return fmt.Errorf("parse cloud ranges %q %s: must be an array: %w", path, family, err)
	}
	for number, value := range values {
		var fields map[string]json.RawMessage
		if err := DecodeStrict(value, &fields); err != nil {
			return fmt.Errorf("parse cloud ranges %q %s[%d]: must be an object: %w", path, family, number, err)
		}
		address, err := requiredString(fields, "address")
		if err != nil {
			return fmt.Errorf("parse cloud ranges %q %s[%d]: %w", path, family, number, err)
		}
		prefix, warning, err := normalizePrefix(address, is4)
		if err != nil {
			return fmt.Errorf("parse cloud ranges %q %s[%d]: %w", path, family, number, err)
		}
		if warning != "" {
			result.Warnings = append(result.Warnings, fmt.Sprintf("%s %s[%d]: %s", path, family, number, warning))
		}
		key := prefix.String()
		if _, ok := seen[key]; !ok {
			return fmt.Errorf("parse cloud ranges %q %s[%d]: lifecycle/detail prefix %s has no matching primary prefix", path, family, number, key)
		}
		record, hasLifecycle, err := lifecycleFromFields(fields, fmt.Sprintf("%s#/%s/%d", path, family, number))
		if err != nil {
			return fmt.Errorf("parse cloud ranges %q %s[%d]: %w", path, family, number, err)
		}
		if hasLifecycle {
			record.revision = revision
			record.digest = digest
			if err := mergeLifecycle(lifecycles, key, record); err != nil {
				return fmt.Errorf("parse cloud ranges %q %s[%d]: %w", path, family, number, err)
			}
		}
	}
	return nil
}

func lifecycleFromFields(fields map[string]json.RawMessage, recordRef string) (lifecycleRecord, bool, error) {
	var state string
	if raw, ok := fields["lifecycle"]; ok {
		value, err := stringValue(raw, "lifecycle")
		if err != nil {
			return lifecycleRecord{}, false, fmt.Errorf("decode lifecycle: %w", err)
		}
		switch value {
		case "active", "retired":
			state = value
		default:
			return lifecycleRecord{}, false, fmt.Errorf("unsupported lifecycle state %q", value)
		}
	}
	retiredAt := ""
	if raw, ok := fields["retired_at"]; ok {
		value, err := stringValue(raw, "retired_at")
		if err != nil {
			return lifecycleRecord{}, false, fmt.Errorf("decode retirement time: %w", err)
		}
		if _, err := time.Parse(time.RFC3339, value); err != nil {
			return lifecycleRecord{}, false, fmt.Errorf("invalid retired_at: %w", err)
		}
		retiredAt = value
		if state == "active" {
			return lifecycleRecord{}, false, fmt.Errorf("active lifecycle conflicts with retired_at")
		}
		state = "retired"
	}
	if state == "retired" && retiredAt == "" {
		return lifecycleRecord{}, false, fmt.Errorf("retired lifecycle requires retired_at")
	}
	if state == "" {
		return lifecycleRecord{}, false, nil
	}
	return lifecycleRecord{state: state, retiredAt: retiredAt, recordRef: recordRef, refs: []string{recordRef}}, true, nil
}

func mergeLifecycle(lifecycles map[string]lifecycleRecord, key string, next lifecycleRecord) error {
	current, ok := lifecycles[key]
	if !ok {
		lifecycles[key] = next
		return nil
	}
	if current.state != next.state {
		return fmt.Errorf("conflicting lifecycle for %s: %s and %s", key, current.state, next.state)
	}
	if current.retiredAt != next.retiredAt {
		return fmt.Errorf("conflicting retired_at for %s: %q and %q", key, current.retiredAt, next.retiredAt)
	}
	// Equal lifecycle facts may appear in both the primary and companion
	// documents. Keep the first fact as the canonical lifecycle provenance and
	// retain every matching record reference.
	for _, ref := range next.refs {
		current.refs = appendUnique(current.refs, ref)
	}
	lifecycles[key] = current
	return nil
}

func appendUnique(values []string, value string) []string {
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}

func validateDocumentFields(data []byte, companion bool) error {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return fmt.Errorf("decode known fields: %w", err)
	}
	for _, name := range []string{"provider", "provider_id", "method", "coverage_notes", "generated_at", "last_update"} {
		if raw, ok := fields[name]; ok {
			if _, err := stringValue(raw, name); err != nil {
				return fmt.Errorf("validate %s: %w", name, err)
			}
		}
	}
	if raw, ok := fields["source"]; ok {
		var value any
		if err := json.Unmarshal(raw, &value); err != nil {
			return fmt.Errorf("source has invalid JSON: %w", err)
		}
		switch typed := value.(type) {
		case string:
		case []any:
			for _, item := range typed {
				if _, ok := item.(string); !ok {
					return fmt.Errorf("source must be a string or an array of strings")
				}
			}
		default:
			return fmt.Errorf("source must be a string or an array of strings")
		}
	}
	if raw, ok := fields["source_http"]; ok {
		var value []json.RawMessage
		if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) || json.Unmarshal(raw, &value) != nil {
			return fmt.Errorf("source_http must be an array")
		}
	}
	if raw, ok := fields["source_updated_at"]; ok && !bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		var value any
		if err := json.Unmarshal(raw, &value); err != nil {
			return fmt.Errorf("source_updated_at has invalid JSON: %w", err)
		}
		switch value.(type) {
		case string, map[string]any:
		default:
			return fmt.Errorf("source_updated_at must be a string, object, or null")
		}
	}
	for _, name := range []string{"ipv4", "ipv6"} {
		if raw, ok := fields[name]; ok && bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			return fmt.Errorf("%s must be an array", name)
		}
	}
	if !companion {
		for _, name := range []string{"details_ipv4", "details_ipv6"} {
			if raw, ok := fields[name]; ok && bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
				return fmt.Errorf("%s must be an array", name)
			}
		}
	}
	return nil
}

func requiredString(fields map[string]json.RawMessage, name string) (string, error) {
	raw, ok := fields[name]
	if !ok {
		return "", fmt.Errorf("%s is required", name)
	}
	value, err := stringValue(raw, name)
	if err != nil {
		return "", fmt.Errorf("decode required %s: %w", name, err)
	}
	if value == "" {
		return "", fmt.Errorf("%s is required", name)
	}
	return value, nil
}

func stringValue(raw json.RawMessage, name string) (string, error) {
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return "", fmt.Errorf("%s must be a string", name)
	}
	var value string
	if err := json.Unmarshal(raw, &value); err != nil {
		return "", fmt.Errorf("%s must be a string", name)
	}
	return value, nil
}

type rangeEntry struct {
	address   string
	lifecycle string
	retiredAt string
}

func parseEntries(raw json.RawMessage) ([]rangeEntry, error) {
	if raw == nil {
		return nil, nil
	}
	var values []json.RawMessage
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return nil, fmt.Errorf("must be an array")
	}
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
		var fields map[string]json.RawMessage
		if err := DecodeStrict(value, &fields); err != nil {
			return nil, fmt.Errorf("entry %d must be a CIDR string or object with address", number)
		}
		address, err := requiredString(fields, "address")
		if err != nil {
			return nil, fmt.Errorf("entry %d must be a CIDR string or object with address: %w", number, err)
		}
		entry := rangeEntry{address: address}
		lifecycle, hasLifecycle, err := lifecycleFromFields(fields, "")
		if err != nil {
			return nil, fmt.Errorf("entry %d: %w", number, err)
		}
		if hasLifecycle {
			entry.lifecycle = lifecycle.state
			entry.retiredAt = lifecycle.retiredAt
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
