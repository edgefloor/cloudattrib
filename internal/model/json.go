package model

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"slices"
	"strings"
	"time"
)

// MarshalJSON emits the JSON value without base64 encoding it.
func (v JSONValue) MarshalJSON() ([]byte, error) {
	if len(v) == 0 {
		return []byte("null"), nil
	}
	if !json.Valid(v) {
		return nil, fmt.Errorf("invalid JSON value")
	}
	return bytes.Clone(v), nil
}

// UnmarshalJSON validates and copies an encoded JSON value.
func (v *JSONValue) UnmarshalJSON(data []byte) error {
	if !json.Valid(data) {
		return fmt.Errorf("invalid JSON value")
	}
	*v = bytes.Clone(data)
	return nil
}

// MarshalJSON emits required report collections as arrays, including when they are empty.
func (r Report) MarshalJSON() ([]byte, error) {
	normalized := r.Clone()
	if normalized.Observations == nil {
		normalized.Observations = make([]Observation, 0)
	}
	if normalized.Evidence == nil {
		normalized.Evidence = make([]Evidence, 0)
	}
	if normalized.Findings == nil {
		normalized.Findings = make([]Finding, 0)
	}
	if normalized.Coverage == nil {
		normalized.Coverage = make([]Coverage, 0)
	}
	if normalized.Warnings == nil {
		normalized.Warnings = make([]string, 0)
	}
	for i := range normalized.Evidence {
		if normalized.Evidence[i].ObservationIDs == nil {
			normalized.Evidence[i].ObservationIDs = make([]string, 0)
		}
		if normalized.Evidence[i].DatasetRecords == nil {
			normalized.Evidence[i].DatasetRecords = make([]DatasetRecord, 0)
		}
	}
	for i := range normalized.Findings {
		if normalized.Findings[i].EvidenceIDs == nil {
			normalized.Findings[i].EvidenceIDs = make([]string, 0)
		}
	}
	type reportJSON Report
	return json.Marshal(reportJSON(normalized))
}

// Clone returns a report whose mutable fields do not alias r.
func (r Report) Clone() Report {
	clone := r
	clone.Observations = cloneObservations(r.Observations)
	clone.Evidence = cloneEvidence(r.Evidence)
	clone.Findings = cloneFindings(r.Findings)
	clone.Coverage = cloneCoverage(r.Coverage)
	clone.Warnings = slices.Clone(r.Warnings)
	return clone
}

// CanonicalJSON returns deterministic JSON for persistence and interface output.
func (r Report) CanonicalJSON() ([]byte, error) {
	canonical := r.canonicalReport()
	return json.Marshal(canonical)
}

func (r Report) canonicalReport() Report {
	canonical := r.Clone()
	slices.SortFunc(canonical.Observations, func(a, b Observation) int { return compare(a.ID, b.ID) })
	slices.SortFunc(canonical.Evidence, func(a, b Evidence) int { return compare(a.ID, b.ID) })
	slices.SortFunc(canonical.Findings, func(a, b Finding) int { return compare(a.ID, b.ID) })
	slices.SortFunc(canonical.Coverage, func(a, b Coverage) int { return compare(a.Capability, b.Capability) })
	slices.Sort(canonical.Warnings)
	for i := range canonical.Evidence {
		slices.Sort(canonical.Evidence[i].ObservationIDs)
		slices.SortFunc(canonical.Evidence[i].DatasetRecords, func(a, b DatasetRecord) int {
			if c := compare(a.SourceID, b.SourceID); c != 0 {
				return c
			}
			return compare(a.RecordRef, b.RecordRef)
		})
	}
	for i := range canonical.Findings {
		slices.Sort(canonical.Findings[i].EvidenceIDs)
		slices.Sort(canonical.Findings[i].ConflictIDs)
		slices.Sort(canonical.Findings[i].Limitations)
	}
	for i := range canonical.Coverage {
		slices.Sort(canonical.Coverage[i].ErrorCodes)
	}
	return canonical
}

// ContentID returns a SHA-256 identifier for the current canonical content
// projection. The projection excludes the report ID itself.
func (r Report) ContentID() (string, error) {
	data, err := r.contentCanonicalJSON()
	if err != nil {
		return "", fmt.Errorf("encode canonical report content: %w", err)
	}
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func (r Report) contentCanonicalJSON() ([]byte, error) {
	version := r.ContentIDVersion
	if version == "" {
		version = ReportContentIDVersion
	}
	if version != ReportContentIDVersion {
		return nil, fmt.Errorf("unsupported content ID version %q", version)
	}
	canonical := r.canonicalReport()
	canonical.ContentIDVersion = version
	canonical.StartedAt = canonical.StartedAt.UTC()
	canonical.EndedAt = canonical.EndedAt.UTC()
	canonical.ClassifiedAt = canonical.ClassifiedAt.UTC()
	for i := range canonical.Observations {
		canonical.Observations[i].ObservedAt = canonical.Observations[i].ObservedAt.UTC()
	}
	for i := range canonical.Evidence {
		canonical.Evidence[i].ClassifiedAt = canonical.Evidence[i].ClassifiedAt.UTC()
		for j := range canonical.Evidence[i].DatasetRecords {
			normalizeOptionalTime(canonical.Evidence[i].DatasetRecords[j].PublishedAt)
			normalizeOptionalTime(canonical.Evidence[i].DatasetRecords[j].EffectiveAt)
		}
	}

	encoded, err := json.Marshal(canonical)
	if err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.UseNumber()
	var projection map[string]any
	if err := decoder.Decode(&projection); err != nil {
		return nil, err
	}
	if err := requireJSONEnd(decoder); err != nil {
		return nil, err
	}
	delete(projection, "report_id")
	var result bytes.Buffer
	if err := writeCanonicalJSON(&result, projection); err != nil {
		return nil, err
	}
	return result.Bytes(), nil
}

func normalizeOptionalTime(value *time.Time) {
	if value != nil {
		*value = value.UTC()
	}
}

func requireJSONEnd(decoder *json.Decoder) error {
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return fmt.Errorf("unexpected trailing JSON value")
		}
		return err
	}
	return nil
}

func writeCanonicalJSON(buffer *bytes.Buffer, value any) error {
	switch typed := value.(type) {
	case nil:
		buffer.WriteString("null")
	case bool:
		if typed {
			buffer.WriteString("true")
		} else {
			buffer.WriteString("false")
		}
	case string:
		encoded, _ := json.Marshal(typed)
		buffer.Write(encoded)
	case json.Number:
		normalized, err := normalizeJSONNumber(typed.String())
		if err != nil {
			return err
		}
		buffer.WriteString(normalized)
	case []any:
		buffer.WriteByte('[')
		for index, item := range typed {
			if index > 0 {
				buffer.WriteByte(',')
			}
			if err := writeCanonicalJSON(buffer, item); err != nil {
				return err
			}
		}
		buffer.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(typed))
		for key := range typed {
			keys = append(keys, key)
		}
		slices.Sort(keys)
		buffer.WriteByte('{')
		for index, key := range keys {
			if index > 0 {
				buffer.WriteByte(',')
			}
			encoded, _ := json.Marshal(key)
			buffer.Write(encoded)
			buffer.WriteByte(':')
			if err := writeCanonicalJSON(buffer, typed[key]); err != nil {
				return err
			}
		}
		buffer.WriteByte('}')
	default:
		return fmt.Errorf("unsupported canonical JSON value %T", value)
	}
	return nil
}

func normalizeJSONNumber(value string) (string, error) {
	negative := strings.HasPrefix(value, "-")
	if negative {
		value = strings.TrimPrefix(value, "-")
	}
	mantissa, exponentText, hasExponent := strings.Cut(value, "e")
	if !hasExponent {
		mantissa, exponentText, hasExponent = strings.Cut(value, "E")
	}
	if !hasExponent {
		exponentText = "0"
	}
	exponent := new(big.Int)
	if _, ok := exponent.SetString(exponentText, 10); !ok {
		return "", fmt.Errorf("invalid JSON number %q", value)
	}
	integer, fraction, hasFraction := strings.Cut(mantissa, ".")
	digits := integer
	if hasFraction {
		digits += fraction
	}
	digits = strings.TrimLeft(digits, "0")
	if digits == "" {
		return "0", nil
	}
	baseExponent := new(big.Int).Set(exponent)
	baseExponent.Sub(baseExponent, big.NewInt(int64(len(fraction))))
	trimmed := strings.TrimRight(digits, "0")
	baseExponent.Add(baseExponent, big.NewInt(int64(len(digits)-len(trimmed))))
	digits = trimmed
	scientificExponent := new(big.Int).Set(baseExponent)
	scientificExponent.Add(scientificExponent, big.NewInt(int64(len(digits)-1)))
	sign := ""
	if negative {
		sign = "-"
	}
	coefficient := digits[:1]
	if len(digits) > 1 {
		coefficient += "." + digits[1:]
	}
	return sign + coefficient + "e" + scientificExponent.String(), nil
}

// ValidateReferences validates finding identity rules and requires every reference to resolve.
func (r Report) ValidateReferences() error {
	observations := make(map[string]struct{}, len(r.Observations))
	for _, observation := range r.Observations {
		if observation.ID == "" {
			return fmt.Errorf("observation has empty ID")
		}
		if _, exists := observations[observation.ID]; exists {
			return fmt.Errorf("duplicate observation ID %q", observation.ID)
		}
		observations[observation.ID] = struct{}{}
	}
	evidence := make(map[string]struct{}, len(r.Evidence))
	for _, item := range r.Evidence {
		if item.ID == "" {
			return fmt.Errorf("evidence has empty ID")
		}
		if _, exists := evidence[item.ID]; exists {
			return fmt.Errorf("duplicate evidence ID %q", item.ID)
		}
		evidence[item.ID] = struct{}{}
		for _, observationID := range item.ObservationIDs {
			if _, exists := observations[observationID]; !exists {
				return fmt.Errorf("evidence %q references missing observation %q", item.ID, observationID)
			}
		}
	}
	findings := make(map[string]struct{}, len(r.Findings))
	for _, finding := range r.Findings {
		if finding.ID == "" {
			return fmt.Errorf("finding has empty ID")
		}
		if _, exists := findings[finding.ID]; exists {
			return fmt.Errorf("duplicate finding ID %q", finding.ID)
		}
		findings[finding.ID] = struct{}{}
		if finding.ProviderID == "" && (finding.ProductID == "" || finding.Category != "web_technology" || finding.Relation != RelationWebIntegration) {
			return fmt.Errorf("finding %q has no provider and is not a technology-only finding", finding.ID)
		}
		if len(finding.EvidenceIDs) == 0 {
			return fmt.Errorf("finding %q has no evidence", finding.ID)
		}
		for _, evidenceID := range finding.EvidenceIDs {
			if _, exists := evidence[evidenceID]; !exists {
				return fmt.Errorf("finding %q references missing evidence %q", finding.ID, evidenceID)
			}
		}
	}
	return nil
}

func cloneObservations(values []Observation) []Observation {
	result := slices.Clone(values)
	for i := range result {
		result[i].Payload = bytes.Clone(values[i].Payload)
	}
	return result
}

func cloneEvidence(values []Evidence) []Evidence {
	result := slices.Clone(values)
	for i := range result {
		result[i].ObservationIDs = slices.Clone(values[i].ObservationIDs)
		result[i].DatasetRecords = slices.Clone(values[i].DatasetRecords)
		for j := range result[i].DatasetRecords {
			result[i].DatasetRecords[j].Fields = bytes.Clone(values[i].DatasetRecords[j].Fields)
			result[i].DatasetRecords[j].PublishedAt = cloneTime(values[i].DatasetRecords[j].PublishedAt)
			result[i].DatasetRecords[j].EffectiveAt = cloneTime(values[i].DatasetRecords[j].EffectiveAt)
		}
	}
	return result
}

func cloneTime(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	clone := *value
	return &clone
}

func cloneFindings(values []Finding) []Finding {
	result := slices.Clone(values)
	for i := range result {
		result[i].EvidenceIDs = slices.Clone(values[i].EvidenceIDs)
		result[i].ConflictIDs = slices.Clone(values[i].ConflictIDs)
		result[i].Limitations = slices.Clone(values[i].Limitations)
	}
	return result
}

func cloneCoverage(values []Coverage) []Coverage {
	result := slices.Clone(values)
	for i := range result {
		result[i].ErrorCodes = slices.Clone(values[i].ErrorCodes)
	}
	return result
}

func compare(a, b string) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	default:
		return 0
	}
}
