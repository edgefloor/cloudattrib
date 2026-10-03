// Package cdnsuffix matches imported CDN DNS suffixes against retained observations.
package cdnsuffix

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"slices"
	"strings"

	"cloudattrib/internal/model"
)

// Record is one immutable, normalized suffix association from a local bundle.
type Record struct {
	ID, Suffix, Category, ProviderID, SourceID, Revision, Digest, RecordRef, ProvenanceGroup string
	RecordRefs                                                                               []string
}

// Detector matches CNAME destinations without making network requests.
type Detector struct {
	bySuffix map[string][]Record
	omitted  int
}

// New copies the bundle's suffix records into a read-only index.
func New(records []Record) *Detector {
	d := &Detector{bySuffix: make(map[string][]Record)}
	for _, record := range records {
		if !supportedCategory(record.Category) {
			d.omitted++
			continue
		}
		record.RecordRefs = slices.Clone(record.RecordRefs)
		d.bySuffix[record.Suffix] = append(d.bySuffix[record.Suffix], record)
	}
	for suffix := range d.bySuffix {
		slices.SortFunc(d.bySuffix[suffix], func(a, b Record) int { return strings.Compare(a.ID, b.ID) })
	}
	return d
}

// Capability reports whether the captured bundle can classify imported suffixes.
func (d *Detector) Capability() model.CapabilityState {
	state := model.CapabilityState{Name: "cdn_suffix", Status: model.CoverageComplete}
	if len(d.bySuffix) == 0 {
		state.Status = model.CoverageUnavailable
		state.Reason = "no usable imported CDN suffix records"
	} else if d.omitted > 0 {
		state.Status = model.CoveragePartial
		state.Reason = "imported suffix categories without a supported relationship were omitted"
	}
	return state
}

func supportedCategory(category string) bool {
	switch category {
	case "cdn", "waf", "cloud":
		return true
	default:
		return false
	}
}

// Detect reports provider-level web delivery for CNAMEs at a suffix boundary.
func (d *Detector) Detect(ctx context.Context, observations []model.Observation, _ model.AttributionView) ([]model.Evidence, []model.Coverage) {
	coverage := model.Coverage{Capability: "cdn_suffix", Attempted: len(observations), Omitted: d.omitted}
	if len(d.bySuffix) == 0 {
		coverage.Status = model.CoverageUnavailable
		coverage.Reason = d.Capability().Reason
		coverage.Omitted = d.omitted
		return nil, []model.Coverage{coverage}
	}
	var evidence []model.Evidence
	for _, observation := range observations {
		if ctx.Err() != nil {
			coverage.Status = model.CoveragePartial
			coverage.ErrorCodes = []model.ErrorCode{model.CodeCancelled}
			coverage.Reason = "suffix detection cancelled"
			return evidence, []model.Coverage{coverage}
		}
		coverage.Completed++
		if observation.Type != "dns_record" || observation.Status != "answered" || observation.Scope == model.ScopeMailDependency {
			continue
		}
		var payload model.DNSPayload
		if json.Unmarshal(observation.Payload, &payload) != nil || !strings.EqualFold(payload.RRType, "CNAME") {
			continue
		}
		name, valid := normalizedName(payload.Value)
		if !valid {
			continue
		}
		for name != "" {
			for _, record := range d.bySuffix[name] {
				fields, err := json.Marshal(record)
				if err != nil {
					continue
				}
				sum := sha256.Sum256([]byte(record.ID + "\x00" + observation.ID))
				evidence = append(evidence, model.Evidence{
					ID:             "evidence-cdn-suffix-" + hex.EncodeToString(sum[:12]),
					ObservationIDs: []string{observation.ID},
					DatasetRecords: []model.DatasetRecord{{SourceID: record.SourceID, Revision: record.Revision, Digest: record.Digest, RecordRef: record.RecordRef, Fields: fields}},
					DetectorID:     "cdn-suffix-v1", Subject: observation.Subject, ProviderID: record.ProviderID,
					Category: record.Category, Relation: model.RelationWebDelivery, Strength: model.StrengthModerate,
					Activity: model.ActivityConfigured, Scope: observation.Scope,
					Explanation: "CNAME destination matches an imported provider suffix",
				})
			}
			_, rest, found := strings.Cut(name, ".")
			if !found {
				break
			}
			name = rest
		}
	}
	slices.SortFunc(evidence, func(a, b model.Evidence) int { return strings.Compare(a.ID, b.ID) })
	coverage.Omitted = d.omitted
	if d.omitted > 0 {
		coverage.Status = model.CoveragePartial
		coverage.Reason = "imported suffix categories without a supported relationship were omitted"
	} else {
		coverage.Status = model.CoverageComplete
	}
	return evidence, []model.Coverage{coverage}
}

func normalizedName(value string) (string, bool) {
	name := strings.ToLower(strings.TrimSuffix(value, "."))
	if len(name) == 0 || len(name) > 253 {
		return "", false
	}
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", false
		}
		for _, char := range label {
			if (char < 'a' || char > 'z') && (char < '0' || char > '9') && char != '-' {
				return "", false
			}
		}
	}
	return name, true
}
