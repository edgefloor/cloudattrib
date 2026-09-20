// Package aggregate groups compatible evidence into deterministic findings.
package aggregate

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"slices"
	"strings"

	"cloudattrib/internal/model"
)

type key struct {
	subject    string
	providerID string
	productID  string
	relation   model.Relation
	scope      model.Scope
}

// Build groups only evidence with the same subject, entity, relation, and scope.
func Build(evidence []model.Evidence) []model.Finding {
	groups := make(map[key][]model.Evidence)
	for _, item := range evidence {
		groupKey := key{subject: item.Subject, providerID: item.ProviderID, productID: item.ProductID, relation: item.Relation, scope: item.Scope}
		groups[groupKey] = append(groups[groupKey], item)
	}
	findings := make([]model.Finding, 0, len(groups))
	for groupKey, items := range groups {
		slices.SortFunc(items, func(a, b model.Evidence) int { return strings.Compare(a.ID, b.ID) })
		items = deduplicate(items)
		finding := model.Finding{
			ID:          findingID(groupKey),
			Subject:     groupKey.subject,
			ProviderID:  groupKey.providerID,
			ProductID:   groupKey.productID,
			Category:    items[0].Category,
			Relation:    groupKey.relation,
			Strength:    items[0].Strength,
			Activity:    items[0].Activity,
			Scope:       groupKey.scope,
			EvidenceIDs: make([]string, 0, len(items)),
		}
		for _, item := range items {
			finding.EvidenceIDs = append(finding.EvidenceIDs, item.ID)
			if strengthRank(item.Strength) > strengthRank(finding.Strength) {
				finding.Strength = item.Strength
			}
		}
		findings = append(findings, finding)
	}
	linkConflicts(findings)
	slices.SortFunc(findings, func(a, b model.Finding) int { return strings.Compare(a.ID, b.ID) })
	return findings
}

func deduplicate(items []model.Evidence) []model.Evidence {
	byID := make(map[string]model.Evidence, len(items))
	for _, item := range items {
		current, ok := byID[item.ID]
		if !ok || strengthRank(item.Strength) > strengthRank(current.Strength) {
			byID[item.ID] = item
		}
	}
	byProvenance := make(map[string]model.Evidence, len(byID))
	for _, item := range byID {
		observationIDs := slices.Clone(item.ObservationIDs)
		slices.Sort(observationIDs)
		provenance := provenanceKey(item, observationIDs)
		current, ok := byProvenance[provenance]
		if !ok || strengthRank(item.Strength) > strengthRank(current.Strength) || strengthRank(item.Strength) == strengthRank(current.Strength) && item.ID < current.ID {
			byProvenance[provenance] = item
		}
	}
	result := make([]model.Evidence, 0, len(byProvenance))
	for _, item := range byProvenance {
		result = append(result, item)
	}
	slices.SortFunc(result, func(a, b model.Evidence) int { return strings.Compare(a.ID, b.ID) })
	return result
}

func provenanceKey(item model.Evidence, observationIDs []string) string {
	if len(item.DatasetRecords) == 0 {
		return strings.Join([]string{item.DetectorID, item.RuleID, strings.Join(observationIDs, ",")}, "\x00")
	}
	records := make([]string, 0, len(item.DatasetRecords))
	for _, record := range item.DatasetRecords {
		var fields struct {
			ProvenanceGroup string `json:"provenance_group"`
		}
		if json.Unmarshal(record.Fields, &fields) == nil && fields.ProvenanceGroup != "" {
			records = append(records, record.SourceID+"/group/"+fields.ProvenanceGroup)
			continue
		}
		records = append(records, strings.Join([]string{record.SourceID, record.Revision, record.Digest, record.RecordRef}, "/"))
	}
	slices.Sort(records)
	return strings.Join([]string{strings.Join(observationIDs, ","), strings.Join(records, ",")}, "\x00")
}

func linkConflicts(findings []model.Finding) {
	for left := range findings {
		if findings[left].Relation != model.RelationNetworkProvider && findings[left].Relation != model.RelationNetworkOrigin && findings[left].Relation != model.RelationServiceRange {
			continue
		}
		for right := range findings {
			if left == right || findings[left].Subject != findings[right].Subject || findings[left].Relation != findings[right].Relation || findings[left].Scope != findings[right].Scope {
				continue
			}
			if findings[left].ProviderID == findings[right].ProviderID && findings[left].ProductID == findings[right].ProductID {
				continue
			}
			findings[left].ConflictIDs = append(findings[left].ConflictIDs, findings[right].ID)
		}
		slices.Sort(findings[left].ConflictIDs)
	}
}

func findingID(value key) string {
	joined := strings.Join([]string{value.subject, value.providerID, value.productID, string(value.relation), string(value.scope)}, "\x00")
	sum := sha256.Sum256([]byte(joined))
	return "finding-" + hex.EncodeToString(sum[:12])
}

func strengthRank(value model.Strength) int {
	switch value {
	case model.StrengthStrong:
		return 3
	case model.StrengthModerate:
		return 2
	case model.StrengthWeak:
		return 1
	default:
		return 0
	}
}
