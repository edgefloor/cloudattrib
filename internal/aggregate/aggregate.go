// Package aggregate groups compatible evidence into deterministic findings.
package aggregate

import (
	"crypto/sha256"
	"encoding/hex"
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
		provenance := strings.Join([]string{item.DetectorID, item.RuleID, strings.Join(observationIDs, ",")}, "\x00")
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
