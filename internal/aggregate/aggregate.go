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
