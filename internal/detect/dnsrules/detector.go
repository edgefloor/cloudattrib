// Package dnsrules evaluates deterministic product rules over DNS observations.
package dnsrules

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"

	"cloudattrib/internal/model"
)

// Detector evaluates the pinned built-in E1 DNS rule set.
type Detector struct{}

// NewDefault returns the initial reviewed DNS product rules.
func NewDefault() *Detector {
	return &Detector{}
}

// Detect evaluates existing observations without performing collection.
func (*Detector) Detect(ctx context.Context, observations []model.Observation, _ model.AttributionView) ([]model.Evidence, []model.Coverage) {
	var evidence []model.Evidence
	for _, observation := range observations {
		if err := ctx.Err(); err != nil {
			return evidence, []model.Coverage{{Capability: "dns_rules", Status: model.CoveragePartial, ErrorCodes: []model.ErrorCode{model.CodeCancelled}}}
		}
		if observation.Type != "dns_record" {
			continue
		}
		var payload model.DNSPayload
		if err := json.Unmarshal(observation.Payload, &payload); err != nil {
			continue
		}
		if payload.RRType != "CNAME" || !matchesSuffix(payload.Value, "cloudfront.net") {
			continue
		}
		evidence = append(evidence, model.Evidence{
			ID:             evidenceID("aws.cloudfront.cname.v1", observation.ID),
			ObservationIDs: []string{observation.ID},
			DetectorID:     "dnsrules-v1",
			RuleID:         "aws.cloudfront.cname.v1",
			Subject:        observation.Subject,
			ProviderID:     "aws",
			ProductID:      "aws.cloudfront",
			Category:       "cdn",
			Relation:       model.RelationWebDelivery,
			Strength:       model.StrengthStrong,
			Activity:       model.ActivityConfigured,
			Scope:          observation.Scope,
			Explanation:    "CNAME target matches the reviewed cloudfront.net label boundary",
		})
	}
	return evidence, []model.Coverage{{Capability: "dns_rules", Status: model.CoverageComplete, Attempted: len(observations), Completed: len(observations)}}
}

func matchesSuffix(value, suffix string) bool {
	value = strings.TrimSuffix(strings.ToLower(value), ".")
	suffix = strings.TrimSuffix(strings.ToLower(suffix), ".")
	return value == suffix || strings.HasSuffix(value, "."+suffix)
}

func evidenceID(ruleID, observationID string) string {
	sum := sha256.Sum256([]byte(ruleID + "\x00" + observationID))
	return "evidence-" + hex.EncodeToString(sum[:12])
}
