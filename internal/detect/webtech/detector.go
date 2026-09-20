// Package webtech adapts the pinned passive Wappalyzer fingerprint engine.
package webtech

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"slices"
	"strings"

	wappalyzer "github.com/projectdiscovery/wappalyzergo"

	"cloudattrib/internal/model"
)

// Mapping assigns a raw technology label to an application taxonomy entry.
type Mapping struct {
	ProviderID string
	ProductID  string
	Category   string
	Relation   model.Relation
}

// Detector performs passive local fingerprinting only.
type Detector struct {
	engine   *wappalyzer.Wappalyze
	mappings map[string]Mapping
}

// New compiles the embedded pinned fingerprints and copies taxonomy mappings.
func New(mappings map[string]Mapping) (*Detector, error) {
	engine, err := wappalyzer.New()
	if err != nil {
		return nil, err
	}
	copied := make(map[string]Mapping, len(mappings))
	for name, mapping := range mappings {
		copied[name] = mapping
	}
	return &Detector{engine: engine, mappings: copied}, nil
}

// Detect fingerprints supplied response bytes and never performs a request.
func (d *Detector) Detect(ctx context.Context, observationID, subject string, headers http.Header, body []byte, _ model.AttributionView) ([]model.Evidence, model.Coverage) {
	if err := ctx.Err(); err != nil {
		return nil, model.Coverage{Capability: "webtech", Status: model.CoveragePartial, ErrorCodes: []model.ErrorCode{model.CodeCancelled}}
	}
	matches := d.engine.Fingerprint(headers.Clone(), slices.Clone(body))
	names := make([]string, 0, len(matches))
	for name := range matches {
		names = append(names, name)
	}
	slices.Sort(names)
	evidence := make([]model.Evidence, 0, len(names))
	for _, name := range names {
		mapping, ok := d.mappings[name]
		if !ok {
			mapping = Mapping{ProductID: "webtech." + normalizeID(name), Category: "web_technology", Relation: model.RelationWebIntegration}
		}
		sum := sha256.Sum256([]byte("wappalyzergo-v0.3.2\x00" + observationID + "\x00" + name))
		evidence = append(evidence, model.Evidence{
			ID:             "evidence-webtech-" + hex.EncodeToString(sum[:12]),
			ObservationIDs: []string{observationID},
			DetectorID:     "wappalyzergo-v0.3.2",
			Subject:        subject,
			ProviderID:     mapping.ProviderID,
			ProductID:      mapping.ProductID,
			Category:       mapping.Category,
			Relation:       mapping.Relation,
			Strength:       model.StrengthModerate,
			Activity:       model.ActivityResponding,
			Scope:          model.ScopeRoot,
			Explanation:    "passive detector result: " + name,
		})
	}
	return evidence, model.Coverage{Capability: "webtech", Status: model.CoverageComplete, Attempted: 1, Completed: 1}
}

func normalizeID(value string) string {
	value = strings.ToLower(value)
	value = strings.Map(func(char rune) rune {
		if char >= 'a' && char <= 'z' || char >= '0' && char <= '9' {
			return char
		}
		return '-'
	}, value)
	return strings.Trim(value, "-")
}
