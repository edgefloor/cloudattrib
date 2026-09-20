// Package dnsrules evaluates deterministic product rules over DNS observations.
package dnsrules

import (
	"context"

	"cloudattrib/internal/model"
	"cloudattrib/internal/rules"
)

// Detector evaluates the pinned built-in E1 DNS rule set.
type Detector struct {
	engine *rules.Engine
}

// NewDefault returns the initial reviewed DNS product rules.
func NewDefault() *Detector {
	engine, err := rules.Default()
	if err != nil {
		panic("embedded rule bundle is invalid: " + err.Error())
	}
	return &Detector{engine: engine}
}

// Detect evaluates existing observations without performing collection.
func (d *Detector) Detect(ctx context.Context, observations []model.Observation, view model.AttributionView) ([]model.Evidence, []model.Coverage) {
	return d.engine.Detect(ctx, observations, view)
}
