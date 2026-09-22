// Package webtech adapts the pinned passive Wappalyzer fingerprint engine.
package webtech

import (
	"context"
	"net/http"
	"slices"

	wappalyzer "github.com/projectdiscovery/wappalyzergo"

	"cloudattrib/internal/model"
)

// Detector performs passive local fingerprinting only.
type Detector struct {
	engine *wappalyzer.Wappalyze
}

// New compiles the embedded pinned fingerprints.
func New() (*Detector, error) {
	engine, err := wappalyzer.New()
	if err != nil {
		return nil, err
	}
	return &Detector{engine: engine}, nil
}

// Detect fingerprints supplied response bytes and never performs a request.
func (d *Detector) Detect(ctx context.Context, headers http.Header, body []byte) ([]model.TechnologyDetection, model.Coverage) {
	if err := ctx.Err(); err != nil {
		return nil, model.Coverage{Capability: "webtech", Status: model.CoveragePartial, ErrorCodes: []model.ErrorCode{model.CodeCancelled}}
	}
	matches := d.engine.Fingerprint(headers.Clone(), slices.Clone(body))
	names := make([]string, 0, len(matches))
	for name := range matches {
		names = append(names, name)
	}
	slices.Sort(names)
	detections := make([]model.TechnologyDetection, 0, len(names))
	for _, name := range names {
		detections = append(detections, model.TechnologyDetection{
			Name: name, DetectorID: "wappalyzergo-v0.3.2", ExplanationGranularity: model.ExplanationGranularityDetectorResult,
		})
	}
	return detections, model.Coverage{Capability: "webtech", Status: model.CoverageComplete, Attempted: 1, Completed: 1}
}
