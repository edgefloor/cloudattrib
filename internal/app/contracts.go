// Package app coordinates collection, classification, enrichment, and reports.
package app

import (
	"context"
	"net"
	"net/http"
	"net/netip"
	"time"

	"cloudattrib/internal/model"
)

// Analyzer exposes the complete application behavior to CLI and HTTP adapters.
type Analyzer interface {
	Analyze(context.Context, model.AnalyzeRequest) (model.Report, error)
	LookupIP(context.Context, model.IPLookupRequest) (model.IPLookupResult, error)
	Reclassify(context.Context, model.ReclassifyRequest) (model.Report, error)
}

// ReclassificationValidator checks replay admission without creating a report.
type ReclassificationValidator interface {
	ValidateReclassify(context.Context, model.ReclassifyRequest) error
}

// DNSClient performs raw queries through an explicitly configured resolver.
type DNSClient interface {
	Query(context.Context, model.DNSQuestion) (model.DNSResult, error)
}

// Dialer connects only to an already approved concrete address.
type Dialer interface {
	DialContext(context.Context, string, netip.Addr, uint16) (net.Conn, error)
}

// CollectionPlan contains normalized, policy-approved collection work.
type CollectionPlan struct {
	Request model.NormalizedRequest
	View    model.AttributionView
}

// Collector produces immutable observations and explicit coverage.
type Collector interface {
	Collect(context.Context, CollectionPlan) ([]model.Observation, []model.Coverage)
}

// Detector interprets existing observations without collecting new data.
type Detector interface {
	Detect(context.Context, []model.Observation, model.AttributionView) ([]model.Evidence, []model.Coverage)
}

// WebDetector classifies one already-collected response without fetching it.
type WebDetector interface {
	Detect(context.Context, string, string, model.Scope, http.Header, []byte, model.AttributionView) ([]model.Evidence, model.Coverage)
}

// PrefixReader returns caller-owned local prefix associations.
type PrefixReader interface {
	LookupPrefixes(context.Context, model.IPLookupRequest, model.AttributionView) ([]model.Association, model.Coverage, error)
}

// ASNReader returns caller-owned local ASN records.
type ASNReader interface {
	LookupASN(context.Context, netip.Addr, model.AttributionView) ([]model.ASNRecord, model.Coverage, error)
}

// SnapshotStore captures immutable bundle views and controls activation.
type SnapshotStore interface {
	Load(context.Context, string) (model.AttributionView, error)
	Active(context.Context) (model.AttributionView, error)
	Activate(context.Context, string) error
}

// ResultStore persists reports atomically and loads replay inputs.
type ResultStore interface {
	SaveReport(context.Context, model.Report) error
	LoadReport(context.Context, string) (model.Report, error)
}

// FindingQuery selects a bounded deterministic page of stored findings.
type FindingQuery struct {
	Domain       string
	ProviderID   string
	ProductID    string
	Relation     model.Relation
	Strength     model.Strength
	ObservedFrom *time.Time
	ObservedTo   *time.Time
	Cursor       string
	Limit        int
}

// StoredFinding links one finding to its immutable report classification.
type StoredFinding struct {
	ReportID     string        `json:"report_id"`
	ClassifiedAt time.Time     `json:"classified_at"`
	Finding      model.Finding `json:"finding"`
}

// FindingPage is one keyset-paginated result page.
type FindingPage struct {
	Items      []StoredFinding `json:"items"`
	NextCursor string          `json:"next_cursor,omitempty"`
}

// FindingStore searches persisted findings without exposing database details.
type FindingStore interface {
	Findings(context.Context, FindingQuery) (FindingPage, error)
}
