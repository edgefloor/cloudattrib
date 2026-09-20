package model

import (
	"net/netip"
	"slices"
	"time"
)

// CapabilityState records whether one immutable view component can execute.
type CapabilityState struct {
	Name      string         `json:"name"`
	Status    CoverageStatus `json:"status"`
	Reason    string         `json:"reason,omitempty"`
	SourceAge *time.Duration `json:"source_age,omitempty"`
}

// AttributionView identifies one immutable set of data, rules, and detectors.
// Packages that build a view retain ownership of its indexes.
type AttributionView struct {
	bundleID      string
	policyVersion string
	detectorIDs   []string
	capabilities  []CapabilityState
}

// NewAttributionView copies the supplied slices into an immutable view identity.
func NewAttributionView(bundleID, policyVersion string, detectorIDs []string, capabilities []CapabilityState) AttributionView {
	return AttributionView{
		bundleID:      bundleID,
		policyVersion: policyVersion,
		detectorIDs:   slices.Clone(detectorIDs),
		capabilities:  slices.Clone(capabilities),
	}
}

// BundleID returns the captured bundle identity.
func (v AttributionView) BundleID() string {
	return v.bundleID
}

// PolicyVersion returns the destination and resource policy identity.
func (v AttributionView) PolicyVersion() string {
	return v.policyVersion
}

// DetectorIDs returns a caller-owned copy of detector identities.
func (v AttributionView) DetectorIDs() []string {
	return slices.Clone(v.detectorIDs)
}

// Capabilities returns a caller-owned copy of capability states.
func (v AttributionView) Capabilities() []CapabilityState {
	return slices.Clone(v.capabilities)
}

// Association is one normalized prefix or source relationship.
type Association struct {
	ID              string       `json:"id"`
	Prefix          netip.Prefix `json:"prefix"`
	ProviderID      string       `json:"provider_id"`
	ProductID       string       `json:"product_id,omitempty"`
	Service         string       `json:"service,omitempty"`
	Region          string       `json:"region,omitempty"`
	Role            string       `json:"role,omitempty"`
	Lifecycle       string       `json:"lifecycle"`
	LifecycleTime   string       `json:"lifecycle_time,omitempty"`
	SourceID        string       `json:"source_id"`
	SourceRevision  string       `json:"source_revision"`
	SourceDigest    string       `json:"source_digest"`
	RecordRef       string       `json:"record_ref"`
	RecordRefs      []string     `json:"record_refs,omitempty"`
	CoverageNotes   string       `json:"coverage_notes,omitempty"`
	ProvenanceGroup string       `json:"provenance_group,omitempty"`
}

// ASNRecord is one local interval lookup result.
type ASNRecord struct {
	ASN         uint32 `json:"asn"`
	Description string `json:"description,omitempty"`
	CountryCode string `json:"country_code,omitempty"`
	SourceID    string `json:"source_id"`
	RecordRef   string `json:"record_ref"`
}

// IPLookupRequest selects local sources and matching behavior.
type IPLookupRequest struct {
	Address        netip.Addr `json:"address"`
	Match          string     `json:"match"`
	IncludeRetired bool       `json:"include_retired"`
	Categories     []string   `json:"categories,omitempty"`
}

// IPLookupResult contains available local associations and coverage.
type IPLookupResult struct {
	Address      netip.Addr    `json:"address"`
	Status       ReportStatus  `json:"status"`
	Associations []Association `json:"associations"`
	ASN          []ASNRecord   `json:"asn"`
	Coverage     []Coverage    `json:"coverage"`
}

// ReclassifyRequest selects an immutable capture and compatible bundle.
type ReclassifyRequest struct {
	ReportID string `json:"report_id"`
	BundleID string `json:"bundle_id"`
}
