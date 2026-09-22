package model

// ProvenanceStatus says whether an identity was available to the producing
// process. Unknown values are not inferred from compatibility labels.
type ProvenanceStatus string

const (
	// ProvenanceKnown means Value identifies the declared input.
	ProvenanceKnown ProvenanceStatus = "known"
	// ProvenanceUnknown means the producing process could not identify the input.
	ProvenanceUnknown ProvenanceStatus = "unknown"
)

// ProvenanceValue is an explicit known or unknown source identity.
type ProvenanceValue struct {
	Status ProvenanceStatus `json:"status"`
	Value  string           `json:"value,omitempty"`
}

// KnownProvenance returns a known identity, or an explicit unknown identity
// when value is empty.
func KnownProvenance(value string) ProvenanceValue {
	if value == "" {
		return UnknownProvenance()
	}
	return ProvenanceValue{Status: ProvenanceKnown, Value: value}
}

// UnknownProvenance returns an explicit unknown identity.
func UnknownProvenance() ProvenanceValue {
	return ProvenanceValue{Status: ProvenanceUnknown}
}

// Explicit returns v with invalid or empty states represented as unknown.
func (v ProvenanceValue) Explicit() ProvenanceValue {
	if v.Status != ProvenanceKnown || v.Value == "" {
		return UnknownProvenance()
	}
	return v
}

// BuildDirtyState records whether tracked source files differed from the
// recorded revision when the binary was built.
type BuildDirtyState string

// BuildDirtyState values describe the tracked source tree at build time.
const (
	BuildClean        BuildDirtyState = "clean"
	BuildDirty        BuildDirtyState = "dirty"
	BuildDirtyUnknown BuildDirtyState = "unknown"
)

// BuildProvenance identifies source code used to produce a report stage.
type BuildProvenance struct {
	Revision ProvenanceValue `json:"revision"`
	Dirty    BuildDirtyState `json:"dirty"`
}

// Explicit returns b with every unavailable value represented as unknown.
func (b BuildProvenance) Explicit() BuildProvenance {
	b.Revision = b.Revision.Explicit()
	if b.Dirty != BuildClean && b.Dirty != BuildDirty {
		b.Dirty = BuildDirtyUnknown
	}
	return b
}

// CompatibilityID returns the legacy build_id representation used by new
// reports. Structured provenance is authoritative.
func (b BuildProvenance) CompatibilityID() string {
	b = b.Explicit()
	if b.Revision.Status != ProvenanceKnown {
		return "unknown"
	}
	switch b.Dirty {
	case BuildDirty:
		return "git:" + b.Revision.Value + "+dirty"
	case BuildDirtyUnknown:
		return "git:" + b.Revision.Value + "+dirty-unknown"
	default:
		return "git:" + b.Revision.Value
	}
}

// CollectionProvenance identifies the code and policy that produced retained
// observations. FingerprintDigest identifies the embedded data used to create
// retained passive-technology observations.
type CollectionProvenance struct {
	Build             BuildProvenance `json:"build"`
	PolicyRevision    ProvenanceValue `json:"policy_revision"`
	FingerprintDigest ProvenanceValue `json:"fingerprint_digest"`
}

// ClassificationProvenance identifies the code and rule artifact that
// produced evidence and findings.
type ClassificationProvenance struct {
	Build       BuildProvenance `json:"build"`
	RulesDigest ProvenanceValue `json:"rules_digest"`
}

// ReportProvenance separates retained collection inputs from the producer of
// the current classification. Reclassification copies Collection unchanged.
type ReportProvenance struct {
	Collection     CollectionProvenance     `json:"collection"`
	Classification ClassificationProvenance `json:"classification"`
}

// ExplicitReportProvenance creates a complete provenance value without
// inventing unavailable metadata.
func ExplicitReportProvenance(build BuildProvenance, policyRevision, fingerprintDigest, rulesDigest ProvenanceValue) ReportProvenance {
	build = build.Explicit()
	return ReportProvenance{
		Collection: CollectionProvenance{
			Build:             build,
			PolicyRevision:    policyRevision.Explicit(),
			FingerprintDigest: fingerprintDigest.Explicit(),
		},
		Classification: ClassificationProvenance{
			Build:       build,
			RulesDigest: rulesDigest.Explicit(),
		},
	}
}

// UnknownCollectionProvenance returns explicit unknowns for a historical
// report that predates structured provenance.
func UnknownCollectionProvenance() CollectionProvenance {
	return CollectionProvenance{
		Build:             (BuildProvenance{}).Explicit(),
		PolicyRevision:    UnknownProvenance(),
		FingerprintDigest: UnknownProvenance(),
	}
}
