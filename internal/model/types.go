// Package model defines the application-owned values shared across collectors,
// classifiers, storage, and interfaces.
package model

import (
	"net/netip"
	"time"
)

const (
	// SchemaVersion is the current report and interface schema version.
	SchemaVersion = "1"
	// ReportContentIDVersion identifies the current canonical report projection.
	ReportContentIDVersion = "2"

	// ExplanationGranularityDetectorResult means the detector identified a
	// technology but did not expose a more specific matching primitive.
	ExplanationGranularityDetectorResult = "detector_result"
)

// TargetKind identifies the caller's input syntax and requested scope.
type TargetKind string

// TargetKind values select domain, URL, or local IP normalization.
const (
	TargetDomain TargetKind = "domain"
	TargetURL    TargetKind = "url"
	TargetIP     TargetKind = "ip"
)

// Mode selects the analysis paths used for a target.
type Mode string

// Mode values select the requested collection and classification paths.
const (
	ModeFull       Mode = "full"
	ModeDNS        Mode = "dns"
	ModeIP         Mode = "ip"
	ModeReclassify Mode = "reclassify"
)

// ReportStatus describes the terminal outcome of an accepted target.
type ReportStatus string

// ReportStatus values describe accepted target outcomes.
const (
	StatusComplete  ReportStatus = "complete"
	StatusPartial   ReportStatus = "partial"
	StatusFailed    ReportStatus = "failed"
	StatusCancelled ReportStatus = "cancelled"
)

// CoverageStatus describes whether one requested capability ran.
type CoverageStatus string

// CoverageStatus values describe one requested capability's outcome.
const (
	CoverageComplete    CoverageStatus = "complete"
	CoveragePartial     CoverageStatus = "partial"
	CoverageUnavailable CoverageStatus = "unavailable"
	CoverageSkipped     CoverageStatus = "skipped"
)

// Relation records the relationship established by evidence.
type Relation string

// Relation values identify the relationship supported by evidence.
const (
	RelationWebDelivery          Relation = "web_delivery"
	RelationAuthoritativeDNS     Relation = "authoritative_dns"
	RelationMailRouting          Relation = "mail_routing"
	RelationSendingAuthorization Relation = "sending_authorization"
	RelationWebIntegration       Relation = "web_integration"
	RelationDomainVerification   Relation = "domain_verification"
	RelationNetworkProvider      Relation = "network_provider"
	RelationNetworkOrigin        Relation = "network_origin"
	RelationServiceRange         Relation = "service_range"
)

// Strength is a categorical support level, not a probability.
type Strength string

// Strength values are categorical support levels.
const (
	StrengthStrong   Strength = "strong"
	StrengthModerate Strength = "moderate"
	StrengthWeak     Strength = "weak"
)

// Activity describes the state directly supported by the evidence.
type Activity string

// Activity values describe the state directly observed or configured.
const (
	ActivityConfigured       Activity = "configured"
	ActivityResponding       Activity = "responding"
	ActivityVerificationOnly Activity = "verification_only"
	ActivityHistorical       Activity = "historical"
	ActivityUnknown          Activity = "unknown"
)

// Scope identifies why a subject is part of the analysis.
type Scope string

// Scope values describe why a subject entered the analysis.
const (
	ScopeRoot             Scope = "root"
	ScopeSubdomain        Scope = "subdomain"
	ScopeCNAME            Scope = "cname_target"
	ScopeMailDependency   Scope = "mail_dependency"
	ScopeDNSDependency    Scope = "dns_dependency"
	ScopeExternalRedirect Scope = "external_redirect"
)

// Target keeps the original input separate from its canonical value.
type Target struct {
	Original  string     `json:"original"`
	Canonical string     `json:"canonical"`
	Kind      TargetKind `json:"kind"`
}

// AnalyzeRequest is the application request before normalization.
type AnalyzeRequest struct {
	Target              string     `json:"target"`
	Kind                TargetKind `json:"kind"`
	Mode                Mode       `json:"mode,omitempty"`
	IncludeWWW          *bool      `json:"include_www,omitempty"`
	AdditionalHostnames []string   `json:"additional_hostnames,omitempty"`
	ScopeRoots          []string   `json:"scope_roots,omitempty"`
	CTDiscovery         bool       `json:"ct_discovery,omitempty"`
	OrganizationLabel   string     `json:"organization_label,omitempty"`
}

// NormalizedRequest is safe to use for planning and collection.
type NormalizedRequest struct {
	Target              Target   `json:"target"`
	Mode                Mode     `json:"mode"`
	SeedHostnames       []string `json:"seed_hostnames"`
	ScopeRoots          []string `json:"scope_roots"`
	OrganizationLabel   string   `json:"organization_label,omitempty"`
	CTDiscovery         bool     `json:"ct_discovery"`
	IDNAProfileVersion  string   `json:"idna_profile_version"`
	PublicSuffixVersion string   `json:"public_suffix_version"`
}

// JSONValue owns an encoded JSON value.
type JSONValue []byte

// DNSQuestion identifies one raw DNS question without exposing library types.
type DNSQuestion struct {
	Name string `json:"name"`
	Type uint16 `json:"type"`
}

// DNSResult contains raw record observations and addresses from one question.
type DNSResult struct {
	Question     DNSQuestion   `json:"question"`
	Attempt      int           `json:"attempt,omitempty"`
	ResponseCode int           `json:"response_code"`
	Transport    string        `json:"transport"`
	Resolver     string        `json:"resolver"`
	Records      []Observation `json:"records"`
	Addresses    []netip.Addr  `json:"addresses"`
	Omitted      int           `json:"omitted,omitempty"`
}

// DNSPayload is the application-owned DNS record and outcome payload.
type DNSPayload struct {
	RRType       string     `json:"rrtype"`
	Owner        string     `json:"owner"`
	Value        string     `json:"value,omitempty"`
	Address      netip.Addr `json:"address,omitempty"`
	TTL          uint32     `json:"ttl,omitempty"`
	ResponseCode int        `json:"response_code,omitempty"`
	Resolver     string     `json:"resolver,omitempty"`
	Transport    string     `json:"transport,omitempty"`
	PolicyReason string     `json:"policy_reason,omitempty"`
}

// HTTPPayload contains sanitized response metadata used by the early pipeline.
type HTTPPayload struct {
	URL           string       `json:"url"`
	StatusCode    int          `json:"status_code"`
	PeerAddress   netip.Addr   `json:"peer_address"`
	Headers       []HTTPHeader `json:"headers"`
	BodyHash      string       `json:"body_hash"`
	BodyLength    int64        `json:"body_length"`
	BodyTruncated bool         `json:"body_truncated"`
	ScriptURLs    []string     `json:"script_urls,omitempty"`
}

// TechnologyPayload retains a passive detector's raw technology label.
type TechnologyPayload struct {
	Name                   string `json:"name"`
	DetectorID             string `json:"detector_id"`
	ExplanationGranularity string `json:"explanation_granularity,omitempty"`
}

// TechnologyDetection is one typed raw label emitted by a passive detector.
// It is collection output, not a provider or product attribution.
type TechnologyDetection struct {
	Name                   string
	DetectorID             string
	ExplanationGranularity string
}

// HTTPHeader is one retained response header and its sanitized values.
type HTTPHeader struct {
	Name   string   `json:"name"`
	Values []string `json:"values"`
}

// Observation is an immutable fact collected from a target.
type Observation struct {
	ID               string    `json:"id"`
	Type             string    `json:"type"`
	Subject          string    `json:"subject"`
	Relation         Relation  `json:"relation,omitempty"`
	Scope            Scope     `json:"scope,omitempty"`
	ObservedAt       time.Time `json:"observed_at"`
	CollectorVersion string    `json:"collector_version,omitempty"`
	Status           string    `json:"status"`
	Payload          JSONValue `json:"payload"`
	ContentHash      string    `json:"content_hash,omitempty"`
}

// DatasetRecord identifies normalized source data consulted by classification.
type DatasetRecord struct {
	SourceID    string     `json:"source_id"`
	Revision    string     `json:"revision"`
	Digest      string     `json:"digest"`
	RecordRef   string     `json:"record_ref"`
	Fields      JSONValue  `json:"fields"`
	PublishedAt *time.Time `json:"published_at,omitempty"`
	EffectiveAt *time.Time `json:"effective_at,omitempty"`
}

// Evidence is one detector's interpretation of observations and source data.
type Evidence struct {
	ID             string          `json:"id"`
	ObservationIDs []string        `json:"observation_ids"`
	DatasetRecords []DatasetRecord `json:"dataset_records"`
	ClassifiedAt   time.Time       `json:"classified_at"`
	DetectorID     string          `json:"detector_id"`
	RuleID         string          `json:"rule_id,omitempty"`
	Subject        string          `json:"subject"`
	ProviderID     string          `json:"provider_id,omitempty"`
	ProductID      string          `json:"product_id,omitempty"`
	Category       string          `json:"category,omitempty"`
	Relation       Relation        `json:"relation"`
	Strength       Strength        `json:"strength"`
	Activity       Activity        `json:"activity,omitempty"`
	Scope          Scope           `json:"scope,omitempty"`
	Explanation    string          `json:"explanation,omitempty"`
}

// Finding groups compatible evidence about one subject and relationship.
type Finding struct {
	ID          string   `json:"id"`
	Subject     string   `json:"subject"`
	ProviderID  string   `json:"provider_id,omitempty"`
	ProductID   string   `json:"product_id,omitempty"`
	Category    string   `json:"category,omitempty"`
	Relation    Relation `json:"relation"`
	Strength    Strength `json:"strength"`
	Activity    Activity `json:"activity,omitempty"`
	Scope       Scope    `json:"scope,omitempty"`
	EvidenceIDs []string `json:"evidence_ids"`
	ConflictIDs []string `json:"conflict_ids,omitempty"`
	Limitations []string `json:"limitations,omitempty"`
}

// Coverage records work attempted, omitted, or unavailable for one capability.
type Coverage struct {
	Capability     string         `json:"capability"`
	Status         CoverageStatus `json:"status"`
	Attempted      int            `json:"attempted"`
	Completed      int            `json:"completed"`
	ErrorCodes     []ErrorCode    `json:"error_codes,omitempty"`
	Truncated      int            `json:"truncated"`
	Omitted        int            `json:"omitted"`
	DataAgeSeconds *int64         `json:"data_age_seconds,omitempty"`
	Reason         string         `json:"reason,omitempty"`
}

// Report is the versioned attribution result envelope.
type Report struct {
	SchemaVersion    string            `json:"schema_version"`
	ContentIDVersion string            `json:"content_id_version,omitempty"`
	ID               string            `json:"report_id"`
	OriginalReportID string            `json:"original_report_id,omitempty"`
	Target           Target            `json:"target"`
	Mode             Mode              `json:"mode"`
	StartedAt        time.Time         `json:"started_at"`
	EndedAt          time.Time         `json:"ended_at"`
	ClassifiedAt     time.Time         `json:"classified_at"`
	BundleID         string            `json:"bundle_id"`
	BuildID          string            `json:"build_id"`
	Provenance       *ReportProvenance `json:"provenance,omitempty"`
	Status           ReportStatus      `json:"status"`
	Observations     []Observation     `json:"observations"`
	Evidence         []Evidence        `json:"evidence"`
	Findings         []Finding         `json:"findings"`
	Coverage         []Coverage        `json:"coverage"`
	Warnings         []string          `json:"warnings"`
}

// CTCheckStatus is the outcome of one independent CT verification step.
type CTCheckStatus string

// CTCheckStatus values describe one independent verification step.
const (
	CTCheckPassed       CTCheckStatus = "passed"
	CTCheckFailed       CTCheckStatus = "failed"
	CTCheckNotPerformed CTCheckStatus = "not_performed"
)

// CTVerificationCheck records one independently evaluated CT property.
type CTVerificationCheck struct {
	Status           CTCheckStatus `json:"status"`
	Procedure        string        `json:"procedure"`
	ProcedureVersion string        `json:"procedure_version"`
	TreeIdentity     string        `json:"tree_identity,omitempty"`
	KeyIdentity      string        `json:"key_identity,omitempty"`
	Reason           string        `json:"reason,omitempty"`
}

// CTVerification keeps signature, continuity, and inclusion results separate.
type CTVerification struct {
	CheckpointSignature CTVerificationCheck `json:"checkpoint_signature"`
	Continuity          CTVerificationCheck `json:"continuity"`
	EntryInclusion      CTVerificationCheck `json:"entry_inclusion"`
}
