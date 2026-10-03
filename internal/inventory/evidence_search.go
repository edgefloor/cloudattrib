package inventory

import (
	"context"
	"strings"
	"time"

	"cloudattrib/internal/model"
)

// EvidenceQuery searches retained deterministic descriptions in one resolver context.
type EvidenceQuery struct {
	Text      string `json:"text"`
	ScopeRoot string `json:"scope_root,omitempty"`
	ContextID string `json:"context_id,omitempty"`
	Limit     int    `json:"limit,omitempty"`
}

// EvidenceResult keeps ranked matches tied to source reports and evidence IDs.
type EvidenceResult struct {
	AssetID                  string             `json:"asset_id"`
	Hostname                 string             `json:"hostname"`
	ContextID                string             `json:"context_id"`
	Description              string             `json:"description"`
	DescriptionRevision      int64              `json:"description_revision"`
	DescriptionHash          string             `json:"description_hash"`
	DescriptionReportID      string             `json:"description_report_id"`
	EvidenceIDs              []string           `json:"evidence_ids"`
	ObservationIDs           []string           `json:"observation_ids"`
	Coverage                 []string           `json:"coverage"`
	LatestCoverage           []string           `json:"latest_coverage"`
	LatestHTTPStatus         *int               `json:"latest_http_status,omitempty"`
	LatestHTTPAt             *time.Time         `json:"latest_http_at,omitempty"`
	LastHTTPResponseStatus   *int               `json:"last_http_response_status,omitempty"`
	LastHTTPResponseAt       *time.Time         `json:"last_http_response_at,omitempty"`
	LastHTTPResponseReportID string             `json:"last_http_response_report_id,omitempty"`
	Omitted                  int                `json:"omitted"`
	LatestAttemptAt          *time.Time         `json:"latest_attempt_at,omitempty"`
	LatestAttemptReportID    string             `json:"latest_attempt_report_id,omitempty"`
	LastPositiveAt           *time.Time         `json:"last_positive_at,omitempty"`
	LastPositiveReportID     string             `json:"last_positive_report_id,omitempty"`
	MatchedTerms             []string           `json:"matched_terms"`
	Rank                     float64            `json:"rank"`
	ProjectionStatus         string             `json:"projection_status"`
	DNSQuestions             []DNSQuestionState `json:"dns_questions,omitempty"`
}

// DNSQuestionState keeps the latest outcome and last positive answer separate.
type DNSQuestionState struct {
	QuestionName         string     `json:"question_name"`
	RRType               string     `json:"rrtype"`
	LatestObservedAt     time.Time  `json:"latest_observed_at"`
	LatestOutcome        string     `json:"latest_outcome"`
	LatestReportID       string     `json:"latest_report_id"`
	LastPositiveAt       *time.Time `json:"last_positive_at,omitempty"`
	LastPositiveReportID string     `json:"last_positive_report_id,omitempty"`
}

// EvidencePage is a bounded ranking window, not an exhaustive match count.
type EvidencePage struct {
	Items     []EvidenceResult `json:"items"`
	Truncated bool             `json:"truncated"`
}

// ProjectionStatus reports recoverable indexing work without exposing query text.
type ProjectionStatus struct {
	Pending                 int64 `json:"pending"`
	Running                 int64 `json:"running"`
	Failed                  int64 `json:"failed"`
	OldestPendingAgeSeconds int64 `json:"oldest_pending_age_seconds"`
	ProtectedReports        int64 `json:"protected_reports"`
	ProtectedDocumentBytes  int64 `json:"protected_document_bytes"`
}

// EvidenceStore reads ranked descriptions and one context state.
type EvidenceStore interface {
	SearchInventoryEvidence(context.Context, EvidenceQuery) (EvidencePage, error)
	ReadInventoryEvidence(context.Context, string, string) (EvidenceResult, error)
	InventoryProjectionStatus(context.Context) (ProjectionStatus, error)
}

// ProjectionStatus reads the durable indexing backlog.
func (s *Service) ProjectionStatus(ctx context.Context) (ProjectionStatus, error) {
	if s == nil || s.store == nil {
		return ProjectionStatus{}, model.NewError(model.CodeInvalidOptions, "inventory store is required", nil)
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return s.store.InventoryProjectionStatus(ctx)
}

// WithDefaultContext sets the resolver context used when callers omit one.
func (s *Service) WithDefaultContext(id string) *Service {
	s.defaultContext = id
	return s
}

// SearchEvidence runs bounded lexical search without collecting from targets.
func (s *Service) SearchEvidence(ctx context.Context, request EvidenceQuery) (EvidencePage, error) {
	if s == nil || s.store == nil {
		return EvidencePage{}, model.NewError(model.CodeInvalidOptions, "inventory store is required", nil)
	}
	request.Text = strings.TrimSpace(request.Text)
	if request.Text == "" || len(request.Text) > 256 || strings.ContainsAny(request.Text, "\x00\r\n") {
		return EvidencePage{}, model.NewError(model.CodeInvalidOptions, "evidence search text must contain 1 to 256 characters", nil)
	}
	if request.Limit == 0 {
		request.Limit = 50
	}
	if request.Limit < 1 || request.Limit > 100 {
		return EvidencePage{}, model.NewError(model.CodeInvalidOptions, "evidence search limit must be between 1 and 100", nil)
	}
	if request.ScopeRoot != "" {
		root, _, err := Normalize(request.ScopeRoot)
		if err != nil {
			return EvidencePage{}, err
		}
		request.ScopeRoot = root
	}
	if request.ContextID == "" {
		request.ContextID = s.defaultContext
	}
	if request.ContextID == "" || len(request.ContextID) > 128 || strings.ContainsAny(request.ContextID, "\x00\r\n") {
		return EvidencePage{}, model.NewError(model.CodeInvalidOptions, "evidence search requires a valid observation context", nil)
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return s.store.SearchInventoryEvidence(ctx, request)
}

// ReadEvidence reads one asset's projected state in a selected context.
func (s *Service) ReadEvidence(ctx context.Context, raw, contextID string) (EvidenceResult, error) {
	if s == nil || s.store == nil {
		return EvidenceResult{}, model.NewError(model.CodeInvalidOptions, "inventory store is required", nil)
	}
	hostname, _, err := Normalize(raw)
	if err != nil {
		return EvidenceResult{}, err
	}
	if contextID == "" {
		contextID = s.defaultContext
	}
	if contextID == "" || len(contextID) > 128 || strings.ContainsAny(contextID, "\x00\r\n") {
		return EvidenceResult{}, model.NewError(model.CodeInvalidOptions, "evidence read requires a valid observation context", nil)
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return s.store.ReadInventoryEvidence(ctx, hostname, contextID)
}
