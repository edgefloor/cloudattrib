// Package retention defines bounded, explicit report-history maintenance.
package retention

import (
	"context"
	"time"

	"cloudattrib/internal/model"
)

// Request selects one ordered page of reports older than Cutoff. Apply deletes
// eligible reports; the zero value previews the same selection.
type Request struct {
	Cutoff time.Time `json:"cutoff"`
	Limit  int       `json:"limit,omitempty"`
	Cursor string    `json:"cursor,omitempty"`
	Apply  bool      `json:"apply,omitempty"`
}

// Candidate reports one inspected document and why it was preserved or removed.
type Candidate struct {
	ReportID      string    `json:"report_id"`
	CreatedAt     time.Time `json:"created_at"`
	DocumentBytes int64     `json:"document_bytes"`
	Protection    string    `json:"protection,omitempty"`
	Deleted       bool      `json:"deleted"`
}

// Page is one bounded maintenance transaction. NextCursor advances past every
// inspected report, including protected reports.
type Page struct {
	Cutoff     time.Time   `json:"cutoff"`
	Applied    bool        `json:"applied"`
	Items      []Candidate `json:"items"`
	Eligible   int         `json:"eligible"`
	Protected  int         `json:"protected"`
	Deleted    int         `json:"deleted"`
	NextCursor string      `json:"next_cursor,omitempty"`
	Complete   bool        `json:"complete"`
}

// Store performs one consistent bounded page in PostgreSQL.
type Store interface {
	RunReportRetention(context.Context, Request) (Page, error)
}

// Service validates the application retention contract before persistence.
type Service struct{ store Store }

// NewService builds explicit bounded report maintenance.
func NewService(store Store) *Service { return &Service{store: store} }

// Run previews or applies one bounded page.
func (s *Service) Run(ctx context.Context, request Request) (Page, error) {
	if s == nil || s.store == nil {
		return Page{}, model.NewError(model.CodeCapabilityUnavailable, "report retention is unavailable", nil)
	}
	if request.Cutoff.IsZero() || request.Cutoff.After(time.Now().UTC()) || len(request.Cursor) > 1024 {
		return Page{}, model.NewError(model.CodeInvalidOptions, "report retention needs a past cutoff and valid cursor", nil)
	}
	if request.Limit == 0 {
		request.Limit = 100
	}
	if request.Limit < 1 || request.Limit > 500 {
		return Page{}, model.NewError(model.CodeInvalidOptions, "report retention limit must be between 1 and 500", nil)
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	return s.store.RunReportRetention(ctx, request)
}
