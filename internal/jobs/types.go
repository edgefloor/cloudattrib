// Package jobs owns durable batch admission and target-attempt state transitions.
package jobs

import (
	"context"
	"time"

	"cloudattrib/internal/model"
)

// JobStatus is the aggregate state of one accepted batch.
type JobStatus string

const (
	// JobQueued means no target in the accepted batch has started.
	JobQueued JobStatus = "queued"
	// JobRunning means at least one target is running or remains nonterminal.
	JobRunning JobStatus = "running"
	// JobCompleted means every target completed successfully.
	JobCompleted JobStatus = "completed"
	// JobPartial means terminal target outcomes include useful and incomplete results.
	JobPartial JobStatus = "partial"
	// JobFailed means all useful work failed.
	JobFailed JobStatus = "failed"
	// JobCancelled means every target was cancelled.
	JobCancelled JobStatus = "cancelled"
)

// TargetStatus is one target row's lifecycle state.
type TargetStatus string

const (
	// TargetQueued means the target is admitted and available for a worker claim.
	TargetQueued TargetStatus = "queued"
	// TargetRunning means one worker owns the current leased attempt.
	TargetRunning TargetStatus = "running"
	// TargetCompleted means analysis completed with full requested coverage.
	TargetCompleted TargetStatus = "completed"
	// TargetPartial means analysis retained useful but incomplete results.
	TargetPartial TargetStatus = "partial"
	// TargetFailed means the target produced no useful result.
	TargetFailed TargetStatus = "failed"
	// TargetCancelled means execution was cancelled before a useful result completed.
	TargetCancelled TargetStatus = "cancelled"
)

// SubmitRequest is atomically admitted or rejected as one batch.
type SubmitRequest struct {
	OperatorID        string                    `json:"operator_id"`
	IdempotencyKey    string                    `json:"idempotency_key"`
	BundleID          string                    `json:"bundle_id,omitempty"`
	Targets           []model.AnalyzeRequest    `json:"targets"`
	Reclassifications []model.ReclassifyRequest `json:"reclassifications,omitempty"`
}

// WorkCount returns the number of capacity reservations in the batch.
func (r SubmitRequest) WorkCount() int { return len(r.Targets) + len(r.Reclassifications) }

// Target is one durable target attempt record.
type Target struct {
	ID              string                   `json:"id"`
	Index           int                      `json:"input_index"`
	Request         model.AnalyzeRequest     `json:"request"`
	Reclassify      *model.ReclassifyRequest `json:"reclassify,omitempty"`
	Status          TargetStatus             `json:"status"`
	Attempts        int                      `json:"attempts"`
	AttemptToken    string                   `json:"-"`
	LeaseOwner      string                   `json:"lease_owner,omitempty"`
	LeaseExpiresAt  time.Time                `json:"lease_expires_at,omitempty"`
	NextAttemptAt   time.Time                `json:"next_attempt_at,omitempty"`
	TerminalReason  string                   `json:"terminal_reason,omitempty"`
	ReportID        string                   `json:"report_id,omitempty"`
	Report          model.Report             `json:"report,omitempty"`
	ReportAvailable bool                     `json:"report_available"`
}

// Job is an accepted batch and its shared immutable bundle reference.
type Job struct {
	ID                string    `json:"id"`
	OperatorID        string    `json:"operator_id"`
	IdempotencyKey    string    `json:"idempotency_key"`
	BundleID          string    `json:"bundle_id,omitempty"`
	Status            JobStatus `json:"status"`
	CancelRequested   bool      `json:"cancel_requested"`
	CancelRequestedBy string    `json:"cancel_requested_by,omitempty"`
	CreatedAt         time.Time `json:"created_at"`
	UpdatedAt         time.Time `json:"updated_at"`
	Targets           []Target  `json:"targets"`
	payloadHash       string
	pinReleased       bool
}

// Claim grants one worker a bounded attempt token.
type Claim struct {
	JobID        string
	TargetID     string
	BundleID     string
	Request      model.AnalyzeRequest
	Reclassify   *model.ReclassifyRequest
	Attempt      int
	AttemptToken string
	LeaseExpires time.Time
}

// Store is the job lifecycle contract used by workers and API adapters.
type Store interface {
	Submit(context.Context, SubmitRequest) (Job, error)
	Job(context.Context, string) (Job, error)
	Claim(context.Context, string, time.Duration) (Claim, error)
	Renew(context.Context, string, string, time.Duration) error
	Complete(context.Context, string, string, model.Report, TargetStatus, string) error
	RequestCancel(context.Context, string, string) error
	RecoverExpired(context.Context, int) error
}
