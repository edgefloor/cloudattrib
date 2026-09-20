package jobs

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"
	"sync"
	"time"

	"cloudattrib/internal/model"
)

type idempotencyIdentity struct {
	operator string
	key      string
}

// MemoryStore is a deterministic in-process implementation of the durable contract.
// It is intended for tests and single-process development, not crash persistence.
type MemoryStore struct {
	mu             sync.Mutex
	maximumTargets int
	reservations   int
	jobs           map[string]*Job
	order          []string
	idempotency    map[idempotencyIdentity]string
	pins           map[string]int
	now            func() time.Time
}

// NewMemoryStore creates a bounded empty store.
func NewMemoryStore(maximumTargets int) *MemoryStore {
	return &MemoryStore{
		maximumTargets: maximumTargets, jobs: make(map[string]*Job), idempotency: make(map[idempotencyIdentity]string),
		pins: make(map[string]int), now: time.Now,
	}
}

// Submit atomically enforces idempotency, capacity, and bundle protection.
func (s *MemoryStore) Submit(ctx context.Context, request SubmitRequest) (Job, error) {
	if err := ctx.Err(); err != nil {
		return Job{}, err
	}
	if request.OperatorID == "" || request.IdempotencyKey == "" || request.WorkCount() == 0 {
		return Job{}, model.NewError(model.CodeInvalidOptions, "operator, idempotency key, and targets are required", nil)
	}
	payloadHash, err := hashRequest(request)
	if err != nil {
		return Job{}, fmt.Errorf("hash job request: %w", err)
	}
	identity := idempotencyIdentity{operator: request.OperatorID, key: request.IdempotencyKey}
	validationErrors := make([]error, len(request.Targets))
	reservations := len(request.Reclassifications)
	for index, targetRequest := range request.Targets {
		validationErrors[index] = ValidateAnalyzeRequest(targetRequest)
		if validationErrors[index] == nil {
			reservations++
		}
	}
	for _, replay := range request.Reclassifications {
		if replay.ReportID == "" || replay.BundleID == "" || replay.BundleID != request.BundleID {
			return Job{}, model.NewError(model.CodeInvalidOptions, "reclassification requires a report and the pinned batch bundle", nil)
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if existingID, ok := s.idempotency[identity]; ok {
		existing := s.jobs[existingID]
		if existing.payloadHash != payloadHash {
			return Job{}, model.NewError(model.CodeIdempotencyConflict, "idempotency key was used for a different request", nil)
		}
		return cloneJob(*existing), nil
	}
	if s.maximumTargets <= 0 || reservations > s.maximumTargets-s.reservations {
		return Job{}, model.NewError(model.CodeQueueCapacityExceeded, "nonterminal target capacity is exhausted", nil)
	}
	now := s.now()
	jobID, err := randomID("job")
	if err != nil {
		return Job{}, fmt.Errorf("create job ID: %w", err)
	}
	status := JobQueued
	if reservations == 0 {
		status = JobFailed
	}
	job := &Job{ID: jobID, OperatorID: request.OperatorID, IdempotencyKey: request.IdempotencyKey, BundleID: request.BundleID, Status: status, CreatedAt: now, UpdatedAt: now, payloadHash: payloadHash}
	job.Targets = make([]Target, request.WorkCount())
	for index, targetRequest := range request.Targets {
		targetID, idErr := randomID("target")
		if idErr != nil {
			return Job{}, fmt.Errorf("create target ID: %w", idErr)
		}
		targetStatus, reason := TargetQueued, ""
		if validationErrors[index] != nil {
			targetStatus, reason = TargetFailed, ValidationReason(validationErrors[index])
		}
		job.Targets[index] = Target{ID: targetID, Index: index, Request: targetRequest, Status: targetStatus, TerminalReason: reason}
	}
	for requestIndex, reclassifyRequest := range request.Reclassifications {
		index := len(request.Targets) + requestIndex
		targetID, idErr := randomID("target")
		if idErr != nil {
			return Job{}, fmt.Errorf("create target ID: %w", idErr)
		}
		copied := reclassifyRequest
		job.Targets[index] = Target{ID: targetID, Index: index, Reclassify: &copied, Status: TargetQueued}
	}
	s.jobs[job.ID] = job
	s.order = append(s.order, job.ID)
	s.idempotency[identity] = job.ID
	s.reservations += reservations
	if job.BundleID != "" && reservations > 0 {
		s.pins[job.BundleID]++
	}
	return cloneJob(*job), nil
}

// Job returns shared-visible job state without applying an owner filter.
func (s *MemoryStore) Job(ctx context.Context, id string) (Job, error) {
	if err := ctx.Err(); err != nil {
		return Job{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	job, ok := s.jobs[id]
	if !ok {
		return Job{}, model.NewError(model.CodeInvalidTarget, "job was not found", nil)
	}
	return cloneJob(*job), nil
}

// Claim selects one eligible target and installs a new attempt token.
func (s *MemoryStore) Claim(ctx context.Context, worker string, lease time.Duration) (Claim, error) {
	if err := ctx.Err(); err != nil {
		return Claim{}, err
	}
	if worker == "" || lease <= 0 {
		return Claim{}, model.NewError(model.CodeInvalidOptions, "worker and positive lease are required", nil)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	for _, jobID := range s.order {
		job := s.jobs[jobID]
		if job.CancelRequested {
			continue
		}
		for index := range job.Targets {
			target := &job.Targets[index]
			if target.Status != TargetQueued || target.NextAttemptAt.After(now) {
				continue
			}
			token, err := randomID("attempt")
			if err != nil {
				return Claim{}, fmt.Errorf("create attempt token: %w", err)
			}
			target.Status = TargetRunning
			target.Attempts++
			target.AttemptToken = token
			target.LeaseOwner = worker
			target.LeaseExpiresAt = now.Add(lease)
			job.Status = JobRunning
			job.UpdatedAt = now
			return Claim{JobID: job.ID, TargetID: target.ID, BundleID: job.BundleID, Request: target.Request, Reclassify: cloneReclassify(target.Reclassify), Attempt: target.Attempts, AttemptToken: token, LeaseExpires: target.LeaseExpiresAt}, nil
		}
	}
	return Claim{}, model.NewError(model.CodeCapabilityUnavailable, "no target is ready to claim", nil)
}

// Renew extends only the currently owned attempt.
func (s *MemoryStore) Renew(ctx context.Context, targetID, token string, lease time.Duration) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	job, target := s.findTarget(targetID)
	if target == nil || target.Status != TargetRunning || target.AttemptToken != token {
		return model.NewError(model.CodeIdempotencyConflict, "attempt token is stale", nil)
	}
	if job.CancelRequested {
		return model.NewError(model.CodeCancelled, "job cancellation was requested", nil)
	}
	target.LeaseExpiresAt = s.now().Add(lease)
	return nil
}

// Complete commits a terminal result only for the current attempt token.
func (s *MemoryStore) Complete(ctx context.Context, targetID, token string, report model.Report, status TargetStatus, reason string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !terminalTarget(status) {
		return model.NewError(model.CodeInvalidOptions, "completion status is not terminal", nil)
	}
	if report.ID != "" {
		if err := report.ValidateReferences(); err != nil {
			return model.NewError(model.CodeInvalidOptions, "report references are invalid", err)
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	job, target := s.findTarget(targetID)
	if target == nil || target.AttemptToken != token {
		return model.NewError(model.CodeIdempotencyConflict, "attempt token is stale", nil)
	}
	if target.Status != TargetRunning {
		if target.Status == status && target.TerminalReason == reason && reportsEqual(target, report) {
			return nil
		}
		return model.NewError(model.CodeIdempotencyConflict, "attempt completion conflicts with the committed result", nil)
	}
	target.Status = status
	target.TerminalReason = reason
	target.LeaseOwner = ""
	target.LeaseExpiresAt = time.Time{}
	if report.ID != "" {
		target.Report = report.Clone()
		target.ReportAvailable = true
	}
	s.reservations--
	s.finishJob(job)
	return nil
}

func reportsEqual(target *Target, report model.Report) bool {
	if !target.ReportAvailable || target.Report.ID == "" {
		return report.ID == ""
	}
	if report.ID == "" {
		return false
	}
	left, leftErr := target.Report.CanonicalJSON()
	right, rightErr := report.CanonicalJSON()
	return leftErr == nil && rightErr == nil && bytes.Equal(left, right)
}

// RequestCancel prevents new claims and terminalizes queued targets.
func (s *MemoryStore) RequestCancel(ctx context.Context, jobID, operatorID string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if operatorID == "" {
		return model.NewError(model.CodeInvalidOptions, "cancelling operator is required", nil)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	job, ok := s.jobs[jobID]
	if !ok {
		return model.NewError(model.CodeInvalidTarget, "job was not found", nil)
	}
	job.CancelRequested = true
	job.CancelRequestedBy = operatorID
	job.UpdatedAt = s.now()
	for index := range job.Targets {
		if job.Targets[index].Status == TargetQueued {
			job.Targets[index].Status = TargetCancelled
			job.Targets[index].TerminalReason = "cancelled before claim"
			s.reservations--
		}
	}
	s.finishJob(job)
	return nil
}

// RecoverExpired requeues bounded attempts or terminalizes exhausted/cancelled work.
func (s *MemoryStore) RecoverExpired(ctx context.Context, maximumAttempts int) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	for _, jobID := range s.order {
		job := s.jobs[jobID]
		for index := range job.Targets {
			target := &job.Targets[index]
			if target.Status != TargetRunning || target.LeaseExpiresAt.After(now) {
				continue
			}
			target.AttemptToken = ""
			target.LeaseOwner = ""
			target.LeaseExpiresAt = time.Time{}
			switch {
			case job.CancelRequested:
				target.Status = TargetCancelled
				target.TerminalReason = "cancelled after lease expiry"
				s.reservations--
			case target.Attempts >= maximumAttempts:
				target.Status = TargetFailed
				target.TerminalReason = "attempt limit exhausted"
				s.reservations--
			default:
				target.Status = TargetQueued
				target.NextAttemptAt = now
			}
		}
		s.finishJob(job)
	}
	return nil
}

// Reservations returns the current nonterminal target count.
func (s *MemoryStore) Reservations() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.reservations
}

// BundlePins returns accepted nonterminal job references for a bundle.
func (s *MemoryStore) BundlePins(bundleID string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.pins[bundleID]
}

func (s *MemoryStore) findTarget(id string) (*Job, *Target) {
	for _, jobID := range s.order {
		job := s.jobs[jobID]
		for index := range job.Targets {
			if job.Targets[index].ID == id {
				return job, &job.Targets[index]
			}
		}
	}
	return nil, nil
}

func (s *MemoryStore) finishJob(job *Job) {
	allTerminal := true
	counts := make(map[TargetStatus]int)
	for _, target := range job.Targets {
		counts[target.Status]++
		allTerminal = allTerminal && terminalTarget(target.Status)
	}
	if !allTerminal {
		job.Status = JobRunning
		return
	}
	switch {
	case counts[TargetFailed] > 0 && counts[TargetCompleted] == 0 && counts[TargetPartial] == 0:
		job.Status = JobFailed
	case counts[TargetCancelled] == len(job.Targets):
		job.Status = JobCancelled
	case counts[TargetPartial] > 0 || counts[TargetFailed] > 0 || counts[TargetCancelled] > 0:
		job.Status = JobPartial
	default:
		job.Status = JobCompleted
	}
	job.UpdatedAt = s.now()
	if !job.pinReleased && job.BundleID != "" {
		s.pins[job.BundleID]--
		job.pinReleased = true
	}
}

func terminalTarget(status TargetStatus) bool {
	return status == TargetCompleted || status == TargetPartial || status == TargetFailed || status == TargetCancelled
}

func hashRequest(request SubmitRequest) (string, error) {
	payload := struct {
		BundleID          string                    `json:"bundle_id"`
		Targets           []model.AnalyzeRequest    `json:"targets"`
		Reclassifications []model.ReclassifyRequest `json:"reclassifications"`
	}{BundleID: request.BundleID, Targets: request.Targets, Reclassifications: request.Reclassifications}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:]), nil
}

func randomID(prefix string) (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", err
	}
	return prefix + "-" + hex.EncodeToString(value[:]), nil
}

func cloneJob(job Job) Job {
	job.Targets = slices.Clone(job.Targets)
	for index := range job.Targets {
		job.Targets[index].Report = job.Targets[index].Report.Clone()
		job.Targets[index].Reclassify = cloneReclassify(job.Targets[index].Reclassify)
	}
	return job
}

func cloneReclassify(request *model.ReclassifyRequest) *model.ReclassifyRequest {
	if request == nil {
		return nil
	}
	copy := *request
	return &copy
}
