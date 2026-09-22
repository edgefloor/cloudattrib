package jobs

import (
	"context"
	"errors"
	"fmt"
	"time"

	"cloudattrib/internal/app"
	"cloudattrib/internal/model"
)

// CapturedAnalyzer keeps one immutable analyzer generation resident.
// Analyzer remains valid until the caller calls Release exactly once.
type CapturedAnalyzer interface {
	Analyzer() app.Analyzer
	Release()
}

// AnalyzerFactory captures the pinned bundle, or the active bundle for an unpinned claim.
type AnalyzerFactory interface {
	CaptureAnalyzer(context.Context, string) (CapturedAnalyzer, error)
}

// Runner executes one claimed target while renewing its bounded lease.
type Runner struct {
	Store         Store
	Factory       AnalyzerFactory
	WorkerID      string
	Lease         time.Duration
	CommitTimeout time.Duration
}

// RunOnce claims and terminalizes at most one target.
func (r Runner) RunOnce(ctx context.Context) error {
	if r.Store == nil || r.Factory == nil || r.WorkerID == "" || r.Lease <= 0 {
		return model.NewError(model.CodeInvalidOptions, "worker store, analyzer factory, identity, and lease are required", nil)
	}
	claim, err := r.Store.Claim(ctx, r.WorkerID, r.Lease)
	if err != nil {
		return fmt.Errorf("claim target: %w", err)
	}
	analysisCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	analysisDone := make(chan struct{})
	renewResult := make(chan error, 1)
	go r.renewLease(analysisCtx, cancel, analysisDone, renewResult, claim)
	var report model.Report
	var analyzeErr error
	captured, captureErr := r.Factory.CaptureAnalyzer(analysisCtx, claim.BundleID)
	if captureErr == nil && captured == nil {
		captureErr = model.NewError(model.CodeCapabilityUnavailable, "analyzer capture is unavailable", nil)
	}
	if captureErr == nil {
		func() {
			defer captured.Release()
			analyzer := captured.Analyzer()
			if analyzer == nil {
				analyzeErr = model.NewError(model.CodeCapabilityUnavailable, "captured analyzer is unavailable", nil)
				return
			}
			if claim.Reclassify != nil {
				report, analyzeErr = analyzer.Reclassify(analysisCtx, *claim.Reclassify)
			} else {
				report, analyzeErr = analyzer.Analyze(analysisCtx, claim.Request)
			}
		}()
	} else {
		analyzeErr = fmt.Errorf("capture attribution bundle: %w", captureErr)
	}
	close(analysisDone)
	renewErr := <-renewResult
	status, reason := targetResult(report, analyzeErr)
	if claim.BundleID != "" && report.ID != "" && report.BundleID != claim.BundleID {
		status = TargetFailed
		reason = "analyzer returned a report from a different bundle"
		report = model.Report{}
	}
	if renewErr != nil && !errors.Is(renewErr, context.Canceled) && !errors.Is(renewErr, context.DeadlineExceeded) {
		status = TargetFailed
		if model.ErrorCodeOf(renewErr) == model.CodeCancelled {
			status = TargetCancelled
		}
		reason = "lease renewal failed: " + renewErr.Error()
		report = model.Report{}
	}
	commitTimeout := r.CommitTimeout
	if commitTimeout <= 0 {
		commitTimeout = r.Lease
	}
	commitCtx, commitCancel := context.WithTimeout(context.WithoutCancel(ctx), commitTimeout)
	defer commitCancel()
	if err := r.Store.Complete(commitCtx, claim.TargetID, claim.AttemptToken, report, status, reason); err != nil {
		return fmt.Errorf("commit target result: %w", err)
	}
	if captureErr != nil {
		return fmt.Errorf("capture attribution bundle: %w", captureErr)
	}
	if analyzeErr != nil {
		return fmt.Errorf("analyze target: %w", analyzeErr)
	}
	if renewErr != nil && model.ErrorCodeOf(renewErr) != model.CodeCancelled && !errors.Is(renewErr, context.Canceled) && !errors.Is(renewErr, context.DeadlineExceeded) {
		return fmt.Errorf("renew target lease: %w", renewErr)
	}
	return nil
}

func (r Runner) renewLease(ctx context.Context, cancel context.CancelFunc, done <-chan struct{}, result chan<- error, claim Claim) {
	interval := r.Lease / 3
	if interval < time.Millisecond {
		interval = time.Millisecond
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-done:
			result <- nil
			return
		case <-ctx.Done():
			result <- ctx.Err()
			return
		case <-ticker.C:
			if err := r.Store.Renew(ctx, claim.TargetID, claim.AttemptToken, r.Lease); err != nil {
				cancel()
				result <- err
				return
			}
		}
	}
}

func targetResult(report model.Report, err error) (TargetStatus, string) {
	if err != nil {
		if model.ErrorCodeOf(err) == model.CodeCancelled || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return TargetCancelled, err.Error()
		}
		return TargetFailed, err.Error()
	}
	switch report.Status {
	case model.StatusComplete:
		return TargetCompleted, ""
	case model.StatusPartial:
		return TargetPartial, ""
	case model.StatusCancelled:
		return TargetCancelled, ""
	default:
		return TargetFailed, "analysis returned failed status"
	}
}
