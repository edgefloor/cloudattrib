package jobs

import (
	"context"
	"fmt"
	"strconv"
	"sync"
	"time"

	"cloudattrib/internal/model"
)

// Supervisor owns bounded worker loops and periodic expired-lease recovery.
type Supervisor struct {
	Runner           Runner
	Workers          int
	PollInterval     time.Duration
	RecoveryInterval time.Duration
	MaximumAttempts  int
	OnError          func(error)
}

// Run recovers abandoned work before starting workers and runs until cancellation.
func (s Supervisor) Run(ctx context.Context) error {
	if s.Runner.Store == nil || s.Runner.Factory == nil || s.Runner.WorkerID == "" || s.Runner.Lease <= 0 ||
		s.Workers <= 0 || s.PollInterval <= 0 || s.RecoveryInterval <= 0 || s.MaximumAttempts <= 0 {
		return model.NewError(model.CodeInvalidOptions, "valid worker supervisor settings are required", nil)
	}
	if err := s.Runner.Store.RecoverExpired(ctx, s.MaximumAttempts); err != nil {
		return fmt.Errorf("startup lease recovery: %w", err)
	}
	var workers sync.WaitGroup
	for index := range s.Workers {
		runner := s.Runner
		runner.WorkerID += "-" + strconv.Itoa(index+1)
		workers.Go(func() { s.runWorker(ctx, runner) })
	}
	recovery := time.NewTicker(s.RecoveryInterval)
	defer recovery.Stop()
	for {
		select {
		case <-ctx.Done():
			workers.Wait()
			return ctx.Err()
		case <-recovery.C:
			if err := s.Runner.Store.RecoverExpired(ctx, s.MaximumAttempts); err != nil && ctx.Err() == nil {
				s.report(fmt.Errorf("periodic lease recovery: %w", err))
			}
		}
	}
}

func (s Supervisor) runWorker(ctx context.Context, runner Runner) {
	for ctx.Err() == nil {
		err := runner.RunOnce(ctx)
		if err != nil && model.ErrorCodeOf(err) != model.CodeCapabilityUnavailable && ctx.Err() == nil {
			s.report(err)
		}
		if err != nil && !waitFor(ctx, s.PollInterval) {
			return
		}
	}
}

func (s Supervisor) report(err error) {
	if s.OnError != nil {
		s.OnError(err)
	}
}

func waitFor(ctx context.Context, delay time.Duration) bool {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}
