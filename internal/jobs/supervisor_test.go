package jobs

import (
	"context"
	"errors"
	"testing"
	"time"

	"cloudattrib/internal/model"
)

func TestSupervisorRecoversAndExecutesDurableWork(t *testing.T) {
	t.Parallel()

	store := NewMemoryStore(2)
	now := time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC)
	store.now = func() time.Time { return now }
	job, err := store.Submit(t.Context(), SubmitRequest{OperatorID: "operator", IdempotencyKey: "supervisor", BundleID: "bundle-1", Targets: []model.AnalyzeRequest{{Target: "example.com", Kind: model.TargetDomain}}})
	if err != nil {
		t.Fatalf("Submit() error = %v", err)
	}
	if _, err := store.Claim(t.Context(), "crashed-worker", time.Second); err != nil {
		t.Fatalf("Claim() error = %v", err)
	}
	now = now.Add(2 * time.Second)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	supervisor := Supervisor{
		Runner:  Runner{Store: store, Factory: &fixtureAnalyzerFactory{}, WorkerID: "worker", Lease: time.Second},
		Workers: 1, PollInterval: time.Millisecond, RecoveryInterval: 10 * time.Millisecond, MaximumAttempts: 3,
	}
	go func() { done <- supervisor.Run(ctx) }()
	deadline := time.NewTimer(time.Second)
	defer deadline.Stop()
	for {
		loaded, loadErr := store.Job(t.Context(), job.ID)
		if loadErr != nil {
			t.Fatalf("Job() error = %v", loadErr)
		}
		if loaded.Status == JobCompleted {
			break
		}
		select {
		case <-deadline.C:
			t.Fatalf("job did not complete: %#v", loaded)
		case <-time.After(time.Millisecond):
		}
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("Run() error = %v", err)
	}
}
