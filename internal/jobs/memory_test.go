package jobs

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"cloudattrib/internal/model"
)

func TestAdmissionIsIdempotentAndCapacityBounded(t *testing.T) {
	t.Parallel()

	store := NewMemoryStore(2)
	request := SubmitRequest{OperatorID: "operator-a", IdempotencyKey: "key", BundleID: "bundle-1", Targets: []model.AnalyzeRequest{{Target: "one.example.com", Kind: model.TargetDomain}, {Target: "two.example.com", Kind: model.TargetDomain}}}
	first, err := store.Submit(context.Background(), request)
	if err != nil {
		t.Fatalf("Submit() error = %v", err)
	}
	second, err := store.Submit(context.Background(), request)
	if err != nil || second.ID != first.ID {
		t.Fatalf("idempotent Submit() = %#v, %v", second, err)
	}
	if got := store.Reservations(); got != 2 {
		t.Fatalf("reservations = %d, want 2", got)
	}
	if got := store.BundlePins("bundle-1"); got != 1 {
		t.Fatalf("bundle pins = %d, want 1", got)
	}
	conflict := request
	conflict.Targets = []model.AnalyzeRequest{{Target: "other.example", Kind: model.TargetDomain}}
	if _, err := store.Submit(context.Background(), conflict); model.ErrorCodeOf(err) != model.CodeIdempotencyConflict {
		t.Fatalf("conflicting Submit() error = %v", err)
	}
	if _, err := store.Submit(context.Background(), SubmitRequest{OperatorID: "operator-b", IdempotencyKey: "other", BundleID: "bundle-1", Targets: []model.AnalyzeRequest{{Target: "three.example.com", Kind: model.TargetDomain}}}); model.ErrorCodeOf(err) != model.CodeQueueCapacityExceeded {
		t.Fatalf("capacity Submit() error = %v", err)
	}
}

func TestInvalidRowsAreTerminalWithoutReservations(t *testing.T) {
	t.Parallel()

	store := NewMemoryStore(1)
	job, err := store.Submit(context.Background(), SubmitRequest{
		OperatorID: "operator", IdempotencyKey: "mixed",
		Targets: []model.AnalyzeRequest{{Target: "not a domain", Kind: model.TargetDomain}, {Target: "example.com", Kind: model.TargetDomain}},
	})
	if err != nil {
		t.Fatalf("Submit() error = %v", err)
	}
	if job.Targets[0].Status != TargetFailed || job.Targets[1].Status != TargetQueued || store.Reservations() != 1 {
		t.Fatalf("job = %#v, reservations = %d", job, store.Reservations())
	}
	if !strings.Contains(job.Targets[0].TerminalReason, "validation failed") {
		t.Fatalf("terminal reason = %q", job.Targets[0].TerminalReason)
	}
}

func TestQueryBearingURLIsRejectedBeforeJobRetention(t *testing.T) {
	t.Parallel()

	store := NewMemoryStore(1)
	_, err := store.Submit(t.Context(), SubmitRequest{
		OperatorID: "operator", IdempotencyKey: "query-secret",
		Targets: []model.AnalyzeRequest{{Target: "https://example.com/path?token=QUERY_CANARY", Kind: model.TargetDomain}},
	})
	if model.ErrorCodeOf(err) != model.CodeInvalidTarget {
		t.Fatalf("Submit() error = %v, want invalid_target", err)
	}
	if strings.Contains(err.Error(), "QUERY_CANARY") {
		t.Fatalf("Submit() error exposed query value: %v", err)
	}
	if len(store.jobs) != 0 || len(store.idempotency) != 0 || store.Reservations() != 0 {
		t.Fatalf("rejected request was retained: jobs=%d idempotency=%d reservations=%d", len(store.jobs), len(store.idempotency), store.Reservations())
	}
}

func TestAttemptTokenRejectsStaleCompletionAndPinReleasesAtAllTerminal(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 9, 20, 10, 0, 0, 0, time.UTC)
	store := NewMemoryStore(10)
	store.now = func() time.Time { return now }
	job, err := store.Submit(context.Background(), SubmitRequest{OperatorID: "operator", IdempotencyKey: "key", BundleID: "bundle", Targets: []model.AnalyzeRequest{{Target: "one.example.com", Kind: model.TargetDomain}, {Target: "two.example.com", Kind: model.TargetDomain}}})
	if err != nil {
		t.Fatalf("Submit() error = %v", err)
	}
	first, err := store.Claim(context.Background(), "worker-1", time.Minute)
	if err != nil {
		t.Fatalf("Claim() error = %v", err)
	}
	now = now.Add(2 * time.Minute)
	if err := store.RecoverExpired(context.Background(), 3); err != nil {
		t.Fatalf("RecoverExpired() error = %v", err)
	}
	retried, err := store.Claim(context.Background(), "worker-2", time.Minute)
	if err != nil {
		t.Fatalf("retry Claim() error = %v", err)
	}
	if retried.TargetID != first.TargetID || retried.AttemptToken == first.AttemptToken {
		t.Fatalf("retry claim = %#v, first = %#v", retried, first)
	}
	if err := store.Complete(context.Background(), first.TargetID, first.AttemptToken, model.Report{ID: "stale"}, TargetCompleted, ""); model.ErrorCodeOf(err) != model.CodeIdempotencyConflict {
		t.Fatalf("stale Complete() error = %v", err)
	}
	if err := store.Complete(context.Background(), retried.TargetID, retried.AttemptToken, model.Report{ID: "fresh"}, TargetCompleted, ""); err != nil {
		t.Fatalf("Complete() error = %v", err)
	}
	if err := store.Complete(context.Background(), retried.TargetID, retried.AttemptToken, model.Report{ID: "fresh"}, TargetCompleted, ""); err != nil {
		t.Fatalf("repeated Complete() error = %v", err)
	}
	if err := store.Complete(context.Background(), retried.TargetID, retried.AttemptToken, model.Report{ID: "different"}, TargetCompleted, ""); model.ErrorCodeOf(err) != model.CodeIdempotencyConflict {
		t.Fatalf("conflicting repeated Complete() error = %v", err)
	}
	if got := store.BundlePins("bundle"); got != 1 {
		t.Fatalf("bundle pins after one target = %d, want 1", got)
	}
	second, err := store.Claim(context.Background(), "worker-2", time.Minute)
	if err != nil {
		t.Fatalf("second Claim() error = %v", err)
	}
	if err := store.Complete(context.Background(), second.TargetID, second.AttemptToken, model.Report{ID: "second"}, TargetPartial, "partial fixture"); err != nil {
		t.Fatalf("second Complete() error = %v", err)
	}
	if got := store.BundlePins("bundle"); got != 0 {
		t.Fatalf("bundle pins after terminal job = %d, want 0", got)
	}
	if got := store.Reservations(); got != 0 {
		t.Fatalf("reservations after terminal job = %d, want 0", got)
	}
	loaded, err := store.Job(context.Background(), job.ID)
	if err != nil || loaded.Status != JobPartial {
		t.Fatalf("Job() = %#v, %v", loaded, err)
	}
}

func TestCancellationKeepsRunningPinUntilTargetTerminates(t *testing.T) {
	t.Parallel()

	store := NewMemoryStore(10)
	job, _ := store.Submit(context.Background(), SubmitRequest{OperatorID: "a", IdempotencyKey: "cancel", BundleID: "bundle", Targets: []model.AnalyzeRequest{{Target: "one.example.com", Kind: model.TargetDomain}, {Target: "two.example.com", Kind: model.TargetDomain}}})
	claim, _ := store.Claim(context.Background(), "worker", time.Minute)
	if err := store.RequestCancel(context.Background(), job.ID, "operator-b"); err != nil {
		t.Fatalf("RequestCancel() error = %v", err)
	}
	if got := store.BundlePins("bundle"); got != 1 {
		t.Fatalf("bundle pins after cancellation request = %d, want 1", got)
	}
	if _, err := store.Claim(context.Background(), "worker", time.Minute); model.ErrorCodeOf(err) != model.CodeCapabilityUnavailable {
		t.Fatalf("Claim() after cancellation error = %v", err)
	}
	if err := store.Complete(context.Background(), claim.TargetID, claim.AttemptToken, model.Report{}, TargetCancelled, "cancelled"); err != nil {
		t.Fatalf("Complete(cancelled) error = %v", err)
	}
	if got := store.BundlePins("bundle"); got != 0 {
		t.Fatalf("bundle pins after all terminal = %d", got)
	}
}

func TestConcurrentAdmissionNeverExceedsCapacity(t *testing.T) {
	t.Parallel()

	store := NewMemoryStore(8)
	var wait sync.WaitGroup
	for index := range 32 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			_, _ = store.Submit(context.Background(), SubmitRequest{OperatorID: "operator", IdempotencyKey: time.Unix(int64(index), 0).String(), Targets: []model.AnalyzeRequest{{Target: "example.com", Kind: model.TargetDomain}}})
		}()
	}
	wait.Wait()
	if got := store.Reservations(); got != 8 {
		t.Fatalf("reservations = %d, want 8", got)
	}
}
