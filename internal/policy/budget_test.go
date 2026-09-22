package policy

import (
	"context"
	"errors"
	"testing"
	"time"

	"cloudattrib/internal/model"
)

func TestControllerCancelledTargetWaiterNeverAcquires(t *testing.T) {
	limits := DefaultLimits()
	controller, err := NewController(limits, 1, 1, 1)
	if err != nil {
		t.Fatal(err)
	}

	first, releaseFirst, err := controller.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer releaseFirst()
	if first == nil {
		t.Fatal("Begin() returned a nil execution context")
	}

	waitCtx, cancelWait := context.WithCancel(t.Context())
	waitResult := make(chan error, 1)
	go func() {
		_, release, beginErr := controller.Begin(waitCtx)
		if release != nil {
			release()
		}
		waitResult <- beginErr
	}()
	cancelWait()
	if err := <-waitResult; !errors.Is(err, context.Canceled) || model.ErrorCodeOf(err) != model.CodeCancelled {
		t.Fatalf("cancelled Begin() error = %v", err)
	}

	releaseFirst()
	thirdCtx, releaseThird, err := controller.Begin(t.Context())
	if err != nil {
		t.Fatalf("third Begin() error = %v", err)
	}
	if err := thirdCtx.Err(); err != nil {
		t.Fatalf("third execution context error = %v", err)
	}
	releaseThird()
}

func TestControllerTargetDeadlineStartsAfterAdmission(t *testing.T) {
	limits := DefaultLimits()
	limits.TargetDeadline = 80 * time.Millisecond
	controller, err := NewController(limits, 1, 1, 1)
	if err != nil {
		t.Fatal(err)
	}

	_, releaseFirst, err := controller.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(releaseFirst)

	started := make(chan context.Context, 1)
	releases := make(chan func(), 1)
	go func() {
		executionCtx, release, beginErr := controller.Begin(t.Context())
		if beginErr != nil {
			started <- nil
			return
		}
		started <- executionCtx
		releases <- release
	}()

	time.Sleep(limits.TargetDeadline + 20*time.Millisecond)
	releaseFirst()
	executionCtx := <-started
	if executionCtx == nil {
		t.Fatal("waiter did not enter execution after admission")
	}
	defer (<-releases)()
	if err := executionCtx.Err(); err != nil {
		t.Fatalf("execution deadline was consumed by queue wait: %v", err)
	}
	select {
	case <-executionCtx.Done():
		if !errors.Is(executionCtx.Err(), context.DeadlineExceeded) {
			t.Fatalf("execution context error = %v", executionCtx.Err())
		}
	case <-time.After(time.Second):
		t.Fatal("execution deadline did not expire")
	}
}

func TestControllerSharesNetworkPermitsAndBudgets(t *testing.T) {
	limits := DefaultLimits()
	limits.DNSQuestions = 1
	limits.HTTPRequests = 1
	limits.ResolvedAddresses = 1
	limits.HTTPTotalBodyBytes = 3
	controller, err := NewController(limits, 2, 1, 1)
	if err != nil {
		t.Fatal(err)
	}

	firstCtx, releaseFirst, err := controller.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer releaseFirst()
	secondCtx, releaseSecond, err := controller.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer releaseSecond()

	releaseDNS, err := AcquireDNS(firstCtx)
	if err != nil {
		t.Fatal(err)
	}
	dnsAcquired := make(chan func(), 1)
	go func() {
		release, acquireErr := AcquireDNS(secondCtx)
		if acquireErr == nil {
			dnsAcquired <- release
		}
	}()
	select {
	case release := <-dnsAcquired:
		release()
		t.Fatal("second execution acquired the process DNS permit early")
	case <-time.After(20 * time.Millisecond):
	}
	releaseDNS()
	select {
	case release := <-dnsAcquired:
		release()
	case <-time.After(time.Second):
		t.Fatal("second execution did not acquire the released DNS permit")
	}

	if release, err := AcquireDNS(firstCtx); model.ErrorCodeOf(err) != model.CodeBudgetExceeded {
		if release != nil {
			release()
		}
		t.Fatalf("second DNS acquisition error = %v", err)
	}
	releaseHTTP, err := AcquireHTTP(firstCtx)
	if err != nil {
		t.Fatal(err)
	}
	releaseHTTP()
	if release, err := AcquireHTTP(firstCtx); model.ErrorCodeOf(err) != model.CodeBudgetExceeded {
		if release != nil {
			release()
		}
		t.Fatalf("second HTTP acquisition error = %v", err)
	}
	if !ReserveAddress(firstCtx) || ReserveAddress(firstCtx) {
		t.Fatal("resolved-address budget did not allow exactly one address")
	}
	allowance, commit := ReserveHTTPBody(firstCtx, 10)
	if allowance != 3 {
		t.Fatalf("body allowance = %d, want 3", allowance)
	}
	commit(2)
	allowance, commit = ReserveHTTPBody(firstCtx, 10)
	if allowance != 1 {
		t.Fatalf("refunded body allowance = %d, want 1", allowance)
	}
	commit(1)
	if allowance, _ := ReserveHTTPBody(firstCtx, 10); allowance != 0 {
		t.Fatalf("exhausted body allowance = %d, want 0", allowance)
	}
}
