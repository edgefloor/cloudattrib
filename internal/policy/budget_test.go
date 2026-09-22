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

func TestAcquirePermitRejectsAlreadyCancelledContext(t *testing.T) {
	t.Parallel()

	for range 1000 {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		permits := make(chan struct{}, 1)
		if err := acquirePermit(ctx, permits); !errors.Is(err, context.Canceled) {
			t.Fatalf("acquirePermit() error = %v, want context.Canceled", err)
		}
		if len(permits) != 0 {
			t.Fatal("cancelled acquisition retained a permit")
		}
	}
}

func TestControllerPacesSameDestinationAcrossExecutions(t *testing.T) {
	t.Parallel()

	limits := DefaultLimits()
	limits.HTTPDestinationInterval = 40 * time.Millisecond
	controller, err := NewController(limits, 2, 2, 2)
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

	firstRelease, err := AcquireHTTP(firstCtx, "93.184.216.34:443")
	if err != nil {
		t.Fatal(err)
	}
	firstRelease()
	started := time.Now()
	secondRelease, err := AcquireHTTP(secondCtx, "93.184.216.34:443")
	if err != nil {
		t.Fatal(err)
	}
	secondRelease()
	if elapsed := time.Since(started); elapsed < 30*time.Millisecond {
		t.Fatalf("same-destination admission waited %v, want pacing interval", elapsed)
	}
}

func TestControllerPacesAfterProcessPermitAdmission(t *testing.T) {
	limits := DefaultLimits()
	limits.HTTPDestinationInterval = 50 * time.Millisecond
	controller, err := NewController(limits, 3, 3, 1)
	if err != nil {
		t.Fatal(err)
	}
	contexts := make([]context.Context, 3)
	releaseTargets := make([]func(), 3)
	for index := range contexts {
		contexts[index], releaseTargets[index], err = controller.Begin(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		defer releaseTargets[index]()
	}

	blocker, err := AcquireHTTP(contexts[0], "1.1.1.1:443")
	if err != nil {
		t.Fatal(err)
	}
	starts := make(chan time.Time, 2)
	for _, ctx := range contexts[1:] {
		go func() {
			release, acquireErr := AcquireHTTP(ctx, "93.184.216.34:443")
			if acquireErr != nil {
				return
			}
			starts <- time.Now()
			release()
		}()
	}
	time.Sleep(2 * limits.HTTPDestinationInterval)
	blocker()
	first := <-starts
	second := <-starts
	if spacing := second.Sub(first); spacing < 40*time.Millisecond {
		t.Fatalf("same-destination starts were spaced by %v after permit contention", spacing)
	}
}

func TestCancelledDestinationWaiterDoesNotDelayNextRequest(t *testing.T) {
	limits := DefaultLimits()
	limits.HTTPDestinationInterval = 80 * time.Millisecond
	controller, err := NewController(limits, 3, 3, 3)
	if err != nil {
		t.Fatal(err)
	}
	contexts := make([]context.Context, 3)
	releaseTargets := make([]func(), 3)
	for index := range contexts {
		contexts[index], releaseTargets[index], err = controller.Begin(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		defer releaseTargets[index]()
	}
	first, err := AcquireHTTP(contexts[0], "93.184.216.34:443")
	if err != nil {
		t.Fatal(err)
	}
	first()

	cancelledCtx, cancel := context.WithTimeout(contexts[1], 10*time.Millisecond)
	defer cancel()
	if release, acquireErr := AcquireHTTP(cancelledCtx, "93.184.216.34:443"); !errors.Is(acquireErr, context.DeadlineExceeded) {
		if release != nil {
			release()
		}
		t.Fatalf("cancelled destination acquisition error = %v", acquireErr)
	}
	time.Sleep(limits.HTTPDestinationInterval)
	started := time.Now()
	third, err := AcquireHTTP(contexts[2], "93.184.216.34:443")
	if err != nil {
		t.Fatal(err)
	}
	third()
	if delay := time.Since(started); delay > 30*time.Millisecond {
		t.Fatalf("cancelled waiter delayed next request by %v", delay)
	}
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
	releaseHTTP, err := AcquireHTTP(firstCtx, "93.184.216.34:443")
	if err != nil {
		t.Fatal(err)
	}
	releaseHTTP()
	if release, err := AcquireHTTP(firstCtx, "93.184.216.34:443"); model.ErrorCodeOf(err) != model.CodeBudgetExceeded {
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
