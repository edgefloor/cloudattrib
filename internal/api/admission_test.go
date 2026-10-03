package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"cloudattrib/internal/model"
	"cloudattrib/internal/policy"
)

type admissionAnalyzer struct {
	controller *policy.Controller
	started    atomic.Int64
}

func (a *admissionAnalyzer) Analyze(ctx context.Context, _ model.AnalyzeRequest) (model.Report, error) {
	executionCtx, release, err := a.controller.Begin(ctx)
	if err != nil {
		return model.Report{}, err
	}
	defer release()
	a.started.Add(1)
	if err := executionCtx.Err(); err != nil {
		return model.Report{}, err
	}
	return fixtureReport(model.StatusComplete), nil
}

func (a *admissionAnalyzer) LookupIP(ctx context.Context, _ model.IPLookupRequest) (model.IPLookupResult, error) {
	_, release, err := a.controller.Begin(ctx)
	if err != nil {
		return model.IPLookupResult{}, err
	}
	defer release()
	a.started.Add(1)
	return model.IPLookupResult{Address: netip.MustParseAddr("192.0.2.1")}, nil
}

func (*admissionAnalyzer) Reclassify(context.Context, model.ReclassifyRequest) (model.Report, error) {
	return model.Report{}, nil
}

func TestSynchronousAdmissionBoundsWaitersAndRejectsWithoutCollection(t *testing.T) {
	controller, err := policy.NewController(policy.DefaultLimits(), 1, 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	_, releaseWorker, err := controller.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer releaseWorker()
	analyzer := &admissionAnalyzer{controller: controller}
	handler := mustHandler(t, Config{Analyzer: analyzer, SynchronousWaiters: 1, SynchronousAdmissionTimeout: time.Second})
	first := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		first <- serve(handler, http.MethodPost, "/v1/analyze", `{"target":"example.com","kind":"domain"}`, "127.0.0.1:1000", nil)
	}()
	deadline := time.Now().Add(time.Second)
	for controller.TargetAdmission().Waiting != 1 {
		if time.Now().After(deadline) {
			t.Fatal("first request did not reach shared target admission")
		}
		time.Sleep(time.Millisecond)
	}
	rejected := serve(handler, http.MethodPost, "/v1/analyze", `{"target":"example.org","kind":"domain"}`, "127.0.0.1:1000", nil)
	if rejected.Code != http.StatusTooManyRequests || decodeError(t, rejected).Code != model.CodeQueueCapacityExceeded {
		t.Fatalf("overflow response = %d %s", rejected.Code, rejected.Body.String())
	}
	if analyzer.started.Load() != 0 {
		t.Fatal("collection started before admission")
	}
	releaseWorker()
	if completed := <-first; completed.Code != http.StatusOK {
		t.Fatalf("admitted response = %d %s", completed.Code, completed.Body.String())
	}
	if analyzer.started.Load() != 1 {
		t.Fatalf("collection starts = %d, want 1", analyzer.started.Load())
	}
	metrics := serve(handler, http.MethodGet, "/metrics", "", "127.0.0.1:1000", nil)
	if !strings.Contains(metrics.Body.String(), "cloudattrib_synchronous_admission_rejections_total 1") || !strings.Contains(metrics.Body.String(), "cloudattrib_synchronous_admission_waiting 0") {
		t.Fatalf("admission metrics = %s", metrics.Body.String())
	}
}

func TestSynchronousAdmissionTimeoutDoesNotConsumeTargetSlot(t *testing.T) {
	controller, err := policy.NewController(policy.DefaultLimits(), 1, 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	_, releaseWorker, err := controller.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	analyzer := &admissionAnalyzer{controller: controller}
	handler := mustHandler(t, Config{Analyzer: analyzer, SynchronousWaiters: 1, SynchronousAdmissionTimeout: 10 * time.Millisecond})
	rejected := serve(handler, http.MethodPost, "/v1/analyze", `{"target":"example.com","kind":"domain"}`, "127.0.0.1:1000", nil)
	if rejected.Code != http.StatusTooManyRequests || decodeError(t, rejected).Code != model.CodeQueueCapacityExceeded {
		t.Fatalf("timeout response = %d %s", rejected.Code, rejected.Body.String())
	}
	if analyzer.started.Load() != 0 {
		t.Fatal("timed-out request collected")
	}
	releaseWorker()
	completed := serve(handler, http.MethodPost, "/v1/analyze", `{"target":"example.org","kind":"domain"}`, "127.0.0.1:1000", nil)
	if completed.Code != http.StatusOK {
		t.Fatalf("later response = %d %s", completed.Code, completed.Body.String())
	}
}

func TestCancelledSynchronousWaiterReleasesCapacity(t *testing.T) {
	controller, err := policy.NewController(policy.DefaultLimits(), 1, 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	_, releaseWorker, err := controller.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer releaseWorker()
	analyzer := &admissionAnalyzer{controller: controller}
	handler := mustHandler(t, Config{Analyzer: analyzer, SynchronousWaiters: 1, SynchronousAdmissionTimeout: time.Second})
	ctx, cancel := context.WithCancel(t.Context())
	request := httptest.NewRequest(http.MethodPost, "/v1/analyze", strings.NewReader(`{"target":"example.com","kind":"domain"}`)).WithContext(ctx)
	request.RemoteAddr = "127.0.0.1:1000"
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		handler.ServeHTTP(httptest.NewRecorder(), request)
	}()
	deadline := time.Now().Add(time.Second)
	for controller.TargetAdmission().Waiting != 1 {
		if time.Now().After(deadline) {
			t.Fatal("request did not reach shared target admission")
		}
		time.Sleep(time.Millisecond)
	}
	cancel()
	<-finished
	if analyzer.started.Load() != 0 || controller.TargetAdmission().Waiting != 0 {
		t.Fatalf("cancelled request retained admission: starts=%d state=%#v", analyzer.started.Load(), controller.TargetAdmission())
	}
	// A new request can occupy the released API waiter slot while the worker
	// continues to hold the target permit.
	second := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		second <- serve(handler, http.MethodPost, "/v1/analyze", `{"target":"example.org","kind":"domain"}`, "127.0.0.1:1000", nil)
	}()
	deadline = time.Now().Add(time.Second)
	for controller.TargetAdmission().Waiting != 1 {
		if time.Now().After(deadline) {
			t.Fatal("replacement request could not wait")
		}
		time.Sleep(time.Millisecond)
	}
	releaseWorker()
	if result := <-second; result.Code != http.StatusOK {
		t.Fatalf("replacement response = %d %s", result.Code, result.Body.String())
	}
}
