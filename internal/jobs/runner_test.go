package jobs

import (
	"context"
	"sync"
	"testing"
	"time"

	"cloudattrib/internal/app"
	"cloudattrib/internal/model"
)

func TestRunnerUsesPinnedBundleAndCommitsTerminalReport(t *testing.T) {
	t.Parallel()

	store := NewMemoryStore(4)
	job, err := store.Submit(context.Background(), SubmitRequest{OperatorID: "operator", IdempotencyKey: "runner", BundleID: "bundle-1", Targets: []model.AnalyzeRequest{{Target: "example.com", Kind: model.TargetDomain}}})
	if err != nil {
		t.Fatalf("Submit() error = %v", err)
	}
	factory := &fixtureAnalyzerFactory{}
	runner := Runner{Store: store, Factory: factory, WorkerID: "worker", Lease: time.Second}
	if err := runner.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce() error = %v", err)
	}
	if factory.bundleID != "bundle-1" {
		t.Fatalf("factory bundle = %q", factory.bundleID)
	}
	if factory.releases != 1 {
		t.Fatalf("capture releases = %d, want 1", factory.releases)
	}
	loaded, err := store.Job(context.Background(), job.ID)
	if err != nil || loaded.Status != JobCompleted || loaded.Targets[0].ReportID != "report" {
		t.Fatalf("Job() = %#v, %v", loaded, err)
	}
}

func TestRunnerExecutesPinnedReclassification(t *testing.T) {
	t.Parallel()

	store := NewMemoryStore(2)
	job, err := store.Submit(context.Background(), SubmitRequest{
		OperatorID: "operator", IdempotencyKey: "reclassify", BundleID: "bundle-2",
		Reclassifications: []model.ReclassifyRequest{{ReportID: "report-1", BundleID: "bundle-2"}},
	})
	if err != nil {
		t.Fatalf("Submit() error = %v", err)
	}
	called := false
	factory := &fixtureAnalyzerFactory{reclassified: &called}
	runner := Runner{Store: store, Factory: factory, WorkerID: "worker", Lease: time.Second}
	if err := runner.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce() error = %v", err)
	}
	loaded, err := store.Job(context.Background(), job.ID)
	if err != nil || !called || loaded.Status != JobCompleted || loaded.Targets[0].ReportID != "reclassified" || loaded.Targets[0].Report.OriginalReportID != "report-1" {
		t.Fatalf("Job() = %#v, called=%v, %v", loaded, called, err)
	}
}

func TestRunnerObservesCancellationDuringLeaseRenewal(t *testing.T) {
	t.Parallel()

	store := NewMemoryStore(2)
	job, err := store.Submit(context.Background(), SubmitRequest{OperatorID: "operator", IdempotencyKey: "cancel-runner", Targets: []model.AnalyzeRequest{{Target: "example.com", Kind: model.TargetDomain}}})
	if err != nil {
		t.Fatalf("Submit() error = %v", err)
	}
	started := make(chan struct{})
	runner := Runner{Store: store, Factory: blockingAnalyzerFactory{started: started}, WorkerID: "worker", Lease: 30 * time.Millisecond}
	done := make(chan error, 1)
	go func() { done <- runner.RunOnce(context.Background()) }()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("analyzer did not start")
	}
	if err := store.RequestCancel(context.Background(), job.ID, "other-operator"); err != nil {
		t.Fatalf("RequestCancel() error = %v", err)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("runner did not stop after cancellation")
	}
	loaded, err := store.Job(context.Background(), job.ID)
	if err != nil || loaded.Status != JobCancelled || loaded.Targets[0].Status != TargetCancelled {
		t.Fatalf("Job() = %#v, %v", loaded, err)
	}
}

func TestRunnerRenewsLeaseAndCancelsDuringBundleAcquisition(t *testing.T) {
	t.Parallel()

	memory := NewMemoryStore(2)
	job, err := memory.Submit(t.Context(), SubmitRequest{OperatorID: "operator", IdempotencyKey: "cancel-load", BundleID: "bundle-slow", Targets: []model.AnalyzeRequest{{Target: "example.com", Kind: model.TargetDomain}}})
	if err != nil {
		t.Fatalf("Submit() error = %v", err)
	}
	renewed := make(chan struct{})
	store := &renewObservedStore{MemoryStore: memory, renewed: renewed}
	factory := &blockingBundleFactory{started: make(chan struct{})}
	runner := Runner{Store: store, Factory: factory, WorkerID: "worker", Lease: 30 * time.Millisecond}
	done := make(chan error, 1)
	go func() { done <- runner.RunOnce(context.Background()) }()
	select {
	case <-factory.started:
	case <-time.After(time.Second):
		t.Fatal("bundle acquisition did not start")
	}
	select {
	case <-renewed:
	case <-time.After(time.Second):
		t.Fatal("lease was not renewed during bundle acquisition")
	}
	if err := memory.RequestCancel(t.Context(), job.ID, "operator"); err != nil {
		t.Fatalf("RequestCancel() error = %v", err)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("runner did not stop after acquisition cancellation")
	}
	loaded, err := memory.Job(t.Context(), job.ID)
	if err != nil || loaded.Targets[0].Status != TargetCancelled {
		t.Fatalf("Job() = %#v, %v", loaded, err)
	}
}

type renewObservedStore struct {
	*MemoryStore
	renewed chan struct{}
	once    sync.Once
}

func (s *renewObservedStore) Renew(ctx context.Context, targetID, token string, lease time.Duration) error {
	s.once.Do(func() { close(s.renewed) })
	return s.MemoryStore.Renew(ctx, targetID, token, lease)
}

type blockingBundleFactory struct {
	started chan struct{}
}

func (f *blockingBundleFactory) CaptureAnalyzer(ctx context.Context, _ string) (CapturedAnalyzer, error) {
	close(f.started)
	<-ctx.Done()
	return nil, ctx.Err()
}

type fixtureAnalyzerFactory struct {
	bundleID     string
	reclassified *bool
	releases     int
}

func (f *fixtureAnalyzerFactory) CaptureAnalyzer(_ context.Context, bundleID string) (CapturedAnalyzer, error) {
	f.bundleID = bundleID
	return &fixtureCapturedAnalyzer{
		analyzer: fixtureAnalyzer{bundleID: bundleID, reclassified: f.reclassified},
		release:  func() { f.releases++ },
	}, nil
}

type fixtureCapturedAnalyzer struct {
	analyzer app.Analyzer
	release  func()
}

func (c *fixtureCapturedAnalyzer) Analyzer() app.Analyzer { return c.analyzer }
func (c *fixtureCapturedAnalyzer) Release()               { c.release() }

type fixtureAnalyzer struct {
	bundleID     string
	reclassified *bool
}

func (f fixtureAnalyzer) Analyze(context.Context, model.AnalyzeRequest) (model.Report, error) {
	return model.Report{ID: "report", BundleID: f.bundleID, Status: model.StatusComplete}, nil
}
func (fixtureAnalyzer) LookupIP(context.Context, model.IPLookupRequest) (model.IPLookupResult, error) {
	return model.IPLookupResult{}, nil
}
func (f fixtureAnalyzer) Reclassify(_ context.Context, request model.ReclassifyRequest) (model.Report, error) {
	if f.reclassified != nil {
		*f.reclassified = true
	}
	return model.Report{ID: "reclassified", OriginalReportID: request.ReportID, BundleID: f.bundleID, Status: model.StatusComplete}, nil
}

type blockingAnalyzerFactory struct{ started chan<- struct{} }

func (f blockingAnalyzerFactory) CaptureAnalyzer(context.Context, string) (CapturedAnalyzer, error) {
	return &fixtureCapturedAnalyzer{analyzer: blockingAnalyzer(f), release: func() {}}, nil
}

type blockingAnalyzer struct{ started chan<- struct{} }

func (a blockingAnalyzer) Analyze(ctx context.Context, _ model.AnalyzeRequest) (model.Report, error) {
	close(a.started)
	<-ctx.Done()
	return model.Report{}, ctx.Err()
}
func (blockingAnalyzer) LookupIP(context.Context, model.IPLookupRequest) (model.IPLookupResult, error) {
	return model.IPLookupResult{}, nil
}
func (blockingAnalyzer) Reclassify(context.Context, model.ReclassifyRequest) (model.Report, error) {
	return model.Report{}, nil
}
