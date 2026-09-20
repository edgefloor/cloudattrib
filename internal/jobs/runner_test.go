package jobs

import (
	"context"
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
	loaded, err := store.Job(context.Background(), job.ID)
	if err != nil || loaded.Status != JobCompleted || loaded.Targets[0].Report.ID != "report" {
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
	if err != nil || !called || loaded.Status != JobCompleted || loaded.Targets[0].Report.OriginalReportID != "report-1" {
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

type fixtureAnalyzerFactory struct {
	bundleID     string
	reclassified *bool
}

func (f *fixtureAnalyzerFactory) AnalyzerForBundle(_ context.Context, bundleID string) (app.Analyzer, error) {
	f.bundleID = bundleID
	return fixtureAnalyzer{bundleID: bundleID, reclassified: f.reclassified}, nil
}

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

func (f blockingAnalyzerFactory) AnalyzerForBundle(context.Context, string) (app.Analyzer, error) {
	return blockingAnalyzer{started: f.started}, nil
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
