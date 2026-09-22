package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	goruntime "runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"cloudattrib/internal/api"
	"cloudattrib/internal/app"
	collectdns "cloudattrib/internal/collect/dns"
	"cloudattrib/internal/ctlog"
	"cloudattrib/internal/datasets"
	"cloudattrib/internal/jobs"
	"cloudattrib/internal/model"
	"cloudattrib/internal/policy"
)

func TestPostgresAPIJobPollingIsConstantAndSkipsReportDocuments(t *testing.T) {
	dsn := os.Getenv("CLOUDATTRIB_POSTGRES_TEST_DSN")
	if dsn == "" {
		t.Skip("CLOUDATTRIB_POSTGRES_TEST_DSN is not set")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
	defer cancel()
	configuration, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatalf("parse PostgreSQL configuration: %v", err)
	}
	tracer := &queryRecorder{}
	configuration.ConnConfig.Tracer = tracer
	store, err := openWithConfig(ctx, configuration, 2000)
	if err != nil {
		t.Fatalf("openWithConfig() error = %v", err)
	}
	t.Cleanup(store.Close)
	if _, err := store.pool.Exec(ctx, `TRUNCATE ct_records,ct_checkpoints,finding_evidence,findings,evidence,observations,job_targets,reports,bundle_pins,jobs,dataset_bundles RESTART IDENTITY CASCADE; UPDATE queue_capacity SET reserved_targets=0,maximum_targets=2000 WHERE singleton=true`); err != nil {
		t.Fatalf("reset database: %v", err)
	}
	smallReport := model.Report{
		SchemaVersion: model.SchemaVersion,
		ID:            "projection-small",
		Target:        model.Target{Original: "example.com", Canonical: "example.com", Kind: model.TargetDomain},
		Status:        model.StatusComplete,
		ClassifiedAt:  time.Unix(1, 0).UTC(),
	}
	largeReport := smallReport
	largeReport.ID = "projection-large"
	largeReport.Observations = []model.Observation{{
		ID: "large-observation", Type: "fixture", Subject: "example.com", Status: "answered",
		Payload: model.JSONValue(`{"blob":"` + strings.Repeat("x", 256<<10) + `"}`),
	}}
	for _, report := range []model.Report{smallReport, largeReport} {
		if err := store.SaveReport(ctx, report); err != nil {
			t.Fatalf("SaveReport(%q) error = %v", report.ID, err)
		}
	}
	insertCompletedProjectionJob(t, ctx, store, "projection-small", smallReport.ID)
	insertCompletedProjectionJob(t, ctx, store, "projection-large", largeReport.ID)

	handler, err := api.NewHandler(api.Config{Jobs: store, Results: store})
	if err != nil {
		t.Fatalf("NewHandler() error = %v", err)
	}
	tracer.Start()
	body, err := pollJob(ctx, handler, "projection-large")
	statements := tracer.Stop()
	if err != nil {
		t.Fatalf("poll completed job: %v", err)
	}
	if len(statements) != 2 {
		t.Fatalf("poll query count = %d, want 2: %#v", len(statements), statements)
	}
	for _, statement := range statements {
		lower := strings.ToLower(statement)
		if strings.Contains(lower, " from reports") || strings.Contains(lower, " join reports") || strings.Contains(lower, " document") {
			t.Fatalf("poll loaded a report document: %s", statement)
		}
	}
	if !strings.Contains(strings.ToLower(statements[0]), " from jobs") || !strings.Contains(strings.ToLower(statements[1]), " from job_targets") {
		t.Fatalf("poll statements = %#v, want one job and one target projection query", statements)
	}
	var response struct {
		Status  jobs.JobStatus            `json:"status"`
		Counts  map[jobs.TargetStatus]int `json:"counts"`
		Targets []struct {
			InputIndex int               `json:"input_index"`
			Status     jobs.TargetStatus `json:"status"`
			Attempts   int               `json:"attempts"`
			ResultURL  string            `json:"result_url"`
		} `json:"targets"`
	}
	if err := json.Unmarshal(body, &response); err != nil {
		t.Fatalf("decode poll response: %v", err)
	}
	if response.Status != jobs.JobCompleted || response.Counts[jobs.TargetCompleted] != 1000 || len(response.Targets) != 1000 {
		t.Fatalf("poll response status=%q counts=%#v targets=%d", response.Status, response.Counts, len(response.Targets))
	}
	for index, target := range response.Targets {
		if target.InputIndex != index || target.Status != jobs.TargetCompleted || target.Attempts != 1 || target.ResultURL != "/v1/results/"+largeReport.ID {
			t.Fatalf("target[%d] = %#v", index, target)
		}
	}

	if _, err := pollJob(ctx, handler, "projection-small"); err != nil {
		t.Fatalf("warm small projection: %v", err)
	}
	if _, err := pollJob(ctx, handler, "projection-large"); err != nil {
		t.Fatalf("warm large projection: %v", err)
	}
	benchmarkCtx, cancelBenchmark := context.WithTimeout(ctx, 20*time.Second)
	defer cancelBenchmark()
	smallAllocations, err := benchmarkJobPoll(benchmarkCtx, handler, "projection-small")
	if err != nil {
		t.Fatalf("benchmark small projection: %v", err)
	}
	largeAllocations, err := benchmarkJobPoll(benchmarkCtx, handler, "projection-large")
	if err != nil {
		t.Fatalf("benchmark large projection: %v", err)
	}
	t.Logf("job poll small=%d B/op %d allocs/op large=%d B/op %d allocs/op", smallAllocations.AllocedBytesPerOp(), smallAllocations.AllocsPerOp(), largeAllocations.AllocedBytesPerOp(), largeAllocations.AllocsPerOp())
	if largeAllocations.AllocedBytesPerOp() > smallAllocations.AllocedBytesPerOp()+(64<<10) || largeAllocations.AllocsPerOp() > smallAllocations.AllocsPerOp()+100 {
		t.Fatalf("poll allocations grew with report document size: small=%d B/op %d allocs/op large=%d B/op %d allocs/op", smallAllocations.AllocedBytesPerOp(), smallAllocations.AllocsPerOp(), largeAllocations.AllocedBytesPerOp(), largeAllocations.AllocsPerOp())
	}

	result := httptest.NewRecorder()
	request := httptest.NewRequestWithContext(ctx, http.MethodGet, "/v1/results/"+largeReport.ID, nil)
	request.RemoteAddr = "127.0.0.1:1000"
	handler.ServeHTTP(result, request)
	if result.Code != http.StatusOK || !strings.Contains(result.Body.String(), "large-observation") {
		t.Fatalf("separate result retrieval = %d, body length %d", result.Code, result.Body.Len())
	}
}

func TestPostgresAPIAndWorkerShareTargetAdmissionAcrossBundles(t *testing.T) {
	for _, scenario := range []struct {
		name, activeBundle, workerBundle string
	}{
		{name: "active a worker b", activeBundle: "bundle-a", workerBundle: "bundle-b"},
		{name: "active b worker a", activeBundle: "bundle-b", workerBundle: "bundle-a"},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			store, ctx := openPostgresTest(t, 4)
			for _, bundleID := range []string{"bundle-a", "bundle-b"} {
				if err := store.RegisterBundle(ctx, bundleID, []byte(`{"schema_version":1}`), true); err != nil {
					t.Fatalf("RegisterBundle(%q) error = %v", bundleID, err)
				}
			}
			limits := policy.DefaultLimits()
			controller, err := policy.NewController(limits, 1, 8, 4)
			if err != nil {
				t.Fatal(err)
			}

			firstStarted := make(chan struct{})
			releaseFirst := make(chan struct{})
			var releaseFirstOnce sync.Once
			release := func() { releaseFirstOnce.Do(func() { close(releaseFirst) }) }
			var activeQueries atomic.Int64
			activeCollector := collectdns.New(func(ctx context.Context, question model.DNSQuestion) (model.DNSResult, error) {
				if activeQueries.Add(1) == 6 {
					close(firstStarted)
				}
				select {
				case <-ctx.Done():
					return model.DNSResult{Question: question}, ctx.Err()
				case <-releaseFirst:
					return model.DNSResult{Question: question}, nil
				}
			}, policy.PublicDestinationPolicy())
			var workerQueries atomic.Int64
			workerCollector := collectdns.New(func(_ context.Context, question model.DNSQuestion) (model.DNSResult, error) {
				workerQueries.Add(1)
				return model.DNSResult{Question: question}, nil
			}, policy.PublicDestinationPolicy())
			activeAnalyzer := app.NewService(app.Dependencies{
				DNS: activeCollector, Controller: controller, Limits: limits,
				View: model.NewAttributionView(scenario.activeBundle, "acceptance", nil, nil),
			})
			workerAnalyzer := app.NewService(app.Dependencies{
				DNS: workerCollector, Controller: controller, Limits: limits,
				View: model.NewAttributionView(scenario.workerBundle, "acceptance", nil, nil),
			})
			factory := &admissionAcceptanceFactory{
				activeBundle: scenario.activeBundle,
				bundles: map[string]app.Analyzer{
					scenario.activeBundle: activeAnalyzer,
					scenario.workerBundle: workerAnalyzer,
				},
				apiEntered:    make(chan string, 2),
				workerEntered: make(chan string, 1),
			}
			handler, err := api.NewHandler(api.Config{Analyzer: factory, Jobs: store, Results: store})
			if err != nil {
				t.Fatalf("NewHandler() error = %v", err)
			}
			server := httptest.NewServer(handler)
			t.Cleanup(func() {
				release()
				server.Close()
			})

			firstDone := make(chan apiResponse, 1)
			go func() {
				firstDone <- postAPIJSON(ctx, server.Client(), server.URL+"/v1/analyze", `{"target":"first.example.com","kind":"domain","mode":"dns","include_www":false}`)
			}()
			if captured := awaitValue(t, factory.apiEntered, "first API analysis entry"); captured != scenario.activeBundle {
				t.Fatalf("first API captured bundle %q, want %q", captured, scenario.activeBundle)
			}
			awaitValue(t, firstStarted, "first API DNS collection")

			jobResponse := postAPIJSON(ctx, server.Client(), server.URL+"/v1/jobs", fmt.Sprintf(`{"idempotency_key":"%s-job","bundle_id":"%s","targets":[{"target":"worker.example.com","kind":"domain","mode":"dns","include_www":false}]}`, scenario.activeBundle, scenario.workerBundle))
			if jobResponse.err != nil || jobResponse.status != http.StatusAccepted {
				t.Fatalf("submit job = %d %s, %v", jobResponse.status, jobResponse.body, jobResponse.err)
			}
			var submitted struct {
				ID string `json:"id"`
			}
			if err := json.Unmarshal(jobResponse.body, &submitted); err != nil || submitted.ID == "" {
				t.Fatalf("decode submitted job: %v, body=%s", err, jobResponse.body)
			}

			runnerDone := make(chan error, 1)
			runner := jobs.Runner{Store: store, Factory: factory, WorkerID: "acceptance-worker", Lease: time.Second}
			go func() { runnerDone <- runner.RunOnce(ctx) }()
			if captured := awaitValue(t, factory.workerEntered, "durable worker analysis entry"); captured != scenario.workerBundle {
				t.Fatalf("worker captured bundle %q, want %q", captured, scenario.workerBundle)
			}

			secondDone := make(chan apiResponse, 1)
			go func() {
				secondDone <- postAPIJSON(ctx, server.Client(), server.URL+"/v1/analyze", `{"target":"second.example.com","kind":"domain","mode":"dns","include_www":false}`)
			}()
			if captured := awaitValue(t, factory.apiEntered, "second API analysis entry"); captured != scenario.activeBundle {
				t.Fatalf("second API captured bundle %q, want %q", captured, scenario.activeBundle)
			}
			awaitTargetAdmission(t, controller, 1, 2)
			if got := activeQueries.Load(); got != 6 {
				t.Fatalf("active analyzer DNS queries before release = %d, want 6", got)
			}
			if got := workerQueries.Load(); got != 0 {
				t.Fatalf("worker analyzer DNS queries before release = %d, want 0", got)
			}

			release()
			for index, result := range []apiResponse{awaitValue(t, firstDone, "first API response"), awaitValue(t, secondDone, "second API response")} {
				if result.err != nil || result.status != http.StatusOK {
					t.Fatalf("API response %d = %d %s, %v", index, result.status, result.body, result.err)
				}
			}
			if err := awaitValue(t, runnerDone, "durable worker completion"); err != nil {
				t.Fatalf("RunOnce() error = %v", err)
			}
			if got := activeQueries.Load(); got != 12 {
				t.Fatalf("active analyzer DNS queries after release = %d, want 12", got)
			}
			if got := workerQueries.Load(); got != 6 {
				t.Fatalf("worker analyzer DNS queries after release = %d, want 6", got)
			}
			job, err := store.Job(ctx, submitted.ID)
			if err != nil || job.Status != jobs.JobCompleted || len(job.Targets) != 1 || job.Targets[0].Status != jobs.TargetCompleted {
				t.Fatalf("completed durable job = %#v, %v", job, err)
			}
		})
	}
}

type admissionAcceptanceFactory struct {
	activeBundle  string
	bundles       map[string]app.Analyzer
	apiEntered    chan string
	workerEntered chan string
}

func (f *admissionAcceptanceFactory) Analyze(ctx context.Context, request model.AnalyzeRequest) (model.Report, error) {
	captured, err := f.capture(f.activeBundle, f.apiEntered)
	if err != nil {
		return model.Report{}, err
	}
	defer captured.Release()
	return captured.Analyzer().Analyze(ctx, request)
}

func (f *admissionAcceptanceFactory) LookupIP(ctx context.Context, request model.IPLookupRequest) (model.IPLookupResult, error) {
	return f.bundles[f.activeBundle].LookupIP(ctx, request)
}

func (f *admissionAcceptanceFactory) Reclassify(ctx context.Context, request model.ReclassifyRequest) (model.Report, error) {
	return f.bundles[f.activeBundle].Reclassify(ctx, request)
}

func (f *admissionAcceptanceFactory) CaptureAnalyzer(_ context.Context, bundleID string) (jobs.CapturedAnalyzer, error) {
	return f.capture(bundleID, f.workerEntered)
}

func (f *admissionAcceptanceFactory) capture(bundleID string, entered chan<- string) (jobs.CapturedAnalyzer, error) {
	analyzer := f.bundles[bundleID]
	if analyzer == nil {
		return nil, fmt.Errorf("bundle %q is unavailable", bundleID)
	}
	return admissionCapturedAnalyzer{
		analyzer: admissionEnteredAnalyzer{Analyzer: analyzer, bundleID: bundleID, entered: entered},
	}, nil
}

type admissionEnteredAnalyzer struct {
	app.Analyzer
	bundleID string
	entered  chan<- string
}

func (a admissionEnteredAnalyzer) Analyze(ctx context.Context, request model.AnalyzeRequest) (model.Report, error) {
	a.entered <- a.bundleID
	return a.Analyzer.Analyze(ctx, request)
}

type admissionCapturedAnalyzer struct {
	analyzer app.Analyzer
}

func (a admissionCapturedAnalyzer) Analyzer() app.Analyzer { return a.analyzer }
func (admissionCapturedAnalyzer) Release()                 {}

type apiResponse struct {
	status int
	body   []byte
	err    error
}

func postAPIJSON(ctx context.Context, client *http.Client, url, body string) apiResponse {
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, url, strings.NewReader(body))
	if err != nil {
		return apiResponse{err: err}
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := client.Do(request)
	if err != nil {
		return apiResponse{err: err}
	}
	encoded, readErr := io.ReadAll(response.Body)
	if closeErr := response.Body.Close(); readErr == nil {
		readErr = closeErr
	}
	return apiResponse{status: response.StatusCode, body: encoded, err: readErr}
}

func awaitTargetAdmission(t *testing.T, controller *policy.Controller, active, waiting int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		snapshot := controller.TargetAdmission()
		if snapshot.Active == active && snapshot.Waiting == waiting {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("target admission = %#v, want active=%d waiting=%d", snapshot, active, waiting)
		}
		goruntime.Gosched()
	}
}

func awaitValue[T any](t *testing.T, channel <-chan T, description string) T {
	t.Helper()
	select {
	case value := <-channel:
		return value
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for %s", description)
		var zero T
		return zero
	}
}

type queryRecorder struct {
	mu         sync.Mutex
	recording  bool
	statements []string
}

func (r *queryRecorder) TraceQueryStart(ctx context.Context, _ *pgx.Conn, data pgx.TraceQueryStartData) context.Context {
	r.mu.Lock()
	if r.recording {
		r.statements = append(r.statements, data.SQL)
	}
	r.mu.Unlock()
	return ctx
}

func (*queryRecorder) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {}

func (r *queryRecorder) Start() {
	r.mu.Lock()
	r.recording = true
	r.statements = nil
	r.mu.Unlock()
}

func (r *queryRecorder) Stop() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.recording = false
	return append([]string(nil), r.statements...)
}

func insertCompletedProjectionJob(t *testing.T, ctx context.Context, store *Store, jobID, reportID string) {
	t.Helper()
	if _, err := store.pool.Exec(ctx, `INSERT INTO jobs(id,operator_id,idempotency_key,payload_hash,status,created_at,updated_at) VALUES($1,'operator',$1,'hash','completed',clock_timestamp(),clock_timestamp())`, jobID); err != nil {
		t.Fatalf("insert job %q: %v", jobID, err)
	}
	batch := &pgx.Batch{}
	for index := range 1000 {
		request, err := json.Marshal(workRequest{Analyze: &model.AnalyzeRequest{Target: fmt.Sprintf("target-%04d.example.com", index), Kind: model.TargetDomain}})
		if err != nil {
			t.Fatalf("encode request: %v", err)
		}
		batch.Queue(`INSERT INTO job_targets(id,job_id,input_index,request,status,attempts,report_id) VALUES($1,$2,$3,$4,'completed',1,$5)`, fmt.Sprintf("%s-target-%04d", jobID, index), jobID, index, request, reportID)
	}
	results := store.pool.SendBatch(ctx, batch)
	if err := results.Close(); err != nil {
		t.Fatalf("insert targets for %q: %v", jobID, err)
	}
}

func pollJob(ctx context.Context, handler http.Handler, jobID string) ([]byte, error) {
	recorder := httptest.NewRecorder()
	request := httptest.NewRequestWithContext(ctx, http.MethodGet, "/v1/jobs/"+jobID, nil)
	request.RemoteAddr = "127.0.0.1:1000"
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		return nil, fmt.Errorf("status %d: %s", recorder.Code, recorder.Body.String())
	}
	return recorder.Body.Bytes(), nil
}

func benchmarkJobPoll(ctx context.Context, handler http.Handler, jobID string) (testing.BenchmarkResult, error) {
	var pollErr error
	result := testing.Benchmark(func(benchmark *testing.B) {
		for benchmark.Loop() {
			if _, err := pollJob(ctx, handler, jobID); err != nil {
				pollErr = err
				benchmark.StopTimer()
				return
			}
		}
	})
	return result, pollErr
}

func TestPostgresConcurrentIdempotentAdmission(t *testing.T) {
	store, ctx := openPostgresTest(t, 32)
	if err := store.RegisterBundle(ctx, "fixture-bundle", []byte(`{"schema_version":1}`), true); err != nil {
		t.Fatalf("RegisterBundle() error = %v", err)
	}

	request := jobs.SubmitRequest{
		OperatorID: "operator-a", IdempotencyKey: "same-key", BundleID: "fixture-bundle",
		Targets: []model.AnalyzeRequest{{Target: "example.com", Kind: model.TargetDomain}},
	}
	const submitters = 16
	start := make(chan struct{})
	results := make(chan jobs.Job, submitters)
	errorsFound := make(chan error, submitters)
	var ready sync.WaitGroup
	ready.Add(submitters)
	for range submitters {
		go func() {
			ready.Done()
			<-start
			job, err := store.Submit(ctx, request)
			results <- job
			errorsFound <- err
		}()
	}
	ready.Wait()
	close(start)

	jobID := ""
	for range submitters {
		if err := <-errorsFound; err != nil {
			t.Errorf("concurrent Submit() error = %v (cause: %v)", err, errors.Unwrap(err))
		}
		job := <-results
		if jobID == "" {
			jobID = job.ID
		} else if job.ID != "" && job.ID != jobID {
			t.Errorf("concurrent Submit() job ID = %q, want %q", job.ID, jobID)
		}
	}

	var jobsFound, targets, reservations, pins int
	if err := store.pool.QueryRow(ctx, `SELECT
		(SELECT count(*) FROM jobs),
		(SELECT count(*) FROM job_targets),
		(SELECT reserved_targets FROM queue_capacity WHERE singleton=true),
		(SELECT count(*) FROM bundle_pins)`).Scan(&jobsFound, &targets, &reservations, &pins); err != nil {
		t.Fatalf("inspect admission state: %v", err)
	}
	if jobsFound != 1 || targets != 1 || reservations != 1 || pins != 1 {
		t.Fatalf("admission state jobs=%d targets=%d reservations=%d pins=%d, want 1 each", jobsFound, targets, reservations, pins)
	}

	conflict := request
	conflict.Targets = []model.AnalyzeRequest{{Target: "other.example.com", Kind: model.TargetDomain}}
	if _, err := store.Submit(ctx, conflict); model.ErrorCodeOf(err) != model.CodeIdempotencyConflict {
		t.Fatalf("conflicting Submit() error = %v, want idempotency conflict", err)
	}
}

func TestPostgresRejectsQueryBearingURLBeforePersistence(t *testing.T) {
	store, ctx := openPostgresTest(t, 1)
	_, err := store.Submit(ctx, jobs.SubmitRequest{
		OperatorID: "operator-a", IdempotencyKey: "query-secret",
		Targets: []model.AnalyzeRequest{{Target: "https://example.com/path?token=QUERY_CANARY", Kind: model.TargetURL}},
	})
	if model.ErrorCodeOf(err) != model.CodeInvalidTarget {
		t.Fatalf("Submit() error = %v, want invalid_target", err)
	}
	if strings.Contains(err.Error(), "QUERY_CANARY") {
		t.Fatalf("Submit() error exposed query value: %v", err)
	}
	var jobsFound, targets int
	if err := store.pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM jobs), (SELECT count(*) FROM job_targets)`).Scan(&jobsFound, &targets); err != nil {
		t.Fatalf("inspect rejected request persistence: %v", err)
	}
	if jobsFound != 0 || targets != 0 {
		t.Fatalf("rejected request persisted jobs=%d targets=%d", jobsFound, targets)
	}
}

func TestPostgresConcurrentDifferentKeyAdmissionConservesCapacity(t *testing.T) {
	const capacity = 8
	store, ctx := openPostgresTest(t, capacity)
	if err := store.RegisterBundle(ctx, "fixture-bundle", []byte(`{"schema_version":1}`), true); err != nil {
		t.Fatalf("RegisterBundle() error = %v", err)
	}

	const submitters = 12
	start := make(chan struct{})
	errorsFound := make(chan error, submitters)
	var ready sync.WaitGroup
	ready.Add(submitters)
	for index := range submitters {
		go func() {
			ready.Done()
			<-start
			_, err := store.Submit(ctx, jobs.SubmitRequest{
				OperatorID: "operator-a", IdempotencyKey: fmt.Sprintf("key-%d", index), BundleID: "fixture-bundle",
				Targets: []model.AnalyzeRequest{{Target: fmt.Sprintf("target-%d.example.com", index), Kind: model.TargetDomain}},
			})
			errorsFound <- err
		}()
	}
	ready.Wait()
	close(start)

	accepted, rejected := 0, 0
	for range submitters {
		switch err := <-errorsFound; model.ErrorCodeOf(err) {
		case "":
			accepted++
		case model.CodeQueueCapacityExceeded:
			rejected++
		default:
			t.Errorf("concurrent Submit() error = %v (cause: %v)", err, errors.Unwrap(err))
		}
	}
	if accepted != capacity || rejected != submitters-capacity {
		t.Fatalf("accepted=%d rejected=%d, want %d and %d", accepted, rejected, capacity, submitters-capacity)
	}
	assertLifecycleCounts(t, ctx, store, capacity, capacity)
}

func TestPostgresClaimAndCancellationUseOneLockProtocol(t *testing.T) {
	store, ctx := openPostgresTest(t, 2)
	if err := store.RegisterBundle(ctx, "fixture-bundle", []byte(`{"schema_version":1}`), true); err != nil {
		t.Fatalf("RegisterBundle() error = %v", err)
	}
	job, err := store.Submit(ctx, jobs.SubmitRequest{
		OperatorID: "operator-a", IdempotencyKey: "claim-cancel", BundleID: "fixture-bundle",
		Targets: []model.AnalyzeRequest{
			{Target: "one.example.com", Kind: model.TargetDomain},
			{Target: "two.example.com", Kind: model.TargetDomain},
		},
	})
	if err != nil {
		t.Fatalf("Submit() error = %v", err)
	}

	claimLocked := make(chan struct{})
	releaseClaim := make(chan struct{})
	cancelAtLock := make(chan struct{})
	var claimOnce, cancelOnce sync.Once
	store.transactionHooks = &transactionHooks{
		beforeLifecycleLock: func(operation string) {
			if operation == "job cancellation" {
				cancelOnce.Do(func() { close(cancelAtLock) })
			}
		},
		afterLifecycleLock: func(operation string) {
			if operation == "target claim" {
				claimOnce.Do(func() {
					close(claimLocked)
					<-releaseClaim
				})
			}
		},
	}
	claimResult := make(chan jobs.Claim, 1)
	claimDone := make(chan error, 1)
	go func() {
		claim, claimErr := store.Claim(ctx, "worker", time.Nanosecond)
		claimResult <- claim
		claimDone <- claimErr
	}()
	<-claimLocked
	cancelDone := make(chan error, 1)
	go func() { cancelDone <- store.RequestCancel(ctx, job.ID, "operator-b") }()
	<-cancelAtLock
	select {
	case err := <-cancelDone:
		t.Fatalf("RequestCancel() returned before claim released lifecycle lock: %v", err)
	default:
	}
	close(releaseClaim)
	if err := <-claimDone; err != nil {
		t.Fatalf("Claim() error = %v", err)
	}
	claim := <-claimResult
	if err := <-cancelDone; err != nil {
		t.Fatalf("RequestCancel() error = %v", err)
	}
	store.transactionHooks = nil

	assertLifecycleCounts(t, ctx, store, 1, 1)
	pinned, err := store.BundlePinned(ctx, "fixture-bundle")
	if err != nil || !pinned {
		t.Fatalf("BundlePinned() during running cancellation = %v, %v", pinned, err)
	}
	if err := store.RecoverExpired(ctx, 1); err != nil {
		t.Fatalf("RecoverExpired() error = %v", err)
	}
	if err := store.Complete(ctx, claim.TargetID, claim.AttemptToken, model.Report{}, jobs.TargetCompleted, ""); model.ErrorCodeOf(err) != model.CodeIdempotencyConflict {
		t.Fatalf("stale Complete() error = %v", err)
	}
	assertLifecycleCounts(t, ctx, store, 0, 0)
	loaded, err := store.Job(ctx, job.ID)
	if err != nil || loaded.Status != jobs.JobCancelled {
		t.Fatalf("Job() = %#v, %v", loaded, err)
	}
}

func TestPostgresSimultaneousCompletionReleasesOneReservation(t *testing.T) {
	store, ctx := openPostgresTest(t, 1)
	job, err := store.Submit(ctx, jobs.SubmitRequest{
		OperatorID: "operator-a", IdempotencyKey: "complete-race",
		Targets: []model.AnalyzeRequest{{Target: "example.com", Kind: model.TargetDomain}},
	})
	if err != nil {
		t.Fatalf("Submit() error = %v", err)
	}
	claim, err := store.Claim(ctx, "worker", time.Minute)
	if err != nil {
		t.Fatalf("Claim() error = %v", err)
	}

	start := make(chan struct{})
	completions := make(chan error, 2)
	for range 2 {
		go func() {
			<-start
			completions <- store.Complete(ctx, claim.TargetID, claim.AttemptToken, model.Report{}, jobs.TargetCompleted, "")
		}()
	}
	close(start)
	for range 2 {
		if err := <-completions; err != nil {
			t.Errorf("Complete() error = %v", err)
		}
	}
	assertLifecycleCounts(t, ctx, store, 0, 0)
	loaded, err := store.Job(ctx, job.ID)
	if err != nil || loaded.Status != jobs.JobCompleted {
		t.Fatalf("Job() = %#v, %v", loaded, err)
	}
}

func TestPostgresCompletionRecoveryRacePreservesAttemptFence(t *testing.T) {
	store, ctx := openPostgresTest(t, 1)
	job, err := store.Submit(ctx, jobs.SubmitRequest{
		OperatorID: "operator-a", IdempotencyKey: "recovery-race",
		Targets: []model.AnalyzeRequest{{Target: "example.com", Kind: model.TargetDomain}},
	})
	if err != nil {
		t.Fatalf("Submit() error = %v", err)
	}
	store.now = func() time.Time { return time.Now().Add(-time.Minute) }
	claim, err := store.Claim(ctx, "worker", time.Nanosecond)
	if err != nil {
		t.Fatalf("Claim() error = %v", err)
	}

	start := make(chan struct{})
	completionDone := make(chan error, 1)
	recoveryDone := make(chan error, 1)
	go func() {
		<-start
		completionDone <- store.Complete(ctx, claim.TargetID, claim.AttemptToken, model.Report{}, jobs.TargetCompleted, "")
	}()
	go func() {
		<-start
		recoveryDone <- store.RecoverExpired(ctx, 1)
	}()
	close(start)
	completionErr := <-completionDone
	if code := model.ErrorCodeOf(completionErr); completionErr != nil && code != model.CodeIdempotencyConflict {
		t.Fatalf("Complete() error = %v, want success or stale token", completionErr)
	}
	if err := <-recoveryDone; err != nil {
		t.Fatalf("RecoverExpired() error = %v", err)
	}
	assertLifecycleCounts(t, ctx, store, 0, 0)
	loaded, err := store.Job(ctx, job.ID)
	if err != nil || (loaded.Status != jobs.JobCompleted && loaded.Status != jobs.JobFailed) {
		t.Fatalf("Job() = %#v, %v", loaded, err)
	}
}

func TestPostgresActivationCallbackIsNotRetried(t *testing.T) {
	store, ctx := openPostgresTest(t, 1)
	calls := 0
	err := store.ActivateBundle(ctx, "fixture-bundle", []byte(`{"schema_version":1}`), true, func() error {
		calls++
		return &pgconn.PgError{Code: "40001", Message: "serialization failure"}
	})
	if err == nil {
		t.Fatal("ActivateBundle() error = nil, want publication failure")
	}
	if calls != 1 {
		t.Fatalf("publication callback calls = %d, want 1", calls)
	}
}

func TestPostgresActivationGenerationIsIdempotentAndResolvesLostAcknowledgement(t *testing.T) {
	store, ctx := openPostgresTest(t, 1)
	manifest := []byte(`{"schema_version":1,"bundle_id":"fixture-bundle"}`)
	proposed := datasets.Activation{
		OperationID: "activation-fixture", BundleID: "fixture-bundle", CandidateHash: manifestDigestForTest(manifest), Action: "activate",
	}
	var activationBackendPID int32
	connectionInterrupted := false
	store.transactionHooks = &transactionHooks{
		beforeActivationCommit: func(tx pgx.Tx) {
			if err := tx.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&activationBackendPID); err != nil {
				t.Fatalf("read activation backend PID: %v", err)
			}
		},
		afterActivationCommit: func() error {
			store.transactionHooks.afterActivationCommit = nil
			admin, err := pgx.Connect(ctx, os.Getenv("CLOUDATTRIB_POSTGRES_TEST_DSN"))
			if err != nil {
				return fmt.Errorf("open interruption connection: %w", err)
			}
			defer func() { _ = admin.Close(ctx) }()
			var terminated bool
			if err := admin.QueryRow(ctx, `SELECT pg_terminate_backend($1)`, activationBackendPID).Scan(&terminated); err != nil {
				return fmt.Errorf("terminate activation connection: %w", err)
			}
			if !terminated {
				return errors.New("activation connection was not terminated")
			}
			interruptionErr := store.pool.Ping(ctx)
			if interruptionErr == nil {
				return errors.New("terminated activation connection remained usable")
			}
			connectionInterrupted = true
			if err := store.pool.Ping(ctx); err != nil {
				return fmt.Errorf("restore PostgreSQL pool after interruption: %w", err)
			}
			return interruptionErr
		},
	}
	committed, err := store.CommitBundleActivation(ctx, proposed, manifest, true)
	if err != nil {
		t.Fatalf("CommitBundleActivation() error = %v", err)
	}
	if !connectionInterrupted {
		t.Fatal("activation commit did not exercise an actual PostgreSQL connection interruption")
	}
	if committed.Generation < 1 || committed.At.IsZero() {
		t.Fatalf("committed activation = %#v", committed)
	}
	again, err := store.CommitBundleActivation(ctx, proposed, manifest, true)
	if err != nil || again.Generation != committed.Generation {
		t.Fatalf("CommitBundleActivation(idempotent) = %#v, %v", again, err)
	}
	conflict := proposed
	conflict.Action = "rollback"
	if _, err := store.CommitBundleActivation(ctx, conflict, manifest, true); model.ErrorCodeOf(err) != model.CodeIdempotencyConflict {
		t.Fatalf("CommitBundleActivation(conflict) error = %v", err)
	}
}

func TestPostgresAdmissionClaimCompletionAndPinLifecycle(t *testing.T) {
	store, ctx := openPostgresTest(t, 4)
	var err error
	publishStarted := make(chan struct{})
	releasePublish := make(chan struct{})
	activationDone := make(chan error, 1)
	go func() {
		activationDone <- store.ActivateBundle(ctx, "coordinated-bundle", []byte(`{"schema_version":1,"bundle_id":"coordinated-bundle"}`), true, func() error {
			close(publishStarted)
			<-releasePublish
			return nil
		})
	}()
	<-publishStarted
	desired, err := store.DesiredBundle(ctx)
	if err != nil || desired == nil || desired.BundleID != "coordinated-bundle" {
		t.Fatalf("DesiredBundle() during publication = %#v, %v", desired, err)
	}
	pruneCtx, cancelPrune := context.WithTimeout(ctx, 100*time.Millisecond)
	protectedDuringPublication := false
	err = store.WithBundlePruneLock(pruneCtx, "coordinated-bundle", func(protected bool) error {
		protectedDuringPublication = protected
		return nil
	})
	cancelPrune()
	if err != nil || !protectedDuringPublication {
		t.Fatalf("WithBundlePruneLock() during publication protected=%v, error=%v", protectedDuringPublication, err)
	}
	close(releasePublish)
	if err := <-activationDone; err != nil {
		t.Fatalf("ActivateBundle() error = %v", err)
	}
	protectedByActivation := false
	if err := store.WithBundlePruneLock(ctx, "coordinated-bundle", func(protected bool) error {
		protectedByActivation = protected
		return nil
	}); err != nil || !protectedByActivation {
		t.Fatalf("WithBundlePruneLock() after activation protected=%v, error=%v", protectedByActivation, err)
	}
	if err := store.RegisterBundle(ctx, "fixture-bundle", []byte(`{"schema_version":1}`), true); err != nil {
		t.Fatalf("RegisterBundle() error = %v", err)
	}
	ctPassed := model.CTVerificationCheck{Status: model.CTCheckPassed, Procedure: "rfc6962-sha256", ProcedureVersion: "1"}
	ctRecord := ctlog.Record{
		Name: "api.example.com", CertificateHash: "fixture-certificate", LoggedAt: time.Unix(10, 0).UTC(), SourceID: "fixture-log",
		Provenance:   ctlog.ProvenanceVerifiedLog,
		Verification: model.CTVerification{CheckpointSignature: ctPassed, Continuity: ctPassed, EntryInclusion: ctPassed},
	}
	checkpoint := ctlog.Checkpoint{LogID: "sha256:fixture-log", NextIndex: 1, VerifiedTreeSize: 1, VerifiedRootHash: make([]byte, 32), KeyIdentity: "sha256:fixture-key"}
	if err := store.CommitCollection(ctx, []ctlog.Record{ctRecord}, checkpoint); err != nil {
		t.Fatalf("CommitCollection() error = %v", err)
	}
	discovered, err := store.Discover(ctx, "example.com", 20)
	if err != nil || len(discovered.Candidates) != 1 || discovered.Candidates[0].Hostname != "api.example.com" {
		t.Fatalf("Discover() = %#v, %v", discovered, err)
	}
	loadedCheckpoint, err := store.LoadCheckpoint(ctx, checkpoint.LogID)
	if err != nil || loadedCheckpoint.NextIndex != 1 || loadedCheckpoint.VerifiedTreeSize != 1 {
		t.Fatalf("LoadCheckpoint() = %#v, %v", loadedCheckpoint, err)
	}
	if err := store.RecordBundleActivation(ctx, "fixture-bundle"); err != nil {
		t.Fatalf("RecordBundleActivation() error = %v", err)
	}
	protected, err := store.ProtectedBundles(ctx, 3)
	if err != nil || len(protected) < 1 || protected[0] != "fixture-bundle" {
		t.Fatalf("ProtectedBundles() = %v, %v", protected, err)
	}
	if err := store.RegisterBundle(ctx, "fixture-bundle", []byte(`{"schema_version":2}`), true); model.ErrorCodeOf(err) != model.CodeIdempotencyConflict {
		t.Fatalf("mutable RegisterBundle() error = %v", err)
	}
	if err := store.RegisterBundle(ctx, "old-bundle", []byte(`{"schema_version":1,"old":true}`), true); err != nil {
		t.Fatalf("RegisterBundle(old) error = %v", err)
	}
	removed := false
	if err := store.WithBundlePruneLock(ctx, "old-bundle", func(protected bool) error { removed = !protected; return nil }); err != nil || !removed {
		t.Fatalf("WithBundlePruneLock() removed=%v, error=%v", removed, err)
	}
	if _, err := store.Submit(ctx, jobs.SubmitRequest{OperatorID: "operator-a", IdempotencyKey: "pruned-key", BundleID: "old-bundle", Targets: []model.AnalyzeRequest{{Target: "example.com", Kind: model.TargetDomain}}}); model.ErrorCodeOf(err) != model.CodeBundleUnavailable {
		t.Fatalf("Submit(pruned bundle) error = %v", err)
	}
	job, err := store.Submit(ctx, jobs.SubmitRequest{OperatorID: "operator-a", IdempotencyKey: "fixture-key", BundleID: "fixture-bundle", Targets: []model.AnalyzeRequest{{Target: "example.com", Kind: model.TargetDomain}}})
	if err != nil {
		t.Fatalf("Submit() error = %v (cause: %v)", err, errors.Unwrap(err))
	}
	metrics, err := store.OperationalMetrics(ctx)
	if err != nil || metrics.ReservedTargets != 1 || metrics.QueuedTargets != 1 || metrics.BundlePins != 1 || metrics.CTCheckpoints != 1 || metrics.ActiveBundleID != "fixture-bundle" {
		t.Fatalf("OperationalMetrics() = %#v, %v", metrics, err)
	}
	pinned, err := store.BundlePinned(ctx, "fixture-bundle")
	if err != nil || !pinned {
		t.Fatalf("BundlePinned() = %v, %v", pinned, err)
	}
	claim, err := store.Claim(ctx, "worker", time.Minute)
	if err != nil {
		t.Fatalf("Claim() error = %v", err)
	}
	report := model.Report{
		SchemaVersion: model.SchemaVersion, ID: "fixture-report", Target: model.Target{Original: "example.com", Canonical: "example.com", Kind: model.TargetDomain},
		Mode: model.ModeFull, StartedAt: time.Unix(1, 0).UTC(), EndedAt: time.Unix(2, 0).UTC(), ClassifiedAt: time.Unix(2, 0).UTC(), BundleID: "fixture-bundle", BuildID: "fixture", Status: model.StatusComplete,
		Observations: []model.Observation{{ID: "observation-1", Subject: "example.com", Type: "dns", ObservedAt: time.Unix(1, 0).UTC(), Status: "answered", Payload: model.JSONValue(`{}`)}},
		Evidence:     []model.Evidence{{ID: "evidence-1", ObservationIDs: []string{"observation-1"}, ClassifiedAt: time.Unix(2, 0).UTC(), Subject: "example.com", ProviderID: "aws", ProductID: "aws.cloudfront", Relation: model.RelationWebDelivery, Strength: model.StrengthStrong}},
		Findings:     []model.Finding{{ID: "finding-1", Subject: "example.com", ProviderID: "aws", ProductID: "aws.cloudfront", Relation: model.RelationWebDelivery, Strength: model.StrengthStrong, EvidenceIDs: []string{"evidence-1"}}},
		Coverage:     []model.Coverage{}, Warnings: []string{},
	}
	if err := store.Complete(ctx, claim.TargetID, claim.AttemptToken, report, jobs.TargetCompleted, ""); err != nil {
		t.Fatalf("Complete() error = %v", err)
	}
	if err := store.Complete(ctx, claim.TargetID, claim.AttemptToken, report, jobs.TargetCompleted, ""); err != nil {
		t.Fatalf("repeated Complete() error = %v", err)
	}
	legacyLoaded, err := store.LoadReport(ctx, report.ID)
	if err != nil {
		t.Fatalf("LoadReport(legacy) error = %v", err)
	}
	if legacyLoaded.ID != report.ID || legacyLoaded.ContentIDVersion != "" {
		t.Fatalf("LoadReport(legacy) identity = %#v", legacyLoaded)
	}
	identityReport := report.Clone()
	identityReport.ID = ""
	identityReport.ContentIDVersion = model.ReportContentIDVersion
	identityReport.Observations[0].Payload = model.JSONValue(`{"nested":{"second":2.00,"first":{"value":1e3}}}`)
	identityReport.ID, err = identityReport.ContentID()
	if err != nil {
		t.Fatalf("ContentID() before JSONB round trip error = %v", err)
	}
	if err := store.SaveReport(ctx, identityReport); err != nil {
		t.Fatalf("SaveReport(identity) error = %v", err)
	}
	identityLoaded, err := store.LoadReport(ctx, identityReport.ID)
	if err != nil {
		t.Fatalf("LoadReport(identity) error = %v", err)
	}
	roundTripID, err := identityLoaded.ContentID()
	if err != nil {
		t.Fatalf("ContentID() after JSONB round trip error = %v", err)
	}
	if roundTripID != identityReport.ID {
		t.Fatalf("ContentID() after JSONB round trip = %q, want %q", roundTripID, identityReport.ID)
	}
	loaded, err := store.Job(ctx, job.ID)
	if err != nil || loaded.Status != jobs.JobCompleted || !loaded.Targets[0].ReportAvailable || loaded.Targets[0].ReportID != report.ID || loaded.Targets[0].Report.ID != "" {
		t.Fatalf("Job() = %#v, %v", loaded, err)
	}
	loadedReport, err := store.LoadReport(ctx, loaded.Targets[0].ReportID)
	if err != nil || loadedReport.ID != report.ID {
		t.Fatalf("LoadReport() = %#v, %v", loadedReport, err)
	}
	page, err := store.Findings(ctx, app.FindingQuery{Domain: "example.com", ProviderID: "aws", Limit: 1})
	if err != nil || len(page.Items) != 1 || page.Items[0].Finding.ID != "finding-1" {
		t.Fatalf("Findings() = %#v, %v", page, err)
	}
	pinned, err = store.BundlePinned(ctx, "fixture-bundle")
	if err != nil || pinned {
		t.Fatalf("BundlePinned() after completion = %v, %v", pinned, err)
	}
	metrics, err = store.OperationalMetrics(ctx)
	if err != nil || metrics.ReservedTargets != 0 || metrics.QueuedTargets != 0 || metrics.RunningTargets != 0 || metrics.BundlePins != 0 {
		t.Fatalf("OperationalMetrics() after completion = %#v, %v", metrics, err)
	}
	replayJob, err := store.Submit(ctx, jobs.SubmitRequest{
		OperatorID: "operator-a", IdempotencyKey: "replay-key", BundleID: "fixture-bundle",
		Reclassifications: []model.ReclassifyRequest{{ReportID: report.ID, BundleID: "fixture-bundle"}},
	})
	if err != nil {
		t.Fatalf("Submit(reclassification) error = %v", err)
	}
	replayClaim, err := store.Claim(ctx, "replay-worker", time.Minute)
	if err != nil || replayClaim.Reclassify == nil || replayClaim.Reclassify.ReportID != report.ID {
		t.Fatalf("Claim(reclassification) = %#v, %v", replayClaim, err)
	}
	reclassified := report.Clone()
	reclassified.ID = "fixture-reclassified"
	reclassified.OriginalReportID = report.ID
	if err := store.Complete(ctx, replayClaim.TargetID, replayClaim.AttemptToken, reclassified, jobs.TargetCompleted, ""); err != nil {
		t.Fatalf("Complete(reclassification) error = %v", err)
	}
	replayLoaded, err := store.Job(ctx, replayJob.ID)
	if err != nil || replayLoaded.Status != jobs.JobCompleted || replayLoaded.Targets[0].ReportID != reclassified.ID || replayLoaded.Targets[0].Report.ID != "" {
		t.Fatalf("Job(reclassification) = %#v, %v", replayLoaded, err)
	}
	replayReport, err := store.LoadReport(ctx, replayLoaded.Targets[0].ReportID)
	if err != nil || replayReport.OriginalReportID != report.ID {
		t.Fatalf("LoadReport(reclassification) = %#v, %v", replayReport, err)
	}

	cancelJob, err := store.Submit(ctx, jobs.SubmitRequest{OperatorID: "operator-a", IdempotencyKey: "cancel-key", BundleID: "fixture-bundle", Targets: []model.AnalyzeRequest{{Target: "one.example.com", Kind: model.TargetDomain}, {Target: "two.example.com", Kind: model.TargetDomain}}})
	if err != nil {
		t.Fatalf("Submit(cancel) error = %v", err)
	}
	store.now = func() time.Time { return time.Now().Add(-2 * time.Minute) }
	cancelClaim, err := store.Claim(ctx, "worker", time.Second)
	if err != nil {
		t.Fatalf("Claim(cancel) error = %v", err)
	}
	if err := store.RequestCancel(ctx, cancelJob.ID, "operator-b"); err != nil {
		t.Fatalf("RequestCancel() error = %v", err)
	}
	pinned, err = store.BundlePinned(ctx, "fixture-bundle")
	if err != nil || !pinned {
		t.Fatalf("BundlePinned() during running cancellation = %v, %v", pinned, err)
	}
	if err := store.RecoverExpired(ctx, 3); err != nil {
		t.Fatalf("RecoverExpired() error = %v", err)
	}
	if err := store.Complete(ctx, cancelClaim.TargetID, cancelClaim.AttemptToken, model.Report{}, jobs.TargetCompleted, ""); model.ErrorCodeOf(err) != model.CodeIdempotencyConflict {
		t.Fatalf("stale Complete() error = %v", err)
	}
	loaded, err = store.Job(ctx, cancelJob.ID)
	if err != nil || loaded.Status != jobs.JobCancelled {
		t.Fatalf("cancelled Job() = %#v, %v", loaded, err)
	}
	pinned, err = store.BundlePinned(ctx, "fixture-bundle")
	if err != nil || pinned {
		t.Fatalf("BundlePinned() after cancelled terminals = %v, %v", pinned, err)
	}
	invalid, err := store.Submit(ctx, jobs.SubmitRequest{OperatorID: "operator-a", IdempotencyKey: "invalid-key", BundleID: "fixture-bundle", Targets: []model.AnalyzeRequest{{Target: "not a domain", Kind: model.TargetDomain}}})
	if err != nil || invalid.Status != jobs.JobFailed || invalid.Targets[0].Status != jobs.TargetFailed {
		t.Fatalf("Submit(invalid row) = %#v, %v", invalid, err)
	}
	var reservations int
	if err := store.pool.QueryRow(ctx, `SELECT reserved_targets FROM queue_capacity WHERE singleton=true`).Scan(&reservations); err != nil || reservations != 0 {
		t.Fatalf("reserved targets after invalid row = %d, %v", reservations, err)
	}
}

func openPostgresTest(t *testing.T, maximumTargets int) (*Store, context.Context) {
	t.Helper()

	dsn := os.Getenv("CLOUDATTRIB_POSTGRES_TEST_DSN")
	if dsn == "" {
		t.Skip("CLOUDATTRIB_POSTGRES_TEST_DSN is not set")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	t.Cleanup(cancel)
	store, err := Open(ctx, dsn, 10_000)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	t.Cleanup(store.Close)
	if _, err := store.pool.Exec(ctx, `TRUNCATE ct_records,ct_checkpoints,finding_evidence,findings,evidence,observations,job_targets,reports,bundle_pins,jobs,dataset_bundles RESTART IDENTITY CASCADE`); err != nil {
		t.Fatalf("reset database: %v", err)
	}
	if _, err := store.pool.Exec(ctx, `UPDATE queue_capacity SET reserved_targets=0,maximum_targets=$1 WHERE singleton=true`, maximumTargets); err != nil {
		t.Fatalf("reset queue capacity: %v", err)
	}
	return store, ctx
}

func assertLifecycleCounts(t *testing.T, ctx context.Context, store *Store, reservations, pins int) {
	t.Helper()

	var gotReservations, gotPins int
	if err := store.pool.QueryRow(ctx, `SELECT
		(SELECT reserved_targets FROM queue_capacity WHERE singleton=true),
		(SELECT count(*) FROM bundle_pins)`).Scan(&gotReservations, &gotPins); err != nil {
		t.Fatalf("inspect lifecycle counts: %v", err)
	}
	if gotReservations != reservations || gotPins != pins {
		t.Fatalf("lifecycle counts reservations=%d pins=%d, want %d and %d", gotReservations, gotPins, reservations, pins)
	}
}

func manifestDigestForTest(manifest []byte) string {
	digest := sha256.Sum256(manifest)
	return "sha256:" + hex.EncodeToString(digest[:])
}
