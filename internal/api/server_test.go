package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"cloudattrib/internal/app"
	"cloudattrib/internal/jobs"
	"cloudattrib/internal/model"
)

func TestAnalyzeReturnsReportAndOperator(t *testing.T) {
	t.Parallel()

	analyzer := &fixtureAnalyzer{report: fixtureReport(model.StatusComplete)}
	handler := mustHandler(t, Config{Analyzer: analyzer})
	recorder := serve(handler, http.MethodPost, "/v1/analyze", `{"target":"example.com","kind":"domain"}`, "127.0.0.1:1000", nil)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d: %s", recorder.Code, http.StatusOK, recorder.Body.String())
	}
	var report model.Report
	if err := json.Unmarshal(recorder.Body.Bytes(), &report); err != nil {
		t.Fatalf("decode report: %v", err)
	}
	if report.ID != "report-1" {
		t.Fatalf("report ID = %q, want report-1", report.ID)
	}
	if analyzer.operatorID != "local-operator" {
		t.Fatalf("operator ID = %q, want local-operator", analyzer.operatorID)
	}
}

func TestAnalyzeErrorsUseStableEnvelope(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		body       string
		analyzeErr error
		wantStatus int
		wantCode   model.ErrorCode
		wantText   string
	}{
		{
			name:       "malformed JSON",
			body:       `{"target":`,
			wantStatus: http.StatusBadRequest,
			wantCode:   model.CodeInvalidSyntax,
			wantText:   "invalid request JSON",
		},
		{
			name:       "unknown property",
			body:       `{"target":"example.com","kind":"domain","unknown":true}`,
			wantStatus: http.StatusBadRequest,
			wantCode:   model.CodeInvalidSyntax,
			wantText:   "invalid request JSON",
		},
		{
			name:       "unavailable execution",
			body:       `{"target":"example.com","kind":"domain"}`,
			analyzeErr: model.NewError(model.CodeCapabilityUnavailable, "DNS collector is unavailable", errors.New("internal detail")),
			wantStatus: http.StatusServiceUnavailable,
			wantCode:   model.CodeCapabilityUnavailable,
			wantText:   "DNS collector is unavailable",
		},
		{
			name:       "unexpected failure is redacted",
			body:       `{"target":"example.com","kind":"domain"}`,
			analyzeErr: errors.New("database password leaked"),
			wantStatus: http.StatusInternalServerError,
			wantCode:   "internal_error",
			wantText:   "internal server error",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			handler := mustHandler(t, Config{Analyzer: &fixtureAnalyzer{analyzeErr: test.analyzeErr}})
			recorder := serve(handler, http.MethodPost, "/v1/analyze", test.body, "127.0.0.1:1000", nil)
			if recorder.Code != test.wantStatus {
				t.Fatalf("status = %d, want %d: %s", recorder.Code, test.wantStatus, recorder.Body.String())
			}
			got := decodeError(t, recorder)
			if got.Code != test.wantCode || got.Message != test.wantText {
				t.Fatalf("error = %#v, want code %q and message %q", got, test.wantCode, test.wantText)
			}
			if strings.Contains(recorder.Body.String(), "internal detail") || strings.Contains(recorder.Body.String(), "password") {
				t.Fatalf("response exposed an internal error: %s", recorder.Body.String())
			}
		})
	}
}

func TestRequestBodyIsLimitedToOneMiB(t *testing.T) {
	t.Parallel()

	handler := mustHandler(t, Config{Analyzer: &fixtureAnalyzer{}})
	body := `{"target":"` + strings.Repeat("a", (1<<20)) + `","kind":"domain"}`
	recorder := serve(handler, http.MethodPost, "/v1/analyze", body, "127.0.0.1:1000", nil)
	if recorder.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want %d: %s", recorder.Code, http.StatusRequestEntityTooLarge, recorder.Body.String())
	}
	if got := decodeError(t, recorder); got.Code != model.CodeInputTooLarge {
		t.Fatalf("error code = %q, want %q", got.Code, model.CodeInputTooLarge)
	}
}

func TestAnalyzePersistsTerminalReport(t *testing.T) {
	t.Parallel()

	results := newFixtureResultStore()
	handler := mustHandler(t, Config{Analyzer: &fixtureAnalyzer{report: fixtureReport(model.StatusComplete)}, Results: results})
	recorder := serve(handler, http.MethodPost, "/v1/analyze", `{"target":"example.com","kind":"domain"}`, "127.0.0.1:1000", nil)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d: %s", recorder.Code, http.StatusOK, recorder.Body.String())
	}
	if _, err := results.LoadReport(t.Context(), "report-1"); err != nil {
		t.Fatalf("persisted report: %v", err)
	}
}

func TestAnalyzeRequiresWritableResultStore(t *testing.T) {
	t.Parallel()

	handler, err := NewHandler(Config{Analyzer: &fixtureAnalyzer{report: fixtureReport(model.StatusComplete)}})
	if err != nil {
		t.Fatalf("NewHandler() error = %v", err)
	}
	recorder := serve(handler, http.MethodPost, "/v1/analyze", `{"target":"example.com","kind":"domain"}`, "127.0.0.1:1000", nil)
	if recorder.Code != http.StatusServiceUnavailable || decodeError(t, recorder).Code != model.CodePersistenceUnavailable {
		t.Fatalf("response = %d %s", recorder.Code, recorder.Body.String())
	}
}

func TestJobsUseAuthenticatedIdempotencyAndSharedVisibility(t *testing.T) {
	t.Parallel()

	store := jobs.NewMemoryStore(10)
	auth := Authentication{Mode: AuthBearer, Credentials: map[string]string{"credential-a": "operator-a", "credential-b": "operator-b"}}
	handler := mustHandler(t, Config{Jobs: store, Authentication: auth})
	created := serve(handler, http.MethodPost, "/v1/jobs", `{"idempotency_key":"request-1","bundle_id":"bundle-1","targets":[{"target":"example.com","kind":"domain"}]}`, "192.0.2.10:1000", map[string]string{"Authorization": "Bearer credential-a"})
	if created.Code != http.StatusAccepted {
		t.Fatalf("create status = %d, want %d: %s", created.Code, http.StatusAccepted, created.Body.String())
	}
	var response jobResponse
	if err := json.Unmarshal(created.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode job: %v", err)
	}
	if response.Counts[jobs.TargetQueued] != 1 || created.Header().Get("Location") != "/v1/jobs/"+response.ID {
		t.Fatalf("job response = %#v, location = %q", response, created.Header().Get("Location"))
	}

	otherHeaders := map[string]string{"Authorization": "Bearer credential-b"}
	loaded := serve(handler, http.MethodGet, "/v1/jobs/"+response.ID, "", "192.0.2.10:1000", otherHeaders)
	if loaded.Code != http.StatusOK {
		t.Fatalf("shared read status = %d, want %d: %s", loaded.Code, http.StatusOK, loaded.Body.String())
	}
	cancelled := serve(handler, http.MethodPost, "/v1/jobs/"+response.ID+"/cancel", "", "192.0.2.10:1000", otherHeaders)
	if cancelled.Code != http.StatusAccepted {
		t.Fatalf("cancel status = %d, want %d: %s", cancelled.Code, http.StatusAccepted, cancelled.Body.String())
	}
	job, err := store.Job(t.Context(), response.ID)
	if err != nil {
		t.Fatalf("load cancelled job: %v", err)
	}
	if !job.CancelRequested || job.CancelRequestedBy != "operator-b" {
		t.Fatalf("cancel attribution = %#v", job)
	}
}

func TestJobsPersistInvalidRowsAsTerminalFailures(t *testing.T) {
	t.Parallel()

	store := jobs.NewMemoryStore(1)
	handler := mustHandler(t, Config{Jobs: store})
	recorder := serve(handler, http.MethodPost, "/v1/jobs", `{"idempotency_key":"mixed","targets":[{"target":"not a domain","kind":"domain"},{"target":"example.com","kind":"domain"}]}`, "127.0.0.1:1000", nil)
	var response jobResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if recorder.Code != http.StatusAccepted || response.Counts[jobs.TargetFailed] != 1 || response.Counts[jobs.TargetQueued] != 1 || store.Reservations() != 1 {
		t.Fatalf("response = %d %#v, reservations=%d", recorder.Code, response, store.Reservations())
	}
}

func TestJobsRejectOversizedBatchBeforeStoreAdmission(t *testing.T) {
	t.Parallel()

	targets := make([]model.AnalyzeRequest, maximumBatchTargets+1)
	for index := range targets {
		targets[index] = model.AnalyzeRequest{Target: "example.com", Kind: model.TargetDomain}
	}
	body, err := json.Marshal(submitJobInput{IdempotencyKey: "too-many", Targets: targets})
	if err != nil {
		t.Fatalf("encode request: %v", err)
	}
	handler := mustHandler(t, Config{Jobs: jobs.NewMemoryStore(2000), MaximumRequestBytes: maximumRequestBytes})
	recorder := serve(handler, http.MethodPost, "/v1/jobs", string(body), "127.0.0.1:1000", nil)
	if recorder.Code != http.StatusUnprocessableEntity || decodeError(t, recorder).Code != model.CodeInvalidOptions {
		t.Fatalf("response = %d %s", recorder.Code, recorder.Body.String())
	}
}

func TestCancellationRejectsOversizedChunkedBody(t *testing.T) {
	t.Parallel()

	store := jobs.NewMemoryStore(2)
	job, err := store.Submit(t.Context(), jobs.SubmitRequest{OperatorID: "operator", IdempotencyKey: "cancel-body", Targets: []model.AnalyzeRequest{{Target: "example.com", Kind: model.TargetDomain}}})
	if err != nil {
		t.Fatalf("Submit() error = %v", err)
	}
	handler := mustHandler(t, Config{Jobs: store})
	request := httptest.NewRequest(http.MethodPost, "/v1/jobs/"+job.ID+"/cancel", strings.NewReader(strings.Repeat("x", int(maximumRequestBytes)+1)))
	request.ContentLength = -1
	request.RemoteAddr = "127.0.0.1:1000"
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusRequestEntityTooLarge || decodeError(t, recorder).Code != model.CodeInputTooLarge {
		t.Fatalf("response = %d %s", recorder.Code, recorder.Body.String())
	}
}

func TestStoredResultAndObservationPagination(t *testing.T) {
	t.Parallel()

	report := fixtureReport(model.StatusComplete)
	report.Observations = []model.Observation{
		{ID: "later", ObservedAt: report.StartedAt.Add(time.Second)},
		{ID: "first-b", ObservedAt: report.StartedAt},
		{ID: "first-a", ObservedAt: report.StartedAt},
	}
	results := newFixtureResultStore()
	if err := results.SaveReport(t.Context(), report); err != nil {
		t.Fatalf("save fixture report: %v", err)
	}
	handler := mustHandler(t, Config{Results: results})
	loaded := serve(handler, http.MethodGet, "/v1/results/report-1", "", "127.0.0.1:1000", nil)
	if loaded.Code != http.StatusOK {
		t.Fatalf("result status = %d, want %d: %s", loaded.Code, http.StatusOK, loaded.Body.String())
	}
	first := serve(handler, http.MethodGet, "/v1/results/report-1/observations?limit=2", "", "127.0.0.1:1000", nil)
	var page struct {
		Items      []model.Observation `json:"items"`
		NextCursor string              `json:"next_cursor"`
	}
	if err := json.Unmarshal(first.Body.Bytes(), &page); err != nil {
		t.Fatalf("decode first page: %v", err)
	}
	if first.Code != http.StatusOK || len(page.Items) != 2 || page.Items[0].ID != "first-a" || page.Items[1].ID != "first-b" || page.NextCursor == "" {
		t.Fatalf("first page = %d %#v", first.Code, page)
	}
	second := serve(handler, http.MethodGet, "/v1/results/report-1/observations?limit=2&cursor="+page.NextCursor, "", "127.0.0.1:1000", nil)
	page = struct {
		Items      []model.Observation `json:"items"`
		NextCursor string              `json:"next_cursor"`
	}{}
	if err := json.Unmarshal(second.Body.Bytes(), &page); err != nil {
		t.Fatalf("decode second page: %v", err)
	}
	if second.Code != http.StatusOK || len(page.Items) != 1 || page.Items[0].ID != "later" || page.NextCursor != "" {
		t.Fatalf("second page = %d %#v", second.Code, page)
	}
}

func TestReclassifyCreatesPinnedReplayJob(t *testing.T) {
	t.Parallel()

	store := jobs.NewMemoryStore(2)
	results := newFixtureResultStore()
	original := fixtureReport(model.StatusComplete)
	original.Observations = []model.Observation{{ID: "observation-1"}}
	if err := results.SaveReport(t.Context(), original); err != nil {
		t.Fatalf("save original report: %v", err)
	}
	handler := mustHandler(t, Config{Jobs: store, Results: results})
	recorder := serve(handler, http.MethodPost, "/v1/results/report-1/reclassify", `{"bundle_id":"bundle-2","idempotency_key":"replay-1"}`, "127.0.0.1:1000", nil)
	var response jobResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode job: %v", err)
	}
	if recorder.Code != http.StatusAccepted || recorder.Header().Get("Location") != "/v1/jobs/"+response.ID {
		t.Fatalf("response = %d %s location=%q", recorder.Code, recorder.Body.String(), recorder.Header().Get("Location"))
	}
	job, err := store.Job(t.Context(), response.ID)
	if err != nil || job.BundleID != "bundle-2" || job.Targets[0].Reclassify == nil || job.Targets[0].Reclassify.ReportID != "report-1" {
		t.Fatalf("reclassification job = %#v, %v", job, err)
	}
}

func TestReclassifyValidatesRetainedInputAndBundle(t *testing.T) {
	t.Parallel()

	store := jobs.NewMemoryStore(2)
	results := newFixtureResultStore()
	handler := mustHandler(t, Config{Jobs: store, Results: results})
	missingBundle := serve(handler, http.MethodPost, "/v1/results/report-1/reclassify", `{"idempotency_key":"replay-1"}`, "127.0.0.1:1000", nil)
	if missingBundle.Code != http.StatusUnprocessableEntity || decodeError(t, missingBundle).Code != model.CodeInvalidOptions {
		t.Fatalf("missing bundle response = %d %s", missingBundle.Code, missingBundle.Body.String())
	}
	missingReport := serve(handler, http.MethodPost, "/v1/results/report-1/reclassify", `{"bundle_id":"bundle-1","idempotency_key":"replay-2"}`, "127.0.0.1:1000", nil)
	if missingReport.Code != http.StatusUnprocessableEntity || decodeError(t, missingReport).Code != model.CodeInvalidTarget {
		t.Fatalf("missing report response = %d %s", missingReport.Code, missingReport.Body.String())
	}
}

func TestFindingAndCatalogSearchAreBounded(t *testing.T) {
	t.Parallel()

	findings := &fixtureFindingStore{page: app.FindingPage{Items: []app.StoredFinding{{
		ReportID: "report-1", ClassifiedAt: time.Date(2026, 9, 20, 9, 0, 0, 0, time.UTC),
		Finding: model.Finding{ID: "finding-1", ProviderID: "aws", ProductID: "aws.cloudfront"},
	}}}}
	handler := mustHandler(t, Config{Findings: findings})
	recorder := serve(handler, http.MethodGet, "/v1/findings?domain=example.com&provider=aws&limit=25&observed_from=2026-09-01T00:00:00Z", "", "127.0.0.1:1000", nil)
	if recorder.Code != http.StatusOK || findings.query.Domain != "example.com" || findings.query.ProviderID != "aws" || findings.query.Limit != 25 || findings.query.ObservedFrom == nil {
		t.Fatalf("finding response = %d %s, query = %#v", recorder.Code, recorder.Body.String(), findings.query)
	}
	providers := serve(handler, http.MethodGet, "/v1/providers?q=amazon&limit=1", "", "127.0.0.1:1000", nil)
	if providers.Code != http.StatusOK || !strings.Contains(providers.Body.String(), `"id":"aws"`) {
		t.Fatalf("provider response = %d %s", providers.Code, providers.Body.String())
	}
	products := serve(handler, http.MethodGet, "/v1/products?q=cdn", "", "127.0.0.1:1000", nil)
	if products.Code != http.StatusOK || !strings.Contains(products.Body.String(), `"id":"aws.cloudfront"`) {
		t.Fatalf("product response = %d %s", products.Code, products.Body.String())
	}
	metrics := serve(handler, http.MethodGet, "/metrics", "", "127.0.0.1:1000", nil)
	if metrics.Code != http.StatusOK || !strings.Contains(metrics.Body.String(), "cloudattrib_http_requests_total 4") {
		t.Fatalf("metrics response = %d %s", metrics.Code, metrics.Body.String())
	}
}

func TestLookupIPDoesNotRequireDurableStore(t *testing.T) {
	t.Parallel()

	analyzer := &fixtureAnalyzer{lookup: model.IPLookupResult{
		Address:  netip.MustParseAddr("198.51.100.7"),
		Status:   model.StatusPartial,
		Coverage: []model.Coverage{{Capability: "prefix", Status: model.CoverageUnavailable}},
	}}
	handler := mustHandler(t, Config{Analyzer: analyzer})
	recorder := serve(handler, http.MethodPost, "/v1/lookup/ip", `{"address":"198.51.100.7","match":"all"}`, "127.0.0.1:1000", nil)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d: %s", recorder.Code, http.StatusOK, recorder.Body.String())
	}
	var result model.IPLookupResult
	if err := json.Unmarshal(recorder.Body.Bytes(), &result); err != nil {
		t.Fatalf("decode lookup result: %v", err)
	}
	if result.Status != model.StatusPartial || analyzer.operatorID != "local-operator" {
		t.Fatalf("result = %#v, operator = %q", result, analyzer.operatorID)
	}
}

func TestLookupIPRejectsInvalidAddressAsInvalidTarget(t *testing.T) {
	t.Parallel()

	handler := mustHandler(t, Config{Analyzer: &fixtureAnalyzer{}})
	recorder := serve(handler, http.MethodPost, "/v1/lookup/ip", `{"address":"not-an-ip"}`, "127.0.0.1:1000", nil)
	if recorder.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want %d: %s", recorder.Code, http.StatusUnprocessableEntity, recorder.Body.String())
	}
	if got := decodeError(t, recorder); got.Code != model.CodeInvalidTarget {
		t.Fatalf("error code = %q, want %q", got.Code, model.CodeInvalidTarget)
	}
}

func TestHealthUsesOperationReadiness(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		snapshot   ReadinessSnapshot
		wantStatus int
	}{
		{
			name: "degraded is live",
			snapshot: ReadinessSnapshot{State: ReadinessDegraded, Operations: []OperationReadiness{{
				Name: "lookup_ip", State: ReadinessReady,
			}}},
			wantStatus: http.StatusOK,
		},
		{
			name:       "no operation is unavailable",
			snapshot:   ReadinessSnapshot{State: ReadinessUnavailable},
			wantStatus: http.StatusServiceUnavailable,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			handler := mustHandler(t, Config{Readiness: fixtureReadiness{snapshot: test.snapshot}})
			live := serve(handler, http.MethodGet, "/livez", "", "127.0.0.1:1000", nil)
			if live.Code != http.StatusOK {
				t.Fatalf("live status = %d, want %d", live.Code, http.StatusOK)
			}
			ready := serve(handler, http.MethodGet, "/readyz", "", "127.0.0.1:1000", nil)
			if ready.Code != test.wantStatus {
				t.Fatalf("ready status = %d, want %d: %s", ready.Code, test.wantStatus, ready.Body.String())
			}
			var snapshot ReadinessSnapshot
			if err := json.Unmarshal(ready.Body.Bytes(), &snapshot); err != nil {
				t.Fatalf("decode readiness: %v", err)
			}
			if snapshot.State != test.snapshot.State {
				t.Fatalf("readiness state = %q, want %q", snapshot.State, test.snapshot.State)
			}
		})
	}
}

func TestDefaultReadinessSeparatesAnalyzePersistenceFromLookup(t *testing.T) {
	t.Parallel()

	handler, err := NewHandler(Config{Analyzer: &fixtureAnalyzer{}})
	if err != nil {
		t.Fatalf("NewHandler() error = %v", err)
	}
	recorder := serve(handler, http.MethodGet, "/readyz", "", "127.0.0.1:1000", nil)
	var snapshot ReadinessSnapshot
	if err := json.Unmarshal(recorder.Body.Bytes(), &snapshot); err != nil {
		t.Fatalf("decode readiness: %v", err)
	}
	states := make(map[string]ReadinessState)
	for _, operation := range snapshot.Operations {
		states[operation.Name] = operation.State
	}
	if recorder.Code != http.StatusOK || snapshot.State != ReadinessDegraded || states["analyze"] != ReadinessUnavailable || states["lookup_ip"] != ReadinessReady {
		t.Fatalf("readiness = %d %#v", recorder.Code, snapshot)
	}
}

func TestAuthenticationRejectsSpoofedIdentityAndUsesConfiguredOperators(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		auth       Authentication
		remoteAddr string
		headers    map[string]string
		wantStatus int
		wantID     string
	}{
		{
			name:       "loopback local operator",
			auth:       Authentication{Mode: AuthLoopback},
			remoteAddr: "127.0.0.1:1000",
			wantStatus: http.StatusOK,
			wantID:     "local-operator",
		},
		{
			name: "loopback rejects identity header",
			auth: Authentication{Mode: AuthLoopback}, remoteAddr: "127.0.0.1:1000",
			headers: map[string]string{"X-Cloudattrib-Operator": "attacker"}, wantStatus: http.StatusUnauthorized,
		},
		{
			name: "loopback rejects remote caller",
			auth: Authentication{Mode: AuthLoopback}, remoteAddr: "192.0.2.10:1000",
			wantStatus: http.StatusUnauthorized,
		},
		{
			name: "bearer maps stable identity",
			auth: Authentication{Mode: AuthBearer, Credentials: map[string]string{"secret": "operator-a"}}, remoteAddr: "192.0.2.10:1000",
			headers: map[string]string{"Authorization": "Bearer secret"}, wantStatus: http.StatusOK, wantID: "operator-a",
		},
		{
			name: "bearer rejects spoofed identity",
			auth: Authentication{Mode: AuthBearer, Credentials: map[string]string{"secret": "operator-a"}}, remoteAddr: "192.0.2.10:1000",
			headers: map[string]string{"Authorization": "Bearer secret", "X-Cloudattrib-Operator": "attacker"}, wantStatus: http.StatusUnauthorized,
		},
		{
			name: "trusted proxy accepts asserted identity from configured range",
			auth: Authentication{Mode: AuthTrustedProxy, TrustedProxyCIDRs: []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}}, remoteAddr: "192.0.2.10:1000",
			headers: map[string]string{"X-Cloudattrib-Operator": "operator-b"}, wantStatus: http.StatusOK, wantID: "operator-b",
		},
		{
			name: "trusted proxy rejects direct spoofing",
			auth: Authentication{Mode: AuthTrustedProxy, TrustedProxyCIDRs: []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}}, remoteAddr: "198.51.100.10:1000",
			headers: map[string]string{"X-Cloudattrib-Operator": "attacker"}, wantStatus: http.StatusUnauthorized,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			analyzer := &fixtureAnalyzer{report: fixtureReport(model.StatusComplete)}
			handler := mustHandler(t, Config{Analyzer: analyzer, Authentication: test.auth})
			recorder := serve(handler, http.MethodPost, "/v1/analyze", `{"target":"example.com","kind":"domain"}`, test.remoteAddr, test.headers)
			if recorder.Code != test.wantStatus {
				t.Fatalf("status = %d, want %d: %s", recorder.Code, test.wantStatus, recorder.Body.String())
			}
			if test.wantID != "" && analyzer.operatorID != test.wantID {
				t.Fatalf("operator ID = %q, want %q", analyzer.operatorID, test.wantID)
			}
		})
	}
}

type fixtureAnalyzer struct {
	report       model.Report
	analyzeErr   error
	lookup       model.IPLookupResult
	lookupErr    error
	operatorID   string
	reclassified model.Report
	reclassify   model.ReclassifyRequest
}

func (a *fixtureAnalyzer) Analyze(ctx context.Context, _ model.AnalyzeRequest) (model.Report, error) {
	a.operatorID = OperatorID(ctx)
	return a.report, a.analyzeErr
}

func (a *fixtureAnalyzer) LookupIP(ctx context.Context, _ model.IPLookupRequest) (model.IPLookupResult, error) {
	a.operatorID = OperatorID(ctx)
	return a.lookup, a.lookupErr
}

func (a *fixtureAnalyzer) Reclassify(_ context.Context, request model.ReclassifyRequest) (model.Report, error) {
	a.reclassify = request
	if a.reclassified.ID == "" {
		return model.Report{}, model.NewError(model.CodeCapabilityUnavailable, "not used", nil)
	}
	return a.reclassified, nil
}

type fixtureResultStore struct {
	reports map[string]model.Report
}

type fixtureFindingStore struct {
	query app.FindingQuery
	page  app.FindingPage
	err   error
}

func (s *fixtureFindingStore) Findings(_ context.Context, query app.FindingQuery) (app.FindingPage, error) {
	s.query = query
	return s.page, s.err
}

func newFixtureResultStore() *fixtureResultStore {
	return &fixtureResultStore{reports: make(map[string]model.Report)}
}

func (s *fixtureResultStore) SaveReport(_ context.Context, report model.Report) error {
	s.reports[report.ID] = report
	return nil
}

func (s *fixtureResultStore) LoadReport(_ context.Context, id string) (model.Report, error) {
	report, ok := s.reports[id]
	if !ok {
		return model.Report{}, model.NewError(model.CodeInvalidTarget, "report was not found", nil)
	}
	return report, nil
}

type fixtureReadiness struct{ snapshot ReadinessSnapshot }

func (f fixtureReadiness) Readiness(context.Context) ReadinessSnapshot { return f.snapshot }

func fixtureReport(status model.ReportStatus) model.Report {
	now := time.Date(2026, 9, 20, 9, 0, 0, 0, time.UTC)
	return model.Report{
		SchemaVersion: model.SchemaVersion,
		ID:            "report-1",
		Target:        model.Target{Original: "example.com", Canonical: "example.com", Kind: model.TargetDomain},
		Mode:          model.ModeFull,
		StartedAt:     now,
		EndedAt:       now,
		ClassifiedAt:  now,
		BundleID:      "bundle-1",
		BuildID:       "build-1",
		Status:        status,
		Observations:  []model.Observation{},
		Evidence:      []model.Evidence{},
		Findings:      []model.Finding{},
		Coverage:      []model.Coverage{},
		Warnings:      []string{},
	}
}

func mustHandler(t *testing.T, config Config) http.Handler {
	t.Helper()
	if config.Analyzer != nil && config.Results == nil {
		config.Results = newFixtureResultStore()
	}
	handler, err := NewHandler(config)
	if err != nil {
		t.Fatalf("NewHandler() error = %v", err)
	}
	return handler
}

func serve(handler http.Handler, method, path, body, remoteAddr string, headers map[string]string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, path, strings.NewReader(body))
	request.RemoteAddr = remoteAddr
	for name, value := range headers {
		request.Header.Set(name, value)
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	return recorder
}

func decodeError(t *testing.T, recorder *httptest.ResponseRecorder) errorEnvelope {
	t.Helper()
	var envelope struct {
		Error errorEnvelope `json:"error"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("decode error envelope: %v", err)
	}
	return envelope.Error
}
