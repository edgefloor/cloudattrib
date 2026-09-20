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
	report     model.Report
	analyzeErr error
	lookup     model.IPLookupResult
	lookupErr  error
	operatorID string
}

func (a *fixtureAnalyzer) Analyze(ctx context.Context, _ model.AnalyzeRequest) (model.Report, error) {
	a.operatorID = OperatorID(ctx)
	return a.report, a.analyzeErr
}

func (a *fixtureAnalyzer) LookupIP(ctx context.Context, _ model.IPLookupRequest) (model.IPLookupResult, error) {
	a.operatorID = OperatorID(ctx)
	return a.lookup, a.lookupErr
}

func (a *fixtureAnalyzer) Reclassify(context.Context, model.ReclassifyRequest) (model.Report, error) {
	return model.Report{}, model.NewError(model.CodeCapabilityUnavailable, "not used", nil)
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
