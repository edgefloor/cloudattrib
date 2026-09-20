// Package api exposes the bounded HTTP adapter for cloudattrib operations.
package api

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"cloudattrib/internal/app"
	"cloudattrib/internal/jobs"
	"cloudattrib/internal/model"
	"cloudattrib/internal/observability"
	"cloudattrib/internal/rules"
)

const maximumRequestBytes int64 = 1 << 20
const maximumBatchTargets = 1000
const maximumPageSize = 500

// Config supplies the application operations and HTTP boundary settings.
type Config struct {
	Analyzer            app.Analyzer
	Jobs                jobs.Store
	Results             app.ResultStore
	Findings            app.FindingStore
	Readiness           ReadinessProvider
	Metrics             observability.Provider
	Authentication      Authentication
	MaximumRequestBytes int64
}

// ReadinessState describes whether an enabled operation can execute.
type ReadinessState string

// Readiness state values are returned by /readyz.
const (
	ReadinessReady       ReadinessState = "ready"
	ReadinessDegraded    ReadinessState = "degraded"
	ReadinessUnavailable ReadinessState = "unavailable"
)

// OperationReadiness describes one independently enabled public operation.
type OperationReadiness struct {
	Name         string                  `json:"name"`
	State        ReadinessState          `json:"state"`
	Capabilities []model.CapabilityState `json:"capabilities,omitempty"`
	Reason       string                  `json:"reason,omitempty"`
}

// ReadinessSnapshot is the bounded operational health response.
type ReadinessSnapshot struct {
	State      ReadinessState       `json:"state"`
	Operations []OperationReadiness `json:"operations"`
}

// ReadinessProvider supplies operation-level readiness without exposing storage ownership.
type ReadinessProvider interface {
	Readiness(context.Context) ReadinessSnapshot
}

// NewHandler constructs an HTTP handler without starting workers or listeners.
func NewHandler(config Config) (http.Handler, error) {
	maxBytes := config.MaximumRequestBytes
	if maxBytes == 0 {
		maxBytes = maximumRequestBytes
	}
	if maxBytes < 1 || maxBytes > maximumRequestBytes {
		return nil, fmt.Errorf("maximum request bytes must be between 1 and %d", maximumRequestBytes)
	}
	authenticator, err := newAuthenticator(config.Authentication)
	if err != nil {
		return nil, fmt.Errorf("configure authentication: %w", err)
	}
	providers, products, err := rules.DefaultCatalog()
	if err != nil {
		return nil, fmt.Errorf("load API catalog: %w", err)
	}
	slices.SortFunc(providers, func(left, right rules.Provider) int { return strings.Compare(left.ID, right.ID) })
	slices.SortFunc(products, func(left, right rules.Product) int { return strings.Compare(left.ID, right.ID) })
	return &server{
		analyzer:     config.Analyzer,
		jobs:         config.Jobs,
		results:      config.Results,
		findings:     config.Findings,
		readiness:    config.Readiness,
		metrics:      config.Metrics,
		authenticate: authenticator,
		maxBytes:     maxBytes,
		providers:    providers,
		products:     products,
	}, nil
}

type server struct {
	analyzer            app.Analyzer
	jobs                jobs.Store
	results             app.ResultStore
	findings            app.FindingStore
	readiness           ReadinessProvider
	metrics             observability.Provider
	authenticate        func(*http.Request) (string, bool)
	maxBytes            int64
	providers           []rules.Provider
	products            []rules.Product
	requests            atomic.Uint64
	admissionRejections atomic.Uint64
}

func (s *server) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	s.requests.Add(1)
	operatorID, authorized := s.authenticate(request)
	if !authorized {
		writeError(writer, http.StatusUnauthorized, errorEnvelope{Code: "unauthorized", Message: "authentication required"})
		return
	}
	request = request.WithContext(withOperatorID(request.Context(), operatorID))
	switch {
	case request.Method == http.MethodPost && request.URL.Path == "/v1/analyze":
		s.analyze(writer, request)
	case request.Method == http.MethodPost && request.URL.Path == "/v1/lookup/ip":
		s.lookupIP(writer, request)
	case request.Method == http.MethodPost && request.URL.Path == "/v1/jobs":
		s.submitJob(writer, request)
	case strings.HasPrefix(request.URL.Path, "/v1/jobs/"):
		s.jobRoute(writer, request)
	case strings.HasPrefix(request.URL.Path, "/v1/results/"):
		s.resultRoute(writer, request)
	case request.Method == http.MethodGet && request.URL.Path == "/v1/providers":
		s.listProviders(writer, request)
	case request.Method == http.MethodGet && request.URL.Path == "/v1/products":
		s.listProducts(writer, request)
	case request.Method == http.MethodGet && request.URL.Path == "/v1/findings":
		s.listFindings(writer, request)
	case request.Method == http.MethodGet && request.URL.Path == "/livez":
		writeJSON(writer, http.StatusOK, map[string]string{"status": "live"})
	case request.Method == http.MethodGet && request.URL.Path == "/readyz":
		s.ready(writer, request)
	case request.Method == http.MethodGet && request.URL.Path == "/metrics":
		s.writeMetrics(writer, request)
	default:
		writeError(writer, http.StatusNotFound, errorEnvelope{Code: "not_found", Message: "route not found"})
	}
}

func (s *server) listFindings(writer http.ResponseWriter, request *http.Request) {
	if s.findings == nil {
		writeApplicationError(writer, model.NewError(model.CodePersistenceUnavailable, "finding search is unavailable", nil))
		return
	}
	limit, err := pageLimit(request)
	if err != nil {
		writeApplicationError(writer, err)
		return
	}
	from, err := optionalTime(request.URL.Query().Get("observed_from"))
	if err != nil {
		writeApplicationError(writer, err)
		return
	}
	to, err := optionalTime(request.URL.Query().Get("observed_to"))
	if err != nil {
		writeApplicationError(writer, err)
		return
	}
	if from != nil && to != nil && from.After(*to) {
		writeApplicationError(writer, model.NewError(model.CodeInvalidOptions, "observed_from must not be after observed_to", nil))
		return
	}
	page, err := s.findings.Findings(request.Context(), app.FindingQuery{
		Domain: request.URL.Query().Get("domain"), ProviderID: request.URL.Query().Get("provider"), ProductID: request.URL.Query().Get("product"),
		Relation: model.Relation(request.URL.Query().Get("relation")), Strength: model.Strength(request.URL.Query().Get("strength")),
		ObservedFrom: from, ObservedTo: to, Cursor: request.URL.Query().Get("cursor"), Limit: limit,
	})
	if err != nil {
		writeApplicationError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, page)
}

func optionalTime(value string) (*time.Time, error) {
	if value == "" {
		return nil, nil
	}
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return nil, model.NewError(model.CodeInvalidOptions, "observation times must use RFC 3339", err)
	}
	return &parsed, nil
}

func (s *server) listProviders(writer http.ResponseWriter, request *http.Request) {
	limit, offset, err := pageParameters(request)
	if err != nil {
		writeApplicationError(writer, err)
		return
	}
	query := strings.ToLower(strings.TrimSpace(request.URL.Query().Get("q")))
	items := make([]rules.Provider, 0, len(s.providers))
	for _, provider := range s.providers {
		if catalogMatch(query, provider.ID, provider.Name, provider.Aliases) {
			items = append(items, provider)
		}
	}
	writeCatalogPage(writer, items, limit, offset)
}

func (s *server) listProducts(writer http.ResponseWriter, request *http.Request) {
	limit, offset, err := pageParameters(request)
	if err != nil {
		writeApplicationError(writer, err)
		return
	}
	query := strings.ToLower(strings.TrimSpace(request.URL.Query().Get("q")))
	items := make([]rules.Product, 0, len(s.products))
	for _, product := range s.products {
		if catalogMatch(query, product.ID, product.Name, append(slices.Clone(product.Aliases), product.Category, product.ProviderID)) {
			items = append(items, product)
		}
	}
	writeCatalogPage(writer, items, limit, offset)
}

func catalogMatch(query string, id string, name string, values []string) bool {
	if query == "" || strings.Contains(strings.ToLower(id), query) || strings.Contains(strings.ToLower(name), query) {
		return true
	}
	for _, value := range values {
		if strings.Contains(strings.ToLower(value), query) {
			return true
		}
	}
	return false
}

func writeCatalogPage[T any](writer http.ResponseWriter, items []T, limit, offset int) {
	if offset > len(items) {
		writeApplicationError(writer, model.NewError(model.CodeInvalidOptions, "cursor is outside the result set", nil))
		return
	}
	end := min(offset+limit, len(items))
	next := ""
	if end < len(items) {
		next = base64.RawURLEncoding.EncodeToString([]byte(strconv.Itoa(end)))
	}
	writeJSON(writer, http.StatusOK, struct {
		Items      []T    `json:"items"`
		NextCursor string `json:"next_cursor,omitempty"`
	}{Items: items[offset:end], NextCursor: next})
}

func (s *server) analyze(writer http.ResponseWriter, request *http.Request) {
	var input model.AnalyzeRequest
	if err := decodeJSONBody(writer, request, s.maxBytes, &input); err != nil {
		writeRequestError(writer, err)
		return
	}
	if s.analyzer == nil {
		writeApplicationError(writer, model.NewError(model.CodeCapabilityUnavailable, "analysis is unavailable", nil))
		return
	}
	if s.results == nil {
		writeApplicationError(writer, model.NewError(model.CodePersistenceUnavailable, "synchronous analysis persistence is unavailable", nil))
		return
	}
	report, err := s.analyzer.Analyze(request.Context(), input)
	if err != nil {
		writeApplicationError(writer, err)
		return
	}
	if err := s.results.SaveReport(request.Context(), report); err != nil {
		writeApplicationError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, report)
}

type submitJobInput struct {
	IdempotencyKey string                 `json:"idempotency_key"`
	BundleID       string                 `json:"bundle_id,omitempty"`
	Targets        []model.AnalyzeRequest `json:"targets"`
}

func (s *server) submitJob(writer http.ResponseWriter, request *http.Request) {
	var input submitJobInput
	if err := decodeJSONBody(writer, request, s.maxBytes, &input); err != nil {
		writeRequestError(writer, err)
		return
	}
	if len(input.Targets) == 0 || len(input.Targets) > maximumBatchTargets {
		writeApplicationError(writer, model.NewError(model.CodeInvalidOptions, "targets must contain between 1 and 1000 entries", nil))
		return
	}
	if s.jobs == nil {
		writeApplicationError(writer, model.NewError(model.CodePersistenceUnavailable, "durable jobs are unavailable", nil))
		return
	}
	job, err := s.jobs.Submit(request.Context(), jobs.SubmitRequest{
		OperatorID:     OperatorID(request.Context()),
		IdempotencyKey: input.IdempotencyKey,
		BundleID:       input.BundleID,
		Targets:        input.Targets,
	})
	if err != nil {
		s.recordAdmissionRejection(err)
		writeApplicationError(writer, err)
		return
	}
	writer.Header().Set("Location", "/v1/jobs/"+job.ID)
	writeJSON(writer, http.StatusAccepted, newJobResponse(job))
}

func (s *server) jobRoute(writer http.ResponseWriter, request *http.Request) {
	remainder := strings.TrimPrefix(request.URL.Path, "/v1/jobs/")
	parts := strings.Split(remainder, "/")
	if len(parts) == 1 && parts[0] != "" && request.Method == http.MethodGet {
		s.getJob(writer, request, parts[0])
		return
	}
	if len(parts) == 2 && parts[0] != "" && parts[1] == "cancel" && request.Method == http.MethodPost {
		s.cancelJob(writer, request, parts[0])
		return
	}
	writeError(writer, http.StatusNotFound, errorEnvelope{Code: "not_found", Message: "route not found"})
}

func (s *server) getJob(writer http.ResponseWriter, request *http.Request, id string) {
	if s.jobs == nil {
		writeApplicationError(writer, model.NewError(model.CodePersistenceUnavailable, "durable jobs are unavailable", nil))
		return
	}
	job, err := s.jobs.Job(request.Context(), id)
	if err != nil {
		writeApplicationError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, newJobResponse(job))
}

func (s *server) cancelJob(writer http.ResponseWriter, request *http.Request, id string) {
	if err := requireEmptyBody(writer, request, s.maxBytes); err != nil {
		writeRequestError(writer, err)
		return
	}
	if s.jobs == nil {
		writeApplicationError(writer, model.NewError(model.CodePersistenceUnavailable, "durable jobs are unavailable", nil))
		return
	}
	if err := s.jobs.RequestCancel(request.Context(), id, OperatorID(request.Context())); err != nil {
		writeApplicationError(writer, err)
		return
	}
	job, err := s.jobs.Job(request.Context(), id)
	if err != nil {
		writeApplicationError(writer, err)
		return
	}
	writeJSON(writer, http.StatusAccepted, newJobResponse(job))
}

func requireEmptyBody(writer http.ResponseWriter, request *http.Request, limit int64) error {
	if request.ContentLength > limit {
		return requestBodyError{tooLarge: true}
	}
	reader := http.MaxBytesReader(writer, request.Body, limit)
	read, err := io.Copy(io.Discard, reader)
	var maxBytesError *http.MaxBytesError
	if errors.As(err, &maxBytesError) {
		return requestBodyError{tooLarge: true}
	}
	if err != nil || read != 0 {
		return requestBodyError{}
	}
	return nil
}

type jobResponse struct {
	ID              string                    `json:"id"`
	Status          jobs.JobStatus            `json:"status"`
	BundleID        string                    `json:"bundle_id,omitempty"`
	CancelRequested bool                      `json:"cancel_requested"`
	CreatedAt       string                    `json:"created_at"`
	UpdatedAt       string                    `json:"updated_at"`
	Counts          map[jobs.TargetStatus]int `json:"counts"`
	Targets         []jobTargetResponse       `json:"targets"`
}

type jobTargetResponse struct {
	ID             string            `json:"id"`
	InputIndex     int               `json:"input_index"`
	Status         jobs.TargetStatus `json:"status"`
	Attempts       int               `json:"attempts"`
	TerminalReason string            `json:"terminal_reason,omitempty"`
	ResultURL      string            `json:"result_url,omitempty"`
}

func newJobResponse(job jobs.Job) jobResponse {
	response := jobResponse{
		ID: job.ID, Status: job.Status, BundleID: job.BundleID, CancelRequested: job.CancelRequested,
		CreatedAt: job.CreatedAt.UTC().Format(timeLayout), UpdatedAt: job.UpdatedAt.UTC().Format(timeLayout),
		Counts: make(map[jobs.TargetStatus]int), Targets: make([]jobTargetResponse, 0, len(job.Targets)),
	}
	for _, target := range job.Targets {
		item := jobTargetResponse{ID: target.ID, InputIndex: target.Index, Status: target.Status, Attempts: target.Attempts, TerminalReason: target.TerminalReason}
		if target.ReportAvailable {
			item.ResultURL = "/v1/results/" + target.Report.ID
		}
		response.Counts[target.Status]++
		response.Targets = append(response.Targets, item)
	}
	return response
}

const timeLayout = "2006-01-02T15:04:05.999999999Z07:00"

func (s *server) resultRoute(writer http.ResponseWriter, request *http.Request) {
	remainder := strings.TrimPrefix(request.URL.Path, "/v1/results/")
	parts := strings.Split(remainder, "/")
	if len(parts) == 1 && parts[0] != "" && request.Method == http.MethodGet {
		s.getResult(writer, request, parts[0])
		return
	}
	if len(parts) == 2 && parts[0] != "" && parts[1] == "observations" && request.Method == http.MethodGet {
		s.getObservations(writer, request, parts[0])
		return
	}
	if len(parts) == 2 && parts[0] != "" && parts[1] == "reclassify" && request.Method == http.MethodPost {
		s.reclassify(writer, request, parts[0])
		return
	}
	writeError(writer, http.StatusNotFound, errorEnvelope{Code: "not_found", Message: "route not found"})
}

func (s *server) getResult(writer http.ResponseWriter, request *http.Request, id string) {
	report, ok := s.loadResult(writer, request, id)
	if ok {
		writeJSON(writer, http.StatusOK, report)
	}
}

func (s *server) loadResult(writer http.ResponseWriter, request *http.Request, id string) (model.Report, bool) {
	if s.results == nil {
		writeApplicationError(writer, model.NewError(model.CodePersistenceUnavailable, "stored results are unavailable", nil))
		return model.Report{}, false
	}
	report, err := s.results.LoadReport(request.Context(), id)
	if err != nil {
		writeApplicationError(writer, err)
		return model.Report{}, false
	}
	return report, true
}

func (s *server) getObservations(writer http.ResponseWriter, request *http.Request, id string) {
	report, ok := s.loadResult(writer, request, id)
	if !ok {
		return
	}
	limit, offset, err := pageParameters(request)
	if err != nil {
		writeApplicationError(writer, err)
		return
	}
	observations := slices.Clone(report.Observations)
	slices.SortStableFunc(observations, func(left, right model.Observation) int {
		if order := left.ObservedAt.Compare(right.ObservedAt); order != 0 {
			return order
		}
		return strings.Compare(left.ID, right.ID)
	})
	if offset > len(observations) {
		writeApplicationError(writer, model.NewError(model.CodeInvalidOptions, "cursor is outside the result set", nil))
		return
	}
	end := min(offset+limit, len(observations))
	next := ""
	if end < len(observations) {
		next = base64.RawURLEncoding.EncodeToString([]byte(strconv.Itoa(end)))
	}
	writeJSON(writer, http.StatusOK, struct {
		Items      []model.Observation `json:"items"`
		NextCursor string              `json:"next_cursor,omitempty"`
	}{Items: observations[offset:end], NextCursor: next})
}

func pageParameters(request *http.Request) (int, int, error) {
	limit, err := pageLimit(request)
	if err != nil {
		return 0, 0, err
	}
	offset := 0
	if cursor := request.URL.Query().Get("cursor"); cursor != "" {
		decoded, err := base64.RawURLEncoding.DecodeString(cursor)
		if err != nil {
			return 0, 0, model.NewError(model.CodeInvalidOptions, "cursor is invalid", err)
		}
		parsed, err := strconv.Atoi(string(decoded))
		if err != nil || parsed < 0 {
			return 0, 0, model.NewError(model.CodeInvalidOptions, "cursor is invalid", err)
		}
		offset = parsed
	}
	return limit, offset, nil
}

func pageLimit(request *http.Request) (int, error) {
	limit := 100
	if raw := request.URL.Query().Get("limit"); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 || parsed > maximumPageSize {
			return 0, model.NewError(model.CodeInvalidOptions, "limit must be between 1 and 500", err)
		}
		limit = parsed
	}
	return limit, nil
}

type reclassifyInput struct {
	BundleID       string `json:"bundle_id"`
	IdempotencyKey string `json:"idempotency_key"`
}

func (s *server) reclassify(writer http.ResponseWriter, request *http.Request, id string) {
	var input reclassifyInput
	if err := decodeJSONBody(writer, request, s.maxBytes, &input); err != nil {
		writeRequestError(writer, err)
		return
	}
	if s.jobs == nil || s.results == nil {
		writeApplicationError(writer, model.NewError(model.CodeCapabilityUnavailable, "reclassification is unavailable", nil))
		return
	}
	if input.BundleID == "" {
		writeApplicationError(writer, model.NewError(model.CodeInvalidOptions, "reclassification requires a bundle ID", nil))
		return
	}
	original, err := s.results.LoadReport(request.Context(), id)
	if err != nil {
		writeApplicationError(writer, err)
		return
	}
	if len(original.Observations) == 0 && len(original.Evidence) == 0 {
		writeApplicationError(writer, model.NewError(model.CodeCapabilityUnavailable, "report has no retained replay inputs", nil))
		return
	}
	if validator, ok := s.analyzer.(app.ReclassificationValidator); ok {
		if err := validator.ValidateReclassify(request.Context(), model.ReclassifyRequest{ReportID: id, BundleID: input.BundleID}); err != nil {
			writeApplicationError(writer, err)
			return
		}
	}
	job, err := s.jobs.Submit(request.Context(), jobs.SubmitRequest{
		OperatorID: OperatorID(request.Context()), IdempotencyKey: input.IdempotencyKey, BundleID: input.BundleID,
		Reclassifications: []model.ReclassifyRequest{{ReportID: id, BundleID: input.BundleID}},
	})
	if err != nil {
		s.recordAdmissionRejection(err)
		writeApplicationError(writer, err)
		return
	}
	writer.Header().Set("Location", "/v1/jobs/"+job.ID)
	writeJSON(writer, http.StatusAccepted, newJobResponse(job))
}

func (s *server) lookupIP(writer http.ResponseWriter, request *http.Request) {
	var input ipLookupInput
	if err := decodeJSONBody(writer, request, s.maxBytes, &input); err != nil {
		writeRequestError(writer, err)
		return
	}
	address, err := netip.ParseAddr(input.Address)
	if err != nil || address.Zone() != "" {
		writeApplicationError(writer, model.NewError(model.CodeInvalidTarget, "IP address is invalid", err))
		return
	}
	if s.analyzer == nil {
		writeApplicationError(writer, model.NewError(model.CodeCapabilityUnavailable, "local IP lookup is unavailable", nil))
		return
	}
	result, err := s.analyzer.LookupIP(request.Context(), model.IPLookupRequest{
		Address:        address.Unmap(),
		Match:          input.Match,
		IncludeRetired: input.IncludeRetired,
		Categories:     input.Categories,
	})
	if err != nil {
		writeApplicationError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, result)
}

func (s *server) ready(writer http.ResponseWriter, request *http.Request) {
	snapshot := s.defaultReadiness(request.Context())
	if s.readiness != nil {
		snapshot = s.readiness.Readiness(request.Context())
	}
	status := http.StatusOK
	if snapshot.State == ReadinessUnavailable {
		status = http.StatusServiceUnavailable
	}
	writeJSON(writer, status, snapshot)
}

func (s *server) recordAdmissionRejection(err error) {
	if model.ErrorCodeOf(err) == model.CodeQueueCapacityExceeded {
		s.admissionRejections.Add(1)
	}
}

func (s *server) writeMetrics(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("Content-Type", "text/plain; version=0.0.4")
	_, _ = fmt.Fprintf(writer, "# TYPE cloudattrib_http_requests_total counter\ncloudattrib_http_requests_total %d\n", s.requests.Load())
	_, _ = fmt.Fprintf(writer, "# TYPE cloudattrib_admission_rejections_total counter\ncloudattrib_admission_rejections_total %d\n", s.admissionRejections.Load())
	if s.metrics == nil {
		return
	}
	snapshot, err := s.metrics.OperationalMetrics(request.Context())
	if err != nil {
		_, _ = fmt.Fprint(writer, "# TYPE cloudattrib_metrics_scrape_error gauge\ncloudattrib_metrics_scrape_error 1\n")
		return
	}
	_, _ = fmt.Fprint(writer, "# TYPE cloudattrib_metrics_scrape_error gauge\ncloudattrib_metrics_scrape_error 0\n")
	_, _ = fmt.Fprintf(writer, "# TYPE cloudattrib_queue_reserved_targets gauge\ncloudattrib_queue_reserved_targets %d\n", snapshot.ReservedTargets)
	_, _ = fmt.Fprintf(writer, "# TYPE cloudattrib_queue_maximum_targets gauge\ncloudattrib_queue_maximum_targets %d\n", snapshot.MaximumTargets)
	_, _ = fmt.Fprintf(writer, "# TYPE cloudattrib_queue_queued_targets gauge\ncloudattrib_queue_queued_targets %d\n", snapshot.QueuedTargets)
	_, _ = fmt.Fprintf(writer, "# TYPE cloudattrib_queue_running_targets gauge\ncloudattrib_queue_running_targets %d\n", snapshot.RunningTargets)
	_, _ = fmt.Fprintf(writer, "# TYPE cloudattrib_bundle_pins gauge\ncloudattrib_bundle_pins %d\n", snapshot.BundlePins)
	_, _ = fmt.Fprintf(writer, "# TYPE cloudattrib_ct_checkpoints gauge\ncloudattrib_ct_checkpoints %d\n", snapshot.CTCheckpoints)
	_, _ = fmt.Fprintf(writer, "# TYPE cloudattrib_ct_ingestion_lag_seconds gauge\ncloudattrib_ct_ingestion_lag_seconds %.3f\n", snapshot.CTIngestionLagSeconds)
	_, _ = fmt.Fprintf(writer, "# TYPE cloudattrib_dataset_unavailable_sources gauge\ncloudattrib_dataset_unavailable_sources %d\n", snapshot.UnavailableSources)
	_, _ = fmt.Fprintf(writer, "# TYPE cloudattrib_dataset_oldest_source_age_seconds gauge\ncloudattrib_dataset_oldest_source_age_seconds %.3f\n", snapshot.OldestSourceAgeSeconds)
	if snapshot.ActiveBundleID != "" {
		_, _ = fmt.Fprintf(writer, "# TYPE cloudattrib_bundle_info gauge\ncloudattrib_bundle_info{bundle_id=%q} 1\n", snapshot.ActiveBundleID)
	}
}

func (s *server) defaultReadiness(_ context.Context) ReadinessSnapshot {
	operations := []OperationReadiness{
		operationReadiness("analyze", s.analyzer != nil && s.results != nil, "analyzer or writable result storage is unavailable"),
		operationReadiness("lookup_ip", s.analyzer != nil, "local analyzer is unavailable"),
		operationReadiness("jobs", s.jobs != nil, "durable job storage is unavailable"),
		operationReadiness("results", s.results != nil, "durable result storage is unavailable"),
		operationReadiness("findings", s.findings != nil, "finding storage is unavailable"),
		{Name: "catalog", State: ReadinessReady},
	}
	ready, unavailable := 0, 0
	for _, operation := range operations {
		if operation.State == ReadinessReady {
			ready++
		} else {
			unavailable++
		}
	}
	state := ReadinessReady
	if ready == 0 {
		state = ReadinessUnavailable
	} else if unavailable > 0 {
		state = ReadinessDegraded
	}
	return ReadinessSnapshot{State: state, Operations: operations}
}

func operationReadiness(name string, ready bool, reason string) OperationReadiness {
	if ready {
		return OperationReadiness{Name: name, State: ReadinessReady}
	}
	return OperationReadiness{Name: name, State: ReadinessUnavailable, Reason: reason}
}

type ipLookupInput struct {
	Address        string   `json:"address"`
	Match          string   `json:"match"`
	IncludeRetired bool     `json:"include_retired"`
	Categories     []string `json:"categories"`
}

type errorEnvelope struct {
	Code    model.ErrorCode `json:"code"`
	Message string          `json:"message"`
}

type requestBodyError struct{ tooLarge bool }

func (e requestBodyError) Error() string { return "invalid request body" }

func decodeJSONBody(writer http.ResponseWriter, request *http.Request, limit int64, target any) error {
	if request.ContentLength > limit {
		return requestBodyError{tooLarge: true}
	}
	decoder := json.NewDecoder(http.MaxBytesReader(writer, request.Body, limit))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		var maxBytesError *http.MaxBytesError
		return requestBodyError{tooLarge: errors.As(err, &maxBytesError)}
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		var maxBytesError *http.MaxBytesError
		return requestBodyError{tooLarge: errors.As(err, &maxBytesError)}
	}
	return nil
}

func writeRequestError(writer http.ResponseWriter, err error) {
	var bodyErr requestBodyError
	if errors.As(err, &bodyErr) && bodyErr.tooLarge {
		writeApplicationError(writer, model.NewError(model.CodeInputTooLarge, "request body exceeds the 1 MiB limit", err))
		return
	}
	writeApplicationError(writer, model.NewError(model.CodeInvalidSyntax, "invalid request JSON", err))
}

func writeApplicationError(writer http.ResponseWriter, err error) {
	code := model.ErrorCodeOf(err)
	if code == "" {
		writeError(writer, http.StatusInternalServerError, errorEnvelope{Code: "internal_error", Message: "internal server error"})
		return
	}
	message := string(code)
	var appErr *model.AppError
	if errors.As(err, &appErr) && appErr.Message != "" {
		message = appErr.Message
	}
	writeError(writer, model.HTTPStatus(err), errorEnvelope{Code: code, Message: message})
}

func writeError(writer http.ResponseWriter, status int, value errorEnvelope) {
	writeJSON(writer, status, struct {
		Error errorEnvelope `json:"error"`
	}{Error: value})
}

func writeJSON(writer http.ResponseWriter, status int, value any) {
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	if err := json.NewEncoder(writer).Encode(value); err != nil {
		return
	}
}

type operatorContextKey struct{}

func withOperatorID(ctx context.Context, operatorID string) context.Context {
	return context.WithValue(ctx, operatorContextKey{}, operatorID)
}

// OperatorID returns the authenticated request identity, if the API set one.
func OperatorID(ctx context.Context) string {
	operatorID, _ := ctx.Value(operatorContextKey{}).(string)
	return operatorID
}

func hasIdentityHeader(request *http.Request, name string) bool {
	return strings.TrimSpace(request.Header.Get(name)) != ""
}
