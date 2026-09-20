// Package api exposes the bounded HTTP adapter for cloudattrib operations.
package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"strings"

	"cloudattrib/internal/app"
	"cloudattrib/internal/model"
)

const maximumRequestBytes int64 = 1 << 20

// Config supplies the application operations and HTTP boundary settings.
type Config struct {
	Analyzer            app.Analyzer
	Readiness           ReadinessProvider
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
	return &server{
		analyzer:     config.Analyzer,
		readiness:    config.Readiness,
		authenticate: authenticator,
		maxBytes:     maxBytes,
	}, nil
}

type server struct {
	analyzer     app.Analyzer
	readiness    ReadinessProvider
	authenticate func(*http.Request) (string, bool)
	maxBytes     int64
}

func (s *server) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
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
	case request.Method == http.MethodGet && request.URL.Path == "/livez":
		writeJSON(writer, http.StatusOK, map[string]string{"status": "live"})
	case request.Method == http.MethodGet && request.URL.Path == "/readyz":
		s.ready(writer, request)
	default:
		writeError(writer, http.StatusNotFound, errorEnvelope{Code: "not_found", Message: "route not found"})
	}
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
	report, err := s.analyzer.Analyze(request.Context(), input)
	if err != nil {
		writeApplicationError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, report)
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

func (s *server) defaultReadiness(_ context.Context) ReadinessSnapshot {
	state := ReadinessUnavailable
	if s.analyzer != nil {
		state = ReadinessReady
	}
	return ReadinessSnapshot{State: state, Operations: []OperationReadiness{
		{Name: "analyze", State: state},
		{Name: "lookup_ip", State: state},
	}}
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
