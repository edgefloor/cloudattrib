package runtime

import (
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"cloudattrib/internal/api"
	"cloudattrib/internal/config"
)

func TestReadDSNRequiresPrivateSingleLineFile(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "postgres.dsn")
	if err := os.WriteFile(path, []byte("postgres://service@database/cloudattrib?sslmode=require\n"), 0o600); err != nil {
		t.Fatalf("write DSN: %v", err)
	}
	value, err := readDSN(path)
	if err != nil || value != "postgres://service@database/cloudattrib?sslmode=require" {
		t.Fatalf("readDSN() = %q, %v", value, err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatalf("chmod DSN: %v", err)
	}
	if _, err := readDSN(path); err == nil {
		t.Fatal("readDSN() accepted a group/world-readable secret")
	}
}

func TestResponseBudgetTransportBoundsWireBytes(t *testing.T) {
	t.Parallel()

	transport := newResponseBudgetTransport(roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader("123456"))}, nil
	}), 5)
	request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://ct.example/test", nil)
	if err != nil {
		t.Fatalf("NewRequestWithContext() error = %v", err)
	}
	response, err := transport.RoundTrip(request)
	if err != nil {
		t.Fatalf("RoundTrip() error = %v", err)
	}
	_, err = io.ReadAll(response.Body)
	if closeErr := response.Body.Close(); closeErr != nil {
		t.Fatalf("Close() error = %v", closeErr)
	}
	if err == nil || transport.Consumed() != 5 {
		t.Fatalf("ReadAll() error = %v, consumed = %d", err, transport.Consumed())
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (function roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

func TestServiceAuthenticationParsesTrustedProxyRanges(t *testing.T) {
	t.Parallel()

	authentication, err := serviceAuthentication(config.API{
		AuthenticationEnabled: true, AuthenticationMode: string(api.AuthTrustedProxy),
		TrustedProxyCIDRs: []string{"192.0.2.7/24"}, TrustedProxyIdentityHeader: "X-Operator",
	})
	if err != nil {
		t.Fatalf("serviceAuthentication() error = %v", err)
	}
	if authentication.Mode != api.AuthTrustedProxy || len(authentication.TrustedProxyCIDRs) != 1 || authentication.TrustedProxyCIDRs[0].String() != "192.0.2.0/24" {
		t.Fatalf("authentication = %#v", authentication)
	}
}
