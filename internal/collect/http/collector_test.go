package http

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"net"
	stdhttp "net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"cloudattrib/internal/model"
	"cloudattrib/internal/policy"
)

func TestCollectRetainsSanitizedScriptURLsForOfflineRules(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(stdhttp.HandlerFunc(func(writer stdhttp.ResponseWriter, _ *stdhttp.Request) {
		_, _ = writer.Write([]byte(`<script src="https://cdn.segment.com/analytics.js/v1/key.js?token=secret"></script>`))
	}))
	t.Cleanup(server.Close)
	address := netip.MustParseAddr("93.184.216.34")
	collector := New((&mappedDialer{destinations: map[netip.Addr]string{address: server.Listener.Addr().String()}}).DialContext, policy.PublicDestinationPolicy(), 2<<20)
	result, err := collector.Collect(context.Background(), "http", "example.com", address)
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}
	var payload model.HTTPPayload
	if err := json.Unmarshal(result.Observation.Payload, &payload); err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	if len(payload.ScriptURLs) != 1 || payload.ScriptURLs[0] != "https://cdn.segment.com/analytics.js/v1/key.js" {
		t.Fatalf("ScriptURLs = %#v", payload.ScriptURLs)
	}
}

func TestCollectTargetPreservesRequestURLAndRedactsObservedQuery(t *testing.T) {
	t.Parallel()

	requestURI := make(chan string, 1)
	server := httptest.NewServer(stdhttp.HandlerFunc(func(writer stdhttp.ResponseWriter, request *stdhttp.Request) {
		requestURI <- request.RequestURI
		writer.WriteHeader(stdhttp.StatusNoContent)
	}))
	t.Cleanup(server.Close)
	address := netip.MustParseAddr("93.184.216.34")
	collector := New((&mappedDialer{destinations: map[netip.Addr]string{address: server.Listener.Addr().String()}}).DialContext, policy.PublicDestinationPolicy(), 2<<20)
	result, err := collector.CollectTarget(context.Background(), "http://example.com/status?probe=secret", address)
	if err != nil {
		t.Fatalf("CollectTarget() error = %v", err)
	}
	if got := <-requestURI; got != "/status?probe=secret" {
		t.Fatalf("request URI = %q", got)
	}
	var payload model.HTTPPayload
	if err := json.Unmarshal(result.Observation.Payload, &payload); err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	if payload.URL != "http://example.com/status?redacted" {
		t.Fatalf("observed URL = %q", payload.URL)
	}
}

func TestCollectTargetDistinguishesRequestPaths(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(stdhttp.HandlerFunc(func(writer stdhttp.ResponseWriter, _ *stdhttp.Request) {
		writer.WriteHeader(stdhttp.StatusNoContent)
	}))
	t.Cleanup(server.Close)
	address := netip.MustParseAddr("93.184.216.34")
	collector := New((&mappedDialer{destinations: map[netip.Addr]string{address: server.Listener.Addr().String()}}).DialContext, policy.PublicDestinationPolicy(), 2<<20)
	occurrence := model.ObservationOccurrence{CollectionRunID: "run-1", Seed: "example.com", Attempt: 1}
	first, err := collector.CollectTargetOccurrence(context.Background(), "http://example.com/first", address, occurrence)
	if err != nil {
		t.Fatalf("CollectTargetOccurrence() first error = %v", err)
	}
	second, err := collector.CollectTargetOccurrence(context.Background(), "http://example.com/second", address, occurrence)
	if err != nil {
		t.Fatalf("CollectTargetOccurrence() second error = %v", err)
	}
	if first.Observation.ID == second.Observation.ID {
		t.Fatalf("observation ID %q reused for distinct request paths", first.Observation.ID)
	}
}

func TestCollectTargetOccurrenceDistinguishesRequestAndAttemptWithoutUsingQueryValues(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(stdhttp.HandlerFunc(func(writer stdhttp.ResponseWriter, _ *stdhttp.Request) {
		writer.WriteHeader(stdhttp.StatusNoContent)
	}))
	t.Cleanup(server.Close)
	address := netip.MustParseAddr("93.184.216.34")
	collector := New((&mappedDialer{destinations: map[netip.Addr]string{address: server.Listener.Addr().String()}}).DialContext, policy.PublicDestinationPolicy(), 2<<20)
	base := model.ObservationOccurrence{CollectionRunID: "run-1", Seed: "example.com", RequestIndex: 4, Attempt: 1}
	first, err := collector.CollectTargetOccurrence(context.Background(), "http://example.com/shared?token=first-secret", address, base)
	if err != nil {
		t.Fatalf("CollectTargetOccurrence() first error = %v", err)
	}
	queryChanged, err := collector.CollectTargetOccurrence(context.Background(), "http://example.com/shared?token=second-secret", address, base)
	if err != nil {
		t.Fatalf("CollectTargetOccurrence() changed query error = %v", err)
	}
	if first.Observation.ID != queryChanged.Observation.ID {
		t.Fatalf("query values changed observation ID: %q != %q", first.Observation.ID, queryChanged.Observation.ID)
	}
	for _, secret := range []string{"first-secret", "second-secret"} {
		if strings.Contains(first.Observation.ID, secret) {
			t.Fatalf("observation ID %q contains query value", first.Observation.ID)
		}
	}

	repeated := base
	repeated.RequestIndex++
	repeatedResult, err := collector.CollectTargetOccurrence(context.Background(), "http://example.com/shared?token=first-secret", address, repeated)
	if err != nil {
		t.Fatalf("CollectTargetOccurrence() repeated request error = %v", err)
	}
	if first.Observation.ID == repeatedResult.Observation.ID {
		t.Fatalf("observation ID %q reused for repeated request", first.Observation.ID)
	}

	retried := base
	retried.Attempt++
	retriedResult, err := collector.CollectTargetOccurrence(context.Background(), "http://example.com/shared?token=first-secret", address, retried)
	if err != nil {
		t.Fatalf("CollectTargetOccurrence() retry error = %v", err)
	}
	if first.Observation.ID == retriedResult.Observation.ID {
		t.Fatalf("observation ID %q reused for retry", first.Observation.ID)
	}
}

func TestCollectRequestTimeoutCancelsSlowHeaders(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(stdhttp.HandlerFunc(func(_ stdhttp.ResponseWriter, request *stdhttp.Request) {
		<-request.Context().Done()
	}))
	t.Cleanup(server.Close)
	address := netip.MustParseAddr("93.184.216.34")
	collector := New(
		(&mappedDialer{destinations: map[netip.Addr]string{address: server.Listener.Addr().String()}}).DialContext,
		policy.PublicDestinationPolicy(), 2<<20, WithRequestTimeout(20*time.Millisecond),
	)
	started := time.Now()
	if _, err := collector.Collect(context.Background(), "http", "example.com", address); err == nil {
		t.Fatal("Collect() succeeded, want timeout")
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("Collect() elapsed = %s, want bounded request", elapsed)
	}
}

func TestRedirectResolvesAndValidatesEveryAddress(t *testing.T) {
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")

	var hostsMu sync.Mutex
	var hosts []string
	landing := httptest.NewServer(stdhttp.HandlerFunc(func(writer stdhttp.ResponseWriter, request *stdhttp.Request) {
		hostsMu.Lock()
		hosts = append(hosts, request.Host)
		hostsMu.Unlock()
		writer.WriteHeader(stdhttp.StatusOK)
	}))
	t.Cleanup(landing.Close)
	start := httptest.NewServer(stdhttp.HandlerFunc(func(writer stdhttp.ResponseWriter, request *stdhttp.Request) {
		hostsMu.Lock()
		hosts = append(hosts, request.Host)
		hostsMu.Unlock()
		writer.Header().Set("Location", "http://redirect.example/")
		writer.WriteHeader(stdhttp.StatusFound)
	}))
	t.Cleanup(start.Close)

	first := netip.MustParseAddr("93.184.216.34")
	second := netip.MustParseAddr("1.1.1.1")
	dialer := &mappedDialer{destinations: map[netip.Addr]string{first: start.Listener.Addr().String(), second: landing.Listener.Addr().String()}}
	collector := New(
		dialer.DialContext,
		policy.PublicDestinationPolicy(),
		2<<20,
		WithRedirectResolver(func(context.Context, string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("127.0.0.1"), second}, nil
		}),
	)
	result, err := collector.Collect(context.Background(), "http", "example.com", first)
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}
	if len(result.Observations) != 2 || result.Coverage.Status != model.CoveragePartial {
		t.Fatalf("Collect() result = %#v", result)
	}
	if result.Observations[1].Scope != model.ScopeExternalRedirect {
		t.Fatalf("redirect scope = %q, want external_redirect", result.Observations[1].Scope)
	}
	wantDials := []netip.Addr{first, second}
	if got := dialer.Addresses(); !equalAddresses(got, wantDials) {
		t.Fatalf("dial addresses = %v, want %v", got, wantDials)
	}
	hostsMu.Lock()
	defer hostsMu.Unlock()
	if len(hosts) != 2 || hosts[0] != "example.com" || hosts[1] != "redirect.example" {
		t.Fatalf("HTTP hosts = %v", hosts)
	}
}

func TestRedirectToOnlyProhibitedAddressesIsNotDialed(t *testing.T) {
	t.Parallel()

	start := httptest.NewServer(stdhttp.HandlerFunc(func(writer stdhttp.ResponseWriter, _ *stdhttp.Request) {
		writer.Header().Set("Location", "http://metadata.example/")
		writer.WriteHeader(stdhttp.StatusFound)
	}))
	t.Cleanup(start.Close)
	first := netip.MustParseAddr("93.184.216.34")
	dialer := &mappedDialer{destinations: map[netip.Addr]string{first: start.Listener.Addr().String()}}
	collector := New(
		dialer.DialContext,
		policy.PublicDestinationPolicy(),
		2<<20,
		WithRedirectResolver(func(context.Context, string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("169.254.169.254")}, nil
		}),
	)
	result, err := collector.Collect(context.Background(), "http", "example.com", first)
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}
	if got := dialer.Addresses(); len(got) != 1 || got[0] != first {
		t.Fatalf("dial addresses = %v, want only %v", got, first)
	}
	if result.Coverage.Status != model.CoveragePartial || result.Coverage.Omitted != 1 {
		t.Fatalf("coverage = %#v", result.Coverage)
	}
}

func TestHTTPSUsesTargetHostnameForSNIWhenDialingApprovedAddress(t *testing.T) {
	t.Parallel()

	clientConnection, serverConnection := net.Pipe()
	serverName := make(chan string, 1)
	go func() {
		defer func() { _ = serverConnection.Close() }()
		server := tls.Server(serverConnection, &tls.Config{
			MinVersion: tls.VersionTLS12,
			GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
				serverName <- hello.ServerName
				return nil, errors.New("fixture stops after client hello")
			},
		})
		_ = server.Handshake()
	}()
	address := netip.MustParseAddr("93.184.216.34")
	collector := New(func(context.Context, string, netip.Addr, uint16) (net.Conn, error) {
		return clientConnection, nil
	}, policy.PublicDestinationPolicy(), 2<<20)
	if _, err := collector.Collect(context.Background(), "https", "example.com", address); err == nil {
		t.Fatal("Collect() succeeded despite fixture handshake stop")
	}
	if got := <-serverName; got != "example.com" {
		t.Fatalf("TLS server name = %q, want example.com", got)
	}
}

type mappedDialer struct {
	mu           sync.Mutex
	destinations map[netip.Addr]string
	addresses    []netip.Addr
}

func (d *mappedDialer) DialContext(ctx context.Context, network string, address netip.Addr, _ uint16) (net.Conn, error) {
	d.mu.Lock()
	d.addresses = append(d.addresses, address)
	destination := d.destinations[address]
	d.mu.Unlock()
	var dialer net.Dialer
	return dialer.DialContext(ctx, network, destination)
}

func (d *mappedDialer) Addresses() []netip.Addr {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]netip.Addr(nil), d.addresses...)
}

func equalAddresses(a, b []netip.Addr) bool {
	if len(a) != len(b) {
		return false
	}
	for index := range a {
		if a[index] != b[index] {
			return false
		}
	}
	return true
}
