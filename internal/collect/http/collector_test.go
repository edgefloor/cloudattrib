package http

import (
	"context"
	"net"
	stdhttp "net/http"
	"net/http/httptest"
	"net/netip"
	"sync"
	"testing"

	"cloudattrib/internal/model"
	"cloudattrib/internal/policy"
)

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
