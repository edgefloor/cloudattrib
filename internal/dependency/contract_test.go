// Package dependency contains compile-time and offline dependency contract probes.
package dependency

import (
	"errors"
	"net/http"
	"net/netip"
	"testing"

	"github.com/gaissmai/bart"
	ctclient "github.com/google/certificate-transparency-go/client"
	"github.com/google/certificate-transparency-go/jsonclient"
	"github.com/miekg/dns"
	wappalyzer "github.com/projectdiscovery/wappalyzergo"
)

func TestBARTSelectedAPI(t *testing.T) {
	t.Parallel()

	table := &bart.Table[[]string]{}
	prefix := netip.MustParsePrefix("198.51.100.0/24")
	table.Insert(prefix, []string{"association"})
	if got, ok := table.Get(prefix); !ok || len(got) != 1 || got[0] != "association" {
		t.Fatalf("Get() = %v, %t", got, ok)
	}
	if got, ok := table.Lookup(netip.MustParseAddr("198.51.100.7")); !ok || got[0] != "association" {
		t.Fatalf("Lookup() = %v, %t", got, ok)
	}
	var covering int
	for range table.Supernets(netip.MustParsePrefix("198.51.100.7/32")) {
		covering++
	}
	if covering != 1 {
		t.Fatalf("Supernets() count = %d, want 1", covering)
	}
}

func TestDNSSelectedAPI(t *testing.T) {
	t.Parallel()

	client := &dns.Client{Net: "udp"}
	message := new(dns.Msg)
	message.SetQuestion("example.com.", dns.TypeA)
	if client.Net != "udp" || len(message.Question) != 1 {
		t.Fatal("selected raw DNS API contract changed")
	}
	_ = client.ExchangeContext
}

func TestWappalyzerPassiveAPI(t *testing.T) {
	t.Parallel()

	detector, err := wappalyzer.New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	result := detector.Fingerprint(map[string][]string{"content-type": {"text/html"}}, []byte("<html></html>"))
	if result == nil {
		t.Fatal("Fingerprint() returned nil map")
	}
}

func TestCTConstructionMakesNoRequest(t *testing.T) {
	t.Parallel()

	transport := &rejectingTransport{}
	httpClient := &http.Client{Transport: transport}
	client, err := ctclient.New("https://ct.invalid/", httpClient, jsonclient.Options{})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if client == nil {
		t.Fatal("New() client = nil")
	}
	if transport.attempted {
		t.Fatal("CT client construction attempted a network request")
	}
}

type rejectingTransport struct {
	attempted bool
}

func (t *rejectingTransport) RoundTrip(*http.Request) (*http.Response, error) {
	t.attempted = true
	return nil, errors.New("network disabled")
}
