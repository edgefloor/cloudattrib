package http

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
	"math/big"
	stdhttp "net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"testing"
	"time"

	"cloudattrib/internal/model"
	"cloudattrib/internal/policy"
)

func observationTypes(observations []model.Observation) []string {
	types := make([]string, len(observations))
	for index, observation := range observations {
		types[index] = observation.Type
	}
	return types
}

func testTLSCertificate(t *testing.T, names []string, before, after time.Time) (tls.Certificate, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: names[0], Organization: []string{"fixture issuer"}},
		DNSNames: names, NotBefore: before, NotAfter: after,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true, IsCA: true,
	}
	encoded, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(encoded)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{encoded}, PrivateKey: key, Leaf: parsed}, parsed
}

func testTLSServer(t *testing.T, certificate tls.Certificate, handler stdhttp.Handler) *httptest.Server {
	t.Helper()
	server := httptest.NewUnstartedServer(handler)
	server.TLS = &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}}
	server.StartTLS()
	t.Cleanup(server.Close)
	return server
}

func TestCollectClassifiesHostnameAndExpiryFailures(t *testing.T) {
	now := time.Now()
	for _, test := range []struct {
		name        string
		hostname    string
		before      time.Time
		after       time.Time
		wantFailure string
	}{
		{"hostname mismatch", "wrong.example", now.Add(-time.Hour), now.Add(time.Hour), "hostname_mismatch"},
		{"expired", "example.com", now.Add(-48 * time.Hour), now.Add(-24 * time.Hour), "certificate_expired_or_not_yet_valid"},
	} {
		t.Run(test.name, func(t *testing.T) {
			certificate, parsed := testTLSCertificate(t, []string{"example.com"}, test.before, test.after)
			server := testTLSServer(t, certificate, stdhttp.HandlerFunc(func(writer stdhttp.ResponseWriter, _ *stdhttp.Request) {
				writer.WriteHeader(stdhttp.StatusNoContent)
			}))
			roots := x509.NewCertPool()
			roots.AddCert(parsed)
			address := netip.MustParseAddr("93.184.216.34")
			dialer := &mappedDialer{destinations: map[netip.Addr]string{address: server.Listener.Addr().String()}}
			collector := New(dialer.DialContext, policy.PublicDestinationPolicy(), 2<<20, WithTLSRootCAs(roots))
			result, err := collector.Collect(t.Context(), "https", test.hostname, address)
			if err == nil || len(result.Observations) != 1 || result.Observations[0].Type != "tls_certificate" || len(dialer.Addresses()) != 1 {
				t.Fatalf("error=%v observations=%v dials=%d", err, observationTypes(result.Observations), len(dialer.Addresses()))
			}
			var payload model.TLSCertificatePayload
			if err := json.Unmarshal(result.Observations[0].Payload, &payload); err != nil {
				t.Fatal(err)
			}
			if payload.Verified || payload.Failure != test.wantFailure {
				t.Fatalf("TLS outcome = %#v", payload)
			}
		})
	}
}

func TestCollectRetainsDistinctCertificatesAcrossHTTPSRedirects(t *testing.T) {
	now := time.Now()
	secondCertificate, secondParsed := testTLSCertificate(t, []string{"other.example"}, now.Add(-time.Hour), now.Add(time.Hour))
	second := testTLSServer(t, secondCertificate, stdhttp.HandlerFunc(func(writer stdhttp.ResponseWriter, _ *stdhttp.Request) {
		writer.WriteHeader(stdhttp.StatusNoContent)
	}))
	first := httptest.NewTLSServer(stdhttp.HandlerFunc(func(writer stdhttp.ResponseWriter, _ *stdhttp.Request) {
		writer.Header().Set("Location", "https://other.example/")
		writer.WriteHeader(stdhttp.StatusFound)
	}))
	t.Cleanup(first.Close)
	roots := x509.NewCertPool()
	roots.AddCert(first.Certificate())
	roots.AddCert(secondParsed)
	firstAddress := netip.MustParseAddr("93.184.216.34")
	secondAddress := netip.MustParseAddr("1.1.1.1")
	dialer := &mappedDialer{destinations: map[netip.Addr]string{firstAddress: first.Listener.Addr().String(), secondAddress: second.Listener.Addr().String()}}
	collector := New(dialer.DialContext, policy.PublicDestinationPolicy(), 2<<20, WithTLSRootCAs(roots), WithRedirectResolver(func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{secondAddress}, nil
	}))
	result, err := collector.Collect(t.Context(), "https", "example.com", firstAddress)
	if err != nil {
		t.Fatal(err)
	}
	if len(dialer.Addresses()) != 2 || !slices.Equal(observationTypes(result.Observations), []string{"tls_certificate", "http_response", "tls_certificate", "http_response"}) {
		t.Fatalf("dials=%d observations=%v", len(dialer.Addresses()), observationTypes(result.Observations))
	}
	var firstTLS, secondTLS model.TLSCertificatePayload
	if err := json.Unmarshal(result.Observations[0].Payload, &firstTLS); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(result.Observations[2].Payload, &secondTLS); err != nil {
		t.Fatal(err)
	}
	if !firstTLS.Verified || !secondTLS.Verified || firstTLS.FingerprintSHA256 == secondTLS.FingerprintSHA256 || firstTLS.Hop != 0 || secondTLS.Hop != 1 || firstTLS.PeerAddress != firstAddress || secondTLS.PeerAddress != secondAddress || secondTLS.IssuerCommonName != "other.example" || !slices.Equal(secondTLS.IssuerOrganization, []string{"fixture issuer"}) || result.Observations[2].Scope != model.ScopeExternalRedirect {
		t.Fatalf("redirect TLS payloads = %#v %#v", firstTLS, secondTLS)
	}
}

func TestCollectRetainsTLSWhenHTTPBodyFails(t *testing.T) {
	server := httptest.NewTLSServer(stdhttp.HandlerFunc(func(writer stdhttp.ResponseWriter, _ *stdhttp.Request) {
		writer.Header().Set("Content-Length", "10")
		_, _ = writer.Write([]byte("abc"))
	}))
	t.Cleanup(server.Close)
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	address := netip.MustParseAddr("93.184.216.34")
	collector := New((&mappedDialer{destinations: map[netip.Addr]string{address: server.Listener.Addr().String()}}).DialContext, policy.PublicDestinationPolicy(), 2<<20, WithTLSRootCAs(roots))
	result, err := collector.Collect(t.Context(), "https", "example.com", address)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(observationTypes(result.Observations), []string{"tls_certificate", "http_response"}) || result.Coverage.Status != model.CoveragePartial {
		t.Fatalf("TLS evidence after body failure: observations=%v coverage=%#v", observationTypes(result.Observations), result.Coverage)
	}
}

func TestCollectDisclosesBoundedCertificateNames(t *testing.T) {
	now := time.Now()
	names := make([]string, 70)
	names[0] = "example.com"
	for index := 1; index < len(names); index++ {
		names[index] = fmt.Sprintf("name-%02d.example.com", index)
	}
	certificate, parsed := testTLSCertificate(t, names, now.Add(-time.Hour), now.Add(time.Hour))
	server := testTLSServer(t, certificate, stdhttp.HandlerFunc(func(writer stdhttp.ResponseWriter, _ *stdhttp.Request) {
		writer.WriteHeader(stdhttp.StatusNoContent)
	}))
	roots := x509.NewCertPool()
	roots.AddCert(parsed)
	address := netip.MustParseAddr("93.184.216.34")
	collector := New((&mappedDialer{destinations: map[netip.Addr]string{address: server.Listener.Addr().String()}}).DialContext, policy.PublicDestinationPolicy(), 2<<20, WithTLSRootCAs(roots))
	result, err := collector.Collect(t.Context(), "https", "example.com", address)
	if err != nil {
		t.Fatal(err)
	}
	var payload model.TLSCertificatePayload
	if err := json.Unmarshal(result.Observations[0].Payload, &payload); err != nil {
		t.Fatal(err)
	}
	if len(payload.DNSNames) != maximumTLSNames || payload.NamesOmitted != 6 || len(result.Observations[0].Payload) > 20<<10 {
		t.Fatalf("bounded TLS payload = names:%d omitted:%d bytes:%d", len(payload.DNSNames), payload.NamesOmitted, len(result.Observations[0].Payload))
	}
}
