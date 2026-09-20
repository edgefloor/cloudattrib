package app_test

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"cloudattrib/internal/app"
	"cloudattrib/internal/cli"
	collectdns "cloudattrib/internal/collect/dns"
	collecthttp "cloudattrib/internal/collect/http"
	"cloudattrib/internal/detect/dnsrules"
	"cloudattrib/internal/enrich/prefix"
	"cloudattrib/internal/model"
	"cloudattrib/internal/policy"
)

func TestE1DomainAnalysisStartsHTTPBeforeAAAAAndKeepsPartialEvidence(t *testing.T) {
	t.Parallel()

	hostSeen := make(chan string, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		hostSeen <- request.Host
		w.Header().Set("Server", "fixture")
		_, _ = w.Write([]byte("fixture response"))
	}))
	t.Cleanup(server.Close)

	dialStarted := make(chan struct{})
	allowAAAA := make(chan struct{})
	dialer := &fixtureDialer{fixtureAddress: server.Listener.Addr().String(), started: dialStarted}
	dnsClient := fixtureDNSClient{allowAAAA: allowAAAA}

	prefixIndex := prefix.New([]model.Association{{
		ID:             "fixture-prefix",
		Prefix:         netip.MustParsePrefix("93.184.216.0/24"),
		ProviderID:     "example-cloud",
		ProductID:      "example.compute",
		Service:        "COMPUTE",
		Lifecycle:      "active",
		SourceID:       "fixture-ranges",
		SourceRevision: "fixture-v1",
		SourceDigest:   "sha256:fixture",
		RecordRef:      "fixture-ranges.json#/0",
		RecordRefs:     []string{"fixture-ranges.json#/0"},
	}})
	view := model.NewAttributionView(
		"fixture-bundle",
		"public-v1",
		[]string{"dnsrules-v1"},
		[]model.CapabilityState{
			{Name: "dns", Status: model.CoverageComplete},
			{Name: "http", Status: model.CoverageComplete},
			{Name: "prefix", Status: model.CoverageComplete},
		},
	)
	service := app.NewService(app.Dependencies{
		DNS:        collectdns.New(dnsClient.Query, policy.PublicDestinationPolicy()),
		HTTP:       collecthttp.New(dialer.DialContext, policy.PublicDestinationPolicy(), 2<<20),
		Detectors:  []app.Detector{dnsrules.NewDefault()},
		Prefixes:   prefixIndex,
		View:       view,
		HTTPScheme: "http",
		Now:        func() time.Time { return time.Date(2026, 9, 20, 8, 0, 0, 0, time.UTC) },
	})

	reportCh := make(chan model.Report, 1)
	errCh := make(chan error, 1)
	go func() {
		report, err := service.Analyze(t.Context(), model.AnalyzeRequest{
			Target: "example.com", Kind: model.TargetDomain, Mode: model.ModeFull,
		})
		reportCh <- report
		errCh <- err
	}()

	select {
	case <-dialStarted:
		close(allowAAAA)
	case <-time.After(2 * time.Second):
		t.Fatal("HTTP did not start before the delayed AAAA result")
	}

	report := <-reportCh
	if err := <-errCh; err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}
	if report.Status != model.StatusPartial {
		t.Fatalf("Analyze() status = %q, want partial", report.Status)
	}
	if err := report.ValidateReferences(); err != nil {
		t.Fatalf("ValidateReferences() error = %v", err)
	}
	if !hasProductRelation(report.Findings, "aws.cloudfront", model.RelationWebDelivery) {
		t.Fatalf("report findings do not contain CloudFront web delivery: %#v", report.Findings)
	}
	if !hasProductRelation(report.Findings, "example.compute", model.RelationServiceRange) {
		t.Fatalf("report findings do not contain fixture range: %#v", report.Findings)
	}
	if dialer.ProhibitedAttempts() != 0 {
		t.Fatalf("prohibited dial attempts = %d, want 0", dialer.ProhibitedAttempts())
	}
	if got := dialer.Selected(); got != netip.MustParseAddr("93.184.216.34") {
		t.Fatalf("selected dial address = %v", got)
	}
	if got := <-hostSeen; got != "example.com" {
		t.Fatalf("HTTP Host = %q, want example.com", got)
	}

	encoded, exit, err := cli.RenderReport(report)
	if err != nil {
		t.Fatalf("RenderReport() error = %v", err)
	}
	if exit != 3 {
		t.Fatalf("RenderReport() exit = %d, want 3", exit)
	}
	var decoded model.Report
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("rendered report is not JSON: %v", err)
	}
	for _, forbidden := range []string{"qualification", "spend_estimate", "savings_estimate", "hidden_origin"} {
		if strings.Contains(string(encoded), forbidden) {
			t.Fatalf("rendered report contains unsupported claim %q", forbidden)
		}
	}
}

func TestE1MissingPrefixSourcePreservesDNSAndHTTP(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	t.Cleanup(server.Close)

	dialer := &fixtureDialer{fixtureAddress: server.Listener.Addr().String(), started: make(chan struct{})}
	client := fixtureDNSClient{failedAAAA: true}
	view := model.NewAttributionView(
		"fixture-bundle-missing-prefix",
		"public-v1",
		[]string{"dnsrules-v1"},
		[]model.CapabilityState{{Name: "prefix", Status: model.CoverageUnavailable, Reason: "fixture source missing"}},
	)
	service := app.NewService(app.Dependencies{
		DNS:        collectdns.New(client.Query, policy.PublicDestinationPolicy()),
		HTTP:       collecthttp.New(dialer.DialContext, policy.PublicDestinationPolicy(), 2<<20),
		Detectors:  []app.Detector{dnsrules.NewDefault()},
		Prefixes:   unavailablePrefixReader{},
		View:       view,
		HTTPScheme: "http",
		Now:        time.Now,
	})

	report, err := service.Analyze(t.Context(), model.AnalyzeRequest{Target: "example.com", Kind: model.TargetDomain})
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}
	if report.Status != model.StatusPartial || !hasProductRelation(report.Findings, "aws.cloudfront", model.RelationWebDelivery) {
		t.Fatalf("Analyze() report = %#v", report)
	}
}

type fixtureDNSClient struct {
	allowAAAA  <-chan struct{}
	failedAAAA bool
}

func (c fixtureDNSClient) Query(ctx context.Context, question model.DNSQuestion) (model.DNSResult, error) {
	switch question.Type {
	case 1:
		return model.DNSResult{Question: question, ResponseCode: 0, Addresses: []netip.Addr{netip.MustParseAddr("93.184.216.34")}}, nil
	case 28:
		if c.failedAAAA {
			return model.DNSResult{Question: question}, errors.New("fixture AAAA timeout")
		}
		select {
		case <-ctx.Done():
			return model.DNSResult{Question: question}, ctx.Err()
		case <-c.allowAAAA:
			return model.DNSResult{Question: question, ResponseCode: 0, Addresses: []netip.Addr{netip.MustParseAddr("::1")}}, nil
		}
	case 5:
		payload, _ := json.Marshal(model.DNSPayload{RRType: "CNAME", Owner: question.Name, Value: "d111111abcdef8.cloudfront.net", TTL: 300})
		return model.DNSResult{Question: question, ResponseCode: 0, Records: []model.Observation{{ID: "dns-cname", Type: "dns_record", Subject: question.Name, Status: "answered", Payload: payload}}}, nil
	default:
		return model.DNSResult{Question: question, ResponseCode: 0}, nil
	}
}

type fixtureDialer struct {
	fixtureAddress string
	started        chan struct{}
	once           sync.Once
	mu             sync.Mutex
	selected       netip.Addr
	prohibited     int
}

func (d *fixtureDialer) DialContext(ctx context.Context, network string, address netip.Addr, _ uint16) (net.Conn, error) {
	d.mu.Lock()
	d.selected = address
	d.mu.Unlock()
	d.once.Do(func() { close(d.started) })
	var dialer net.Dialer
	return dialer.DialContext(ctx, network, d.fixtureAddress)
}

func (d *fixtureDialer) Selected() netip.Addr {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.selected
}

func (d *fixtureDialer) ProhibitedAttempts() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.prohibited
}

type unavailablePrefixReader struct{}

func (unavailablePrefixReader) LookupPrefixes(context.Context, model.IPLookupRequest, model.AttributionView) ([]model.Association, model.Coverage, error) {
	return nil, model.Coverage{Capability: "prefix", Status: model.CoverageUnavailable, ErrorCodes: []model.ErrorCode{model.CodeSourceUnavailable}}, nil
}

func hasProductRelation(findings []model.Finding, product string, relation model.Relation) bool {
	for _, finding := range findings {
		if finding.ProductID == product && finding.Relation == relation {
			return true
		}
	}
	return false
}
