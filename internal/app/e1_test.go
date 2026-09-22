package app_test

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
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
		DNS:       collectdns.New(dnsClient.Query, policy.PublicDestinationPolicy()),
		HTTP:      collecthttp.New(dialer.DialContext, policy.PublicDestinationPolicy(), 2<<20),
		Detectors: []app.Detector{dnsrules.NewDefault()},
		Prefixes:  prefixIndex,
		View:      view,
		BuildProvenance: model.BuildProvenance{
			Revision: model.KnownProvenance("0123456789abcdef"), Dirty: model.BuildClean,
		},
		RulesDigest:       model.KnownProvenance("sha256:fixture-rules"),
		FingerprintDigest: model.KnownProvenance("sha256:fixture-fingerprints"),
		HTTPScheme:        "http",
		Now:               func() time.Time { return time.Date(2026, 9, 20, 8, 0, 0, 0, time.UTC) },
	})

	reportCh := make(chan model.Report, 1)
	errCh := make(chan error, 1)
	go func() {
		includeWWW := false
		report, err := service.Analyze(t.Context(), model.AnalyzeRequest{
			Target: "example.com", Kind: model.TargetDomain, Mode: model.ModeFull, IncludeWWW: &includeWWW,
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
	if report.Provenance == nil || report.BuildID != "git:0123456789abcdef" {
		t.Fatalf("report build provenance = %#v, build ID = %q", report.Provenance, report.BuildID)
	}
	if report.Provenance.Collection.PolicyRevision.Value != "public-v1" || report.Provenance.Collection.FingerprintDigest.Value != "sha256:fixture-fingerprints" || report.Provenance.Classification.RulesDigest.Value != "sha256:fixture-rules" {
		t.Fatalf("report classifier provenance = %#v", report.Provenance)
	}
	if !hasCoverage(report.Coverage, "tls_certificate", model.CoverageSkipped) {
		t.Fatalf("TLS coverage = %#v, want skipped for plain HTTP", report.Coverage)
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
	httpLinked := false
	for _, item := range report.Evidence {
		if item.DetectorID != "prefix-v1" {
			continue
		}
		for _, observationID := range item.ObservationIDs {
			httpLinked = httpLinked || strings.HasPrefix(observationID, "http-response-")
		}
	}
	if !httpLinked {
		t.Fatalf("prefix evidence did not retain HTTP peer provenance: %#v", report.Evidence)
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

func hasCoverage(coverage []model.Coverage, capability string, status model.CoverageStatus) bool {
	for _, item := range coverage {
		if item.Capability == capability && item.Status == status {
			return true
		}
	}
	return false
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

	includeWWW := false
	report, err := service.Analyze(t.Context(), model.AnalyzeRequest{Target: "example.com", Kind: model.TargetDomain, IncludeWWW: &includeWWW})
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}
	if report.Status != model.StatusPartial || !hasProductRelation(report.Findings, "aws.cloudfront", model.RelationWebDelivery) {
		t.Fatalf("Analyze() report = %#v", report)
	}
}

func TestE1ConvergingSeedsRetainBothObservationHistories(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Host != "landing.example" {
			writer.Header().Set("Location", "http://landing.example/shared")
			writer.WriteHeader(http.StatusFound)
			return
		}
		writer.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(server.Close)

	address := netip.MustParseAddr("93.184.216.34")
	dialer := &fixtureDialer{fixtureAddress: server.Listener.Addr().String(), started: make(chan struct{})}
	collector := collecthttp.New(
		dialer.DialContext,
		policy.PublicDestinationPolicy(),
		2<<20,
		collecthttp.WithRedirectResolver(func(context.Context, string) ([]netip.Addr, error) {
			return []netip.Addr{address}, nil
		}),
	)
	service := app.NewService(app.Dependencies{
		DNS:        collectdns.New(fixtureDNSClient{failedAAAA: true}.Query, policy.PublicDestinationPolicy()),
		HTTP:       collector,
		Detectors:  []app.Detector{dnsrules.NewDefault()},
		View:       model.NewAttributionView("fixture-bundle", "public-v1", []string{"dnsrules-v1"}, nil),
		HTTPScheme: "http",
		Now:        func() time.Time { return time.Date(2026, 9, 22, 8, 0, 0, 0, time.UTC) },
	})

	report, err := service.Analyze(t.Context(), model.AnalyzeRequest{Target: "example.com", Kind: model.TargetDomain, Mode: model.ModeFull})
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}
	if err := report.ValidateReferences(); err != nil {
		t.Fatalf("ValidateReferences() error = %v", err)
	}
	if report.ContentIDVersion != model.ReportContentIDVersion {
		t.Fatalf("content ID version = %q, want %q", report.ContentIDVersion, model.ReportContentIDVersion)
	}
	recomputedID, err := report.ContentID()
	if err != nil {
		t.Fatalf("ContentID() after assignment error = %v", err)
	}
	if recomputedID != report.ID {
		t.Fatalf("ContentID() after assignment = %q, want %q", recomputedID, report.ID)
	}
	seen := make(map[string]struct{}, len(report.Observations))
	landingResponses := 0
	for _, observation := range report.Observations {
		if _, duplicate := seen[observation.ID]; duplicate {
			t.Fatalf("duplicate observation ID %q in converging seed report", observation.ID)
		}
		seen[observation.ID] = struct{}{}
		if observation.Type == "http_response" && observation.Subject == "landing.example" {
			landingResponses++
		}
	}
	if landingResponses != 2 {
		t.Fatalf("landing response observations = %d, want 2", landingResponses)
	}
}

func TestTechnologyFingerprintUsesSameRetainedInputLiveAndReplay(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("X-Powered-By", "fixture")
		_, _ = writer.Write([]byte("fixture response"))
	}))
	t.Cleanup(server.Close)

	dialer := &fixtureDialer{fixtureAddress: server.Listener.Addr().String(), started: make(chan struct{})}
	view := model.NewAttributionView("fixture-bundle", "public-v1", []string{"dnsrules-v1"}, nil)
	classifiedAt := time.Date(2026, 9, 22, 10, 0, 0, 0, time.UTC)
	live := app.NewService(app.Dependencies{
		DNS:         collectdns.New(fixtureDNSClient{failedAAAA: true}.Query, policy.PublicDestinationPolicy()),
		HTTP:        collecthttp.New(dialer.DialContext, policy.PublicDestinationPolicy(), 2<<20),
		Detectors:   []app.Detector{dnsrules.NewDefault()},
		WebDetector: fixtureTechnologyDetector{},
		View:        view,
		HTTPScheme:  "http",
		Now:         func() time.Time { return classifiedAt },
	})
	includeWWW := false
	report, err := live.Analyze(t.Context(), model.AnalyzeRequest{Target: "example.com", Kind: model.TargetDomain, Mode: model.ModeFull, IncludeWWW: &includeWWW})
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}
	technology := observationByType(report.Observations, "technology")
	if technology.ID == "" || technology.CollectorVersion != "fixture-fingerprint-v1" {
		t.Fatalf("live technology observation = %#v", technology)
	}
	var payload model.TechnologyPayload
	if err := json.Unmarshal(technology.Payload, &payload); err != nil {
		t.Fatalf("decode technology payload: %v", err)
	}
	if payload.Name != "React" || payload.DetectorID != "fixture-fingerprint-v1" || payload.ExplanationGranularity != model.ExplanationGranularityDetectorResult {
		t.Fatalf("technology payload = %#v", payload)
	}
	liveEvidence := evidenceForProduct(report.Evidence, "webtech.react")
	if liveEvidence.ID == "" || len(liveEvidence.ObservationIDs) != 1 || liveEvidence.ObservationIDs[0] != technology.ID {
		t.Fatalf("live React evidence = %#v", liveEvidence)
	}

	replay := app.NewService(app.Dependencies{
		Detectors:   []app.Detector{dnsrules.NewDefault()},
		WebDetector: panicTechnologyDetector{},
		Store:       replayReportStore{report: report},
		View:        view,
		Now:         func() time.Time { return classifiedAt.Add(time.Hour) },
	})
	reclassified, err := replay.Reclassify(t.Context(), model.ReclassifyRequest{ReportID: report.ID, BundleID: view.BundleID()})
	if err != nil {
		t.Fatalf("Reclassify() error = %v", err)
	}
	replayedTechnology := observationByType(reclassified.Observations, "technology")
	if replayedTechnology.ID != technology.ID || !replayedTechnology.ObservedAt.Equal(technology.ObservedAt) || string(replayedTechnology.Payload) != string(technology.Payload) {
		t.Fatalf("replayed technology observation = %#v, want %#v", replayedTechnology, technology)
	}
	replayedEvidence := evidenceForProduct(reclassified.Evidence, "webtech.react")
	if replayedEvidence.ProductID != liveEvidence.ProductID || replayedEvidence.ProviderID != liveEvidence.ProviderID || replayedEvidence.Relation != liveEvidence.Relation || replayedEvidence.Scope != liveEvidence.Scope || !slices.Equal(replayedEvidence.ObservationIDs, liveEvidence.ObservationIDs) {
		t.Fatalf("replayed React evidence = %#v, live = %#v", replayedEvidence, liveEvidence)
	}
}

type fixtureTechnologyDetector struct{}

func (fixtureTechnologyDetector) Detect(context.Context, http.Header, []byte) ([]model.TechnologyDetection, model.Coverage) {
	return []model.TechnologyDetection{{Name: "React", DetectorID: "fixture-fingerprint-v1", ExplanationGranularity: model.ExplanationGranularityDetectorResult}}, model.Coverage{Capability: "webtech", Status: model.CoverageComplete, Attempted: 1, Completed: 1}
}

type panicTechnologyDetector struct{}

func (panicTechnologyDetector) Detect(context.Context, http.Header, []byte) ([]model.TechnologyDetection, model.Coverage) {
	panic("reclassification must not run passive fingerprint collection")
}

type replayReportStore struct{ report model.Report }

func (store replayReportStore) SaveReport(context.Context, model.Report) error { return nil }
func (store replayReportStore) LoadReport(context.Context, string) (model.Report, error) {
	return store.report, nil
}

func observationByType(observations []model.Observation, observationType string) model.Observation {
	for _, observation := range observations {
		if observation.Type == observationType {
			return observation
		}
	}
	return model.Observation{}
}

func evidenceForProduct(evidence []model.Evidence, productID string) model.Evidence {
	for _, item := range evidence {
		if item.ProductID == productID {
			return item
		}
	}
	return model.Evidence{}
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
