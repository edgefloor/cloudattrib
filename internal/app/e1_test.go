package app_test

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"cloudattrib/internal/app"
	"cloudattrib/internal/cli"
	collectdns "cloudattrib/internal/collect/dns"
	collecthttp "cloudattrib/internal/collect/http"
	"cloudattrib/internal/datasets"
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

func TestE1HTTPFallsBackToSecondApprovedSeedAddress(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(server.Close)
	first := netip.MustParseAddr("93.184.216.34")
	second := netip.MustParseAddr("1.1.1.1")
	dialer := &addressFallbackDialer{working: second, destination: server.Listener.Addr().String()}
	dnsCollector := collectdns.New(func(_ context.Context, question model.DNSQuestion) (model.DNSResult, error) {
		result := model.DNSResult{Question: question, ResponseCode: 0}
		if question.Type == 1 {
			result.Addresses = []netip.Addr{first, second}
		}
		return result, nil
	}, policy.PublicDestinationPolicy())
	service := app.NewService(app.Dependencies{
		DNS: dnsCollector, HTTP: collecthttp.New(dialer.DialContext, policy.PublicDestinationPolicy(), 2<<20),
		View: model.NewAttributionView("fixture-bundle", "public-v1", nil, nil), HTTPScheme: "http", Now: time.Now,
	})
	includeWWW := false
	report, err := service.Analyze(t.Context(), model.AnalyzeRequest{Target: "example.com", Kind: model.TargetDomain, Mode: model.ModeFull, IncludeWWW: &includeWWW})
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}
	if got := dialer.Addresses(); !slices.Equal(got, []netip.Addr{first, second}) {
		t.Fatalf("dial addresses = %v", got)
	}
	if observationByType(report.Observations, "http_response").ID == "" {
		t.Fatalf("report has no HTTP response after fallback: %#v", report)
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

type addressFallbackDialer struct {
	mu          sync.Mutex
	working     netip.Addr
	destination string
	addresses   []netip.Addr
}

func (d *addressFallbackDialer) DialContext(ctx context.Context, network string, address netip.Addr, _ uint16) (net.Conn, error) {
	d.mu.Lock()
	d.addresses = append(d.addresses, address)
	d.mu.Unlock()
	if address != d.working {
		return nil, errors.New("fixture connection refused")
	}
	var dialer net.Dialer
	return dialer.DialContext(ctx, network, d.destination)
}

func (d *addressFallbackDialer) Addresses() []netip.Addr {
	d.mu.Lock()
	defer d.mu.Unlock()
	return slices.Clone(d.addresses)
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

func TestImportedCDNSuffixWorksInAnalysisAndReplay(t *testing.T) {
	directory := t.TempDir()
	data := []byte(`{"cdn":{"fixture-provider":["edge.fixture.test"]}}`)
	if err := os.WriteFile(filepath.Join(directory, "cdncheck-sources-data.json"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := datasets.LoadSources(t.Context(), directory, "build-a")
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Prefixes != nil {
		t.Fatal("suffix-only import created a prefix index")
	}
	for _, capability := range loaded.Candidate.View.Capabilities() {
		if capability.Name == "prefix_source/cdncheck-data" && capability.Status != model.CoverageUnavailable {
			t.Fatalf("suffix-only source advertises prefix availability: %#v", capability)
		}
	}
	query := func(_ context.Context, question model.DNSQuestion) (model.DNSResult, error) {
		result := model.DNSResult{Question: question, ResponseCode: 0}
		if question.Type == 5 {
			payload, err := json.Marshal(model.DNSPayload{RRType: "CNAME", Owner: question.Name, Value: "customer.edge.fixture.test"})
			if err != nil {
				return result, err
			}
			result.Records = []model.Observation{{ID: "fixture-cname", Type: "dns_record", Subject: question.Name, Status: "answered", Scope: model.ScopeRoot, Payload: payload}}
		}
		return result, nil
	}
	live := app.NewService(app.Dependencies{
		DNS:       collectdns.New(query, policy.PublicDestinationPolicy()),
		Detectors: []app.Detector{loaded.Suffixes}, View: loaded.Candidate.View,
	})
	includeWWW := false
	report, err := live.Analyze(t.Context(), model.AnalyzeRequest{Target: "example.com", Kind: model.TargetDomain, Mode: model.ModeDNS, IncludeWWW: &includeWWW})
	if err != nil {
		t.Fatal(err)
	}
	var liveEvidence model.Evidence
	for _, item := range report.Evidence {
		if item.ProviderID == "fixture-provider" && item.DetectorID == "cdn-suffix-v1" {
			liveEvidence = item
		}
	}
	if liveEvidence.ID == "" || liveEvidence.ProductID != "" || liveEvidence.DatasetRecords[0].RecordRef == "" {
		t.Fatalf("imported suffix evidence = %#v", report.Evidence)
	}
	if err := report.ValidateReferences(); err != nil {
		t.Fatalf("live report references: %v", err)
	}
	replay := app.NewService(app.Dependencies{Store: replayReportStore{report: report}, Detectors: []app.Detector{loaded.Suffixes}, View: loaded.Candidate.View})
	reclassified, err := replay.Reclassify(t.Context(), model.ReclassifyRequest{ReportID: report.ID, BundleID: loaded.Candidate.View.BundleID()})
	if err != nil {
		t.Fatal(err)
	}
	var replayEvidence model.Evidence
	for _, item := range reclassified.Evidence {
		if item.DetectorID == "cdn-suffix-v1" {
			replayEvidence = item
		}
	}
	if replayEvidence.ID != liveEvidence.ID || replayEvidence.ProviderID != liveEvidence.ProviderID || replayEvidence.Scope != liveEvidence.Scope {
		t.Fatalf("replay evidence = %#v, live = %#v", replayEvidence, liveEvidence)
	}
	if err := reclassified.ValidateReferences(); err != nil {
		t.Fatalf("replay report references: %v", err)
	}
}

func TestImportedCDNSuffixReplayPreservesRetainedObservationScopes(t *testing.T) {
	directory := t.TempDir()
	if err := os.WriteFile(filepath.Join(directory, "cdncheck-sources-data.json"),
		[]byte(`{"cdn":{"fixture-provider":["edge.fixture.test"]}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := datasets.LoadSources(t.Context(), directory, "build-a")
	if err != nil {
		t.Fatal(err)
	}
	observations := make([]model.Observation, 0, 4)
	want := map[string]model.Scope{
		"example.com":           model.ScopeRoot,
		"sub.example.com":       model.ScopeSubdomain,
		"dep.example.net":       model.ScopeDNSDependency,
		"landing.other.example": model.ScopeExternalRedirect,
	}
	for subject, scope := range want {
		payload, err := json.Marshal(model.DNSPayload{RRType: "CNAME", Owner: subject, Value: "host.edge.fixture.test"})
		if err != nil {
			t.Fatal(err)
		}
		observations = append(observations, model.Observation{
			ID: "cname-" + subject, Type: "dns_record", Subject: subject, Scope: scope, Status: "answered", Payload: payload,
		})
	}
	original := model.Report{ID: "retained-suffix-scopes", BundleID: loaded.Candidate.View.BundleID(),
		Target: model.Target{Canonical: "example.com", Kind: model.TargetDomain}, Observations: observations}
	service := app.NewService(app.Dependencies{Store: replayReportStore{report: original},
		Detectors: []app.Detector{loaded.Suffixes}, View: loaded.Candidate.View})
	replayed, err := service.Reclassify(t.Context(), model.ReclassifyRequest{ReportID: original.ID, BundleID: original.BundleID})
	if err != nil {
		t.Fatal(err)
	}
	seen := make(map[string]bool, len(want))
	for _, evidence := range replayed.Evidence {
		if evidence.DetectorID != "cdn-suffix-v1" {
			continue
		}
		scope, exists := want[evidence.Subject]
		if !exists || evidence.Scope != scope || evidence.ProviderID != "fixture-provider" ||
			len(evidence.ObservationIDs) != 1 || len(evidence.DatasetRecords) != 1 ||
			evidence.DatasetRecords[0].Revision == "" || evidence.DatasetRecords[0].Digest == "" || evidence.DatasetRecords[0].RecordRef == "" {
			t.Fatalf("replay lost suffix scope or provenance: %#v", evidence)
		}
		if seen[evidence.Subject] {
			t.Fatalf("duplicate suffix evidence for %q", evidence.Subject)
		}
		seen[evidence.Subject] = true
	}
	if len(seen) != len(want) {
		t.Fatalf("replay covered %d scopes, want %d: %#v", len(seen), len(want), replayed.Evidence)
	}
	for _, finding := range replayed.Findings {
		if finding.ProviderID != "fixture-provider" {
			continue
		}
		if scope, exists := want[finding.Subject]; !exists || finding.Scope != scope {
			t.Fatalf("replay promoted scoped suffix evidence: %#v", finding)
		}
	}
	if err := replayed.ValidateReferences(); err != nil {
		t.Fatalf("replay references: %v", err)
	}
}

func TestAnalyzePreservesDNSDependencyScope(t *testing.T) {
	query := func(_ context.Context, question model.DNSQuestion) (model.DNSResult, error) {
		result := model.DNSResult{Question: question, ResponseCode: 0}
		if question.Type == 15 {
			payload, err := json.Marshal(model.DNSPayload{RRType: "MX", Owner: question.Name, Value: "10 mx.example.net"})
			if err != nil {
				return result, err
			}
			result.Records = []model.Observation{{Type: "dns_record", Subject: "mx.example.net", Scope: model.ScopeMailDependency, Status: "answered", Payload: payload}}
		}
		return result, nil
	}
	service := app.NewService(app.Dependencies{DNS: collectdns.New(query, policy.PublicDestinationPolicy())})
	includeWWW := false
	report, err := service.Analyze(t.Context(), model.AnalyzeRequest{Target: "example.com", Kind: model.TargetDomain, Mode: model.ModeDNS, IncludeWWW: &includeWWW})
	if err != nil {
		t.Fatal(err)
	}
	for _, observation := range report.Observations {
		if observation.Type == "dns_record" {
			if observation.Scope != model.ScopeMailDependency {
				t.Fatalf("dependency scope = %q", observation.Scope)
			}
			return
		}
	}
	t.Fatal("missing dependency observation")
}

func TestAnalyzeAttributesInheritedNameserverAddressToDependency(t *testing.T) {
	query := func(_ context.Context, question model.DNSQuestion) (model.DNSResult, error) {
		result := model.DNSResult{Question: question, ResponseCode: 0}
		value, rrtype := "", ""
		switch {
		case question.Name == "example.com" && question.Type == 6:
			value, rrtype = "ns.example.com", "SOA"
		case question.Name == "example.com" && question.Type == 2:
			value, rrtype = "ns.example.com", "NS"
		case question.Name == "ns.example.com" && question.Type == 1:
			result.Addresses = []netip.Addr{netip.MustParseAddr("93.184.216.34")}
		}
		if rrtype != "" {
			payload, err := json.Marshal(model.DNSPayload{RRType: rrtype, Owner: question.Name, Value: value})
			if err != nil {
				return result, err
			}
			result.Records = []model.Observation{{Type: "dns_record", Subject: question.Name, Status: "answered", Payload: payload}}
		}
		return result, nil
	}
	prefixes := prefix.New([]model.Association{{
		ID: "dns-provider", Prefix: netip.MustParsePrefix("93.184.216.0/24"), ProviderID: "dns-provider",
		SourceID: "fixture", SourceRevision: "1", SourceDigest: "digest", RecordRef: "#/0", Lifecycle: "active",
	}})
	service := app.NewService(app.Dependencies{
		DNS: collectdns.New(query, policy.PublicDestinationPolicy()), Prefixes: prefixes,
		View: model.NewAttributionView("bundle", "policy", nil, []model.CapabilityState{{Name: "prefix", Status: model.CoverageComplete}}),
	})
	includeWWW := false
	report, err := service.Analyze(t.Context(), model.AnalyzeRequest{Target: "www.example.com", Kind: model.TargetDomain, Mode: model.ModeDNS, IncludeWWW: &includeWWW})
	if err != nil {
		t.Fatal(err)
	}
	var inherited, dependency bool
	for _, observation := range report.Observations {
		if observation.Type == "dns_record" && observation.Subject == "example.com" && observation.Scope == model.ScopeInheritedZone {
			inherited = true
		}
	}
	for _, evidence := range report.Evidence {
		if evidence.ProviderID == "dns-provider" && evidence.Subject == "ns.example.com" && evidence.Scope == model.ScopeDNSDependency {
			dependency = true
		}
		if evidence.ProviderID == "dns-provider" && evidence.Scope == model.ScopeRoot {
			t.Fatalf("nameserver address attributed to root: %#v", evidence)
		}
	}
	if !inherited || !dependency {
		t.Fatalf("inherited=%t dependency=%t report=%#v", inherited, dependency, report)
	}
	if err := report.ValidateReferences(); err != nil {
		t.Fatal(err)
	}
}

func TestAnalyzeDoesNotDialMailOrDNSDependencies(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(server.Close)
	seedAddress := netip.MustParseAddr("93.184.216.34")
	dependencyAddress := netip.MustParseAddr("1.1.1.1")
	dialer := &addressFallbackDialer{working: seedAddress, destination: server.Listener.Addr().String()}
	query := func(_ context.Context, question model.DNSQuestion) (model.DNSResult, error) {
		result := model.DNSResult{Question: question, ResponseCode: 0}
		if question.Name == "example.com" && question.Type == 1 {
			result.Addresses = []netip.Addr{seedAddress}
		}
		if question.Name == "mail.provider.test" && question.Type == 1 || question.Name == "ns.provider.test" && question.Type == 1 {
			result.Addresses = []netip.Addr{dependencyAddress}
		}
		value, rrtype := "", ""
		if question.Name == "example.com" && question.Type == 15 {
			value, rrtype = "10 mail.provider.test", "MX"
		}
		if question.Name == "example.com" && question.Type == 2 {
			value, rrtype = "ns.provider.test", "NS"
		}
		if rrtype != "" {
			payload, err := json.Marshal(model.DNSPayload{RRType: rrtype, Owner: question.Name, Value: value})
			if err != nil {
				return result, err
			}
			result.Records = []model.Observation{{Type: "dns_record", Subject: question.Name, Status: "answered", Payload: payload}}
		}
		return result, nil
	}
	service := app.NewService(app.Dependencies{
		DNS:  collectdns.New(query, policy.PublicDestinationPolicy()),
		HTTP: collecthttp.New(dialer.DialContext, policy.PublicDestinationPolicy(), 2<<20),
		View: model.NewAttributionView("bundle", "policy", nil, nil), HTTPScheme: "http",
	})
	includeWWW := false
	report, err := service.Analyze(t.Context(), model.AnalyzeRequest{Target: "example.com", Kind: model.TargetDomain, Mode: model.ModeFull, IncludeWWW: &includeWWW})
	if err != nil {
		t.Fatal(err)
	}
	if got := dialer.Addresses(); !slices.Equal(got, []netip.Addr{seedAddress}) {
		t.Fatalf("HTTP dialed dependency addresses: %v", got)
	}
	var mail, dns bool
	for _, observation := range report.Observations {
		if observation.Type != "dns_address" {
			continue
		}
		mail = mail || observation.Scope == model.ScopeMailDependency
		dns = dns || observation.Scope == model.ScopeDNSDependency
	}
	if !mail || !dns {
		t.Fatalf("dependency address observations missing: mail=%t dns=%t", mail, dns)
	}
}

func TestRedirectStartsHTTPBeforeOtherAddressFamilyFinishes(t *testing.T) {
	for _, fastType := range []uint16{1, 28} {
		t.Run(map[uint16]string{1: "A first", 28: "AAAA first"}[fastType], func(t *testing.T) {
			landingStarted := make(chan struct{}, 1)
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				if request.Host == "redirect.example" {
					landingStarted <- struct{}{}
					writer.WriteHeader(http.StatusNoContent)
					return
				}
				writer.Header().Set("Location", "http://redirect.example/landing")
				writer.WriteHeader(http.StatusFound)
			}))
			t.Cleanup(server.Close)
			allowSlow := make(chan struct{})
			address := netip.MustParseAddr("93.184.216.34")
			if fastType == 28 {
				address = netip.MustParseAddr("2606:2800:220:1:248:1893:25c8:1946")
			}
			collector := collectdns.New(func(ctx context.Context, question model.DNSQuestion) (model.DNSResult, error) {
				result := model.DNSResult{Question: question, Outcome: model.DNSOutcomeNoData}
				if question.Name == "example.com" && question.Type == 1 {
					result.Outcome = model.DNSOutcomeAnswered
					result.Addresses = []netip.Addr{netip.MustParseAddr("93.184.216.34")}
				}
				if question.Name == "redirect.example" && (question.Type == 1 || question.Type == 28) {
					if question.Type == fastType {
						result.Outcome = model.DNSOutcomeAnswered
						result.Addresses = []netip.Addr{address}
					} else {
						select {
						case <-allowSlow:
							result.Outcome = model.DNSOutcomeTimeout
						case <-ctx.Done():
							return result, ctx.Err()
						}
					}
				}
				return result, nil
			}, policy.PublicDestinationPolicy())
			dialer := &fixtureDialer{fixtureAddress: server.Listener.Addr().String(), started: make(chan struct{})}
			service := app.NewService(app.Dependencies{
				DNS: collector, HTTP: collecthttp.New(dialer.DialContext, policy.PublicDestinationPolicy(), 2<<20),
				View: model.NewAttributionView("fixture-bundle", "public-v1", nil, nil), HTTPScheme: "http", Now: time.Now,
			})
			type outcome struct {
				report model.Report
				err    error
			}
			finished := make(chan outcome, 1)
			go func() {
				includeWWW := false
				report, err := service.Analyze(t.Context(), model.AnalyzeRequest{Target: "example.com", Kind: model.TargetDomain, Mode: model.ModeFull, IncludeWWW: &includeWWW})
				finished <- outcome{report: report, err: err}
			}()
			select {
			case <-landingStarted:
			case <-time.After(2 * time.Second):
				t.Fatal("redirect HTTP did not start before the other address family finished")
			}
			close(allowSlow)
			completed := <-finished
			if completed.err != nil {
				t.Fatal(completed.err)
			}
			var landing, partialHTTP, failedFamilyRetained bool
			for _, observation := range completed.report.Observations {
				landing = landing || observation.Type == "http_response" && observation.Subject == "redirect.example"
				if observation.Type == "dns_query" && observation.Subject == "redirect.example" && observation.Status == string(model.DNSOutcomeTimeout) && observation.Scope == model.ScopeExternalRedirect {
					var payload model.DNSPayload
					if err := json.Unmarshal(observation.Payload, &payload); err != nil {
						t.Fatal(err)
					}
					failedFamilyRetained = payload.RRType == map[uint16]string{1: "AAAA", 28: "A"}[fastType]
				}
			}
			for _, coverage := range completed.report.Coverage {
				partialHTTP = partialHTTP || coverage.Capability == "http" && coverage.Status == model.CoveragePartial
			}
			if !landing || !partialHTTP || !failedFamilyRetained {
				t.Fatalf("landing response = %t, partial HTTP coverage = %t, failed family retained = %t", landing, partialHTTP, failedFamilyRetained)
			}
		})
	}
}

func TestSameHostRedirectPathsReuseDNSQuestionsWithinAnalysis(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.Host + request.URL.Path {
		case "example.com/":
			writer.Header().Set("Location", "http://redirect.example/one")
			writer.WriteHeader(http.StatusFound)
		case "redirect.example/one":
			writer.Header().Set("Location", "/two")
			writer.WriteHeader(http.StatusFound)
		default:
			writer.WriteHeader(http.StatusNoContent)
		}
	}))
	t.Cleanup(server.Close)
	var mu sync.Mutex
	calls := make(map[uint16]int)
	address := netip.MustParseAddr("93.184.216.34")
	collector := collectdns.New(func(_ context.Context, question model.DNSQuestion) (model.DNSResult, error) {
		result := model.DNSResult{Question: question, Outcome: model.DNSOutcomeNoData}
		if question.Name == "example.com" && question.Type == 1 {
			result.Outcome = model.DNSOutcomeAnswered
			result.Addresses = []netip.Addr{address}
		}
		if question.Name == "redirect.example" && (question.Type == 1 || question.Type == 28) {
			mu.Lock()
			calls[question.Type]++
			mu.Unlock()
			if question.Type == 1 {
				result.Outcome = model.DNSOutcomeAnswered
				result.Addresses = []netip.Addr{address}
				payload, _ := json.Marshal(model.DNSPayload{RRType: "A", Owner: question.Name, Address: address, TTL: 300})
				result.Records = []model.Observation{{Type: "dns_record", Subject: question.Name, Status: "answered", Payload: payload}}
			} else {
				result.NegativeTTL = 300
			}
		}
		return result, nil
	}, policy.PublicDestinationPolicy())
	dialer := &fixtureDialer{fixtureAddress: server.Listener.Addr().String(), started: make(chan struct{})}
	service := app.NewService(app.Dependencies{
		DNS: collector, HTTP: collecthttp.New(dialer.DialContext, policy.PublicDestinationPolicy(), 2<<20),
		View: model.NewAttributionView("fixture-bundle", "public-v1", nil, nil), HTTPScheme: "http", Now: time.Now,
	})
	includeWWW := false
	report, err := service.Analyze(t.Context(), model.AnalyzeRequest{Target: "example.com", Kind: model.TargetDomain, Mode: model.ModeFull, IncludeWWW: &includeWWW})
	if err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if calls[1] != 1 || calls[28] != 1 {
		t.Fatalf("redirect DNS calls = %#v", calls)
	}
	var responses int
	for _, observation := range report.Observations {
		if observation.Type == "http_response" {
			responses++
		}
	}
	if responses != 3 {
		t.Fatalf("HTTP response count = %d, want 3", responses)
	}
	var redirectAQueries []model.Observation
	for _, observation := range report.Observations {
		if observation.Type != "dns_query" || observation.Subject != "redirect.example" {
			continue
		}
		var payload model.DNSPayload
		if err := json.Unmarshal(observation.Payload, &payload); err != nil {
			t.Fatal(err)
		}
		if payload.RRType == "A" {
			redirectAQueries = append(redirectAQueries, observation)
		}
	}
	if len(redirectAQueries) != 2 || redirectAQueries[0].ID == redirectAQueries[1].ID || !redirectAQueries[0].ObservedAt.Equal(redirectAQueries[1].ObservedAt) {
		t.Fatalf("cached redirect query observations = %#v", redirectAQueries)
	}
	if err := report.ValidateReferences(); err != nil {
		t.Fatal(err)
	}
}

func TestRedirectCancellationJoinsOutstandingDNSFamily(t *testing.T) {
	landingStarted := make(chan struct{}, 1)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Host == "redirect.example" {
			writer.WriteHeader(http.StatusNoContent)
			landingStarted <- struct{}{}
			return
		}
		writer.Header().Set("Location", "http://redirect.example/")
		writer.WriteHeader(http.StatusFound)
	}))
	t.Cleanup(server.Close)
	slowDone := make(chan struct{})
	address := netip.MustParseAddr("93.184.216.34")
	collector := collectdns.New(func(ctx context.Context, question model.DNSQuestion) (model.DNSResult, error) {
		result := model.DNSResult{Question: question, Outcome: model.DNSOutcomeNoData}
		if question.Type == 1 && (question.Name == "example.com" || question.Name == "redirect.example") {
			result.Outcome = model.DNSOutcomeAnswered
			result.Addresses = []netip.Addr{address}
		}
		if question.Name == "redirect.example" && question.Type == 28 {
			<-ctx.Done()
			close(slowDone)
			return model.DNSResult{Question: question, Outcome: model.DNSOutcomeCancelled}, ctx.Err()
		}
		return result, nil
	}, policy.PublicDestinationPolicy())
	dialer := &fixtureDialer{fixtureAddress: server.Listener.Addr().String(), started: make(chan struct{})}
	service := app.NewService(app.Dependencies{
		DNS: collector, HTTP: collecthttp.New(dialer.DialContext, policy.PublicDestinationPolicy(), 2<<20),
		View: model.NewAttributionView("fixture-bundle", "public-v1", nil, nil), HTTPScheme: "http", Now: time.Now,
	})
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	type outcome struct {
		report model.Report
		err    error
	}
	finished := make(chan outcome, 1)
	go func() {
		includeWWW := false
		report, err := service.Analyze(ctx, model.AnalyzeRequest{Target: "example.com", Kind: model.TargetDomain, Mode: model.ModeFull, IncludeWWW: &includeWWW})
		finished <- outcome{report: report, err: err}
	}()
	select {
	case <-landingStarted:
		cancel()
	case <-time.After(2 * time.Second):
		t.Fatal("landing request did not start")
	}
	completed := <-finished
	select {
	case <-slowDone:
	default:
		t.Fatal("analysis returned before outstanding redirect DNS query stopped")
	}
	if completed.err != nil {
		t.Fatal(completed.err)
	}
	var completedHop, cancelledDNS bool
	for _, observation := range completed.report.Observations {
		completedHop = completedHop || observation.Type == "http_response" && observation.Subject == "example.com"
		cancelledDNS = cancelledDNS || observation.Type == "dns_query" && observation.Subject == "redirect.example" && observation.Status == string(model.DNSOutcomeCancelled)
	}
	if !completedHop || !cancelledDNS {
		t.Fatalf("completed hop retained = %t, DNS cancellation retained = %t", completedHop, cancelledDNS)
	}
}

func TestRedirectUsesSharedDNSQuestionBudgetAndRetainsPriorHop(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Location", "http://redirect.example/")
		writer.WriteHeader(http.StatusFound)
	}))
	t.Cleanup(server.Close)
	address := netip.MustParseAddr("93.184.216.34")
	limits := policy.DefaultLimits()
	limits.DNSQuestions = 6
	collector := collectdns.New(func(_ context.Context, question model.DNSQuestion) (model.DNSResult, error) {
		result := model.DNSResult{Question: question, Outcome: model.DNSOutcomeNoData}
		if question.Name == "example.com" && question.Type == 1 {
			result.Outcome = model.DNSOutcomeAnswered
			result.Addresses = []netip.Addr{address}
		}
		if question.Name == "example.com" && question.Type == 2 {
			payload, _ := json.Marshal(model.DNSPayload{RRType: "NS", Owner: question.Name, Value: "ns.example.net"})
			result.Outcome = model.DNSOutcomeAnswered
			result.Records = []model.Observation{{Type: "dns_record", Subject: question.Name, Status: "answered", Payload: payload}}
		}
		return result, nil
	}, policy.PublicDestinationPolicy()).WithLimits(limits)
	dialer := &fixtureDialer{fixtureAddress: server.Listener.Addr().String(), started: make(chan struct{})}
	service := app.NewService(app.Dependencies{
		DNS: collector, HTTP: collecthttp.New(dialer.DialContext, policy.PublicDestinationPolicy(), 2<<20),
		View: model.NewAttributionView("fixture-bundle", "public-v1", nil, nil), HTTPScheme: "http", Now: time.Now,
	})
	includeWWW := false
	report, err := service.Analyze(t.Context(), model.AnalyzeRequest{Target: "example.com", Kind: model.TargetDomain, Mode: model.ModeFull, IncludeWWW: &includeWWW})
	if err != nil {
		t.Fatal(err)
	}
	var completedHop, exhaustedRedirect, landing bool
	for _, observation := range report.Observations {
		completedHop = completedHop || observation.Type == "http_response" && observation.Subject == "example.com"
		exhaustedRedirect = exhaustedRedirect || observation.Type == "dns_query" && observation.Subject == "redirect.example" && observation.Status == string(model.DNSOutcomeBudgetExhausted)
		landing = landing || observation.Type == "http_response" && observation.Subject == "redirect.example"
	}
	if !completedHop || !exhaustedRedirect || landing {
		t.Fatalf("completed hop = %t, budget outcome = %t, landing = %t", completedHop, exhaustedRedirect, landing)
	}
}

func TestAnalysisAndLookupCalculateSourceAgeAtUseTime(t *testing.T) {
	published := time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC)
	clock := published.Add(24 * time.Hour)
	view := model.NewAttributionView("bundle", "policy", nil, []model.CapabilityState{{
		Name: "prefix_source/aws-ip-ranges", Status: model.CoverageComplete, PublishedAt: &published,
	}})
	service := app.NewService(app.Dependencies{
		DNS:      collectdns.New(fixtureDNSClient{failedAAAA: true}.Query, policy.PublicDestinationPolicy()),
		Prefixes: prefix.New(nil), View: view, Now: func() time.Time { return clock },
	})
	ageFor := func(coverage []model.Coverage) int64 {
		for _, item := range coverage {
			if item.Capability == "prefix_source/aws-ip-ranges" && item.DataAgeSeconds != nil {
				return *item.DataAgeSeconds
			}
		}
		t.Fatal("source age missing from coverage")
		return -1
	}
	includeWWW := false
	request := model.AnalyzeRequest{Target: "example.com", Kind: model.TargetDomain, Mode: model.ModeDNS, IncludeWWW: &includeWWW}
	first, err := service.Analyze(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}
	clock = clock.Add(48 * time.Hour)
	second, err := service.Analyze(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}
	lookup, err := service.LookupIP(t.Context(), model.IPLookupRequest{Address: netip.MustParseAddr("93.184.216.34")})
	if err != nil {
		t.Fatal(err)
	}
	if ageFor(first.Coverage) != 86400 || ageFor(second.Coverage) != 259200 || ageFor(lookup.Coverage) != 259200 {
		t.Fatalf("ages: first=%d second=%d lookup=%d", ageFor(first.Coverage), ageFor(second.Coverage), ageFor(lookup.Coverage))
	}
	if ageFor(first.Coverage) != 86400 {
		t.Fatal("later classification changed historical report age")
	}
}
