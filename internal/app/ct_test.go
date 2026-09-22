package app_test

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"sync"
	"testing"
	"time"

	"cloudattrib/internal/app"
	collectdns "cloudattrib/internal/collect/dns"
	"cloudattrib/internal/ctlog"
	"cloudattrib/internal/model"
	"cloudattrib/internal/policy"
)

func TestCTDiscoverySeedsOrdinaryDNSAndRetainsHistoricalObservation(t *testing.T) {
	t.Parallel()

	index := ctlog.NewMemoryStore()
	passed := model.CTVerificationCheck{Status: model.CTCheckPassed, Procedure: "rfc6962-sha256", ProcedureVersion: "1"}
	loggedAt := time.Date(2026, 9, 19, 10, 0, 0, 0, time.UTC)
	if err := index.Import(context.Background(), []ctlog.Record{{
		Name: "api.example.com", CertificateHash: "fixture", LoggedAt: loggedAt, SourceID: "fixture", Provenance: ctlog.ProvenanceVerifiedLog,
		Verification: model.CTVerification{CheckpointSignature: passed, Continuity: passed, EntryInclusion: passed},
	}}); err != nil {
		t.Fatalf("Import() error = %v", err)
	}
	dnsClient := &recordingDNSClient{}
	service := app.NewService(app.Dependencies{
		DNS: collectdns.New(dnsClient.Query, policy.PublicDestinationPolicy()), CT: index, CTEnabled: true, CTMaximumSeed: 20,
		View: model.NewAttributionView("fixture-bundle", "fixture-public", nil, nil), Now: func() time.Time { return time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC) },
	})
	includeWWW := false
	report, err := service.Analyze(context.Background(), model.AnalyzeRequest{
		Target: "example.com", Kind: model.TargetDomain, Mode: model.ModeDNS, IncludeWWW: &includeWWW, CTDiscovery: true,
	})
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}
	if !dnsClient.queried("api.example.com") {
		t.Fatalf("DNS queries = %v, want CT candidate", dnsClient.names())
	}
	if !hasObservation(report.Observations, "ct_name", "api.example.com") || !hasObservation(report.Observations, "dns_address", "api.example.com") {
		t.Fatalf("observations do not contain CT seed and live DNS validation: %#v", report.Observations)
	}
	if len(report.Findings) != 0 {
		t.Fatalf("CT history alone created findings: %#v", report.Findings)
	}
	coverage, ok := findCoverage(report.Coverage, "ct_discovery")
	if !ok || coverage.Status != model.CoverageComplete || coverage.Completed != 1 {
		t.Fatalf("CT coverage = %#v", coverage)
	}
}

func TestCTDiscoveryReportsDisabledSeparately(t *testing.T) {
	t.Parallel()

	service := app.NewService(app.Dependencies{
		DNS: collectdns.New((&recordingDNSClient{}).Query, policy.PublicDestinationPolicy()), CT: panicCTReader{},
		View: model.NewAttributionView("fixture-bundle", "fixture-public", nil, nil), Now: time.Now,
	})
	includeWWW := false
	report, err := service.Analyze(context.Background(), model.AnalyzeRequest{
		Target: "example.com", Kind: model.TargetDomain, Mode: model.ModeDNS, IncludeWWW: &includeWWW, CTDiscovery: true,
	})
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}
	coverage, ok := findCoverage(report.Coverage, "ct_discovery")
	if !ok || coverage.Status != model.CoverageSkipped || coverage.Reason != "disabled" {
		t.Fatalf("CT coverage = %#v", coverage)
	}
}

func TestCTIndexOutageDoesNotDisableOrdinaryAnalysis(t *testing.T) {
	t.Parallel()

	service := app.NewService(app.Dependencies{
		DNS: collectdns.New((&recordingDNSClient{}).Query, policy.PublicDestinationPolicy()), CT: failingCTReader{}, CTEnabled: true,
		View: model.NewAttributionView("fixture-bundle", "fixture-public", nil, nil), Now: time.Now,
	})
	includeWWW := false
	report, err := service.Analyze(context.Background(), model.AnalyzeRequest{
		Target: "example.com", Kind: model.TargetDomain, Mode: model.ModeDNS, IncludeWWW: &includeWWW, CTDiscovery: true,
	})
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}
	coverage, ok := findCoverage(report.Coverage, "ct_discovery")
	if !ok || coverage.Status != model.CoverageUnavailable || !hasObservation(report.Observations, "dns_address", "example.com") {
		t.Fatalf("report did not preserve ordinary DNS through CT outage: %#v", report)
	}
}

func TestCTObservationIdentityIsPerCollectionOccurrence(t *testing.T) {
	t.Parallel()

	index := ctlog.NewMemoryStore()
	passed := model.CTVerificationCheck{Status: model.CTCheckPassed, Procedure: "rfc6962-sha256", ProcedureVersion: "1"}
	if err := index.Import(context.Background(), []ctlog.Record{{
		Name: "api.example.com", CertificateHash: "fixture", LoggedAt: time.Date(2026, 9, 19, 10, 0, 0, 0, time.UTC), SourceID: "fixture", Provenance: ctlog.ProvenanceVerifiedLog,
		Verification: model.CTVerification{CheckpointSignature: passed, Continuity: passed, EntryInclusion: passed},
	}}); err != nil {
		t.Fatal(err)
	}
	service := app.NewService(app.Dependencies{
		DNS: collectdns.New((&recordingDNSClient{}).Query, policy.PublicDestinationPolicy()), CT: index, CTEnabled: true, CTMaximumSeed: 20,
		View: model.NewAttributionView("fixture-bundle", "fixture-public", nil, nil), Now: time.Now,
	})
	includeWWW := false
	request := model.AnalyzeRequest{Target: "example.com", Kind: model.TargetDomain, Mode: model.ModeDNS, IncludeWWW: &includeWWW, CTDiscovery: true}
	first, err := service.Analyze(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	second, err := service.Analyze(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	firstCT := ctObservationByType(first.Observations, "ct_name")
	secondCT := ctObservationByType(second.Observations, "ct_name")
	if firstCT.ID == secondCT.ID {
		t.Fatalf("CT occurrence IDs are equal: %q", firstCT.ID)
	}
	if firstCT.ContentHash == "" || firstCT.ContentHash != secondCT.ContentHash {
		t.Fatalf("CT content hashes = %q and %q, want equal non-empty values", firstCT.ContentHash, secondCT.ContentHash)
	}
}

func TestCTDiscoveryReportsFullSeedBudget(t *testing.T) {
	t.Parallel()

	limits := policy.DefaultLimits()
	limits.SeedHostnames = 1
	service := app.NewService(app.Dependencies{
		DNS: collectdns.New((&recordingDNSClient{}).Query, policy.PublicDestinationPolicy()), CT: ctlog.NewMemoryStore(), CTEnabled: true, CTMaximumSeed: 1,
		View: model.NewAttributionView("fixture-bundle", "fixture-public", nil, nil), Limits: limits, Now: time.Now,
	})
	includeWWW := false
	report, err := service.Analyze(context.Background(), model.AnalyzeRequest{
		Target: "example.com", Kind: model.TargetDomain, Mode: model.ModeDNS, IncludeWWW: &includeWWW, CTDiscovery: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	coverage, ok := findCoverage(report.Coverage, "ct_discovery")
	if !ok || coverage.Status != model.CoveragePartial || coverage.Omitted == 0 || !slices.Contains(coverage.ErrorCodes, model.CodeBudgetExceeded) {
		t.Fatalf("CT coverage = %#v, want partial budget exhaustion with omitted work", coverage)
	}
}

type recordingDNSClient struct {
	mu           sync.Mutex
	queriedNames []string
}

type failingCTReader struct{}

func (failingCTReader) Discover(context.Context, string, int) (ctlog.QueryResult, error) {
	return ctlog.QueryResult{}, errors.New("fixture index outage")
}

type panicCTReader struct{}

func (panicCTReader) Discover(context.Context, string, int) (ctlog.QueryResult, error) {
	panic("disabled CT reader was called")
}

func (c *recordingDNSClient) Query(_ context.Context, question model.DNSQuestion) (model.DNSResult, error) {
	c.mu.Lock()
	c.queriedNames = append(c.queriedNames, question.Name)
	c.mu.Unlock()
	result := model.DNSResult{Question: question, ResponseCode: 0}
	if question.Type == 1 {
		result.Addresses = []netip.Addr{netip.MustParseAddr("93.184.216.34")}
	}
	return result, nil
}

func (c *recordingDNSClient) queried(name string) bool {
	return slices.Contains(c.names(), name)
}

func (c *recordingDNSClient) names() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Clone(c.queriedNames)
}

func hasObservation(observations []model.Observation, observationType, subject string) bool {
	for _, observation := range observations {
		if observation.Type == observationType && observation.Subject == subject {
			return true
		}
	}
	return false
}

func ctObservationByType(observations []model.Observation, observationType string) model.Observation {
	for _, observation := range observations {
		if observation.Type == observationType {
			return observation
		}
	}
	return model.Observation{}
}

func findCoverage(items []model.Coverage, capability string) (model.Coverage, bool) {
	for _, item := range items {
		if item.Capability == capability {
			return item, true
		}
	}
	return model.Coverage{}, false
}
