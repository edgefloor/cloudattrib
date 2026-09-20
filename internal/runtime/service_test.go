package runtime

import (
	"context"
	"io"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"cloudattrib/internal/api"
	"cloudattrib/internal/app"
	"cloudattrib/internal/config"
	"cloudattrib/internal/datasets"
	"cloudattrib/internal/model"
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

func TestCheckedInCTCollectorYAMLLoads(t *testing.T) {
	t.Parallel()

	configuration, err := loadCTCollectorFile(filepath.Join("..", "..", "config", "ct-logs.example.yaml"))
	if err != nil {
		t.Fatalf("loadCTCollectorFile() error = %v", err)
	}
	if configuration.Protocol != "rfc6962" || configuration.StartIndex == nil || configuration.Budget.MaximumEntries != 256 {
		t.Fatalf("collector configuration = %#v", configuration)
	}
}

func TestNewAnalyzerLoadsOfflinePrefixAndASNData(t *testing.T) {
	t.Parallel()

	configuration := config.Default()
	configuration.Data.SourceDirectory = runtimeFixtureSources(t, "runtime-source")
	configuration.Data.BundleDirectory = filepath.Join(t.TempDir(), "bundles")
	analyzer, bundleID, _, lookup, err := newAnalyzerDetails(t.Context(), configuration, standaloneReportStore{})
	if err != nil {
		t.Fatalf("newAnalyzerDetails() error = %v", err)
	}
	result, err := analyzer.LookupIP(context.Background(), model.IPLookupRequest{Address: netip.MustParseAddr("192.0.2.1"), Match: "all"})
	if err != nil {
		t.Fatalf("LookupIP() error = %v", err)
	}
	if !lookup.complete() || !strings.HasPrefix(bundleID, "bundle-sha256-") || len(result.Associations) == 0 || len(result.ASN) == 0 {
		t.Fatalf("LookupIP() bundle = %q, result = %#v", bundleID, result)
	}
}

func TestNewAnalyzerTreatsMissingASNAsDegradedNotAvailable(t *testing.T) {
	t.Parallel()

	sources := t.TempDir()
	data, err := os.ReadFile(filepath.Join("..", "..", "testdata", "upstream", "aws-ip-ranges.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sources, "aws-ip-ranges.json"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	configuration := config.Default()
	configuration.Data.SourceDirectory = sources
	configuration.Data.BundleDirectory = filepath.Join(t.TempDir(), "bundles")
	analyzer, _, _, lookup, err := newAnalyzerDetails(t.Context(), configuration, standaloneReportStore{})
	if err != nil {
		t.Fatalf("newAnalyzerDetails() error = %v", err)
	}
	if !lookup.usable() || lookup.complete() || !lookup.prefix || lookup.asn {
		t.Fatalf("lookup availability = %#v", lookup)
	}
	result, err := analyzer.LookupIP(context.Background(), model.IPLookupRequest{Address: netip.MustParseAddr("192.0.2.1"), Match: "all"})
	if err != nil {
		t.Fatalf("LookupIP() error = %v", err)
	}
	if result.Status != model.StatusPartial || len(result.Associations) == 0 || len(result.ASN) != 0 {
		t.Fatalf("LookupIP() = %#v", result)
	}
}

func TestLookupIPIsPartialWhenConfiguredProviderFeedsAreMissing(t *testing.T) {
	t.Parallel()

	sources := runtimeFixtureSources(t, "missing-provider-feeds")
	for _, name := range []string{"gcp-cloud.json", "azure-service-tags.json", "cdncheck-sources-data.json"} {
		if err := os.Remove(filepath.Join(sources, name)); err != nil {
			t.Fatal(err)
		}
	}
	configuration := config.Default()
	configuration.Data.SourceDirectory = sources
	configuration.Data.BundleDirectory = filepath.Join(t.TempDir(), "bundles")
	analyzer, _, _, lookup, err := newAnalyzerDetails(t.Context(), configuration, standaloneReportStore{})
	if err != nil {
		t.Fatalf("newAnalyzerDetails() error = %v", err)
	}
	if lookup.complete() {
		t.Fatalf("lookup availability = %#v, want degraded", lookup)
	}
	result, err := analyzer.LookupIP(t.Context(), model.IPLookupRequest{Address: netip.MustParseAddr("8.8.8.8"), Match: "all"})
	if err != nil {
		t.Fatalf("LookupIP() error = %v", err)
	}
	if result.Status != model.StatusPartial {
		t.Fatalf("LookupIP() status = %q, coverage = %#v", result.Status, result.Coverage)
	}
}

func TestLookupIPRejectsAddressFamilyWithNoUsableSource(t *testing.T) {
	t.Parallel()

	sources := t.TempDir()
	data, err := os.ReadFile(filepath.Join("..", "..", "testdata", "upstream", "iptoasn-v6.tsv"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sources, "iptoasn-v6.tsv"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	configuration := config.Default()
	configuration.Data.SourceDirectory = sources
	configuration.Data.BundleDirectory = filepath.Join(t.TempDir(), "bundles")
	analyzer, _, _, _, err := newAnalyzerDetails(t.Context(), configuration, standaloneReportStore{})
	if err != nil {
		t.Fatal(err)
	}
	_, err = analyzer.LookupIP(t.Context(), model.IPLookupRequest{Address: netip.MustParseAddr("8.8.8.8"), Match: "all"})
	if model.ErrorCodeOf(err) != model.CodeCapabilityUnavailable {
		t.Fatalf("LookupIP() error = %v, want capability_unavailable", err)
	}
}

func TestBundleAnalyzerFactoryReloadsDesiredAndRetainsPinnedBundle(t *testing.T) {
	t.Parallel()

	configuration := config.Default()
	configuration.Data.BundleDirectory = filepath.Join(t.TempDir(), "bundles")
	configuration.Data.SourceDirectory = filepath.Join(t.TempDir(), "absent")
	repository, err := datasets.NewRepository(configuration.Data.BundleDirectory, detectorBuildID)
	if err != nil {
		t.Fatalf("NewRepository() error = %v", err)
	}
	first, err := repository.Import(context.Background(), runtimeFixtureSources(t, "runtime-first"))
	if err != nil {
		t.Fatalf("Import(first) error = %v", err)
	}
	if _, err := repository.Activate(context.Background(), first.CandidateID, first.CandidateHash, "activate"); err != nil {
		t.Fatalf("Activate(first) error = %v", err)
	}
	store := standaloneReportStore{}
	analyzer, bundleID, _, lookup, err := newAnalyzerDetails(t.Context(), configuration, store)
	if err != nil {
		t.Fatalf("newAnalyzerDetails() error = %v", err)
	}
	factory := &bundleAnalyzerFactory{
		configuration:  configuration,
		store:          store,
		active:         analyzer,
		activeBundleID: bundleID,
		activeLookup:   lookup,
		analyzers:      map[string]app.Analyzer{bundleID: analyzer},
		lookup:         map[string]lookupAvailability{bundleID: lookup},
	}
	second, err := repository.Import(context.Background(), runtimeFixtureSources(t, "runtime-second"))
	if err != nil {
		t.Fatalf("Import(second) error = %v", err)
	}
	if _, err := repository.Activate(context.Background(), second.CandidateID, second.CandidateHash, "activate"); err != nil {
		t.Fatalf("Activate(second) error = %v", err)
	}
	if err := factory.reloadDesired(t.Context()); err != nil {
		t.Fatalf("reloadDesired() error = %v", err)
	}
	if factory.activeBundleID != second.CandidateID {
		t.Fatalf("active bundle = %q, want %q", factory.activeBundleID, second.CandidateID)
	}
	if !factory.localLookupAvailability().complete() {
		t.Fatal("local lookup is not ready after loading an attributed bundle")
	}
	if _, err := factory.AnalyzerForBundle(context.Background(), first.CandidateID); err != nil {
		t.Fatalf("AnalyzerForBundle(first) error = %v", err)
	}
}

func TestBundleAnalyzerFactoryReconstructsBuiltinAfterDatasetActivation(t *testing.T) {
	t.Parallel()

	configuration := config.Default()
	configuration.Data.BundleDirectory = filepath.Join(t.TempDir(), "bundles")
	configuration.Data.SourceDirectory = filepath.Join(t.TempDir(), "absent")
	repository, err := datasets.NewRepository(configuration.Data.BundleDirectory, detectorBuildID)
	if err != nil {
		t.Fatal(err)
	}
	report, err := repository.Import(t.Context(), runtimeFixtureSources(t, "active-dataset"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repository.Activate(t.Context(), report.CandidateID, report.CandidateHash, "activate"); err != nil {
		t.Fatal(err)
	}
	store := standaloneReportStore{}
	active, bundleID, _, lookup, err := newAnalyzerDetails(t.Context(), configuration, store)
	if err != nil {
		t.Fatal(err)
	}
	factory := &bundleAnalyzerFactory{
		configuration: configuration, store: store, active: active, activeBundleID: bundleID, activeLookup: lookup,
		analyzers: map[string]app.Analyzer{bundleID: active}, lookup: map[string]lookupAvailability{bundleID: lookup},
	}
	builtin, err := factory.AnalyzerForBundle(t.Context(), builtinBundleID)
	if err != nil || builtin == nil {
		t.Fatalf("AnalyzerForBundle(%q) = %T, %v", builtinBundleID, builtin, err)
	}
}

func TestBundleAnalyzerFactoryLoadsDifferentBundlesConcurrently(t *testing.T) {
	t.Parallel()

	started := make(chan string, 2)
	release := make(chan struct{})
	factory := &bundleAnalyzerFactory{
		analyzers: make(map[string]app.Analyzer), lookup: make(map[string]lookupAvailability),
		load: func(ctx context.Context, bundleID string) (app.Analyzer, lookupAvailability, error) {
			started <- bundleID
			select {
			case <-ctx.Done():
				return nil, lookupAvailability{}, ctx.Err()
			case <-release:
				return runtimeFixtureAnalyzer{bundleID: bundleID}, lookupAvailability{}, nil
			}
		},
	}
	done := make(chan error, 2)
	for _, bundleID := range []string{"bundle-a", "bundle-b"} {
		go func() {
			_, err := factory.AnalyzerForBundle(t.Context(), bundleID)
			done <- err
		}()
	}
	seen := map[string]bool{}
	for range 2 {
		select {
		case bundleID := <-started:
			seen[bundleID] = true
		case <-time.After(time.Second):
			t.Fatal("bundle loads did not start concurrently")
		}
	}
	close(release)
	for range 2 {
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}
	if !seen["bundle-a"] || !seen["bundle-b"] {
		t.Fatalf("started loads = %#v", seen)
	}
}

func TestBundleAnalyzerFactoryReloadLoopCancelsBlockedLoad(t *testing.T) {
	t.Parallel()

	configuration := config.Default()
	configuration.Data.BundleDirectory = filepath.Join(t.TempDir(), "bundles")
	repository, err := datasets.NewRepository(configuration.Data.BundleDirectory, detectorBuildID)
	if err != nil {
		t.Fatal(err)
	}
	desired, err := repository.Import(t.Context(), runtimeFixtureSources(t, "reload-cancellation"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repository.Activate(t.Context(), desired.CandidateID, desired.CandidateHash, "activate"); err != nil {
		t.Fatal(err)
	}
	loadStarted := make(chan struct{})
	loadStopped := make(chan struct{})
	factory := &bundleAnalyzerFactory{
		configuration:  configuration,
		active:         runtimeFixtureAnalyzer{bundleID: "previous-bundle"},
		activeBundleID: "previous-bundle",
		analyzers:      make(map[string]app.Analyzer),
		lookup:         make(map[string]lookupAvailability),
		load: func(ctx context.Context, _ string) (app.Analyzer, lookupAvailability, error) {
			close(loadStarted)
			<-ctx.Done()
			close(loadStopped)
			return nil, lookupAvailability{}, ctx.Err()
		},
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	loopDone := make(chan struct{})
	unexpectedError := make(chan error, 1)
	go func() {
		defer close(loopDone)
		factory.reloadLoop(ctx, time.Millisecond, func(err error) { unexpectedError <- err })
	}()
	select {
	case <-loadStarted:
	case <-time.After(time.Second):
		t.Fatal("reload loop did not start the desired bundle load")
	}
	cancel()
	select {
	case <-loadStopped:
	case <-time.After(time.Second):
		t.Fatal("bundle load did not observe reload-loop cancellation")
	}
	select {
	case <-loopDone:
	case <-time.After(time.Second):
		t.Fatal("reload loop did not terminate after cancellation")
	}
	select {
	case err := <-unexpectedError:
		t.Fatalf("reload loop reported shutdown cancellation: %v", err)
	default:
	}
	status, err := repository.Status()
	if err != nil {
		t.Fatal(err)
	}
	if len(status.Loads) != 0 {
		t.Fatalf("shutdown cancellation recorded a load failure: %#v", status.Loads)
	}
}

type runtimeFixtureAnalyzer struct{ bundleID string }

func (a runtimeFixtureAnalyzer) Analyze(context.Context, model.AnalyzeRequest) (model.Report, error) {
	return model.Report{BundleID: a.bundleID, Status: model.StatusComplete}, nil
}
func (runtimeFixtureAnalyzer) LookupIP(context.Context, model.IPLookupRequest) (model.IPLookupResult, error) {
	return model.IPLookupResult{}, nil
}
func (a runtimeFixtureAnalyzer) Reclassify(context.Context, model.ReclassifyRequest) (model.Report, error) {
	return model.Report{BundleID: a.bundleID, Status: model.StatusComplete}, nil
}

func TestServiceReadinessReportsMissingLocalLookupData(t *testing.T) {
	t.Parallel()

	snapshot := serviceReadinessSnapshot(true, lookupAvailability{})
	states := make(map[string]api.OperationReadiness, len(snapshot.Operations))
	for _, operation := range snapshot.Operations {
		states[operation.Name] = operation
	}
	if snapshot.State != api.ReadinessDegraded || states["analyze"].State != api.ReadinessDegraded || states["lookup_ip"].State != api.ReadinessUnavailable {
		t.Fatalf("readiness = %#v", snapshot)
	}
	if len(states["analyze"].Capabilities) != 2 || len(states["lookup_ip"].Capabilities) != 2 {
		t.Fatalf("lookup capabilities = %#v", states["lookup_ip"].Capabilities)
	}
}

func TestServiceReadinessReportsPartialLocalLookupData(t *testing.T) {
	t.Parallel()

	snapshot := serviceReadinessSnapshot(true, lookupAvailability{prefix: true})
	states := make(map[string]api.OperationReadiness, len(snapshot.Operations))
	for _, operation := range snapshot.Operations {
		states[operation.Name] = operation
	}
	if snapshot.State != api.ReadinessDegraded || states["analyze"].State != api.ReadinessDegraded || states["lookup_ip"].State != api.ReadinessDegraded {
		t.Fatalf("readiness = %#v", snapshot)
	}
	if states["lookup_ip"].Capabilities[0].Status != model.CoverageComplete || states["lookup_ip"].Capabilities[1].Status != model.CoverageUnavailable {
		t.Fatalf("lookup capabilities = %#v", states["lookup_ip"].Capabilities)
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

func runtimeFixtureSources(t *testing.T, syncToken string) string {
	t.Helper()
	directory := t.TempDir()
	fixtures := map[string]string{
		"aws-ip-ranges.json":         "../../testdata/upstream/aws-ip-ranges.json",
		"gcp-cloud.json":             "../../testdata/upstream/gcp-cloud.json",
		"azure-service-tags.json":    "../../testdata/upstream/azure-service-tags.json",
		"cdncheck-sources-data.json": "../../testdata/upstream/cdncheck-sources-data.json",
		"iptoasn-v4.tsv":             "../../testdata/upstream/iptoasn-v4.tsv",
		"iptoasn-v6.tsv":             "../../testdata/upstream/iptoasn-v6.tsv",
	}
	for target, source := range fixtures {
		data, err := os.ReadFile(source)
		if err != nil {
			t.Fatalf("read fixture %s: %v", source, err)
		}
		if target == "aws-ip-ranges.json" {
			data = []byte(strings.Replace(string(data), "fixture-1", syncToken, 1))
		}
		if err := os.WriteFile(filepath.Join(directory, target), data, 0o600); err != nil {
			t.Fatalf("write fixture %s: %v", target, err)
		}
	}
	cloudRanges := filepath.Join(directory, "cloudranges", "json")
	if err := os.MkdirAll(cloudRanges, 0o700); err != nil {
		t.Fatalf("create cloudranges fixture: %v", err)
	}
	if err := os.WriteFile(filepath.Join(cloudRanges, "fixture.json"), []byte(`{"provider":"Fixture","provider_id":"fixture","method":"published_list","ipv4":["203.0.113.0/24"],"ipv6":["2001:db8::/32"]}`), 0o600); err != nil {
		t.Fatalf("write cloudranges fixture: %v", err)
	}
	return directory
}
