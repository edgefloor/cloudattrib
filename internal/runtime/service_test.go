package runtime

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	goruntime "runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"cloudattrib/internal/api"
	"cloudattrib/internal/app"
	"cloudattrib/internal/config"
	"cloudattrib/internal/datasets"
	"cloudattrib/internal/jobs"
	"cloudattrib/internal/model"
	"cloudattrib/internal/observability"
)

func TestBundleAnalyzerFactoryBoundsResidencyAndEvictsUnusedLRU(t *testing.T) {
	t.Parallel()

	var loads sync.Map
	factory := newFixtureBundleAnalyzerFactory(2, "active", 10, func(_ context.Context, bundleID string) (app.Analyzer, lookupAvailability, int64, error) {
		counter, _ := loads.LoadOrStore(bundleID, new(atomic.Int64))
		counter.(*atomic.Int64).Add(1)
		return runtimeFixtureAnalyzer{bundleID: bundleID}, lookupAvailability{}, 20, nil
	})

	for _, bundleID := range []string{"bundle-a", "bundle-b", "bundle-c"} {
		captured, err := factory.CaptureAnalyzer(t.Context(), bundleID)
		if err != nil {
			t.Fatalf("CaptureAnalyzer(%q) error = %v", bundleID, err)
		}
		captured.Release()
	}
	resident, estimated := factory.residencySnapshot()
	if resident != 2 || estimated != 30 {
		t.Fatalf("residencySnapshot() = %d, %d, want 2, 30", resident, estimated)
	}
	captured, err := factory.CaptureAnalyzer(t.Context(), "bundle-a")
	if err != nil {
		t.Fatalf("CaptureAnalyzer(evicted) error = %v", err)
	}
	captured.Release()
	value, _ := loads.Load("bundle-a")
	if value.(*atomic.Int64).Load() != 2 {
		t.Fatalf("bundle-a load count = %d, want 2", value.(*atomic.Int64).Load())
	}
}

func TestBundleAnalyzerFactoryProtectsCapturedGenerationAndCancelsCapacityWait(t *testing.T) {
	t.Parallel()

	var loads atomic.Int64
	factory := newFixtureBundleAnalyzerFactory(2, "active", 10, func(_ context.Context, bundleID string) (app.Analyzer, lookupAvailability, int64, error) {
		loads.Add(1)
		return runtimeFixtureAnalyzer{bundleID: bundleID}, lookupAvailability{}, 20, nil
	})
	captured, err := factory.CaptureAnalyzer(t.Context(), "captured")
	if err != nil {
		t.Fatal(err)
	}
	waitCtx, cancel := context.WithCancel(t.Context())
	waitDone := make(chan error, 1)
	go func() {
		_, acquireErr := factory.CaptureAnalyzer(waitCtx, "waiting")
		waitDone <- acquireErr
	}()
	deadline := time.Now().Add(time.Second)
	for factory.capacityWaiterCount() != 1 && time.Now().Before(deadline) {
		goruntime.Gosched()
	}
	if factory.capacityWaiterCount() != 1 {
		t.Fatal("acquisition did not wait for resident capacity")
	}
	cancel()
	if err := <-waitDone; !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled CaptureAnalyzer() error = %v", err)
	}
	if factory.capacityWaiterCount() != 0 {
		t.Fatalf("capacity waiters after cancellation = %d, want 0", factory.capacityWaiterCount())
	}
	if loads.Load() != 1 {
		t.Fatalf("load count after cancelled capacity wait = %d, want 1", loads.Load())
	}
	resident, _ := factory.residencySnapshot()
	if resident != 2 {
		t.Fatalf("resident generations while captured = %d, want 2", resident)
	}
	captured.Release()
	next, err := factory.CaptureAnalyzer(t.Context(), "waiting")
	if err != nil {
		t.Fatal(err)
	}
	next.Release()
}

func TestBundleAnalyzerFactorySingleflightsSameGeneration(t *testing.T) {
	t.Parallel()

	started := make(chan struct{})
	release := make(chan struct{})
	var loads atomic.Int64
	factory := newFixtureBundleAnalyzerFactory(2, "active", 10, func(ctx context.Context, bundleID string) (app.Analyzer, lookupAvailability, int64, error) {
		loads.Add(1)
		close(started)
		select {
		case <-ctx.Done():
			return nil, lookupAvailability{}, 0, ctx.Err()
		case <-release:
			return runtimeFixtureAnalyzer{bundleID: bundleID}, lookupAvailability{}, 20, nil
		}
	})
	captures := make(chan jobs.CapturedAnalyzer, 2)
	errors := make(chan error, 2)
	for range 2 {
		go func() {
			captured, err := factory.CaptureAnalyzer(t.Context(), "shared")
			captures <- captured
			errors <- err
		}()
	}
	<-started
	deadline := time.Now().Add(time.Second)
	for factory.loadWaiterCount("shared") != 1 && time.Now().Before(deadline) {
		goruntime.Gosched()
	}
	if factory.loadWaiterCount("shared") != 1 {
		t.Fatal("concurrent acquisition did not join the pending load")
	}
	close(release)
	for range 2 {
		if err := <-errors; err != nil {
			t.Fatal(err)
		}
		(<-captures).Release()
	}
	if loads.Load() != 1 {
		t.Fatalf("same-generation load count = %d, want 1", loads.Load())
	}
}

func TestBundleAnalyzerFactorySharedLoadSurvivesInitiatorCancellation(t *testing.T) {
	t.Parallel()

	started := make(chan struct{})
	releaseLoad := make(chan struct{})
	loadCancelled := make(chan struct{}, 1)
	factory := newFixtureBundleAnalyzerFactory(2, "active", 10, func(ctx context.Context, bundleID string) (app.Analyzer, lookupAvailability, int64, error) {
		close(started)
		select {
		case <-ctx.Done():
			loadCancelled <- struct{}{}
			return nil, lookupAvailability{}, 0, ctx.Err()
		case <-releaseLoad:
			return runtimeFixtureAnalyzer{bundleID: bundleID}, lookupAvailability{}, 20, nil
		}
	})
	initiatorCtx, cancelInitiator := context.WithCancel(t.Context())
	initiatorDone := make(chan error, 1)
	go func() {
		_, err := factory.CaptureAnalyzer(initiatorCtx, "shared")
		initiatorDone <- err
	}()
	<-started
	waiterDone := make(chan struct {
		captured jobs.CapturedAnalyzer
		err      error
	}, 1)
	go func() {
		captured, err := factory.CaptureAnalyzer(t.Context(), "shared")
		waiterDone <- struct {
			captured jobs.CapturedAnalyzer
			err      error
		}{captured: captured, err: err}
	}()
	deadline := time.Now().Add(time.Second)
	for factory.loadWaiterCount("shared") != 1 && time.Now().Before(deadline) {
		goruntime.Gosched()
	}
	cancelInitiator()
	if err := <-initiatorDone; !errors.Is(err, context.Canceled) {
		t.Fatalf("initiating acquisition error = %v", err)
	}
	select {
	case <-loadCancelled:
		t.Fatal("initiator cancellation canceled a shared load")
	case <-time.After(20 * time.Millisecond):
	}
	close(releaseLoad)
	result := <-waiterDone
	if result.err != nil {
		t.Fatalf("remaining waiter error = %v", result.err)
	}
	result.captured.Release()
}

func TestBundleAnalyzerFactoryFailedLoadLeavesNoResidentGeneration(t *testing.T) {
	t.Parallel()

	factory := newFixtureBundleAnalyzerFactory(2, "active", 10, func(context.Context, string) (app.Analyzer, lookupAvailability, int64, error) {
		return nil, lookupAvailability{}, 0, errors.New("broken bundle")
	})
	if _, err := factory.CaptureAnalyzer(t.Context(), "broken"); err == nil {
		t.Fatal("CaptureAnalyzer() error = nil")
	}
	resident, estimated := factory.residencySnapshot()
	if resident != 1 || estimated != 10 {
		t.Fatalf("residencySnapshot() after failure = %d, %d", resident, estimated)
	}
}

func TestBundleAnalyzerFactorySharesFailedLoadWithoutRetainingGeneration(t *testing.T) {
	t.Parallel()

	started := make(chan struct{})
	release := make(chan struct{})
	var loads atomic.Int64
	factory := newFixtureBundleAnalyzerFactory(2, "active", 10, func(ctx context.Context, _ string) (app.Analyzer, lookupAvailability, int64, error) {
		loads.Add(1)
		close(started)
		select {
		case <-ctx.Done():
			return nil, lookupAvailability{}, 0, ctx.Err()
		case <-release:
			return nil, lookupAvailability{}, 0, errors.New("broken bundle")
		}
	})
	done := make(chan error, 2)
	for range 2 {
		go func() {
			_, err := factory.CaptureAnalyzer(t.Context(), "broken")
			done <- err
		}()
	}
	<-started
	deadline := time.Now().Add(time.Second)
	for factory.loadWaiterCount("broken") != 1 && time.Now().Before(deadline) {
		goruntime.Gosched()
	}
	if factory.loadWaiterCount("broken") != 1 {
		t.Fatal("concurrent acquisition did not join the pending failed load")
	}
	close(release)
	for range 2 {
		if err := <-done; err == nil {
			t.Fatal("CaptureAnalyzer() error = nil")
		}
	}
	if loads.Load() != 1 {
		t.Fatalf("failed load count = %d, want 1", loads.Load())
	}
	resident, estimated := factory.residencySnapshot()
	if resident != 1 || estimated != 10 {
		t.Fatalf("residencySnapshot() after shared failure = %d, %d", resident, estimated)
	}
}

func TestServiceMetricsAddsProcessResidencyToDurableSnapshot(t *testing.T) {
	t.Parallel()

	factory := newFixtureBundleAnalyzerFactory(2, "active", 123, nil)
	provider := serviceMetricsProvider{
		durable:   fixtureOperationalMetrics{snapshot: observability.Snapshot{BundlePins: 7}},
		analyzers: factory,
	}
	snapshot, err := provider.OperationalMetrics(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.BundlePins != 7 || snapshot.ResidentGenerations != 1 || snapshot.EstimatedRetainedBytes != 123 {
		t.Fatalf("OperationalMetrics() = %#v", snapshot)
	}
}

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
	firstActivation, err := repository.Activate(context.Background(), first.CandidateID, first.CandidateHash, "activate")
	if err != nil {
		t.Fatalf("Activate(first) error = %v", err)
	}
	store := standaloneReportStore{}
	analyzer, bundleID, _, lookup, err := newAnalyzerDetails(t.Context(), configuration, store)
	if err != nil {
		t.Fatalf("newAnalyzerDetails() error = %v", err)
	}
	factory := newBundleAnalyzerFactory(4, analyzer, bundleID, lookup, firstActivation, 0)
	factory.configuration = configuration
	factory.store = store
	factory.authority = &fixtureActivationAuthority{desired: &firstActivation}
	factory.repository = repository
	second, err := repository.Import(context.Background(), runtimeFixtureSources(t, "runtime-second"))
	if err != nil {
		t.Fatalf("Import(second) error = %v", err)
	}
	secondActivation, err := repository.Activate(context.Background(), second.CandidateID, second.CandidateHash, "activate")
	if err != nil {
		t.Fatalf("Activate(second) error = %v", err)
	}
	uncommittedPointer := secondActivation
	uncommittedPointer.OperationID = ""
	uncommittedPointer.Generation = 0
	encodedPointer, err := json.Marshal(uncommittedPointer)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(configuration.Data.BundleDirectory, "active.json"), encodedPointer, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := factory.reloadDesired(t.Context()); err != nil {
		t.Fatalf("reloadDesired() error = %v", err)
	}
	if factory.activeBundleID != first.CandidateID {
		t.Fatalf("uncommitted filesystem pointer changed active bundle to %q", factory.activeBundleID)
	}
	factory.authority.(*fixtureActivationAuthority).desired = &secondActivation
	if err := factory.reloadDesired(t.Context()); err != nil {
		t.Fatalf("reloadDesired(committed) error = %v", err)
	}
	if factory.activeBundleID != second.CandidateID {
		t.Fatalf("active bundle = %q, want %q", factory.activeBundleID, second.CandidateID)
	}
	if !factory.localLookupAvailability().complete() {
		t.Fatal("local lookup is not ready after loading an attributed bundle")
	}
	captured, err := factory.CaptureAnalyzer(context.Background(), first.CandidateID)
	if err != nil {
		t.Fatalf("CaptureAnalyzer(first) error = %v", err)
	}
	captured.Release()
}

func TestBundleAnalyzerFactoryFailedLoadKeepsLastKnownGood(t *testing.T) {
	t.Parallel()

	configuration := config.Default()
	configuration.Data.BundleDirectory = filepath.Join(t.TempDir(), "bundles")
	repository, err := datasets.NewRepository(configuration.Data.BundleDirectory, detectorBuildID)
	if err != nil {
		t.Fatal(err)
	}
	report, err := repository.Import(t.Context(), runtimeFixtureSources(t, "failed-load"))
	if err != nil {
		t.Fatal(err)
	}
	desired, err := repository.Activate(t.Context(), report.CandidateID, report.CandidateHash, "activate")
	if err != nil {
		t.Fatal(err)
	}
	previous := datasets.Activation{OperationID: "activation-previous", Generation: desired.Generation - 1, BundleID: "previous-bundle"}
	factory := newBundleAnalyzerFactory(4, runtimeFixtureAnalyzer{bundleID: previous.BundleID}, previous.BundleID, lookupAvailability{}, previous, 0)
	factory.configuration = configuration
	factory.authority = &fixtureActivationAuthority{desired: &desired}
	factory.repository = repository
	factory.load = func(context.Context, string) (app.Analyzer, lookupAvailability, int64, error) {
		return nil, lookupAvailability{}, 0, errors.New("corrupt candidate")
	}
	if err := factory.reloadDesired(t.Context()); err == nil {
		t.Fatal("reloadDesired() error = nil, want corrupt candidate failure")
	}
	if factory.activeBundleID != previous.BundleID || factory.loaded.OperationID != previous.OperationID {
		t.Fatalf("last-known-good changed to bundle=%q activation=%#v", factory.activeBundleID, factory.loaded)
	}
	status, err := repository.Status()
	if err != nil || len(status.Loads) != 1 || status.Loads[0].Status != "failed" || status.Loads[0].Generation != desired.Generation {
		t.Fatalf("Status() = %#v, %v", status, err)
	}
}

func TestBundleAnalyzerFactoryUnchangedActivationSkipsCandidateValidation(t *testing.T) {
	t.Parallel()

	configuration := config.Default()
	configuration.Data.BundleDirectory = filepath.Join(t.TempDir(), "bundles")
	repository, err := datasets.NewRepository(configuration.Data.BundleDirectory, detectorBuildID)
	if err != nil {
		t.Fatal(err)
	}
	report, err := repository.Import(t.Context(), runtimeFixtureSources(t, "unchanged-reload"))
	if err != nil {
		t.Fatal(err)
	}
	activation, err := repository.Activate(t.Context(), report.CandidateID, report.CandidateHash, "activate")
	if err != nil {
		t.Fatal(err)
	}
	factory := newBundleAnalyzerFactory(4, runtimeFixtureAnalyzer{bundleID: activation.BundleID}, activation.BundleID, lookupAvailability{}, activation, 0)
	factory.configuration = configuration
	factory.authority = &fixtureActivationAuthority{desired: &activation}
	factory.repository = repository
	manifestPath := filepath.Join(configuration.Data.BundleDirectory, "candidates", report.CandidateID, "manifest.json")
	if err := os.WriteFile(manifestPath, []byte("corrupt after process load"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := factory.reloadDesired(t.Context()); err != nil {
		t.Fatalf("reloadDesired() error = %v, unchanged activation must not revalidate artifacts", err)
	}
}

func TestBundleAnalyzerFactoryRepairsMissingAndCorruptPointers(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name   string
		mutate func(*testing.T, string)
	}{
		{
			name: "missing",
			mutate: func(t *testing.T, path string) {
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "corrupt",
			mutate: func(t *testing.T, path string) {
				if err := os.WriteFile(path, []byte("not json"), 0o600); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "timestamp drift",
			mutate: func(t *testing.T, path string) {
				encoded, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				var activation datasets.Activation
				if err := json.Unmarshal(encoded, &activation); err != nil {
					t.Fatal(err)
				}
				activation.At = activation.At.Add(time.Second)
				encoded, err = json.Marshal(activation)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, encoded, 0o600); err != nil {
					t.Fatal(err)
				}
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			configuration := config.Default()
			configuration.Data.BundleDirectory = filepath.Join(t.TempDir(), "bundles")
			repository, err := datasets.NewRepository(configuration.Data.BundleDirectory, detectorBuildID)
			if err != nil {
				t.Fatal(err)
			}
			report, err := repository.Import(t.Context(), runtimeFixtureSources(t, "repair-"+test.name))
			if err != nil {
				t.Fatal(err)
			}
			activation, err := repository.Activate(t.Context(), report.CandidateID, report.CandidateHash, "activate")
			if err != nil {
				t.Fatal(err)
			}
			factory := newBundleAnalyzerFactory(4, runtimeFixtureAnalyzer{bundleID: activation.BundleID}, activation.BundleID, lookupAvailability{}, activation, 0)
			factory.configuration = configuration
			factory.authority = &fixtureActivationAuthority{desired: &activation}
			factory.repository = repository
			test.mutate(t, filepath.Join(configuration.Data.BundleDirectory, "active.json"))

			if err := factory.reloadDesired(t.Context()); err != nil {
				t.Fatalf("reloadDesired() error = %v", err)
			}
			published, err := repository.Active()
			if err != nil || !sameActivation(published, &activation) || !published.At.Equal(activation.At) {
				t.Fatalf("Active() = %#v, %v; want repaired activation %#v", published, err, activation)
			}
		})
	}
}

func TestBundleAnalyzerFactoryActivationDoesNotChangeInflightAttempt(t *testing.T) {
	t.Parallel()

	started := make(chan struct{})
	release := make(chan struct{})
	previous := blockingRuntimeAnalyzer{bundleID: "previous-bundle", started: started, release: release}
	next := runtimeFixtureAnalyzer{bundleID: "next-bundle"}
	factory := newFixtureBundleAnalyzerFactory(2, previous.bundleID, 0, func(context.Context, string) (app.Analyzer, lookupAvailability, int64, error) {
		return next, lookupAvailability{}, 0, nil
	})
	factory.active = previous
	factory.residents[previous.bundleID].analyzer = previous
	nextCapture, err := factory.CaptureAnalyzer(t.Context(), next.bundleID)
	if err != nil {
		t.Fatal(err)
	}
	nextCapture.Release()
	reportDone := make(chan model.Report, 1)
	go func() {
		report, _ := factory.Analyze(t.Context(), model.AnalyzeRequest{Target: "example.com"})
		reportDone <- report
	}()
	<-started
	factory.mu.Lock()
	factory.active = next
	factory.activeBundleID = next.bundleID
	factory.notifyLocked()
	factory.mu.Unlock()
	close(release)
	if report := <-reportDone; report.BundleID != previous.bundleID {
		t.Fatalf("in-flight report bundle = %q, want %q", report.BundleID, previous.bundleID)
	}
}

type fixtureActivationAuthority struct {
	desired *datasets.Activation
	err     error
}

func (f *fixtureActivationAuthority) DesiredBundle(context.Context) (*datasets.Activation, error) {
	if f.desired == nil {
		return nil, f.err
	}
	copy := *f.desired
	return &copy, f.err
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
	factory := newBundleAnalyzerFactory(4, active, bundleID, lookup, datasets.Activation{}, 0)
	factory.configuration = configuration
	factory.store = store
	builtin, err := factory.CaptureAnalyzer(t.Context(), builtinBundleID)
	if err != nil || builtin == nil {
		t.Fatalf("CaptureAnalyzer(%q) = %T, %v", builtinBundleID, builtin, err)
	}
	builtin.Release()
}

func TestBundleAnalyzerFactoryLoadsDifferentBundlesConcurrently(t *testing.T) {
	t.Parallel()

	started := make(chan string, 2)
	release := make(chan struct{})
	factory := newFixtureBundleAnalyzerFactory(4, "active", 0,
		func(ctx context.Context, bundleID string) (app.Analyzer, lookupAvailability, int64, error) {
			started <- bundleID
			select {
			case <-ctx.Done():
				return nil, lookupAvailability{}, 0, ctx.Err()
			case <-release:
				return runtimeFixtureAnalyzer{bundleID: bundleID}, lookupAvailability{}, 0, nil
			}
		})
	done := make(chan error, 2)
	for _, bundleID := range []string{"bundle-a", "bundle-b"} {
		go func() {
			captured, err := factory.CaptureAnalyzer(t.Context(), bundleID)
			if captured != nil {
				captured.Release()
			}
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
	desiredActivation, err := repository.Activate(t.Context(), desired.CandidateID, desired.CandidateHash, "activate")
	if err != nil {
		t.Fatal(err)
	}
	loadStarted := make(chan struct{})
	loadStopped := make(chan struct{})
	factory := newBundleAnalyzerFactory(4, runtimeFixtureAnalyzer{bundleID: "previous-bundle"}, "previous-bundle", lookupAvailability{}, datasets.Activation{}, 0)
	factory.configuration = configuration
	factory.authority = &fixtureActivationAuthority{desired: &desiredActivation}
	factory.repository = repository
	factory.load = func(ctx context.Context, _ string) (app.Analyzer, lookupAvailability, int64, error) {
		close(loadStarted)
		<-ctx.Done()
		close(loadStopped)
		return nil, lookupAvailability{}, 0, ctx.Err()
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

func newFixtureBundleAnalyzerFactory(
	maximumResident int,
	activeBundleID string,
	estimatedBytes int64,
	load func(context.Context, string) (app.Analyzer, lookupAvailability, int64, error),
) *bundleAnalyzerFactory {
	active := runtimeFixtureAnalyzer{bundleID: activeBundleID}
	factory := newBundleAnalyzerFactory(maximumResident, active, activeBundleID, lookupAvailability{}, datasets.Activation{BundleID: activeBundleID}, estimatedBytes)
	factory.load = load
	return factory
}

type fixtureOperationalMetrics struct {
	snapshot observability.Snapshot
	err      error
}

func (m fixtureOperationalMetrics) OperationalMetrics(context.Context) (observability.Snapshot, error) {
	return m.snapshot, m.err
}

type blockingRuntimeAnalyzer struct {
	bundleID string
	started  chan<- struct{}
	release  <-chan struct{}
}

func (a blockingRuntimeAnalyzer) Analyze(context.Context, model.AnalyzeRequest) (model.Report, error) {
	close(a.started)
	<-a.release
	return model.Report{BundleID: a.bundleID, Status: model.StatusComplete}, nil
}

func (blockingRuntimeAnalyzer) LookupIP(context.Context, model.IPLookupRequest) (model.IPLookupResult, error) {
	return model.IPLookupResult{}, nil
}

func (a blockingRuntimeAnalyzer) Reclassify(context.Context, model.ReclassifyRequest) (model.Report, error) {
	return model.Report{BundleID: a.bundleID, Status: model.StatusComplete}, nil
}

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
	if len(states["analyze"].Capabilities) != 3 || len(states["lookup_ip"].Capabilities) != 2 {
		t.Fatalf("lookup capabilities = %#v", states["lookup_ip"].Capabilities)
	}
	if states["analyze"].Capabilities[0].Name != "tls_certificate" || states["analyze"].Capabilities[0].Status != model.CoverageUnavailable {
		t.Fatalf("analyze capabilities = %#v", states["analyze"].Capabilities)
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
