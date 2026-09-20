package runtime

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"cloudattrib/internal/api"
	"cloudattrib/internal/app"
	"cloudattrib/internal/config"
	"cloudattrib/internal/datasets"
	"cloudattrib/internal/jobs"
	"cloudattrib/internal/model"
	"cloudattrib/internal/store/postgres"
)

const (
	builtinBundleID      = "builtin-rules-v1"
	detectorBuildID      = "cloudattrib-runtime-v1"
	serviceShutdownGrace = 10 * time.Second
	workerCommitTimeout  = 5 * time.Second
)

// Serve runs the durable API, worker pool, and lease recovery under one lifecycle.
func Serve(ctx context.Context, configuration config.Config) error {
	if err := configuration.Validate(); err != nil {
		return fmt.Errorf("validate service configuration: %w", err)
	}
	dsn, err := readDSN(configuration.Storage.PostgresDSNFile)
	if err != nil {
		return err
	}
	store, err := postgres.Open(ctx, dsn, configuration.Limits.MaximumBacklogTargets)
	if err != nil {
		return err
	}
	defer store.Close()
	analyzer, activeBundleID, manifest, lookup, err := newAnalyzerDetails(ctx, configuration, store)
	if err != nil {
		return err
	}
	var bootstrap *datasets.ValidationReport
	var repository *datasets.Repository
	if activeBundleID != builtinBundleID {
		repository, err = datasets.NewRepository(configuration.Data.BundleDirectory, detectorBuildID)
		if err != nil {
			return err
		}
		active, activeErr := repository.Active()
		if activeErr != nil {
			return fmt.Errorf("read active bundle before service staging: %w", activeErr)
		}
		if active == nil {
			report, importErr := repository.Import(ctx, configuration.Data.SourceDirectory)
			if importErr != nil {
				return fmt.Errorf("stage initial service bundle: %w", importErr)
			}
			if report.CandidateID != activeBundleID {
				return fmt.Errorf("staged initial service bundle identity differs from loaded view")
			}
			bootstrap = &report
		}
	}
	if bootstrap != nil {
		if _, err := repository.ActivateCoordinated(ctx, bootstrap.CandidateID, bootstrap.CandidateHash, "bootstrap", func(candidate datasets.Manifest, candidateBytes []byte, publish func() error) error {
			return store.ActivateBundle(ctx, candidate.BundleID, candidateBytes, true, publish)
		}); err != nil {
			return fmt.Errorf("activate initial service bundle: %w", err)
		}
	} else {
		if err := store.RegisterBundle(ctx, activeBundleID, manifest, true); err != nil {
			return fmt.Errorf("register active bundle: %w", err)
		}
		if err := store.RecordBundleActivation(ctx, activeBundleID); err != nil {
			return fmt.Errorf("record active bundle: %w", err)
		}
	}
	analyzerFactory := &bundleAnalyzerFactory{
		configuration: configuration, store: store, active: analyzer, activeBundleID: activeBundleID, activeLookup: lookup,
		analyzers: map[string]app.Analyzer{activeBundleID: analyzer}, lookup: map[string]lookupAvailability{activeBundleID: lookup},
	}
	authentication, err := serviceAuthentication(configuration.API)
	if err != nil {
		return err
	}
	handler, err := api.NewHandler(api.Config{
		Analyzer: analyzerFactory, Jobs: store, Results: store, Findings: store, Authentication: authentication,
		Readiness: serviceReadiness{store: store, analyzers: analyzerFactory}, Metrics: store,
		MaximumRequestBytes: configuration.Limits.MaximumRequestBytes,
	})
	if err != nil {
		return fmt.Errorf("create API handler: %w", err)
	}
	if err := store.RecoverExpired(ctx, configuration.Storage.MaximumAttempts); err != nil {
		return fmt.Errorf("recover expired work before serving: %w", err)
	}

	listener, err := net.Listen("tcp", configuration.API.ListenAddress)
	if err != nil {
		return fmt.Errorf("listen for API requests: %w", err)
	}
	defer func() { _ = listener.Close() }()

	supervisor := jobs.Supervisor{
		Runner: jobs.Runner{
			Store: store, Factory: analyzerFactory, WorkerID: "service-worker", Lease: configuration.Storage.LeaseDuration,
			CommitTimeout: workerCommitTimeout,
		},
		Workers: configuration.Limits.ConcurrentTargets, PollInterval: 100 * time.Millisecond,
		RecoveryInterval: max(configuration.Storage.LeaseDuration/2, time.Second), MaximumAttempts: configuration.Storage.MaximumAttempts,
		OnError: func(workerErr error) { log.Printf("cloudattrib worker: %v", workerErr) },
	}
	workerCtx, stopWorkers := context.WithCancel(ctx)
	defer stopWorkers()
	reloadDone := make(chan struct{})
	go func() {
		defer close(reloadDone)
		analyzerFactory.reloadLoop(workerCtx, time.Second, func(reloadErr error) { log.Printf("cloudattrib bundle reload: %v", reloadErr) })
	}()
	workerErr := make(chan error, 1)
	go func() { workerErr <- supervisor.Run(workerCtx) }()

	server := &http.Server{
		Handler: handler, ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:  configuration.Limits.Target.TargetDeadline + 5*time.Second,
		WriteTimeout: configuration.Limits.Target.TargetDeadline + 5*time.Second,
		IdleTimeout:  30 * time.Second,
	}
	serverErr := make(chan error, 1)
	go func() { serverErr <- server.Serve(listener) }()

	var runErr error
	workerStopped := false
	serverStopped := false
	select {
	case <-ctx.Done():
		runErr = ctx.Err()
	case err := <-workerErr:
		workerStopped = true
		if !errors.Is(err, context.Canceled) {
			runErr = fmt.Errorf("job supervisor stopped: %w", err)
		}
	case err := <-serverErr:
		serverStopped = true
		if !errors.Is(err, http.ErrServerClosed) {
			runErr = fmt.Errorf("serve API: %w", err)
		}
	}
	stopWorkers()
	shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), serviceShutdownGrace)
	defer cancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		_ = server.Close()
		if runErr == nil {
			runErr = fmt.Errorf("shut down API: %w", err)
		}
	}
	if !workerStopped {
		if err := <-workerErr; !errors.Is(err, context.Canceled) && runErr == nil {
			runErr = fmt.Errorf("job supervisor stopped: %w", err)
		}
	}
	<-reloadDone
	if !serverStopped {
		if err := <-serverErr; !errors.Is(err, http.ErrServerClosed) && runErr == nil {
			runErr = fmt.Errorf("serve API: %w", err)
		}
	}
	return runErr
}

type bundleAnalyzerFactory struct {
	configuration  config.Config
	store          app.ResultStore
	active         app.Analyzer
	activeBundleID string
	activeLookup   lookupAvailability
	mu             sync.Mutex
	analyzers      map[string]app.Analyzer
	lookup         map[string]lookupAvailability
	loads          map[string]*bundleLoad
	load           func(context.Context, string) (app.Analyzer, lookupAvailability, error)
}

type bundleLoad struct {
	done     chan struct{}
	analyzer app.Analyzer
	lookup   lookupAvailability
	err      error
}

func (f *bundleAnalyzerFactory) AnalyzerForBundle(ctx context.Context, bundleID string) (app.Analyzer, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	f.mu.Lock()
	if bundleID == "" || bundleID == f.activeBundleID {
		analyzer := f.active
		f.mu.Unlock()
		return analyzer, nil
	}
	if analyzer := f.analyzers[bundleID]; analyzer != nil {
		f.mu.Unlock()
		return analyzer, nil
	}
	if pending := f.loads[bundleID]; pending != nil {
		f.mu.Unlock()
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-pending.done:
			return pending.analyzer, pending.err
		}
	}
	if f.loads == nil {
		f.loads = make(map[string]*bundleLoad)
	}
	pending := &bundleLoad{done: make(chan struct{})}
	f.loads[bundleID] = pending
	f.mu.Unlock()

	loader := f.load
	if loader == nil {
		loader = f.loadBundle
	}
	pending.analyzer, pending.lookup, pending.err = loader(ctx, bundleID)
	f.mu.Lock()
	if pending.err == nil {
		if f.analyzers == nil {
			f.analyzers = make(map[string]app.Analyzer)
		}
		if f.lookup == nil {
			f.lookup = make(map[string]lookupAvailability)
		}
		f.analyzers[bundleID] = pending.analyzer
		f.lookup[bundleID] = pending.lookup
	}
	delete(f.loads, bundleID)
	close(pending.done)
	f.mu.Unlock()
	return pending.analyzer, pending.err
}

func (f *bundleAnalyzerFactory) loadBundle(ctx context.Context, bundleID string) (app.Analyzer, lookupAvailability, error) {
	configuration := f.configuration
	if bundleID == builtinBundleID {
		configuration.Data.SourceDirectory = filepath.Join(configuration.Data.BundleDirectory, ".isolated", builtinBundleID, "absent")
		configuration.Data.BundleDirectory = filepath.Join(configuration.Data.BundleDirectory, ".isolated", builtinBundleID)
	} else {
		if !strings.HasPrefix(bundleID, "bundle-sha256-") {
			return nil, lookupAvailability{}, model.NewError(model.CodeBundleUnavailable, "bundle is unavailable to this detector build", nil)
		}
		configuration.Data.SourceDirectory = filepath.Join(configuration.Data.BundleDirectory, "candidates", bundleID, "sources")
		configuration.Data.BundleDirectory = filepath.Join(configuration.Data.BundleDirectory, ".isolated", bundleID)
	}
	analyzer, loadedBundleID, _, lookup, err := newAnalyzerDetails(ctx, configuration, f.store)
	if err != nil || loadedBundleID != bundleID {
		return nil, lookupAvailability{}, model.NewError(model.CodeBundleUnavailable, "bundle is unavailable to this detector build", err)
	}
	return analyzer, lookup, nil
}

func (f *bundleAnalyzerFactory) localLookupAvailability() lookupAvailability {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.activeLookup
}

func (f *bundleAnalyzerFactory) Analyze(ctx context.Context, request model.AnalyzeRequest) (model.Report, error) {
	analyzer, err := f.AnalyzerForBundle(ctx, "")
	if err != nil {
		return model.Report{}, err
	}
	return analyzer.Analyze(ctx, request)
}

func (f *bundleAnalyzerFactory) LookupIP(ctx context.Context, request model.IPLookupRequest) (model.IPLookupResult, error) {
	analyzer, err := f.AnalyzerForBundle(ctx, "")
	if err != nil {
		return model.IPLookupResult{}, err
	}
	return analyzer.LookupIP(ctx, request)
}

func (f *bundleAnalyzerFactory) Reclassify(ctx context.Context, request model.ReclassifyRequest) (model.Report, error) {
	analyzer, err := f.AnalyzerForBundle(ctx, request.BundleID)
	if err != nil {
		return model.Report{}, err
	}
	return analyzer.Reclassify(ctx, request)
}

func (f *bundleAnalyzerFactory) ValidateReclassify(ctx context.Context, request model.ReclassifyRequest) error {
	analyzer, err := f.AnalyzerForBundle(ctx, request.BundleID)
	if err != nil {
		return err
	}
	validator, ok := analyzer.(app.ReclassificationValidator)
	if !ok {
		return model.NewError(model.CodeCapabilityUnavailable, "bundle cannot validate replay", nil)
	}
	return validator.ValidateReclassify(ctx, request)
}

func (f *bundleAnalyzerFactory) reloadLoop(ctx context.Context, interval time.Duration, onError func(error)) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := f.reloadDesired(ctx); err != nil && ctx.Err() == nil && onError != nil {
				onError(err)
			}
		}
	}
}

func (f *bundleAnalyzerFactory) reloadDesired(ctx context.Context) error {
	repository, err := datasets.NewRepository(f.configuration.Data.BundleDirectory, detectorBuildID)
	if err != nil {
		return err
	}
	activation, err := repository.Active()
	if err != nil || activation == nil {
		return err
	}
	f.mu.Lock()
	if activation.BundleID == f.activeBundleID {
		f.mu.Unlock()
		return nil
	}
	f.mu.Unlock()
	analyzer, err := f.AnalyzerForBundle(ctx, activation.BundleID)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		_ = repository.RecordLoad(activation.BundleID, "failed", err.Error())
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	f.mu.Lock()
	f.active = analyzer
	f.activeBundleID = activation.BundleID
	f.activeLookup = f.lookup[activation.BundleID]
	f.mu.Unlock()
	return repository.RecordLoad(activation.BundleID, "loaded", "")
}

var _ app.Analyzer = (*bundleAnalyzerFactory)(nil)
var _ app.ReclassificationValidator = (*bundleAnalyzerFactory)(nil)

type serviceReadiness struct {
	store     *postgres.Store
	analyzers *bundleAnalyzerFactory
}

func (r serviceReadiness) Readiness(ctx context.Context) api.ReadinessSnapshot {
	persistenceReady := r.store != nil && r.store.Ping(ctx) == nil
	lookup := lookupAvailability{}
	if r.analyzers != nil {
		lookup = r.analyzers.localLookupAvailability()
	}
	return serviceReadinessSnapshot(persistenceReady, lookup)
}

func serviceReadinessSnapshot(persistenceReady bool, lookup lookupAvailability) api.ReadinessSnapshot {
	analyze := runtimeOperationReadiness("analyze", persistenceReady, "writable PostgreSQL storage is unavailable")
	if persistenceReady && !lookup.complete() {
		analyze.State = api.ReadinessDegraded
		analyze.Capabilities = localLookupCapabilities(lookup)
		analyze.Reason = "some local attribution data is unavailable"
	}
	lookupOperation := api.OperationReadiness{Name: "lookup_ip", Capabilities: localLookupCapabilities(lookup)}
	switch {
	case lookup.complete():
		lookupOperation.State = api.ReadinessReady
	case lookup.usable():
		lookupOperation.State = api.ReadinessDegraded
		lookupOperation.Reason = "some local attribution data is unavailable"
	default:
		lookupOperation.State = api.ReadinessUnavailable
		lookupOperation.Reason = "local prefix and ASN attribution data is unavailable"
	}
	operations := []api.OperationReadiness{
		analyze,
		lookupOperation,
		runtimeOperationReadiness("jobs", persistenceReady, "durable job storage is unavailable"),
		runtimeOperationReadiness("results", persistenceReady, "durable result storage is unavailable"),
		runtimeOperationReadiness("findings", persistenceReady, "finding storage is unavailable"),
		{Name: "catalog", State: api.ReadinessReady},
	}
	state := api.ReadinessReady
	if !persistenceReady || !lookup.complete() {
		state = api.ReadinessDegraded
	}
	return api.ReadinessSnapshot{State: state, Operations: operations}
}

func localLookupCapabilities(availability lookupAvailability) []model.CapabilityState {
	if len(availability.data) > 0 {
		return slices.Clone(availability.data)
	}
	prefix := model.CapabilityState{Name: "prefix", Status: model.CoverageComplete}
	if !availability.prefix {
		prefix = model.CapabilityState{Name: "prefix", Status: model.CoverageUnavailable, Reason: "no active local prefix bundle"}
	}
	asn := model.CapabilityState{Name: "asn", Status: model.CoverageComplete}
	if !availability.asn {
		asn = model.CapabilityState{Name: "asn", Status: model.CoverageUnavailable, Reason: "no active local ASN bundle"}
	}
	return []model.CapabilityState{
		prefix,
		asn,
	}
}

func runtimeOperationReadiness(name string, ready bool, reason string) api.OperationReadiness {
	if ready {
		return api.OperationReadiness{Name: name, State: api.ReadinessReady}
	}
	return api.OperationReadiness{Name: name, State: api.ReadinessUnavailable, Reason: reason}
}

func readDSN(path string) (string, error) {
	if path == "" {
		return "", model.NewError(model.CodePersistenceUnavailable, "PostgreSQL DSN file is required", nil)
	}
	file, err := os.Open(path)
	if err != nil {
		return "", model.NewError(model.CodePersistenceUnavailable, "open PostgreSQL DSN file", err)
	}
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil {
		return "", model.NewError(model.CodePersistenceUnavailable, "inspect PostgreSQL DSN file", err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return "", model.NewError(model.CodePersistenceUnavailable, "PostgreSQL DSN file must be a private regular file", nil)
	}
	content, err := io.ReadAll(io.LimitReader(file, 4097))
	if err != nil {
		return "", model.NewError(model.CodePersistenceUnavailable, "read PostgreSQL DSN file", err)
	}
	if len(content) == 0 || len(content) > 4096 {
		return "", model.NewError(model.CodePersistenceUnavailable, "PostgreSQL DSN file is empty or too large", nil)
	}
	dsn := strings.TrimSpace(string(content))
	if dsn == "" || strings.ContainsAny(dsn, "\r\n") {
		return "", model.NewError(model.CodePersistenceUnavailable, "PostgreSQL DSN file must contain one connection string", nil)
	}
	return dsn, nil
}

func serviceAuthentication(configuration config.API) (api.Authentication, error) {
	if !configuration.AuthenticationEnabled {
		return api.Authentication{Mode: api.AuthLoopback, LocalOperatorID: configuration.LocalOperatorID}, nil
	}
	credentials := configuration.Credentials
	if configuration.CredentialsFile != "" {
		if len(credentials) != 0 {
			return api.Authentication{}, fmt.Errorf("configure either inline API credentials or credentials_file, not both")
		}
		var err error
		credentials, err = config.LoadCredentials(configuration.CredentialsFile)
		if err != nil {
			return api.Authentication{}, err
		}
	}
	authentication := api.Authentication{
		Mode: api.AuthenticationMode(configuration.AuthenticationMode), Credentials: credentials,
		IdentityHeader: configuration.TrustedProxyIdentityHeader, LocalOperatorID: configuration.LocalOperatorID,
	}
	for _, value := range configuration.TrustedProxyCIDRs {
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			return api.Authentication{}, fmt.Errorf("parse trusted proxy CIDR: %w", err)
		}
		authentication.TrustedProxyCIDRs = append(authentication.TrustedProxyCIDRs, prefix.Masked())
	}
	return authentication, nil
}
