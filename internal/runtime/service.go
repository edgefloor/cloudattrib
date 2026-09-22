package runtime

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"cloudattrib/internal/api"
	"cloudattrib/internal/app"
	"cloudattrib/internal/config"
	"cloudattrib/internal/datasets"
	"cloudattrib/internal/detect/webtech"
	"cloudattrib/internal/jobs"
	"cloudattrib/internal/model"
	"cloudattrib/internal/observability"
	"cloudattrib/internal/policy"
	"cloudattrib/internal/store/postgres"
)

const (
	builtinBundleID      = "builtin-rules-v1"
	serviceShutdownGrace = 10 * time.Second
	workerCommitTimeout  = 5 * time.Second
)

func prepareServiceActivation(ctx context.Context, configuration config.Config, store *postgres.Store, repository *datasets.Repository) (*datasets.Activation, error) {
	desired, err := store.DesiredBundle(ctx)
	if err != nil {
		return nil, err
	}
	if desired != nil && desired.CandidateHash != "" {
		return desired, nil
	}
	commit := func(proposed datasets.Activation, _ datasets.Manifest, manifest []byte) (datasets.Activation, error) {
		return store.CommitBundleActivation(ctx, proposed, manifest, true)
	}
	if desired != nil && desired.BundleID != builtinBundleID {
		report, validateErr := repository.Validate(ctx, desired.BundleID)
		if validateErr != nil {
			return nil, fmt.Errorf("migrate legacy service activation: %w", validateErr)
		}
		activation, activateErr := repository.ActivateCommitted(ctx, report.CandidateID, report.CandidateHash, "migration", commit)
		if activateErr != nil {
			return nil, fmt.Errorf("commit migrated service activation: %w", activateErr)
		}
		return &activation, nil
	}
	if desired != nil {
		manifest := []byte(`{"schema_version":1,"bundle_id":"builtin-rules-v1"}`)
		proposal, proposeErr := datasets.NewActivationProposal(builtinBundleID, manifestDigest(manifest), "migration")
		if proposeErr != nil {
			return nil, proposeErr
		}
		activation, commitErr := store.CommitBundleActivation(ctx, proposal, manifest, true)
		return &activation, commitErr
	}

	report, err := repository.Import(ctx, configuration.Data.SourceDirectory)
	if errors.Is(err, datasets.ErrNoSources) {
		manifest := []byte(`{"schema_version":1,"bundle_id":"builtin-rules-v1"}`)
		proposal, proposeErr := datasets.NewActivationProposal(builtinBundleID, manifestDigest(manifest), "bootstrap")
		if proposeErr != nil {
			return nil, proposeErr
		}
		activation, commitErr := store.CommitBundleActivation(ctx, proposal, manifest, true)
		if commitErr != nil {
			return nil, fmt.Errorf("commit initial built-in bundle: %w", commitErr)
		}
		return &activation, nil
	}
	if err != nil {
		return nil, fmt.Errorf("stage initial service bundle: %w", err)
	}
	activation, err := repository.ActivateCommitted(ctx, report.CandidateID, report.CandidateHash, "bootstrap", commit)
	if err != nil {
		return nil, fmt.Errorf("commit initial service bundle: %w", err)
	}
	return &activation, nil
}

func loadServiceAnalyzer(
	ctx context.Context,
	configuration config.Config,
	store *postgres.Store,
	repository *datasets.Repository,
	desired *datasets.Activation,
	controller *policy.Controller,
	sharedWebDetector app.WebDetector,
) (app.Analyzer, string, lookupAvailability, datasets.Activation, int64, error) {
	history, err := store.ActivationHistory(ctx, 3)
	if err != nil {
		return nil, "", lookupAvailability{}, datasets.Activation{}, 0, err
	}
	if desired != nil && (len(history) == 0 || history[0].OperationID != desired.OperationID) {
		history = append([]datasets.Activation{*desired}, history...)
	}
	if len(history) == 0 {
		return nil, "", lookupAvailability{}, datasets.Activation{}, 0, model.NewError(model.CodeBundleUnavailable, "no committed service bundle is available", nil)
	}
	var failures []error
	for index, activation := range history {
		if index == 0 && activation.BundleID != builtinBundleID {
			if err := repository.ReconcileAuthoritative(ctx, activation, store.DesiredBundle); err != nil {
				_ = repository.RecordLoad(activation, "failed", err.Error())
				failures = append(failures, fmt.Errorf("reconcile desired generation %d: %w", activation.Generation, err))
				continue
			}
		}
		analyzer, bundleID, manifest, lookup, loadErr := newAnalyzerDetailsForBundleWithResources(ctx, configuration, store, activation.BundleID, controller, sharedWebDetector)
		if loadErr != nil || bundleID != activation.BundleID {
			if loadErr == nil {
				loadErr = fmt.Errorf("loaded bundle identity %q differs from committed bundle %q", bundleID, activation.BundleID)
			}
			_ = repository.RecordLoad(activation, "failed", loadErr.Error())
			failures = append(failures, fmt.Errorf("load generation %d: %w", activation.Generation, loadErr))
			continue
		}
		reason := ""
		if len(failures) > 0 {
			reason = "desired generation could not be loaded: " + errors.Join(failures...).Error()
		}
		if err := repository.RecordLoad(activation, "loaded", reason); err != nil {
			return nil, "", lookupAvailability{}, datasets.Activation{}, 0, err
		}
		return analyzer, bundleID, lookup, activation, estimatedGenerationBytes(manifest), nil
	}
	return nil, "", lookupAvailability{}, datasets.Activation{}, 0, fmt.Errorf("load committed service bundle: %w", errors.Join(failures...))
}

func manifestDigest(manifest []byte) string {
	digest := sha256.Sum256(manifest)
	return "sha256:" + hex.EncodeToString(digest[:])
}

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
	controller, err := policy.NewController(
		configuration.Limits.Target,
		configuration.Limits.ConcurrentTargets,
		configuration.Limits.ConcurrentDNS,
		configuration.Limits.ConcurrentHTTP,
	)
	if err != nil {
		return fmt.Errorf("create execution controller: %w", err)
	}
	sharedWebDetector, err := webtech.New()
	if err != nil {
		return fmt.Errorf("create shared passive web detector: %w", err)
	}
	repository, err := datasets.NewRepository(configuration.Data.BundleDirectory, detectorBuildID)
	if err != nil {
		return err
	}
	desired, err := prepareServiceActivation(ctx, configuration, store, repository)
	if err != nil {
		return err
	}
	analyzer, activeBundleID, lookup, loaded, retainedBytes, err := loadServiceAnalyzer(ctx, configuration, store, repository, desired, controller, sharedWebDetector)
	if err != nil {
		return err
	}
	analyzerFactory := newBundleAnalyzerFactory(
		configuration.Limits.MaximumResidentGenerations,
		analyzer, activeBundleID, lookup, loaded, retainedBytes,
	)
	analyzerFactory.configuration = configuration
	analyzerFactory.store = store
	analyzerFactory.authority = store
	analyzerFactory.repository = repository
	analyzerFactory.controller = controller
	analyzerFactory.sharedWebDetector = sharedWebDetector
	authentication, err := serviceAuthentication(configuration.API)
	if err != nil {
		return err
	}
	handler, err := api.NewHandler(api.Config{
		Analyzer: analyzerFactory, Jobs: store, Results: store, Findings: store, Authentication: authentication,
		Readiness:           serviceReadiness{store: store, analyzers: analyzerFactory},
		Metrics:             serviceMetricsProvider{durable: store, analyzers: analyzerFactory},
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
		ReadTimeout: configuration.Limits.Target.TargetDeadline + 5*time.Second,
		IdleTimeout: 30 * time.Second,
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
	configuration     config.Config
	store             app.ResultStore
	authority         bundleActivationAuthority
	repository        *datasets.Repository
	active            app.Analyzer
	activeBundleID    string
	activeLookup      lookupAvailability
	loaded            datasets.Activation
	mu                sync.Mutex
	maximumResident   int
	residents         map[string]*residentAnalyzer
	loads             map[string]*bundleLoad
	changed           chan struct{}
	sequence          uint64
	capacityWaiters   int
	load              func(context.Context, string) (app.Analyzer, lookupAvailability, int64, error)
	controller        *policy.Controller
	sharedWebDetector app.WebDetector
}

type bundleActivationAuthority interface {
	DesiredBundle(context.Context) (*datasets.Activation, error)
}

type bundleLoad struct {
	done    chan struct{}
	err     error
	waiters int
	cancel  context.CancelFunc
}

type residentAnalyzer struct {
	analyzer       app.Analyzer
	lookup         lookupAvailability
	references     int
	lastUsed       uint64
	estimatedBytes int64
}

type bundleCapture struct {
	factory  *bundleAnalyzerFactory
	bundleID string
	analyzer app.Analyzer
	lookup   lookupAvailability
	once     sync.Once
}

func (c *bundleCapture) Analyzer() app.Analyzer {
	if c == nil {
		return nil
	}
	return c.analyzer
}

func (c *bundleCapture) Release() {
	if c == nil || c.factory == nil {
		return
	}
	c.once.Do(func() { c.factory.release(c.bundleID) })
}

func newBundleAnalyzerFactory(maximumResident int, active app.Analyzer, activeBundleID string, lookup lookupAvailability, loaded datasets.Activation, estimatedBytes int64) *bundleAnalyzerFactory {
	factory := &bundleAnalyzerFactory{
		active: active, activeBundleID: activeBundleID, activeLookup: lookup, loaded: loaded,
		maximumResident: maximumResident,
		residents:       make(map[string]*residentAnalyzer),
		loads:           make(map[string]*bundleLoad),
		changed:         make(chan struct{}),
	}
	if active != nil && activeBundleID != "" {
		factory.residents[activeBundleID] = &residentAnalyzer{analyzer: active, lookup: lookup, estimatedBytes: estimatedBytes}
	}
	return factory
}

func (f *bundleAnalyzerFactory) ensureStateLocked() {
	if f.maximumResident < 2 {
		f.maximumResident = f.configuration.Limits.MaximumResidentGenerations
		if f.maximumResident < 2 {
			f.maximumResident = config.Default().Limits.MaximumResidentGenerations
		}
	}
	if f.residents == nil {
		f.residents = make(map[string]*residentAnalyzer)
	}
	if f.loads == nil {
		f.loads = make(map[string]*bundleLoad)
	}
	if f.changed == nil {
		f.changed = make(chan struct{})
	}
	if f.active != nil && f.activeBundleID != "" && f.residents[f.activeBundleID] == nil {
		f.residents[f.activeBundleID] = &residentAnalyzer{analyzer: f.active, lookup: f.activeLookup}
	}
}

func (f *bundleAnalyzerFactory) nextSequenceLocked() uint64 {
	f.sequence++
	return f.sequence
}

func (f *bundleAnalyzerFactory) notifyLocked() {
	close(f.changed)
	f.changed = make(chan struct{})
}

func (f *bundleAnalyzerFactory) reserveCapacityLocked() bool {
	for len(f.residents)+len(f.loads) >= f.maximumResident {
		var candidate string
		var oldest uint64
		for bundleID, resident := range f.residents {
			if bundleID == f.activeBundleID || resident.references != 0 {
				continue
			}
			if candidate == "" || resident.lastUsed < oldest {
				candidate = bundleID
				oldest = resident.lastUsed
			}
		}
		if candidate == "" {
			return false
		}
		delete(f.residents, candidate)
	}
	return true
}

func (f *bundleAnalyzerFactory) capture(ctx context.Context, requestedBundleID string) (*bundleCapture, error) {
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		f.mu.Lock()
		f.ensureStateLocked()
		bundleID := requestedBundleID
		if bundleID == "" {
			bundleID = f.activeBundleID
		}
		if resident := f.residents[bundleID]; resident != nil {
			resident.references++
			resident.lastUsed = f.nextSequenceLocked()
			capture := &bundleCapture{factory: f, bundleID: bundleID, analyzer: resident.analyzer, lookup: resident.lookup}
			f.mu.Unlock()
			return capture, nil
		}
		if pending := f.loads[bundleID]; pending != nil {
			done := pending.done
			if pending.waiters == 0 {
				f.mu.Unlock()
				select {
				case <-ctx.Done():
					return nil, ctx.Err()
				case <-done:
					continue
				}
			}
			pending.waiters++
			f.mu.Unlock()
			if waitErr := f.waitForBundleLoad(ctx, pending); waitErr != nil {
				return nil, waitErr
			}
			continue
		}
		if !f.reserveCapacityLocked() {
			changed := f.changed
			f.capacityWaiters++
			f.mu.Unlock()
			var waitErr error
			select {
			case <-ctx.Done():
				waitErr = ctx.Err()
			case <-changed:
			}
			f.mu.Lock()
			f.capacityWaiters--
			f.mu.Unlock()
			if waitErr != nil {
				return nil, waitErr
			}
			continue
		}
		loadCtx, cancelLoad := context.WithCancel(context.Background())
		pending := &bundleLoad{done: make(chan struct{}), waiters: 1, cancel: cancelLoad}
		f.loads[bundleID] = pending
		f.mu.Unlock()
		go f.runBundleLoad(loadCtx, bundleID, pending)
		if waitErr := f.waitForBundleLoad(ctx, pending); waitErr != nil {
			return nil, waitErr
		}
	}
}

func (f *bundleAnalyzerFactory) waitForBundleLoad(ctx context.Context, pending *bundleLoad) error {
	var waitErr error
	select {
	case <-ctx.Done():
		waitErr = ctx.Err()
	case <-pending.done:
	}
	f.mu.Lock()
	pending.waiters--
	if waitErr != nil && pending.waiters == 0 {
		pending.cancel()
	}
	loadErr := pending.err
	f.mu.Unlock()
	if waitErr != nil {
		return waitErr
	}
	return loadErr
}

func (f *bundleAnalyzerFactory) runBundleLoad(ctx context.Context, bundleID string, pending *bundleLoad) {
	loader := f.load
	if loader == nil {
		loader = f.loadBundle
	}
	analyzer, lookup, estimatedBytes, loadErr := loader(ctx, bundleID)
	if loadErr == nil {
		loadErr = ctx.Err()
	}
	if loadErr == nil && analyzer == nil {
		loadErr = model.NewError(model.CodeBundleUnavailable, "bundle analyzer load returned no analyzer", nil)
	}
	f.mu.Lock()
	if f.loads[bundleID] == pending {
		delete(f.loads, bundleID)
	}
	pending.err = loadErr
	if loadErr == nil {
		f.residents[bundleID] = &residentAnalyzer{
			analyzer: analyzer, lookup: lookup,
			lastUsed: f.nextSequenceLocked(), estimatedBytes: estimatedBytes,
		}
	}
	close(pending.done)
	f.notifyLocked()
	f.mu.Unlock()
}

func (f *bundleAnalyzerFactory) CaptureAnalyzer(ctx context.Context, bundleID string) (jobs.CapturedAnalyzer, error) {
	return f.capture(ctx, bundleID)
}

func (f *bundleAnalyzerFactory) release(bundleID string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	resident := f.residents[bundleID]
	if resident == nil || resident.references == 0 {
		return
	}
	resident.references--
	resident.lastUsed = f.nextSequenceLocked()
	f.notifyLocked()
}

func (f *bundleAnalyzerFactory) residencySnapshot() (int64, int64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ensureStateLocked()
	var estimatedBytes int64
	for _, resident := range f.residents {
		estimatedBytes += resident.estimatedBytes
	}
	return int64(len(f.residents)), estimatedBytes
}

func (f *bundleAnalyzerFactory) capacityWaiterCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.capacityWaiters
}

func (f *bundleAnalyzerFactory) loadWaiterCount(bundleID string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	if pending := f.loads[bundleID]; pending != nil {
		return max(pending.waiters-1, 0)
	}
	return 0
}

func (f *bundleAnalyzerFactory) loadBundle(ctx context.Context, bundleID string) (app.Analyzer, lookupAvailability, int64, error) {
	var analyzer app.Analyzer
	var loadedBundleID string
	var manifest []byte
	var lookup lookupAvailability
	var err error
	if f.controller == nil {
		analyzer, loadedBundleID, manifest, lookup, err = newAnalyzerDetailsForBundle(ctx, f.configuration, f.store, bundleID)
	} else {
		analyzer, loadedBundleID, manifest, lookup, err = newAnalyzerDetailsForBundleWithResources(ctx, f.configuration, f.store, bundleID, f.controller, f.sharedWebDetector)
	}
	if err != nil || loadedBundleID != bundleID {
		return nil, lookupAvailability{}, 0, model.NewError(model.CodeBundleUnavailable, "bundle is unavailable to this detector build", err)
	}
	return analyzer, lookup, estimatedGenerationBytes(manifest), nil
}

func estimatedGenerationBytes(manifest []byte) int64 {
	var parsed datasets.Manifest
	if json.Unmarshal(manifest, &parsed) != nil {
		return 0
	}
	var total int64
	for _, artifact := range parsed.Artifacts {
		if artifact.Size > 0 {
			if artifact.Size > int64(^uint64(0)>>1)-total {
				return int64(^uint64(0) >> 1)
			}
			total += artifact.Size
		}
	}
	return total
}

func (f *bundleAnalyzerFactory) localLookupAvailability() lookupAvailability {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.activeLookup
}

func (f *bundleAnalyzerFactory) Analyze(ctx context.Context, request model.AnalyzeRequest) (model.Report, error) {
	captured, err := f.capture(ctx, "")
	if err != nil {
		return model.Report{}, err
	}
	defer captured.Release()
	return captured.analyzer.Analyze(ctx, request)
}

func (f *bundleAnalyzerFactory) LookupIP(ctx context.Context, request model.IPLookupRequest) (model.IPLookupResult, error) {
	captured, err := f.capture(ctx, "")
	if err != nil {
		return model.IPLookupResult{}, err
	}
	defer captured.Release()
	return captured.analyzer.LookupIP(ctx, request)
}

func (f *bundleAnalyzerFactory) Reclassify(ctx context.Context, request model.ReclassifyRequest) (model.Report, error) {
	captured, err := f.capture(ctx, request.BundleID)
	if err != nil {
		return model.Report{}, err
	}
	defer captured.Release()
	return captured.analyzer.Reclassify(ctx, request)
}

func (f *bundleAnalyzerFactory) ValidateReclassify(ctx context.Context, request model.ReclassifyRequest) error {
	captured, err := f.capture(ctx, request.BundleID)
	if err != nil {
		return err
	}
	defer captured.Release()
	validator, ok := captured.analyzer.(app.ReclassificationValidator)
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
	authority := f.authority
	if authority == nil {
		var ok bool
		authority, ok = f.store.(bundleActivationAuthority)
		if !ok {
			return model.NewError(model.CodePersistenceUnavailable, "committed bundle activation authority is unavailable", nil)
		}
	}
	activation, err := authority.DesiredBundle(ctx)
	if err != nil || activation == nil {
		return err
	}
	repository := f.repository
	if repository == nil {
		repository, err = datasets.NewRepository(f.configuration.Data.BundleDirectory, detectorBuildID)
		if err != nil {
			return err
		}
	}
	if activation.BundleID != builtinBundleID {
		if activation.CandidateHash == "" {
			return fmt.Errorf("committed bundle activation has no candidate hash")
		}
		published, pointerErr := repository.Active()
		if pointerErr != nil || !sameActivation(published, activation) {
			if err := repository.ReconcileAuthoritative(ctx, *activation, authority.DesiredBundle); err != nil {
				if ctx.Err() != nil {
					return ctx.Err()
				}
				_ = repository.RecordLoad(*activation, "failed", err.Error())
				return fmt.Errorf("reconcile committed bundle activation: %w", err)
			}
		}
	}
	f.mu.Lock()
	if activation.OperationID == f.loaded.OperationID && activation.Generation == f.loaded.Generation {
		f.mu.Unlock()
		return nil
	}
	f.mu.Unlock()
	captured, err := f.capture(ctx, activation.BundleID)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		_ = repository.RecordLoad(*activation, "failed", err.Error())
		return err
	}
	if err := ctx.Err(); err != nil {
		captured.Release()
		return err
	}
	f.mu.Lock()
	f.active = captured.analyzer
	f.activeBundleID = activation.BundleID
	f.activeLookup = captured.lookup
	f.loaded = *activation
	f.notifyLocked()
	f.mu.Unlock()
	captured.Release()
	return repository.RecordLoad(*activation, "loaded", "")
}

func sameActivation(left, right *datasets.Activation) bool {
	return left != nil && right != nil &&
		left.OperationID == right.OperationID &&
		left.Generation == right.Generation &&
		left.BundleID == right.BundleID &&
		left.CandidateHash == right.CandidateHash &&
		left.Action == right.Action
}

var _ app.Analyzer = (*bundleAnalyzerFactory)(nil)
var _ app.ReclassificationValidator = (*bundleAnalyzerFactory)(nil)
var _ jobs.AnalyzerFactory = (*bundleAnalyzerFactory)(nil)
var _ jobs.CapturedAnalyzer = (*bundleCapture)(nil)

type serviceMetricsProvider struct {
	durable   observability.Provider
	analyzers *bundleAnalyzerFactory
}

func (p serviceMetricsProvider) OperationalMetrics(ctx context.Context) (observability.Snapshot, error) {
	snapshot, err := p.durable.OperationalMetrics(ctx)
	if err != nil {
		return observability.Snapshot{}, err
	}
	if p.analyzers != nil {
		snapshot.ResidentGenerations, snapshot.EstimatedRetainedBytes = p.analyzers.residencySnapshot()
	}
	return snapshot, nil
}

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
	analyze.Capabilities = append([]model.CapabilityState{{Name: "tls_certificate", Status: model.CoverageUnavailable, Reason: "TLS certificate evidence collection is unsupported"}}, localLookupCapabilities(lookup)...)
	if persistenceReady && !lookup.complete() {
		analyze.State = api.ReadinessDegraded
		analyze.Reason = "TLS certificate evidence and some local attribution data are unavailable"
	} else if persistenceReady {
		analyze.State = api.ReadinessDegraded
		analyze.Reason = "TLS certificate evidence collection is unsupported"
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
	state := api.ReadinessDegraded
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
