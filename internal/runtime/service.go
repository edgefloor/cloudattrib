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
	"strings"
	"time"

	"cloudattrib/internal/api"
	"cloudattrib/internal/app"
	"cloudattrib/internal/config"
	"cloudattrib/internal/jobs"
	"cloudattrib/internal/model"
	"cloudattrib/internal/store/postgres"
)

const builtinBundleID = "builtin-rules-v1"

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
	if err := store.RegisterBundle(ctx, builtinBundleID, []byte(`{"schema_version":1,"bundle_id":"builtin-rules-v1"}`), true); err != nil {
		return fmt.Errorf("register builtin bundle: %w", err)
	}
	analyzer, err := newAnalyzer(configuration, store)
	if err != nil {
		return err
	}
	authentication, err := serviceAuthentication(configuration.API)
	if err != nil {
		return err
	}
	handler, err := api.NewHandler(api.Config{
		Analyzer: analyzer, Jobs: store, Results: store, Findings: store, Authentication: authentication,
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
		Runner:  jobs.Runner{Store: store, Factory: fixedAnalyzerFactory{analyzer: analyzer}, WorkerID: "service-worker", Lease: configuration.Storage.LeaseDuration},
		Workers: configuration.Limits.ConcurrentTargets, PollInterval: 100 * time.Millisecond,
		RecoveryInterval: max(configuration.Storage.LeaseDuration/2, time.Second), MaximumAttempts: configuration.Storage.MaximumAttempts,
		OnError: func(workerErr error) { log.Printf("cloudattrib worker: %v", workerErr) },
	}
	workerCtx, stopWorkers := context.WithCancel(ctx)
	defer stopWorkers()
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
	select {
	case <-ctx.Done():
		runErr = ctx.Err()
	case err := <-workerErr:
		if !errors.Is(err, context.Canceled) {
			runErr = fmt.Errorf("job supervisor stopped: %w", err)
		}
	case err := <-serverErr:
		if !errors.Is(err, http.ErrServerClosed) {
			runErr = fmt.Errorf("serve API: %w", err)
		}
	}
	stopWorkers()
	shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	if err := server.Shutdown(shutdownCtx); err != nil && runErr == nil {
		runErr = fmt.Errorf("shut down API: %w", err)
	}
	return runErr
}

type fixedAnalyzerFactory struct{ analyzer app.Analyzer }

func (f fixedAnalyzerFactory) AnalyzerForBundle(_ context.Context, bundleID string) (app.Analyzer, error) {
	if bundleID != "" && bundleID != builtinBundleID {
		return nil, model.NewError(model.CodeBundleUnavailable, "bundle is unavailable to this detector build", nil)
	}
	return f.analyzer, nil
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
	authentication := api.Authentication{
		Mode: api.AuthenticationMode(configuration.AuthenticationMode), Credentials: configuration.Credentials,
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
