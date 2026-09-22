package postgres

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"golang.org/x/sys/unix"

	"cloudattrib/internal/datasets"
)

const (
	activationCrashModeEnv      = "CLOUDATTRIB_ACTIVATION_CRASH_HELPER"
	activationCrashRootEnv      = "CLOUDATTRIB_ACTIVATION_CRASH_ROOT"
	activationCrashCandidateEnv = "CLOUDATTRIB_ACTIVATION_CRASH_CANDIDATE"
	activationCrashHashEnv      = "CLOUDATTRIB_ACTIVATION_CRASH_HASH"
	activationCrashMarkerEnv    = "CLOUDATTRIB_ACTIVATION_CRASH_MARKER"
	activationCrashIdentityEnv  = "CLOUDATTRIB_ACTIVATION_CRASH_IDENTITY"
)

func TestPostgresActivationConvergesAcrossProcessTerminationBoundaries(t *testing.T) {
	store, ctx := openPostgresTest(t, 1)
	repositoryRoot := filepath.Join(t.TempDir(), "bundles")
	repository, err := datasets.NewRepository(repositoryRoot, "build-a")
	if err != nil {
		t.Fatal(err)
	}
	first, err := repository.Import(ctx, activationCrashFixtureSources(t, "crash-first"))
	if err != nil {
		t.Fatal(err)
	}
	firstActivation, err := repository.ActivateCommitted(ctx, first.CandidateID, first.CandidateHash, "activate", func(proposed datasets.Activation, _ datasets.Manifest, manifest []byte) (datasets.Activation, error) {
		return store.CommitBundleActivation(ctx, proposed, manifest, true)
	})
	if err != nil {
		t.Fatalf("activate initial generation: %v", err)
	}
	second, err := repository.Import(ctx, activationCrashFixtureSources(t, "crash-second"))
	if err != nil {
		t.Fatal(err)
	}

	t.Run("termination before commit leaves no generation to adopt", func(t *testing.T) {
		marker := filepath.Join(t.TempDir(), "before-commit")
		identityPath := marker + "-identity.json"
		process := startActivationCrashHelper(t, "before_commit", repositoryRoot, second, marker, identityPath)
		waitForActivationCrashMarker(t, process, marker)
		proposed := readActivationCrashIdentity(t, identityPath)
		killActivationCrashHelper(t, process)

		committed, err := store.BundleActivation(ctx, proposed.OperationID)
		if err != nil {
			t.Fatalf("load killed transaction operation: %v", err)
		}
		if committed != nil {
			t.Fatalf("uncommitted operation was adopted: %#v", committed)
		}
		assertActivationCrashState(t, ctx, store, repository, firstActivation)
	})

	var committedIdentity datasets.Activation
	t.Run("termination after commit precedes filesystem publication", func(t *testing.T) {
		marker := filepath.Join(t.TempDir(), "after-commit")
		identityPath := marker + "-identity.json"
		process := startActivationCrashHelper(t, "after_commit", repositoryRoot, second, marker, identityPath)
		waitForActivationCrashMarker(t, process, marker)
		committedIdentity = readActivationCrashIdentity(t, identityPath)
		killActivationCrashHelper(t, process)

		desired, err := store.DesiredBundle(ctx)
		if err != nil || desired == nil {
			t.Fatalf("DesiredBundle() after committed crash = %#v, %v", desired, err)
		}
		if desired.OperationID != committedIdentity.OperationID || desired.BundleID != second.CandidateID || desired.Generation <= firstActivation.Generation {
			t.Fatalf("desired activation after committed crash = %#v, proposed %#v", desired, committedIdentity)
		}
		committedIdentity = *desired
		active, err := repository.Active()
		if err != nil || active == nil || active.OperationID != firstActivation.OperationID {
			t.Fatalf("filesystem pointer advanced before publication: %#v, %v", active, err)
		}
		byIdentity, err := store.BundleActivation(ctx, committedIdentity.OperationID)
		if err != nil || byIdentity == nil || byIdentity.Generation != committedIdentity.Generation {
			t.Fatalf("BundleActivation(%q) = %#v, %v", committedIdentity.OperationID, byIdentity, err)
		}
	})

	t.Run("termination during reconciliation converges after restart", func(t *testing.T) {
		auditPath := filepath.Join(repositoryRoot, "activation-audit.jsonl")
		if err := os.Remove(auditPath); err != nil {
			t.Fatalf("remove activation audit: %v", err)
		}
		if err := unix.Mkfifo(auditPath, 0o600); err != nil {
			t.Fatalf("create blocking activation audit FIFO: %v", err)
		}

		process := startActivationCrashHelper(t, "reconcile", repositoryRoot, datasets.ValidationReport{}, "", "")
		waitForActivationCrashPointer(t, process, repository, committedIdentity.OperationID)
		killActivationCrashHelper(t, process)
		if err := os.Remove(auditPath); err != nil {
			t.Fatalf("remove blocking activation audit FIFO: %v", err)
		}

		runActivationCrashHelper(t, "reconcile", repositoryRoot, datasets.ValidationReport{}, "", "")
		assertActivationCrashState(t, ctx, store, repository, committedIdentity)
	})
}

func TestActivationCrashHelperProcess(t *testing.T) {
	mode := os.Getenv(activationCrashModeEnv)
	if mode == "" {
		t.Skip("activation crash helper is started by its parent integration test")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	store, err := Open(ctx, os.Getenv("CLOUDATTRIB_POSTGRES_TEST_DSN"), 10_000)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	repository, err := datasets.NewRepository(os.Getenv(activationCrashRootEnv), "build-a")
	if err != nil {
		t.Fatal(err)
	}
	if mode == "reconcile" {
		desired, err := store.DesiredBundle(ctx)
		if err != nil || desired == nil {
			t.Fatalf("load desired activation: %#v, %v", desired, err)
		}
		if err := repository.ReconcileAuthoritative(ctx, *desired, store.DesiredBundle); err != nil {
			t.Fatalf("reconcile desired activation: %v", err)
		}
		return
	}

	candidateID := os.Getenv(activationCrashCandidateEnv)
	candidateHash := os.Getenv(activationCrashHashEnv)
	_, err = repository.ActivateCommitted(ctx, candidateID, candidateHash, "activate", func(proposed datasets.Activation, _ datasets.Manifest, manifest []byte) (datasets.Activation, error) {
		writeActivationCrashIdentity(t, os.Getenv(activationCrashIdentityEnv), proposed)
		switch mode {
		case "before_commit":
			store.transactionHooks = &transactionHooks{beforeActivationCommit: func(pgx.Tx) {
				pauseActivationCrashHelper(t, os.Getenv(activationCrashMarkerEnv))
			}}
		case "after_commit":
			store.transactionHooks = &transactionHooks{afterActivationCommit: func() error {
				pauseActivationCrashHelper(t, os.Getenv(activationCrashMarkerEnv))
				return nil
			}}
		default:
			t.Fatalf("unknown activation crash mode %q", mode)
		}
		return store.CommitBundleActivation(ctx, proposed, manifest, true)
	})
	if err != nil {
		t.Fatalf("activation helper returned before termination: %v", err)
	}
}

type activationCrashProcess struct {
	command  *exec.Cmd
	done     chan error
	output   *bytes.Buffer
	finished atomic.Bool
}

func startActivationCrashHelper(t *testing.T, mode, root string, candidate datasets.ValidationReport, marker, identityPath string) *activationCrashProcess {
	t.Helper()
	command := exec.Command(os.Args[0], "-test.run=^TestActivationCrashHelperProcess$")
	command.Env = append(os.Environ(),
		activationCrashModeEnv+"="+mode,
		activationCrashRootEnv+"="+root,
		activationCrashCandidateEnv+"="+candidate.CandidateID,
		activationCrashHashEnv+"="+candidate.CandidateHash,
		activationCrashMarkerEnv+"="+marker,
		activationCrashIdentityEnv+"="+identityPath,
	)
	output := &bytes.Buffer{}
	command.Stdout = output
	command.Stderr = output
	if err := command.Start(); err != nil {
		t.Fatalf("start activation crash helper: %v", err)
	}
	process := &activationCrashProcess{command: command, done: make(chan error, 1), output: output}
	go func() {
		err := command.Wait()
		process.finished.Store(true)
		process.done <- err
	}()
	t.Cleanup(func() {
		if !process.finished.Load() {
			_ = command.Process.Kill()
			select {
			case <-process.done:
			case <-time.After(5 * time.Second):
			}
		}
	})
	return process
}

func runActivationCrashHelper(t *testing.T, mode, root string, candidate datasets.ValidationReport, marker, identityPath string) {
	t.Helper()
	command := exec.Command(os.Args[0], "-test.run=^TestActivationCrashHelperProcess$")
	command.Env = append(os.Environ(),
		activationCrashModeEnv+"="+mode,
		activationCrashRootEnv+"="+root,
		activationCrashCandidateEnv+"="+candidate.CandidateID,
		activationCrashHashEnv+"="+candidate.CandidateHash,
		activationCrashMarkerEnv+"="+marker,
		activationCrashIdentityEnv+"="+identityPath,
	)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("restart activation helper: %v\n%s", err, output)
	}
}

func waitForActivationCrashMarker(t *testing.T, process *activationCrashProcess, path string) {
	t.Helper()
	waitForActivationCrashCondition(t, process, func() bool {
		_, err := os.Stat(path)
		return err == nil
	}, "helper marker "+path)
}

func waitForActivationCrashPointer(t *testing.T, process *activationCrashProcess, repository *datasets.Repository, operationID string) {
	t.Helper()
	waitForActivationCrashCondition(t, process, func() bool {
		active, err := repository.Active()
		return err == nil && active != nil && active.OperationID == operationID
	}, "reconciled filesystem pointer")
}

func waitForActivationCrashCondition(t *testing.T, process *activationCrashProcess, condition func() bool, description string) {
	t.Helper()
	deadline := time.NewTimer(10 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		if condition() {
			return
		}
		select {
		case err := <-process.done:
			t.Fatalf("activation crash helper exited before %s: %v\n%s", description, err, process.output.String())
		case <-deadline.C:
			t.Fatalf("timed out waiting for %s\n%s", description, process.output.String())
		case <-ticker.C:
		}
	}
}

func killActivationCrashHelper(t *testing.T, process *activationCrashProcess) {
	t.Helper()
	if err := process.command.Process.Kill(); err != nil {
		t.Fatalf("kill activation crash helper: %v", err)
	}
	if err := <-process.done; err == nil {
		t.Fatal("activation crash helper exited successfully after SIGKILL")
	}
}

func pauseActivationCrashHelper(t *testing.T, marker string) {
	t.Helper()
	if err := os.WriteFile(marker, []byte("ready\n"), 0o600); err != nil {
		t.Fatalf("write activation crash marker: %v", err)
	}
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(signals)
	<-signals
}

func writeActivationCrashIdentity(t *testing.T, path string, activation datasets.Activation) {
	t.Helper()
	data, err := json.Marshal(activation)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(data, '\n'), 0o600); err != nil {
		t.Fatalf("write activation crash identity: %v", err)
	}
}

func readActivationCrashIdentity(t *testing.T, path string) datasets.Activation {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var activation datasets.Activation
	if err := json.Unmarshal(data, &activation); err != nil {
		t.Fatal(err)
	}
	return activation
}

func assertActivationCrashState(t *testing.T, ctx context.Context, store *Store, repository *datasets.Repository, want datasets.Activation) {
	t.Helper()
	desired, err := store.DesiredBundle(ctx)
	if err != nil || desired == nil || desired.OperationID != want.OperationID || desired.Generation != want.Generation || desired.BundleID != want.BundleID {
		t.Fatalf("desired activation = %#v, %v; want %#v", desired, err, want)
	}
	active, err := repository.Active()
	if err != nil || active == nil || active.OperationID != want.OperationID || active.Generation != want.Generation || active.BundleID != want.BundleID {
		t.Fatalf("active activation = %#v, %v; want %#v", active, err, want)
	}
}

func activationCrashFixtureSources(t *testing.T, token string) string {
	t.Helper()
	directory := t.TempDir()
	fixtures := []string{
		"aws-ip-ranges.json",
		"gcp-cloud.json",
		"azure-service-tags.json",
		"cdncheck-sources-data.json",
		"iptoasn-v4.tsv",
		"iptoasn-v6.tsv",
	}
	for _, name := range fixtures {
		data, err := os.ReadFile(filepath.Join("..", "..", "..", "testdata", "upstream", name))
		if err != nil {
			t.Fatalf("read fixture %s: %v", name, err)
		}
		if name == "aws-ip-ranges.json" {
			data = []byte(strings.Replace(string(data), "fixture-1", token, 1))
		}
		if err := os.WriteFile(filepath.Join(directory, name), data, 0o600); err != nil {
			t.Fatalf("write fixture %s: %v", name, err)
		}
	}
	return directory
}
