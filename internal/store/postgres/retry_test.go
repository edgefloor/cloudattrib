package postgres

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"

	"cloudattrib/internal/model"
)

func TestRetryReplaySafeRetriesSerializationFailuresAndDeadlocks(t *testing.T) {
	t.Parallel()

	errorsByAttempt := []error{
		&pgconn.PgError{Code: "40001", Message: "serialization failure"},
		&pgconn.PgError{Code: "40P01", Message: "deadlock detected"},
		nil,
	}
	attempts := 0
	err := retryReplaySafe(t.Context(), "fixture transaction", func() error {
		err := errorsByAttempt[attempts]
		attempts++
		return err
	})
	if err != nil {
		t.Fatalf("retryReplaySafe() error = %v", err)
	}
	if attempts != len(errorsByAttempt) {
		t.Fatalf("attempts = %d, want %d", attempts, len(errorsByAttempt))
	}
}

func TestRetryReplaySafeStopsAfterBoundedAttempts(t *testing.T) {
	t.Parallel()

	attempts := 0
	err := retryReplaySafe(t.Context(), "fixture transaction", func() error {
		attempts++
		return &pgconn.PgError{Code: "40001", Message: "serialization failure"}
	})
	if model.ErrorCodeOf(err) != model.CodePersistenceFailed {
		t.Fatalf("retryReplaySafe() error = %v, want persistence_failed", err)
	}
	if attempts != transactionRetryLimit {
		t.Fatalf("attempts = %d, want %d", attempts, transactionRetryLimit)
	}
}

func TestRetryReplaySafeHonorsCancellationWhileWaiting(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(t.Context())
	attempts := 0
	err := retryReplaySafe(ctx, "fixture transaction", func() error {
		attempts++
		cancel()
		return &pgconn.PgError{Code: "40P01", Message: "deadlock detected"}
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("retryReplaySafe() error = %v, want context cancellation", err)
	}
	if attempts != 1 {
		t.Fatalf("attempts = %d, want 1", attempts)
	}
}

func TestRetryReplaySafeDoesNotRetryOtherFailures(t *testing.T) {
	t.Parallel()

	want := &pgconn.PgError{Code: "23505", Message: "unique violation"}
	attempts := 0
	err := retryReplaySafe(t.Context(), "fixture transaction", func() error {
		attempts++
		return want
	})
	if !errors.Is(err, want) {
		t.Fatalf("retryReplaySafe() error = %v, want %v", err, want)
	}
	if attempts != 1 {
		t.Fatalf("attempts = %d, want 1", attempts)
	}
}

func TestRetryReplaySafeDoesNotRetryAmbiguousCommitFailure(t *testing.T) {
	t.Parallel()

	want := errors.New("connection lost while committing")
	attempts := 0
	err := retryReplaySafe(t.Context(), "fixture transaction", func() error {
		attempts++
		return want
	})
	if !errors.Is(err, want) {
		t.Fatalf("retryReplaySafe() error = %v, want %v", err, want)
	}
	if attempts != 1 {
		t.Fatalf("attempts = %d, want 1", attempts)
	}
}
