package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"cloudattrib/internal/model"
)

const (
	transactionRetryLimit = 4
	transactionRetryBase  = 5 * time.Millisecond
)

// retryReplaySafe reruns a complete transaction after PostgreSQL has explicitly
// rejected it. Other errors, including connection failures with an ambiguous
// commit outcome, are returned without replay.
func retryReplaySafe(ctx context.Context, operation string, run func() error) error {
	var lastErr error
	for attempt := 0; attempt < transactionRetryLimit; attempt++ {
		if err := ctx.Err(); err != nil {
			return persistence(operation, err)
		}
		lastErr = run()
		if lastErr == nil {
			return nil
		}
		if !retriableTransactionError(lastErr) {
			return lastErr
		}
		if attempt+1 == transactionRetryLimit {
			break
		}
		delay := transactionRetryBase << attempt
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return persistence(operation, ctx.Err())
		case <-timer.C:
		}
	}
	return model.NewError(model.CodePersistenceFailed, operation+" retries exhausted", lastErr)
}

func retriableTransactionError(err error) bool {
	var postgresError *pgconn.PgError
	if !errors.As(err, &postgresError) {
		return false
	}
	return postgresError.Code == "40001" || postgresError.Code == "40P01"
}

func (s *Store) replaySafeTransaction(ctx context.Context, operation string, options pgx.TxOptions, body func(pgx.Tx) error) error {
	return retryReplaySafe(ctx, operation, func() error {
		tx, err := s.pool.BeginTx(ctx, options)
		if err != nil {
			return persistence("begin "+operation, err)
		}
		defer func() { _ = tx.Rollback(ctx) }()
		if err := body(tx); err != nil {
			return err
		}
		if err := tx.Commit(ctx); err != nil {
			// PostgreSQL errors 40001 and 40P01 explicitly mean this
			// transaction did not commit. Connection-level commit errors are
			// ambiguous and retryReplaySafe deliberately returns them.
			return persistence("commit "+operation, err)
		}
		return nil
	})
}

func (s *Store) lockLifecycle(ctx context.Context, tx pgx.Tx, operation string) error {
	if hooks := s.transactionHooks; hooks != nil && hooks.beforeLifecycleLock != nil {
		hooks.beforeLifecycleLock(operation)
	}
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, lifecycleLockID); err != nil {
		return persistence("lock "+operation, err)
	}
	if hooks := s.transactionHooks; hooks != nil && hooks.afterLifecycleLock != nil {
		hooks.afterLifecycleLock(operation)
	}
	return nil
}
