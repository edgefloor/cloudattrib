package postgres

import (
	"context"
	_ "embed"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed migrations/001_initial.sql
var initialMigration string

//go:embed migrations/002_bundle_lifecycle.sql
var bundleLifecycleMigration string

//go:embed migrations/003_ct.sql
var ctMigration string

//go:embed migrations/004_activation_generations.sql
var activationGenerationMigration string

// Migrate applies the idempotent initial schema under a database advisory lock.
func Migrate(ctx context.Context, pool *pgxpool.Pool, maximumTargets int) error {
	if maximumTargets <= 0 {
		return fmt.Errorf("maximum targets must be positive")
	}
	transaction, err := pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin migration: %w", err)
	}
	defer func() { _ = transaction.Rollback(ctx) }()
	if _, err := transaction.Exec(ctx, `SELECT pg_advisory_xact_lock(174120260920)`); err != nil {
		return fmt.Errorf("lock migrations: %w", err)
	}
	if _, err := transaction.Exec(ctx, initialMigration); err != nil {
		return fmt.Errorf("apply initial migration: %w", err)
	}
	if _, err := transaction.Exec(ctx, `INSERT INTO schema_migrations(version) VALUES (1) ON CONFLICT DO NOTHING`); err != nil {
		return fmt.Errorf("record migration: %w", err)
	}
	if _, err := transaction.Exec(ctx, bundleLifecycleMigration); err != nil {
		return fmt.Errorf("apply bundle lifecycle migration: %w", err)
	}
	if _, err := transaction.Exec(ctx, `INSERT INTO schema_migrations(version) VALUES (2) ON CONFLICT DO NOTHING`); err != nil {
		return fmt.Errorf("record bundle lifecycle migration: %w", err)
	}
	if _, err := transaction.Exec(ctx, ctMigration); err != nil {
		return fmt.Errorf("apply CT migration: %w", err)
	}
	if _, err := transaction.Exec(ctx, `INSERT INTO schema_migrations(version) VALUES (3) ON CONFLICT DO NOTHING`); err != nil {
		return fmt.Errorf("record CT migration: %w", err)
	}
	if _, err := transaction.Exec(ctx, activationGenerationMigration); err != nil {
		return fmt.Errorf("apply activation generation migration: %w", err)
	}
	if _, err := transaction.Exec(ctx, `INSERT INTO schema_migrations(version) VALUES (4) ON CONFLICT DO NOTHING`); err != nil {
		return fmt.Errorf("record activation generation migration: %w", err)
	}
	capacity, err := transaction.Exec(ctx, `INSERT INTO queue_capacity(singleton,reserved_targets,maximum_targets) VALUES (true,0,$1) ON CONFLICT (singleton) DO UPDATE SET maximum_targets=EXCLUDED.maximum_targets WHERE queue_capacity.reserved_targets <= EXCLUDED.maximum_targets`, maximumTargets)
	if err != nil {
		return fmt.Errorf("initialize queue capacity: %w", err)
	}
	if capacity.RowsAffected() != 1 {
		return fmt.Errorf("maximum targets is below current reservations")
	}
	if err := transaction.Commit(ctx); err != nil {
		return fmt.Errorf("commit migration: %w", err)
	}
	return nil
}
