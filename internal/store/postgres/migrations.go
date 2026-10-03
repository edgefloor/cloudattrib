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

//go:embed migrations/005_observation_page.sql
var observationPageMigration string

//go:embed migrations/006_inventory.sql
var inventoryMigration string

//go:embed migrations/007_inventory_evidence.sql
var inventoryEvidenceMigration string

//go:embed migrations/008_report_retention.sql
var reportRetentionMigration string

//go:embed migrations/009_inventory_embeddings.sql
var inventoryEmbeddingMigration string

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
	if _, err := transaction.Exec(ctx, observationPageMigration); err != nil {
		return fmt.Errorf("apply observation page migration: %w", err)
	}
	if _, err := transaction.Exec(ctx, `INSERT INTO schema_migrations(version) VALUES (5) ON CONFLICT DO NOTHING`); err != nil {
		return fmt.Errorf("record observation page migration: %w", err)
	}
	if _, err := transaction.Exec(ctx, inventoryMigration); err != nil {
		return fmt.Errorf("apply inventory migration: %w", err)
	}
	if _, err := transaction.Exec(ctx, `INSERT INTO schema_migrations(version) VALUES (6) ON CONFLICT DO NOTHING`); err != nil {
		return fmt.Errorf("record inventory migration: %w", err)
	}
	if _, err := transaction.Exec(ctx, inventoryEvidenceMigration); err != nil {
		return fmt.Errorf("apply inventory evidence migration: %w", err)
	}
	if _, err := transaction.Exec(ctx, `INSERT INTO schema_migrations(version) VALUES (7) ON CONFLICT DO NOTHING`); err != nil {
		return fmt.Errorf("record inventory evidence migration: %w", err)
	}
	if _, err := transaction.Exec(ctx, reportRetentionMigration); err != nil {
		return fmt.Errorf("apply report retention migration: %w", err)
	}
	if _, err := transaction.Exec(ctx, `INSERT INTO schema_migrations(version) VALUES (8) ON CONFLICT DO NOTHING`); err != nil {
		return fmt.Errorf("record report retention migration: %w", err)
	}
	if _, err := transaction.Exec(ctx, inventoryEmbeddingMigration); err != nil {
		return fmt.Errorf("apply inventory embedding migration: %w", err)
	}
	if _, err := transaction.Exec(ctx, `INSERT INTO schema_migrations(version) VALUES (9) ON CONFLICT DO NOTHING`); err != nil {
		return fmt.Errorf("record inventory embedding migration: %w", err)
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
