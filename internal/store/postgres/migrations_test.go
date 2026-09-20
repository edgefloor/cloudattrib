package postgres

import (
	"strings"
	"testing"
)

func TestInitialMigrationContainsLifecycleAndReportConstraints(t *testing.T) {
	t.Parallel()

	for _, fragment := range []string{
		"UNIQUE (operator_id, idempotency_key)",
		"CREATE TABLE IF NOT EXISTS bundle_pins",
		"CHECK (reserved_targets >= 0)",
		"attempt_token text",
		"FOREIGN KEY (report_id, evidence_id)",
		"job_targets_claim_idx",
	} {
		if !strings.Contains(initialMigration, fragment) {
			t.Fatalf("migration does not contain %q", fragment)
		}
	}
}

func TestCTMigrationContainsRecordAndCheckpointConstraints(t *testing.T) {
	t.Parallel()

	for _, fragment := range []string{
		"CREATE TABLE IF NOT EXISTS ct_records",
		"PRIMARY KEY (name, certificate_hash, source_id)",
		"CREATE TABLE IF NOT EXISTS ct_checkpoints",
		"CHECK (verified_tree_size >= 0)",
	} {
		if !strings.Contains(ctMigration, fragment) {
			t.Fatalf("CT migration does not contain %q", fragment)
		}
	}
}
