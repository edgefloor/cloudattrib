package postgres

import (
	"cloudattrib/internal/jobs"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"time"

	"github.com/jackc/pgx/v5"

	"cloudattrib/internal/ctlog"
	"cloudattrib/internal/inventory"
	"cloudattrib/internal/model"
)

// ImportInventoryChunk atomically publishes a bounded, retryable hostname chunk.
func (s *Store) ImportInventoryChunk(ctx context.Context, receipt inventory.ImportReceipt, payloadHash string, roots []string, sightings []inventory.Sighting, startedAt time.Time) (inventory.ImportReceipt, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return inventory.ImportReceipt{}, persistence("begin inventory import", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	// Tombstones use PostgreSQL's clock. Compare against the same clock so a
	// host/DB clock offset cannot reject a fresh import after deletion.
	if err := tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&startedAt); err != nil {
		return inventory.ImportReceipt{}, persistence("timestamp inventory import", err)
	}
	command, err := tx.Exec(ctx, `INSERT INTO inventory_import_chunks(operation_id,chunk_id,payload_hash) VALUES($1,$2,$3) ON CONFLICT DO NOTHING`, receipt.OperationID, receipt.ChunkID, payloadHash)
	if err != nil {
		return inventory.ImportReceipt{}, persistence("reserve inventory import chunk", err)
	}
	if command.RowsAffected() == 0 {
		var existingHash string
		var counts []byte
		if err := tx.QueryRow(ctx, `SELECT payload_hash,counts FROM inventory_import_chunks WHERE operation_id=$1 AND chunk_id=$2 FOR UPDATE`, receipt.OperationID, receipt.ChunkID).Scan(&existingHash, &counts); err != nil {
			return inventory.ImportReceipt{}, persistence("read inventory import chunk", err)
		}
		if existingHash != payloadHash {
			return inventory.ImportReceipt{}, model.NewError(model.CodeIdempotencyConflict, "inventory import chunk changed", nil)
		}
		if err := json.Unmarshal(counts, &receipt.Counts); err != nil {
			return inventory.ImportReceipt{}, persistence("decode inventory import counts", err)
		}
		return receipt, nil
	}
	// Scope registration and asset publication must see each other at commit.
	// CT transactions take the shared form, so concurrent CT writes still proceed.
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(174120260922)`); err != nil {
		return inventory.ImportReceipt{}, persistence("lock inventory scope registration", err)
	}
	for _, root := range roots {
		if _, err := tx.Exec(ctx, `INSERT INTO inventory_scopes(root) VALUES($1) ON CONFLICT DO NOTHING`, root); err != nil {
			return inventory.ImportReceipt{}, persistence("insert inventory scope", err)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO inventory_memberships(asset_id,root,hostname)
			SELECT asset_id,$1,hostname FROM inventory_assets WHERE hostname=$1 OR hostname LIKE '%.' || $1
			ON CONFLICT DO NOTHING`, root); err != nil {
			return inventory.ImportReceipt{}, persistence("backfill inventory scope membership", err)
		}
	}
	sort.Slice(sightings, func(i, j int) bool { return sightings[i].Hostname < sightings[j].Hostname })
	if s.transactionHooks != nil && s.transactionHooks.beforeInventoryPublish != nil {
		if err := s.transactionHooks.beforeInventoryPublish(); err != nil {
			return inventory.ImportReceipt{}, err
		}
	}
	for _, sighting := range sightings {
		if err := lockInventoryHostname(ctx, tx, sighting.Hostname); err != nil {
			return inventory.ImportReceipt{}, err
		}
		var suppressed, stale bool
		if err := tx.QueryRow(ctx, `SELECT COALESCE((SELECT suppressed FROM inventory_tombstones WHERE hostname=$1),false),
			COALESCE((SELECT deleted_at >= $2 FROM inventory_tombstones WHERE hostname=$1),false)`, sighting.Hostname, startedAt).Scan(&suppressed, &stale); err != nil {
			return inventory.ImportReceipt{}, persistence("read inventory suppression", err)
		}
		if suppressed {
			receipt.Counts.Suppressed++
			continue
		}
		if stale {
			receipt.Counts.Stale++
			continue
		}
		command, err := tx.Exec(ctx, `INSERT INTO inventory_assets(asset_id,hostname,reversed_labels,normalization_version,deletion_generation)
			VALUES($1,$2,$3,$4,COALESCE((SELECT deletion_generation FROM inventory_tombstones WHERE hostname=$2),0))
			ON CONFLICT (hostname) DO NOTHING`, sighting.AssetID, sighting.Hostname, sighting.ReversedLabels, sighting.NormalizationVersion)
		if err != nil {
			return inventory.ImportReceipt{}, persistence("insert inventory asset", err)
		}
		if command.RowsAffected() == 1 {
			receipt.Counts.Accepted++
		} else {
			receipt.Counts.Duplicate++
		}
		if err := upsertInventorySighting(ctx, tx, sighting, "hostname_import", "imported_unverified", "unverified", "", "", "", ""); err != nil {
			return inventory.ImportReceipt{}, err
		}
	}
	counts, err := json.Marshal(receipt.Counts)
	if err != nil {
		return inventory.ImportReceipt{}, fmt.Errorf("encode inventory import counts: %w", err)
	}
	if _, err := tx.Exec(ctx, `UPDATE inventory_import_chunks SET counts=$3 WHERE operation_id=$1 AND chunk_id=$2`, receipt.OperationID, receipt.ChunkID, counts); err != nil {
		return inventory.ImportReceipt{}, persistence("store inventory import counts", err)
	}
	if s.transactionHooks != nil && s.transactionHooks.beforeInventoryCommit != nil {
		if err := s.transactionHooks.beforeInventoryCommit(); err != nil {
			return inventory.ImportReceipt{}, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return inventory.ImportReceipt{}, persistence("commit inventory import", err)
	}
	return receipt, nil
}

func lockInventoryHostname(ctx context.Context, tx pgx.Tx, hostname string) error {
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, hostname); err != nil {
		return persistence("lock inventory hostname", err)
	}
	return nil
}

// RegisterInventoryScopes makes CT source scopes available before publishing names.
func (s *Store) RegisterInventoryScopes(ctx context.Context, rawRoots []string) error {
	if len(rawRoots) == 0 || len(rawRoots) > 32 {
		return model.NewError(model.CodeInvalidOptions, "inventory scopes must contain 1 to 32 roots", nil)
	}
	roots := make([]string, 0, len(rawRoots))
	for _, raw := range rawRoots {
		root, _, err := inventory.Normalize(raw)
		if err != nil {
			return err
		}
		roots = append(roots, root)
	}
	sort.Strings(roots)
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return persistence("begin inventory scope registration", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(174120260922)`); err != nil {
		return persistence("lock inventory scope registration", err)
	}
	for _, root := range roots {
		if _, err := tx.Exec(ctx, `INSERT INTO inventory_scopes(root) VALUES($1) ON CONFLICT DO NOTHING`, root); err != nil {
			return persistence("register inventory scope", err)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO inventory_memberships(asset_id,root,hostname)
			SELECT asset_id,$1,hostname FROM inventory_assets WHERE hostname=$1 OR hostname LIKE '%.' || $1
			ON CONFLICT DO NOTHING`, root); err != nil {
			return persistence("backfill inventory scope", err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return persistence("commit inventory scope registration", err)
	}
	return nil
}

func upsertInventorySighting(ctx context.Context, tx pgx.Tx, sighting inventory.Sighting, kind, provenance, verification, reference, logID, entryIndex, checkpointID string) error {
	if _, err := tx.Exec(ctx, `INSERT INTO inventory_memberships(asset_id,root,hostname)
		SELECT $1,root,$2 FROM inventory_scopes WHERE $2=root OR $2 LIKE '%.' || root
		ON CONFLICT DO NOTHING`, sighting.AssetID, sighting.Hostname); err != nil {
		return persistence("link inventory scopes", err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO inventory_sources(asset_id,source_kind,source_id,provenance,verification,first_observed_at,last_observed_at,provenance_ref,log_id,entry_index,checkpoint_id)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
		ON CONFLICT (asset_id,source_kind,source_id,provenance) DO UPDATE SET
		verification=EXCLUDED.verification,
		first_observed_at=LEAST(inventory_sources.first_observed_at,EXCLUDED.first_observed_at),
		last_observed_at=GREATEST(inventory_sources.last_observed_at,EXCLUDED.last_observed_at),
		last_received_at=clock_timestamp(),provenance_ref=EXCLUDED.provenance_ref,
		log_id=EXCLUDED.log_id,entry_index=EXCLUDED.entry_index,checkpoint_id=EXCLUDED.checkpoint_id`,
		sighting.AssetID, kind, sighting.SourceID, provenance, verification, sighting.FirstObservedAt, sighting.LastObservedAt, reference, logID, entryIndex, checkpointID); err != nil {
		return persistence("upsert inventory source", err)
	}
	return nil
}

func upsertCTInventory(ctx context.Context, tx pgx.Tx, record ctlog.Record, startedAt time.Time) error {
	if record.Wildcard {
		return nil
	}
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock_shared(174120260922)`); err != nil {
		return persistence("lock inventory scope publication", err)
	}
	hostname, version, err := inventory.Normalize(record.Name)
	if err != nil {
		return fmt.Errorf("normalize CT inventory name: %w", err)
	}
	if err := lockInventoryHostname(ctx, tx, hostname); err != nil {
		return err
	}
	var suppressed, stale bool
	if err := tx.QueryRow(ctx, `SELECT COALESCE((SELECT suppressed FROM inventory_tombstones WHERE hostname=$1),false),
		COALESCE((SELECT deleted_at >= $2 FROM inventory_tombstones WHERE hostname=$1),false)`, hostname, startedAt).Scan(&suppressed, &stale); err != nil {
		return persistence("read CT inventory suppression", err)
	}
	if suppressed || stale {
		return nil
	}
	sighting := inventory.Sighting{
		AssetID: inventory.AssetID(hostname), Hostname: hostname, ReversedLabels: inventory.ReverseLabels(hostname),
		NormalizationVersion: version, SourceID: boundedInventorySourceID(record.SourceID),
		FirstObservedAt: &record.LoggedAt, LastObservedAt: &record.LoggedAt,
	}
	if _, err := tx.Exec(ctx, `INSERT INTO inventory_assets(asset_id,hostname,reversed_labels,normalization_version,deletion_generation)
		VALUES($1,$2,$3,$4,COALESCE((SELECT deletion_generation FROM inventory_tombstones WHERE hostname=$2),0))
		ON CONFLICT (hostname) DO NOTHING`, sighting.AssetID, hostname, sighting.ReversedLabels, version); err != nil {
		return persistence("insert CT inventory asset", err)
	}
	reference := record.CertificateHash
	if len(reference) > 255 {
		digest := sha256.Sum256([]byte(reference))
		reference = "sha256:" + hex.EncodeToString(digest[:])
	}
	entryIndex := ""
	if record.EntryIndex != nil {
		entryIndex = fmt.Sprint(*record.EntryIndex)
	}
	return upsertInventorySighting(ctx, tx, sighting, "ct", string(record.Provenance), string(record.Provenance), reference,
		boundedInventorySourceID(record.LogID), entryIndex, boundedInventorySourceID(record.CheckpointID))
}

func boundedInventorySourceID(source string) string {
	if len(source) <= 128 {
		return source
	}
	digest := sha256.Sum256([]byte(source))
	return "source-sha256:" + hex.EncodeToString(digest[:])
}

func publishReportInventory(ctx context.Context, tx pgx.Tx, report model.Report, selection *jobs.InventorySelection) error {
	raw := ""
	switch report.Target.Kind {
	case model.TargetDomain:
		raw = report.Target.Canonical
	case model.TargetURL:
		parsed, err := url.Parse(report.Target.Canonical)
		if err != nil {
			return model.NewError(model.CodeInvalidOptions, "report target URL is invalid", err)
		}
		raw = parsed.Hostname()
	default:
		return nil
	}
	hostname, version, err := inventory.Normalize(raw)
	if err != nil {
		return model.NewError(model.CodeInvalidOptions, "report target hostname is invalid", err)
	}
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock_shared(174120260922)`); err != nil {
		return persistence("lock report inventory scope publication", err)
	}
	if err := lockInventoryHostname(ctx, tx, hostname); err != nil {
		return err
	}
	startedAt := report.StartedAt
	var suppressed, stale bool
	if err := tx.QueryRow(ctx, `SELECT COALESCE((SELECT suppressed FROM inventory_tombstones WHERE hostname=$1),false),
		COALESCE((SELECT deleted_at >= $2 FROM inventory_tombstones WHERE hostname=$1),false)`, hostname, startedAt).Scan(&suppressed, &stale); err != nil {
		return persistence("read report inventory deletion", err)
	}
	if suppressed || stale {
		return nil
	}
	assetID := inventory.AssetID(hostname)
	if selection != nil {
		var generation int64
		err := tx.QueryRow(ctx, `SELECT deletion_generation FROM inventory_assets WHERE asset_id=$1 AND hostname=$2 FOR UPDATE`, selection.AssetID, hostname).Scan(&generation)
		if errors.Is(err, pgx.ErrNoRows) || err == nil && generation != selection.DeletionGeneration {
			return nil
		}
		if err != nil {
			return persistence("validate selected inventory asset generation", err)
		}
		assetID = selection.AssetID
	} else {
		if _, err := tx.Exec(ctx, `INSERT INTO inventory_assets(asset_id,hostname,reversed_labels,normalization_version,deletion_generation)
			VALUES($1,$2,$3,$4,COALESCE((SELECT deletion_generation FROM inventory_tombstones WHERE hostname=$2),0))
			ON CONFLICT (hostname) DO NOTHING`, assetID, hostname, inventory.ReverseLabels(hostname), version); err != nil {
			return persistence("insert report inventory asset", err)
		}
	}
	sighting := inventory.Sighting{AssetID: assetID, Hostname: hostname, SourceID: boundedInventorySourceID(report.ID)}
	for _, observation := range report.Observations {
		if observation.Subject != hostname || observation.ObservedAt.IsZero() {
			continue
		}
		observed := observation.ObservedAt
		if sighting.FirstObservedAt == nil || observed.Before(*sighting.FirstObservedAt) {
			sighting.FirstObservedAt = &observed
		}
		if sighting.LastObservedAt == nil || observed.After(*sighting.LastObservedAt) {
			sighting.LastObservedAt = &observed
		}
	}
	verification := "attempted"
	if sighting.LastObservedAt != nil {
		verification = "collected"
	}
	if err := upsertInventorySighting(ctx, tx, sighting, "report", "report", verification, "", "", "", ""); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO inventory_projection_tasks(report_id,projector_version,deletion_generation)
		SELECT $1,$2,deletion_generation FROM inventory_assets WHERE asset_id=$3
		ON CONFLICT (report_id,projector_version) DO UPDATE SET status='pending',attempts=0,
			lease_token=NULL,lease_expires_at=NULL,next_attempt_at=NULL,last_error='',updated_at=clock_timestamp()
		WHERE inventory_projection_tasks.status='failed' AND inventory_projection_tasks.attempts>=5`,
		report.ID, inventory.DescriptionFormatVersion, assetID); err != nil {
		return persistence("queue inventory report projection", err)
	}
	return nil
}
