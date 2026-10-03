package postgres

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"cloudattrib/internal/ctlog"
	"cloudattrib/internal/inventory"
	"cloudattrib/internal/model"
)

type inventoryBackfillCursor struct {
	Name        string `json:"name"`
	Certificate string `json:"certificate"`
	Source      string `json:"source"`
}

// BackfillCTInventory copies a bounded page of historical CT names atomically.
// The returned cursor is durable after the transaction commits.
func (s *Store) BackfillCTInventory(ctx context.Context, cursor string, limit int) (inventory.BackfillPage, error) {
	if limit < 1 || limit > 1000 || len(cursor) > 4096 {
		return inventory.BackfillPage{}, model.NewError(model.CodeInvalidOptions, "invalid inventory backfill page", nil)
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	position := inventoryBackfillCursor{}
	if cursor != "" {
		encoded, err := base64.RawURLEncoding.DecodeString(cursor)
		if err != nil || json.Unmarshal(encoded, &position) != nil || position.Name == "" || position.Certificate == "" || position.Source == "" {
			return inventory.BackfillPage{}, model.NewError(model.CodeInvalidOptions, "invalid inventory backfill cursor", err)
		}
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return inventory.BackfillPage{}, persistence("begin inventory backfill", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	rows, err := tx.Query(ctx, `SELECT name,certificate_hash,source_id,logged_at,provenance,
		document->>'log_id',document->>'entry_index',document->>'checkpoint_id' FROM ct_records
		WHERE NOT wildcard AND (name,certificate_hash,source_id)>($1,$2,$3)
		ORDER BY name,certificate_hash,source_id LIMIT $4`, position.Name, position.Certificate, position.Source, limit+1)
	if err != nil {
		return inventory.BackfillPage{}, persistence("read historical CT names", err)
	}
	records := make([]ctlog.Record, 0, limit+1)
	for rows.Next() {
		var record ctlog.Record
		var provenance string
		var logID, entryIndex, checkpointID *string
		if err := rows.Scan(&record.Name, &record.CertificateHash, &record.SourceID, &record.LoggedAt, &provenance,
			&logID, &entryIndex, &checkpointID); err != nil {
			rows.Close()
			return inventory.BackfillPage{}, persistence("scan historical CT name", err)
		}
		record.Provenance = ctlog.Provenance(provenance)
		if logID != nil {
			record.LogID = *logID
		}
		if checkpointID != nil {
			record.CheckpointID = *checkpointID
		}
		if entryIndex != nil {
			parsed, parseErr := strconv.ParseUint(*entryIndex, 10, 64)
			if parseErr != nil {
				rows.Close()
				return inventory.BackfillPage{}, model.NewError(model.CodePersistenceFailed, "historical CT entry index is invalid", parseErr)
			}
			record.EntryIndex = &parsed
		}
		records = append(records, record)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return inventory.BackfillPage{}, persistence("iterate historical CT names", err)
	}
	rows.Close()
	more := len(records) > limit
	if more {
		records = records[:limit]
	}
	for _, record := range records {
		if err := upsertCTInventory(ctx, tx, record, record.LoggedAt); err != nil {
			return inventory.BackfillPage{}, fmt.Errorf("backfill CT name %q: %w", record.Name, err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return inventory.BackfillPage{}, persistence("commit inventory backfill", err)
	}
	page := inventory.BackfillPage{Processed: len(records), Complete: !more}
	if more {
		last := records[len(records)-1]
		encoded, _ := json.Marshal(inventoryBackfillCursor{Name: last.Name, Certificate: last.CertificateHash, Source: last.SourceID})
		page.NextCursor = base64.RawURLEncoding.EncodeToString(encoded)
	}
	return page, nil
}
