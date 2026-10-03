package postgres

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"time"

	"cloudattrib/internal/inventory"
	"cloudattrib/internal/model"
)

// BackfillInventoryReports queues historical reports in restartable ID pages.
// It reads retained report documents only and makes no target requests.
func (s *Store) BackfillInventoryReports(ctx context.Context, cursor string, limit int) (inventory.BackfillPage, error) {
	if limit < 1 || limit > 1000 || len(cursor) > 1024 {
		return inventory.BackfillPage{}, model.NewError(model.CodeInvalidOptions, "invalid report backfill page", nil)
	}
	after := ""
	if cursor != "" {
		decoded, err := base64.RawURLEncoding.DecodeString(cursor)
		if err != nil || len(decoded) == 0 || len(decoded) > 255 {
			return inventory.BackfillPage{}, model.NewError(model.CodeInvalidOptions, "invalid report backfill cursor", err)
		}
		after = string(decoded)
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return inventory.BackfillPage{}, persistence("begin inventory report backfill", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	rows, err := tx.Query(ctx, `SELECT id FROM reports WHERE id>$1 ORDER BY id LIMIT $2`, after, limit+1)
	if err != nil {
		return inventory.BackfillPage{}, persistence("read historical report IDs", err)
	}
	ids := make([]string, 0, limit+1)
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return inventory.BackfillPage{}, persistence("scan historical report ID", err)
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return inventory.BackfillPage{}, persistence("iterate historical report IDs", err)
	}
	rows.Close()
	more := len(ids) > limit
	if more {
		ids = ids[:limit]
	}
	for _, id := range ids {
		var encoded []byte
		if err := tx.QueryRow(ctx, `SELECT document FROM reports WHERE id=$1`, id).Scan(&encoded); err != nil {
			return inventory.BackfillPage{}, persistence("read historical report", err)
		}
		var report model.Report
		if err := json.Unmarshal(encoded, &report); err != nil {
			return inventory.BackfillPage{}, persistence("decode historical report", err)
		}
		if err := publishReportInventory(ctx, tx, report, nil); err != nil {
			return inventory.BackfillPage{}, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return inventory.BackfillPage{}, persistence("commit inventory report backfill", err)
	}
	page := inventory.BackfillPage{Processed: len(ids), Complete: !more}
	if more {
		page.NextCursor = base64.RawURLEncoding.EncodeToString([]byte(ids[len(ids)-1]))
	}
	return page, nil
}
