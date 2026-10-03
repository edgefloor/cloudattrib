package postgres

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"cloudattrib/internal/model"
	"cloudattrib/internal/retention"
)

type retentionCursor struct {
	Cutoff    time.Time `json:"cutoff"`
	CreatedAt time.Time `json:"created_at"`
	ReportID  string    `json:"report_id"`
}

func decodeRetentionCursor(encoded string, cutoff time.Time) (retentionCursor, error) {
	if encoded == "" {
		return retentionCursor{}, nil
	}
	data, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || len(data) > 512 {
		return retentionCursor{}, model.NewError(model.CodeInvalidOptions, "invalid report retention cursor", err)
	}
	var cursor retentionCursor
	if err := json.Unmarshal(data, &cursor); err != nil || cursor.Cutoff.IsZero() || !cursor.Cutoff.Equal(cutoff) || cursor.CreatedAt.IsZero() || cursor.ReportID == "" || len(cursor.ReportID) > 255 {
		return retentionCursor{}, model.NewError(model.CodeInvalidOptions, "invalid report retention cursor", err)
	}
	return cursor, nil
}

func encodeRetentionCursor(item retention.Candidate, cutoff time.Time) string {
	data, _ := json.Marshal(retentionCursor{Cutoff: cutoff, CreatedAt: item.CreatedAt, ReportID: item.ReportID})
	return base64.RawURLEncoding.EncodeToString(data)
}

// RunReportRetention previews or applies one bounded ordered page. Applying
// locks selected reports before checking their live references, so a new replay
// or inventory reference cannot slip between eligibility and deletion.
func (s *Store) RunReportRetention(ctx context.Context, request retention.Request) (retention.Page, error) {
	cursor, err := decodeRetentionCursor(request.Cursor, request.Cutoff)
	if err != nil {
		return retention.Page{}, err
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return retention.Page{}, persistence("begin report retention", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	query := `SELECT id,created_at,octet_length(document::text)::bigint FROM reports
		WHERE created_at<$1 AND (created_at,id)>($2,$3)
		ORDER BY created_at,id LIMIT $4`
	if request.Apply {
		query += ` FOR UPDATE`
	}
	rows, err := tx.Query(ctx, query, request.Cutoff, cursor.CreatedAt, cursor.ReportID, request.Limit+1)
	if err != nil {
		return retention.Page{}, persistence("select report retention page", err)
	}
	items := make([]retention.Candidate, 0, request.Limit+1)
	for rows.Next() {
		var item retention.Candidate
		if err := rows.Scan(&item.ReportID, &item.CreatedAt, &item.DocumentBytes); err != nil {
			rows.Close()
			return retention.Page{}, persistence("scan report retention candidate", err)
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return retention.Page{}, persistence("iterate report retention candidates", err)
	}
	rows.Close()
	more := len(items) > request.Limit
	if more {
		items = items[:request.Limit]
	}
	page := retention.Page{Cutoff: request.Cutoff, Applied: request.Apply, Items: items, Complete: !more}
	for index := range page.Items {
		item := &page.Items[index]
		if err := tx.QueryRow(ctx, `SELECT CASE
			WHEN EXISTS(SELECT 1 FROM reports WHERE original_report_id=$1) THEN 'replay_input'
			WHEN EXISTS(SELECT 1 FROM job_targets WHERE status IN ('queued','running') AND request->'reclassify'->>'report_id'=$1) THEN 'active_reclassification'
			WHEN EXISTS(SELECT 1 FROM job_targets WHERE status IN ('queued','running') AND report_id=$1) THEN 'active_target'
			WHEN EXISTS(SELECT 1 FROM inventory_projection_tasks WHERE report_id=$1) THEN 'pending_projection'
			WHEN EXISTS(SELECT 1 FROM inventory_context_support WHERE report_id=$1) THEN 'inventory_evidence'
			ELSE '' END`, item.ReportID).Scan(&item.Protection); err != nil {
			return retention.Page{}, persistence("check report retention protection", err)
		}
		if item.Protection != "" {
			page.Protected++
			continue
		}
		page.Eligible++
		if !request.Apply {
			continue
		}
		if _, err := tx.Exec(ctx, `UPDATE job_targets SET report_id=NULL
			WHERE report_id=$1 AND status IN ('completed','partial','failed','cancelled')`, item.ReportID); err != nil {
			return retention.Page{}, persistence("detach expired terminal job result", err)
		}
		result, err := tx.Exec(ctx, `DELETE FROM reports WHERE id=$1`, item.ReportID)
		if err != nil {
			return retention.Page{}, persistence("delete expired report", err)
		}
		if result.RowsAffected() != 1 {
			return retention.Page{}, model.NewError(model.CodePersistenceFailed, "expired report disappeared during retention", errors.New(item.ReportID))
		}
		item.Deleted = true
		page.Deleted++
	}
	if more && len(page.Items) > 0 {
		page.NextCursor = encodeRetentionCursor(page.Items[len(page.Items)-1], request.Cutoff)
	}
	if err := tx.Commit(ctx); err != nil {
		return retention.Page{}, persistence("commit report retention page", err)
	}
	return page, nil
}
