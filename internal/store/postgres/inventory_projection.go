package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"time"

	"github.com/jackc/pgx/v5"

	"cloudattrib/internal/inventory"
	"cloudattrib/internal/model"
)

// InventoryProjectionStatus reports durable projection lag and protected report storage.
func (s *Store) InventoryProjectionStatus(ctx context.Context) (inventory.ProjectionStatus, error) {
	var status inventory.ProjectionStatus
	err := s.pool.QueryRow(ctx, `SELECT count(*) FILTER (WHERE status='pending'),count(*) FILTER (WHERE status='running'),
		count(*) FILTER (WHERE status='failed'),COALESCE(extract(epoch FROM clock_timestamp()-min(created_at) FILTER (WHERE status='pending'))::bigint,0)
		FROM inventory_projection_tasks`).Scan(&status.Pending, &status.Running, &status.Failed, &status.OldestPendingAgeSeconds)
	if err != nil {
		return inventory.ProjectionStatus{}, persistence("read inventory projection status", err)
	}
	err = s.pool.QueryRow(ctx, `WITH protected AS (
		SELECT report_id FROM inventory_projection_tasks
		UNION SELECT report_id FROM inventory_context_support
	)
	SELECT count(*),COALESCE(sum(octet_length(r.document::text)),0)
	FROM protected p JOIN reports r ON r.id=p.report_id`).Scan(&status.ProtectedReports, &status.ProtectedDocumentBytes)
	if err != nil {
		return inventory.ProjectionStatus{}, persistence("read inventory protected report storage", err)
	}
	return status, nil
}

type inventoryProjectionClaim struct {
	ReportID           string
	ProjectorVersion   string
	Token              string
	DeletionGeneration int64
}

func (s *Store) claimInventoryProjection(ctx context.Context) (*inventoryProjectionClaim, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, persistence("begin inventory projection claim", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	claim := &inventoryProjectionClaim{}
	err = tx.QueryRow(ctx, `SELECT report_id,projector_version,deletion_generation FROM inventory_projection_tasks
		WHERE attempts<5 AND (status='pending' OR status='failed' AND next_attempt_at<=clock_timestamp() OR status='running' AND lease_expires_at<=clock_timestamp())
		ORDER BY created_at,report_id FOR UPDATE SKIP LOCKED LIMIT 1`).Scan(&claim.ReportID, &claim.ProjectorVersion, &claim.DeletionGeneration)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, persistence("claim inventory projection", err)
	}
	claim.Token, err = newID("inventory-projection")
	if err != nil {
		return nil, fmt.Errorf("create inventory projection token: %w", err)
	}
	if _, err := tx.Exec(ctx, `UPDATE inventory_projection_tasks SET status='running',attempts=attempts+1,lease_token=$2,
		lease_expires_at=clock_timestamp()+interval '30 seconds',updated_at=clock_timestamp() WHERE report_id=$1 AND projector_version=$3`,
		claim.ReportID, claim.Token, claim.ProjectorVersion); err != nil {
		return nil, persistence("lease inventory projection", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, persistence("commit inventory projection claim", err)
	}
	return claim, nil
}

// ProcessNextInventoryProjection processes one durable task outside the job lifecycle lock.
// It returns false when no task is currently eligible.
func (s *Store) ProcessNextInventoryProjection(ctx context.Context) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, 25*time.Second)
	defer cancel()
	claim, err := s.claimInventoryProjection(ctx)
	if err != nil || claim == nil {
		return false, err
	}
	report, err := s.LoadReport(ctx, claim.ReportID)
	if err == nil {
		err = s.publishInventoryProjection(ctx, *claim, report)
	}
	if err != nil {
		failCtx, failCancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
		defer failCancel()
		if failErr := s.failInventoryProjection(failCtx, *claim); failErr != nil {
			return true, errors.Join(err, failErr)
		}
		return true, err
	}
	return true, nil
}

func (s *Store) failInventoryProjection(ctx context.Context, claim inventoryProjectionClaim) error {
	_, err := s.pool.Exec(ctx, `UPDATE inventory_projection_tasks SET status='failed',lease_token=NULL,lease_expires_at=NULL,
		next_attempt_at=clock_timestamp()+make_interval(secs=>LEAST(300,attempts*attempts)),last_error='projection_failed',updated_at=clock_timestamp()
		WHERE report_id=$1 AND projector_version=$2 AND lease_token=$3`, claim.ReportID, claim.ProjectorVersion, claim.Token)
	if err != nil {
		return persistence("record inventory projection failure", err)
	}
	return nil
}

func projectionHostname(report model.Report) (string, error) {
	raw := report.Target.Canonical
	if report.Target.Kind == model.TargetURL {
		parsed, err := url.Parse(raw)
		if err != nil {
			return "", err
		}
		raw = parsed.Hostname()
	}
	hostname, _, err := inventory.Normalize(raw)
	return hostname, err
}

func reportContextID(report model.Report) string {
	if report.Provenance != nil && report.Provenance.Collection.ObservationContext != nil {
		value := report.Provenance.Collection.ObservationContext.Explicit()
		if value.Status == model.ProvenanceKnown {
			return value.Value
		}
	}
	return "unknown"
}

func (s *Store) publishInventoryProjection(ctx context.Context, claim inventoryProjectionClaim, report model.Report) error {
	hostname, err := projectionHostname(report)
	if err != nil {
		return model.NewError(model.CodeInvalidTarget, "projection report target is invalid", err)
	}
	description := inventory.DescribeReport(report, hostname)
	contextID := reportContextID(report)
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return persistence("begin inventory projection publication", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	// A generation build captures existing descriptions under this lock. Any
	// later description publication sees the new generation and queues its work.
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(174120260922)`); err != nil {
		return persistence("serialize inventory description publication", err)
	}
	var generation int64
	err = tx.QueryRow(ctx, `SELECT deletion_generation FROM inventory_projection_tasks WHERE report_id=$1 AND projector_version=$2 AND status='running' AND lease_token=$3 FOR UPDATE`,
		claim.ReportID, claim.ProjectorVersion, claim.Token).Scan(&generation)
	if errors.Is(err, pgx.ErrNoRows) {
		return model.NewError(model.CodeIdempotencyConflict, "inventory projection lease is stale", nil)
	}
	if err != nil {
		return persistence("lock inventory projection task", err)
	}
	if err := lockInventoryHostname(ctx, tx, hostname); err != nil {
		return err
	}
	var assetID string
	var assetGeneration int64
	err = tx.QueryRow(ctx, `SELECT asset_id,deletion_generation FROM inventory_assets WHERE hostname=$1 FOR UPDATE`, hostname).Scan(&assetID, &assetGeneration)
	if errors.Is(err, pgx.ErrNoRows) || err == nil && assetGeneration != generation {
		if _, err := tx.Exec(ctx, `DELETE FROM inventory_projection_tasks WHERE report_id=$1 AND projector_version=$2`, claim.ReportID, claim.ProjectorVersion); err != nil {
			return persistence("discard obsolete inventory projection", err)
		}
		if err := tx.Commit(ctx); err != nil {
			return persistence("commit obsolete inventory projection", err)
		}
		return nil
	}
	if err != nil {
		return persistence("read inventory projection asset", err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO inventory_asset_contexts(asset_id,context_id,deletion_generation) VALUES($1,$2,$3) ON CONFLICT DO NOTHING`, assetID, contextID, generation); err != nil {
		return persistence("create inventory context", err)
	}
	if err := s.updateInventoryContext(ctx, tx, assetID, contextID, hostname, assetGeneration, report, description); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM inventory_projection_tasks WHERE report_id=$1 AND projector_version=$2`, claim.ReportID, claim.ProjectorVersion); err != nil {
		return persistence("complete inventory projection", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return persistence("commit inventory projection", err)
	}
	return nil
}

func (s *Store) updateInventoryContext(ctx context.Context, tx pgx.Tx, assetID, contextID, hostname string, assetGeneration int64, report model.Report, description inventory.Description) error {
	var latestAt, positiveAt, descriptionAt, descriptionClassifiedAt *time.Time
	var latestReport, positiveReport, descriptionReport, currentHash, currentFormat string
	var latestCoverage []string
	var latestHTTPStatus, lastHTTPStatus *int
	var latestHTTPAt, lastHTTPAt *time.Time
	var lastHTTPReport *string
	var revision int64
	err := tx.QueryRow(ctx, `SELECT latest_attempt_at,COALESCE(latest_attempt_report_id,''),last_positive_at,COALESCE(last_positive_report_id,''),
		description_observed_at,description_classified_at,COALESCE(description_report_id,''),description_hash,description_format_version,description_revision,
		latest_coverage,latest_http_status,latest_http_at,last_http_response_status,last_http_response_at,last_http_response_report_id
		FROM inventory_asset_contexts WHERE asset_id=$1 AND context_id=$2 FOR UPDATE`, assetID, contextID).
		Scan(&latestAt, &latestReport, &positiveAt, &positiveReport, &descriptionAt, &descriptionClassifiedAt, &descriptionReport, &currentHash, &currentFormat, &revision,
			&latestCoverage, &latestHTTPStatus, &latestHTTPAt, &lastHTTPStatus, &lastHTTPAt, &lastHTTPReport)
	if err != nil {
		return persistence("lock inventory context", err)
	}
	replay := report.OriginalReportID != ""
	attemptedAt := description.AttemptedAt
	if attemptedAt.IsZero() {
		attemptedAt = description.ObservedAt
	}
	if !replay && !attemptedAt.IsZero() && laterInventoryPosition(attemptedAt, report.ID, latestAt, latestReport) {
		latestAt, latestReport = &attemptedAt, report.ID
		latestCoverage = description.Coverage
		httpAttempted := report.Mode == model.ModeFull
		httpResponseSeen := false
		for _, coverage := range report.Coverage {
			if coverage.Capability == "http" {
				httpAttempted = true
			}
		}
		for _, observation := range report.Observations {
			if observation.Type != "http_response" || observation.Subject != hostname || observation.Scope == model.ScopeExternalRedirect {
				continue
			}
			var payload model.HTTPPayload
			if json.Unmarshal(observation.Payload, &payload) != nil || payload.StatusCode < 100 || payload.StatusCode > 599 {
				continue
			}
			httpAttempted = true
			httpResponseSeen = true
			if latestHTTPAt == nil || observation.ObservedAt.After(*latestHTTPAt) {
				status := payload.StatusCode
				latestHTTPStatus = &status
				observed := observation.ObservedAt
				latestHTTPAt = &observed
			}
		}
		if httpAttempted && !httpResponseSeen {
			latestHTTPStatus = nil
			latestHTTPAt = &attemptedAt
		}
	}
	// A delayed older report cannot replace the latest attempt, but it can still
	// supply the most recent response when the latest attempt had none.
	if !replay {
		for _, observation := range report.Observations {
			if observation.Type != "http_response" || observation.Subject != hostname || observation.Scope == model.ScopeExternalRedirect {
				continue
			}
			var payload model.HTTPPayload
			if json.Unmarshal(observation.Payload, &payload) != nil || payload.StatusCode < 100 || payload.StatusCode > 599 {
				continue
			}
			if lastHTTPAt == nil || laterInventoryPosition(observation.ObservedAt, report.ID, lastHTTPAt, valueOrEmpty(lastHTTPReport)) {
				status := payload.StatusCode
				lastHTTPStatus = &status
				observed := observation.ObservedAt
				lastHTTPAt = &observed
				lastHTTPReport = &report.ID
			}
		}
	}
	if !replay && description.Positive && !description.ObservedAt.IsZero() && laterInventoryPosition(description.ObservedAt, report.ID, positiveAt, positiveReport) {
		positiveAt, positiveReport = &description.ObservedAt, report.ID
	}
	replaceDescription := descriptionReport == "" || description.Positive && laterInventoryPosition(description.ObservedAt, report.ID, descriptionAt, descriptionReport)
	if descriptionReport == report.ID && currentFormat != description.FormatVersion {
		replaceDescription = true
	}
	if replay && descriptionAt != nil && description.ObservedAt.Equal(*descriptionAt) && report.ClassifiedAt.After(valueOrZero(descriptionClassifiedAt)) {
		replaceDescription = true
	}
	if _, err := tx.Exec(ctx, `UPDATE inventory_asset_contexts SET latest_attempt_at=$3,latest_attempt_report_id=NULLIF($4,''),
		last_positive_at=$5,last_positive_report_id=NULLIF($6,''),latest_coverage=$7,
		latest_http_status=$8,latest_http_at=$9,last_http_response_status=$10,last_http_response_at=$11,
		last_http_response_report_id=$12,updated_at=clock_timestamp()
		WHERE asset_id=$1 AND context_id=$2`, assetID, contextID, latestAt, latestReport, positiveAt, positiveReport,
		latestCoverage, latestHTTPStatus, latestHTTPAt, lastHTTPStatus, lastHTTPAt, lastHTTPReport); err != nil {
		return persistence("update inventory observation state", err)
	}
	if replaceDescription {
		revision++
		descriptionAt, descriptionClassifiedAt, descriptionReport = &description.ObservedAt, &report.ClassifiedAt, report.ID
		previousHash := currentHash
		currentHash = description.ContentHash
		if _, err := tx.Exec(ctx, `UPDATE inventory_asset_contexts SET description=$3,description_hash=$4,description_revision=$5,
			description_format_version=$6,description_observed_at=$7,description_classified_at=$8,description_report_id=$9,
			description_observation_ids=$10,description_evidence_ids=$11,coverage=$12,omitted=$13,updated_at=clock_timestamp()
			WHERE asset_id=$1 AND context_id=$2`, assetID, contextID, description.Text, currentHash, revision,
			description.FormatVersion, descriptionAt, descriptionClassifiedAt, descriptionReport,
			description.ObservationIDs, description.EvidenceIDs, description.Coverage, description.Omitted); err != nil {
			return persistence("publish inventory description", err)
		}
		if currentHash != previousHash {
			if _, err := tx.Exec(ctx, `INSERT INTO inventory_embedding_tasks(asset_id,context_id,generation_id,description_revision,description_hash,deletion_generation)
				SELECT $1,$2,generation_id,$3,$4,$5 FROM inventory_embedding_generations WHERE status IN ('building','active')
				ON CONFLICT (asset_id,context_id,generation_id) DO UPDATE SET
				description_revision=EXCLUDED.description_revision,description_hash=EXCLUDED.description_hash,
				deletion_generation=EXCLUDED.deletion_generation,status='pending',attempts=0,
				lease_token=NULL,lease_expires_at=NULL,next_attempt_at=NULL,last_error='',updated_at=clock_timestamp()`,
				assetID, contextID, revision, currentHash, assetGeneration); err != nil {
				return persistence("queue inventory embedding work", err)
			}
		} else {
			if _, err := tx.Exec(ctx, `UPDATE inventory_embedding_tasks SET description_revision=$3,updated_at=clock_timestamp()
				WHERE asset_id=$1 AND context_id=$2 AND description_hash=$4 AND deletion_generation=$5`,
				assetID, contextID, revision, currentHash, assetGeneration); err != nil {
				return persistence("advance unchanged inventory embedding work", err)
			}
			var vectorStorageReady bool
			if err := tx.QueryRow(ctx, `SELECT to_regclass('inventory_embeddings') IS NOT NULL`).Scan(&vectorStorageReady); err != nil {
				return persistence("check inventory vector storage", err)
			}
			if vectorStorageReady {
				if _, err := tx.Exec(ctx, `UPDATE inventory_embeddings SET description_revision=$3,updated_at=clock_timestamp()
					WHERE asset_id=$1 AND context_id=$2 AND description_hash=$4 AND deletion_generation=$5`,
					assetID, contextID, revision, currentHash, assetGeneration); err != nil {
					return persistence("advance unchanged inventory vectors", err)
				}
			}
		}
	}
	if !replay {
		if err := publishInventoryDNSState(ctx, tx, assetID, contextID, hostname, report); err != nil {
			return err
		}
	}
	return replaceInventorySupports(ctx, tx, assetID, contextID, latestReport, positiveReport, descriptionReport, valueOrEmpty(lastHTTPReport))
}

func valueOrEmpty(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

func laterInventoryPosition(at time.Time, reportID string, oldAt *time.Time, oldReportID string) bool {
	return oldAt == nil || at.After(*oldAt) || at.Equal(*oldAt) && reportID > oldReportID
}

func valueOrZero(value *time.Time) time.Time {
	if value == nil {
		return time.Time{}
	}
	return *value
}

func publishInventoryDNSState(ctx context.Context, tx pgx.Tx, assetID, contextID, hostname string, report model.Report) error {
	for _, observation := range report.Observations {
		if observation.Type != "dns_query" || observation.Subject != hostname || observation.Scope == model.ScopeMailDependency || observation.Scope == model.ScopeDNSDependency || observation.Scope == model.ScopeExternalRedirect || observation.ObservedAt.IsZero() {
			continue
		}
		var payload model.DNSPayload
		if json.Unmarshal(observation.Payload, &payload) != nil || payload.RRType == "" || payload.Owner == "" {
			continue
		}
		positive := observation.Status == string(model.DNSOutcomeAnswered)
		if _, err := tx.Exec(ctx, `INSERT INTO inventory_dns_state(asset_id,context_id,question_name,rrtype,latest_observed_at,latest_outcome,latest_report_id,last_positive_at,last_positive_report_id)
			VALUES($1,$2,$3,$4,$5::timestamptz,$6,$7::text,CASE WHEN $8::boolean THEN $5::timestamptz ELSE NULL END,CASE WHEN $8::boolean THEN $7::text ELSE NULL END)
			ON CONFLICT (asset_id,context_id,question_name,rrtype) DO UPDATE SET
			latest_observed_at=CASE WHEN (EXCLUDED.latest_observed_at,EXCLUDED.latest_report_id)>(inventory_dns_state.latest_observed_at,inventory_dns_state.latest_report_id) THEN EXCLUDED.latest_observed_at ELSE inventory_dns_state.latest_observed_at END,
			latest_outcome=CASE WHEN (EXCLUDED.latest_observed_at,EXCLUDED.latest_report_id)>(inventory_dns_state.latest_observed_at,inventory_dns_state.latest_report_id) THEN EXCLUDED.latest_outcome ELSE inventory_dns_state.latest_outcome END,
			latest_report_id=CASE WHEN (EXCLUDED.latest_observed_at,EXCLUDED.latest_report_id)>(inventory_dns_state.latest_observed_at,inventory_dns_state.latest_report_id) THEN EXCLUDED.latest_report_id ELSE inventory_dns_state.latest_report_id END,
			last_positive_at=CASE WHEN EXCLUDED.last_positive_at IS NOT NULL AND (inventory_dns_state.last_positive_at IS NULL OR (EXCLUDED.last_positive_at,EXCLUDED.last_positive_report_id)>(inventory_dns_state.last_positive_at,inventory_dns_state.last_positive_report_id)) THEN EXCLUDED.last_positive_at ELSE inventory_dns_state.last_positive_at END,
			last_positive_report_id=CASE WHEN EXCLUDED.last_positive_at IS NOT NULL AND (inventory_dns_state.last_positive_at IS NULL OR (EXCLUDED.last_positive_at,EXCLUDED.last_positive_report_id)>(inventory_dns_state.last_positive_at,inventory_dns_state.last_positive_report_id)) THEN EXCLUDED.last_positive_report_id ELSE inventory_dns_state.last_positive_report_id END`,
			assetID, contextID, payload.Owner, payload.RRType, observation.ObservedAt, observation.Status, report.ID, positive); err != nil {
			return persistence("publish inventory DNS state", err)
		}
	}
	return nil
}

func replaceInventorySupports(ctx context.Context, tx pgx.Tx, assetID, contextID string, reportIDs ...string) error {
	rows, err := tx.Query(ctx, `SELECT latest_report_id,last_positive_report_id FROM inventory_dns_state WHERE asset_id=$1 AND context_id=$2`, assetID, contextID)
	if err != nil {
		return persistence("read inventory DNS support", err)
	}
	for rows.Next() {
		var latest string
		var positive *string
		if err := rows.Scan(&latest, &positive); err != nil {
			rows.Close()
			return persistence("scan inventory DNS support", err)
		}
		reportIDs = append(reportIDs, latest)
		if positive != nil {
			reportIDs = append(reportIDs, *positive)
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return persistence("iterate inventory DNS support", err)
	}
	rows.Close()
	unique := make(map[string]struct{}, len(reportIDs))
	for _, id := range reportIDs {
		if id != "" {
			unique[id] = struct{}{}
		}
	}
	ordered := make([]string, 0, len(unique))
	for id := range unique {
		ordered = append(ordered, id)
	}
	sort.Strings(ordered)
	if _, err := tx.Exec(ctx, `DELETE FROM inventory_context_support WHERE asset_id=$1 AND context_id=$2`, assetID, contextID); err != nil {
		return persistence("release obsolete inventory support", err)
	}
	for _, id := range ordered {
		if _, err := tx.Exec(ctx, `INSERT INTO inventory_context_support(asset_id,context_id,report_id) VALUES($1,$2,$3)`, assetID, contextID, id); err != nil {
			return persistence("protect inventory support report", err)
		}
	}
	return nil
}
