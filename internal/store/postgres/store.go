// Package postgres persists jobs, reports, and bundle pins in PostgreSQL.
package postgres

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"cloudattrib/internal/app"
	"cloudattrib/internal/jobs"
	"cloudattrib/internal/model"
)

const lifecycleLockID int64 = 174120260921

// Store is a PostgreSQL implementation of the durable job lifecycle.
type Store struct {
	pool *pgxpool.Pool
	now  func() time.Time
}

type workRequest struct {
	Analyze    *model.AnalyzeRequest    `json:"analyze,omitempty"`
	Reclassify *model.ReclassifyRequest `json:"reclassify,omitempty"`
}

// Open connects, verifies connectivity, and applies the schema.
func Open(ctx context.Context, connectionString string, maximumTargets int) (*Store, error) {
	configuration, err := pgxpool.ParseConfig(connectionString)
	if err != nil {
		return nil, model.NewError(model.CodePersistenceUnavailable, "parse PostgreSQL configuration", err)
	}
	pool, err := pgxpool.NewWithConfig(ctx, configuration)
	if err != nil {
		return nil, model.NewError(model.CodePersistenceUnavailable, "open PostgreSQL pool", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, model.NewError(model.CodePersistenceUnavailable, "ping PostgreSQL", err)
	}
	if err := Migrate(ctx, pool, maximumTargets); err != nil {
		pool.Close()
		return nil, model.NewError(model.CodePersistenceUnavailable, "migrate PostgreSQL", err)
	}
	return &Store{pool: pool, now: time.Now}, nil
}

// Close closes the connection pool.
func (s *Store) Close() { s.pool.Close() }

// RegisterBundle records a validated local bundle before jobs may pin it.
func (s *Store) RegisterBundle(ctx context.Context, bundleID string, manifest []byte, compatible bool) error {
	if bundleID == "" || !json.Valid(manifest) {
		return model.NewError(model.CodeInvalidOptions, "bundle ID and JSON manifest are required", nil)
	}
	if _, err := s.pool.Exec(ctx, `INSERT INTO dataset_bundles(bundle_id,manifest,compatible) VALUES($1,$2,$3) ON CONFLICT (bundle_id) DO UPDATE SET manifest=EXCLUDED.manifest,compatible=EXCLUDED.compatible`, bundleID, manifest, compatible); err != nil {
		return persistence("register bundle", err)
	}
	return nil
}

// Submit atomically admits a job, reserves capacity, and creates its bundle pin.
func (s *Store) Submit(ctx context.Context, request jobs.SubmitRequest) (jobs.Job, error) {
	if request.OperatorID == "" || request.IdempotencyKey == "" || request.WorkCount() == 0 {
		return jobs.Job{}, model.NewError(model.CodeInvalidOptions, "operator, idempotency key, and targets are required", nil)
	}
	hash, err := payloadHash(request)
	if err != nil {
		return jobs.Job{}, fmt.Errorf("hash job payload: %w", err)
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return jobs.Job{}, persistence("begin job admission", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, lifecycleLockID); err != nil {
		return jobs.Job{}, persistence("lock bundle admission", err)
	}
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1::text,0))`, request.OperatorID+":"+request.IdempotencyKey); err != nil {
		return jobs.Job{}, persistence("lock idempotency key", err)
	}
	var existingID, existingHash string
	err = tx.QueryRow(ctx, `SELECT id,payload_hash FROM jobs WHERE operator_id=$1 AND idempotency_key=$2`, request.OperatorID, request.IdempotencyKey).Scan(&existingID, &existingHash)
	if err == nil {
		if existingHash != hash {
			return jobs.Job{}, model.NewError(model.CodeIdempotencyConflict, "idempotency key was used for a different request", nil)
		}
		if err := tx.Commit(ctx); err != nil {
			return jobs.Job{}, persistence("commit idempotent admission", err)
		}
		return s.Job(ctx, existingID)
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return jobs.Job{}, persistence("check idempotency key", err)
	}
	if request.BundleID != "" {
		var compatible bool
		if err := tx.QueryRow(ctx, `SELECT compatible FROM dataset_bundles WHERE bundle_id=$1 FOR SHARE`, request.BundleID).Scan(&compatible); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return jobs.Job{}, model.NewError(model.CodeBundleUnavailable, "requested bundle is unavailable", nil)
			}
			return jobs.Job{}, persistence("validate requested bundle", err)
		}
		if !compatible {
			return jobs.Job{}, model.NewError(model.CodeBundleIncompatible, "requested bundle is incompatible", nil)
		}
	}
	capacity, err := tx.Exec(ctx, `UPDATE queue_capacity SET reserved_targets=reserved_targets+$1 WHERE singleton=true AND reserved_targets+$1<=maximum_targets`, request.WorkCount())
	if err != nil {
		return jobs.Job{}, persistence("reserve queue capacity", err)
	}
	if capacity.RowsAffected() != 1 {
		return jobs.Job{}, model.NewError(model.CodeQueueCapacityExceeded, "nonterminal target capacity is exhausted", nil)
	}
	now := s.now().UTC()
	jobID, err := newID("job")
	if err != nil {
		return jobs.Job{}, fmt.Errorf("create job ID: %w", err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO jobs(id,operator_id,idempotency_key,payload_hash,bundle_id,status,created_at,updated_at) VALUES($1,$2,$3,$4,NULLIF($5,''),'queued',$6,$6)`, jobID, request.OperatorID, request.IdempotencyKey, hash, request.BundleID, now); err != nil {
		return jobs.Job{}, persistence("insert job", err)
	}
	result := jobs.Job{ID: jobID, OperatorID: request.OperatorID, IdempotencyKey: request.IdempotencyKey, BundleID: request.BundleID, Status: jobs.JobQueued, CreatedAt: now, UpdatedAt: now, Targets: make([]jobs.Target, request.WorkCount())}
	for index, targetRequest := range request.Targets {
		targetID, idErr := newID("target")
		if idErr != nil {
			return jobs.Job{}, fmt.Errorf("create target ID: %w", idErr)
		}
		copied := targetRequest
		encoded, encodeErr := json.Marshal(workRequest{Analyze: &copied})
		if encodeErr != nil {
			return jobs.Job{}, fmt.Errorf("encode target request: %w", encodeErr)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO job_targets(id,job_id,input_index,request,status) VALUES($1,$2,$3,$4,'queued')`, targetID, jobID, index, encoded); err != nil {
			return jobs.Job{}, persistence("insert target", err)
		}
		result.Targets[index] = jobs.Target{ID: targetID, Index: index, Request: targetRequest, Status: jobs.TargetQueued}
	}
	for requestIndex, reclassifyRequest := range request.Reclassifications {
		index := len(request.Targets) + requestIndex
		targetID, idErr := newID("target")
		if idErr != nil {
			return jobs.Job{}, fmt.Errorf("create target ID: %w", idErr)
		}
		copied := reclassifyRequest
		encoded, encodeErr := json.Marshal(workRequest{Reclassify: &copied})
		if encodeErr != nil {
			return jobs.Job{}, fmt.Errorf("encode reclassification request: %w", encodeErr)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO job_targets(id,job_id,input_index,request,status) VALUES($1,$2,$3,$4,'queued')`, targetID, jobID, index, encoded); err != nil {
			return jobs.Job{}, persistence("insert reclassification target", err)
		}
		result.Targets[index] = jobs.Target{ID: targetID, Index: index, Reclassify: &copied, Status: jobs.TargetQueued}
	}
	if request.BundleID != "" {
		if _, err := tx.Exec(ctx, `INSERT INTO bundle_pins(bundle_id,job_id) VALUES($1,$2)`, request.BundleID, jobID); err != nil {
			return jobs.Job{}, persistence("pin job bundle", err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return jobs.Job{}, persistence("commit job admission", err)
	}
	return result, nil
}

// Job returns a job to any authenticated operator under the shared-operator model.
func (s *Store) Job(ctx context.Context, id string) (jobs.Job, error) {
	var job jobs.Job
	if err := s.pool.QueryRow(ctx, `SELECT id,operator_id,idempotency_key,COALESCE(bundle_id,''),status,cancel_requested,COALESCE(cancel_requested_by,''),created_at,updated_at FROM jobs WHERE id=$1`, id).Scan(
		&job.ID, &job.OperatorID, &job.IdempotencyKey, &job.BundleID, &job.Status, &job.CancelRequested, &job.CancelRequestedBy, &job.CreatedAt, &job.UpdatedAt,
	); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return jobs.Job{}, model.NewError(model.CodeInvalidTarget, "job was not found", nil)
		}
		return jobs.Job{}, persistence("load job", err)
	}
	rows, err := s.pool.Query(ctx, `SELECT id,input_index,request,status,attempts,COALESCE(lease_owner,''),lease_expires_at,next_attempt_at,COALESCE(terminal_reason,''),COALESCE(report_id,'') FROM job_targets WHERE job_id=$1 ORDER BY input_index`, id)
	if err != nil {
		return jobs.Job{}, persistence("load job targets", err)
	}
	reportIDs := make([]string, 0)
	for rows.Next() {
		var target jobs.Target
		var requestJSON []byte
		var leaseExpires, nextAttempt *time.Time
		var reportID string
		if err := rows.Scan(&target.ID, &target.Index, &requestJSON, &target.Status, &target.Attempts, &target.LeaseOwner, &leaseExpires, &nextAttempt, &target.TerminalReason, &reportID); err != nil {
			return jobs.Job{}, persistence("scan job target", err)
		}
		if err := decodeWorkRequest(requestJSON, &target.Request, &target.Reclassify); err != nil {
			return jobs.Job{}, persistence("decode target request", err)
		}
		if leaseExpires != nil {
			target.LeaseExpiresAt = *leaseExpires
		}
		if nextAttempt != nil {
			target.NextAttemptAt = *nextAttempt
		}
		job.Targets = append(job.Targets, target)
		reportIDs = append(reportIDs, reportID)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return jobs.Job{}, persistence("iterate job targets", err)
	}
	for index, reportID := range reportIDs {
		if reportID == "" {
			continue
		}
		report, loadErr := s.LoadReport(ctx, reportID)
		if loadErr != nil {
			return jobs.Job{}, loadErr
		}
		job.Targets[index].Report, job.Targets[index].ReportAvailable = report, true
	}
	return job, nil
}

// Claim leases one queued target using SKIP LOCKED.
func (s *Store) Claim(ctx context.Context, worker string, lease time.Duration) (jobs.Claim, error) {
	if worker == "" || lease <= 0 {
		return jobs.Claim{}, model.NewError(model.CodeInvalidOptions, "worker and positive lease are required", nil)
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return jobs.Claim{}, persistence("begin claim", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var claim jobs.Claim
	var requestJSON []byte
	if err := tx.QueryRow(ctx, `SELECT jt.id,j.id,COALESCE(j.bundle_id,''),jt.request,jt.attempts FROM job_targets jt JOIN jobs j ON j.id=jt.job_id WHERE jt.status='queued' AND NOT j.cancel_requested AND (jt.next_attempt_at IS NULL OR jt.next_attempt_at<=clock_timestamp()) ORDER BY j.created_at,jt.input_index FOR UPDATE OF jt SKIP LOCKED LIMIT 1`).Scan(&claim.TargetID, &claim.JobID, &claim.BundleID, &requestJSON, &claim.Attempt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return jobs.Claim{}, model.NewError(model.CodeCapabilityUnavailable, "no target is ready to claim", nil)
		}
		return jobs.Claim{}, persistence("select claim", err)
	}
	if err := decodeWorkRequest(requestJSON, &claim.Request, &claim.Reclassify); err != nil {
		return jobs.Claim{}, persistence("decode claimed request", err)
	}
	claim.Attempt++
	claim.AttemptToken, err = newID("attempt")
	if err != nil {
		return jobs.Claim{}, fmt.Errorf("create attempt token: %w", err)
	}
	claim.LeaseExpires = s.now().UTC().Add(lease)
	if _, err := tx.Exec(ctx, `UPDATE job_targets SET status='running',attempts=$2,attempt_token=$3,lease_owner=$4,lease_expires_at=$5 WHERE id=$1`, claim.TargetID, claim.Attempt, claim.AttemptToken, worker, claim.LeaseExpires); err != nil {
		return jobs.Claim{}, persistence("update claim", err)
	}
	if _, err := tx.Exec(ctx, `UPDATE jobs SET status='running',updated_at=clock_timestamp() WHERE id=$1`, claim.JobID); err != nil {
		return jobs.Claim{}, persistence("update claimed job", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return jobs.Claim{}, persistence("commit claim", err)
	}
	return claim, nil
}

// Renew extends a current target attempt lease.
func (s *Store) Renew(ctx context.Context, targetID, token string, lease time.Duration) error {
	result, err := s.pool.Exec(ctx, `UPDATE job_targets jt SET lease_expires_at=$3 FROM jobs j WHERE jt.id=$1 AND jt.attempt_token=$2 AND jt.status='running' AND j.id=jt.job_id AND NOT j.cancel_requested`, targetID, token, s.now().UTC().Add(lease))
	if err != nil {
		return persistence("renew target lease", err)
	}
	if result.RowsAffected() != 1 {
		var cancelled bool
		queryErr := s.pool.QueryRow(ctx, `SELECT j.cancel_requested FROM job_targets jt JOIN jobs j ON j.id=jt.job_id WHERE jt.id=$1 AND jt.attempt_token=$2 AND jt.status='running'`, targetID, token).Scan(&cancelled)
		if queryErr == nil && cancelled {
			return model.NewError(model.CodeCancelled, "job cancellation was requested", nil)
		}
		return model.NewError(model.CodeIdempotencyConflict, "attempt token is stale", nil)
	}
	return nil
}

// Complete stores a report and terminal target state in one transaction.
func (s *Store) Complete(ctx context.Context, targetID, token string, report model.Report, status jobs.TargetStatus, reason string) error {
	if status != jobs.TargetCompleted && status != jobs.TargetPartial && status != jobs.TargetFailed && status != jobs.TargetCancelled {
		return model.NewError(model.CodeInvalidOptions, "completion status is not terminal", nil)
	}
	if report.ID != "" {
		if err := report.ValidateReferences(); err != nil {
			return model.NewError(model.CodeInvalidOptions, "report references are invalid", err)
		}
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return persistence("begin completion", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var jobID string
	if err := tx.QueryRow(ctx, `SELECT job_id FROM job_targets WHERE id=$1 AND attempt_token=$2 AND status='running' FOR UPDATE`, targetID, token).Scan(&jobID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return model.NewError(model.CodeIdempotencyConflict, "attempt token is stale", nil)
		}
		return persistence("lock target completion", err)
	}
	if report.ID != "" {
		if err := saveReport(ctx, tx, report); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(ctx, `UPDATE job_targets SET status=$2,terminal_reason=NULLIF($3,''),report_id=NULLIF($4,''),attempt_token=NULL,lease_owner=NULL,lease_expires_at=NULL WHERE id=$1`, targetID, status, reason, report.ID); err != nil {
		return persistence("terminalize target", err)
	}
	if _, err := tx.Exec(ctx, `UPDATE queue_capacity SET reserved_targets=reserved_targets-1 WHERE singleton=true AND reserved_targets>0`); err != nil {
		return persistence("release queue reservation", err)
	}
	if err := finalizeJob(ctx, tx, jobID); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return persistence("commit target completion", err)
	}
	return nil
}

// RequestCancel accepts cancellation from any authenticated shared operator.
func (s *Store) RequestCancel(ctx context.Context, jobID, operatorID string) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return persistence("begin cancellation", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	result, err := tx.Exec(ctx, `UPDATE jobs SET cancel_requested=true,cancel_requested_by=$2,updated_at=clock_timestamp() WHERE id=$1`, jobID, operatorID)
	if err != nil {
		return persistence("request cancellation", err)
	}
	if result.RowsAffected() != 1 {
		return model.NewError(model.CodeInvalidTarget, "job was not found", nil)
	}
	var released int
	if err := tx.QueryRow(ctx, `WITH cancelled AS (UPDATE job_targets SET status='cancelled',terminal_reason='cancelled before claim' WHERE job_id=$1 AND status='queued' RETURNING 1) SELECT count(*) FROM cancelled`, jobID).Scan(&released); err != nil {
		return persistence("cancel queued targets", err)
	}
	if released > 0 {
		if _, err := tx.Exec(ctx, `UPDATE queue_capacity SET reserved_targets=reserved_targets-$1 WHERE singleton=true`, released); err != nil {
			return persistence("release cancelled reservations", err)
		}
	}
	if err := finalizeJob(ctx, tx, jobID); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return persistence("commit cancellation", err)
	}
	return nil
}

// RecoverExpired requeues or terminalizes expired attempts under one lifecycle lock.
func (s *Store) RecoverExpired(ctx context.Context, maximumAttempts int) error {
	if maximumAttempts <= 0 {
		return model.NewError(model.CodeInvalidOptions, "maximum attempts must be positive", nil)
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return persistence("begin lease recovery", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, lifecycleLockID); err != nil {
		return persistence("lock lease recovery", err)
	}
	rows, err := tx.Query(ctx, `SELECT jt.id,jt.job_id,jt.attempts,j.cancel_requested FROM job_targets jt JOIN jobs j ON j.id=jt.job_id WHERE jt.status='running' AND jt.lease_expires_at<=clock_timestamp() FOR UPDATE OF jt`)
	if err != nil {
		return persistence("select expired attempts", err)
	}
	type expired struct {
		id, jobID string
		attempts  int
		cancelled bool
	}
	var expiredTargets []expired
	for rows.Next() {
		var item expired
		if err := rows.Scan(&item.id, &item.jobID, &item.attempts, &item.cancelled); err != nil {
			rows.Close()
			return persistence("scan expired attempt", err)
		}
		expiredTargets = append(expiredTargets, item)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return persistence("iterate expired attempts", err)
	}
	terminalCount := 0
	affectedJobs := make(map[string]struct{})
	for _, item := range expiredTargets {
		status, reason := jobs.TargetQueued, ""
		if item.cancelled {
			status, reason, terminalCount = jobs.TargetCancelled, "cancelled after lease expiry", terminalCount+1
		} else if item.attempts >= maximumAttempts {
			status, reason, terminalCount = jobs.TargetFailed, "attempt limit exhausted", terminalCount+1
		}
		if _, err := tx.Exec(ctx, `UPDATE job_targets SET status=$2,terminal_reason=NULLIF($3,''),attempt_token=NULL,lease_owner=NULL,lease_expires_at=NULL,next_attempt_at=CASE WHEN $2='queued' THEN clock_timestamp() ELSE NULL END WHERE id=$1`, item.id, status, reason); err != nil {
			return persistence("recover expired attempt", err)
		}
		affectedJobs[item.jobID] = struct{}{}
	}
	if terminalCount > 0 {
		if _, err := tx.Exec(ctx, `UPDATE queue_capacity SET reserved_targets=reserved_targets-$1 WHERE singleton=true`, terminalCount); err != nil {
			return persistence("release expired reservations", err)
		}
	}
	for jobID := range affectedJobs {
		if err := finalizeJob(ctx, tx, jobID); err != nil {
			return err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return persistence("commit lease recovery", err)
	}
	return nil
}

// LoadReport loads one immutable report document.
func (s *Store) LoadReport(ctx context.Context, id string) (model.Report, error) {
	var document []byte
	if err := s.pool.QueryRow(ctx, `SELECT document FROM reports WHERE id=$1`, id).Scan(&document); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return model.Report{}, model.NewError(model.CodeInvalidTarget, "report was not found", nil)
		}
		return model.Report{}, persistence("load report", err)
	}
	var report model.Report
	if err := json.Unmarshal(document, &report); err != nil {
		return model.Report{}, persistence("decode report", err)
	}
	return report, nil
}

type findingCursor struct {
	ClassifiedAt time.Time `json:"classified_at"`
	ReportID     string    `json:"report_id"`
	FindingID    string    `json:"finding_id"`
}

// Findings returns a stable keyset-ordered page of stored findings.
func (s *Store) Findings(ctx context.Context, query app.FindingQuery) (app.FindingPage, error) {
	if query.Limit < 1 || query.Limit > 500 {
		return app.FindingPage{}, model.NewError(model.CodeInvalidOptions, "finding limit must be between 1 and 500", nil)
	}
	cursor := findingCursor{}
	if query.Cursor != "" {
		decoded, err := base64.RawURLEncoding.DecodeString(query.Cursor)
		if err == nil {
			err = json.Unmarshal(decoded, &cursor)
		}
		if err != nil || cursor.ClassifiedAt.IsZero() || cursor.ReportID == "" || cursor.FindingID == "" {
			return app.FindingPage{}, model.NewError(model.CodeInvalidOptions, "finding cursor is invalid", err)
		}
	}
	rows, err := s.pool.Query(ctx, `
		SELECT f.report_id,r.classified_at,f.finding_id,f.document
		FROM findings f JOIN reports r ON r.id=f.report_id
		WHERE ($1='' OR r.target=$1)
		  AND ($2='' OR f.provider_id=$2)
		  AND ($3='' OR f.product_id=$3)
		  AND ($4='' OR f.relation=$4)
		  AND ($5='' OR f.strength=$5)
		  AND (($6::timestamptz IS NULL AND $7::timestamptz IS NULL) OR EXISTS (
		      SELECT 1 FROM observations o WHERE o.report_id=f.report_id
		      AND ($6::timestamptz IS NULL OR o.observed_at >= $6)
		      AND ($7::timestamptz IS NULL OR o.observed_at <= $7)))
		  AND ($8::timestamptz IS NULL OR (r.classified_at,f.report_id,f.finding_id) > ($8,$9,$10))
		ORDER BY r.classified_at,f.report_id,f.finding_id
		LIMIT $11`, query.Domain, query.ProviderID, query.ProductID, query.Relation, query.Strength, query.ObservedFrom, query.ObservedTo,
		nullTime(cursor.ClassifiedAt), cursor.ReportID, cursor.FindingID, query.Limit+1)
	if err != nil {
		return app.FindingPage{}, persistence("search findings", err)
	}
	defer rows.Close()
	page := app.FindingPage{Items: make([]app.StoredFinding, 0, query.Limit)}
	for rows.Next() {
		var item app.StoredFinding
		var findingID string
		var document []byte
		if err := rows.Scan(&item.ReportID, &item.ClassifiedAt, &findingID, &document); err != nil {
			return app.FindingPage{}, persistence("scan finding", err)
		}
		if err := json.Unmarshal(document, &item.Finding); err != nil {
			return app.FindingPage{}, persistence("decode finding", err)
		}
		if len(page.Items) == query.Limit {
			last := page.Items[len(page.Items)-1]
			encoded, encodeErr := json.Marshal(findingCursor{ClassifiedAt: last.ClassifiedAt, ReportID: last.ReportID, FindingID: last.Finding.ID})
			if encodeErr != nil {
				return app.FindingPage{}, persistence("encode finding cursor", encodeErr)
			}
			page.NextCursor = base64.RawURLEncoding.EncodeToString(encoded)
			break
		}
		page.Items = append(page.Items, item)
	}
	if err := rows.Err(); err != nil {
		return app.FindingPage{}, persistence("iterate findings", err)
	}
	return page, nil
}

func nullTime(value time.Time) *time.Time {
	if value.IsZero() {
		return nil
	}
	return &value
}

// SaveReport stores a standalone immutable report atomically.
func (s *Store) SaveReport(ctx context.Context, report model.Report) error {
	if err := report.ValidateReferences(); err != nil {
		return model.NewError(model.CodeInvalidOptions, "report references are invalid", err)
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return persistence("begin report storage", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := saveReport(ctx, tx, report); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return persistence("commit report storage", err)
	}
	return nil
}

// BundlePinned reports durable queued, running, or retry protection.
func (s *Store) BundlePinned(ctx context.Context, bundleID string) (bool, error) {
	var pinned bool
	if err := s.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM bundle_pins WHERE bundle_id=$1)`, bundleID).Scan(&pinned); err != nil {
		return false, persistence("check bundle pins", err)
	}
	return pinned, nil
}

// WithBundlePruneLock serializes pruning with admission and exposes durable pins.
func (s *Store) WithBundlePruneLock(ctx context.Context, bundleID string, action func(bool) error) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return persistence("begin bundle pruning", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, lifecycleLockID); err != nil {
		return persistence("lock bundle pruning", err)
	}
	var pinned bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM bundle_pins WHERE bundle_id=$1)`, bundleID).Scan(&pinned); err != nil {
		return persistence("check bundle pruning pins", err)
	}
	if err := action(pinned); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return persistence("commit bundle pruning", err)
	}
	return nil
}

func finalizeJob(ctx context.Context, tx pgx.Tx, jobID string) error {
	var queued, running, completed, partial, failed, cancelled int
	if err := tx.QueryRow(ctx, `SELECT count(*) FILTER (WHERE status='queued'),count(*) FILTER (WHERE status='running'),count(*) FILTER (WHERE status='completed'),count(*) FILTER (WHERE status='partial'),count(*) FILTER (WHERE status='failed'),count(*) FILTER (WHERE status='cancelled') FROM job_targets WHERE job_id=$1`, jobID).Scan(&queued, &running, &completed, &partial, &failed, &cancelled); err != nil {
		return persistence("count job target states", err)
	}
	if queued+running > 0 {
		return nil
	}
	status := jobs.JobCompleted
	switch {
	case failed > 0 && completed == 0 && partial == 0:
		status = jobs.JobFailed
	case cancelled > 0 && cancelled == completed+partial+failed+cancelled:
		status = jobs.JobCancelled
	case partial+failed+cancelled > 0:
		status = jobs.JobPartial
	}
	if _, err := tx.Exec(ctx, `UPDATE jobs SET status=$2,updated_at=clock_timestamp() WHERE id=$1`, jobID, status); err != nil {
		return persistence("terminalize job", err)
	}
	if _, err := tx.Exec(ctx, `DELETE FROM bundle_pins WHERE job_id=$1`, jobID); err != nil {
		return persistence("release job bundle pin", err)
	}
	return nil
}

func saveReport(ctx context.Context, tx pgx.Tx, report model.Report) error {
	if report.ID == "" {
		return model.NewError(model.CodeInvalidOptions, "report ID is required", nil)
	}
	document, err := report.CanonicalJSON()
	if err != nil {
		return fmt.Errorf("encode report: %w", err)
	}
	providers, products, relations := reportProjection(report)
	inserted, err := tx.Exec(ctx, `INSERT INTO reports(id,original_report_id,target,provider_ids,product_ids,relations,status,classified_at,bundle_id,document) VALUES($1,NULLIF($2,''),$3,$4,$5,$6,$7,$8,$9,$10) ON CONFLICT (id) DO NOTHING`, report.ID, report.OriginalReportID, report.Target.Canonical, providers, products, relations, report.Status, report.ClassifiedAt, report.BundleID, document)
	if err != nil {
		return persistence("insert report", err)
	}
	if inserted.RowsAffected() == 0 {
		var existing []byte
		if err := tx.QueryRow(ctx, `SELECT document FROM reports WHERE id=$1`, report.ID).Scan(&existing); err != nil {
			return persistence("load existing report", err)
		}
		if !sameJSON(existing, document) {
			return model.NewError(model.CodeIdempotencyConflict, "report ID already has different content", nil)
		}
	}
	for _, observation := range report.Observations {
		encoded, encodeErr := json.Marshal(observation)
		if encodeErr != nil {
			return fmt.Errorf("encode observation: %w", encodeErr)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO observations(report_id,observation_id,subject,observation_type,observed_at,document) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT DO NOTHING`, report.ID, observation.ID, observation.Subject, observation.Type, observation.ObservedAt, encoded); err != nil {
			return persistence("insert observation", err)
		}
	}
	for _, evidence := range report.Evidence {
		encoded, encodeErr := json.Marshal(evidence)
		if encodeErr != nil {
			return fmt.Errorf("encode evidence: %w", encodeErr)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO evidence(report_id,evidence_id,provider_id,product_id,relation,strength,classified_at,document) VALUES($1,$2,NULLIF($3,''),NULLIF($4,''),$5,$6,$7,$8) ON CONFLICT DO NOTHING`, report.ID, evidence.ID, evidence.ProviderID, evidence.ProductID, evidence.Relation, evidence.Strength, evidence.ClassifiedAt, encoded); err != nil {
			return persistence("insert evidence", err)
		}
	}
	for _, finding := range report.Findings {
		encoded, encodeErr := json.Marshal(finding)
		if encodeErr != nil {
			return fmt.Errorf("encode finding: %w", encodeErr)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO findings(report_id,finding_id,subject,provider_id,product_id,relation,strength,document) VALUES($1,$2,$3,NULLIF($4,''),NULLIF($5,''),$6,$7,$8) ON CONFLICT DO NOTHING`, report.ID, finding.ID, finding.Subject, finding.ProviderID, finding.ProductID, finding.Relation, finding.Strength, encoded); err != nil {
			return persistence("insert finding", err)
		}
		for _, evidenceID := range finding.EvidenceIDs {
			if _, err := tx.Exec(ctx, `INSERT INTO finding_evidence(report_id,finding_id,evidence_id) VALUES($1,$2,$3) ON CONFLICT DO NOTHING`, report.ID, finding.ID, evidenceID); err != nil {
				return persistence("link finding evidence", err)
			}
		}
	}
	return nil
}

func sameJSON(left, right []byte) bool {
	var leftValue, rightValue any
	if json.Unmarshal(left, &leftValue) != nil || json.Unmarshal(right, &rightValue) != nil {
		return false
	}
	return reflect.DeepEqual(leftValue, rightValue)
}

func reportProjection(report model.Report) ([]string, []string, []string) {
	providers, products, relations := make([]string, 0), make([]string, 0), make([]string, 0)
	for _, finding := range report.Findings {
		if finding.ProviderID != "" {
			providers = append(providers, finding.ProviderID)
		}
		if finding.ProductID != "" {
			products = append(products, finding.ProductID)
		}
		relations = append(relations, string(finding.Relation))
	}
	slices.Sort(providers)
	slices.Sort(products)
	slices.Sort(relations)
	return slices.Compact(providers), slices.Compact(products), slices.Compact(relations)
}

func payloadHash(request jobs.SubmitRequest) (string, error) {
	encoded, err := json.Marshal(struct {
		BundleID          string                    `json:"bundle_id"`
		Targets           []model.AnalyzeRequest    `json:"targets"`
		Reclassifications []model.ReclassifyRequest `json:"reclassifications"`
	}{BundleID: request.BundleID, Targets: request.Targets, Reclassifications: request.Reclassifications})
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:]), nil
}

func decodeWorkRequest(encoded []byte, analyze *model.AnalyzeRequest, reclassify **model.ReclassifyRequest) error {
	var work workRequest
	if err := json.Unmarshal(encoded, &work); err != nil {
		return err
	}
	if work.Analyze != nil && work.Reclassify != nil {
		return fmt.Errorf("work request contains multiple operations")
	}
	if work.Analyze != nil {
		*analyze = *work.Analyze
		*reclassify = nil
		return nil
	}
	if work.Reclassify != nil {
		*analyze = model.AnalyzeRequest{}
		copy := *work.Reclassify
		*reclassify = &copy
		return nil
	}
	// Rows written before work envelopes were introduced contain a bare analysis request.
	if err := json.Unmarshal(encoded, analyze); err != nil {
		return err
	}
	if analyze.Target == "" {
		return fmt.Errorf("work request contains no operation")
	}
	*reclassify = nil
	return nil
}

func newID(prefix string) (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", err
	}
	return prefix + "-" + hex.EncodeToString(value[:]), nil
}

func persistence(operation string, err error) error {
	return model.NewError(model.CodePersistenceFailed, operation, err)
}

var _ jobs.Store = (*Store)(nil)
