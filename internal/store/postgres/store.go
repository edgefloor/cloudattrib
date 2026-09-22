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
	"cloudattrib/internal/ctlog"
	"cloudattrib/internal/jobs"
	"cloudattrib/internal/model"
	"cloudattrib/internal/observability"
)

const lifecycleLockID int64 = 174120260921

// Store is a PostgreSQL implementation of the durable job lifecycle.
type Store struct {
	pool             *pgxpool.Pool
	now              func() time.Time
	transactionHooks *transactionHooks
}

type transactionHooks struct {
	beforeLifecycleLock func(string)
	afterLifecycleLock  func(string)
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

// Ping verifies that durable operations can reach PostgreSQL.
func (s *Store) Ping(ctx context.Context) error {
	if err := s.pool.Ping(ctx); err != nil {
		return persistence("ping PostgreSQL", err)
	}
	return nil
}

// OperationalMetrics reads bounded queue, pin, bundle, and CT gauges.
func (s *Store) OperationalMetrics(ctx context.Context) (observability.Snapshot, error) {
	var snapshot observability.Snapshot
	err := s.pool.QueryRow(ctx, `WITH active AS (
		SELECT manifest FROM dataset_bundles WHERE bundle_id=(SELECT bundle_id FROM bundle_activations ORDER BY activation_order DESC LIMIT 1)
	) SELECT
		reserved_targets,
		maximum_targets,
		(SELECT count(*) FROM job_targets WHERE status='queued'),
		(SELECT count(*) FROM job_targets WHERE status='running'),
		(SELECT count(*) FROM bundle_pins),
		(SELECT count(*) FROM ct_checkpoints),
		COALESCE((SELECT GREATEST(EXTRACT(EPOCH FROM clock_timestamp()-max(tree_timestamp)),0) FROM ct_checkpoints WHERE tree_timestamp IS NOT NULL),0),
		COALESCE((SELECT count(*) FROM active, jsonb_array_elements(COALESCE(manifest->'sources','[]'::jsonb)) source WHERE source->>'status'<>'complete'),0),
		COALESCE((SELECT GREATEST(EXTRACT(EPOCH FROM clock_timestamp()-min((source->>'published_at')::timestamptz)),0) FROM active, jsonb_array_elements(COALESCE(manifest->'sources','[]'::jsonb)) source WHERE source ? 'published_at'),0),
		COALESCE((SELECT bundle_id FROM bundle_activations ORDER BY activation_order DESC LIMIT 1),'')
	FROM queue_capacity WHERE singleton=true`).Scan(
		&snapshot.ReservedTargets,
		&snapshot.MaximumTargets,
		&snapshot.QueuedTargets,
		&snapshot.RunningTargets,
		&snapshot.BundlePins,
		&snapshot.CTCheckpoints,
		&snapshot.CTIngestionLagSeconds,
		&snapshot.UnavailableSources,
		&snapshot.OldestSourceAgeSeconds,
		&snapshot.ActiveBundleID,
	)
	if err != nil {
		return observability.Snapshot{}, persistence("read operational metrics", err)
	}
	return snapshot, nil
}

// RegisterBundle records a validated local bundle before jobs may pin it.
func (s *Store) RegisterBundle(ctx context.Context, bundleID string, manifest []byte, compatible bool) error {
	if bundleID == "" || !json.Valid(manifest) {
		return model.NewError(model.CodeInvalidOptions, "bundle ID and JSON manifest are required", nil)
	}
	result, err := s.pool.Exec(ctx, `INSERT INTO dataset_bundles(bundle_id,manifest,compatible,available) VALUES($1,$2,$3,true)
		ON CONFLICT (bundle_id) DO UPDATE SET available=true
		WHERE dataset_bundles.manifest=EXCLUDED.manifest AND dataset_bundles.compatible=EXCLUDED.compatible`, bundleID, manifest, compatible)
	if err != nil {
		return persistence("register bundle", err)
	}
	if result.RowsAffected() != 1 {
		return model.NewError(model.CodeIdempotencyConflict, "bundle ID is already registered with different immutable content", nil)
	}
	return nil
}

// ActivateBundle serializes durable bundle admission with pruning and invokes
// filesystem publication before the activation transaction commits.
func (s *Store) ActivateBundle(ctx context.Context, bundleID string, manifest []byte, compatible bool, publish func() error) error {
	if bundleID == "" || !json.Valid(manifest) || publish == nil {
		return model.NewError(model.CodeInvalidOptions, "bundle ID, JSON manifest, and publication callback are required", nil)
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return persistence("begin bundle activation", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := s.lockLifecycle(ctx, tx, "bundle activation"); err != nil {
		return err
	}
	result, err := tx.Exec(ctx, `INSERT INTO dataset_bundles(bundle_id,manifest,compatible,available) VALUES($1,$2,$3,true)
		ON CONFLICT (bundle_id) DO UPDATE SET available=true
		WHERE dataset_bundles.manifest=EXCLUDED.manifest AND dataset_bundles.compatible=EXCLUDED.compatible`, bundleID, manifest, compatible)
	if err != nil {
		return persistence("register bundle activation", err)
	}
	if result.RowsAffected() != 1 {
		return model.NewError(model.CodeIdempotencyConflict, "bundle ID is already registered with different immutable content", nil)
	}
	if err := publish(); err != nil {
		return fmt.Errorf("publish bundle activation: %w", err)
	}
	result, err = tx.Exec(ctx, `INSERT INTO bundle_activations(bundle_id)
		SELECT bundle_id FROM dataset_bundles WHERE bundle_id=$1 AND available
		ON CONFLICT (bundle_id) DO UPDATE SET activation_order=nextval('bundle_activation_order'),activated_at=clock_timestamp()`, bundleID)
	if err != nil {
		return persistence("record bundle activation", err)
	}
	if result.RowsAffected() != 1 {
		return model.NewError(model.CodeBundleUnavailable, "bundle is unavailable", nil)
	}
	if err := tx.Commit(ctx); err != nil {
		return persistence("commit bundle activation", err)
	}
	return nil
}

// Submit atomically admits a job, reserves capacity, and creates its bundle pin.
func (s *Store) Submit(ctx context.Context, request jobs.SubmitRequest) (jobs.Job, error) {
	if request.OperatorID == "" || request.IdempotencyKey == "" || request.WorkCount() == 0 {
		return jobs.Job{}, model.NewError(model.CodeInvalidOptions, "operator, idempotency key, and targets are required", nil)
	}
	if err := jobs.ValidatePersistentAnalyzeRequests(request.Targets); err != nil {
		return jobs.Job{}, err
	}
	hash, err := payloadHash(request)
	if err != nil {
		return jobs.Job{}, fmt.Errorf("hash job payload: %w", err)
	}
	validationErrors := make([]error, len(request.Targets))
	reservations := len(request.Reclassifications)
	for index, targetRequest := range request.Targets {
		validationErrors[index] = jobs.ValidateAnalyzeRequest(targetRequest)
		if validationErrors[index] == nil {
			reservations++
		}
	}
	for _, replay := range request.Reclassifications {
		if replay.ReportID == "" || replay.BundleID == "" || replay.BundleID != request.BundleID {
			return jobs.Job{}, model.NewError(model.CodeInvalidOptions, "reclassification requires a report and the pinned batch bundle", nil)
		}
	}
	var result jobs.Job
	var existingID string
	err = s.replaySafeTransaction(ctx, "job admission", pgx.TxOptions{}, func(tx pgx.Tx) error {
		result = jobs.Job{}
		existingID = ""
		if err := s.lockLifecycle(ctx, tx, "job admission"); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1::text,0))`, request.OperatorID+":"+request.IdempotencyKey); err != nil {
			return persistence("lock idempotency key", err)
		}
		var existingHash string
		err := tx.QueryRow(ctx, `SELECT id,payload_hash FROM jobs WHERE operator_id=$1 AND idempotency_key=$2`, request.OperatorID, request.IdempotencyKey).Scan(&existingID, &existingHash)
		if err == nil {
			if existingHash != hash {
				return model.NewError(model.CodeIdempotencyConflict, "idempotency key was used for a different request", nil)
			}
			return nil
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return persistence("check idempotency key", err)
		}
		if request.BundleID != "" {
			var compatible bool
			if err := tx.QueryRow(ctx, `SELECT compatible FROM dataset_bundles WHERE bundle_id=$1 AND available FOR SHARE`, request.BundleID).Scan(&compatible); err != nil {
				if errors.Is(err, pgx.ErrNoRows) {
					return model.NewError(model.CodeBundleUnavailable, "requested bundle is unavailable", nil)
				}
				return persistence("validate requested bundle", err)
			}
			if !compatible {
				return model.NewError(model.CodeBundleIncompatible, "requested bundle is incompatible", nil)
			}
		}
		capacity, err := tx.Exec(ctx, `UPDATE queue_capacity SET reserved_targets=reserved_targets+$1 WHERE singleton=true AND reserved_targets+$1<=maximum_targets`, reservations)
		if err != nil {
			return persistence("reserve queue capacity", err)
		}
		if capacity.RowsAffected() != 1 {
			return model.NewError(model.CodeQueueCapacityExceeded, "nonterminal target capacity is exhausted", nil)
		}
		now := s.now().UTC()
		jobID, err := newID("job")
		if err != nil {
			return fmt.Errorf("create job ID: %w", err)
		}
		jobStatus := jobs.JobQueued
		if reservations == 0 {
			jobStatus = jobs.JobFailed
		}
		if _, err := tx.Exec(ctx, `INSERT INTO jobs(id,operator_id,idempotency_key,payload_hash,bundle_id,status,created_at,updated_at) VALUES($1,$2,$3,$4,NULLIF($5,''),$6,$7,$7)`, jobID, request.OperatorID, request.IdempotencyKey, hash, request.BundleID, jobStatus, now); err != nil {
			return persistence("insert job", err)
		}
		result = jobs.Job{ID: jobID, OperatorID: request.OperatorID, IdempotencyKey: request.IdempotencyKey, BundleID: request.BundleID, Status: jobStatus, CreatedAt: now, UpdatedAt: now, Targets: make([]jobs.Target, request.WorkCount())}
		for index, targetRequest := range request.Targets {
			targetID, idErr := newID("target")
			if idErr != nil {
				return fmt.Errorf("create target ID: %w", idErr)
			}
			copied := targetRequest
			encoded, encodeErr := json.Marshal(workRequest{Analyze: &copied})
			if encodeErr != nil {
				return fmt.Errorf("encode target request: %w", encodeErr)
			}
			targetStatus, reason := jobs.TargetQueued, ""
			if validationErrors[index] != nil {
				targetStatus, reason = jobs.TargetFailed, jobs.ValidationReason(validationErrors[index])
			}
			if _, err := tx.Exec(ctx, `INSERT INTO job_targets(id,job_id,input_index,request,status,terminal_reason) VALUES($1,$2,$3,$4,$5,NULLIF($6,''))`, targetID, jobID, index, encoded, targetStatus, reason); err != nil {
				return persistence("insert target", err)
			}
			result.Targets[index] = jobs.Target{ID: targetID, Index: index, Request: targetRequest, Status: targetStatus, TerminalReason: reason}
		}
		for requestIndex, reclassifyRequest := range request.Reclassifications {
			index := len(request.Targets) + requestIndex
			targetID, idErr := newID("target")
			if idErr != nil {
				return fmt.Errorf("create target ID: %w", idErr)
			}
			copied := reclassifyRequest
			encoded, encodeErr := json.Marshal(workRequest{Reclassify: &copied})
			if encodeErr != nil {
				return fmt.Errorf("encode reclassification request: %w", encodeErr)
			}
			if _, err := tx.Exec(ctx, `INSERT INTO job_targets(id,job_id,input_index,request,status) VALUES($1,$2,$3,$4,'queued')`, targetID, jobID, index, encoded); err != nil {
				return persistence("insert reclassification target", err)
			}
			result.Targets[index] = jobs.Target{ID: targetID, Index: index, Reclassify: &copied, Status: jobs.TargetQueued}
		}
		if request.BundleID != "" && reservations > 0 {
			if _, err := tx.Exec(ctx, `INSERT INTO bundle_pins(bundle_id,job_id) VALUES($1,$2)`, request.BundleID, jobID); err != nil {
				return persistence("pin job bundle", err)
			}
		}
		return nil
	})
	if err != nil {
		return jobs.Job{}, err
	}
	if existingID != "" {
		return s.Job(ctx, existingID)
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
	defer rows.Close()
	for rows.Next() {
		var target jobs.Target
		var requestJSON []byte
		var leaseExpires, nextAttempt *time.Time
		if err := rows.Scan(&target.ID, &target.Index, &requestJSON, &target.Status, &target.Attempts, &target.LeaseOwner, &leaseExpires, &nextAttempt, &target.TerminalReason, &target.ReportID); err != nil {
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
		target.ReportAvailable = target.ReportID != ""
		job.Targets = append(job.Targets, target)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return jobs.Job{}, persistence("iterate job targets", err)
	}
	return job, nil
}

// Claim leases one queued target using SKIP LOCKED.
func (s *Store) Claim(ctx context.Context, worker string, lease time.Duration) (jobs.Claim, error) {
	if worker == "" || lease <= 0 {
		return jobs.Claim{}, model.NewError(model.CodeInvalidOptions, "worker and positive lease are required", nil)
	}
	var claim jobs.Claim
	err := s.replaySafeTransaction(ctx, "target claim", pgx.TxOptions{}, func(tx pgx.Tx) error {
		claim = jobs.Claim{}
		if err := s.lockLifecycle(ctx, tx, "target claim"); err != nil {
			return err
		}
		var requestJSON []byte
		if err := tx.QueryRow(ctx, `SELECT jt.id,j.id,COALESCE(j.bundle_id,''),jt.request,jt.attempts FROM job_targets jt JOIN jobs j ON j.id=jt.job_id WHERE jt.status='queued' AND NOT j.cancel_requested AND (jt.next_attempt_at IS NULL OR jt.next_attempt_at<=clock_timestamp()) ORDER BY j.created_at,jt.input_index FOR UPDATE OF j,jt SKIP LOCKED LIMIT 1`).Scan(&claim.TargetID, &claim.JobID, &claim.BundleID, &requestJSON, &claim.Attempt); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return model.NewError(model.CodeCapabilityUnavailable, "no target is ready to claim", nil)
			}
			return persistence("select claim", err)
		}
		if err := decodeWorkRequest(requestJSON, &claim.Request, &claim.Reclassify); err != nil {
			return persistence("decode claimed request", err)
		}
		claim.Attempt++
		var err error
		claim.AttemptToken, err = newID("attempt")
		if err != nil {
			return fmt.Errorf("create attempt token: %w", err)
		}
		claim.LeaseExpires = s.now().UTC().Add(lease)
		if _, err := tx.Exec(ctx, `UPDATE job_targets SET status='running',attempts=$2,attempt_token=$3,lease_owner=$4,lease_expires_at=$5 WHERE id=$1`, claim.TargetID, claim.Attempt, claim.AttemptToken, worker, claim.LeaseExpires); err != nil {
			return persistence("update claim", err)
		}
		if _, err := tx.Exec(ctx, `UPDATE jobs SET status='running',updated_at=clock_timestamp() WHERE id=$1`, claim.JobID); err != nil {
			return persistence("update claimed job", err)
		}
		return nil
	})
	if err != nil {
		return jobs.Claim{}, err
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

// Complete stores a report and terminal target state in one transaction. Lease
// expiry makes an attempt eligible for recovery; the token remains authoritative
// until recovery revokes it so a completion racing recovery has one serial winner.
func (s *Store) Complete(ctx context.Context, targetID, token string, report model.Report, status jobs.TargetStatus, reason string) error {
	if status != jobs.TargetCompleted && status != jobs.TargetPartial && status != jobs.TargetFailed && status != jobs.TargetCancelled {
		return model.NewError(model.CodeInvalidOptions, "completion status is not terminal", nil)
	}
	if report.ID != "" {
		if err := report.ValidateReferences(); err != nil {
			return model.NewError(model.CodeInvalidOptions, "report references are invalid", err)
		}
	}
	return s.replaySafeTransaction(ctx, "target completion", pgx.TxOptions{}, func(tx pgx.Tx) error {
		if err := s.lockLifecycle(ctx, tx, "target completion"); err != nil {
			return err
		}
		var jobID, existingReason, existingReportID string
		var existingStatus jobs.TargetStatus
		if err := tx.QueryRow(ctx, `SELECT job_id,status,COALESCE(terminal_reason,''),COALESCE(report_id,'') FROM job_targets WHERE id=$1 AND attempt_token=$2 FOR UPDATE`, targetID, token).Scan(&jobID, &existingStatus, &existingReason, &existingReportID); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return model.NewError(model.CodeIdempotencyConflict, "attempt token is stale", nil)
			}
			return persistence("lock target completion", err)
		}
		if existingStatus != jobs.TargetRunning {
			matches := existingStatus == status && existingReason == reason && existingReportID == report.ID
			if matches && report.ID != "" {
				document, encodeErr := report.CanonicalJSON()
				if encodeErr != nil {
					return model.NewError(model.CodeInvalidOptions, "encode repeated report completion", encodeErr)
				}
				var existingDocument []byte
				if err := tx.QueryRow(ctx, `SELECT document FROM reports WHERE id=$1`, report.ID).Scan(&existingDocument); err != nil {
					return persistence("load repeated report completion", err)
				}
				matches = sameJSON(existingDocument, document)
			}
			if matches {
				return nil
			}
			return model.NewError(model.CodeIdempotencyConflict, "attempt completion conflicts with the committed result", nil)
		}
		if report.ID != "" {
			if err := saveReport(ctx, tx, report); err != nil {
				return err
			}
		}
		if _, err := tx.Exec(ctx, `UPDATE job_targets SET status=$2,terminal_reason=NULLIF($3,''),report_id=NULLIF($4,''),lease_owner=NULL,lease_expires_at=NULL WHERE id=$1`, targetID, status, reason, report.ID); err != nil {
			return persistence("terminalize target", err)
		}
		released, err := tx.Exec(ctx, `UPDATE queue_capacity SET reserved_targets=reserved_targets-1 WHERE singleton=true AND reserved_targets>0`)
		if err != nil {
			return persistence("release queue reservation", err)
		}
		if released.RowsAffected() != 1 {
			return persistence("release queue reservation", fmt.Errorf("reservation invariant is inconsistent"))
		}
		return finalizeJob(ctx, tx, jobID)
	})
}

// RequestCancel accepts cancellation from any authenticated shared operator.
func (s *Store) RequestCancel(ctx context.Context, jobID, operatorID string) error {
	if operatorID == "" {
		return model.NewError(model.CodeInvalidOptions, "cancelling operator is required", nil)
	}
	return s.replaySafeTransaction(ctx, "job cancellation", pgx.TxOptions{}, func(tx pgx.Tx) error {
		if err := s.lockLifecycle(ctx, tx, "job cancellation"); err != nil {
			return err
		}
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
			capacity, err := tx.Exec(ctx, `UPDATE queue_capacity SET reserved_targets=reserved_targets-$1 WHERE singleton=true AND reserved_targets >= $1`, released)
			if err != nil {
				return persistence("release cancelled reservations", err)
			}
			if capacity.RowsAffected() != 1 {
				return persistence("release cancelled reservations", fmt.Errorf("reservation invariant is inconsistent"))
			}
		}
		return finalizeJob(ctx, tx, jobID)
	})
}

// RecoverExpired requeues or terminalizes expired attempts under one lifecycle lock.
func (s *Store) RecoverExpired(ctx context.Context, maximumAttempts int) error {
	if maximumAttempts <= 0 {
		return model.NewError(model.CodeInvalidOptions, "maximum attempts must be positive", nil)
	}
	return s.replaySafeTransaction(ctx, "lease recovery", pgx.TxOptions{}, func(tx pgx.Tx) error {
		if err := s.lockLifecycle(ctx, tx, "lease recovery"); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `SELECT jt.id,jt.job_id,jt.attempts,j.cancel_requested FROM jobs j JOIN job_targets jt ON jt.job_id=j.id WHERE jt.status='running' AND jt.lease_expires_at<=clock_timestamp() ORDER BY j.created_at,jt.input_index FOR UPDATE OF j,jt`)
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
			capacity, err := tx.Exec(ctx, `UPDATE queue_capacity SET reserved_targets=reserved_targets-$1 WHERE singleton=true AND reserved_targets >= $1`, terminalCount)
			if err != nil {
				return persistence("release expired reservations", err)
			}
			if capacity.RowsAffected() != 1 {
				return persistence("release expired reservations", fmt.Errorf("reservation invariant is inconsistent"))
			}
		}
		for jobID := range affectedJobs {
			if err := finalizeJob(ctx, tx, jobID); err != nil {
				return err
			}
		}
		return nil
	})
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
	var protected bool
	err := s.replaySafeTransaction(ctx, "bundle pruning", pgx.TxOptions{}, func(tx pgx.Tx) error {
		if err := s.lockLifecycle(ctx, tx, "bundle pruning"); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM bundle_pins WHERE bundle_id=$1) OR EXISTS(
			SELECT 1 FROM (SELECT bundle_id FROM bundle_activations ORDER BY activation_order DESC LIMIT 3) protected WHERE bundle_id=$1)`, bundleID).Scan(&protected); err != nil {
			return persistence("check bundle pruning pins", err)
		}
		if !protected {
			result, err := tx.Exec(ctx, `UPDATE dataset_bundles SET available=false WHERE bundle_id=$1 AND available`, bundleID)
			if err != nil {
				return persistence("mark bundle unavailable", err)
			}
			if result.RowsAffected() != 1 {
				return model.NewError(model.CodeBundleUnavailable, "bundle is unavailable", nil)
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	return action(protected)
}

// RecordBundleActivation durably orders active and rollback-protected bundles.
func (s *Store) RecordBundleActivation(ctx context.Context, bundleID string) error {
	result, err := s.pool.Exec(ctx, `INSERT INTO bundle_activations(bundle_id)
		SELECT bundle_id FROM dataset_bundles WHERE bundle_id=$1 AND available
		ON CONFLICT (bundle_id) DO UPDATE SET activation_order=nextval('bundle_activation_order'),activated_at=clock_timestamp()`, bundleID)
	if err != nil {
		return persistence("record bundle activation", err)
	}
	if result.RowsAffected() != 1 {
		return model.NewError(model.CodeBundleUnavailable, "bundle is unavailable", nil)
	}
	return nil
}

// ProtectedBundles returns the active bundle and prior rollback generations.
func (s *Store) ProtectedBundles(ctx context.Context, limit int) ([]string, error) {
	if limit < 1 {
		return nil, model.NewError(model.CodeInvalidOptions, "protected bundle limit must be positive", nil)
	}
	rows, err := s.pool.Query(ctx, `SELECT bundle_id FROM bundle_activations ORDER BY activation_order DESC LIMIT $1`, limit)
	if err != nil {
		return nil, persistence("load protected bundles", err)
	}
	defer rows.Close()
	var bundles []string
	for rows.Next() {
		var bundleID string
		if err := rows.Scan(&bundleID); err != nil {
			return nil, persistence("scan protected bundle", err)
		}
		bundles = append(bundles, bundleID)
	}
	if err := rows.Err(); err != nil {
		return nil, persistence("iterate protected bundles", err)
	}
	return bundles, nil
}

// Import atomically adds normalized CT records to the local index.
func (s *Store) Import(ctx context.Context, records []ctlog.Record) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return persistence("begin CT import", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := insertCTRecords(ctx, tx, records); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return persistence("commit CT import", err)
	}
	return nil
}

// LoadCheckpoint returns the durable ingestion and verification positions for a log.
func (s *Store) LoadCheckpoint(ctx context.Context, logID string) (ctlog.Checkpoint, error) {
	var checkpoint ctlog.Checkpoint
	var treeTimestamp *time.Time
	err := s.pool.QueryRow(ctx, `SELECT log_id,next_index,verified_tree_size,verified_root_hash,tree_timestamp,tree_identity,key_identity FROM ct_checkpoints WHERE log_id=$1`, logID).Scan(
		&checkpoint.LogID, &checkpoint.NextIndex, &checkpoint.VerifiedTreeSize, &checkpoint.VerifiedRootHash, &treeTimestamp, &checkpoint.TreeIdentity, &checkpoint.KeyIdentity,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return ctlog.Checkpoint{}, nil
	}
	if err != nil {
		return ctlog.Checkpoint{}, persistence("load CT checkpoint", err)
	}
	if treeTimestamp != nil {
		checkpoint.TreeTimestamp = *treeTimestamp
	}
	return checkpoint, nil
}

// CommitCollection atomically stores CT records and collector progress.
func (s *Store) CommitCollection(ctx context.Context, records []ctlog.Record, checkpoint ctlog.Checkpoint) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return persistence("begin CT collection commit", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := insertCTRecords(ctx, tx, records); err != nil {
		return err
	}
	result, err := tx.Exec(ctx, `INSERT INTO ct_checkpoints(log_id,next_index,verified_tree_size,verified_root_hash,tree_timestamp,tree_identity,key_identity)
		VALUES($1,$2,$3,$4,$5,$6,$7)
		ON CONFLICT (log_id) DO UPDATE SET next_index=EXCLUDED.next_index,verified_tree_size=EXCLUDED.verified_tree_size,
		verified_root_hash=EXCLUDED.verified_root_hash,tree_timestamp=EXCLUDED.tree_timestamp,tree_identity=EXCLUDED.tree_identity,
		key_identity=EXCLUDED.key_identity,updated_at=clock_timestamp()
		WHERE EXCLUDED.next_index > ct_checkpoints.next_index OR
			(EXCLUDED.next_index = ct_checkpoints.next_index AND EXCLUDED.verified_tree_size >= ct_checkpoints.verified_tree_size)`, checkpoint.LogID,
		checkpoint.NextIndex, checkpoint.VerifiedTreeSize, checkpoint.VerifiedRootHash, nullTime(checkpoint.TreeTimestamp), checkpoint.TreeIdentity, checkpoint.KeyIdentity)
	if err != nil {
		return persistence("store CT checkpoint", err)
	}
	if result.RowsAffected() != 1 {
		return model.NewError(model.CodeIdempotencyConflict, "CT checkpoint would regress", nil)
	}
	if err := tx.Commit(ctx); err != nil {
		return persistence("commit CT collection", err)
	}
	return nil
}

// Discover returns deterministic recent concrete hostnames from the local CT index.
func (s *Store) Discover(ctx context.Context, root string, limit int) (ctlog.QueryResult, error) {
	if limit < 1 {
		return ctlog.QueryResult{}, model.NewError(model.CodeInvalidOptions, "CT discovery limit must be positive", nil)
	}
	rows, err := s.pool.Query(ctx, `WITH ranked AS (
		SELECT document,provenance,row_number() OVER (PARTITION BY name ORDER BY logged_at DESC,certificate_hash,source_id) AS ordinal
		FROM ct_records WHERE NOT wildcard AND (name=$1 OR name LIKE '%.' || $1)
	), selected AS (
		SELECT document,provenance FROM ranked WHERE ordinal=1
	)
	SELECT document,count(*) OVER (),bool_or(provenance <> 'verified_log') OVER ()
	FROM selected ORDER BY (document->>'logged_at')::timestamptz DESC,document->>'name' LIMIT $2`, root, limit)
	if err != nil {
		return ctlog.QueryResult{}, persistence("query CT index", err)
	}
	defer rows.Close()
	result := ctlog.QueryResult{}
	for rows.Next() {
		var document []byte
		if err := rows.Scan(&document, &result.Available, &result.Partial); err != nil {
			return ctlog.QueryResult{}, persistence("scan CT candidate", err)
		}
		var record ctlog.Record
		if err := json.Unmarshal(document, &record); err != nil {
			return ctlog.QueryResult{}, persistence("decode CT candidate", err)
		}
		result.Candidates = append(result.Candidates, ctlog.Candidate{
			Hostname: record.Name, CertificateHash: record.CertificateHash, LoggedAt: record.LoggedAt, SourceID: record.SourceID,
			Provenance: record.Provenance, Verification: record.Verification, CheckpointID: record.CheckpointID,
		})
	}
	if err := rows.Err(); err != nil {
		return ctlog.QueryResult{}, persistence("iterate CT candidates", err)
	}
	result.Omitted = result.Available - len(result.Candidates)
	identity := sha256.New()
	for _, candidate := range result.Candidates {
		_, _ = fmt.Fprintf(identity, "%s\x00%s\x00%s\n", candidate.Hostname, candidate.CertificateHash, candidate.CheckpointID)
	}
	result.IndexIdentity = "sha256:" + hex.EncodeToString(identity.Sum(nil))
	return result, nil
}

func insertCTRecords(ctx context.Context, tx pgx.Tx, records []ctlog.Record) error {
	for _, record := range records {
		document, err := json.Marshal(record)
		if err != nil {
			return fmt.Errorf("encode CT record: %w", err)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO ct_records(name,certificate_hash,source_id,wildcard,logged_at,provenance,document)
			VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT (name,certificate_hash,source_id) DO NOTHING`, record.Name, record.CertificateHash,
			record.SourceID, record.Wildcard, record.LoggedAt, record.Provenance, document); err != nil {
			return persistence("insert CT record", err)
		}
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
var _ ctlog.Store = (*Store)(nil)
var _ ctlog.Reader = (*Store)(nil)
