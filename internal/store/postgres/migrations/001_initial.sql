CREATE TABLE IF NOT EXISTS schema_migrations (
    version bigint PRIMARY KEY,
    applied_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE TABLE IF NOT EXISTS queue_capacity (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    reserved_targets bigint NOT NULL CHECK (reserved_targets >= 0),
    maximum_targets bigint NOT NULL CHECK (maximum_targets > 0 AND reserved_targets <= maximum_targets)
);

CREATE TABLE IF NOT EXISTS dataset_bundles (
    bundle_id text PRIMARY KEY,
    manifest jsonb NOT NULL,
    compatible boolean NOT NULL,
	available boolean NOT NULL DEFAULT true,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE SEQUENCE IF NOT EXISTS bundle_activation_order;
CREATE TABLE IF NOT EXISTS bundle_activations (
	bundle_id text PRIMARY KEY REFERENCES dataset_bundles(bundle_id) ON DELETE CASCADE,
	activation_order bigint NOT NULL DEFAULT nextval('bundle_activation_order'),
	activated_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE TABLE IF NOT EXISTS jobs (
    id text PRIMARY KEY,
    operator_id text NOT NULL,
    idempotency_key text NOT NULL,
    payload_hash text NOT NULL,
    bundle_id text,
    status text NOT NULL CHECK (status IN ('queued','running','completed','partial','failed','cancelled')),
    cancel_requested boolean NOT NULL DEFAULT false,
    cancel_requested_by text,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    UNIQUE (operator_id, idempotency_key)
);

CREATE TABLE IF NOT EXISTS bundle_pins (
    bundle_id text NOT NULL,
    job_id text PRIMARY KEY REFERENCES jobs(id) ON DELETE CASCADE,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE INDEX IF NOT EXISTS bundle_pins_bundle_idx ON bundle_pins(bundle_id);

CREATE TABLE IF NOT EXISTS reports (
    id text PRIMARY KEY,
    original_report_id text,
    target text NOT NULL,
    provider_ids text[] NOT NULL DEFAULT '{}',
    product_ids text[] NOT NULL DEFAULT '{}',
    relations text[] NOT NULL DEFAULT '{}',
    status text NOT NULL,
    classified_at timestamptz NOT NULL,
    bundle_id text NOT NULL,
    document jsonb NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE INDEX IF NOT EXISTS reports_target_idx ON reports(target, classified_at DESC, id);
CREATE INDEX IF NOT EXISTS reports_provider_ids_idx ON reports USING gin(provider_ids);
CREATE INDEX IF NOT EXISTS reports_product_ids_idx ON reports USING gin(product_ids);
CREATE INDEX IF NOT EXISTS reports_relations_idx ON reports USING gin(relations);

CREATE TABLE IF NOT EXISTS observations (
    report_id text NOT NULL REFERENCES reports(id) ON DELETE CASCADE,
    observation_id text NOT NULL,
    subject text NOT NULL,
    observation_type text NOT NULL,
    observed_at timestamptz NOT NULL,
    document jsonb NOT NULL,
    PRIMARY KEY (report_id, observation_id)
);

CREATE TABLE IF NOT EXISTS evidence (
    report_id text NOT NULL REFERENCES reports(id) ON DELETE CASCADE,
    evidence_id text NOT NULL,
    provider_id text,
    product_id text,
    relation text NOT NULL,
    strength text NOT NULL,
    classified_at timestamptz NOT NULL,
    document jsonb NOT NULL,
    PRIMARY KEY (report_id, evidence_id)
);

CREATE TABLE IF NOT EXISTS findings (
    report_id text NOT NULL REFERENCES reports(id) ON DELETE CASCADE,
    finding_id text NOT NULL,
    subject text NOT NULL,
    provider_id text,
    product_id text,
    relation text NOT NULL,
    strength text NOT NULL,
    document jsonb NOT NULL,
    PRIMARY KEY (report_id, finding_id)
);
CREATE INDEX IF NOT EXISTS findings_search_idx ON findings(provider_id, product_id, relation, strength, subject);

CREATE TABLE IF NOT EXISTS finding_evidence (
    report_id text NOT NULL,
    finding_id text NOT NULL,
    evidence_id text NOT NULL,
    PRIMARY KEY (report_id, finding_id, evidence_id),
    FOREIGN KEY (report_id, finding_id) REFERENCES findings(report_id, finding_id) ON DELETE CASCADE,
    FOREIGN KEY (report_id, evidence_id) REFERENCES evidence(report_id, evidence_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS job_targets (
    id text PRIMARY KEY,
    job_id text NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
    input_index integer NOT NULL,
    request jsonb NOT NULL,
    status text NOT NULL CHECK (status IN ('queued','running','completed','partial','failed','cancelled')),
    attempts integer NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    attempt_token text,
    lease_owner text,
    lease_expires_at timestamptz,
    next_attempt_at timestamptz,
    terminal_reason text,
    report_id text REFERENCES reports(id),
    UNIQUE (job_id, input_index)
);
CREATE INDEX IF NOT EXISTS job_targets_claim_idx ON job_targets(status, next_attempt_at, job_id, input_index);
CREATE INDEX IF NOT EXISTS job_targets_lease_idx ON job_targets(status, lease_expires_at) WHERE status = 'running';
