ALTER TABLE job_targets ADD COLUMN IF NOT EXISTS inventory_asset_id text;
ALTER TABLE job_targets ADD COLUMN IF NOT EXISTS inventory_deletion_generation bigint;

CREATE TABLE IF NOT EXISTS inventory_projection_tasks (
    report_id text NOT NULL REFERENCES reports(id) ON DELETE RESTRICT,
    projector_version text NOT NULL,
    deletion_generation bigint NOT NULL DEFAULT 0,
    status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','running','failed')),
    attempts integer NOT NULL DEFAULT 0,
    lease_token text,
    lease_expires_at timestamptz,
    next_attempt_at timestamptz,
    last_error text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (report_id,projector_version)
);
CREATE INDEX IF NOT EXISTS inventory_projection_tasks_claim_idx
    ON inventory_projection_tasks(status,next_attempt_at,created_at,report_id);
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conrelid = 'inventory_projection_tasks'::regclass
          AND conname = 'inventory_projection_tasks_report_id_fkey'
          AND confdeltype = 'c'
    ) THEN
        ALTER TABLE inventory_projection_tasks DROP CONSTRAINT inventory_projection_tasks_report_id_fkey;
        ALTER TABLE inventory_projection_tasks ADD CONSTRAINT inventory_projection_tasks_report_id_fkey
            FOREIGN KEY (report_id) REFERENCES reports(id) ON DELETE RESTRICT;
    END IF;
END $$;

CREATE TABLE IF NOT EXISTS inventory_asset_contexts (
    asset_id text NOT NULL REFERENCES inventory_assets(asset_id) ON DELETE CASCADE,
    context_id text NOT NULL,
    deletion_generation bigint NOT NULL,
    latest_attempt_at timestamptz,
    latest_attempt_report_id text,
    last_positive_at timestamptz,
    last_positive_report_id text,
    description text NOT NULL DEFAULT '',
    description_hash text NOT NULL DEFAULT '',
    description_revision bigint NOT NULL DEFAULT 0,
    description_format_version text NOT NULL DEFAULT '',
    description_observed_at timestamptz,
    description_classified_at timestamptz,
    description_report_id text,
    description_observation_ids text[] NOT NULL DEFAULT '{}',
    description_evidence_ids text[] NOT NULL DEFAULT '{}',
    coverage text[] NOT NULL DEFAULT '{}',
    latest_coverage text[] NOT NULL DEFAULT '{}',
    omitted integer NOT NULL DEFAULT 0,
    latest_http_status integer,
    latest_http_at timestamptz,
    last_http_response_status integer,
    last_http_response_at timestamptz,
    last_http_response_report_id text,
    search_vector tsvector GENERATED ALWAYS AS (to_tsvector('simple', description)) STORED,
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (asset_id,context_id)
);
CREATE INDEX IF NOT EXISTS inventory_asset_contexts_search_idx ON inventory_asset_contexts USING gin(search_vector);
CREATE INDEX IF NOT EXISTS inventory_asset_contexts_context_idx ON inventory_asset_contexts(context_id,asset_id);
ALTER TABLE inventory_asset_contexts ADD COLUMN IF NOT EXISTS latest_coverage text[] NOT NULL DEFAULT '{}';
ALTER TABLE inventory_asset_contexts ADD COLUMN IF NOT EXISTS last_http_response_report_id text;

CREATE TABLE IF NOT EXISTS inventory_dns_state (
    asset_id text NOT NULL,
    context_id text NOT NULL,
    question_name text NOT NULL,
    rrtype text NOT NULL,
    latest_observed_at timestamptz NOT NULL,
    latest_outcome text NOT NULL,
    latest_report_id text NOT NULL,
    last_positive_at timestamptz,
    last_positive_report_id text,
    PRIMARY KEY (asset_id,context_id,question_name,rrtype),
    FOREIGN KEY (asset_id,context_id) REFERENCES inventory_asset_contexts(asset_id,context_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS inventory_context_support (
    asset_id text NOT NULL,
    context_id text NOT NULL,
    report_id text NOT NULL REFERENCES reports(id) ON DELETE RESTRICT,
    PRIMARY KEY (asset_id,context_id,report_id),
    FOREIGN KEY (asset_id,context_id) REFERENCES inventory_asset_contexts(asset_id,context_id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS inventory_context_support_report_idx ON inventory_context_support(report_id);
