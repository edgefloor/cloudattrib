-- Metadata and durable work exist without pgvector. The vector extension and
-- vector table are installed only when semantic search is explicitly enabled.
CREATE TABLE IF NOT EXISTS inventory_embedding_generations (
    generation_id text PRIMARY KEY,
    model_id text NOT NULL,
    model_revision text NOT NULL,
    artifact_sha256 text NOT NULL,
    model_license text NOT NULL,
    dimensions integer NOT NULL CHECK (dimensions BETWEEN 1 AND 2000),
    document_format_version text NOT NULL,
    preprocessing text NOT NULL,
    query_prefix text NOT NULL,
    document_prefix text NOT NULL,
    metric text NOT NULL CHECK (metric = 'cosine'),
    status text NOT NULL CHECK (status IN ('building','active','retained')),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
ALTER TABLE inventory_embedding_generations ADD COLUMN IF NOT EXISTS retained_at timestamptz;
CREATE UNIQUE INDEX IF NOT EXISTS inventory_embedding_one_active_generation_idx
    ON inventory_embedding_generations(status) WHERE status='active';

CREATE TABLE IF NOT EXISTS inventory_embedding_tasks (
    asset_id text NOT NULL,
    context_id text NOT NULL,
    generation_id text NOT NULL REFERENCES inventory_embedding_generations(generation_id) ON DELETE CASCADE,
    description_revision bigint NOT NULL,
    description_hash text NOT NULL,
    deletion_generation bigint NOT NULL,
    status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','running','failed')),
    attempts integer NOT NULL DEFAULT 0,
    lease_token text,
    lease_expires_at timestamptz,
    next_attempt_at timestamptz,
    last_error text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (asset_id,context_id,generation_id),
    FOREIGN KEY (asset_id,context_id) REFERENCES inventory_asset_contexts(asset_id,context_id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS inventory_embedding_tasks_claim_idx
    ON inventory_embedding_tasks(status,next_attempt_at,created_at,asset_id,context_id,generation_id);
-- Claiming work orders by creation time within one generation. The status and
-- retry index above cannot satisfy that order and otherwise makes each claim
-- scan and sort the whole pending queue at large inventory sizes.
CREATE INDEX IF NOT EXISTS inventory_embedding_tasks_generation_claim_idx
    ON inventory_embedding_tasks(generation_id,created_at,asset_id,context_id) WHERE attempts<5;
