CREATE EXTENSION IF NOT EXISTS pg_trgm;

CREATE TABLE IF NOT EXISTS inventory_assets (
    asset_id text PRIMARY KEY,
    hostname text COLLATE "C" NOT NULL UNIQUE,
    reversed_labels text COLLATE "C" NOT NULL,
    normalization_version text NOT NULL,
    archived_at timestamptz,
    deletion_generation bigint NOT NULL DEFAULT 0,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE INDEX IF NOT EXISTS inventory_assets_reversed_idx ON inventory_assets(reversed_labels text_pattern_ops, asset_id);
CREATE INDEX IF NOT EXISTS inventory_assets_hostname_prefix_idx ON inventory_assets(hostname text_pattern_ops, asset_id);
CREATE INDEX IF NOT EXISTS inventory_assets_hostname_trgm_idx ON inventory_assets USING gin(hostname gin_trgm_ops);

CREATE TABLE IF NOT EXISTS inventory_scopes (
    root text COLLATE "C" PRIMARY KEY,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE IF NOT EXISTS inventory_memberships (
    asset_id text NOT NULL REFERENCES inventory_assets(asset_id) ON DELETE CASCADE,
    root text COLLATE "C" NOT NULL REFERENCES inventory_scopes(root) ON DELETE CASCADE,
    hostname text COLLATE "C" NOT NULL,
    PRIMARY KEY (asset_id, root)
);
ALTER TABLE inventory_memberships ADD COLUMN IF NOT EXISTS hostname text COLLATE "C";
UPDATE inventory_memberships m SET hostname=a.hostname FROM inventory_assets a
WHERE m.asset_id=a.asset_id AND m.hostname IS NULL;
ALTER TABLE inventory_memberships ALTER COLUMN hostname SET NOT NULL;
CREATE INDEX IF NOT EXISTS inventory_memberships_scope_hostname_idx ON inventory_memberships(root, hostname);

CREATE TABLE IF NOT EXISTS inventory_sources (
    asset_id text NOT NULL REFERENCES inventory_assets(asset_id) ON DELETE CASCADE,
    source_kind text NOT NULL CHECK (source_kind IN ('hostname_import','ct','report')),
    source_id text NOT NULL,
    provenance text NOT NULL,
    verification text NOT NULL,
    first_observed_at timestamptz,
    last_observed_at timestamptz,
    first_received_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    last_received_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    provenance_ref text NOT NULL DEFAULT '',
    log_id text NOT NULL DEFAULT '',
    entry_index text NOT NULL DEFAULT '',
    checkpoint_id text NOT NULL DEFAULT '',
    PRIMARY KEY (asset_id, source_kind, source_id, provenance)
);
ALTER TABLE inventory_sources ADD COLUMN IF NOT EXISTS log_id text NOT NULL DEFAULT '';
ALTER TABLE inventory_sources ADD COLUMN IF NOT EXISTS entry_index text NOT NULL DEFAULT '';
ALTER TABLE inventory_sources ADD COLUMN IF NOT EXISTS checkpoint_id text NOT NULL DEFAULT '';

CREATE TABLE IF NOT EXISTS inventory_import_chunks (
    operation_id text NOT NULL,
    chunk_id text NOT NULL,
    payload_hash text NOT NULL,
    counts jsonb NOT NULL DEFAULT '{}'::jsonb,
    committed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (operation_id, chunk_id)
);

CREATE TABLE IF NOT EXISTS inventory_tombstones (
    hostname text COLLATE "C" PRIMARY KEY,
    deletion_generation bigint NOT NULL,
    suppressed boolean NOT NULL,
    deleted_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

ALTER TABLE job_targets ADD COLUMN IF NOT EXISTS inventory_asset_id text;
ALTER TABLE job_targets ADD COLUMN IF NOT EXISTS inventory_deletion_generation bigint;
