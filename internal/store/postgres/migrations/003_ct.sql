CREATE TABLE IF NOT EXISTS ct_records (
    name text NOT NULL,
    certificate_hash text NOT NULL,
    source_id text NOT NULL,
    wildcard boolean NOT NULL,
    logged_at timestamptz NOT NULL,
    provenance text NOT NULL CHECK (provenance IN ('verified_log','log_unverified','imported_unverified')),
    document jsonb NOT NULL,
    PRIMARY KEY (name, certificate_hash, source_id)
);
CREATE INDEX IF NOT EXISTS ct_records_discovery_idx ON ct_records(name, wildcard, logged_at DESC);

CREATE TABLE IF NOT EXISTS ct_checkpoints (
    log_id text PRIMARY KEY,
    next_index bigint NOT NULL CHECK (next_index >= 0),
    verified_tree_size bigint NOT NULL CHECK (verified_tree_size >= 0),
    verified_root_hash bytea NOT NULL,
    tree_timestamp timestamptz,
    tree_identity text NOT NULL,
    key_identity text NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
