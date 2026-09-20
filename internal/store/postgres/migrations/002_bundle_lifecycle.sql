ALTER TABLE dataset_bundles ADD COLUMN IF NOT EXISTS available boolean NOT NULL DEFAULT true;

CREATE SEQUENCE IF NOT EXISTS bundle_activation_order;
CREATE TABLE IF NOT EXISTS bundle_activations (
    bundle_id text PRIMARY KEY REFERENCES dataset_bundles(bundle_id) ON DELETE CASCADE,
    activation_order bigint NOT NULL DEFAULT nextval('bundle_activation_order'),
    activated_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
