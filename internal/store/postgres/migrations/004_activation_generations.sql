CREATE SEQUENCE IF NOT EXISTS bundle_activation_generation;

CREATE TABLE IF NOT EXISTS bundle_activation_generations (
    operation_id text PRIMARY KEY,
    generation bigint NOT NULL DEFAULT nextval('bundle_activation_generation'),
    bundle_id text NOT NULL REFERENCES dataset_bundles(bundle_id) ON DELETE RESTRICT,
    candidate_hash text NOT NULL,
    action text NOT NULL,
    activated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (generation)
);

INSERT INTO bundle_activation_generations(operation_id,generation,bundle_id,candidate_hash,action,activated_at)
SELECT 'legacy-' || activation_order || '-' || bundle_id,activation_order,bundle_id,'','migration',activated_at
FROM bundle_activations
ON CONFLICT DO NOTHING;

SELECT setval(
    'bundle_activation_generation',
    GREATEST(COALESCE((SELECT max(generation) FROM bundle_activation_generations),0)+1,1),
    false
);
