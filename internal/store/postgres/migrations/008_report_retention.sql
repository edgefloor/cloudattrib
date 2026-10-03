CREATE INDEX IF NOT EXISTS reports_retention_idx ON reports(created_at,id);
CREATE INDEX IF NOT EXISTS reports_original_report_idx ON reports(original_report_id) WHERE original_report_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS job_targets_reclassify_input_idx
    ON job_targets ((request->'reclassify'->>'report_id'))
    WHERE status IN ('queued','running') AND request ? 'reclassify';

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conrelid = 'reports'::regclass AND conname = 'reports_original_report_id_fkey'
    ) THEN
        ALTER TABLE reports ADD CONSTRAINT reports_original_report_id_fkey
            FOREIGN KEY (original_report_id) REFERENCES reports(id) ON DELETE RESTRICT NOT VALID;
    END IF;
END $$;
