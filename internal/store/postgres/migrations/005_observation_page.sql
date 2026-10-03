CREATE INDEX IF NOT EXISTS observations_report_time_id_idx
    ON observations(report_id, observed_at, observation_id);
