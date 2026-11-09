-- Catch-up reads: between daily scans, read only the CloudTrail events that arrived since the last read.
ALTER TABLE scan_runs DROP CONSTRAINT IF EXISTS scan_runs_trigger_check;
ALTER TABLE scan_runs ADD CONSTRAINT scan_runs_trigger_check CHECK (trigger IN ('schedule','manual','onboarding','tail'));
CREATE INDEX IF NOT EXISTS scan_runs_account_created_idx ON scan_runs (account_id, created_at DESC);
