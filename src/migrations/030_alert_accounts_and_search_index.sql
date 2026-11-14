-- 1. Alert rules can name accounts, not only environments. Empty means every account; with both set, an account must
--    be named and in a named environment.
ALTER TABLE alert_rules ADD COLUMN IF NOT EXISTS accounts uuid[] NOT NULL DEFAULT '{}';

-- 2. Old alert messages are removed after a while (alerts.keepDays). A match must still remember that it was sent once
--    its message is gone, or it would be posted again: queued_at says so, delivery_id is only the link to the message.
ALTER TABLE alert_hits ADD COLUMN IF NOT EXISTS queued_at timestamptz;
UPDATE alert_hits h SET queued_at = coalesce(d.created_at, h.found_at) FROM alert_deliveries d WHERE d.id = h.delivery_id AND h.queued_at IS NULL;
DROP INDEX IF EXISTS alert_hits_unsent;
CREATE INDEX IF NOT EXISTS alert_hits_waiting ON alert_hits(rule_id) WHERE queued_at IS NULL;
CREATE INDEX IF NOT EXISTS alert_deliveries_done ON alert_deliveries(created_at) WHERE status <> 'pending';

-- 3. Trigram indexes for the search box (Ctrl K), which matches '%text%'. pg_trgm ships with Postgres and is a trusted
--    extension (13+), so the app's own user can usually add it. Where it cannot, search still works, without the index.
--    Not partial (WHERE deleted_at IS NULL): the planner did not pick a partial trigram index for the search query.
DO $$
BEGIN
  BEGIN
    CREATE EXTENSION IF NOT EXISTS pg_trgm;
  EXCEPTION WHEN OTHERS THEN
    RAISE NOTICE 'pg_trgm not available (%): search runs without trigram indexes', SQLERRM;
  END;
  IF EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'pg_trgm') THEN
    EXECUTE 'CREATE INDEX IF NOT EXISTS roles_name_trgm ON roles USING gin (name gin_trgm_ops)';
    EXECUTE 'CREATE INDEX IF NOT EXISTS roles_arn_trgm ON roles USING gin (arn gin_trgm_ops)';
    EXECUTE 'CREATE INDEX IF NOT EXISTS iam_access_keys_id_trgm ON iam_access_keys USING gin (key_id gin_trgm_ops)';
    EXECUTE 'CREATE INDEX IF NOT EXISTS gcp_principals_email_trgm ON gcp_principals USING gin (email gin_trgm_ops)';
    EXECUTE 'CREATE INDEX IF NOT EXISTS gcp_principals_member_trgm ON gcp_principals USING gin (member gin_trgm_ops)';
    EXECUTE 'CREATE INDEX IF NOT EXISTS gcp_principals_display_trgm ON gcp_principals USING gin (display_name gin_trgm_ops)';
  END IF;
END $$;
