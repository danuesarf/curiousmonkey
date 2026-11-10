-- no-transaction
-- Space sums the last 7 days of activity on every load. Without an index on day that read every day ever stored;
-- with it, only the last week. role_id and the counts ride along so most of it never touches the table.
-- Built CONCURRENTLY so a large activity_daily keeps taking writes while it builds; a build that was interrupted
-- leaves an invalid index behind, which is dropped and rebuilt.
DO $$ BEGIN IF EXISTS (SELECT 1 FROM pg_index i JOIN pg_class c ON c.oid = i.indexrelid WHERE c.relname = 'activity_daily_day_idx' AND NOT i.indisvalid) THEN EXECUTE 'DROP INDEX activity_daily_day_idx'; END IF; END $$;
CREATE INDEX CONCURRENTLY IF NOT EXISTS activity_daily_day_idx ON activity_daily (day, role_id) INCLUDE (count, error_count);
-- Space looks up the sessions in an account that were entered from another session (role chaining). Most sessions
-- were not, so a partial index holds only the chained ones and costs nothing for the rest.
DO $$ BEGIN IF EXISTS (SELECT 1 FROM pg_index i JOIN pg_class c ON c.oid = i.indexrelid WHERE c.relname = 'track_sessions_chained_idx' AND NOT i.indisvalid) THEN EXECUTE 'DROP INDEX track_sessions_chained_idx'; END IF; END $$;
CREATE INDEX CONCURRENTLY IF NOT EXISTS track_sessions_chained_idx ON track_sessions (account_id, started_at) WHERE parent_key_id IS NOT NULL;
