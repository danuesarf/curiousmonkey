-- no-transaction
-- Built concurrently: scans and writes go on while they build. Each statement must be safe to run again.
-- principal_id: the merge in 040 moves rows by caller, and deleting a caller looks up the rows that point at it
-- (ON DELETE CASCADE / SET NULL). Without these, every deleted caller scans the whole table.
CREATE INDEX CONCURRENTLY IF NOT EXISTS role_sessions_principal_idx ON role_sessions (principal_id);
CREATE INDEX CONCURRENTLY IF NOT EXISTS track_sessions_principal_idx ON track_sessions (principal_id);
CREATE INDEX CONCURRENTLY IF NOT EXISTS activity_daily_principal_idx ON activity_daily (principal_id);
-- the scanner finds the other keys of a console session by role, session name and creation time
CREATE INDEX CONCURRENTLY IF NOT EXISTS role_sessions_signature_idx ON role_sessions (role_id, session_name, session_created) WHERE session_name IS NOT NULL;
