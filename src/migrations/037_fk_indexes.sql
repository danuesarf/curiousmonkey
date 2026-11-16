-- no-transaction
-- Indexes for foreign keys whose deletes cascade into big tables. Without one, Postgres finds the rows to delete (or set
-- to null) by reading the whole referencing table, once per deleted parent row. That happens when old callers are
-- pruned (every 6 hours), when an account is removed (all its roles and callers), and when old alert deliveries go.
-- Measured at 5M activity rows and 2M sessions: deleting 20 callers took 9.2 s without these, 80 ms with them; a
-- role page's top actions per caller 46 ms, then 2 ms. The composite primary key of activity_daily starts with
-- role_id, so it cannot serve a lookup by principal_id alone (Postgres 17 has no skip scan).
-- Built CONCURRENTLY so the tables keep taking writes; an interrupted build leaves an invalid index, dropped and rebuilt.
DO $$ BEGIN IF EXISTS (SELECT 1 FROM pg_index i JOIN pg_class c ON c.oid = i.indexrelid WHERE c.relname = 'activity_daily_principal_idx' AND NOT i.indisvalid) THEN EXECUTE 'DROP INDEX activity_daily_principal_idx'; END IF; END $$;
CREATE INDEX CONCURRENTLY IF NOT EXISTS activity_daily_principal_idx ON activity_daily (principal_id);
DO $$ BEGIN IF EXISTS (SELECT 1 FROM pg_index i JOIN pg_class c ON c.oid = i.indexrelid WHERE c.relname = 'role_sessions_principal_idx' AND NOT i.indisvalid) THEN EXECUTE 'DROP INDEX role_sessions_principal_idx'; END IF; END $$;
CREATE INDEX CONCURRENTLY IF NOT EXISTS role_sessions_principal_idx ON role_sessions (principal_id);
DO $$ BEGIN IF EXISTS (SELECT 1 FROM pg_index i JOIN pg_class c ON c.oid = i.indexrelid WHERE c.relname = 'track_sessions_principal_idx' AND NOT i.indisvalid) THEN EXECUTE 'DROP INDEX track_sessions_principal_idx'; END IF; END $$;
CREATE INDEX CONCURRENTLY IF NOT EXISTS track_sessions_principal_idx ON track_sessions (principal_id);
-- removing an account deletes its roles, each of which would read all of role_sessions
DO $$ BEGIN IF EXISTS (SELECT 1 FROM pg_index i JOIN pg_class c ON c.oid = i.indexrelid WHERE c.relname = 'role_sessions_role_idx' AND NOT i.indisvalid) THEN EXECUTE 'DROP INDEX role_sessions_role_idx'; END IF; END $$;
CREATE INDEX CONCURRENTLY IF NOT EXISTS role_sessions_role_idx ON role_sessions (role_id);
-- old deliveries are deleted 5,000 at a time, each setting alert_hits.delivery_id to null; most hits have none
DO $$ BEGIN IF EXISTS (SELECT 1 FROM pg_index i JOIN pg_class c ON c.oid = i.indexrelid WHERE c.relname = 'alert_hits_delivery_idx' AND NOT i.indisvalid) THEN EXECUTE 'DROP INDEX alert_hits_delivery_idx'; END IF; END $$;
CREATE INDEX CONCURRENTLY IF NOT EXISTS alert_hits_delivery_idx ON alert_hits (delivery_id) WHERE delivery_id IS NOT NULL;
-- Radar changes are kept 120 days; removing an account deletes its roles, each of which would read all of them.
-- Account-level changes have no role.
DO $$ BEGIN IF EXISTS (SELECT 1 FROM pg_index i JOIN pg_class c ON c.oid = i.indexrelid WHERE c.relname = 'changes_role_idx' AND NOT i.indisvalid) THEN EXECUTE 'DROP INDEX changes_role_idx'; END IF; END $$;
CREATE INDEX CONCURRENTLY IF NOT EXISTS changes_role_idx ON changes (role_id) WHERE role_id IS NOT NULL;
