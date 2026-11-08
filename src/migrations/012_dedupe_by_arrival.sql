-- seen_events and role_sessions were pruned by event time, so reading old history (a backfill, a resume)
-- lost them almost at once: a resumed read then counted its overlap again, and a session started in one
-- slice could not be matched to its calls in the next. Prune by when the row was written instead.
ALTER TABLE seen_events ADD COLUMN IF NOT EXISTS seen_at timestamptz NOT NULL DEFAULT now();
CREATE INDEX IF NOT EXISTS seen_events_seen_idx ON seen_events (seen_at);
ALTER TABLE role_sessions ADD COLUMN IF NOT EXISTS seen_at timestamptz NOT NULL DEFAULT now();
CREATE INDEX IF NOT EXISTS role_sessions_seen_idx ON role_sessions (seen_at);
