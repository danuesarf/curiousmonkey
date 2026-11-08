-- track_calls had a primary key (session_id, event_id) and an index (session_id, at): two indexes per stored call.
-- One key on (session_id, at, event_id) serves both the session timeline and de-duplication (an event's time
-- never changes), and halves the index work when a backfill stores calls.
ALTER TABLE track_calls DROP CONSTRAINT IF EXISTS track_calls_pkey;
DROP INDEX IF EXISTS track_calls_at_idx;
ALTER TABLE track_calls ADD PRIMARY KEY (session_id, at, event_id);
