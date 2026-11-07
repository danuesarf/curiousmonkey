-- "Can't resolve": a reviewer tried and gave up, with a note. The service stays unconfirmed (safe), and the
-- name reopens when it is still being called after reopen_at.
ALTER TABLE event_action_map DROP CONSTRAINT event_action_map_status_check;
ALTER TABLE event_action_map ADD CONSTRAINT event_action_map_status_check CHECK (status IN ('suggested','accepted','unresolved'));
ALTER TABLE event_action_map ADD COLUMN reopen_at timestamptz;

-- A region's history is complete when its read has reached the present at least once (and its old end is covered).
ALTER TABLE scan_checkpoints ADD COLUMN caught_up_at timestamptz;
UPDATE scan_checkpoints SET caught_up_at = last_run_at;   -- rows written by earlier versions came from finished reads
