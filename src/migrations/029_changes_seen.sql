-- One change feed for Radar and the bell: what each person has seen is the newest change id they looked at.
-- A change's `at` is when it happened, which can be earlier than when it was recorded (a new caller found in older
-- history), so the id, not the time, says what is new.
ALTER TABLE users ADD COLUMN IF NOT EXISTS changes_seen_id bigint;
