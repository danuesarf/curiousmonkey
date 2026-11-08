-- seen_events is pruned by seen_at (since 012); nothing reads event_time any more, so its index only cost writes and
-- about a quarter of the table's index space.
DROP INDEX IF EXISTS seen_events_time_idx;
