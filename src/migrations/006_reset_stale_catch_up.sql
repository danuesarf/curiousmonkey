-- 005 stamped caught_up_at on every checkpoint, including reads that were only part way through.
-- Clear the stamps whose read position is well behind them; the read sets it again when it reaches the present.
UPDATE scan_checkpoints SET caught_up_at = NULL WHERE caught_up_at IS NOT NULL AND last_event_time < caught_up_at - interval '1 day';
