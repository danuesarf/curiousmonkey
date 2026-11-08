-- Per-job settings an operator chose, e.g. a smaller slice size when a region is rebuilt.
ALTER TABLE scan_jobs ADD COLUMN IF NOT EXISTS options jsonb NOT NULL DEFAULT '{}';
