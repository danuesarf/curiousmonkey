-- Worker telemetry: the latest snapshot on the worker row, and a 24-hour series for charts.
ALTER TABLE workers ADD COLUMN IF NOT EXISTS concurrency int;
ALTER TABLE workers ADD COLUMN IF NOT EXISTS runtime jsonb;           -- node version, cpu cores, memory limits; fixed for the process
ALTER TABLE workers ADD COLUMN IF NOT EXISTS telemetry jsonb;         -- latest sample
ALTER TABLE workers ADD COLUMN IF NOT EXISTS end_reason text;         -- stopped | lost | out-of-memory (likely)

CREATE TABLE IF NOT EXISTS worker_samples (
  worker_id   text NOT NULL,
  at          timestamptz NOT NULL DEFAULT now(),
  rss         bigint, heap_used bigint, heap_limit bigint, external bigint,
  mem_used    bigint, mem_limit bigint,
  cpu_pct     real,   cpu_limit real,
  loop_p99_ms real,   active_jobs int,
  events      int,    s3_files int, s3_bytes bigint, api_calls int, throttles int,
  PRIMARY KEY (worker_id, at)
);
CREATE INDEX IF NOT EXISTS worker_samples_at_idx ON worker_samples (at);
