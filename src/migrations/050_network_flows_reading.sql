-- VPC flow logs read in place (src/network/flows.js): each flow log keeps how far it is read, forward and back, so
-- nothing is listed twice; only the stored days are kept, and a prune finds old files by their time.

-- how far each flow log is read: every file from `back` up to `front` is read; `pending` files are listed but not read
-- yet; `status` says whether it is read at all (one flow log per VPC and kind of traffic is, so nothing counts twice)
ALTER TABLE net_flow_reads ADD COLUMN IF NOT EXISTS front timestamptz;
ALTER TABLE net_flow_reads ADD COLUMN IF NOT EXISTS back timestamptz;
ALTER TABLE net_flow_reads ADD COLUMN IF NOT EXISTS listed_at timestamptz;
ALTER TABLE net_flow_reads ADD COLUMN IF NOT EXISTS pending int NOT NULL DEFAULT 0;
ALTER TABLE net_flow_reads ADD COLUMN IF NOT EXISTS status text NOT NULL DEFAULT 'read';   -- read, skipped

CREATE INDEX IF NOT EXISTS net_flow_files_time ON net_flow_files (file_time);
ALTER TABLE net_flow_reads ADD COLUMN IF NOT EXISTS created timestamptz;               -- when the flow log was turned on

-- what a worker's background step did last, for Operations and the pages it fills (the VPC flow log reader first):
-- which worker, when, how long, what it did, and the last time it did anything
CREATE TABLE IF NOT EXISTS worker_steps (
  step        text PRIMARY KEY,
  worker_id   text,
  started_at  timestamptz,
  finished_at timestamptz,
  ms          int,
  error       text,
  result      jsonb,             -- the last step
  runs        bigint NOT NULL DEFAULT 0,
  worked_at   timestamptz,       -- the last step that read something or failed
  work        jsonb              -- what it did
);
