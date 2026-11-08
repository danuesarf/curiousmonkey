-- S3 trails are read file by file. One cursor per account and region: the last file read (keys sort by delivery
-- time), the start of what has been read, and an in-progress backfill when the lookback was widened.
CREATE TABLE IF NOT EXISTS trail_cursors (
  account_id  uuid NOT NULL REFERENCES cloud_accounts(id) ON DELETE CASCADE,
  region      text NOT NULL,
  last_key    text,                 -- last file read going forward
  after_time  timestamptz,          -- when no file has been read yet: read files delivered after this
  lo_time     timestamptz,          -- history is read from here on
  back_to     timestamptz,          -- backfill in progress: read files delivered before this ...
  back_key    text,                 -- ... after this one
  floor_time  timestamptz,          -- moved over from the per-slice reader: events before this were counted by it
  files_read  bigint NOT NULL DEFAULT 0,
  bytes_read  bigint NOT NULL DEFAULT 0,
  updated_at  timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (account_id, region)
);
