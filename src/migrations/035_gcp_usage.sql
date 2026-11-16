-- Google Cloud role usage, from audit logs read with the Logging API (entries.list), project by project. Optional:
-- off until turned on per connection, because it needs one more permission (logging.logEntries.list).
--
-- Admin Activity audit logs sit in every project's _Required bucket for 400 days, free, whether or not a sink exists.
-- Each project is read forward (new entries) and backward (the backfill, down to the lookback), one window at a time;
-- a window's counts and the cursor move commit together, so a crash re-reads that window and never counts twice.
-- Like CloudTrail on the AWS side, raw entries are never stored: only per-day counts of who checked which permission.

ALTER TABLE gcp_connections
  ADD COLUMN IF NOT EXISTS usage_enabled       boolean NOT NULL DEFAULT false,
  ADD COLUMN IF NOT EXISTS usage_lookback_days int     NOT NULL DEFAULT 30 CHECK (usage_lookback_days BETWEEN 1 AND 400),
  ADD COLUMN IF NOT EXISTS usage_data_access   boolean NOT NULL DEFAULT false,   -- also read Data Access logs (_Default bucket), when enabled there
  ADD COLUMN IF NOT EXISTS usage_analyzed_at   timestamptz;

-- One row per project ever read. Stable ids (gcp_projects is replaced on every IAM scan), and the storage counters:
-- rows written for this project, turned into bytes with each table's measured bytes per row.
CREATE TABLE gcp_usage_projects (
  id             serial PRIMARY KEY,
  connection_id  uuid NOT NULL REFERENCES gcp_connections(id) ON DELETE CASCADE,
  project_id     text NOT NULL,
  daily_rows     bigint NOT NULL DEFAULT 0,          -- rows in gcp_activity_daily
  summary_rows   bigint NOT NULL DEFAULT 0,          -- rows in gcp_usage_summary
  bytes_est      bigint NOT NULL DEFAULT 0,          -- refreshed hourly from the counters above
  bytes_at       timestamptz,
  UNIQUE (connection_id, project_id)
);

-- Where each project's reading stands. Leased one at a time, so several workers share projects.
CREATE TABLE gcp_log_cursors (
  project_ref    int  NOT NULL REFERENCES gcp_usage_projects(id) ON DELETE CASCADE,
  log            text NOT NULL CHECK (log IN ('activity','data_access')),
  hi_time        timestamptz,                        -- everything before this is read (forward edge)
  lo_time        timestamptz,                        -- everything from here on is read (backfill edge)
  run_after      timestamptz NOT NULL DEFAULT now(),
  lease_until    timestamptz,
  lease_by       text,
  entries_read   bigint NOT NULL DEFAULT 0,
  pages_read     bigint NOT NULL DEFAULT 0,
  windows_read   int    NOT NULL DEFAULT 0,
  last_error     text,
  error_at       timestamptz,
  errors_in_row  int    NOT NULL DEFAULT 0,
  updated_at     timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (project_ref, log)
);
CREATE INDEX gcp_log_cursors_due ON gcp_log_cursors (run_after);

-- Callers and permissions as small integers: an activity row is six fixed-width columns, about a third of the size
-- of the same row with text keys, and its indexes shrink with it.
CREATE TABLE gcp_usage_members (id serial PRIMARY KEY, member text NOT NULL UNIQUE);
CREATE TABLE gcp_usage_perms   (id serial PRIMARY KEY, permission text NOT NULL UNIQUE);

-- Per day, per project: who checked which permission, how often, how often denied.
CREATE TABLE gcp_activity_daily (
  project_ref  int  NOT NULL REFERENCES gcp_usage_projects(id) ON DELETE CASCADE,
  day          date NOT NULL,
  member_id    int  NOT NULL,
  perm_id      int  NOT NULL,
  count        int  NOT NULL DEFAULT 0,             -- granted
  denied       int  NOT NULL DEFAULT 0,
  PRIMARY KEY (project_ref, day, member_id, perm_id)
);
-- No other index: it would be the biggest thing on disk (a covering one adds 44% to every row). An identity's calls per
-- day read only the projects its summary rows name, each one primary-key range (project, days in the lookback).

-- First and last use of each permission by each caller in each project, kept up to date as days are added. The
-- usage analysis and an identity's permission list read this, never the daily table.
CREATE TABLE gcp_usage_summary (
  project_ref  int  NOT NULL REFERENCES gcp_usage_projects(id) ON DELETE CASCADE,
  member_id    int  NOT NULL,
  perm_id      int  NOT NULL,
  first_day    date NOT NULL,
  last_day     date NOT NULL,
  count        bigint NOT NULL DEFAULT 0,
  denied       bigint NOT NULL DEFAULT 0,
  PRIMARY KEY (project_ref, member_id, perm_id)
);
CREATE INDEX gcp_usage_summary_member ON gcp_usage_summary (member_id);

-- Logging API read quota, shared by every worker: a token bucket per connection (the quota is charged to the
-- identity's project, so one connection's reads never starve another's).
CREATE TABLE gcp_read_budget (
  connection_id uuid PRIMARY KEY REFERENCES gcp_connections(id) ON DELETE CASCADE,
  tokens        double precision NOT NULL,
  at            timestamptz NOT NULL DEFAULT now()
);

-- the outcome of the usage analysis, next to the permission analysis
ALTER TABLE gcp_principals
  ADD COLUMN IF NOT EXISTS used_count        int,
  ADD COLUMN IF NOT EXISTS unused_count      int,
  ADD COLUMN IF NOT EXISTS unconfirmed_count int,
  ADD COLUMN IF NOT EXISTS last_activity_at  date;
