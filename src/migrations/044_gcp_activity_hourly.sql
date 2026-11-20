-- Google Cloud usage by the hour, for Space (heights, the glow of the hour, the replay): calls per caller per project
-- per hour, kept 31 days like AWS's hourly rollups. No permission dimension: per day is enough for that, and an hour
-- row per caller stays small. Written with the daily counts, in the same transaction as the cursor's move.
CREATE TABLE IF NOT EXISTS gcp_activity_hourly (
  project_ref  int         NOT NULL REFERENCES gcp_usage_projects(id) ON DELETE CASCADE,
  hour         timestamptz NOT NULL,
  member_id    int         NOT NULL,
  count        int         NOT NULL DEFAULT 0,
  denied       int         NOT NULL DEFAULT 0,
  PRIMARY KEY (project_ref, hour, member_id)
);
CREATE INDEX IF NOT EXISTS gcp_activity_hourly_hour ON gcp_activity_hourly (hour);
