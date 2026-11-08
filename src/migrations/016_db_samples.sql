-- Database size and free disk, sampled hourly by the app, for growth and days-until-full on the Health page.
CREATE TABLE db_samples (
  taken_at   timestamptz PRIMARY KEY DEFAULT now(),
  db_bytes   bigint NOT NULL,
  disk_free  bigint,                -- null when the disk under Postgres cannot be seen
  disk_total bigint,
  tables     jsonb NOT NULL DEFAULT '{}'
);
