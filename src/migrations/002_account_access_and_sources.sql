-- How the worker reaches an account, and where it reads CloudTrail from.
ALTER TABLE cloud_accounts
  ALTER COLUMN role_arn DROP NOT NULL,
  ADD COLUMN auth_mode       text NOT NULL DEFAULT 'assume_role' CHECK (auth_mode IN ('assume_role','access_key')),
  ADD COLUMN base_identity   text NOT NULL DEFAULT 'system' CHECK (base_identity IN ('system','stored')),
  ADD COLUMN credentials_enc text,          -- AES-GCM {accessKeyId, secretAccessKey, sessionToken}; never returned by the API
  ADD COLUMN credentials_hint text,         -- e.g. AKIA…7Q2F, for display
  ADD COLUMN trust_principal text,          -- only used to render the trust policy snippet
  ADD COLUMN event_source    text NOT NULL DEFAULT 'event-history' CHECK (event_source IN ('event-history','s3')),
  ADD COLUMN s3_bucket       text,
  ADD COLUMN s3_prefix       text,
  ADD COLUMN s3_org_id       text,
  ADD COLUMN s3_region       text,
  ADD COLUMN lookback_days   int NOT NULL DEFAULT 90 CHECK (lookback_days BETWEEN 1 AND 730),
  ADD COLUMN updated_at      timestamptz;

-- One checkpoint per account and region, whichever source wrote it, so switching source neither re-reads nor skips history.
ALTER TABLE scan_checkpoints DROP CONSTRAINT scan_checkpoints_pkey;
ALTER TABLE scan_checkpoints ADD PRIMARY KEY (account_id, region);

-- What the worker's own (system) credentials resolve to, reported at startup.
ALTER TABLE workers ADD COLUMN aws_identity jsonb;
