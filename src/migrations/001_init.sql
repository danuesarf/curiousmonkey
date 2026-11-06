-- Curious Monkey schema. One workspace per deployment (self-hosted).

CREATE TABLE workspace (
  id           int PRIMARY KEY DEFAULT 1 CHECK (id = 1),
  name         text NOT NULL,
  slug         text NOT NULL,
  external_id  text NOT NULL,
  signin_method text NOT NULL DEFAULT 'local',
  created_at   timestamptz NOT NULL DEFAULT now()
);

-- ===== people and access =====
CREATE TABLE users (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  email           text NOT NULL,
  name            text NOT NULL,
  password_hash   text,
  role            text NOT NULL CHECK (role IN ('owner','admin','reviewer','account_owner','auditor')),
  team            text CHECK (team IN ('infrasec','infosec')),
  scope_accounts  uuid[],                      -- NULL = every account
  totp_secret     text,                        -- encrypted
  totp_confirmed  boolean NOT NULL DEFAULT false,
  oidc_subject    text UNIQUE,
  disabled        boolean NOT NULL DEFAULT false,
  last_login_at   timestamptz,
  created_at      timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX users_email_uq ON users (lower(email));

CREATE TABLE sessions (
  id          text PRIMARY KEY,                -- sha256 of the cookie token
  user_id     uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  csrf        text NOT NULL,
  ip          text,
  user_agent  text,
  created_at  timestamptz NOT NULL DEFAULT now(),
  expires_at  timestamptz NOT NULL
);
CREATE INDEX sessions_user_idx ON sessions (user_id);

CREATE TABLE invites (
  token_hash      text PRIMARY KEY,
  email           text NOT NULL,
  role            text NOT NULL,
  team            text,
  scope_accounts  uuid[],
  created_by      uuid REFERENCES users(id) ON DELETE SET NULL,
  expires_at      timestamptz NOT NULL,
  accepted_at     timestamptz,
  created_at      timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE sso_group_mappings (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  group_name      text NOT NULL UNIQUE,
  role            text NOT NULL CHECK (role IN ('owner','admin','reviewer','account_owner','auditor')),
  team            text CHECK (team IN ('infrasec','infosec')),
  scope_accounts  uuid[]
);

-- ===== connected cloud accounts =====
CREATE TABLE cloud_accounts (
  id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  provider       text NOT NULL DEFAULT 'aws',
  account_id     text NOT NULL UNIQUE,
  name           text NOT NULL,
  environment    text NOT NULL DEFAULT 'production',
  role_arn       text NOT NULL,
  regions        text[] NOT NULL,
  method         text,
  status         text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','connected','error')),
  status_detail  jsonb,
  last_scan_at   timestamptz,
  created_by     uuid REFERENCES users(id) ON DELETE SET NULL,
  created_at     timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE scan_runs (
  id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  account_id   uuid NOT NULL REFERENCES cloud_accounts(id) ON DELETE CASCADE,
  requested_by uuid REFERENCES users(id) ON DELETE SET NULL,
  trigger      text NOT NULL CHECK (trigger IN ('schedule','manual','onboarding')),
  status       text NOT NULL DEFAULT 'queued' CHECK (status IN ('queued','running','succeeded','failed','partial')),
  created_at   timestamptz NOT NULL DEFAULT now(),
  started_at   timestamptz,
  finished_at  timestamptz,
  stats        jsonb,
  error        text
);
CREATE INDEX scan_runs_status_idx ON scan_runs (status, created_at);
CREATE INDEX scan_runs_account_idx ON scan_runs (account_id, created_at DESC);

-- ===== job queue (Postgres, claimed with FOR UPDATE SKIP LOCKED) =====
-- A scan run is a set of jobs. Jobs of a lower stage must finish before the next stage starts:
--   stage 1 inventory | stage 2 events (one per region) + advisor | stage 3 analyze
CREATE TABLE scan_jobs (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  run_id        uuid NOT NULL REFERENCES scan_runs(id) ON DELETE CASCADE,
  account_id    uuid NOT NULL REFERENCES cloud_accounts(id) ON DELETE CASCADE,
  kind          text NOT NULL CHECK (kind IN ('inventory','events','advisor','analyze')),
  region        text NOT NULL DEFAULT '',
  stage         int  NOT NULL,
  status        text NOT NULL DEFAULT 'queued'
                CHECK (status IN ('queued','running','succeeded','failed','dead','canceled')),
  attempts      int  NOT NULL DEFAULT 0,
  max_attempts  int  NOT NULL DEFAULT 5,
  run_after     timestamptz NOT NULL DEFAULT now(),   -- backoff: not claimable before this
  locked_by     text,
  locked_until  timestamptz,                          -- lease; extended by heartbeats
  heartbeat_at  timestamptz,
  progress      jsonb NOT NULL DEFAULT '{}',          -- e.g. {"slice":"2026-10-01T06:00Z","done":120,"total":360}
  last_error    text,
  error_retryable boolean,
  created_at    timestamptz NOT NULL DEFAULT now(),
  started_at    timestamptz,
  finished_at   timestamptz,
  UNIQUE (run_id, kind, region)
);
CREATE INDEX scan_jobs_claim_idx ON scan_jobs (status, run_after) WHERE status IN ('queued','running');
CREATE INDEX scan_jobs_run_idx ON scan_jobs (run_id, stage);

CREATE TABLE scan_job_log (
  id      bigserial PRIMARY KEY,
  job_id  uuid NOT NULL REFERENCES scan_jobs(id) ON DELETE CASCADE,
  at      timestamptz NOT NULL DEFAULT now(),
  level   text NOT NULL DEFAULT 'info',
  message text NOT NULL,
  detail  jsonb
);
CREATE INDEX scan_job_log_job_idx ON scan_job_log (job_id, id);

CREATE TABLE workers (
  id           text PRIMARY KEY,                      -- hostname:pid:random
  hostname     text NOT NULL,
  version      text,
  started_at   timestamptz NOT NULL DEFAULT now(),
  heartbeat_at timestamptz NOT NULL DEFAULT now(),
  current_job  uuid,
  jobs_done    int NOT NULL DEFAULT 0,
  jobs_failed  int NOT NULL DEFAULT 0,
  stopped_at   timestamptz
);

-- One checkpoint per account, region and source. The next scan resumes after it.
CREATE TABLE scan_checkpoints (
  account_id       uuid NOT NULL REFERENCES cloud_accounts(id) ON DELETE CASCADE,
  region           text NOT NULL,
  source           text NOT NULL DEFAULT 'event-history',
  first_event_time timestamptz,               -- start of the stored history
  last_event_time  timestamptz NOT NULL,      -- everything before this is already stored
  last_run_at      timestamptz NOT NULL DEFAULT now(),
  events_read      bigint NOT NULL DEFAULT 0,
  gap_detected     boolean NOT NULL DEFAULT false,
  PRIMARY KEY (account_id, region, source)
);

-- Only needed for the overlap window that guards against late delivery.
CREATE TABLE seen_events (
  account_id  uuid NOT NULL REFERENCES cloud_accounts(id) ON DELETE CASCADE,
  event_id    text NOT NULL,
  event_time  timestamptz NOT NULL,
  PRIMARY KEY (account_id, event_id)
);
CREATE INDEX seen_events_time_idx ON seen_events (event_time);

CREATE TABLE data_event_sources (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  account_id    uuid NOT NULL REFERENCES cloud_accounts(id) ON DELETE CASCADE,
  source_name   text NOT NULL,
  source_type   text NOT NULL CHECK (source_type IN ('trail','event-data-store')),
  resource_type text NOT NULL,
  arn_patterns  text[] NOT NULL,
  read_write    text NOT NULL DEFAULT 'All',
  readable      boolean NOT NULL DEFAULT false,   -- can the configured scan source read these events?
  discovered_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (account_id, source_name, resource_type)
);

CREATE TABLE managed_policy_cache (
  arn         text NOT NULL,
  version_id  text NOT NULL,
  document    jsonb NOT NULL,
  fetched_at  timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (arn, version_id)
);

-- ===== IAM inventory =====
CREATE TABLE roles (
  id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  account_id       uuid NOT NULL REFERENCES cloud_accounts(id) ON DELETE CASCADE,
  arn              text NOT NULL,
  name             text NOT NULL,
  path             text NOT NULL DEFAULT '/',
  kind             text NOT NULL CHECK (kind IN ('custom','service-linked','identity-center')),
  permission_set   text,
  trust_policy     jsonb,
  boundary_arn     text,
  tags             jsonb NOT NULL DEFAULT '{}',
  created_in_aws   timestamptz,
  last_used_at     timestamptz,
  last_used_region text,
  inline_count     int NOT NULL DEFAULT 0,
  attached_count   int NOT NULL DEFAULT 0,
  -- analysis results
  granted_count      int NOT NULL DEFAULT 0,
  used_count         int NOT NULL DEFAULT 0,
  unused_count       int NOT NULL DEFAULT 0,
  unconfirmed_count  int NOT NULL DEFAULT 0,
  risk             text NOT NULL DEFAULT 'Low' CHECK (risk IN ('High','Medium','Low')),
  risk_score       int NOT NULL DEFAULT 0,
  risk_reasons     jsonb NOT NULL DEFAULT '[]',
  reviewer_team    text NOT NULL DEFAULT 'infrasec' CHECK (reviewer_team IN ('infrasec','infosec')),
  requires_both    boolean NOT NULL DEFAULT false,
  last_activity_at timestamptz,
  analysis_hash    text,
  analyzed_at      timestamptz,
  ai_summary       text,
  ai_summary_hash  text,
  deleted_at       timestamptz,
  UNIQUE (account_id, arn)
);
CREATE INDEX roles_account_idx ON roles (account_id) WHERE deleted_at IS NULL;

CREATE TABLE role_policies (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  role_id     uuid NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
  kind        text NOT NULL CHECK (kind IN ('inline','managed')),
  name        text NOT NULL,
  arn         text,
  aws_managed boolean NOT NULL DEFAULT false,
  document    jsonb NOT NULL,
  doc_hash    text NOT NULL,
  UNIQUE (role_id, kind, name)
);

-- A row is written only when a policy document actually changes.
CREATE TABLE policy_history (
  id        bigserial PRIMARY KEY,
  role_id   uuid NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
  kind      text NOT NULL,
  name      text NOT NULL,
  doc_hash  text NOT NULL,
  document  jsonb NOT NULL,
  seen_at   timestamptz NOT NULL DEFAULT now(),
  UNIQUE (role_id, kind, name, doc_hash)
);

-- ===== who used a role =====
CREATE TABLE principals (
  id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  role_id        uuid NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
  key            text NOT NULL,
  kind           text NOT NULL,
  display        text NOT NULL,
  via            text NOT NULL,
  caller         jsonb NOT NULL DEFAULT '{}',
  first_seen     timestamptz,
  last_seen      timestamptz,
  sessions_count int NOT NULL DEFAULT 0,
  source_ips     text[] NOT NULL DEFAULT '{}',
  mfa            boolean,
  source_identity text,
  session_tags   text[] NOT NULL DEFAULT '{}',
  UNIQUE (role_id, key)
);

CREATE TABLE role_sessions (
  access_key_id text PRIMARY KEY,
  role_id       uuid NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
  principal_id  uuid NOT NULL REFERENCES principals(id) ON DELETE CASCADE,
  started_at    timestamptz NOT NULL
);
CREATE INDEX role_sessions_started_idx ON role_sessions (started_at);

-- ===== what they did (append-only aggregates; raw events are never stored) =====
CREATE TABLE activity_daily (
  role_id      uuid NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
  principal_id uuid NOT NULL REFERENCES principals(id) ON DELETE CASCADE,
  action       text NOT NULL,
  day          date NOT NULL,
  count        int NOT NULL DEFAULT 0,        -- calls that were not denied
  error_count  int NOT NULL DEFAULT 0,        -- calls denied by IAM
  PRIMARY KEY (role_id, principal_id, action, day)
);

CREATE TABLE activity_resources (
  role_id   uuid NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
  action    text NOT NULL,
  resource  text NOT NULL,
  last_seen timestamptz NOT NULL,
  count     int NOT NULL DEFAULT 0,
  PRIMARY KEY (role_id, action, resource)
);

CREATE TABLE passrole_observed (
  role_id         uuid NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
  passed_role_arn text NOT NULL,
  service         text NOT NULL,
  last_seen       timestamptz NOT NULL,
  count           int NOT NULL DEFAULT 0,
  PRIMARY KEY (role_id, passed_role_arn, service)
);

CREATE TABLE advisor_services (
  role_id            uuid NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
  service_namespace  text NOT NULL,
  last_authenticated timestamptz,
  tracked_actions    jsonb NOT NULL DEFAULT '[]',
  refreshed_at       timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (role_id, service_namespace)
);

-- ===== analysis output =====
CREATE TABLE role_actions (
  role_id     uuid NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
  action      text NOT NULL,
  status      text NOT NULL CHECK (status IN ('used','unused','unconfirmed')),
  reason      text,
  access_level text,
  event_count bigint NOT NULL DEFAULT 0,
  last_seen   date,
  PRIMARY KEY (role_id, action)
);
CREATE INDEX role_actions_status_idx ON role_actions (role_id, status);

CREATE TABLE flags (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  role_id     uuid NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
  category    text NOT NULL,
  key         text NOT NULL,
  title       text NOT NULL,
  actions     text[] NOT NULL DEFAULT '{}',
  resources   text[] NOT NULL DEFAULT '{}',
  reason      text NOT NULL,
  evidence    text,
  suggestion  text,
  suggested_resources text[] NOT NULL DEFAULT '{}',
  severity    text NOT NULL DEFAULT 'medium' CHECK (severity IN ('high','medium','low')),
  status      text NOT NULL DEFAULT 'open' CHECK (status IN ('open','resolved')),
  created_at  timestamptz NOT NULL DEFAULT now(),
  updated_at  timestamptz NOT NULL DEFAULT now(),
  UNIQUE (role_id, category, key)
);

CREATE TABLE review_decisions (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  flag_id     uuid NOT NULL UNIQUE REFERENCES flags(id) ON DELETE CASCADE,
  role_id     uuid NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
  decision    text NOT NULL,
  resources   text[],
  note        text,
  decided_by  uuid REFERENCES users(id) ON DELETE SET NULL,
  team        text,
  decided_at  timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE recommendations (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  role_id       uuid NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
  status        text NOT NULL DEFAULT 'draft' CHECK (status IN ('draft','approved','superseded')),
  source        text NOT NULL CHECK (source IN ('ai','rules','rules-fallback')),
  model         text,
  policies      jsonb NOT NULL,
  statements    jsonb NOT NULL,
  diff          jsonb NOT NULL,
  checks        jsonb NOT NULL,
  summary       text,
  instruction   text,
  analysis_hash text NOT NULL,
  created_by    uuid REFERENCES users(id) ON DELETE SET NULL,
  created_at    timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX recommendations_role_idx ON recommendations (role_id, created_at DESC);

CREATE TABLE recommendation_approvals (
  id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  recommendation_id uuid NOT NULL REFERENCES recommendations(id) ON DELETE CASCADE,
  user_id           uuid REFERENCES users(id) ON DELETE SET NULL,
  team              text NOT NULL,
  approved_at       timestamptz NOT NULL DEFAULT now(),
  UNIQUE (recommendation_id, team)
);

CREATE TABLE audit_log (
  id          bigserial PRIMARY KEY,
  at          timestamptz NOT NULL DEFAULT now(),
  actor_id    uuid,
  actor_email text,
  action      text NOT NULL,
  target_type text,
  target_id   text,
  detail      jsonb,
  ip          text
);
CREATE INDEX audit_log_at_idx ON audit_log (at DESC);
