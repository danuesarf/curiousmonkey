-- Role sessions and their calls, so one session (and every role it jumped into) can be replayed call by call.
-- Kept for SESSION_RETENTION_DAYS (default 30); the per-day counts used for analysis are kept regardless.
CREATE TABLE track_sessions (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  account_id      uuid NOT NULL REFERENCES cloud_accounts(id) ON DELETE CASCADE,
  role_id         uuid NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
  access_key_id   text NOT NULL UNIQUE,         -- the session's temporary key: how calls and jumps are linked
  principal_id    uuid REFERENCES principals(id) ON DELETE SET NULL,
  parent_key_id   text,                         -- key of the session that made the AssumeRole (any account)
  via             text,                         -- sts:AssumeRole, sts:AssumeRoleWithSAML, ...
  caller_type     text,
  caller_arn      text,
  session_name    text,
  source_ip       text,
  user_agent      text,
  mfa             boolean,
  source_identity text,
  trust           jsonb,                        -- trust-policy conditions met on entry
  start_known     boolean NOT NULL DEFAULT true,  -- false: the AssumeRole is older than the stored history
  started_at      timestamptz NOT NULL,
  last_call_at    timestamptz,
  calls           int NOT NULL DEFAULT 0,
  denied          int NOT NULL DEFAULT 0
);
CREATE INDEX track_sessions_role_idx ON track_sessions (role_id, started_at DESC);
CREATE INDEX track_sessions_account_idx ON track_sessions (account_id, started_at DESC);
CREATE INDEX track_sessions_parent_idx ON track_sessions (parent_key_id);

CREATE TABLE track_calls (
  session_id   uuid NOT NULL REFERENCES track_sessions(id) ON DELETE CASCADE,
  event_id     text NOT NULL,
  at           timestamptz NOT NULL,
  action       text,
  event_source text NOT NULL,
  event_name   text NOT NULL,
  resources    text[] NOT NULL DEFAULT '{}',
  denied       boolean NOT NULL DEFAULT false,
  error_code   text,
  child_key_id text,                            -- set on an AssumeRole: the session it created
  PRIMARY KEY (session_id, event_id)
);
CREATE INDEX track_calls_at_idx ON track_calls (session_id, at);
