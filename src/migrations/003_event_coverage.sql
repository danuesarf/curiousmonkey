-- What each scan did with every event it read, so gaps are visible instead of silent.
CREATE TABLE event_coverage (
  account_id      uuid NOT NULL REFERENCES cloud_accounts(id) ON DELETE CASCADE,
  region          text NOT NULL,
  day             date NOT NULL,
  events          bigint NOT NULL DEFAULT 0,   -- every event read (deduplicated)
  assume_events   bigint NOT NULL DEFAULT 0,   -- AssumeRole* into a known role
  role_calls      bigint NOT NULL DEFAULT 0,   -- API calls credited to a known role
  recovered_role  bigint NOT NULL DEFAULT 0,   -- of those, role found by name (event had no sessionIssuer)
  other_role      bigint NOT NULL DEFAULT 0,   -- made by a role this account does not have (deleted, or another account's)
  not_role        bigint NOT NULL DEFAULT 0,   -- IAM users, root, AWS services: not analyzed by design
  no_permission   bigint NOT NULL DEFAULT 0,   -- console sign-in and similar: no IAM action involved
  unmapped        bigint NOT NULL DEFAULT 0,   -- role calls whose event name is not a known IAM action
  no_resources    bigint NOT NULL DEFAULT 0,   -- successful role calls that named no resource ARN
  PRIMARY KEY (account_id, region, day)
);

-- Event names seen that are not in the IAM action catalog. raw_action is the key activity is stored under.
CREATE TABLE unmapped_events (
  account_id    uuid NOT NULL REFERENCES cloud_accounts(id) ON DELETE CASCADE,
  raw_action    text NOT NULL,
  event_source  text NOT NULL,
  event_name    text NOT NULL,
  count         bigint NOT NULL DEFAULT 0,
  first_seen    timestamptz NOT NULL,
  last_seen     timestamptz NOT NULL,
  identity_type text,
  param_keys    text[] NOT NULL DEFAULT '{}',   -- request parameter names only, never values
  PRIMARY KEY (account_id, raw_action)
);

-- How an unmapped event name translates to an IAM action. Applies to every account, and to history already stored.
CREATE TABLE event_action_map (
  raw_action    text PRIMARY KEY,
  event_source  text NOT NULL,
  event_name    text NOT NULL,
  action        text,                          -- NULL: the call needs no IAM permission
  status        text NOT NULL CHECK (status IN ('suggested','accepted')),
  source        text NOT NULL CHECK (source IN ('manual','bedrock')),
  confidence    real,
  note          text,
  suggested_at  timestamptz,
  decided_by    uuid REFERENCES users(id) ON DELETE SET NULL,
  decided_at    timestamptz
);

-- Calls that named no resource. If an action has any, its resources are never narrowed to the ones seen.
ALTER TABLE activity_daily ADD COLUMN no_resource_count int NOT NULL DEFAULT 0;
