-- IAM users, monitored like roles: they live in the roles table as kind 'iam-user', so their policies, calls,
-- permission analysis, risk, Radar and Space all work the same way. What only users have is stored beside them:
-- the console password and MFA, the groups they are in, and every access key with its age and last use.
ALTER TABLE roles DROP CONSTRAINT IF EXISTS roles_kind_check;
ALTER TABLE roles ADD CONSTRAINT roles_kind_check CHECK (kind IN ('custom','service-linked','identity-center','iam-user'));

-- a user's effective policies include those of its groups: stored as kind 'group', named <group>/<policy>
ALTER TABLE role_policies DROP CONSTRAINT IF EXISTS role_policies_kind_check;
ALTER TABLE role_policies ADD CONSTRAINT role_policies_kind_check CHECK (kind IN ('inline','managed','group'));

CREATE TABLE IF NOT EXISTS iam_user_details (
  role_id            uuid PRIMARY KEY REFERENCES roles(id) ON DELETE CASCADE,
  user_id            text,                          -- AIDA...
  password_enabled   boolean NOT NULL DEFAULT false,
  password_created   timestamptz,
  password_last_used timestamptz,
  mfa                jsonb NOT NULL DEFAULT '[]',   -- [{ serial, type: virtual | hardware | u2f, enabled }]
  groups             text[] NOT NULL DEFAULT '{}',
  updated_at         timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS iam_access_keys (
  role_id            uuid NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
  key_id             text NOT NULL,                 -- AKIA...
  status             text,                          -- Active | Inactive (null: seen in CloudTrail before the inventory read it)
  created_at         timestamptz,
  last_used_at       timestamptz,                   -- from IAM (GetAccessKeyLastUsed)
  last_used_service  text,
  last_used_region   text,
  trail_first_seen   timestamptz,                   -- from CloudTrail, as calls arrive
  trail_last_seen    timestamptz,
  trail_calls        bigint NOT NULL DEFAULT 0,
  source_ips         text[] NOT NULL DEFAULT '{}',
  deleted_at         timestamptz,                   -- gone from IAM: kept so its history still reads
  PRIMARY KEY (role_id, key_id)
);

-- what CloudTrail calls by IAM users were counted as (they used to be dropped as "not a role")
ALTER TABLE event_coverage ADD COLUMN IF NOT EXISTS user_calls int NOT NULL DEFAULT 0;
