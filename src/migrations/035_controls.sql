-- Manage policy: every rule the tool checks is a control. A built-in control can be given another severity or turned
-- off (control_overrides); a custom control is a rule written in the portal (custom_controls). Each finding names the
-- control that made it, so findings can be listed and counted by control.

CREATE TABLE control_overrides (
  control_id  text PRIMARY KEY,                       -- a built-in control: perm.wildcard-all, trust.public, cred.key-old…
  severity    text CHECK (severity IN ('high', 'medium', 'low')),   -- null: the built-in severity
  enabled     boolean NOT NULL DEFAULT true,
  note        text,                                   -- why it was changed
  updated_by  uuid REFERENCES users(id) ON DELETE SET NULL,
  updated_at  timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE custom_controls (
  id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name         text NOT NULL,
  description  text,
  target       text NOT NULL CHECK (target IN ('identity', 'way-in')),   -- roles and IAM users, or ways into a role (trust)
  rule         text NOT NULL,                          -- the query; what matches gets a finding
  severity     text NOT NULL CHECK (severity IN ('high', 'medium', 'low')),
  remediation  text,
  enabled      boolean NOT NULL DEFAULT true,
  created_by   uuid REFERENCES users(id) ON DELETE SET NULL,
  created_at   timestamptz NOT NULL DEFAULT now(),
  updated_by   uuid REFERENCES users(id) ON DELETE SET NULL,
  updated_at   timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX custom_controls_name ON custom_controls (lower(name));

ALTER TABLE flags ADD COLUMN IF NOT EXISTS control text;
UPDATE flags SET control = CASE
  WHEN category = 'wildcard' THEN CASE WHEN key IN ('*', '*:*') THEN 'perm.wildcard-all' ELSE 'perm.wildcard-service' END
  WHEN category = 'role-idle' THEN 'usage.role-idle'
  WHEN category = 'external-principal' THEN 'usage.unexpected-principal'
  WHEN category IN ('data-event', 'authorization-only', 'not-logged', 'before-window', 'service-unknown', 'unmapped-event') THEN 'evidence.' || category
  WHEN category = 'trust' THEN 'trust.' || substring(key from '[^|]*$')
  ELSE NULL END
 WHERE control IS NULL;
CREATE INDEX IF NOT EXISTS flags_control ON flags (control) WHERE status = 'open';

-- rules ask "which identities are allowed (or used) this action": answered from this index without reading the table
CREATE INDEX IF NOT EXISTS role_actions_action ON role_actions (action, status, role_id);
