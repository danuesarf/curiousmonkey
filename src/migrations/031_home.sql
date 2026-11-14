-- Home: the page after sign-in. It lists what to do first; each person can put an item off ("Not now") and hide the
-- setup checklist once they no longer need it.
CREATE TABLE IF NOT EXISTS home_snoozes (
  user_id     uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  action_key  text NOT NULL,                       -- findings-high, keys-old, setup-alerts, …
  until       timestamptz NOT NULL,
  PRIMARY KEY (user_id, action_key)
);
ALTER TABLE users ADD COLUMN IF NOT EXISTS home_setup_hidden boolean NOT NULL DEFAULT false;

-- The "what to do first" digest: an alert rule of its own kind (trigger 'todo'). It is not built from matches like the
-- other rules; at its time it posts the team's list as Home shows it. Off until someone creates one.
ALTER TABLE alert_rules DROP CONSTRAINT IF EXISTS alert_rules_trigger_check;
ALTER TABLE alert_rules ADD CONSTRAINT alert_rules_trigger_check CHECK (trigger IN ('finding', 'change', 'key-age', 'console-no-mfa', 'scan-failed', 'todo'));
ALTER TABLE alert_rules ADD COLUMN IF NOT EXISTS digest_at   text;                                -- 'HH:MM' in the workspace time zone; null = alerts.digestAt
ALTER TABLE alert_rules ADD COLUMN IF NOT EXISTS digest_days int[] NOT NULL DEFAULT '{1,2,3,4,5,6,7}';  -- ISO weekdays, 1 = Monday
ALTER TABLE alert_rules ADD COLUMN IF NOT EXISTS todo_tiers  text[] NOT NULL DEFAULT '{blocking,urgent,hygiene}';
ALTER TABLE alert_rules ADD COLUMN IF NOT EXISTS todo_max    int NOT NULL DEFAULT 5;
ALTER TABLE alert_rules ADD COLUMN IF NOT EXISTS todo_team   text;                                -- infrasec, infosec, or null for the whole workspace
ALTER TABLE alert_rules ADD COLUMN IF NOT EXISTS skip_empty  boolean NOT NULL DEFAULT true;
