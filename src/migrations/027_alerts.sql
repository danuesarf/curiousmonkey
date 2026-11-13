-- Alerts: rules that post to Slack or a webhook when something worth knowing happens, at once or in a daily digest.
-- A rule's matches are recorded once each (alert_hits); a message (alert_deliveries) carries every match not sent yet.

-- Where messages go. The URL carries its own secret (a Slack webhook URL is a credential), so it is stored encrypted
-- and never returned; url_hint is what the page shows.
CREATE TABLE IF NOT EXISTS alert_destinations (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name        text NOT NULL,
  kind        text NOT NULL CHECK (kind IN ('slack', 'webhook')),
  url_enc     text NOT NULL,
  url_hint    text NOT NULL,
  created_by  uuid REFERENCES users(id) ON DELETE SET NULL,
  created_at  timestamptz NOT NULL DEFAULT now(),
  updated_at  timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS alert_rules (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name            text NOT NULL,
  trigger         text NOT NULL CHECK (trigger IN ('finding', 'change', 'key-age', 'console-no-mfa', 'scan-failed')),
  min_severity    text NOT NULL DEFAULT 'high' CHECK (min_severity IN ('high', 'medium', 'low')),
  change_kinds    text[] NOT NULL DEFAULT '{}',     -- 'change' rules: which Radar changes; empty means all
  environments    text[] NOT NULL DEFAULT '{}',     -- empty means every environment
  destination_id  uuid NOT NULL REFERENCES alert_destinations(id) ON DELETE RESTRICT,
  mode            text NOT NULL DEFAULT 'instant' CHECK (mode IN ('instant', 'daily')),
  enabled         boolean NOT NULL DEFAULT true,
  -- events from before the rule was created (or last switched on) are not alerted, so a new rule does not flood the channel
  since           timestamptz NOT NULL DEFAULT now(),
  since_change_id bigint NOT NULL DEFAULT 0,
  last_digest_day date,
  created_by      uuid REFERENCES users(id) ON DELETE SET NULL,
  created_at      timestamptz NOT NULL DEFAULT now(),
  updated_at      timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS alert_deliveries (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  rule_id         uuid REFERENCES alert_rules(id) ON DELETE SET NULL,
  destination_id  uuid REFERENCES alert_destinations(id) ON DELETE SET NULL,
  rule_name       text,                               -- kept for the log after the rule is removed
  destination_name text,
  kind            text NOT NULL CHECK (kind IN ('instant', 'daily', 'test')),
  status          text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'sent', 'failed')),
  attempts        int NOT NULL DEFAULT 0,
  next_attempt_at timestamptz NOT NULL DEFAULT now(),
  items           int NOT NULL DEFAULT 0,
  payload         jsonb NOT NULL,
  http_status     int,
  error           text,
  created_at      timestamptz NOT NULL DEFAULT now(),
  sent_at         timestamptz
);
CREATE INDEX IF NOT EXISTS alert_deliveries_created ON alert_deliveries(created_at DESC);
CREATE INDEX IF NOT EXISTS alert_deliveries_due ON alert_deliveries(next_attempt_at) WHERE status = 'pending';

CREATE TABLE IF NOT EXISTS alert_hits (
  rule_id      uuid NOT NULL REFERENCES alert_rules(id) ON DELETE CASCADE,
  dedupe       text NOT NULL,                         -- flag:<id>, change:<id>, key-age:<key id>, nomfa:<user id>, job:<id>
  item         jsonb NOT NULL,
  delivery_id  uuid REFERENCES alert_deliveries(id) ON DELETE SET NULL,
  found_at     timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (rule_id, dedupe)
);
CREATE INDEX IF NOT EXISTS alert_hits_unsent ON alert_hits(rule_id) WHERE delivery_id IS NULL;
