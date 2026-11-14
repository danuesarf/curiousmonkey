-- What changed on an identity (History tab), and frozen access reviews with a sign-off per review team.

-- Written where inventory and analysis compare the stored state with the new one. Only changes to an identity
-- already known are recorded: its first inventory is the baseline. Keys created or deleted, new callers and decisions
-- come from their own tables; this holds what nothing else keeps.
CREATE TABLE IF NOT EXISTS identity_events (
  id       bigserial PRIMARY KEY,
  role_id  uuid NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
  at       timestamptz NOT NULL DEFAULT now(),
  kind     text NOT NULL CHECK (kind IN ('policy-added', 'policy-removed', 'policy-changed', 'trust-changed', 'boundary-changed',
                                         'risk', 'key-status', 'password', 'mfa', 'deleted', 'restored')),
  title    text NOT NULL,
  detail   jsonb NOT NULL DEFAULT '{}'           -- policy: { name, policyKind, awsManaged, before, after }; risk: { from, to, reasons }
);
CREATE INDEX IF NOT EXISTS identity_events_role ON identity_events(role_id, at DESC);

-- An access review: a snapshot of the identities in some accounts, frozen when it is created, for evidence.
CREATE TABLE IF NOT EXISTS access_reviews (
  id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name         text NOT NULL,
  period_from  date NOT NULL,
  period_to    date NOT NULL,
  account_ids  uuid[] NOT NULL,
  teams        text[] NOT NULL,                  -- the review teams that must sign off
  snapshot     jsonb NOT NULL,                   -- { accounts, totals, takenAt }; the identities are in access_review_items
  status       text NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'signed')),
  created_by   uuid REFERENCES users(id) ON DELETE SET NULL,
  created_by_name text,
  created_at   timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS access_reviews_created ON access_reviews(created_at DESC);

-- One identity as it stood when the review was taken. The columns are what the page filters on; data holds the rest.
CREATE TABLE IF NOT EXISTS access_review_items (
  review_id      uuid NOT NULL REFERENCES access_reviews(id) ON DELETE CASCADE,
  n              int NOT NULL,                   -- order: account, then riskiest first
  account_id     uuid NOT NULL,
  kind           text NOT NULL,
  risk           text,
  name           text NOT NULL,
  calls          bigint NOT NULL DEFAULT 0,      -- in the period
  open_findings  int NOT NULL DEFAULT 0,
  undecided      int NOT NULL DEFAULT 0,
  data           jsonb NOT NULL,
  PRIMARY KEY (review_id, n)
);

CREATE TABLE IF NOT EXISTS access_review_signoffs (
  review_id  uuid NOT NULL REFERENCES access_reviews(id) ON DELETE CASCADE,
  team       text NOT NULL,
  user_id    uuid REFERENCES users(id) ON DELETE SET NULL,
  user_name  text NOT NULL,                      -- kept as signed, even if the member is renamed or removed
  user_email text,
  note       text,
  signed_at  timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (review_id, team)
);

-- the History tab reads decisions and approvals on one identity's findings from the audit log
CREATE INDEX IF NOT EXISTS audit_log_target ON audit_log(target_type, target_id);
