-- Trust map review workflow.
-- Expected trust: a way in a reviewer has looked at and accepts, such as the management account into
-- AWSControlTowerExecution, or a named vendor with ExternalId. It is left out of "needs attention" and its findings
-- are not filed, until it changes (a finding it was not accepted with), or its review date passes.
CREATE TABLE trust_expected (
  id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  source       text NOT NULL,                  -- where it comes from, as the map names it: src:acct:<id>, src:oidc:<label>, or an account's id
  source_label text NOT NULL,
  roles        text NOT NULL DEFAULT '*',      -- role names it covers (a pattern, * for any)
  accounts     text[] NOT NULL DEFAULT '{}',   -- 12-digit IDs of the accounts it covers; empty: every account
  findings     text[] NOT NULL DEFAULT '{}',   -- the findings accepted with it; a way in with any other is not covered
  note         text NOT NULL,
  review_by    date,
  created_by   uuid REFERENCES users(id) ON DELETE SET NULL,
  created_at   timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX trust_expected_source ON trust_expected (source);

-- the change feed learns two kinds: a new way into a role, and a guard taken off one (ExternalId, subject, MFA…)
ALTER TABLE changes DROP CONSTRAINT changes_kind_check;
ALTER TABLE changes ADD CONSTRAINT changes_kind_check
  CHECK (kind IN ('new-caller', 'denied', 'grew', 'unidentified', 'new-role', 'dead', 'cleaned', 'new-trust', 'trust-weakened'));

-- trust findings now come from the Trust map's rules (category 'trust'); the analyzer's old ones are retired
UPDATE flags SET status = 'resolved', updated_at = now() WHERE category = 'trust-wildcard' AND status = 'open';

-- trust findings are looked up by role and key when they are filed
CREATE INDEX IF NOT EXISTS flags_trust ON flags (role_id, key) WHERE category = 'trust';
