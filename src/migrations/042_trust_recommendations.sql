-- Specific trust: drafts that replace a whole-account principal (arn:aws:iam::<account>:root) with the identities seen
-- coming in from it (src/recommender/trust.js). Reviewed and approved like least-privilege drafts.
CREATE TABLE trust_recommendations (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  role_id     uuid NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
  status      text NOT NULL DEFAULT 'draft' CHECK (status IN ('draft', 'approved', 'superseded')),
  style       text NOT NULL DEFAULT 'condition' CHECK (style IN ('condition', 'principal')),
  before      jsonb NOT NULL,              -- the trust policy the draft was made from
  policy      jsonb NOT NULL,              -- the draft
  changes     jsonb NOT NULL,
  accounts    jsonb NOT NULL,              -- each whole-account principal: narrowed, removed or kept
  callers     jsonb NOT NULL,              -- who was seen coming in, as named when drafted
  excluded    text[] NOT NULL DEFAULT '{}',-- callers the reviewer left out on purpose
  checks      jsonb NOT NULL,
  summary     text,
  trust_hash  text NOT NULL,               -- of `before`: a draft of a policy that changed since is stale
  created_by  uuid REFERENCES users(id) ON DELETE SET NULL,
  created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX trust_recommendations_role ON trust_recommendations (role_id, created_at DESC);

CREATE TABLE trust_recommendation_approvals (
  id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  recommendation_id uuid NOT NULL REFERENCES trust_recommendations(id) ON DELETE CASCADE,
  user_id           uuid REFERENCES users(id) ON DELETE SET NULL,
  team              text NOT NULL,
  approved_at       timestamptz NOT NULL DEFAULT now(),
  UNIQUE (recommendation_id, team)
);
