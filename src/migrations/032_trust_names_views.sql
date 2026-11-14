-- Names for where trust comes from: an outside AWS account, an OIDC provider, a SAML provider. The workspace's name wins
-- over the bundled list of known vendors (src/data/known-aws-accounts.json).
CREATE TABLE trust_sources (
  source      text PRIMARY KEY,                  -- as the map names it: src:acct:<id>, src:oidc:<label>, src:saml:<label>…
  name        text NOT NULL,
  owner       text,                              -- who looks after it here (a team or a person)
  purpose     text,
  review_by   date,
  updated_by  uuid REFERENCES users(id) ON DELETE SET NULL,
  updated_at  timestamptz NOT NULL DEFAULT now()
);

-- Saved views: a named filter on a page, for one person or the whole workspace
CREATE TABLE saved_views (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id     uuid REFERENCES users(id) ON DELETE CASCADE,
  page        text NOT NULL CHECK (page IN ('trust')),
  name        text NOT NULL,
  query       text NOT NULL,                     -- the page's address after '?': q, sel, tab, show…
  shared      boolean NOT NULL DEFAULT false,
  created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX saved_views_user ON saved_views (page, user_id);
