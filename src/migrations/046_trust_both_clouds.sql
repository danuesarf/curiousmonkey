-- One Trust map for both clouds. Google Cloud ways in are filed, decided and fed like AWS ones, but they are not about
-- an AWS role: a finding, a decision or a change may name a Google Cloud subject instead. Google Cloud principals are
-- rebuilt on each scan (new ids), so the subject is the stable IAM member of what is reached
-- (gcp:serviceAccount:x@p.iam.gserviceaccount.com, or gcp:scope:<where granted>|<project> for a grant on a whole
-- project, folder or organization, or gcp:project:<project> for roles held on the project itself).

-- findings
ALTER TABLE flags ALTER COLUMN role_id DROP NOT NULL;
ALTER TABLE flags ADD COLUMN IF NOT EXISTS gcp_subject text;
ALTER TABLE flags ADD COLUMN IF NOT EXISTS gcp_label   text;          -- what it is called (the service account's email…)
ALTER TABLE flags ADD COLUMN IF NOT EXISTS gcp_project text;
ALTER TABLE flags ADD CONSTRAINT flags_subject CHECK ((role_id IS NOT NULL) <> (gcp_subject IS NOT NULL)) NOT VALID;
ALTER TABLE flags VALIDATE CONSTRAINT flags_subject;
CREATE UNIQUE INDEX IF NOT EXISTS flags_gcp_key ON flags (gcp_subject, category, key) WHERE gcp_subject IS NOT NULL;

-- decisions on them
ALTER TABLE review_decisions ALTER COLUMN role_id DROP NOT NULL;

-- the change feed (Radar, the bell, alerts): a Google Cloud change has no AWS account
ALTER TABLE changes ALTER COLUMN account_id DROP NOT NULL;
ALTER TABLE changes ADD COLUMN IF NOT EXISTS gcp_project text;
CREATE INDEX IF NOT EXISTS changes_gcp_at ON changes (gcp_project, at DESC) WHERE gcp_project IS NOT NULL;

-- when each Google Cloud way in was first seen, and when it lost its IAM condition: "new" and "weakened" on the
-- Trust map. The first sync of a connection records what is there as known, not new.
CREATE TABLE IF NOT EXISTS gcp_ways_seen (
  key          text PRIMARY KEY,               -- subject | member | how | role | where granted
  first_seen   timestamptz NOT NULL,
  last_seen    timestamptz NOT NULL,
  conditional  boolean NOT NULL DEFAULT false,
  weakened_at  timestamptz                     -- the condition on its binding was taken off
);
CREATE INDEX IF NOT EXISTS gcp_ways_seen_last ON gcp_ways_seen (last_seen);
