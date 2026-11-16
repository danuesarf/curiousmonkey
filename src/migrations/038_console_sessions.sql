-- Console sessions. The AWS console signs in with AssumeRoleWithSAML (or another AssumeRole), then makes its calls
-- with temporary keys that never appear in that event. Those calls could not be tied to the person who signed in, so
-- each person showed twice (a "federated" caller with the sign-ins, a "session <name>" caller with the calls) and
-- every console key became a session of its own.
--
-- Schema only, and only changes that need no table rewrite or scan: this runs while the tables are locked, and
-- role_sessions, activity_daily and track_sessions are large. Indexes come in 039 (built without blocking writes),
-- the merge of what is already stored in 040.
--
-- Keys the scanner ties to a session are kept in role_sessions with the sign-in they belong to:
--   signin_key       the key of the sign-in (AssumeRole) this key's calls belong to; NULL for a sign-in's own key
--   session_name     the role session name
--   session_created  sessionContext.attributes.creationDate of the calls: the same for every key of one sign-in
ALTER TABLE role_sessions ADD COLUMN IF NOT EXISTS signin_key text;
ALTER TABLE role_sessions ADD COLUMN IF NOT EXISTS session_name text;
ALTER TABLE role_sessions ADD COLUMN IF NOT EXISTS session_created timestamptz;

-- IP addresses seen on a caller's API calls. source_ips stays the addresses of its sign-ins (AssumeRole); for IAM
-- Identity Center those are AWS's own, not the person's.
ALTER TABLE principals ADD COLUMN IF NOT EXISTS call_ips text[] NOT NULL DEFAULT '{}';
