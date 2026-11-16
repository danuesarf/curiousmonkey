-- Console sessions. The AWS console signs in with AssumeRoleWithSAML (or another AssumeRole), then makes its calls
-- with temporary keys that never appear in that event. Those calls could not be tied to the person who signed in, so
-- each person showed twice (a "federated" caller with the sign-ins, a "session <name>" caller with the calls) and
-- every console key became a session of its own.
--
-- Keys the scanner ties to a session are now kept in role_sessions with the sign-in they belong to:
--   signin_key       the key of the sign-in (AssumeRole) this key's calls belong to; NULL for a sign-in's own key
--   session_name     the role session name
--   session_created  sessionContext.attributes.creationDate of the calls: the same for every key of one sign-in
ALTER TABLE role_sessions ADD COLUMN signin_key text;
ALTER TABLE role_sessions ADD COLUMN session_name text;
ALTER TABLE role_sessions ADD COLUMN session_created timestamptz;
CREATE INDEX role_sessions_signature_idx ON role_sessions (role_id, session_name, session_created) WHERE session_name IS NOT NULL;

-- IP addresses seen on a caller's API calls. source_ips stays the addresses of its sign-ins (AssumeRole); for IAM
-- Identity Center those are AWS's own, not the person's.
ALTER TABLE principals ADD COLUMN call_ips text[] NOT NULL DEFAULT '{}';

-- The fallback caller is no longer about a session that started before the history: it is one whose sign-in was not seen.
UPDATE principals SET via = 'sign-in not seen' WHERE kind = 'session' AND via = 'unknown (started before the window)';
UPDATE track_sessions SET via = 'sign-in not seen' WHERE start_known = false AND via = 'started before stored history';

-- Merge what is already stored. Only IAM Identity Center roles, under /aws-reserved/sso.amazonaws.com/ (a path only AWS
-- can create roles in; the AWSReservedSSO_ name alone can be copied): AWS manages their trust policy and only Identity
-- Center can assume them, so the session name is the person's user name and cannot be chosen by anyone else. On other
-- roles a session name proves nothing, and the fallback caller stays as it is.
CREATE TEMP TABLE caller_map ON COMMIT DROP AS
  SELECT DISTINCT ON (s.id) s.id AS old_id, f.id AS keep_id
    FROM principals s
    JOIN roles r ON r.id = s.role_id AND r.arn LIKE '%:role/aws-reserved/sso.amazonaws.com/%'
    JOIN principals f ON f.role_id = s.role_id AND f.kind = 'federated' AND f.display = substr(s.display, length('session ') + 1)
   WHERE s.kind = 'session'
   ORDER BY s.id, f.last_seen DESC NULLS LAST;

UPDATE principals p SET first_seen = LEAST(p.first_seen, t.first_seen), last_seen = GREATEST(p.last_seen, t.last_seen)
  FROM (SELECT c.keep_id, min(s.first_seen) AS first_seen, max(s.last_seen) AS last_seen
          FROM caller_map c JOIN principals s ON s.id = c.old_id GROUP BY c.keep_id) t
 WHERE p.id = t.keep_id;

INSERT INTO activity_daily(role_id, principal_id, action, day, count, error_count)
  SELECT a.role_id, c.keep_id, a.action, a.day, sum(a.count), sum(a.error_count)
    FROM activity_daily a JOIN caller_map c ON c.old_id = a.principal_id
   GROUP BY a.role_id, c.keep_id, a.action, a.day
ON CONFLICT (role_id, principal_id, action, day) DO UPDATE SET count = activity_daily.count + EXCLUDED.count, error_count = activity_daily.error_count + EXCLUDED.error_count;
UPDATE role_sessions s SET principal_id = c.keep_id FROM caller_map c WHERE s.principal_id = c.old_id;
UPDATE track_sessions s SET principal_id = c.keep_id FROM caller_map c WHERE s.principal_id = c.old_id;
DELETE FROM principals p USING caller_map c WHERE p.id = c.old_id;
