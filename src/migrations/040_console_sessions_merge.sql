-- Merge the callers already stored apart (see 038). Only IAM Identity Center roles, under
-- /aws-reserved/sso.amazonaws.com/ (a path only AWS can create roles in; the AWSReservedSSO_ name alone can be copied):
-- AWS manages their trust policy and only Identity Center can assume them, so the session name is the person's user
-- name and cannot be chosen by anyone else. On other roles a session name proves nothing, and the fallback caller stays.
-- Every statement goes through an index (039, or activity_daily's key, which starts with role_id).

-- the fallback caller's label: it is a caller whose sign-in was not seen, not one that started before the history
UPDATE principals SET via = 'sign-in not seen' WHERE kind = 'session' AND via = 'unknown (started before the window)';

CREATE TEMP TABLE caller_map ON COMMIT DROP AS
  SELECT DISTINCT ON (s.id) s.id AS old_id, f.id AS keep_id, s.role_id
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
    FROM caller_map c JOIN activity_daily a ON a.role_id = c.role_id AND a.principal_id = c.old_id
   GROUP BY a.role_id, c.keep_id, a.action, a.day
ON CONFLICT (role_id, principal_id, action, day) DO UPDATE SET count = activity_daily.count + EXCLUDED.count, error_count = activity_daily.error_count + EXCLUDED.error_count;
DELETE FROM activity_daily a USING caller_map c WHERE a.role_id = c.role_id AND a.principal_id = c.old_id;
UPDATE role_sessions s SET principal_id = c.keep_id FROM caller_map c WHERE s.principal_id = c.old_id;
UPDATE track_sessions s SET principal_id = c.keep_id FROM caller_map c WHERE s.principal_id = c.old_id;
DELETE FROM principals p USING caller_map c WHERE p.id = c.old_id;
