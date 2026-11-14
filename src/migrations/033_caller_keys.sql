-- Bitbucket Pipelines callers were kept one per pipeline step (the step is part of the subject). Merge them into one
-- caller per repository (and deployment environment), as they are recorded from now on: sessions summed, first and last
-- seen kept, their daily counts and sessions moved to the one that stays.
CREATE TEMP TABLE caller_merge ON COMMIT DROP AS
  SELECT p.id, p.role_id, regexp_replace(p.key, '(:\{[0-9a-fA-F-]{36}\}(:[^:]+)?):\{[0-9a-fA-F-]{36}\}$', '\1:*') AS new_key
    FROM principals p
   WHERE p.kind = 'federated' AND p.key ~* 'bitbucket\.org' AND p.key ~ ':\{[0-9a-fA-F-]{36}\}(:[^:]+)?:\{[0-9a-fA-F-]{36}\}$';

CREATE TEMP TABLE caller_keep ON COMMIT DROP AS
  SELECT DISTINCT ON (m.role_id, m.new_key) m.role_id, m.new_key, coalesce(x.id, m.id) AS keep_id
    FROM caller_merge m
    LEFT JOIN principals x ON x.role_id = m.role_id AND x.key = m.new_key       -- already recorded the new way
   ORDER BY m.role_id, m.new_key, x.id NULLS LAST, m.id;

CREATE TEMP TABLE caller_map ON COMMIT DROP AS
  SELECT m.id AS old_id, k.keep_id FROM caller_merge m JOIN caller_keep k ON k.role_id = m.role_id AND k.new_key = m.new_key;

-- totals onto the one that stays
UPDATE principals p SET key = k.new_key,
       display = regexp_replace(p.display, ':\{[0-9a-fA-F-]{36}\}$', ':*'),
       sessions_count = t.sessions, first_seen = t.first_seen, last_seen = t.last_seen
  FROM caller_keep k,
       LATERAL (SELECT sum(q.sessions_count)::int AS sessions, min(q.first_seen) AS first_seen, max(q.last_seen) AS last_seen
                  FROM principals q WHERE q.id = k.keep_id OR q.id IN (SELECT old_id FROM caller_map WHERE keep_id = k.keep_id AND old_id <> k.keep_id)) t
 WHERE p.id = k.keep_id;

-- daily counts and sessions follow
INSERT INTO activity_daily(role_id, principal_id, action, day, count, error_count)
  SELECT a.role_id, c.keep_id, a.action, a.day, sum(a.count), sum(a.error_count)
    FROM activity_daily a JOIN caller_map c ON c.old_id = a.principal_id WHERE c.old_id <> c.keep_id
   GROUP BY a.role_id, c.keep_id, a.action, a.day
ON CONFLICT (role_id, principal_id, action, day) DO UPDATE SET count = activity_daily.count + EXCLUDED.count, error_count = activity_daily.error_count + EXCLUDED.error_count;
UPDATE role_sessions s SET principal_id = c.keep_id FROM caller_map c WHERE s.principal_id = c.old_id AND c.old_id <> c.keep_id;
UPDATE track_sessions s SET principal_id = c.keep_id FROM caller_map c WHERE s.principal_id = c.old_id AND c.old_id <> c.keep_id;
DELETE FROM principals p USING caller_map c WHERE p.id = c.old_id AND c.old_id <> c.keep_id;
