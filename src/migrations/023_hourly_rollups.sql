-- Events and Space read "what happened in this hour" from two small tables written as calls arrive, instead of
-- working it out from every stored call and session each time a page opens.
--
--   call_hourly    one row per account, hour, role and kind of call (action and outcome): how many. Tells a search
--                  which hours and roles have a match before it reads a single call, and gives Space its hourly totals.
--   session_hours  which sessions made a call in an hour. Finds the sessions active in a window from one small index.
--
-- Calls stored before this migration are counted in the background, newest day first (rollup_backfill tracks how far
-- back each account is covered). Until an hour is covered, searches use the older, slower way for it.
-- `rolled` marks calls counted as they arrived (null on older rows), so the backfill never counts a call twice.
-- Adding a nullable column does not rewrite the table.
ALTER TABLE track_calls ADD COLUMN IF NOT EXISTS rolled boolean;

-- the kinds of call seen: an action with its outcome. A few thousand rows however many calls are stored, so a
-- search finds the kinds that match its words here first, and call_hourly holds only their key.
CREATE TABLE IF NOT EXISTS call_kinds (
  k            uuid PRIMARY KEY,              -- md5 of the columns below
  action       text NOT NULL DEFAULT '',
  event_source text NOT NULL,
  event_name   text NOT NULL,
  error_code   text NOT NULL DEFAULT '',
  denied       boolean NOT NULL
);

CREATE TABLE IF NOT EXISTS call_hourly (
  account_id   uuid NOT NULL REFERENCES cloud_accounts(id) ON DELETE CASCADE,
  hour         timestamptz NOT NULL,
  role_id      uuid NOT NULL,
  k            uuid NOT NULL,                 -- call_kinds.k
  denied       boolean NOT NULL,
  n            integer NOT NULL,
  PRIMARY KEY (account_id, hour, role_id, k)
);

CREATE TABLE IF NOT EXISTS session_hours (
  account_id uuid NOT NULL REFERENCES cloud_accounts(id) ON DELETE CASCADE,
  hour       timestamptz NOT NULL,
  role_id    uuid NOT NULL,
  session_id uuid NOT NULL,
  PRIMARY KEY (account_id, hour, role_id, session_id)
);

CREATE TABLE IF NOT EXISTS rollup_backfill (
  account_id   uuid PRIMARY KEY REFERENCES cloud_accounts(id) ON DELETE CASCADE,
  covered_from timestamptz NOT NULL,          -- every hour from here on is in the rollups
  done         boolean NOT NULL DEFAULT false,
  queued_at    timestamptz NOT NULL DEFAULT now()
);
-- accounts that already have stored calls start uncovered; accounts added later are covered from their first call
INSERT INTO rollup_backfill(account_id, covered_from)
SELECT a.id, date_trunc('day', now()) + interval '2 days' FROM cloud_accounts a
 WHERE EXISTS (SELECT 1 FROM track_sessions s WHERE s.account_id = a.id)
ON CONFLICT DO NOTHING;
