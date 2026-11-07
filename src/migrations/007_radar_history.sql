-- Radar v3: where things were (snapshots), what changed (changes), and an optional OU / group per account.

-- One row per role per day, written after a final analysis once the account's history is fully read.
-- Trails ("where it was 7 and 30 days ago") and trends come from here.
CREATE TABLE role_snapshots (
  role_id      uuid NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
  account_id   uuid NOT NULL REFERENCES cloud_accounts(id) ON DELETE CASCADE,
  day          date NOT NULL,
  granted      int NOT NULL,
  used         int NOT NULL,
  unused       int NOT NULL,
  unconfirmed  int NOT NULL,
  calls        bigint NOT NULL DEFAULT 0,      -- stored calls, all time
  denied       bigint NOT NULL DEFAULT 0,      -- stored denied calls, all time
  active90     boolean NOT NULL DEFAULT false, -- any call in the last 90 days
  PRIMARY KEY (role_id, day)
);
CREATE INDEX role_snapshots_account_day ON role_snapshots(account_id, day);

-- Changes that matter, shown as pings on the radar and in the feed.
CREATE TABLE changes (
  id          bigserial PRIMARY KEY,
  account_id  uuid NOT NULL REFERENCES cloud_accounts(id) ON DELETE CASCADE,
  role_id     uuid REFERENCES roles(id) ON DELETE CASCADE,
  kind        text NOT NULL CHECK (kind IN ('new-caller','denied','grew','unidentified','new-role','dead','cleaned')),
  severity    text NOT NULL CHECK (severity IN ('high','warn','info','good')),
  title       text NOT NULL,
  detail      text,
  dedupe      text NOT NULL UNIQUE,            -- the same change is recorded once
  at          timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX changes_account_at ON changes(account_id, at DESC);
CREATE INDEX changes_at ON changes(at DESC);

ALTER TABLE cloud_accounts ADD COLUMN ou text;              -- an AWS Organizations OU or any grouping the team uses
ALTER TABLE users ADD COLUMN radar_seen_at timestamptz;     -- "since you last looked"
