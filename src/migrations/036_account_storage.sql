-- Database space each AWS account's data takes. Estimated hourly by the worker from the catalog, not from the write
-- paths: every table tied to an account (directly, through its roles, or through its sessions) is split by account,
-- exactly for small tables and from a page sample for big ones, and its measured size (heap, indexes, TOAST) is shared
-- out by those row counts, so the accounts add up to the tables.

-- the latest estimate, with the split by table
CREATE TABLE account_storage (
  account_id  uuid PRIMARY KEY REFERENCES cloud_accounts(id) ON DELETE CASCADE,
  bytes       bigint NOT NULL,
  rows_est    bigint NOT NULL,
  by_table    jsonb  NOT NULL DEFAULT '{}',     -- { table: [bytes, rows] }
  sampled     boolean NOT NULL DEFAULT false,   -- some of it comes from a sample
  at          timestamptz NOT NULL DEFAULT now()
);

-- one point per account per hour, 30 days, for growth
CREATE TABLE account_storage_samples (
  account_id  uuid NOT NULL REFERENCES cloud_accounts(id) ON DELETE CASCADE,
  at          timestamptz NOT NULL,
  bytes       bigint NOT NULL,
  PRIMARY KEY (account_id, at)
);
CREATE INDEX account_storage_samples_at ON account_storage_samples (at);
