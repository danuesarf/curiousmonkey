-- What VPC flow logs can and cannot show (src/network/flows.js, analyze.js applyUsage).

-- when each networking object was first seen, kept from read to read (null: there before the first read of its
-- account or project): a line, or a server's open port, is not called unused for longer than it has been there
ALTER TABLE net_items ADD COLUMN IF NOT EXISTS first_seen timestamptz;

-- whether a flow log's listing counts as having looked: a VPC's own flow log of accepted traffic, delivered (AWS
-- does not say delivery fails), read without error. An idle VPC writes no files; while such a flow log is listed
-- and finds none, the VPC is still covered (up to 48 hours past its newest file) instead of dropping out each night.
ALTER TABLE net_flow_reads ADD COLUMN IF NOT EXISTS covers boolean NOT NULL DEFAULT false;
