-- Extensions: optional features a workspace turns on (Admin → Extensions). The first is Networking: VPCs, subnets,
-- route tables, gateways, security groups, network ACLs, firewalls, peering, transit gateways and VPNs in AWS
-- accounts and Google Cloud projects, what reaches them from the internet, and how they connect to each other,
-- across the two clouds too (src/network/).

CREATE TABLE IF NOT EXISTS extensions (
  key         text PRIMARY KEY,                       -- networking
  enabled     boolean NOT NULL DEFAULT false,
  settings    jsonb NOT NULL DEFAULT '{}',
  updated_by  uuid REFERENCES users(id) ON DELETE SET NULL,
  updated_at  timestamptz NOT NULL DEFAULT now()
);

-- Everything the networking reader saw, one row per object. `owner` is the AWS account ID or the Google Cloud project
-- ID the object lives in; a read replaces what is stored for that owner.
CREATE TABLE IF NOT EXISTS net_items (
  id                 uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  cloud              text NOT NULL CHECK (cloud IN ('aws', 'gcp')),
  owner              text NOT NULL,
  account_id         uuid REFERENCES cloud_accounts(id) ON DELETE CASCADE,
  gcp_connection_id  uuid REFERENCES gcp_connections(id) ON DELETE CASCADE,
  region             text,
  type               text NOT NULL,                   -- vpc, subnet, route-table, sg, nacl, igw, nat, peering, tgw, vpn…
  native_id          text NOT NULL,
  name               text,
  vpc                text,                            -- the VPC (AWS) or network (Google Cloud) it belongs to
  data               jsonb NOT NULL DEFAULT '{}',
  seen_at            timestamptz NOT NULL DEFAULT now(),
  UNIQUE (cloud, owner, type, native_id)
);
CREATE INDEX IF NOT EXISTS net_items_owner ON net_items (cloud, owner, type);

-- When each owner was last read, what was skipped (a call the reader may not make), and the error if it failed.
CREATE TABLE IF NOT EXISTS net_reads (
  cloud    text NOT NULL,
  owner    text NOT NULL,
  read_at  timestamptz NOT NULL DEFAULT now(),
  counts   jsonb NOT NULL DEFAULT '{}',
  skipped  text[] NOT NULL DEFAULT '{}',
  error    text,
  PRIMARY KEY (cloud, owner)
);

CREATE TABLE IF NOT EXISTS net_findings (
  id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  key          text NOT NULL UNIQUE,                  -- control | cloud | owner | object
  control      text NOT NULL,                         -- net.sg-admin-open, net.gcp-default-network…
  severity     text NOT NULL CHECK (severity IN ('high', 'medium', 'low')),
  cloud        text NOT NULL,
  owner        text NOT NULL,
  account_id   uuid REFERENCES cloud_accounts(id) ON DELETE CASCADE,
  item_type    text,
  native_id    text,
  item_name    text,
  vpc          text,
  title        text NOT NULL,
  detail       text NOT NULL,
  suggestion   text,
  status       text NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'resolved')),
  decision     text CHECK (decision IN ('expected', 'investigate')),
  note         text,
  decided_by   uuid REFERENCES users(id) ON DELETE SET NULL,
  decided_at   timestamptz,
  created_at   timestamptz NOT NULL DEFAULT now(),
  updated_at   timestamptz NOT NULL DEFAULT now(),
  resolved_at  timestamptz
);
CREATE INDEX IF NOT EXISTS net_findings_open ON net_findings (severity, control) WHERE status = 'open';
