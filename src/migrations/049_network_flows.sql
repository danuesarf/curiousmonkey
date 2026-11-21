-- VPC flow logs (Networking extension): read from the S3 buckets flow logs are delivered to, attributed to the line
-- each record travelled on (the subnet's route table, as AWS routes it), and kept by the hour, so the map can say
-- which peering, transit gateway attachment, VPN or Direct Connect is used, and what the internet reaches.

-- every file read, once (pruned after 35 days)
CREATE TABLE IF NOT EXISTS net_flow_files (
  bucket       text NOT NULL,
  key          text NOT NULL,
  flow_log     text NOT NULL,                 -- fl-…
  owner        text NOT NULL,                 -- the account the flow log belongs to
  vpc_node     text,                          -- aws:vpc:<account>:<vpc>
  file_time    timestamptz NOT NULL,          -- from the file name: when the window it holds ended
  size         bigint NOT NULL DEFAULT 0,
  records      int NOT NULL DEFAULT 0,
  read_at      timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (bucket, key)
);
CREATE INDEX IF NOT EXISTS net_flow_files_vpc ON net_flow_files (vpc_node, file_time);

-- traffic on each line of the map, per hour, side (the VPC whose interface logged it), direction and server port
CREATE TABLE IF NOT EXISTS net_flow_hourly (
  hour      timestamptz NOT NULL,
  link_id   text NOT NULL,
  side      text NOT NULL,
  dir       text NOT NULL,                    -- out: a connection from the side; in: to it
  port      int NOT NULL,
  proto     text NOT NULL,
  action    text NOT NULL,                    -- ACCEPT, REJECT
  bytes     bigint NOT NULL DEFAULT 0,
  packets   bigint NOT NULL DEFAULT 0,
  records   bigint NOT NULL DEFAULT 0,
  PRIMARY KEY (hour, link_id, side, dir, port, proto, action)
);
CREATE INDEX IF NOT EXISTS net_flow_hourly_link ON net_flow_hourly (link_id, hour);

-- what the internet reached on each public address (an interface or a load balancer), per hour and port
CREATE TABLE IF NOT EXISTS net_flow_exposure (
  hour      timestamptz NOT NULL,
  target    text NOT NULL,                    -- eni-… or a load balancer ARN
  port      int NOT NULL,
  proto     text NOT NULL,
  action    text NOT NULL,
  records   bigint NOT NULL DEFAULT 0,
  bytes     bigint NOT NULL DEFAULT 0,
  sources   int NOT NULL DEFAULT 0,           -- distinct source addresses seen in one read (at least)
  PRIMARY KEY (hour, target, port, proto, action)
);

-- each flow log's reading state: where it is delivered, the last file read, and why it is not read
CREATE TABLE IF NOT EXISTS net_flow_reads (
  flow_log    text PRIMARY KEY,
  owner       text NOT NULL,
  vpc_node    text,
  bucket      text,
  prefix      text,
  last_time   timestamptz,
  files       int NOT NULL DEFAULT 0,
  bytes       bigint NOT NULL DEFAULT 0,
  note        text,                           -- not S3, Parquet, not allowed…
  error       text,
  read_at     timestamptz NOT NULL DEFAULT now()
);
