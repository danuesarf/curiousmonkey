-- Google Cloud: who can do what, and where they can come from. Permissions only, no audit logs yet.
-- One connection reads an organization, a folder or a single project. Each scan replaces that connection's snapshot.

CREATE TABLE gcp_connections (
  id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name           text NOT NULL,
  scope_type     text NOT NULL CHECK (scope_type IN ('organization','folder','project')),
  scope_id       text NOT NULL,                     -- numeric org/folder id, or a project id
  auth_mode      text NOT NULL CHECK (auth_mode IN ('wif','key')),
  wif            jsonb,                             -- { projectNumber, poolId, providerId, serviceAccount }
  key_enc        text,                              -- service account key JSON, encrypted
  key_hint       text,                              -- client_email and key id, for display
  environment    text NOT NULL DEFAULT 'production',
  status         text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','connected','error')),
  status_detail  jsonb,
  last_scan_at   timestamptz,
  next_scan_at   timestamptz DEFAULT now(),
  lease_until    timestamptz,
  lease_by       text,
  progress       jsonb,
  created_by     uuid REFERENCES users(id) ON DELETE SET NULL,
  created_at     timestamptz NOT NULL DEFAULT now(),
  UNIQUE (scope_type, scope_id)
);

CREATE TABLE gcp_projects (
  project_id     text NOT NULL,
  connection_id  uuid NOT NULL REFERENCES gcp_connections(id) ON DELETE CASCADE,
  number         text,
  name           text,
  parent         text,                              -- folders/123 or organizations/456
  ancestors      text[] NOT NULL DEFAULT '{}',      -- nearest first, up to the organization
  labels         jsonb NOT NULL DEFAULT '{}',
  environment    text,                              -- set here; null = the label, then the connection's default
  seen_at        timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (connection_id, project_id)          -- an organization and a project inside it may both be connected
);

-- service accounts, users, groups, domains, the public and federated identities: anything an IAM policy names
CREATE TABLE gcp_principals (
  id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  connection_id  uuid NOT NULL REFERENCES gcp_connections(id) ON DELETE CASCADE,
  member         text NOT NULL,                     -- as IAM writes it: serviceAccount:x@p.iam.gserviceaccount.com
  kind           text NOT NULL,                     -- serviceAccount | user | group | domain | public | federated | deleted | other
  email          text,
  display_name   text,
  project_id     text,                              -- a service account's home project
  unique_id      text,                              -- a service account's numeric id (what AWS trust policies name)
  disabled       boolean NOT NULL DEFAULT false,
  managed_by     text,                              -- google (a Google-managed service agent) | null
  keys           jsonb NOT NULL DEFAULT '[]',       -- user-managed keys: [{ id, created, expires, disabled }]
  roles          jsonb NOT NULL DEFAULT '[]',       -- [{ role, resource, inherited, condition }]
  permissions    int NOT NULL DEFAULT 0,
  reach          text[] NOT NULL DEFAULT '{}',      -- projects it holds roles in
  origin         jsonb,                             -- a federated identity: the AWS account, role or repo behind it
  sources        jsonb NOT NULL DEFAULT '[]',       -- who or what can act as it
  risk           text NOT NULL DEFAULT 'Low' CHECK (risk IN ('High','Medium','Low')),
  risk_score     int NOT NULL DEFAULT 0,
  risk_reasons   jsonb NOT NULL DEFAULT '[]',
  analyzed_at    timestamptz,
  UNIQUE (connection_id, member)
);
CREATE INDEX gcp_principals_kind_idx ON gcp_principals (kind);
CREATE INDEX gcp_principals_unique_idx ON gcp_principals (unique_id) WHERE unique_id IS NOT NULL;

CREATE TABLE gcp_bindings (
  connection_id  uuid NOT NULL REFERENCES gcp_connections(id) ON DELETE CASCADE,
  resource       text NOT NULL,                     -- organizations/1, folders/2, projects/p, projects/p/serviceAccounts/x
  resource_type  text NOT NULL,                     -- organization | folder | project | serviceAccount
  project_id     text,
  role           text NOT NULL,
  member         text NOT NULL,
  condition      jsonb
);
CREATE INDEX gcp_bindings_member_idx ON gcp_bindings (connection_id, member);
CREATE INDEX gcp_bindings_resource_idx ON gcp_bindings (connection_id, resource);

-- role definitions: predefined ones are shared, custom ones belong to a project or organization
CREATE TABLE gcp_role_defs (
  name           text PRIMARY KEY,                  -- roles/x, projects/p/roles/x, organizations/1/roles/x
  title          text,
  permissions    text[] NOT NULL DEFAULT '{}',
  stage          text,
  fetched_at     timestamptz NOT NULL DEFAULT now()
);

-- workload identity federation: pools and providers, the doors from AWS, GitHub and others into Google Cloud
CREATE TABLE gcp_wif_providers (
  name           text NOT NULL,                     -- projects/<number>/locations/global/workloadIdentityPools/<pool>/providers/<provider>
  connection_id  uuid NOT NULL REFERENCES gcp_connections(id) ON DELETE CASCADE,
  project_id     text NOT NULL,
  project_number text,
  pool_id        text NOT NULL,
  provider_id    text NOT NULL,
  display_name   text,
  type           text NOT NULL,                     -- aws | oidc | saml | x509
  aws_account_id text,
  issuer         text,
  allowed_audiences text[] NOT NULL DEFAULT '{}',
  attribute_mapping jsonb NOT NULL DEFAULT '{}',
  attribute_condition text,
  disabled       boolean NOT NULL DEFAULT false,
  PRIMARY KEY (connection_id, name)
);
