-- What the scanner reads around the trust policies, so the Trust map can name things and say who is behind them.

-- EKS clusters (eks:ListClusters, eks:DescribeCluster): a cluster's OIDC issuer names the provider roles trust
CREATE TABLE eks_clusters (
  account_id   uuid NOT NULL REFERENCES cloud_accounts(id) ON DELETE CASCADE,
  region       text NOT NULL,
  name         text NOT NULL,
  arn          text NOT NULL,
  oidc_issuer  text,                              -- https://oidc.eks.<region>.amazonaws.com/id/<ID>
  seen_at      timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (account_id, arn)
);
CREATE INDEX eks_clusters_issuer ON eks_clusters (oidc_issuer);

-- The organisation's accounts (organizations:ListAccounts, from the management or a delegated administrator account):
-- an "outside" account that is the organisation's own is yours, not onboarded
CREATE TABLE org_accounts (
  account_id   text PRIMARY KEY,                  -- 12 digits
  name         text NOT NULL,
  email        text,
  status       text,
  seen_from    uuid REFERENCES cloud_accounts(id) ON DELETE SET NULL,
  seen_at      timestamptz NOT NULL DEFAULT now()
);

-- IAM Identity Center assignments (sso-admin, identitystore): who gets each permission set in each account
CREATE TABLE idc_assignments (
  instance_arn     text NOT NULL,
  account_id       text NOT NULL,                 -- 12 digits
  permission_set   text NOT NULL,                 -- its name: the AWSReservedSSO_<name>_<hash> role in the account
  principal_type   text NOT NULL CHECK (principal_type IN ('USER', 'GROUP')),
  principal_id     text NOT NULL,
  principal_name   text,
  seen_from        uuid REFERENCES cloud_accounts(id) ON DELETE SET NULL,
  seen_at          timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (instance_arn, account_id, permission_set, principal_type, principal_id)
);
CREATE INDEX idc_assignments_account ON idc_assignments (account_id, permission_set);
