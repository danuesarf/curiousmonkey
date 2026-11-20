-- Resource access: who resource-based policies let in. S3 buckets, KMS keys, DynamoDB tables, SQS queues, SNS topics,
-- secrets, Lambda functions and ECR repositories are read with each account's inventory. Their grants (who each
-- statement lets in, how far that reaches, what it allows) and findings are worked out from the policy and the estate,
-- and worked out again when the estate or the workspace's policy changes (src/resourceSync.js).

-- the organisation an account belongs to (organizations:DescribeOrganization answers from any member account), so
-- aws:PrincipalOrgID conditions can be told apart: your organisation, or someone else's
ALTER TABLE cloud_accounts ADD COLUMN IF NOT EXISTS aws_org_id text;

CREATE TABLE resources (
  id                 uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  account_id         uuid NOT NULL REFERENCES cloud_accounts(id) ON DELETE CASCADE,
  service            text NOT NULL,                     -- s3, kms, dynamodb, sqs, sns, secretsmanager, lambda, ecr
  arn                text NOT NULL,
  name               text NOT NULL,
  region             text,
  policy             jsonb,                             -- null: the resource has no resource policy
  doc_hash           text,
  extra              jsonb NOT NULL DEFAULT '{}',       -- what else decides access: S3 Block Public Access, a KMS key's manager…
  exposure           text NOT NULL DEFAULT 'none'
                     CHECK (exposure IN ('public', 'external', 'cross-account', 'service', 'private', 'none')),
  grants             jsonb NOT NULL DEFAULT '[]',       -- who the policy lets in, statement by statement
  worst              text CHECK (worst IN ('high', 'medium', 'low')),   -- most severe open finding
  seen_at            timestamptz NOT NULL DEFAULT now(),
  policy_changed_at  timestamptz,
  deleted_at         timestamptz,
  UNIQUE (account_id, arn)
);
CREATE INDEX resources_listed ON resources (exposure, service) WHERE deleted_at IS NULL;

CREATE TABLE resource_findings (
  id                 uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  resource_id        uuid NOT NULL REFERENCES resources(id) ON DELETE CASCADE,
  key                text NOT NULL,                     -- control | statement | principal
  control            text NOT NULL,                     -- res.public, res.external-account…
  severity           text NOT NULL CHECK (severity IN ('high', 'medium', 'low')),
  title              text NOT NULL,
  detail             text NOT NULL,
  suggestion         text,
  principal          text,
  principal_account  text,
  statement          int,
  sid                text,
  actions            text[] NOT NULL DEFAULT '{}',
  conditions         text[] NOT NULL DEFAULT '{}',
  status             text NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'resolved')),
  -- a reviewer's call: expected (accepted, with a reason) or investigate. Cleared when the grant changes.
  decision           text CHECK (decision IN ('expected', 'investigate')),
  note               text,
  decided_by         uuid REFERENCES users(id) ON DELETE SET NULL,
  decided_at         timestamptz,
  created_at         timestamptz NOT NULL DEFAULT now(),
  updated_at         timestamptz NOT NULL DEFAULT now(),
  resolved_at        timestamptz,
  UNIQUE (resource_id, key)
);
CREATE INDEX resource_findings_open ON resource_findings (control, severity) WHERE status = 'open';

-- what the stored analysis was worked out from (connected and organisation accounts, organisation IDs, the policy)
CREATE TABLE resource_analysis (
  id   boolean PRIMARY KEY DEFAULT true CHECK (id),
  sig  text NOT NULL,
  at   timestamptz NOT NULL DEFAULT now()
);

-- the change feed learns that a resource was opened to anyone, or to an account outside the estate
ALTER TABLE changes DROP CONSTRAINT changes_kind_check;
ALTER TABLE changes ADD CONSTRAINT changes_kind_check
  CHECK (kind IN ('new-caller', 'denied', 'grew', 'unidentified', 'new-role', 'dead', 'cleaned', 'new-trust', 'trust-weakened', 'resource-public', 'resource-shared'));
