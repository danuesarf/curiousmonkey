-- The role's unique ID from IAM (AROA...). A cross-account AssumeRole shows up in the target account's trail as
-- userIdentity { type: AWSAccount, accountId, principalId: "AROA...:session" } with no ARN; this lets us name the caller.
ALTER TABLE roles ADD COLUMN IF NOT EXISTS aws_id text;
CREATE INDEX IF NOT EXISTS roles_aws_id_idx ON roles (aws_id) WHERE aws_id IS NOT NULL;
