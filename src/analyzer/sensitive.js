// Actions that decide who can do what, or hide what was done. The catalog's access levels file almost all of them
// under Write, next to logs:PutLogEvents, so severity rules cannot tell them apart by level. These lists can:
// they are what severity is raised for, where a plain write is not.
import { globMatch } from './wildcard.js';

// The account's own identity plane: holding any of these on every resource is administrator by another name.
const IDENTITY = [
  'iam:Attach*Policy', 'iam:Put*Policy', 'iam:Put*PermissionsBoundary', 'iam:Delete*PermissionsBoundary', 'iam:CreatePolicyVersion', 'iam:SetDefaultPolicyVersion',
  'iam:UpdateAssumeRolePolicy', 'iam:CreateAccessKey', 'iam:CreateLoginProfile', 'iam:UpdateLoginProfile', 'iam:AddUserToGroup', 'iam:CreateServiceSpecificCredential',
  'iam:CreateSAMLProvider', 'iam:UpdateSAMLProvider', 'iam:CreateOpenIDConnectProvider', 'iam:UpdateOpenIDConnectProviderThumbprint', 'iam:AddClientIDToOpenIDConnectProvider',
  'iam:PassRole',
  'organizations:AttachPolicy', 'organizations:CreatePolicy', 'organizations:UpdatePolicy', 'organizations:DetachPolicy', 'organizations:DeletePolicy', 'organizations:LeaveOrganization',
  'sso:AttachManagedPolicyToPermissionSet', 'sso:PutInlinePolicyToPermissionSet', 'sso:CreateAccountAssignment', 'sso:ProvisionPermissionSet',
];
// Access to one kind of resource (its policy, grants or code that runs as a role), and switching the audit trail off.
const RESOURCE = [
  'kms:CreateGrant', 'kms:PutKeyPolicy', 'kms:ScheduleKeyDeletion', 'kms:DisableKey',
  's3:PutBucketPolicy', 's3:DeleteBucketPolicy', 's3:PutBucketAcl', 's3:PutObjectAcl', 's3:PutBucketPublicAccessBlock', 's3:PutAccountPublicAccessBlock',
  'lambda:AddPermission', 'lambda:UpdateFunctionCode', 'lambda:UpdateFunctionConfiguration', 'lambda:CreateFunction',
  'secretsmanager:PutResourcePolicy', 'ecr:SetRepositoryPolicy', 'sns:AddPermission', 'sqs:AddPermission', 'glue:PutResourcePolicy', 'backup:PutBackupVaultAccessPolicy',
  'ssm:SendCommand', 'ssm:StartSession', 'cloudformation:CreateStack', 'cloudformation:UpdateStack', 'cloudformation:CreateChangeSet', 'ec2:ModifyInstanceAttribute',
  'cloudtrail:StopLogging', 'cloudtrail:DeleteTrail', 'cloudtrail:UpdateTrail', 'cloudtrail:PutEventSelectors',
  'guardduty:DeleteDetector', 'guardduty:UpdateDetector', 'config:StopConfigurationRecorder', 'config:DeleteConfigurationRecorder',
];
// Reading the data itself, not its description.
const DATA_READ = [
  's3:GetObject', 's3:GetObjectVersion', 'secretsmanager:GetSecretValue', 'secretsmanager:BatchGetSecretValue', 'ssm:GetParameter', 'ssm:GetParameters', 'ssm:GetParametersByPath',
  'dynamodb:GetItem', 'dynamodb:BatchGetItem', 'dynamodb:Query', 'dynamodb:Scan', 'rds-data:ExecuteStatement', 'athena:GetQueryResults',
];
const any = (list, action) => list.some((p) => globMatch(p, action, { ci: true }));

/** 'identity' (IAM, Organizations, Identity Center), 'resource' (a resource's own policy, code or audit trail), or null. */
export const privilegeTier = (action, level = null) => (any(IDENTITY, action) ? 'identity' : any(RESOURCE, action) || level === 'Permissions' ? 'resource' : null);
export const isPrivilege = (action, level = null) => privilegeTier(action, level) !== null;
export const isDataRead = (action) => any(DATA_READ, action);
