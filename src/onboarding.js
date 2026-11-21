// Generates what an account owner deploys so the worker can read IAM and CloudTrail, never customer data.
//   assume_role : a role trusted by the worker's base identity (with the workspace ExternalId)
//   access_key  : a dedicated IAM user whose access key is stored (encrypted) on the account
// The explicit Denies mean a stolen scanner credential cannot read data, even if someone later widens the Allow.
// With an S3 trail, reading that trail's log objects (and decrypting them with a CloudTrail KMS context) is the
// only exception to the data Deny.
import { config } from './config.js';
import { AWS_NETWORK_READS } from './network/awsReader.js';

export const SCANNER_ALLOW = [
  'iam:ListRoles', 'iam:GetRole', 'iam:ListRolePolicies', 'iam:GetRolePolicy', 'iam:ListAttachedRolePolicies', 'iam:GetPolicy', 'iam:GetPolicyVersion',
  'iam:GenerateServiceLastAccessedDetails', 'iam:GetServiceLastAccessedDetails', 'cloudtrail:LookupEvents', 'cloudtrail:DescribeTrails',
  'cloudtrail:GetEventSelectors', 'cloudtrail:ListEventDataStores', 'organizations:DescribeOrganization',
  'iam:ListSAMLProviders', 'iam:GetSAMLProvider',   // which IdP, or IAM Identity Center instance, each SAML provider is
  'eks:ListClusters', 'eks:DescribeCluster',         // names EKS clusters whose OIDC providers roles trust
  // from the management (or a delegated administrator) account only; elsewhere these are denied and skipped
  'organizations:ListAccounts',                      // the organisation's accounts not onboarded here are yours, not outsiders
  'sso:ListInstances', 'sso:ListPermissionSets', 'sso:DescribePermissionSet', 'sso:ListAccountsForProvisionedPermissionSet', 'sso:ListAccountAssignments',
  'identitystore:DescribeUser', 'identitystore:DescribeGroup',   // who is behind each Identity Center permission set
  // IAM users: their policies (and their groups'), access key metadata and last use, console password and MFA
  'iam:ListUsers', 'iam:GetUser', 'iam:ListAccessKeys', 'iam:GetAccessKeyLastUsed', 'iam:ListMFADevices', 'iam:GetLoginProfile', 'iam:ListGroupsForUser',
  'iam:ListUserPolicies', 'iam:GetUserPolicy', 'iam:ListAttachedUserPolicies', 'iam:ListGroupPolicies', 'iam:GetGroupPolicy', 'iam:ListAttachedGroupPolicies',
  // resource access: resource-based policies and the settings that decide them, never the data (Resource access page)
  's3:ListAllMyBuckets', 's3:GetBucketLocation', 's3:GetBucketPolicy', 's3:GetBucketPublicAccessBlock', 's3:GetAccountPublicAccessBlock',
  'kms:ListKeys', 'kms:ListAliases', 'kms:DescribeKey', 'kms:GetKeyPolicy', 'dynamodb:ListTables', 'dynamodb:GetResourcePolicy',
  'sqs:ListQueues', 'sqs:GetQueueAttributes', 'sns:ListTopics', 'sns:GetTopicAttributes', 'secretsmanager:ListSecrets', 'secretsmanager:GetResourcePolicy',
  'lambda:ListFunctions', 'lambda:GetPolicy', 'ecr:DescribeRepositories', 'ecr:GetRepositoryPolicy',
];
const DENY_DATA = [
  'dynamodb:GetItem', 'dynamodb:BatchGetItem', 'dynamodb:Query', 'dynamodb:Scan', 'secretsmanager:GetSecretValue',
  'ssm:GetParameter', 'ssm:GetParameters', 'ssm:GetParametersByPath', 'sqs:ReceiveMessage', 'lambda:InvokeFunction',
];
export const SCANNER_DENY = ['s3:GetObject', 's3:GetObjectVersion', 'kms:Decrypt', ...DENY_DATA];

const clean = (p) => (p ? `${p.replace(/^\/+|\/+$/g, '')}/` : '');
export const trailObjectsArn = ({ bucket, prefix }) => `arn:aws:s3:::${bucket}/${clean(prefix)}AWSLogs/*`;

// VPC flow log files (Networking extension): only keys under AWSLogs/<account>/vpcflowlogs/, in any bucket
export const FLOW_OBJECTS = ['arn:aws:s3:::*/AWSLogs/*/vpcflowlogs/*', 'arn:aws:s3:::*/AWSLogs/aws-account-id=*/aws-service=vpcflowlogs/*'];
const FLOW_PREFIXES = ['*AWSLogs/*/vpcflowlogs/*', '*aws-service=vpcflowlogs/*'];

export function scannerPolicy({ s3, network = false } = {}) {
  const st = [{ Sid: 'ReadIamAndTrailMetadata', Effect: 'Allow', Action: SCANNER_ALLOW, Resource: '*' }];
  // the Networking extension: VPC networking, Direct Connect, Resolver, Network Firewall and load balancer metadata
  // (read-only), and VPC flow log files and nothing else in the buckets they are delivered to
  if (network) st.push({ Sid: 'ReadNetworking', Effect: 'Allow', Action: AWS_NETWORK_READS, Resource: '*' },
    { Sid: 'ListFlowLogFiles', Effect: 'Allow', Action: 's3:ListBucket', Resource: 'arn:aws:s3:::*', Condition: { StringLike: { 's3:prefix': FLOW_PREFIXES } } },
    { Sid: 'ReadFlowLogFiles', Effect: 'Allow', Action: 's3:GetObject', Resource: FLOW_OBJECTS },
    { Sid: 'DecryptFlowLogFiles', Effect: 'Allow', Action: 'kms:Decrypt', Resource: '*', Condition: { StringLike: { 'kms:EncryptionContext:aws:s3:arn': FLOW_OBJECTS } } });
  const objects = [...(s3?.bucket ? [trailObjectsArn(s3)] : []), ...(network ? FLOW_OBJECTS : [])];
  if (s3?.bucket) {
    st.push(
      { Sid: 'ListTrailBucket', Effect: 'Allow', Action: ['s3:ListBucket', 's3:GetBucketLocation'], Resource: `arn:aws:s3:::${s3.bucket}` },
      { Sid: 'ReadTrailLogFiles', Effect: 'Allow', Action: 's3:GetObject', Resource: trailObjectsArn(s3) },
      { Sid: 'DecryptTrailLogFiles', Effect: 'Allow', Action: 'kms:Decrypt', Resource: '*',
        Condition: { StringLike: { 'kms:EncryptionContext:aws:cloudtrail:arn': 'arn:aws:cloudtrail:*' } } });
  }
  if (objects.length) {
    // conditions in one statement are ANDed: decrypting is refused unless it is for CloudTrail or for a flow log file
    const notTrail = s3?.bucket ? { Null: { 'kms:EncryptionContext:aws:cloudtrail:arn': 'true' } } : {};
    const notFlow = network ? { StringNotLike: { 'kms:EncryptionContext:aws:s3:arn': FLOW_OBJECTS } } : {};
    st.push(
      { Sid: 'NeverReadOtherObjects', Effect: 'Deny', Action: ['s3:GetObject', 's3:GetObjectVersion'], NotResource: objects.length === 1 ? objects[0] : objects },
      { Sid: network ? 'NeverDecryptOtherData' : 'NeverDecryptOutsideCloudTrail', Effect: 'Deny', Action: 'kms:Decrypt', Resource: '*', Condition: { ...notTrail, ...notFlow } },
    );
  } else {
    st.push({ Sid: 'NeverReadObjectsOrDecrypt', Effect: 'Deny', Action: ['s3:GetObject', 's3:GetObjectVersion', 'kms:Decrypt'], Resource: '*' });
  }
  st.push({ Sid: 'NeverReadCustomerData', Effect: 'Deny', Action: DENY_DATA, Resource: '*' });
  return { Version: '2012-10-17', Statement: st };
}

const indent = (o, n = 2) => JSON.stringify(o, null, 2).replace(/\n/g, `\n${' '.repeat(n)}`);

export function scannerSnippets({ mode = 'assume_role', principalArn, roleName, userName = 'curious-monkey-scanner', externalId, s3, network = false }) {
  const perms = scannerPolicy({ s3, network });
  if (mode === 'access_key') {
    const terraform = `resource "aws_iam_user" "curious_monkey" {
  name = "${userName}"
}

resource "aws_iam_user_policy" "curious_monkey" {
  name   = "curious-monkey-read-only"
  user   = aws_iam_user.curious_monkey.name
  policy = jsonencode(${indent(perms)})
}

# Then create its access key (kept out of Terraform state on purpose):
#   aws iam create-access-key --user-name ${userName}`;
    const cloudformation = `AWSTemplateFormatVersion: '2010-09-09'
Description: Curious Monkey read-only scanner user
Resources:
  CuriousMonkeyScanner:
    Type: AWS::IAM::User
    Properties:
      UserName: ${userName}
      Policies:
        - PolicyName: curious-monkey-read-only
          PolicyDocument: ${JSON.stringify(perms)}
# Then create its access key: aws iam create-access-key --user-name ${userName}`;
    return { mode, perms, terraform, cloudformation, userName };
  }

  const principal = principalArn || 'arn:aws:iam::<WORKER_ACCOUNT>:role/<WORKER_ROLE>';
  const trust = { Version: '2012-10-17', Statement: [{ Effect: 'Allow', Principal: { AWS: principal },
    Action: 'sts:AssumeRole', Condition: { StringEquals: { 'sts:ExternalId': externalId } } }] };
  const terraform = `resource "aws_iam_role" "curious_monkey" {
  name               = "${roleName}"
  assume_role_policy = jsonencode(${indent(trust)})
}

resource "aws_iam_role_policy" "curious_monkey" {
  name   = "curious-monkey-read-only"
  role   = aws_iam_role.curious_monkey.id
  policy = jsonencode(${indent(perms)})
}`;
  const cloudformation = `AWSTemplateFormatVersion: '2010-09-09'
Description: Curious Monkey read-only scanner role
Resources:
  CuriousMonkeyScanner:
    Type: AWS::IAM::Role
    Properties:
      RoleName: ${roleName}
      AssumeRolePolicyDocument: ${JSON.stringify(trust)}
      Policies:
        - PolicyName: curious-monkey-read-only
          PolicyDocument: ${JSON.stringify(perms)}
Outputs:
  RoleArn:
    Value: !GetAtt CuriousMonkeyScanner.Arn`;
  // What the base identity (worker role/user, or the stored keys' user) needs: nothing but this.
  const basePolicy = { Version: '2012-10-17', Statement: [{ Effect: 'Allow', Action: 'sts:AssumeRole', Resource: `arn:aws:iam::*:role/${roleName}` }] };
  return { mode, trust, perms, terraform, cloudformation, basePolicy, principal: principalArn || null };
}

/** Bucket policy to add when the trail bucket lives in another account (for example a log-archive account). */
export function crossAccountBucketPolicy({ s3, readerArn }) {
  return { Version: '2012-10-17', Statement: [
    { Sid: 'CuriousMonkeyList', Effect: 'Allow', Principal: { AWS: readerArn }, Action: ['s3:ListBucket', 's3:GetBucketLocation'], Resource: `arn:aws:s3:::${s3.bucket}` },
    { Sid: 'CuriousMonkeyRead', Effect: 'Allow', Principal: { AWS: readerArn }, Action: 's3:GetObject', Resource: trailObjectsArn(s3) },
  ] };
}
export const defaultRoleName = () => config.scanner.roleName;
