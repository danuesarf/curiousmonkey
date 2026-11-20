// Demo resources with resource-based policies: one of each kind of exposure, so the Resource access page has
// something to show and the tests something to hold on to. Deterministic per account.
export const DEMO_ORG = 'o-curiousdemo1';
const DATADOG = '464622532012';           // a known vendor (fwd:cloudsec's list)
const STRANGER = '888888888888';          // an account nobody knows

export function demoResources(acct, region = 'us-east-1') {
  const other = acct === '111111111111' ? '222222222222' : '111111111111';
  const root = (a) => `arn:aws:iam::${a}:root`;
  const own = { Sid: 'EnableIAMPolicies', Effect: 'Allow', Principal: { AWS: root(acct) }, Action: 'kms:*', Resource: '*' };
  const bucket = (name, statements, extra = {}) => ({ service: 's3', arn: `arn:aws:s3:::${name}`, name, region,
    policy: statements ? { Version: '2012-10-17', Statement: statements } : null, extra: { restrictPublic: false, ...extra } });
  const r = (service, arn, name, statements, extra = {}) => ({ service, arn, name, region, policy: statements ? { Version: '2012-10-17', Statement: statements } : null, extra });
  const p = acct.slice(0, 3);
  return {
    s3: [
      bucket(`demo-${p}-public-assets`, [{ Sid: 'PublicRead', Effect: 'Allow', Principal: '*', Action: 's3:GetObject', Resource: `arn:aws:s3:::demo-${p}-public-assets/*` }]),
      bucket(`demo-${p}-website-blocked`, [{ Sid: 'PublicRead', Effect: 'Allow', Principal: { AWS: '*' }, Action: 's3:GetObject', Resource: `arn:aws:s3:::demo-${p}-website-blocked/*` }],
        { restrictPublic: true, restrictPublicFrom: 'the account\'s Block Public Access', accountBlock: { BlockPublicPolicy: true, RestrictPublicBuckets: true } }),
      bucket(`demo-${p}-vendor-exports`, [{ Sid: 'DatadogRead', Effect: 'Allow', Principal: { AWS: root(DATADOG) }, Action: ['s3:GetObject', 's3:ListBucket'], Resource: '*' }]),
      bucket(`demo-${p}-org-artifacts`, [
        { Sid: 'OrgRead', Effect: 'Allow', Principal: '*', Action: ['s3:GetObject', 's3:ListBucket'], Resource: '*', Condition: { StringEquals: { 'aws:PrincipalOrgID': DEMO_ORG } } }]),
      bucket(`demo-${p}-trail-logs`, [
        { Sid: 'CloudTrailWrite', Effect: 'Allow', Principal: { Service: 'cloudtrail.amazonaws.com' }, Action: 's3:PutObject', Resource: '*' },
        { Sid: 'DenyOutsideOrg', Effect: 'Deny', Principal: '*', Action: 's3:*', Resource: '*', Condition: { StringNotEquals: { 'aws:PrincipalOrgID': DEMO_ORG }, Bool: { 'aws:PrincipalIsAWSService': 'false' } } }]),
      bucket(`demo-${p}-private`, null),
    ],
    kms: [
      r('kms', `arn:aws:kms:${region}:${acct}:key/0000${p}00-0000-4000-8000-00000000000a`, 'payments-data', [own]),
      r('kms', `arn:aws:kms:${region}:${acct}:key/0000${p}00-0000-4000-8000-00000000000b`, 'shared-backups', [own,
        { Sid: 'AllowStagingUse', Effect: 'Allow', Principal: { AWS: root(other) }, Action: ['kms:Decrypt', 'kms:DescribeKey'], Resource: '*' }]),
      r('kms', `arn:aws:kms:${region}:${acct}:key/0000${p}00-0000-4000-8000-00000000000c`, 'legacy-partner', [own,
        { Sid: 'PartnerDecrypt', Effect: 'Allow', Principal: { AWS: `arn:aws:iam::${STRANGER}:role/partner-etl` }, Action: 'kms:*', Resource: '*' }]),
    ],
    dynamodb: [
      r('dynamodb', `arn:aws:dynamodb:${region}:${acct}:table/ledger`, 'ledger', null),
      r('dynamodb', `arn:aws:dynamodb:${region}:${acct}:table/feature-flags`, 'feature-flags', [
        { Sid: 'ReadFromStaging', Effect: 'Allow', Principal: { AWS: `arn:aws:iam::${other}:role/app` }, Action: ['dynamodb:GetItem', 'dynamodb:Query'], Resource: '*' }]),
    ],
    sqs: [
      r('sqs', `arn:aws:sqs:${region}:${acct}:order-events`, 'order-events', [
        { Sid: 'SnsFanout', Effect: 'Allow', Principal: { Service: 'sns.amazonaws.com' }, Action: 'sqs:SendMessage', Resource: '*', Condition: { ArnEquals: { 'aws:SourceArn': `arn:aws:sns:${region}:${acct}:orders` } } }]),
      r('sqs', `arn:aws:sqs:${region}:${acct}:inbound-webhooks`, 'inbound-webhooks', [
        { Sid: 'Anyone', Effect: 'Allow', Principal: { AWS: '*' }, Action: 'sqs:SendMessage', Resource: '*', Condition: { StringEquals: { 'aws:SourceVpce': 'vpce-0a1b2c3d' } } }]),
    ],
    sns: [
      r('sns', `arn:aws:sns:${region}:${acct}:orders`, 'orders', [
        { Sid: '__default_statement_ID', Effect: 'Allow', Principal: { AWS: '*' }, Action: ['SNS:GetTopicAttributes', 'SNS:Subscribe', 'SNS:Publish'], Resource: '*', Condition: { StringEquals: { 'AWS:SourceOwner': acct } } }]),
      r('sns', `arn:aws:sns:${region}:${acct}:alarms`, 'alarms', [
        { Sid: 'EventsPublish', Effect: 'Allow', Principal: { Service: 'events.amazonaws.com' }, Action: 'sns:Publish', Resource: '*' }]),
    ],
    secretsmanager: [
      r('secretsmanager', `arn:aws:secretsmanager:${region}:${acct}:secret:prod/db-AbCdEf`, 'prod/db', null),
      r('secretsmanager', `arn:aws:secretsmanager:${region}:${acct}:secret:vendor/api-key-XyZ123`, 'vendor/api-key', [
        { Sid: 'VendorRead', Effect: 'Allow', Principal: { AWS: root(STRANGER) }, Action: 'secretsmanager:GetSecretValue', Resource: '*' }]),
    ],
    lambda: [
      r('lambda', `arn:aws:lambda:${region}:${acct}:function:thumbnailer`, 'thumbnailer', [
        { Sid: 's3-invoke', Effect: 'Allow', Principal: { Service: 's3.amazonaws.com' }, Action: 'lambda:InvokeFunction', Resource: '*', Condition: { StringEquals: { 'AWS:SourceAccount': acct } } }]),
      r('lambda', `arn:aws:lambda:${region}:${acct}:function:status-url`, 'status-url', [
        { Sid: 'FunctionURLAllowPublicAccess', Effect: 'Allow', Principal: '*', Action: 'lambda:InvokeFunctionUrl', Resource: '*', Condition: { StringEquals: { 'lambda:FunctionUrlAuthType': 'NONE' } } }]),
    ],
    ecr: [
      r('ecr', `arn:aws:ecr:${region}:${acct}:repository/base-images`, 'base-images', [
        { Sid: 'OrgPull', Effect: 'Allow', Principal: '*', Action: ['ecr:BatchGetImage', 'ecr:GetDownloadUrlForLayer'], Condition: { StringEquals: { 'aws:PrincipalOrgID': DEMO_ORG } } }]),
      r('ecr', `arn:aws:ecr:${region}:${acct}:repository/old-app`, 'old-app', [
        { Sid: 'Gone', Effect: 'Allow', Principal: { AWS: 'AROAEXAMPLEDELETED123' }, Action: 'ecr:*' }]),
    ],
  };
}
