// A small invented AWS estate used by AWS_MODE=demo and by the tests. Nothing here is real.
import crypto from 'node:crypto';
const P = (stmts) => ({ Version: '2012-10-17', Statement: stmts });
const A = (Action, Resource = '*', extra = {}) => ({ Effect: 'Allow', Action, Resource, ...extra });

export const MANAGED = {
  'arn:aws:iam::aws:policy/AmazonSSMReadOnlyAccess': P([A(['ssm:Describe*', 'ssm:Get*', 'ssm:List*'])]),
  'arn:aws:iam::aws:policy/ReadOnlyAccess': P([A(['ec2:Describe*', 'ecs:Describe*', 'ecs:List*', 'eks:Describe*', 'eks:List*', 'cloudformation:List*', 'cloudformation:Describe*', 'cloudwatch:Get*', 'logs:Describe*'])]),
  'arn:aws:iam::aws:policy/aws-service-role/AmazonECSServiceRolePolicy': P([A(['ec2:Describe*', 'elasticloadbalancing:Describe*', 'elasticloadbalancing:RegisterTargets', 'elasticloadbalancing:DeregisterTargets'])]),
  'arn:aws:iam::aws:policy/PowerUserAccess': P([{ Effect: 'Allow', NotAction: ['iam:*', 'organizations:*', 'account:*'], Resource: '*' }]),
  'arn:aws:iam::aws:policy/AdministratorAccess': P([A('*')]),
};

// IAM Identity Center: every account gets its own AWSSSO_<id>_DO_NOT_DELETE provider, all issued by the one
// organisation instance (managed from an invented account). The staging demo account also has an account instance
// of its own turned on, so the "more than one Identity Center" warning has something to show.
const hex = (s, n) => crypto.createHash('sha1').update(s).digest('hex').slice(0, n);
const issuerFor = (home, ins) => `https://portal.sso.ap-southeast-1.amazonaws.com/saml/assertion/${Buffer.from(`${home}_ins-${ins}`).toString('base64')}`;
export const ssoProviderName = (acct, which = 'org') => `AWSSSO_${hex(`${which}${acct}`, 16)}_DO_NOT_DELETE`;
export function samlProvidersOf(acct) {
  const out = [{ name: ssoProviderName(acct), issuer: issuerFor('999900001111', 'a1b2c3d4e5f60718') }];
  if (acct.endsWith('2')) out.push({ name: ssoProviderName(acct, 'local'), issuer: issuerFor(acct, hex(`local${acct}`, 16)) });
  return out.map((p) => ({ ...p, arn: `arn:aws:iam::${acct}:saml-provider/${p.name}`, createdAt: new Date('2025-03-01T00:00:00Z') }));
}

// the two demo accounts trust each other a little, as real estates do: monitoring from the whole other account, and
// the other account's ETL role reading the lake
const SIBLING = { '111111111111': '222222222222', '222222222222': '111111111111' };
// the demo Google Cloud estate's BigQuery exporter (gcp/demo.js) reads the payments lake: an AWS role trusting a
// Google service account by its unique ID, the way GCP -> AWS federation is set up
const GCP_EXPORTER_ID = '104857600000000000001';

export function buildEstate(acct) {
  const arn = (name, path = '/') => `arn:aws:iam::${acct}:role${path}${name}`;
  const sib = SIBLING[acct];
  const alsoFrom = (stmts) => (sib ? stmts : []);
  const roles = [
    { name: 'payments-api-prod', path: '/', kind: 'custom',
      trust: P([{ Effect: 'Allow', Action: 'sts:AssumeRole', Principal: { Service: 'ecs-tasks.amazonaws.com' } }]),
      inline: [{ name: 'payments-access', document: P([
        A(['s3:GetObject', 's3:PutObject'], 'arn:aws:s3:::acme-payments-docs/*'),
        A('s3:ListBucket', 'arn:aws:s3:::acme-payments-docs'),
        A(['dynamodb:GetItem', 'dynamodb:PutItem', 'dynamodb:Query'], `arn:aws:dynamodb:ap-southeast-3:${acct}:table/payments`),
        A(['sqs:SendMessage', 'sqs:ReceiveMessage'], `arn:aws:sqs:ap-southeast-3:${acct}:payments-events`),
        A('iam:PassRole', arn('payments-task-exec')),
        A(['ec2:DescribeInstances', 'ec2:TerminateInstances']),
        A(['logs:CreateLogStream', 'logs:CreateLogGroup']),
      ]) }],
      attached: ['arn:aws:iam::aws:policy/AmazonSSMReadOnlyAccess'],
      principals: [{ key: 'svc:ecs-tasks', type: 'Service', invokedBy: 'ecs-tasks.amazonaws.com', hours: [0, 6, 12, 18], sessions: 'task' }],
      usage: [{ p: 'svc:ecs-tasks', src: 'ssm.amazonaws.com', name: 'GetParameter', perHour: 6, res: `arn:aws:ssm:ap-southeast-3:${acct}:parameter/payments/db` },
              { p: 'svc:ecs-tasks', src: 'ec2.amazonaws.com', name: 'DescribeInstances', perHour: 1 },
              { p: 'svc:ecs-tasks', src: 'logs.amazonaws.com', name: 'CreateLogStream', perHour: 2 }],
      advisor: { s3: 2, dynamodb: 100, ssm: 0, ec2: 0, logs: 0 },
      dataEvents: true },
    { name: 'ci-deployer', path: '/', kind: 'custom',
      trust: P([{ Effect: 'Allow', Action: 'sts:AssumeRoleWithWebIdentity', Principal: { Federated: `arn:aws:iam::${acct}:oidc-provider/token.actions.githubusercontent.com` },
        Condition: { StringEquals: { 'token.actions.githubusercontent.com:aud': 'sts.amazonaws.com' }, StringLike: { 'token.actions.githubusercontent.com:sub': 'repo:acme-corp/platform:ref:refs/heads/main' } } }]),
      inline: [{ name: 'deploy', document: P([A(['ecs:UpdateService', 'ecs:RegisterTaskDefinition', 'ecs:DescribeServices', 'ecs:DeleteService']),
        A(['ecr:GetAuthorizationToken', 'ecr:PutImage', 'ecr:BatchCheckLayerAvailability']), A('iam:PassRole', arn('payments-task-exec')), A('cloudformation:*')]) }],
      attached: [],
      principals: [{ key: 'web:github', type: 'WebIdentityUser', federated: true, hours: [3, 9, 15], sessions: 'run' }],
      usage: [{ p: 'web:github', src: 'ecs.amazonaws.com', name: 'RegisterTaskDefinition', perHour: 1, params: { executionRoleArn: arn('payments-task-exec') } },
              { p: 'web:github', src: 'ecs.amazonaws.com', name: 'UpdateService', perHour: 1 },
              { p: 'web:github', src: 'ecr.amazonaws.com', name: 'GetAuthorizationToken', perHour: 1 }],
      advisor: { ecs: 0, ecr: 0, iam: 0, cloudformation: 60 }, ghOnly: true },
    { name: 'data-etl', path: '/', kind: 'custom',
      trust: P([{ Effect: 'Allow', Action: 'sts:AssumeRole', Principal: { AWS: arn('airflow-worker') } }]),
      inline: [{ name: 'etl', document: P([A(['s3:*', 'glue:*', 'athena:*'])]) }], attached: [],
      principals: [{ key: 'role:airflow-worker', type: 'AssumedRole', arn: `arn:aws:sts::${acct}:assumed-role/airflow-worker/airflow`, hours: [1, 2, 3], sessions: 'dag', viaRole: 'airflow-worker', viaPr: 'svc:ecs-tasks' }],
      usage: [{ p: 'role:airflow-worker', src: 'glue.amazonaws.com', name: 'GetJobRuns', perHour: 4 },
              { p: 'role:airflow-worker', src: 'athena.amazonaws.com', name: 'StartQueryExecution', perHour: 2 }],
      advisor: { s3: 1, glue: 0, athena: 0 } },
    { name: 'legacy-admin', path: '/', kind: 'custom',
      trust: P([{ Effect: 'Allow', Action: 'sts:AssumeRole', Principal: { AWS: 'arn:aws:iam::999999999999:root' }, Condition: { StringEquals: { 'sts:ExternalId': 'legacy-2021' } } }]),
      inline: [{ name: 'admin', document: P([A('*')]) }], attached: [],
      principals: [{ key: 'user:888888888888:contractor', type: 'IAMUser', accountId: '888888888888', arn: 'arn:aws:iam::888888888888:user/contractor', hours: [10], sessions: 'day', days: [2, 4] }],
      usage: [{ p: 'user:888888888888:contractor', src: 'iam.amazonaws.com', name: 'ListUsers', perHour: 1 },
              { p: 'user:888888888888:contractor', src: 'ec2.amazonaws.com', name: 'DescribeInstances', perHour: 2 },
              { p: 'user:888888888888:contractor', src: 'kms.amazonaws.com', name: 'ListKeys', perHour: 3, deniedEvery: 3 }],
      advisor: { iam: 0, ec2: 0, kms: 0 } },
    { name: 'AWSServiceRoleForECS', path: '/aws-service-role/ecs.amazonaws.com/', kind: 'service-linked',
      trust: P([{ Effect: 'Allow', Action: 'sts:AssumeRole', Principal: { Service: 'ecs.amazonaws.com' } }]),
      inline: [], attached: ['arn:aws:iam::aws:policy/aws-service-role/AmazonECSServiceRolePolicy'],
      principals: [{ key: 'svc:ecs', type: 'Service', invokedBy: 'ecs.amazonaws.com', hours: [0, 4, 8, 12, 16, 20], sessions: 'svc' }],
      usage: [{ p: 'svc:ecs', src: 'ec2.amazonaws.com', name: 'DescribeInstances', perHour: 3 },
              { p: 'svc:ecs', src: 'elasticloadbalancing.amazonaws.com', name: 'RegisterTargets', perHour: 1 }],
      advisor: { ec2: 0, elasticloadbalancing: 0 } },
    { name: 'AWSReservedSSO_PlatformEngineer_3f1c9a', path: '/aws-reserved/sso.amazonaws.com/', kind: 'identity-center', permissionSet: 'PlatformEngineer',
      trust: P([{ Effect: 'Allow', Action: ['sts:AssumeRoleWithSAML', 'sts:TagSession'], Principal: { Federated: `arn:aws:iam::${acct}:saml-provider/${ssoProviderName(acct)}` }, Condition: { StringEquals: { 'SAML:aud': 'https://signin.aws.amazon.com/saml' } } }]),
      inline: [], attached: ['arn:aws:iam::aws:policy/PowerUserAccess'],
      principals: [{ key: 'sso:dewi@acme', type: 'SAMLUser', federated: true, hours: [2, 3, 4, 5], sessions: 'day', days: [1, 2, 3, 4, 5] }],
      usage: [{ p: 'sso:dewi@acme', src: 'eks.amazonaws.com', name: 'DescribeCluster', perHour: 3 },
              { p: 'sso:dewi@acme', src: 'ec2.amazonaws.com', name: 'DescribeInstances', perHour: 2 },
              { p: 'sso:dewi@acme', src: 'cloudformation.amazonaws.com', name: 'ListStacks', perHour: 1 }],
      advisor: { eks: 0, ec2: 0, cloudformation: 0, s3: 40 } },
    { name: 'old-batch-runner', path: '/', kind: 'custom',
      trust: P([{ Effect: 'Allow', Action: 'sts:AssumeRole', Principal: { Service: 'glue.amazonaws.com' } }]),
      inline: [{ name: 'batch', document: P([A(['s3:GetObject'], 'arn:aws:s3:::acme-legacy-batch/*'), A('glue:StartJobRun')]) }], attached: [],
      principals: [], usage: [], advisor: { glue: 210 }, lastUsedDaysAgo: 210 },
    { name: 'monitoring-reader', path: '/', kind: 'custom',
      trust: P([{ Effect: 'Allow', Action: 'sts:AssumeRole', Principal: { AWS: `arn:aws:iam::${acct}:root` } },
        ...alsoFrom([{ Effect: 'Allow', Action: 'sts:AssumeRole', Principal: { AWS: `arn:aws:iam::${sib}:root` } }])]),
      inline: [{ name: 'read', document: P([A(['cloudwatch:GetMetricData', 'cloudwatch:ListMetrics', 'logs:DescribeLogGroups', 'logs:GetLogEvents'])]) }], attached: [],
      principals: [{ key: 'role:grafana', type: 'AssumedRole', arn: `arn:aws:sts::${acct}:assumed-role/grafana/g`, hours: [0, 6, 12, 18], sessions: 'day' }],
      usage: [{ p: 'role:grafana', src: 'monitoring.amazonaws.com', name: 'GetMetricData', perHour: 5 }, { p: 'role:grafana', src: 'logs.amazonaws.com', name: 'DescribeLogGroups', perHour: 1 }],
      advisor: { cloudwatch: 0, logs: 0 } },
    // role chaining: airflow-worker (an ECS task) assumes data-etl, which assumes lake-reader
    { name: 'airflow-worker', path: '/', kind: 'custom',
      trust: P([{ Effect: 'Allow', Action: 'sts:AssumeRole', Principal: { Service: 'ecs-tasks.amazonaws.com' } }]),
      inline: [{ name: 'worker', document: P([A('sts:AssumeRole', arn('data-etl')), A(['logs:CreateLogStream', 'logs:PutLogEvents']), A(['ecs:RunTask', 'ecs:StopTask'])]) }], attached: [],
      principals: [{ key: 'svc:ecs-tasks', type: 'Service', invokedBy: 'ecs-tasks.amazonaws.com', hours: [1, 2, 3], sessions: 'worker' }],
      usage: [{ p: 'svc:ecs-tasks', src: 'logs.amazonaws.com', name: 'CreateLogStream', perHour: 1 }],
      advisor: { logs: 0, ecs: 400, sts: 0 } },
    { name: 'lake-reader', path: '/', kind: 'custom',
      trust: P([{ Effect: 'Allow', Action: 'sts:AssumeRole', Principal: { AWS: arn('data-etl') }, Condition: { StringEquals: { 'aws:PrincipalTag/team': 'data' } } },
        ...alsoFrom([{ Effect: 'Allow', Action: 'sts:AssumeRole', Principal: { AWS: `arn:aws:iam::${sib}:role/data-etl` } }]),
        ...(acct === '111111111111' ? [{ Effect: 'Allow', Action: 'sts:AssumeRoleWithWebIdentity', Principal: { Federated: 'accounts.google.com' },
          Condition: { StringEquals: { 'accounts.google.com:aud': GCP_EXPORTER_ID, 'accounts.google.com:sub': GCP_EXPORTER_ID } } }] : [])]),
      inline: [{ name: 'lake', document: P([A(['s3:GetObject', 's3:ListBucket', 's3:DeleteObject', 's3:GetIntelligentTieringConfiguration'], ['arn:aws:s3:::acme-lake', 'arn:aws:s3:::acme-lake/*'])]) }], attached: [],
      principals: [{ key: 'role:data-etl', type: 'AssumedRole', arn: `arn:aws:sts::${acct}:assumed-role/data-etl/dag`, hours: [2], sessions: 'lake', viaRole: 'data-etl', viaPr: 'role:airflow-worker' }],
      // S3 logs ListBucketIntelligentTieringConfigurations, but the permission is s3:GetIntelligentTieringConfiguration:
      // an event name that does not match an IAM action and has to be identified
      usage: [{ p: 'role:data-etl', src: 's3.amazonaws.com', name: 'ListObjects', perHour: 2, res: 'arn:aws:s3:::acme-lake' },
              { p: 'role:data-etl', src: 's3.amazonaws.com', name: 'ListBucketIntelligentTieringConfigurations', perHour: 1, res: 'arn:aws:s3:::acme-lake' }],
      advisor: { s3: 0 } },
  ];
  return roles.map((r) => ({ ...r, arn: arn(r.name, r.path) }));
}

// IAM users: long-lived identities with access keys and console passwords. Each one shows something worth watching:
// an old CI key still in daily use, an admin who signs in to the console (with MFA), a reporting key nobody has used
// in years, and (staging only) a vendor with a console password and no MFA.
const keyId = (acct, user, n) => `AKIA${crypto.createHash('sha1').update(`${acct}${user}${n}`).digest('hex').slice(0, 16).toUpperCase()}`;
export function buildUsers(acct) {
  const arn = (name) => `arn:aws:iam::${acct}:user/${name}`;
  const users = [
    { name: 'ci-legacy', createdDaysAgo: 700, groups: [],
      inline: [{ name: 'deploy', document: P([A(['ecr:GetAuthorizationToken', 'ecr:PutImage', 'ecr:BatchCheckLayerAvailability', 'ecs:UpdateService', 'ecs:DescribeServices', 'ecs:RegisterTaskDefinition']), A('iam:PassRole', `arn:aws:iam::${acct}:role/payments-task-exec`)]) }],
      attached: [],
      keys: [{ id: keyId(acct, 'ci-legacy', 1), status: 'Active', createdDaysAgo: 420, lastUsedHoursAgo: 1, service: 'ecr' }, { id: keyId(acct, 'ci-legacy', 2), status: 'Inactive', createdDaysAgo: 650, lastUsedHoursAgo: 24 * 400, service: 'ecs' }],
      usage: [{ key: 1, src: 'ecr.amazonaws.com', name: 'GetAuthorizationToken', hours: [2, 8, 14, 20] }, { key: 1, src: 'ecs.amazonaws.com', name: 'DescribeServices', hours: [2, 8, 14, 20] }] },
    { name: 'snapshot-bot', createdDaysAgo: 120, groups: [],
      inline: [{ name: 'snapshots', document: P([A(['ec2:CreateSnapshot', 'ec2:DescribeVolumes', 'ec2:DescribeSnapshots', 'ec2:DeleteSnapshot'])]) }], attached: [],
      keys: [{ id: keyId(acct, 'snapshot-bot', 1), status: 'Active', createdDaysAgo: 40, lastUsedHoursAgo: 3, service: 'ec2' }],
      usage: [{ key: 1, src: 'ec2.amazonaws.com', name: 'DescribeVolumes', hours: [1, 13] }, { key: 1, src: 'ec2.amazonaws.com', name: 'CreateSnapshot', hours: [1] }] },
    { name: 'old-reporting', createdDaysAgo: 900, groups: [],
      inline: [{ name: 'metrics', document: P([A(['cloudwatch:GetMetricData', 'cloudwatch:ListMetrics'])]) }], attached: [],
      keys: [{ id: keyId(acct, 'old-reporting', 1), status: 'Active', createdDaysAgo: 800, lastUsedHoursAgo: null }], usage: [] },
  ];
  if (acct === '111111111111') users.push({ name: 'alice.admin', createdDaysAgo: 500, groups: ['Admins'], inline: [], attached: [],
    groupPolicies: { Admins: { attached: ['arn:aws:iam::aws:policy/AdministratorAccess'], inline: [] } },
    password: { createdDaysAgo: 500, lastUsedDaysAgo: 3 }, mfa: [{ serial: `arn:aws:iam::${acct}:mfa/alice.admin`, type: 'virtual' }], keys: [], usage: [] });
  if (acct === '222222222222') users.push({ name: 'vendor-sync', createdDaysAgo: 260, groups: ['Vendors'], inline: [], attached: [],
    groupPolicies: { Vendors: { attached: ['arn:aws:iam::aws:policy/ReadOnlyAccess'], inline: [] } },
    password: { createdDaysAgo: 260, lastUsedDaysAgo: 140 }, mfa: [],
    keys: [{ id: keyId(acct, 'vendor-sync', 1), status: 'Active', createdDaysAgo: 200, lastUsedHoursAgo: 5, service: 'ec2' }],
    usage: [{ key: 1, src: 'ec2.amazonaws.com', name: 'DescribeInstances', hours: [4, 16] }] });
  return users.map((u) => ({ ...u, arn: arn(u.name), userId: `AIDA${crypto.createHash('sha1').update(`${acct}${u.name}`).digest('hex').slice(0, 17).toUpperCase()}` }));
}
