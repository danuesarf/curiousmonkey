import { test } from 'node:test';
import assert from 'node:assert/strict';
import { globMatch, isSubsetGlob } from '../src/analyzer/wildcard.js';
import { eventToAction } from '../src/analyzer/actionNames.js';
import { parseEvent } from '../src/analyzer/events.js';
import { matchTrust } from '../src/analyzer/trust.js';
import { analyze } from '../src/analyzer/analyze.js';
import { expandAction, catalogInfo } from '../src/analyzer/catalog.js';

test('glob matching', () => {
  assert.ok(globMatch('s3:Get*', 's3:GetObject', { ci: true }));
  assert.ok(globMatch('*', 'anything'));
  assert.ok(!globMatch('s3:Put*', 's3:GetObject'));
  assert.ok(globMatch('ec2:Describe?nstances', 'ec2:DescribeInstances'));
});

test('subset check is sound', () => {
  assert.ok(isSubsetGlob('s3:GetObject', 's3:Get*'));
  assert.ok(isSubsetGlob('s3:Get*', 's3:*'));
  assert.ok(isSubsetGlob('arn:aws:s3:::b/logs/*', 'arn:aws:s3:::b/*'));
  assert.ok(!isSubsetGlob('s3:*', 's3:Get*'));
  assert.ok(!isSubsetGlob('arn:aws:s3:::b/*', 'arn:aws:s3:::b/logs/*'));
  assert.ok(!isSubsetGlob('*', 's3:*'));
  assert.ok(isSubsetGlob('abc', '*'));
  assert.ok(!isSubsetGlob('a?c', 'abc'));
});

test('catalog expands wildcards', () => {
  assert.ok(catalogInfo.services > 400);
  const g = expandAction('s3:GetObject*');
  assert.ok(g.includes('s3:GetObject') && g.includes('s3:GetObjectAcl'));
  assert.ok(expandAction('*').length > 20000);
});

test('event names map to IAM actions', () => {
  assert.equal(eventToAction('s3.amazonaws.com', 'ListBuckets'), 's3:ListAllMyBuckets');
  assert.equal(eventToAction('monitoring.amazonaws.com', 'PutMetricData'), 'cloudwatch:PutMetricData');
  assert.equal(eventToAction('lambda.amazonaws.com', 'GetFunction20150331v2'), 'lambda:GetFunction');
  assert.equal(eventToAction('ec2.amazonaws.com', 'DescribeInstances'), 'ec2:DescribeInstances');
  assert.equal(eventToAction('apigateway.amazonaws.com', 'GetRestApis'), 'apigateway:GET');
});

const ROLE = 'arn:aws:iam::111111111111:role/app';
const rec = (o) => ({ eventID: 'e' + Math.random(), eventTime: '2026-10-01T00:00:00Z', awsRegion: 'us-east-1', sourceIPAddress: '1.2.3.4', ...o });

test('parses an API call made by a role session and detects PassRole', () => {
  const e = parseEvent(rec({
    eventSource: 'ec2.amazonaws.com', eventName: 'RunInstances',
    userIdentity: { type: 'AssumedRole', arn: 'arn:aws:sts::111111111111:assumed-role/app/sess', accessKeyId: 'ASIA1', sessionContext: { sessionIssuer: { arn: ROLE } } },
    requestParameters: { iamInstanceProfile: { arn: 'arn:aws:iam::111111111111:role/ec2-worker' } },
  }));
  assert.equal(e.type, 'api'); assert.equal(e.action, 'ec2:RunInstances');
  assert.deepEqual(e.passedRoles, ['arn:aws:iam::111111111111:role/ec2-worker']);
});

test('denied calls are marked', () => {
  const e = parseEvent(rec({ eventSource: 's3.amazonaws.com', eventName: 'ListBuckets', errorCode: 'AccessDenied',
    userIdentity: { type: 'AssumedRole', sessionContext: { sessionIssuer: { arn: ROLE } } } }));
  assert.equal(e.denied, true);
});

const TRUST = { Statement: [{ Effect: 'Allow', Action: 'sts:AssumeRole', Principal: { AWS: 'arn:aws:iam::222222222222:root' },
  Condition: { StringEquals: { 'sts:ExternalId': 'abc' }, Bool: { 'aws:MultiFactorAuthPresent': 'true' } } }] };

test('trust match reports the conditions the caller met', () => {
  const m = matchTrust(TRUST, { accountId: '222222222222', arn: 'arn:aws:iam::222222222222:user/dhimas', type: 'IAMUser' });
  assert.ok(m.matched);
  assert.deepEqual(m.conditions, ['sts:ExternalId StringEquals abc', 'aws:MultiFactorAuthPresent Bool true']);
  assert.ok(!matchTrust(TRUST, { accountId: '999999999999', arn: 'arn:aws:iam::999999999999:user/x' }).matched);
});

const policy = (actions, resource = '*') => ({ name: 'p', kind: 'inline', document: { Statement: [{ Effect: 'Allow', Action: actions, Resource: resource }] } });
const WIN = new Date('2026-08-01T00:00:00Z');
const base = (over) => ({ role: { arn: ROLE, kind: 'custom', trust_policy: TRUST, last_used_at: '2026-10-30T00:00:00Z' }, windowStart: WIN, now: new Date('2026-11-01'),
  activity: { actions: new Map(), passroles: [], principals: [] }, advisor: [], ...over });

test('used / unused / unconfirmed are separated and never mixed up', () => {
  const r = analyze(base({
    policies: [policy(['s3:GetObject', 's3:ListBucket', 'ec2:DescribeInstances', 'ec2:TerminateInstances', 'iam:PassRole'])],
    activity: { actions: new Map([['s3:ListBucket', { count: 5, lastSeen: '2026-10-30' }]]), passroles: [], principals: [] },
  }));
  const by = Object.fromEntries(r.actions.map((a) => [a.action, a]));
  assert.equal(by['s3:ListBucket'].status, 'used');
  assert.equal(by['s3:GetObject'].status, 'unconfirmed'); assert.equal(by['s3:GetObject'].reason, 'data-event');
  assert.equal(by['iam:PassRole'].status, 'unconfirmed'); assert.equal(by['iam:PassRole'].reason, 'authorization-only');
  assert.equal(by['ec2:TerminateInstances'].status, 'unused');
  assert.ok(r.flags.some((f) => f.category === 'data-event' && f.key === 's3'));
});

test('PassRole is used when a passed role was seen', () => {
  const r = analyze(base({ policies: [policy(['iam:PassRole'])],
    activity: { actions: new Map(), passroles: [{ arn: 'arn:aws:iam::1:role/x', service: 'ec2', count: 3 }], principals: [] } }));
  assert.equal(r.actions[0].status, 'used');
});

test('access advisor splits before-window from service-unknown', () => {
  const r = analyze(base({ policies: [policy(['sqs:ListQueues', 'sns:ListTopics', 'ecs:ListClusters'])],
    advisor: [{ service: 'sqs', lastAuthenticated: '2026-05-01' }, { service: 'sns', lastAuthenticated: '2026-10-20' }] }));
  const by = Object.fromEntries(r.actions.map((a) => [a.action, a]));
  assert.equal(by['sqs:ListQueues'].reason, 'before-window');
  assert.equal(by['sns:ListTopics'].reason, 'service-unknown');
  assert.equal(by['ecs:ListClusters'].status, 'unused');
});

test('admin role is High risk and flagged as wildcard', () => {
  const r = analyze(base({ policies: [policy('*')] }));
  assert.equal(r.risk, 'High'); assert.equal(r.requiresBoth, true);
  assert.ok(r.flags.some((f) => f.category === 'wildcard'));
});

test('SSO roles go to Information Security, service-linked to Infrastructure Security', () => {
  const sso = analyze(base({ role: { arn: ROLE, kind: 'identity-center', trust_policy: {}, last_used_at: '2026-10-30' }, policies: [policy(['ec2:DescribeInstances'])] }));
  assert.equal(sso.reviewerTeam, 'infosec');
  const slr = analyze(base({ role: { arn: ROLE, kind: 'service-linked', trust_policy: {}, last_used_at: '2026-10-30' }, policies: [policy(['ec2:DescribeInstances'])] }));
  assert.equal(slr.reviewerTeam, 'infrasec');
});

test('principal not named in trust policy is flagged', () => {
  const r = analyze(base({ policies: [policy(['ec2:DescribeInstances'])],
    activity: { actions: new Map(), passroles: [], principals: [{ key: 'u', display: 'user/x', kind: 'user', via: 'sts:AssumeRole', trust: { matched: false } }] } }));
  assert.ok(r.flags.some((f) => f.category === 'external-principal'));
});

test('analysis hash is stable and changes with the data', () => {
  const a = analyze(base({ policies: [policy(['ec2:DescribeInstances'])] }));
  const b = analyze(base({ policies: [policy(['ec2:DescribeInstances'])] }));
  const c = analyze(base({ policies: [policy(['ec2:DescribeInstances', 'ec2:RunInstances'])] }));
  assert.equal(a.analysisHash, b.analysisHash); assert.notEqual(a.analysisHash, c.analysisHash);
});

// ---------------------------------------------------------------- severities
import { gapSeverity, wildcardSeverity } from '../src/analyzer/analyze.js';
import { privilegeTier, isDataRead } from '../src/analyzer/sensitive.js';
const sevOf = (r, cat, key) => r.flags.find((f) => f.category === cat && (!key || f.key === key))?.severity;

test('an evidence gap is never high: the KMS case, data events, SQS, PassRole', () => {
  // KMS used through another service: Access Advisor says used, no event names the action
  const kms = analyze(base({ policies: [policy(['kms:Decrypt', 'kms:GenerateDataKey', 'kms:DescribeKey'], 'arn:aws:kms:ap-southeast-3:1:key/k')],
    advisor: [{ service: 'kms', lastAuthenticated: '2026-10-20' }] }));
  assert.equal(sevOf(kms, 'service-unknown', 'kms'), 'low');
  // the same gap with the right to hand the key to others: worth a reviewer's look, still not high
  const grant = analyze(base({ policies: [policy(['kms:Decrypt', 'kms:CreateGrant'])], advisor: [{ service: 'kms', lastAuthenticated: '2026-10-20' }] }));
  assert.equal(sevOf(grant, 'service-unknown', 'kms'), 'medium');
  // data events: one bucket low; writes to every bucket medium; reads of every bucket low
  assert.equal(sevOf(analyze(base({ policies: [policy(['s3:PutObject', 's3:DeleteObject'], 'arn:aws:s3:::one/*')] })), 'data-event'), 'low');
  assert.equal(sevOf(analyze(base({ policies: [policy(['s3:PutObject'])] })), 'data-event'), 'medium');
  assert.equal(sevOf(analyze(base({ policies: [policy(['s3:GetObject'])] })), 'data-event'), 'low');
  // nothing can ever confirm SQS messages
  assert.equal(sevOf(analyze(base({ policies: [policy(['sqs:SendMessage', 'sqs:DeleteMessage'])] })), 'not-logged'), 'low');
  // PassRole: every role medium, named roles low; session tags low
  assert.equal(sevOf(analyze(base({ policies: [policy(['iam:PassRole'])] })), 'authorization-only'), 'medium');
  assert.equal(sevOf(analyze(base({ policies: [policy(['iam:PassRole'], 'arn:aws:iam::1:role/app-*')] })), 'authorization-only'), 'low');
  assert.equal(sevOf(analyze(base({ policies: [policy(['sts:TagSession'])] })), 'authorization-only'), 'low');
  for (const cat of ['data-event', 'authorization-only', 'not-logged', 'before-window', 'service-unknown', 'unmapped-event']) {
    assert.notEqual(gapSeverity(cat, [{ action: 'iam:PutRolePolicy', level: 'Write', resources: ['*'] }]), 'high', cat);
  }
  assert.equal(privilegeTier('iam:AttachRolePolicy'), 'identity'); assert.equal(privilegeTier('kms:PutKeyPolicy'), 'resource');
  assert.equal(privilegeTier('logs:PutLogEvents'), null); assert.ok(isDataRead('secretsmanager:GetSecretValue') && !isDataRead('s3:GetBucketPolicy'));
});

test('wildcards are rated by what they expand to; NotAction is flagged', () => {
  assert.equal(wildcardSeverity('*'), 'high');
  assert.equal(wildcardSeverity('iam:*'), 'high'); assert.equal(wildcardSeverity('iam:Put*'), 'high'); assert.equal(wildcardSeverity('organizations:*'), 'high');
  assert.equal(wildcardSeverity('s3:*'), 'medium'); assert.equal(wildcardSeverity('ec2:*'), 'medium'); assert.equal(wildcardSeverity('s3:Get*'), 'medium');   // reads every object
  assert.equal(wildcardSeverity('ec2:Describe*'), 'low'); assert.equal(wildcardSeverity('iam:Get*'), 'low'); assert.equal(wildcardSeverity('iam:List*'), 'low');
  assert.equal(wildcardSeverity('nosuchservice:*'), 'medium');
  assert.equal(wildcardSeverity('*', { kind: 'service-linked' }), 'low');                       // AWS owns that policy
  const na = (not) => analyze(base({ policies: [{ name: 'p', kind: 'inline', document: { Statement: [{ Effect: 'Allow', NotAction: not, Resource: '*' }] } }] }));
  assert.equal(na(['s3:DeleteBucket']).flags.find((f) => f.key.startsWith('NotAction:')).severity, 'high');
  assert.equal(na(['iam:*', 'organizations:*']).flags.find((f) => f.key.startsWith('NotAction:')).severity, 'medium');   // PowerUser-like
  // read-only wildcards add nothing to the score; identity-plane ones add 20
  const ro = analyze(base({ policies: [policy(['ec2:Describe*'])], activity: { actions: new Map([['ec2:DescribeInstances', { count: 1, lastSeen: '2026-10-30' }]]), passroles: [], principals: [] } }));
  assert.ok(!ro.riskReasons.some((x) => /wildcard/.test(x)));
  assert.ok(analyze(base({ policies: [policy(['iam:*'])] })).riskReasons.some((x) => /wildcard/.test(x)));
});

test('an idle role is rated by what it could do; a new role is not idle yet', () => {
  const idle = (policies, role = {}) => analyze(base({ policies, role: { arn: ROLE, kind: 'custom', trust_policy: TRUST, last_used_at: null, ...role } }));
  assert.equal(sevOf(idle([policy(['ec2:DescribeInstances', 's3:ListAllMyBuckets'])]), 'role-idle'), 'low');
  assert.equal(sevOf(idle([policy(['ec2:TerminateInstances'])]), 'role-idle'), 'medium');
  assert.equal(sevOf(idle([policy(['*'])]), 'role-idle'), 'high');
  assert.equal(sevOf(idle([policy(['iam:AttachRolePolicy'], 'arn:aws:iam::1:role/x')]), 'role-idle'), 'high');
  assert.equal(sevOf(idle([policy(['*'])], { kind: 'service-linked' }), 'role-idle'), 'low');
  assert.equal(sevOf(idle([policy(['ec2:DescribeInstances'])], { trust_policy: { Statement: [{ Effect: 'Allow', Principal: '*', Action: 'sts:AssumeRole' }] } }), 'role-idle'), 'high');
  assert.equal(sevOf(idle([policy(['*'])], { created_in_aws: '2026-10-25T00:00:00Z' }), 'role-idle'), undefined);       // 7 days old
  assert.equal(sevOf(idle([policy(['*'])], { created_in_aws: '2026-09-01T00:00:00Z' }), 'role-idle'), 'high');
});

test('a role anyone can assume is High whatever it grants', () => {
  const r = analyze(base({ policies: [policy(['ec2:DescribeInstances'])], role: { arn: ROLE, kind: 'custom', last_used_at: '2026-10-30T00:00:00Z', trust_policy: { Statement: [{ Effect: 'Allow', Principal: '*', Action: 'sts:AssumeRole' }] } },
    activity: { actions: new Map([['ec2:DescribeInstances', { count: 1, lastSeen: '2026-10-30' }]]), passroles: [], principals: [] } }));
  assert.equal(r.risk, 'High');
});
