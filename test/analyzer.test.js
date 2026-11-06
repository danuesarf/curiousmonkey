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
