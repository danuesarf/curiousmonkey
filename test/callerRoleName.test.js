// A caller that is a role session is named after its role, whichever ARN CloudTrail gives: the session ARN, or the
// role's own ARN (the target account's copy of a cross-account AssumeRole), IAM Identity Center roles included.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { principalFrom } from '../src/scanner/applyEvents.js';
import { parseEvent } from '../src/analyzer/events.js';
import { roleOfCallerArn, matchTrust } from '../src/analyzer/trust.js';

const SSO = 'arn:aws:iam::111122223333:role/aws-reserved/sso.amazonaws.com/ap-southeast-1/AWSReservedSSO_AdministratorAccess_0123456789abcdef';
const assume = (userIdentity) => parseEvent({ eventID: 'e1', eventTime: '2026-11-20T17:00:00Z', awsRegion: 'ap-southeast-1', eventSource: 'sts.amazonaws.com', eventName: 'AssumeRole',
  requestParameters: { roleArn: 'arn:aws:iam::444455556666:role/AWSControlTowerExecution', roleSessionName: 'dana@acme.example' }, responseElements: { credentials: { accessKeyId: 'ASIAEXAMPLE0001' } }, userIdentity });

test('the role a caller ARN names: a session, or the role itself with its path', () => {
  assert.deepEqual(roleOfCallerArn('arn:aws:sts::111122223333:assumed-role/Deployer/ci-run'), { account: '111122223333', name: 'Deployer', roleArn: null });
  assert.deepEqual(roleOfCallerArn(SSO), { account: '111122223333', name: 'AWSReservedSSO_AdministratorAccess_0123456789abcdef', roleArn: SSO });
  assert.equal(roleOfCallerArn('arn:aws:iam::111122223333:user/ana'), null);
});

test('an Identity Center session with no session ARN in the record is named after its role, not "undefined"', () => {
  const e = assume({ type: 'AssumedRole', principalId: 'AROAEXAMPLE000000001:dana@acme.example', accountId: '111122223333',
    sessionContext: { sessionIssuer: { type: 'Role', arn: SSO, userName: 'AWSReservedSSO_AdministratorAccess_0123456789abcdef', accountId: '111122223333' } } });
  const p = principalFrom(e);
  assert.equal(p.key, 'role:111122223333:AWSReservedSSO_AdministratorAccess_0123456789abcdef');
  assert.equal(p.display, 'role/AWSReservedSSO_AdministratorAccess_0123456789abcdef (111122223333)');
  assert.ok(!/undefined/.test(p.display));
  // the usual record (with the session ARN) gives the same caller
  const usual = principalFrom(assume({ type: 'AssumedRole', arn: 'arn:aws:sts::111122223333:assumed-role/AWSReservedSSO_AdministratorAccess_0123456789abcdef/dana@acme.example',
    principalId: 'AROAEXAMPLE000000001:dana@acme.example', accountId: '111122223333' }));
  assert.equal(usual.key, p.key);
  // nothing to name it by but its unique ID
  const bare = principalFrom(assume({ type: 'AssumedRole', principalId: 'AROAEXAMPLE000000001:dana@acme.example', accountId: '111122223333' }));
  assert.deepEqual([bare.key, bare.kind], ['acct:111122223333:AROAEXAMPLE000000001', 'account']);
});

test('the trust policy is matched for such a caller: the role by ARN, path included', () => {
  const doc = { Version: '2012-10-17', Statement: [{ Effect: 'Allow', Principal: { AWS: SSO }, Action: 'sts:AssumeRole' }] };
  const e = assume({ type: 'AssumedRole', principalId: 'AROAEXAMPLE000000001:dana@acme.example', accountId: '111122223333', sessionContext: { sessionIssuer: { arn: SSO } } });
  const m = matchTrust(doc, e.caller);
  assert.ok(m, 'matched');
});
