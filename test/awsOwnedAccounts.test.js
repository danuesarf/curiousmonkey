// Accounts AWS runs for its own services (ELB access-log delivery, Redshift logging…) are the service, not an outsider.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { analyzeResource, accessText } from '../src/analyzer/resourcePolicy.js';
import { knownVendor } from '../src/trustmap.js';

const OWN = '111122223333', ELB = '114774131450';   // ELB = the published us-east-1 ELB log-delivery account
const estate = { connected: new Map([[OWN, 'demo-prod']]), org: new Map(), orgIds: new Set(), vendor: knownVendor };
const run = (statements) => analyzeResource({ service: 's3', arn: 'arn:aws:s3:::demo-alb-logs', name: 'demo-alb-logs', accountId: OWN, policy: { Statement: statements } }, estate);
const one = (r) => r.findings.map((f) => `${f.control}:${f.severity}`).sort();

test('the ELB log-delivery account writing under this account\'s own prefix: an AWS service, no finding', () => {
  const r = run([{ Effect: 'Allow', Principal: { AWS: `arn:aws:iam::${ELB}:root` }, Action: 's3:PutObject', Resource: `arn:aws:s3:::demo-alb-logs/alb/AWSLogs/${OWN}/*` }]);
  assert.equal(r.exposure, 'service');
  assert.deepEqual(one(r), []);
  assert.equal(r.grants[0].reach, 'service'); assert.equal(r.grants[0].awsOwned, true);
  assert.equal(r.grants[0].accountName, 'ELB logs (AWS)');
  assert.equal(r.grants[0].accessText, 'write into it, not read it');
});

test('the same account on the whole bucket: medium, worded as log delivery, not high as an outsider', () => {
  const r = run([{ Effect: 'Allow', Principal: { AWS: `arn:aws:iam::${ELB}:root` }, Action: 's3:PutObject', Resource: 'arn:aws:s3:::demo-alb-logs/*' }]);
  assert.equal(r.exposure, 'service');
  assert.deepEqual(one(r), ['res.service-no-source:medium']);
  assert.match(r.findings[0].title, /ELB logs \(AWS\) account 114774131450/);
  assert.match(r.findings[0].detail, /write into it, not read it/);
  assert.match(r.findings[0].suggestion, new RegExp(`AWSLogs/${OWN}/`));
});

test('an aws:SourceAccount condition also scopes it', () => {
  const r = run([{ Effect: 'Allow', Principal: { AWS: ELB }, Action: 's3:PutObject', Resource: 'arn:aws:s3:::demo-alb-logs/*', Condition: { StringEquals: { 'aws:SourceAccount': OWN } } }]);
  assert.deepEqual(one(r), []);
});

test('a third-party vendor is still an outsider; reads still read', () => {
  const r = analyzeResource({ service: 's3', arn: 'arn:x', name: 'x', accountId: OWN, policy: { Statement: [{ Effect: 'Allow', Principal: { AWS: 'arn:aws:iam::999988887777:root' }, Action: 's3:PutObject' }] } },
    { ...estate, vendor: (a) => (a === '999988887777' ? 'Some vendor' : null) });
  assert.deepEqual(one(r), ['res.external-account:high']);
  assert.equal(accessText(['s3:GetObject', 's3:PutObject'], 'data'), 'read or change what it holds');
});
