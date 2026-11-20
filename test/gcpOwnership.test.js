// Whose is a Google Cloud identity: Google's own service accounts, your projects that no connection reads, default
// service accounts named by number, your domains, and one way in per wide grant. Made-up names only.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseMember } from '../src/gcp/analyze.js';
import { makeOwnership, projectOfServiceAccount } from '../src/gcp/ownership.js';
import { groupOf, collapseWide } from '../src/gcp/trust.js';
import { analyzeGcpResource } from '../src/gcp/resources.js';

const sa = (email) => `serviceAccount:${email}`;

test('Google-owned service accounts, Firebase\'s exporters included, are service agents; look-alikes are not', () => {
  for (const e of ['crashlytics-exporter@crashlytics-bigquery-prod.iam.gserviceaccount.com', 'exporter@fcm-bq-export-prod.iam.gserviceaccount.com',
    'exporter@performance-bq-export-prod.iam.gserviceaccount.com', 'firebase-measurement@system.gserviceaccount.com', 'service-123@gcp-sa-pubsub.iam.gserviceaccount.com',
    'bq-123@bigquery-encryption.iam.gserviceaccount.com', '123@cloudbuild.gserviceaccount.com', 'x@some-api.google.com.iam.gserviceaccount.com'])
    assert.equal(parseMember(sa(e)).managed, true, e);
  for (const e of ['exporter@lookalike-bq-export-prod.iam.gserviceaccount.com', 'crashlytics-exporter@acme-data.iam.gserviceaccount.com', 'deployer@acme-ci.iam.gserviceaccount.com'])
    assert.equal(parseMember(sa(e)).managed, false, e);
});

test('the project a service account lives in: by ID, App Engine default, Compute Engine default by number', () => {
  assert.equal(projectOfServiceAccount('deployer@acme-ci.iam.gserviceaccount.com'), 'acme-ci');
  assert.equal(projectOfServiceAccount('acme-web@appspot.gserviceaccount.com'), 'acme-web');
  assert.equal(projectOfServiceAccount('400000000001-compute@developer.gserviceaccount.com'), '400000000001');
  assert.deepEqual([parseMember(sa('acme-web@appspot.gserviceaccount.com')).project, parseMember(sa('400000000001-compute@developer.gserviceaccount.com')).projectNumber], ['acme-web', '400000000001']);
});

const own = makeOwnership({
  read: [{ project_id: 'acme-data', number: '400000000001' }, { project_id: 'acme-ci', number: '400000000002' }],
  seen: [{ project_id: 'acme-tools', number: '400000000003', organization: 'organizations/1' }, { project_id: 'vendor-x', number: '500000000001', organization: 'organizations/9' }],
  organizations: ['organizations/1'], patterns: ['acme-legacy-*', '400000000099'], domains: ['acme.example'],
});

test('whose a project is: read by a connection, yours (seen under your organization, or listed), or not', () => {
  assert.equal(own.project('acme-data'), 'read');
  assert.equal(own.project('400000000002'), 'read');                 // by number
  assert.equal(own.project('acme-tools'), 'yours');                  // the reader sees it under your organization
  assert.equal(own.project('acme-legacy-terraform'), 'yours');       // a pattern
  assert.equal(own.project('400000000099'), 'yours');                // a number on the list
  assert.equal(own.project('vendor-x'), null);                       // seen, but under someone else's organization
  assert.equal(own.project('partner-prod-1'), null);
  assert.deepEqual([own.inDomain('ana@acme.example'), own.inDomain('ana@eu.acme.example'), own.inDomain('x@gmail.com')], [true, true, false]);
  assert.equal(makeOwnership({}).inDomain('x@gmail.com'), null, 'no domain known: cannot tell');
});

test('ways in: your unread project is yours, Google\'s exporters are yours, a partner is outside, a foreign default service account is outside', () => {
  const from = (member, projects = new Set(['acme-data'])) => groupOf({ kind: member.startsWith('serviceAccount:') ? 'serviceAccount' : member.split(':')[0], member }, own, projects);
  assert.equal(from(sa('deployer@acme-ci.iam.gserviceaccount.com')), 'org');                  // another connection reads it
  assert.equal(from(sa('terraform@acme-legacy-terraform.iam.gserviceaccount.com')), 'own');
  assert.equal(from(sa('rotator@acme-tools.iam.gserviceaccount.com')), 'own');
  assert.equal(from(sa('crashlytics-exporter@crashlytics-bigquery-prod.iam.gserviceaccount.com')), 'org');
  assert.equal(from(sa('events@partner-prod-1.iam.gserviceaccount.com')), 'other-org');
  assert.equal(from(sa('500000000001-compute@developer.gserviceaccount.com')), 'other-org');   // vendor-x's default, by number
  assert.equal(from(sa('400000000002-compute@developer.gserviceaccount.com')), 'org');
  assert.equal(from(sa('vendor-x@appspot.gserviceaccount.com')), 'other-org');
  assert.equal(from('user:vendor@gmail.com'), 'external');
  assert.equal(from('user:ana@acme.example'), 'org');
  assert.equal(groupOf({ kind: 'user', member: 'user:vendor@gmail.com' }, makeOwnership({})), 'org', 'no domain known: not called outside');
});

test('one grant on a whole project is one way in, listing the service accounts it reaches', () => {
  const w = (target, extra = {}) => ({ connectionId: 'c', member: 'serviceAccount:terraform@acme-legacy-terraform.iam.gserviceaccount.com', label: 'terraform', via: 'actAs', role: 'roles/iam.serviceAccountUser',
    at: { type: 'project', label: 'project acme-data' }, wide: true, worst: 'medium', findings: [{ id: 'wide-impersonation', severity: 'medium' }],
    target: { kind: 'serviceAccount', id: target, label: `${target}@acme-data.iam.gserviceaccount.com`, project: 'acme-data' }, ...extra });
  const out = collapseWide([w('a'), w('b'), w('c', { worst: 'high' }), w('d', { wide: false, at: { type: 'serviceAccount', label: 'the service account itself' } })]);
  assert.equal(out.length, 2);
  const scope = out.find((x) => x.target.kind === 'scope');
  assert.deepEqual([scope.count, scope.worst, scope.target.label, scope.target.members.map((m) => m.id)], [3, 'high', '3 service accounts in project acme-data', ['a', 'b', 'c']]);
  assert.equal(collapseWide([w('a')])[0].target.kind, 'serviceAccount', 'one alone stays as it is');
});

test('resource-level IAM follows the same rule: your unread project is yours, an unknown domain is not called outside', () => {
  const bucket = (members) => ({ service: 'gcs', type: 'bucket', arn: '//storage.googleapis.com/b', name: 'b', project_id: 'acme-data', policy: { bindings: [{ role: 'roles/storage.objectViewer', members }] } });
  const estate = { projects: new Set(['acme-data']), otherProjects: new Set(['acme-ci']), own, providers: [], awsAccounts: new Map() };
  const exp = (m, e = estate) => analyzeGcpResource(bucket([m]), e).exposure;
  assert.equal(exp(sa('terraform@acme-legacy-terraform.iam.gserviceaccount.com')), 'cross-account');
  assert.equal(exp(sa('events@partner-prod-1.iam.gserviceaccount.com')), 'external');
  assert.equal(exp(sa('500000000001-compute@developer.gserviceaccount.com')), 'external', 'another company\'s default service account is not a Google service');
  assert.equal(exp(sa('exporter@fcm-bq-export-prod.iam.gserviceaccount.com')), 'service');
  assert.equal(exp('user:vendor@gmail.com'), 'external');
  assert.equal(exp('user:vendor@gmail.com', { ...estate, own: makeOwnership({}) }), 'private', 'no domain known: no finding');
});
