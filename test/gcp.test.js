import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { startPg } from './helpers/pg.js';
import { parseMember, federatedOrigin, analyzeGcp, googleTrustsOf } from '../src/gcp/analyze.js';
import { gcpSnippets, awsRoleOf } from '../src/gcp/onboarding.js';

process.env.AWS_MODE = 'demo'; process.env.LOOKUP_DELAY_MS = '0';

// ---------------------------------------------------------------- pure parts
test('members: every kind IAM writes is recognised', () => {
  assert.equal(parseMember('allUsers').kind, 'public');
  assert.equal(parseMember('user:a@x.io').kind, 'user');
  assert.equal(parseMember('deleted:serviceAccount:x@p.iam.gserviceaccount.com?uid=1').kind, 'deleted');
  const g = parseMember('serviceAccount:prj.svc.id.goog[ns/ksa]');
  assert.deepEqual([g.kind, g.namespace, g.ksa], ['gke', 'ns', 'ksa']);
  const d = parseMember('serviceAccount:123-compute@developer.gserviceaccount.com');
  assert.ok(d.isDefault);
  assert.ok(parseMember('serviceAccount:service-123@gcp-sa-pubsub.iam.gserviceaccount.com').managed);
  const f = parseMember('principalSet://iam.googleapis.com/projects/42/locations/global/workloadIdentityPools/aws/attribute.aws_role/arn:aws:sts::111111111111:assumed-role/etl');
  assert.deepEqual([f.kind, f.pool, f.projectNumber], ['federated', 'aws', '42']);
});

test('federation: the AWS account and role behind a federated identity; a pool with no condition is broad', () => {
  const providers = [{ pool_id: 'aws', project_number: '42', provider_id: 'a', type: 'aws', aws_account_id: '111111111111', attribute_condition: null }];
  const role = federatedOrigin(parseMember('principalSet://iam.googleapis.com/projects/42/locations/global/workloadIdentityPools/aws/attribute.aws_role/arn:aws:sts::111111111111:assumed-role/etl'), providers);
  assert.deepEqual([role.cloud, role.awsAccountId, role.awsRole, role.broad], ['aws', '111111111111', 'etl', false]);
  const whole = federatedOrigin(parseMember('principalSet://iam.googleapis.com/projects/42/locations/global/workloadIdentityPools/aws/*'), providers);
  assert.equal(whole.broad, true); assert.match(whole.label, /any role/);
  const pinned = federatedOrigin(parseMember('principalSet://iam.googleapis.com/projects/42/locations/global/workloadIdentityPools/aws/*'), [{ ...providers[0], attribute_condition: "attribute.aws_role=='x'" }]);
  assert.equal(pinned.broad, false);
});

test('analysis: inheritance from organization and folders, impersonation, keys, default service accounts', () => {
  const sa = (email, project, extra = {}) => ({ email, project_id: project, unique_id: '1', keys: [], disabled: false, ...extra });
  const b = (resource, resource_type, project_id, role, member) => ({ resource, resource_type, project_id, role, member, condition: null });
  const r = analyzeGcp({
    org: { domain: 'acme.example' },
    projects: [{ project_id: 'p1', ancestors: ['folders/1', 'organizations/9'] }, { project_id: 'p2', ancestors: ['folders/2', 'organizations/9'] }],
    roleDefs: new Map([['roles/owner', ['resourcemanager.projects.setIamPolicy', 'iam.serviceAccounts.actAs', 'x.y.z']], ['roles/iam.serviceAccountTokenCreator', ['iam.serviceAccounts.getAccessToken']],
      ['roles/editor', ['iam.serviceAccounts.actAs', 'a.b.c']], ['roles/viewer', ['a.b.get']]]),
    serviceAccounts: [sa('app@p1.iam.gserviceaccount.com', 'p1', { keys: [{ id: 'k', created: new Date(Date.now() - 200 * 864e5).toISOString(), expires: null }] }), sa('1-compute@developer.gserviceaccount.com', 'p2')],
    bindings: [b('organizations/9', 'organization', null, 'roles/owner', 'user:boss@acme.example'),
      b('folders/1', 'folder', null, 'roles/iam.serviceAccountTokenCreator', 'group:ops@acme.example'),
      b('projects/p2', 'project', 'p2', 'roles/editor', 'serviceAccount:1-compute@developer.gserviceaccount.com'),
      b('projects/p1', 'project', 'p1', 'roles/viewer', 'user:friend@gmail.com')],
    providers: [],
  });
  const boss = r.get('user:boss@acme.example');
  assert.deepEqual(boss.reach, ['p1', 'p2']); assert.equal(boss.risk, 'High');
  assert.ok(boss.reasons.some((x) => x.id === 'basic-owner'));
  const ops = r.get('group:ops@acme.example');
  assert.deepEqual(ops.reach, ['p1']);                                                   // folders/1 only
  assert.ok(ops.reasons.some((x) => x.id === 'impersonate-many'));
  const app = r.get('serviceAccount:app@p1.iam.gserviceaccount.com');
  assert.ok(app.sources.some((s) => s.via === 'token' && s.member === 'group:ops@acme.example'));
  assert.ok(app.sources.some((s) => s.via === 'key'));
  assert.ok(app.reasons.some((x) => x.id === 'key' && x.severity === 'medium'));
  assert.equal(r.get('serviceAccount:1-compute@developer.gserviceaccount.com').reasons.find((x) => x.id === 'basic-editor').severity, 'high');
  assert.ok(r.get('user:friend@gmail.com').reasons.some((x) => x.id === 'external'));
});

test('AWS trust policies name Google service accounts by unique ID', () => {
  const t = googleTrustsOf({ Statement: [{ Effect: 'Allow', Principal: { Federated: 'accounts.google.com' }, Action: 'sts:AssumeRoleWithWebIdentity', Condition: { StringEquals: { 'accounts.google.com:aud': '104857600000000000001' } } },
    { Effect: 'Allow', Principal: { Federated: 'accounts.google.com' }, Action: 'sts:AssumeRoleWithWebIdentity' }, { Effect: 'Allow', Principal: { Service: 'ec2.amazonaws.com' } }] });
  assert.deepEqual(t, [{ statement: 0, ids: ['104857600000000000001'], any: false }, { statement: 1, ids: [], any: true }]);
});

test('onboarding: a custom role for organizations and projects, predefined roles for folders, federation pinned to the scanner role', () => {
  const aws = awsRoleOf('arn:aws:sts::111111111111:assumed-role/cm-worker/i-0abc');
  assert.equal(aws.sessionArn, 'arn:aws:sts::111111111111:assumed-role/cm-worker');
  const org = gcpSnippets({ scopeType: 'organization', scopeId: '100000000001', mode: 'wif', home: 'acme-shared-ci', homeNumber: '300000000003', aws });
  const all = org.steps.map((s) => s.code).join('\n');
  assert.match(all, /gcloud iam roles create curiousMonkeyReader --organization=100000000001/);
  assert.match(all, /--attribute-condition="attribute.aws_role=='arn:aws:sts::111111111111:assumed-role\/cm-worker'"/);
  assert.doesNotMatch(all, /setIamPolicy|keys create/);
  const folder = gcpSnippets({ scopeType: 'folder', scopeId: '200000000001', mode: 'key' });
  assert.match(folder.steps.map((s) => s.code).join('\n'), /roles\/iam.securityReviewer[\s\S]*keys create/);
});

// ---------------------------------------------------------------- through the API, with the demo estates
let pg, db, q, w, server, base, totp, gcpScan;
before(async () => {
  pg = await startPg(54361);
  db = await import('../src/db.js');
  await (await import('../src/migrate.js')).migrate(() => {});
  q = await import('../src/queue.js'); w = await import('../src/worker.js'); totp = await import('../src/auth/totp.js'); gcpScan = await import('../src/gcp/scan.js');
  await (await import('../src/settings.js')).refreshSettings();
  const { createApp } = await import('../src/server.js');
  server = createApp().listen(0); base = `http://127.0.0.1:${server.address().port}`;
  await q.registerWorker();
});
after(async () => { server?.close(); await db?.closePool(); await pg?.stop(); });

class Client {
  constructor() { this.cookie = ''; this.csrf = ''; }
  async call(method, path, body) {
    const headers = { 'content-type': 'application/json' };
    if (this.cookie) headers.cookie = this.cookie;
    if (this.csrf) headers['x-csrf-token'] = this.csrf;
    const r = await fetch(base + path, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
    const sc = r.headers.get('set-cookie'); if (sc) this.cookie = sc.split(';')[0];
    const text = await r.text(); let json = null; try { json = JSON.parse(text); } catch { /* not json */ }
    if (json?.csrf) this.csrf = json.csrf;
    return { status: r.status, json, text };
  }
  get(p) { return this.call('GET', p); } post(p, b) { return this.call('POST', p, b ?? {}); }
}
const PW = 'correct horse battery staple';
const owner = new Client();
let conn;
async function drain() { for (let j; (j = await q.claimJob());) { try { await w.runJob(j); } catch (e) { await q.failJob(j, e); } } }

test('setup: an owner, the two demo AWS accounts scanned', async () => {
  await owner.post('/api/auth/signup', { name: 'Owner', email: 'owner@acme.example', password: PW, workspaceName: 'Acme' });
  const s = await owner.post('/api/auth/mfa/start'); await owner.post('/api/auth/mfa/confirm', { code: totp.code(s.json.secret) });
  for (const [name, id, environment] of [['payments-prod', '111111111111', 'production'], ['data-platform-stg', '222222222222', 'staging']]) {
    const a = await owner.post('/api/accounts', { name, accountId: id, environment, regions: ['ap-southeast-3'] });
    await owner.post(`/api/accounts/${a.json.id}/verify`);
  }
  await drain();
  assert.equal((await owner.get('/api/gcp/connections')).json.items.length, 0);
});

test('connections: validated, keys must be key files, test before saving, one per scope', async () => {
  assert.equal((await owner.post('/api/gcp/connections', { name: 'x', scopeType: 'organization', scopeId: 'acme', authMode: 'wif' })).status, 400);
  assert.equal((await owner.post('/api/gcp/connections', { name: 'x', scopeType: 'project', scopeId: 'acme-shared-ci', authMode: 'key', key: '{"type":"authorized_user"}' })).status, 400);
  const on = await owner.get('/api/gcp/onboarding?scopeType=organization&scopeId=100000000001&home=acme-shared-ci&homeNumber=300000000003');
  assert.match(on.json.steps.map((x) => x.code).join('\n'), /create-aws/);
  const wif = { projectNumber: '300000000003', poolId: 'curious-monkey', providerId: 'aws-scanner', serviceAccount: 'cm-reader@acme-shared-ci.iam.gserviceaccount.com' };
  const t = await owner.post('/api/gcp/connections/test', { scopeType: 'organization', scopeId: '100000000001', authMode: 'wif', wif });
  assert.equal(t.json.ok, true, JSON.stringify(t.json)); assert.equal(t.json.projects, 3); assert.equal(t.json.policyReadable, true);
  const c = await owner.post('/api/gcp/connections', { name: 'acme.example', scopeType: 'organization', scopeId: '100000000001', authMode: 'wif', wif, environment: 'shared' });
  assert.equal(c.status, 201); conn = c.json.id;
  assert.equal((await owner.post('/api/gcp/connections', { name: 'again', scopeType: 'organization', scopeId: '100000000001', authMode: 'wif', wif })).status, 409);
});

test('the worker scans a due connection and stores the analysis', async () => {
  const r = await gcpScan.gcpTick('test-worker');
  assert.equal(r.ok, true, r.error); assert.equal(r.summary.projects, 3); assert.equal(r.summary.serviceAccounts, 9);
  assert.equal(await gcpScan.gcpTick('test-worker'), null);                              // nothing else due: next scan in 24 hours
  const list = (await owner.get('/api/gcp/connections')).json.items;
  assert.equal(list[0].status, 'connected'); assert.equal(list[0].serviceAccounts, 9); assert.ok(list[0].high >= 4);
});

test('principals: listed riskiest first, filtered, with where they come from', async () => {
  const all = (await owner.get('/api/gcp/principals?limit=200')).json;
  assert.ok(all.total >= 18);
  assert.equal(all.items[0].risk, 'High');
  assert.equal(all.facets.kinds.serviceAccount, 9);
  const keys = (await owner.get('/api/gcp/principals?source=key')).json.items.map((x) => x.email).sort();
  assert.deepEqual(keys, ['bq-exporter@acme-payments-prod.iam.gserviceaccount.com', 'terraform@acme-shared-ci.iam.gserviceaccount.com']);
  const fromAws = (await owner.get('/api/gcp/principals?source=aws')).json.items.map((x) => x.email || x.member);
  assert.ok(fromAws.includes('lake-sync@acme-data-stg.iam.gserviceaccount.com') && fromAws.includes('etl-runner@acme-data-stg.iam.gserviceaccount.com'));
  const stg = (await owner.get('/api/gcp/principals?project=acme-data-stg&kind=serviceAccount')).json.items;
  assert.ok(stg.length >= 3 && stg.every((x) => x.project === 'acme-data-stg' || x.reach.includes('acme-data-stg')));
  const search = (await owner.get('/api/gcp/principals?q=vendor')).json.items;
  assert.equal(search.length, 1); assert.ok(search[0].reasons.some((r) => r.id === 'external'));
});

test('one principal: roles with where they are granted, who can become it, and the AWS roles on either side', async () => {
  const find = async (q) => (await owner.get(`/api/gcp/principals?q=${q}`)).json.items[0];
  const lake = (await owner.get(`/api/gcp/principals/${(await find('lake-sync')).id}`)).json;
  assert.equal(lake.environment, 'staging');
  assert.ok(lake.roles.some((r) => r.role === 'roles/storage.admin' && r.resourceType === 'project'));
  assert.equal(lake.aws.into.length, 1);
  assert.equal(lake.aws.into[0].awsRole, 'data-etl'); assert.equal(lake.aws.into[0].awsAccountName, 'data-platform-stg'); assert.ok(lake.aws.into[0].awsRoleId);
  const etl = (await owner.get(`/api/gcp/principals/${(await find('etl-runner')).id}`)).json;
  assert.equal(etl.risk, 'High'); assert.ok(etl.reasons.some((r) => r.id === 'wif-broad'));
  assert.equal(etl.aws.into[0].awsRole, null); assert.equal(etl.aws.into[0].broad, true);   // any role in the AWS account
  const exp = (await owner.get(`/api/gcp/principals/${(await find('bq-exporter')).id}`)).json;
  assert.equal(exp.aws.out.length, 1); assert.equal(exp.aws.out[0].awsRole, 'lake-reader'); assert.equal(exp.aws.out[0].awsAccountName, 'payments-prod');
  const dep = (await owner.get(`/api/gcp/principals/${(await find('deployer')).id}`)).json;
  assert.ok(dep.becomes.length >= 3);                                                     // serviceAccountUser on the production folder
  assert.ok(dep.sources.some((s) => s.via === 'wif' && /GitHub/.test(s.origin.label)));
  const perms = await owner.get(`/api/gcp/roles/permissions?name=${encodeURIComponent('roles/storage.admin')}`);
  assert.ok(perms.json.permissions.includes('storage.buckets.setIamPolicy'));
});

test('space: projects in their environments, outside identities, and the paths between the clouds', async () => {
  const s = (await owner.get('/api/space/gcp')).json;
  assert.deepEqual(s.projects.map((p) => [p.projectId, p.environment]).sort(), [['acme-data-stg', 'staging'], ['acme-payments-prod', 'production'], ['acme-shared-ci', 'shared']]);
  assert.ok(s.outside.some((o) => /GitHub Actions/.test(o.label)));
  assert.ok(s.outside.some((o) => o.label === 'vendor.dev@gmail.com'));
  const into = s.links.awsToGcp.map((l) => `${l.awsAccountName}:${l.awsRole || '*'}->${l.gcpEmail || 'direct'}`).sort();
  assert.deepEqual(into, ['data-platform-stg:data-etl->lake-sync@acme-data-stg.iam.gserviceaccount.com', 'data-platform-stg:lake-reader->direct', 'payments-prod:*->etl-runner@acme-data-stg.iam.gserviceaccount.com']);
  assert.deepEqual(s.links.gcpToAws.map((l) => `${l.gcpEmail}->${l.awsAccountName}:${l.awsRole}`), ['bq-exporter@acme-payments-prod.iam.gserviceaccount.com->payments-prod:lake-reader']);
  // a project's environment can be set by hand
  await owner.call('PUT', `/api/gcp/connections/${conn}/projects/acme-shared-ci/environment`, { environment: 'production' });
  assert.equal((await owner.get('/api/gcp/projects')).json.items.find((p) => p.projectId === 'acme-shared-ci').environment, 'production');
});

test('an AWS role page learns where the role reaches in Google Cloud, and who comes in from there', async () => {
  const roles = (await owner.get('/api/roles?limit=100')).json.items;
  const etl = roles.find((r) => r.name === 'data-etl' && r.aws_account_id === '222222222222');
  const into = (await owner.get(`/api/gcp/aws-role/${etl.id}`)).json.into.map((l) => l.gcpEmail);
  assert.deepEqual(into, ['lake-sync@acme-data-stg.iam.gserviceaccount.com']);
  const any = roles.find((r) => r.name === 'monitoring-reader' && r.aws_account_id === '111111111111');
  assert.ok((await owner.get(`/api/gcp/aws-role/${any.id}`)).json.into.some((l) => l.broad && /etl-runner/.test(l.gcpEmail)));   // a pool open to the whole account
  const lake = roles.find((r) => r.name === 'lake-reader' && r.aws_account_id === '111111111111');
  assert.equal((await owner.get(`/api/gcp/aws-role/${lake.id}`)).json.from[0].gcpEmail, 'bq-exporter@acme-payments-prod.iam.gserviceaccount.com');
});

test('the trust map names the Google service account an AWS role trusts', async () => {
  const t = (await owner.get('/api/trust?q=provider:google')).json;
  const e = t.rows.find((x) => x.role === 'lake-reader' && /Google/.test(x.source));
  assert.ok(e, JSON.stringify(Object.keys(t)));
  assert.equal(e.source, 'Google Cloud · bq-exporter@acme-payments-prod.iam.gserviceaccount.com');
});

test('a scan keeps environments set by hand; failures are recorded and retried later; members limited to accounts do not see Google Cloud', async () => {
  await owner.post(`/api/gcp/connections/${conn}/scan`);
  assert.equal((await gcpScan.gcpTick('w', { gw: { ...((await import('../src/gcp/demo.js')).demoGcpGateway()), folders: async () => { throw new Error('PERMISSION_DENIED: folders'); } } })).ok, false);
  const c = (await owner.get('/api/gcp/connections')).json.items[0];
  assert.equal(c.status, 'error'); assert.match(c.detail.message, /PERMISSION_DENIED/);
  assert.equal((await owner.get('/api/gcp/principals')).json.total > 0, true);           // the last good snapshot stays
  await db.query(`UPDATE gcp_connections SET next_scan_at=now()`);
  assert.equal((await gcpScan.gcpTick('w')).ok, true);
  assert.equal((await owner.get('/api/gcp/projects')).json.items.find((p) => p.projectId === 'acme-shared-ci').environment, 'production');

  const accts = (await owner.get('/api/accounts')).json.items;
  const inv = await owner.post('/api/members/invite', { email: 'squad@acme.example', role: 'account_owner', scope_accounts: [accts[0].id] });
  const squad = new Client(); await squad.post('/api/auth/signup', { name: 'Squad', email: 'squad@acme.example', password: PW, invite: inv.json.link.split('invite=')[1] });
  assert.equal((await squad.get('/api/gcp/principals')).status, 404);
  assert.equal((await squad.get('/api/space/gcp')).json.hidden, true);
  assert.equal((await squad.post(`/api/gcp/connections/${conn}/scan`)).status, 404);
  // removing the connection removes its data
  assert.equal((await owner.call('DELETE', `/api/gcp/connections/${conn}`)).status, 200);
  assert.equal((await owner.get('/api/gcp/principals')).json.total, 0);
});

test('federation pools: the GKE pool and other managed pools are skipped, and a pool that refuses provider listing never fails the scan', async () => {
  const { realGcpGateway } = await import('../src/gcp/real.js');
  const P = 'projects/52/locations/global/workloadIdentityPools';
  const asked = [];
  const client = { async request({ url }) {
    asked.push(url);
    if (url.endsWith('/workloadIdentityPools?pageSize=100')) return { data: { workloadIdentityPools: [
      { name: `${P}/acme-stg.svc.id.goog`, state: 'ACTIVE' },                // GKE: listing providers is "not supported"
      { name: `${P}/trust`, state: 'ACTIVE', mode: 'TRUST_DOMAIN' },
      { name: `${P}/odd`, state: 'ACTIVE' },
      { name: `${P}/aws`, state: 'ACTIVE' }] } };
    if (url.includes('/aws/providers')) return { data: { workloadIdentityPoolProviders: [{ name: `${P}/aws/providers/a1`, state: 'ACTIVE', aws: { accountId: '111111111111' } }] } };
    throw Object.assign(new Error('RPC Method ListWorkloadIdentityPoolProviders is not supported'), { response: { status: 400, data: { error: { message: 'not supported' } } } });
  } };
  const out = await realGcpGateway({ auth_mode: 'key' }, { client }).wifProviders('acme-stg');
  assert.deepEqual(out.map((p) => p.name), [`${P}/aws/providers/a1`]);
  assert.ok(!asked.some((u) => /svc\.id\.goog\/providers|trust\/providers/.test(u)), 'managed pools are not asked for providers');
});
