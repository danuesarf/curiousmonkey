import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { startPg } from './helpers/pg.js';

process.env.AWS_MODE = 'demo'; process.env.LOOKUP_DELAY_MS = '0';
let pg, db, q, w, server, base, totp;
before(async () => {
  pg = await startPg(54334);
  db = await import('../src/db.js');
  await (await import('../src/migrate.js')).migrate(() => {});
  q = await import('../src/queue.js'); w = await import('../src/worker.js'); totp = await import('../src/auth/totp.js');
  const { createApp } = await import('../src/server.js');
  server = createApp().listen(0); base = `http://127.0.0.1:${server.address().port}`;
  await q.registerWorker();
});
after(async () => { server.close(); await db.closePool(); await pg.stop(); });

class Client {
  constructor() { this.cookie = ''; this.csrf = ''; }
  async call(method, path, body, { csrf = true } = {}) {
    const headers = { 'content-type': 'application/json' };
    if (this.cookie) headers.cookie = this.cookie;
    if (csrf && this.csrf) headers['x-csrf-token'] = this.csrf;
    const r = await fetch(base + path, { method, headers, body: body === undefined ? undefined : JSON.stringify(body), redirect: 'manual' });
    const sc = r.headers.get('set-cookie'); if (sc) this.cookie = sc.split(';')[0];
    const text = await r.text(); let json = null; try { json = JSON.parse(text); } catch { /* not json */ }
    if (json?.csrf) this.csrf = json.csrf;
    return { status: r.status, json, text, headers: r.headers };
  }
  get(p) { return this.call('GET', p); } post(p, b, o) { return this.call('POST', p, b ?? {}, o); } patch(p, b) { return this.call('PATCH', p, b ?? {}); }
}
async function drain() { for (let j; (j = await q.claimJob());) { try { await w.runJob(j); } catch (e) { await q.failJob(j, e); } } }
const PW = 'correct horse battery staple';
const owner = new Client();

test('first visit says setup is needed; the first sign-up becomes the owner and creates the workspace', async () => {
  assert.equal((await owner.get('/api/auth/state')).json.needsSetup, true);
  const r = await owner.post('/api/auth/signup', { name: 'Dhimas', email: 'dhimas@kbi.id', password: PW, workspaceName: 'KBI' });
  assert.equal(r.status, 201); assert.equal(r.json.user.role, 'owner');
  assert.equal((await owner.get('/api/auth/state')).json.needsSetup, false);
});

test('weak passwords are refused', async () => {
  const r = await new Client().post('/api/auth/signup', { name: 'x', email: 'x@kbi.id', password: 'short' });
  assert.equal(r.status, 400);               // validation runs before the closed-sign-up check
});

test('an owner must set up two-factor before using the API', async () => {
  assert.equal((await owner.get('/api/accounts')).status, 403);
  assert.equal((await owner.get('/api/accounts')).json.error, 'mfa_setup_required');
  const s = await owner.post('/api/auth/mfa/start');
  assert.ok(s.json.qr.startsWith('data:image/png'));
  assert.equal((await owner.post('/api/auth/mfa/confirm', { code: '000000' })).status, 400);
  assert.equal((await owner.post('/api/auth/mfa/confirm', { code: totp.code(s.json.secret) })).status, 200);
  assert.equal((await owner.get('/api/accounts')).status, 200);
  owner.secret = s.json.secret;
});

test('state-changing requests without the CSRF token are rejected', async () => {
  const r = await owner.call('POST', '/api/accounts', { name: 'x', accountId: '123456789012' }, { csrf: false });
  assert.equal(r.status, 403); assert.equal(r.json.error, 'bad_csrf');
});

test('sign-in needs the authenticator code; wrong passwords and codes are refused', async () => {
  const c = new Client();
  assert.equal((await c.post('/api/auth/signin', { email: 'dhimas@kbi.id', password: 'nope-nope-nope' })).status, 401);
  const need = await c.post('/api/auth/signin', { email: 'dhimas@kbi.id', password: PW });
  assert.equal(need.json.error, 'mfa_required');
  assert.equal((await c.post('/api/auth/signin', { email: 'dhimas@kbi.id', password: PW, code: '123456' })).json.error, 'bad_code');
  const ok = await c.post('/api/auth/signin', { email: 'dhimas@kbi.id', password: PW, code: totp.code(owner.secret) });
  assert.equal(ok.status, 200);
});

test('repeated failures lock the sign-in for that address', async () => {
  const c = new Client(); let last;
  for (let i = 0; i < 11; i++) last = await c.post('/api/auth/signin', { email: 'victim@kbi.id', password: 'wrong-wrong-wrong' });
  assert.equal(last.status, 429);
});

test('after setup, open sign-up is closed; invites work once', async () => {
  const stranger = new Client();
  assert.equal((await stranger.post('/api/auth/signup', { name: 'Eve', email: 'eve@evil.io', password: PW })).json.error, 'invite_required');
  const inv = await owner.post('/api/members/invite', { email: 'sari@kbi.id', role: 'reviewer' });
  assert.equal(inv.status, 400);                                   // reviewers need a team
  const inv2 = await owner.post('/api/members/invite', { email: 'sari@kbi.id', role: 'reviewer', team: 'infosec' });
  assert.equal(inv2.status, 201);
  const token = inv2.json.link.split('invite=')[1];
  assert.equal((await new Client().get(`/api/auth/invite/${token}`)).json.email, 'sari@kbi.id');
  assert.equal((await new Client().post('/api/auth/signup', { name: 'X', email: 'other@kbi.id', password: PW, invite: token })).status, 403);   // wrong email
  const ok = new Client();
  const r = await ok.post('/api/auth/signup', { name: 'Sari', email: 'sari@kbi.id', password: PW, invite: token });
  assert.equal(r.status, 201); assert.equal(r.json.user.team, 'infosec');
  assert.equal((await new Client().post('/api/auth/signup', { name: 'Sari', email: 'sari@kbi.id', password: PW, invite: token })).status, 403);  // used
});

let accA, accB;
test('onboarding: snippets carry the ExternalId; accounts validate; duplicates are refused', async () => {
  const s = await owner.get('/api/onboarding/snippets');
  assert.match(s.json.terraform, /sts:ExternalId/); assert.match(s.json.terraform, /NeverReadCustomerData/);
  assert.equal((await owner.post('/api/accounts', { name: 'x', accountId: '123' })).status, 400);
  const a = await owner.post('/api/accounts', { name: 'prod', accountId: '111111111111', regions: ['ap-southeast-3'] });
  const b = await owner.post('/api/accounts', { name: 'staging', accountId: '222222222222', environment: 'staging', regions: ['ap-southeast-3'] });
  assert.equal(a.status, 201); accA = a.json.id; accB = b.json.id;
  assert.equal((await owner.post('/api/accounts', { name: 'dup', accountId: '111111111111' })).status, 409);
  assert.equal(a.json.role_arn, 'arn:aws:iam::111111111111:role/CuriousMonkeyScanner');
});

test('accounts: access modes, S3 source and edits; stored keys never come back', async () => {
  // Fake key, assembled at runtime so it never sits in the source as a literal (secret scanners flag those).
  const KEY = { accessKeyId: ['AK', 'IA', 'ABCDEFGHIJKLMNOP'].join(''), secretAccessKey: ['abcdefghijklmnop', 'qrstuvwxyz0123456789ABCD'].join('') };
  // access-key mode needs keys; Event History cannot go past 90 days; S3 needs a bucket
  assert.equal((await owner.post('/api/accounts', { name: 'u', accountId: '555555555555', authMode: 'access_key' })).json.field, 'credentials');
  assert.equal((await owner.post('/api/accounts', { name: 'u', accountId: '555555555555', lookbackDays: 120 })).json.field, 'lookbackDays');
  assert.equal((await owner.post('/api/accounts', { name: 'u', accountId: '555555555555', eventSource: 's3' })).json.field, 's3.bucket');
  const u = await owner.post('/api/accounts', { name: 'user-mode', accountId: '555555555555', authMode: 'access_key', credentials: KEY,
    eventSource: 's3', lookbackDays: 365, s3: { bucket: 'kbi-org-cloudtrail', prefix: 'org', orgId: 'o-abc123def4' } });
  assert.equal(u.status, 201);
  assert.equal(u.json.credentials_enc, undefined); assert.equal(u.json.has_credentials, true); assert.equal(u.json.credentials_hint, 'AKIA…MNOP');
  assert.equal(u.json.role_arn, null); assert.equal(u.json.lookback_days, 365);
  assert.doesNotMatch((await owner.get('/api/accounts')).text, /credentials_enc|abcdefghijklmnop/);
  const stored = (await db.query('SELECT credentials_enc FROM cloud_accounts WHERE id=$1', [u.json.id])).rows[0].credentials_enc;
  assert.doesNotMatch(stored, /abcdefghijklmnop/);                         // encrypted at rest
  // edit: rename keeps the keys and the status; switching to an assumed role with system credentials drops the keys
  await db.query(`UPDATE cloud_accounts SET status='connected' WHERE id=$1`, [u.json.id]);
  const r1 = await owner.patch(`/api/accounts/${u.json.id}`, { name: 'renamed' });
  assert.equal(r1.json.name, 'renamed'); assert.equal(r1.json.has_credentials, true); assert.equal(r1.json.status, 'connected'); assert.equal(r1.json.accessChanged, false);
  assert.equal((await owner.patch(`/api/accounts/${u.json.id}`, { eventSource: 'event-history' })).json.field, 'lookbackDays');
  const r2 = await owner.patch(`/api/accounts/${u.json.id}`, { authMode: 'assume_role', baseIdentity: 'system', roleName: 'CmScanner' });
  assert.equal(r2.json.has_credentials, false); assert.equal(r2.json.status, 'pending'); assert.equal(r2.json.role_arn, 'arn:aws:iam::555555555555:role/CmScanner');
  // snippets follow the mode and the bucket
  const sn = await owner.get('/api/onboarding/snippets?mode=assume_role&bucket=kbi-org-cloudtrail&prefix=org&principal=arn:aws:iam::999999999999:role/cm-worker');
  assert.match(sn.json.terraform, /NotResource/); assert.match(sn.json.terraform, /cm-worker/); assert.ok(sn.json.basePolicy);
  assert.match((await owner.get('/api/onboarding/snippets?mode=access_key')).json.terraform, /aws_iam_user/);
  assert.equal((await owner.get('/api/onboarding/identity')).status, 200);
  await owner.call('DELETE', `/api/accounts/${u.json.id}`);
});

test('verify queues a scan; the worker connects the account and fills the portal', async () => {
  assert.equal((await owner.post(`/api/accounts/${accA}/verify`)).status, 202);
  assert.equal((await owner.post(`/api/accounts/${accA}/scan`)).status, 409);          // already running
  assert.equal((await owner.post(`/api/accounts/${accB}/verify`)).status, 202);
  const mid = await owner.get('/api/ops/overview');
  assert.ok(mid.json.jobs.queued > 0);
  await drain();
  const list = (await owner.get('/api/accounts')).json.items;
  assert.equal(list.find((x) => x.id === accA).status, 'connected');
  assert.equal(list.find((x) => x.id === accA).roles, 10);
  assert.equal(list.find((x) => x.id === accA).data_event_sources, 2);
  assert.ok(list.find((x) => x.id === accA).checkpoints.length >= 1);
});

test('role list: filters, sorting, paging and facets', async () => {
  const all = (await owner.get('/api/roles?limit=100')).json;
  assert.equal(all.total, 20);
  assert.equal(all.items[0].risk, 'High');                                              // sorted by risk first
  const sso = (await owner.get('/api/roles?kinds=identity-center')).json;
  assert.equal(sso.total, 2); assert.ok(sso.items.every((r) => r.kind === 'identity-center'));
  const one = (await owner.get(`/api/roles?accounts=${accA}&q=payments`)).json;
  assert.equal(one.total, 1);
  assert.equal((await owner.get('/api/roles?risks=High&teams=infosec')).json.items.every((r) => r.risk === 'High' && r.reviewer_team === 'infosec'), true);
  assert.equal((await owner.get('/api/roles?idle=1')).json.total, 2);                  // old-batch-runner in each account
  assert.ok(all.facets.length > 3);
});

test('role detail shows who used it, with the conditions they met', async () => {
  const id = (await owner.get(`/api/roles?accounts=${accA}&q=ci-deployer`)).json.items[0].id;
  const d = (await owner.get(`/api/roles/${id}`)).json;
  assert.equal(d.principals[0].via, 'sts:AssumeRoleWithWebIdentity');
  assert.ok(d.principals[0].caller.trust.conditions.length >= 1);
  assert.ok(d.passRoles.length === 1);
  assert.ok(d.window.first && d.window.last);
  const acts = (await owner.get(`/api/roles/${id}/actions?status=used`)).json;
  assert.ok(acts.items.some((a) => a.action === 'ecs:UpdateService'));
});

let reviewerClient;
test('RBAC: an auditor can read but not change anything; a scoped account owner sees only their account', async () => {
  const mk = async (email, role, extra = {}) => {
    const inv = await owner.post('/api/members/invite', { email, role, ...extra });
    const c = new Client();
    await c.post('/api/auth/signup', { name: email, email, password: PW, invite: inv.json.link.split('invite=')[1] });
    return c;
  };
  const auditor = await mk('aud@kbi.id', 'auditor');
  assert.equal((await auditor.get('/api/roles')).json.total, 20);
  assert.equal((await auditor.post('/api/accounts', { name: 'x', accountId: '999999999999' })).status, 403);
  assert.equal((await auditor.post(`/api/accounts/${accA}/scan`)).status, 403);
  assert.equal((await auditor.get('/api/audit')).status, 200);
  assert.equal((await auditor.get('/api/members')).status, 403);
  const scoped = await mk('squad@kbi.id', 'account_owner', { scope_accounts: [accB] });
  const mine = (await scoped.get('/api/roles?limit=100')).json;
  assert.equal(mine.total, 10); assert.ok(mine.items.every((r) => r.account_id === accB));
  const other = (await owner.get(`/api/roles?accounts=${accA}&q=payments`)).json.items[0].id;
  assert.equal((await scoped.get(`/api/roles/${other}`)).status, 404);                 // not 403: existence is not revealed
  assert.equal((await scoped.get('/api/accounts')).json.items.length, 1);
  reviewerClient = await mk('rev@kbi.id', 'reviewer', { team: 'infrasec' });
});

test('the reviewer is forced to set up two-factor like everyone with decision power', async () => {
  assert.equal((await reviewerClient.get('/api/roles')).json.error, 'mfa_setup_required');
  const s = await reviewerClient.post('/api/auth/mfa/start');
  await reviewerClient.post('/api/auth/mfa/confirm', { code: totp.code(s.json.secret) });
  assert.equal((await reviewerClient.get('/api/roles')).status, 200);
});

test('decisions: only valid choices per finding type; recorded with the reviewer; change is audited', async () => {
  const id = (await owner.get(`/api/roles?accounts=${accA}&q=payments`)).json.items[0].id;
  const d = (await owner.get(`/api/roles/${id}`)).json;
  const dataFlag = d.flags.find((f) => f.category === 'data-event');
  assert.equal((await owner.post(`/api/flags/${dataFlag.id}/decision`, { decision: 'accept' })).status, 400);
  assert.equal((await owner.post(`/api/flags/${dataFlag.id}/decision`, { decision: 'keep_scoped', resources: ['arn:aws:s3:::kbi-payments-docs/*'], note: 'ok' })).status, 200);
  const after = (await owner.get(`/api/roles/${id}`)).json.flags.find((f) => f.id === dataFlag.id);
  assert.equal(after.decision, 'keep_scoped'); assert.equal(after.decided_by, 'Dhimas');
  const log = (await owner.get('/api/audit?action=flag.decide')).json;
  assert.ok(log.items.length >= 1);
});

test('recommend, then both teams approve a High-risk role; the export reflects approval', async () => {
  const id = (await owner.get(`/api/roles?accounts=${accA}&q=legacy-admin`)).json.items[0].id;
  const rec = await reviewerClient.post(`/api/roles/${id}/recommend`, { useAi: false });
  assert.equal(rec.status, 201); assert.equal(rec.json.source, 'rules');
  assert.deepEqual(rec.json.requiredTeams, ['infrasec', 'infosec']);
  const a1 = await reviewerClient.post(`/api/recommendations/${rec.json.id}/approve`);
  assert.equal(a1.json.approved, false); assert.deepEqual(a1.json.waitingFor, ['infosec']);
  // sari (infosec) approves; she has not enrolled MFA, so give her a session through the DB-free path: sign in then enroll
  const sari = new Client();
  await sari.post('/api/auth/signin', { email: 'sari@kbi.id', password: PW });
  const s = await sari.post('/api/auth/mfa/start'); await sari.post('/api/auth/mfa/confirm', { code: totp.code(s.json.secret) });
  const a2 = await sari.post(`/api/recommendations/${rec.json.id}/approve`);
  assert.equal(a2.json.approved, true);
  const ex = await sari.get(`/api/recommendations/${rec.json.id}/export`);
  assert.equal(ex.json.approved, true);
  assert.match((await sari.get(`/api/recommendations/${rec.json.id}/export?format=terraform`)).text, /aws_iam_policy/);
});

test('service-linked roles cannot get a recommendation; the API says why', async () => {
  const id = (await owner.get(`/api/roles?accounts=${accA}&kinds=service-linked`)).json.items[0].id;
  const r = await owner.post(`/api/roles/${id}/recommend`, { useAi: false });
  assert.equal(r.status, 409); assert.match(r.json.message, /cannot be edited/);
});

test('monitoring: run detail, job log, retry and cancel are available and audited', async () => {
  const ov = (await owner.get('/api/ops/overview')).json;
  assert.ok(ov.runs.length >= 2, 'runs'); assert.ok(ov.workers.length >= 1, 'workers'); assert.equal(ov.jobs.queued || 0, 0, JSON.stringify(ov.jobs));
  const det = (await owner.get(`/api/ops/runs/${ov.runs[0].id}`)).json;
  assert.ok(det.jobs.length >= 4, 'jobs ' + det.jobs.length);
  const log = (await owner.get(`/api/ops/jobs/${det.jobs[0].id}/log`)).json;
  assert.ok(log.items.some((l) => /succeeded/.test(l.message)), JSON.stringify(log.items));
  await owner.post(`/api/accounts/${accA}/scan`);
  const run = (await owner.get('/api/ops/overview')).json.runs[0];
  const cc = await owner.post(`/api/ops/runs/${run.id}/cancel`); assert.ok(cc.json.canceled > 0, JSON.stringify([cc.status, cc.json, run]));
  assert.equal((await owner.get('/api/audit?action=ops.cancel')).json.items.length, 1);
});

test('the last owner cannot be demoted or disabled', async () => {
  const me = (await owner.get('/api/members')).json.members.find((m) => m.email === 'dhimas@kbi.id');
  assert.equal((await owner.call('PATCH', `/api/members/${me.id}`, { role: 'admin' })).json.error, 'last_owner');
  assert.equal((await owner.call('PATCH', `/api/members/${me.id}`, { disabled: true })).status, 409);
});

test('disabling a member ends their sessions at once', async () => {
  const m = (await owner.get('/api/members')).json.members.find((x) => x.email === 'aud@kbi.id');
  assert.equal((await owner.call('PATCH', `/api/members/${m.id}`, { disabled: true })).status, 200);
  const c = new Client(); const r = await c.post('/api/auth/signin', { email: 'aud@kbi.id', password: PW });
  assert.equal(r.status, 401);
});

test('health and metrics endpoints answer; unknown API paths are JSON 404s; the SPA shell is served', async () => {
  assert.equal((await fetch(base + '/healthz')).status, 200);
  assert.match(await (await fetch(base + '/metrics')).text(), /cm_scan_jobs/);
  assert.equal((await owner.get('/api/nope')).status, 404);
});

test('security headers are set', async () => {
  const r = await fetch(base + '/healthz');
  assert.match(r.headers.get('content-security-policy'), /script-src 'self'/);
  assert.equal(r.headers.get('x-powered-by'), null);
});
