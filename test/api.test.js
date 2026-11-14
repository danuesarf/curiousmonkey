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
    eventSource: 's3', lookbackDays: 365, s3: { bucket: 'acme-org-cloudtrail', prefix: 'org', orgId: 'o-abc123def4' } });
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
  // taking regions out: remembered, so an S3 trail reader does not add them back, and their read state is dropped
  await db.query(`UPDATE cloud_accounts SET regions='{ap-southeast-3,eu-north-1,us-east-1}' WHERE id=$1`, [u.json.id]);
  await db.query(`INSERT INTO scan_checkpoints(account_id, region, source, last_event_time) VALUES ($1,'eu-north-1','s3',now()), ($1,'us-east-1','s3',now())`, [u.json.id]);
  const rr = await owner.patch(`/api/accounts/${u.json.id}`, { regions: ['ap-southeast-3', 'us-east-1'] });
  assert.deepEqual([rr.json.regions, rr.json.excluded_regions], [['ap-southeast-3', 'us-east-1'], ['eu-north-1']]);
  assert.deepEqual((await db.query('SELECT region FROM scan_checkpoints WHERE account_id=$1', [u.json.id])).rows.map((x) => x.region), ['us-east-1']);
  assert.deepEqual((await owner.patch(`/api/accounts/${u.json.id}`, { regions: ['ap-southeast-3', 'eu-north-1', 'us-east-1'] })).json.excluded_regions, [], 'ticking it again lets it back in');
  const r2 = await owner.patch(`/api/accounts/${u.json.id}`, { authMode: 'assume_role', baseIdentity: 'system', roleName: 'CmScanner' });
  assert.equal(r2.json.has_credentials, false); assert.equal(r2.json.status, 'pending'); assert.equal(r2.json.role_arn, 'arn:aws:iam::555555555555:role/CmScanner');
  // snippets follow the mode and the bucket
  const sn = await owner.get('/api/onboarding/snippets?mode=assume_role&bucket=acme-org-cloudtrail&prefix=org&principal=arn:aws:iam::999999999999:role/cm-worker');
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

let reviewerClient, auditorClient, scopedClient;
test('RBAC: an auditor can read but not change anything; a scoped account owner sees only their account', async () => {
  const mk = async (email, role, extra = {}) => {
    const inv = await owner.post('/api/members/invite', { email, role, ...extra });
    const c = new Client();
    await c.post('/api/auth/signup', { name: email, email, password: PW, invite: inv.json.link.split('invite=')[1] });
    return c;
  };
  const auditor = await mk('aud@kbi.id', 'auditor'); auditorClient = auditor;
  assert.equal((await auditor.get('/api/roles')).json.total, 20);
  assert.equal((await auditor.post('/api/accounts', { name: 'x', accountId: '999999999999' })).status, 403);
  assert.equal((await auditor.post(`/api/accounts/${accA}/scan`)).status, 403);
  assert.equal((await auditor.get('/api/audit')).status, 200);
  assert.equal((await auditor.get('/api/members')).status, 403);
  const scoped = await mk('squad@kbi.id', 'account_owner', { scope_accounts: [accB] }); scopedClient = scoped;
  const mine = (await scoped.get('/api/roles?limit=100')).json;
  assert.equal(mine.total, 10); assert.ok(mine.items.every((r) => r.account_id === accB));
  const other = (await owner.get(`/api/roles?accounts=${accA}&q=payments`)).json.items[0].id;
  assert.equal((await scoped.get(`/api/roles/${other}`)).status, 404);                 // not 403: existence is not revealed
  assert.equal((await scoped.get('/api/accounts')).json.items.length, 1);
  // unidentified calls across the estate: everything for a member who sees everything, only their account for a scoped one
  const ins = (acct, raw, name) => db.query(`INSERT INTO unmapped_events(account_id, raw_action, event_source, event_name, count, first_seen, last_seen) VALUES ($1,$2,'estate.amazonaws.com',$3,3,now(),now())`, [acct, raw, name]);
  await ins(accA, 'estate:EstateOnlyInA', 'EstateOnlyInA'); await ins(accB, 'estate:EstateOnlyInB', 'EstateOnlyInB');
  try {
    const all = (await owner.get('/api/coverage?days=30')).json;
    assert.deepEqual(all.unmapped.filter((u) => u.raw_action.startsWith('estate:')).map((u) => u.raw_action).sort(), ['estate:EstateOnlyInA', 'estate:EstateOnlyInB']);
    assert.ok(all.unmapped.every((u) => u.account_id && u.account_name), 'each name says which account it was seen in');
    const mineB = (await scoped.get('/api/coverage')).json.unmapped.filter((u) => u.raw_action.startsWith('estate:'));
    assert.deepEqual(mineB.map((u) => u.raw_action), ['estate:EstateOnlyInB']);
    const one = (await owner.get(`/api/accounts/${accA}/coverage`)).json;                  // the per-account answer is unchanged
    assert.deepEqual(one.unmapped.filter((u) => u.raw_action.startsWith('estate:')).map((u) => u.raw_action), ['estate:EstateOnlyInA']);
    assert.equal((await scoped.get(`/api/accounts/${accA}/coverage`)).status, 404);
    assert.equal((await new Client().get('/api/coverage')).status, 401);
  } finally { await db.query(`DELETE FROM unmapped_events WHERE raw_action LIKE 'estate:%'`); }
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
  assert.equal((await owner.post(`/api/flags/${dataFlag.id}/decision`, { decision: 'keep_scoped', resources: ['arn:aws:s3:::acme-payments-docs/*'], note: 'ok' })).status, 200);
  const after = (await owner.get(`/api/roles/${id}`)).json.flags.find((f) => f.id === dataFlag.id);
  assert.equal(after.decision, 'keep_scoped'); assert.equal(after.decided_by, 'Dhimas');
  const log = (await owner.get('/api/audit?action=flag.decide')).json;
  assert.ok(log.items.length >= 1);
});

test('findings inbox: one list across roles, counts per severity, filters, and the waiting count on the status bar', async () => {
  const all = (await owner.get('/api/findings?state=all&limit=200')).json;
  assert.ok(all.total > 0); assert.equal(all.items.length, Math.min(all.total, 200));
  assert.ok(new Set(all.items.map((x) => x.role_id)).size > 1, 'findings from more than one role');
  const sevRank = { high: 0, medium: 1, low: 2 };
  assert.ok(all.items.every((x, i) => !i || sevRank[all.items[i - 1].severity] <= sevRank[x.severity]), 'most severe first');
  assert.equal(all.severity.high + all.severity.medium + all.severity.low, all.total);
  const one = all.items[0];
  assert.ok(one.role_name && one.account_name && Array.isArray(one.allowed));
  // filters
  const high = (await owner.get('/api/findings?severity=high&state=all')).json;
  assert.ok(high.items.every((x) => x.severity === 'high')); assert.equal(high.total, all.severity.high);
  assert.equal(high.severity.medium, all.severity.medium, 'the severity counts ignore the severity filter');
  const cat = all.categories[0].category;
  assert.ok((await owner.get(`/api/findings?category=${cat}&state=all`)).json.items.every((x) => x.category === cat));
  const inA = (await owner.get(`/api/findings?accounts=${accA}&state=all&limit=200`)).json;
  assert.ok(inA.items.every((x) => x.account_id === accA));
  // the one decided in the test above is not waiting; it shows under "decided"
  const open = (await owner.get('/api/findings?limit=200')).json, decided = (await owner.get('/api/findings?state=decided&limit=200')).json;
  assert.ok(open.items.every((x) => !x.decision)); assert.ok(decided.items.length >= 1 && decided.items.every((x) => x.decision));
  assert.equal(open.total + decided.total, all.total);
  assert.equal((await owner.get('/api/status')).json.findings, open.total);
  // search finds by role name
  const byName = (await owner.get(`/api/findings?state=all&q=${encodeURIComponent(one.role_name)}`)).json;
  assert.ok(byName.items.length && byName.items.every((x) => x.role_name.toLowerCase().includes(one.role_name.toLowerCase()) || x.title.toLowerCase().includes(one.role_name.toLowerCase())));
  // a member limited to account B sees only B's findings, and none of A's
  const mine = (await scopedClient.get('/api/findings?state=all&limit=200')).json;
  assert.ok(mine.items.every((x) => x.account_id === accB));
  assert.equal((await new Client().get('/api/findings')).status, 401);
});

test('findings inbox: bulk decisions are all or nothing, per-kind, scoped and audited; clearing puts them back', async () => {
  const open = (await owner.get(`/api/findings?accounts=${accA}&limit=200`)).json.items;
  const acts = open.filter((x) => x.allowed.includes('remove')).slice(0, 2);
  const others = open.filter((x) => x.allowed.includes('accept')).slice(0, 1);
  assert.equal(acts.length, 2); assert.equal(others.length, 1);
  // mixed kinds: refused, nothing written
  const mixed = await owner.post('/api/findings/decisions', { ids: [...acts, ...others].map((x) => x.id), decision: 'remove' });
  assert.equal(mixed.status, 400); assert.equal(mixed.json.error, 'bad_decision'); assert.match(mixed.json.message, /1 of the selected/);
  assert.equal((await db.query('SELECT count(*)::int n FROM review_decisions WHERE flag_id = ANY($1::uuid[])', [acts.map((x) => x.id)])).rows[0].n, 0);
  // resources belong to keep_scoped only
  assert.equal((await owner.post('/api/findings/decisions', { ids: [acts[0].id], decision: 'remove', resources: ['arn:aws:s3:::x'] })).status, 400);
  // no permission to decide, or not in scope: refused
  assert.equal((await auditorClient.post('/api/findings/decisions', { ids: [acts[0].id], decision: 'remove' })).status, 403);
  assert.equal((await scopedClient.post('/api/findings/decisions', { ids: [acts[0].id], decision: 'remove' })).status, 403);   // account owners cannot decide at all
  const rev = await reviewerClient.post('/api/findings/decisions', { ids: [...acts.map((x) => x.id), '00000000-0000-4000-8000-000000000000'], decision: 'remove' });
  assert.equal(rev.status, 404);
  // the real thing
  const ok = await reviewerClient.post('/api/findings/decisions', { ids: acts.map((x) => x.id), decision: 'remove', note: 'unused for a year' });
  assert.equal(ok.status, 200); assert.equal(ok.json.decided, 2);
  const rows = (await db.query('SELECT decision, note, team FROM review_decisions WHERE flag_id = ANY($1::uuid[])', [acts.map((x) => x.id)])).rows;
  assert.equal(rows.length, 2); assert.ok(rows.every((r) => r.decision === 'remove' && r.note === 'unused for a year' && r.team === 'infrasec'));
  const role = (await owner.get(`/api/roles/${acts[0].role_id}`)).json.flags.find((f) => f.id === acts[0].id);
  assert.equal(role.decision, 'remove', 'the role page sees the inbox decision');
  const log = (await owner.get('/api/audit?action=flag.decide')).json.items;
  assert.ok(acts.every((x) => log.some((e) => e.target_id === x.id && e.detail?.bulk === true)), 'one audit entry per finding');
  assert.ok(!(await owner.get('/api/findings?limit=200')).json.items.some((x) => acts.some((y) => y.id === x.id)), 'decided ones leave the waiting list');
  // clear them again
  const cl = await reviewerClient.post('/api/findings/decisions/clear', { ids: acts.map((x) => x.id) });
  assert.equal(cl.status, 200); assert.equal(cl.json.cleared, 2);
  assert.equal((await db.query('SELECT count(*)::int n FROM review_decisions WHERE flag_id = ANY($1::uuid[])', [acts.map((x) => x.id)])).rows[0].n, 0);
  // a finding a newer scan resolved cannot be decided from a stale list
  await db.query(`UPDATE flags SET status='resolved' WHERE id=$1`, [others[0].id]);
  try {
    const stale = await owner.post('/api/findings/decisions', { ids: [others[0].id], decision: 'accept' });
    assert.equal(stale.status, 409); assert.equal(stale.json.error, 'resolved');
  } finally { await db.query(`UPDATE flags SET status='open' WHERE id=$1`, [others[0].id]); }
});

test('search: a few of each kind by name or ID, exact names first, only in the member\'s accounts', async () => {
  const r = (await owner.get('/api/search?q=legacy')).json;
  assert.ok(r.roles.length >= 1 && r.roles.length <= 5); assert.ok(r.roles.every((x) => /legacy/i.test(x.name) && x.account && x.risk));
  assert.equal((await owner.get('/api/search?q=legacy-admin')).json.roles[0].name, 'legacy-admin', 'the exact name comes first');
  // IAM users and their access keys
  const u = (await owner.get('/api/iam-users?limit=50')).json.items.find((x) => x.keys.length);
  const byUser = (await owner.get(`/api/search?q=${encodeURIComponent(u.name)}`)).json;
  assert.ok(byUser.users.some((x) => x.id === u.id)); assert.ok(byUser.roles.every((x) => x.kind !== 'iam-user'), 'users are not listed again as roles');
  const byKey = (await owner.get(`/api/search?q=${u.keys[0].id.slice(0, 10)}`)).json;
  assert.ok(byKey.keys.some((k) => k.id === u.keys[0].id && k.userId === u.id));
  assert.equal((await owner.get('/api/search?q=AKI')).json.keys.length, 0, 'three letters are too few for a key ID');
  // accounts by name and by AWS account ID
  assert.deepEqual((await owner.get('/api/search?q=1111111')).json.accounts.map((a) => a.awsAccountId), ['111111111111']);
  assert.ok((await owner.get('/api/search?q=stag')).json.accounts.some((a) => a.id === accB));
  // too short, and LIKE wildcards are plain text
  const short = (await owner.get('/api/search?q=a')).json; assert.equal(short.roles.length + short.users.length + short.accounts.length, 0);
  const pct = (await owner.get('/api/search?q=%25%25')).json; assert.equal(pct.roles.length + pct.users.length + pct.accounts.length, 0);
  // a member limited to account B finds nothing from account A, and no Google Cloud
  const mine = (await scopedClient.get('/api/search?q=legacy')).json;
  const inB = new Set((await scopedClient.get('/api/roles?limit=100')).json.items.map((x) => x.id));
  assert.ok(mine.roles.every((x) => inB.has(x.id))); assert.deepEqual(mine.gcp, []);
  assert.equal((await scopedClient.get('/api/search?q=1111111')).json.accounts.length, 0);
  assert.equal((await new Client().get('/api/search?q=legacy')).status, 401);
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

test('password reset: only an owner makes the link; it works once, signs the member out, and can reset two-factor', async () => {
  const NEW = 'brand-new-password-42';
  const members = async () => (await owner.get('/api/members')).json.members;
  const squad = (await members()).find((x) => x.email === 'squad@kbi.id');
  const squadSession = new Client(); assert.equal((await squadSession.post('/api/auth/signin', { email: 'squad@kbi.id', password: PW })).status, 200);

  // an admin can manage members but cannot reset passwords
  const inv = await owner.post('/api/members/invite', { email: 'adm@kbi.id', role: 'admin' });
  const adm = new Client(); await adm.post('/api/auth/signup', { name: 'Adm', email: 'adm@kbi.id', password: PW, invite: inv.json.link.split('invite=')[1] });
  const s = await adm.post('/api/auth/mfa/start'); await adm.post('/api/auth/mfa/confirm', { code: totp.code(s.json.secret) });
  const denied = await adm.post(`/api/members/${squad.id}/reset-password`, {});
  assert.equal(denied.status, 403); assert.match(denied.json.message, /owner/);

  // a newer link cancels the older one
  const first = (await owner.post(`/api/members/${squad.id}/reset-password`, {})).json;
  const made = await owner.post(`/api/members/${squad.id}/reset-password`, {});
  assert.equal(made.status, 201); assert.equal(made.json.expiresInHours, 24);
  const token = made.json.link.split('token=')[1];
  assert.match(made.json.link, /#\/reset\?token=/);                                    // after the #: never sent to the server
  const anon = new Client();
  assert.equal((await anon.get(`/api/auth/reset/${first.link.split('token=')[1]}`)).status, 404);
  assert.equal((await anon.get(`/api/auth/reset/${token}`)).json.email, 'squad@kbi.id');

  // the link alone changes nothing; the old password still works until it is used
  assert.equal((await new Client().post('/api/auth/signin', { email: 'squad@kbi.id', password: PW })).status, 200);
  assert.equal((await anon.post('/api/auth/reset', { token, password: 'short' })).status, 400);
  assert.equal((await anon.post('/api/auth/reset', { token, password: PW })).json.error, 'same_password');
  const done = await anon.post('/api/auth/reset', { token, password: NEW });
  assert.equal(done.status, 200); assert.equal(done.json.email, 'squad@kbi.id');
  assert.equal((await squadSession.get('/api/roles')).status, 401);                     // signed out everywhere
  assert.equal((await new Client().post('/api/auth/signin', { email: 'squad@kbi.id', password: PW })).status, 401);
  assert.equal((await new Client().post('/api/auth/signin', { email: 'squad@kbi.id', password: NEW })).status, 200);
  assert.equal((await anon.post('/api/auth/reset', { token, password: 'another-password-77' })).status, 404);   // once only

  // resetting two-factor: the admin signs in with no code and is asked to set it up again
  const rev = (await members()).find((x) => x.email === 'adm@kbi.id');
  assert.equal(rev.totp_confirmed, true);
  const t2 = (await owner.post(`/api/members/${rev.id}/reset-password`, { resetMfa: true })).json.link.split('token=')[1];
  assert.equal((await anon.get(`/api/auth/reset/${t2}`)).json.resetMfa, true);
  assert.equal((await anon.post('/api/auth/reset', { token: t2, password: NEW })).status, 200);
  const back = new Client(); const r = await back.post('/api/auth/signin', { email: 'adm@kbi.id', password: NEW });
  assert.equal(r.status, 200); assert.equal(r.json.user.needsMfaSetup, true);

  // disabled members get no link; every step is in the audit log
  const aud = (await members()).find((x) => x.email === 'aud@kbi.id');
  assert.equal((await owner.post(`/api/members/${aud.id}/reset-password`, {})).json.error, 'disabled');
  const log = (await owner.get('/api/audit?action=')).json.items.map((i) => i.action);
  assert.ok(log.includes('member.password_reset_link') && log.includes('auth.password_reset'));
});

test('single sign-on: only owners set it; the secret is stored encrypted and never returned; the sign-in page follows', async () => {
  const inv = await owner.post('/api/members/invite', { email: 'adm2@kbi.id', role: 'admin' });
  const adm = new Client(); await adm.post('/api/auth/signup', { name: 'Adm2', email: 'adm2@kbi.id', password: PW, invite: inv.json.link.split('invite=')[1] });
  const s = await adm.post('/api/auth/mfa/start'); await adm.post('/api/auth/mfa/confirm', { code: totp.code(s.json.secret) });
  assert.equal((await adm.get('/api/settings')).status, 200);                           // admins configure the rest
  assert.equal((await adm.get('/api/settings/sso')).status, 403);
  assert.equal((await adm.call('PUT', '/api/settings/sso', {})).status, 403);

  const v0 = (await owner.get('/api/settings/sso')).json;
  assert.equal(v0.source, 'none'); assert.match(v0.redirectUri, /\/api\/auth\/oidc\/callback$/);
  assert.equal(v0.presets.jumpcloud.issuers.us, 'https://oauth.id.jumpcloud.com/');
  assert.equal((await new Client().get('/api/auth/state')).json.oidc, false);

  const SECRET = 'jc-client-secret-value-123';
  const body = { enabled: true, provider: 'jumpcloud', issuer: 'https://oauth.id.jumpcloud.com/', clientId: 'cm-client-id', groupsClaim: 'groups', scopes: 'openid email profile', buttonLabel: 'JumpCloud' };
  assert.equal((await owner.call('PUT', '/api/settings/sso', body)).json.fields.clientSecret, 'Paste the client secret.');
  assert.equal((await owner.call('PUT', '/api/settings/sso', { ...body, clientSecret: SECRET, issuer: 'http://oauth.id.jumpcloud.com/' })).status, 400);   // https only
  assert.equal((await owner.call('PUT', '/api/settings/sso', { ...body, clientSecret: SECRET, scopes: 'email profile' })).status, 400);                    // needs openid
  const saved = await owner.call('PUT', '/api/settings/sso', { ...body, clientSecret: SECRET });
  assert.equal(saved.status, 200); assert.equal(saved.json.source, 'saved'); assert.equal(saved.json.hasSecret, true);
  assert.ok(!saved.text.includes(SECRET));
  const stored = (await db.query(`SELECT value FROM app_settings WHERE key='sso.oidc'`)).rows[0].value;
  assert.ok(!JSON.stringify(stored).includes(SECRET)); assert.match(stored.secret, /^v1\./);

  const st = (await new Client().get('/api/auth/state')).json;
  assert.equal(st.oidc, true); assert.equal(st.oidcLabel, 'JumpCloud');

  // saving without a secret keeps it; turning it off hides the button
  assert.equal((await owner.call('PUT', '/api/settings/sso', { ...body, clientId: 'cm-client-id-2' })).json.hasSecret, true);
  await owner.call('PUT', '/api/settings/sso', { ...body, enabled: false });
  assert.equal((await new Client().get('/api/auth/state')).json.oidc, false);
  assert.equal((await new Client().get('/api/auth/oidc/login')).status, 404);

  // the audit log records what changed, never the secret
  const log = (await owner.get('/api/audit?action=settings.sso')).json.items;
  assert.ok(log.length >= 3); assert.ok(!JSON.stringify(log).includes(SECRET));
  assert.ok(log.some((l) => JSON.stringify(l).includes('clientSecret')));

  const cleared = (await owner.call('DELETE', '/api/settings/sso')).json;
  assert.equal(cleared.source, 'none');
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

test('configuration: owners change Bedrock and lookback limits; others cannot; limits apply to accounts', async () => {
  const put = (c, b) => c.call('PUT', '/api/settings', b);
  let r = await owner.get('/api/settings');
  assert.equal(r.status, 200);
  assert.equal(r.json.settings['ai.enabled'].overridden, false);
  assert.ok(Array.isArray(r.json.history));

  assert.equal((await put(owner, { 'ai.region': 'not a region' })).status, 400);
  assert.equal((await put(owner, { 'history.defaultLookbackDays': 400, 'history.maxLookbackDays': 180 })).status, 400);   // default above max
  r = await put(owner, { 'ai.enabled': true, 'ai.region': 'ap-southeast-1', 'ai.modelId': 'apac.anthropic.claude-sonnet-4-5-20250929-v1:0', 'history.maxLookbackDays': 180, 'history.sliceHours': 1 });
  assert.equal(r.status, 200); assert.equal(r.json.changed.length, 5);
  const { config } = await import('../src/config.js');
  assert.equal(config.ai.region, 'ap-southeast-1'); assert.equal(config.scanner.sliceHours, 1); assert.equal(config.scanner.maxLookbackDays, 180);
  r = await owner.get('/api/settings');
  assert.equal(r.json.settings['ai.region'].overridden, true);
  assert.equal((await owner.get('/api/settings/limits')).json.maxLookbackDays, 180);

  // an account cannot ask for more than the workspace maximum
  r = await owner.post('/api/accounts', { accountId: '999999999990', name: 'too-far', eventSource: 's3', s3: { bucket: 'kbi-org-trail' }, lookbackDays: 365 });
  assert.equal(r.status, 400, JSON.stringify(r.json)); assert.equal(r.json.field, 'lookbackDays', JSON.stringify(r.json));

  // reset to default, audited
  r = await put(owner, { 'ai.region': null, 'ai.enabled': null, 'ai.modelId': null, 'history.maxLookbackDays': null, 'history.sliceHours': null });
  assert.equal(r.status, 200);
  assert.equal(config.scanner.sliceHours, 6);
  const audit = await db.query(`SELECT count(*)::int n FROM audit_log WHERE action='settings.update'`);
  assert.ok(audit.rows[0].n >= 2);
  assert.equal((await owner.post('/api/settings/bedrock/test', {})).json.ok, false);              // demo mode does not call AWS

  assert.equal((await reviewerClient.get('/api/settings')).status, 403);
  assert.equal((await put(reviewerClient, { 'ai.enabled': true })).status, 403);
});

test('worker status: telemetry, lost-worker detection and advice', async () => {
  const tel = await import('../src/telemetry.js');
  tel.bump('events', 500);
  const s = tel.sample();
  assert.ok(s.rss > 0 && s.heapLimit > 0 && s.events >= 500);
  await q.workerRuntime(tel.runtime(2));
  await q.workerTelemetry(s);
  // a worker that died with its heap nearly full
  await db.query(`INSERT INTO workers(id, hostname, started_at, heartbeat_at, telemetry) VALUES ('dead-1','box', now() - interval '1 hour', now() - interval '5 minutes', $1)`,
    [JSON.stringify({ heapUsed: 470e6, heapLimit: 512e6 })]);
  const r = await owner.get('/api/ops/workers?range=1h');
  assert.equal(r.status, 200);
  const me = r.json.workers.find((w) => w.id === q.workerId);
  assert.ok(me.telemetry.heapLimit > 0 && me.series.length >= 1 && me.runtime.node);
  assert.equal(r.json.workers.find((w) => w.id === 'dead-1').end_reason, 'out-of-memory (likely)');
  assert.ok(r.json.advice.some((a) => a.level === 'critical' && a.area === 'memory'));
  assert.equal((await reviewerClient.get('/api/ops/workers')).status, 200);       // reviewers have ops
});

test('advice flags a heap too small for the container and a stalled read', async () => {
  const { advise } = await import('../src/workerStatus.js');
  const w = { alive: true, hostname: 'w1', concurrency: 2, series: [], telemetry: { heapUsed: 100e6, heapLimit: 512e6 }, runtime: { memLimit: 4096 * 1048576, heapLimit: 512e6, cgroup: 2, cpuLimit: 1, availableCores: 8 } };
  const out = advise({ workers: [w], reading: [{ kind: 'events', status: 'running', stalled: true, sinceProgressS: 1800, account_name: 'NonProduction', region: 'ap-southeast-1' }], fails: [], queue: { ready: 0, oldest_wait_s: 0 }, accounts: [] });
  assert.ok(out.some((a) => /max-old-space-size=3072/.test(a.fix || '')));
  assert.ok(out.some((a) => a.area === 'reading' && /no progress/.test(a.title)));
});

test('planned accounts: placeholders with no access, never scanned, onboarded later', async () => {
  const p = await owner.post('/api/accounts/planned', { name: 'management', accountId: '424242424242', environment: 'production', ou: 'Root', note: 'after the CAB' });
  assert.equal(p.status, 201); assert.equal(p.json.status, 'planned'); assert.equal(p.json.role_arn, null);
  // never scanned, and the normal connect form points at onboarding instead of duplicating it
  assert.equal((await owner.post(`/api/accounts/${p.json.id}/scan`)).json.error, 'planned');
  assert.equal((await owner.post('/api/accounts', { name: 'm', accountId: '424242424242' })).json.error, 'planned');
  // a planned account never holds the history bar back
  const st = await owner.get('/api/status');
  assert.ok(!st.json.reading.some((r) => r.id === p.json.id));
  // many at once: bad lines are reported, existing IDs are skipped
  assert.match((await owner.post('/api/accounts/planned/bulk', { text: '12345, x' })).json.message, /Line 1/);
  const bulk = await owner.post('/api/accounts/planned/bulk', { text: '# id, name, env, ou\n515151515151, network-hub, shared, Infra\n424242424242, management\n889900112233' });
  assert.equal(bulk.json.added, 2); assert.equal(bulk.json.updated, 0); assert.deepEqual(bulk.json.skipped, ['424242424242']);   // same details: unchanged
  const moved = await owner.post('/api/accounts/planned/bulk', { text: '424242424242, management, shared, Root' });
  assert.equal(moved.json.updated, 1);
  assert.equal((await owner.get(`/api/accounts/${p.json.id}`)).json.environment, 'shared');
  // static page code is revalidated on every load, so a deploy is picked up at once
  assert.equal((await owner.get('/js/main.js')).headers.get('cache-control'), 'no-cache');
  // editing a planned account changes details only
  const e = await owner.patch(`/api/accounts/${p.json.id}`, { name: 'org-management', authMode: 'access_key' });
  assert.equal(e.json.name, 'org-management'); assert.equal(e.json.status, 'planned'); assert.equal(e.json.auth_mode, 'assume_role');
  // onboarding sets up access and makes it scannable
  const o = await owner.patch(`/api/accounts/${p.json.id}`, { onboard: true, eventSource: 'event-history', authMode: 'assume_role', roleName: 'CuriousMonkeyScanner', regions: ['us-east-1'] });
  assert.equal(o.json.status, 'pending'); assert.equal(o.json.role_arn, 'arn:aws:iam::424242424242:role/CuriousMonkeyScanner'); assert.ok(o.json.onboarded_at);
  assert.equal((await owner.post(`/api/accounts/${p.json.id}/scan`)).status, 202);
});

test('environments: the defaults, accounts by name, rename in place, and removing one in use asks where its accounts go', async () => {
  const put = (body) => owner.call('PUT', '/api/environments', body);
  const list = (await owner.get('/api/environments')).json.environments;
  assert.deepEqual(list.map((e) => e.id), ['production', 'shared', 'staging', 'development', 'sandbox']);
  // an account can be given its environment by name, in any case
  const a = await owner.post('/api/accounts/planned', { accountId: '313131313131', name: 'env-test-stg', environment: 'Staging' });
  assert.equal(a.status, 201, a.text);
  const env = async () => (await db.query(`SELECT environment FROM cloud_accounts WHERE account_id='313131313131'`)).rows[0].environment;
  assert.equal(await env(), 'staging');
  assert.equal((await owner.post('/api/accounts/planned', { accountId: '323232323232', name: 'x', environment: 'qa' })).status, 400);

  // add one, rename staging: accounts stay where they are
  const next = list.map(({ id, name, color }) => ({ id, name: id === 'staging' ? 'Non-production' : name, color }));
  let r = await put({ environments: [...next, { name: 'QA', color: '#2fb5c4' }] });
  assert.equal(r.status, 200, r.text);
  assert.equal(r.json.environments.at(-1).id, 'qa');
  assert.equal(r.json.environments.find((e) => e.id === 'staging').name, 'Non-production');
  assert.equal(await env(), 'staging');
  assert.equal((await owner.post('/api/accounts/planned', { accountId: '323232323232', name: 'x', environment: 'qa' })).status, 201);

  // remove staging: refused while accounts use it, then their accounts move where asked
  const without = r.json.environments.filter((e) => e.id !== 'staging').map(({ id, name, color }) => ({ id, name, color }));
  const inStaging = (await db.query(`SELECT count(*)::int n FROM cloud_accounts WHERE environment='staging'`)).rows[0].n;
  r = await put({ environments: without });
  assert.equal(r.status, 409); assert.deepEqual(r.json.inUse, { staging: inStaging });
  r = await put({ environments: without, reassign: { staging: 'qa' } });
  assert.equal(r.status, 200, r.text);
  assert.deepEqual(r.json.moved, { staging: { to: 'qa', accounts: inStaging } });
  assert.equal(await env(), 'qa');
  // at least one, no two with the same name, a real colour; and it is in the audit log
  assert.equal((await put({ environments: [] })).status, 400);
  assert.equal((await put({ environments: [{ name: 'A', color: '#000000' }, { name: 'a', color: '#111111' }] })).status, 400);
  assert.equal((await put({ environments: [{ name: 'A', color: 'red' }] })).status, 400);
  assert.ok((await db.query(`SELECT 1 FROM audit_log WHERE action='settings.environments'`)).rowCount >= 2);
});

// ---------- alerts and thresholds ----------
import http from 'node:http';
/** A stand-in for Slack or a webhook: records each POST; a path with /fail answers 500. */
async function receiver() {
  const got = [];
  const srv = http.createServer((req, res) => {
    let body = ''; req.on('data', (c) => { body += c; });
    req.on('end', () => { got.push({ path: req.url, body: JSON.parse(body || 'null') }); res.writeHead(req.url.includes('/fail') ? 500 : 200).end('ok'); });
  }).listen(0);
  await new Promise((r) => srv.once('listening', r));
  return { got, url: (p) => `http://127.0.0.1:${srv.address().port}${p}`, close: () => srv.close() };
}

test('risk thresholds are workspace settings: the IAM users list follows them; out-of-range values are refused', async () => {
  const before = (await owner.get('/api/iam-users?limit=100')).json;
  assert.deepEqual(before.rules, { rotateDays: 90, staleDays: 90 });
  assert.equal((await owner.call('PUT', '/api/settings', { 'risk.keyRotateDays': 3 })).status, 400);
  assert.equal((await owner.call('PUT', '/api/settings', { 'risk.keyRotateDays': 700 })).status, 200);
  try {
    const after = (await owner.get('/api/iam-users?limit=100')).json;
    assert.equal(after.rules.rotateDays, 700);
    assert.ok(after.totals.oldKeys < before.totals.oldKeys, 'fewer keys are past a longer rotation age');
    assert.equal((await owner.get('/api/settings')).json.settings['risk.keyRotateDays'].value, 700);
  } finally { await owner.call('PUT', '/api/settings', { 'risk.keyRotateDays': null }); }
  assert.equal((await owner.get('/api/iam-users?limit=1')).json.rules.rotateDays, 90);
});

test('alert destinations: URL checked, stored encrypted, never shown; test message; only settings holders', async () => {
  const rx = await receiver();
  try {
    const slackBad = await owner.post('/api/alerts/destinations', { name: 'sec', kind: 'slack', url: rx.url('/hook') });
    assert.equal(slackBad.status, 400); assert.equal(slackBad.json.field, 'url'); assert.match(slackBad.json.message, /hooks\.slack\.com/);
    assert.equal((await owner.post('/api/alerts/destinations', { name: 'x', kind: 'webhook', url: 'not a url' })).status, 400);
    assert.equal((await reviewerClient.post('/api/alerts/destinations', { name: 'x', kind: 'webhook', url: rx.url('/a') })).status, 403);
    assert.equal((await reviewerClient.get('/api/alerts')).status, 403);
    const d = await owner.post('/api/alerts/destinations', { name: 'n8n', kind: 'webhook', url: rx.url('/ok/secret-token-123') });
    assert.equal(d.status, 201); assert.equal(d.json.urlHint.endsWith('…-123'), true);
    const page = await owner.get('/api/alerts');
    assert.ok(!page.text.includes('secret-token'), 'the URL is never returned');
    assert.ok(!(await db.query('SELECT url_enc FROM alert_destinations WHERE id=$1', [d.json.id])).rows[0].url_enc.includes('secret-token'), 'stored encrypted');
    const t = await owner.post(`/api/alerts/destinations/${d.json.id}/test`);
    assert.deepEqual([t.json.ok, t.json.status], [true, 200]);
    assert.equal(rx.got.at(-1).path, '/ok/secret-token-123'); assert.equal(rx.got.at(-1).body.kind, 'test'); assert.equal(rx.got.at(-1).body.source, 'curious-monkey');
    // a failing endpoint: reported, logged as failed (a test is not retried)
    const bad = await owner.post('/api/alerts/destinations', { name: 'broken', kind: 'webhook', url: rx.url('/fail') });
    const tb = await owner.post(`/api/alerts/destinations/${bad.json.id}/test`);
    assert.deepEqual([tb.json.ok, tb.json.status], [false, 500]);
    const log = (await owner.get('/api/alerts')).json.deliveries;
    assert.equal(log[0].status, 'failed'); assert.equal(log[0].kind, 'test'); assert.equal(log[1].status, 'sent');
    assert.ok((await owner.get('/api/audit?action=alert.destination.test')).json.items.length >= 2);
    for (const id of [d.json.id, bad.json.id]) assert.equal((await owner.call('DELETE', `/api/alerts/destinations/${id}`)).status, 200);
  } finally { rx.close(); }
});

test('alert URL rules in production: https only, no loopback or metadata service; private addresses allowed', async () => {
  const { urlProblem } = await import('../src/alerts.js');
  const { config } = await import('../src/config.js');
  const was = config.env; config.env = 'production';
  try {
    for (const u of ['http://hooks.example.com/x', 'https://169.254.169.254/latest', 'https://[::1]/x', 'https://[::ffff:127.0.0.1]/x', 'https://localhost/x', 'https://2130706433/x', 'https://metadata.google.internal/x', 'https://u:p@example.com/x'])
      assert.ok(urlProblem(u, 'webhook'), `refused: ${u}`);
    for (const u of ['https://n8n.internal.example/webhook/abc', 'https://10.0.4.12/hook', 'https://hooks.example.com/x']) assert.equal(urlProblem(u, 'webhook'), null, `allowed: ${u}`);
    assert.equal(urlProblem('https://hooks.slack.com/services/T0/B0/xyz', 'slack'), null);
    assert.ok(urlProblem('https://hooks.slack.com.evil.example/services/x', 'slack'));
  } finally { config.env = was; }
});

test('alert rules: new findings only (no backlog), one message per batch, sent once; a condition posts what is true now', async () => {
  const rx = await receiver();
  const { alertsTick } = await import('../src/alerts.js');
  const rules = [];
  try {
    const dest = (await owner.post('/api/alerts/destinations', { name: 'hook', kind: 'webhook', url: rx.url('/ok/1') })).json;
    const mk = async (b) => { const r = await owner.post('/api/alerts/rules', { destinationId: dest.id, ...b }); assert.equal(r.status, 201, r.text); rules.push(r.json.id); return r.json; };
    assert.equal((await owner.post('/api/alerts/rules', { name: 'x', trigger: 'finding', destinationId: '00000000-0000-4000-8000-000000000000' })).status, 400);
    await mk({ name: 'New High finding', trigger: 'finding', minSeverity: 'high' });
    await alertsTick();
    assert.equal(rx.got.length, 0, 'findings from before the rule are not posted');
    // two findings appear: one high, one low
    const hi = (await db.query(`SELECT f.id, f.title FROM flags f WHERE status='open' AND severity='high' LIMIT 1`)).rows[0];
    const lo = (await db.query(`SELECT f.id FROM flags f WHERE status='open' AND severity='low' LIMIT 1`)).rows[0];
    await db.query(`UPDATE flags SET created_at = now() WHERE id = ANY($1::uuid[])`, [[hi.id, lo?.id].filter(Boolean)]);
    let r = await alertsTick();
    assert.equal(r.sent, 1); assert.equal(rx.got.length, 1);
    const msg = rx.got[0].body;
    assert.equal(msg.count, 1); assert.equal(msg.items[0].title, hi.title); assert.equal(msg.items[0].severity, 'high');
    assert.match(msg.items[0].url, /#\/identities\/[\w-]+\?tab=findings$/); assert.equal(msg.rule.trigger, 'finding');
    await alertsTick(); assert.equal(rx.got.length, 1, 'each finding is posted once');

    // a condition: every active key past the rotation age, in one message, once
    await mk({ name: 'Old keys', trigger: 'key-age' });
    r = await alertsTick();
    const old = (await db.query(`SELECT k.key_id FROM iam_access_keys k JOIN roles r ON r.id=k.role_id WHERE k.status='Active' AND k.deleted_at IS NULL AND r.deleted_at IS NULL AND k.created_at < now() - interval '90 days'`)).rows;
    assert.ok(old.length > 1); assert.equal(rx.got.length, 2); assert.equal(rx.got[1].body.count, old.length);
    await alertsTick(); assert.equal(rx.got.length, 2);
    // rotated: forgotten; old again: posted again
    const k = old[0].key_id;
    const was = (await db.query(`UPDATE iam_access_keys SET created_at = now() WHERE key_id=$1 RETURNING (SELECT created_at FROM iam_access_keys WHERE key_id=$1) AS prev`, [k])).rows[0].prev;
    await alertsTick();
    await db.query(`UPDATE iam_access_keys SET created_at = $2 WHERE key_id=$1`, [k, was]);
    await alertsTick();
    assert.equal(rx.got.length, 3); assert.equal(rx.got[2].body.count, 1); assert.match(rx.got[2].body.items[0].title, new RegExp(k));

    // the page: rules with their destination, the log newest first
    const page = (await owner.get('/api/alerts')).json;
    assert.equal(page.rules.length, 2); assert.ok(page.rules.every((x) => x.destinationName === 'hook'));
    assert.equal(page.deliveries.filter((x) => x.status === 'sent' && x.kind === 'instant').length, 3);
    assert.equal((await owner.call('DELETE', `/api/alerts/destinations/${dest.id}`)).status, 409, 'a destination in use cannot be removed');
  } finally {
    for (const id of rules) await owner.call('DELETE', `/api/alerts/rules/${id}`);
    await db.query('DELETE FROM alert_destinations'); rx.close();
  }
});

test('alert rules: Radar changes by kind; a failed post is retried once, then marked failed; daily digests wait for their hour', async () => {
  const rx = await receiver();
  const { alertsTick } = await import('../src/alerts.js');
  const rules = [];
  try {
    const ok = (await owner.post('/api/alerts/destinations', { name: 'ok', kind: 'webhook', url: rx.url('/ok/2') })).json;
    const bad = (await owner.post('/api/alerts/destinations', { name: 'down', kind: 'webhook', url: rx.url('/fail') })).json;
    const mk = async (b) => { const r = await owner.post('/api/alerts/rules', b); assert.equal(r.status, 201, r.text); rules.push(r.json.id); return r.json; };
    const role = (await db.query(`SELECT id, account_id FROM roles WHERE kind <> 'iam-user' AND deleted_at IS NULL LIMIT 1`)).rows[0];
    const change = (kind, sev, key) => db.query(`INSERT INTO changes(account_id, role_id, kind, severity, title, detail, dedupe) VALUES ($1,$2,$3,$4,$5,'d',$6)`, [role.account_id, role.id, kind, sev, `${kind} happened`, key]);
    await change('new-caller', 'high', 'old-one');                  // before the rule: not posted
    await mk({ name: 'Callers', trigger: 'change', changeKinds: ['new-caller'], minSeverity: 'high', destinationId: ok.id });
    await change('new-caller', 'high', 'a'); await change('new-caller', 'warn', 'b'); await change('grew', 'high', 'c');
    await alertsTick();
    assert.equal(rx.got.length, 1); assert.equal(rx.got[0].body.count, 1); assert.equal(rx.got[0].body.items[0].kind, 'new-caller');

    // retry: first failure waits, second is final
    const mfa = await mk({ name: 'No MFA', trigger: 'console-no-mfa', destinationId: bad.id });
    await alertsTick();
    let d = (await db.query(`SELECT * FROM alert_deliveries WHERE rule_id=$1`, [mfa.id])).rows;
    assert.equal(d.length, 1); assert.deepEqual([d[0].status, d[0].attempts, d[0].http_status], ['pending', 1, 500]);
    await alertsTick();
    assert.equal((await db.query(`SELECT attempts FROM alert_deliveries WHERE id=$1`, [d[0].id])).rows[0].attempts, 1, 'not before its time');
    await db.query(`UPDATE alert_deliveries SET next_attempt_at = now() WHERE id=$1`, [d[0].id]);
    const r = await alertsTick();
    d = (await db.query(`SELECT * FROM alert_deliveries WHERE id=$1`, [d[0].id])).rows;
    assert.deepEqual([d[0].status, d[0].attempts, d[0].error], ['failed', 2, 'Answered 500.']); assert.equal(r.failed, 1);
    await owner.call('PUT', `/api/alerts/rules/${mfa.id}`, { enabled: false });

    // daily: collected all day, sent once after the digest hour (09:00 Jakarta = 02:00 UTC)
    const daily = await mk({ name: 'Keys daily', trigger: 'key-age', mode: 'daily', destinationId: ok.id });
    const n = rx.got.length;
    await alertsTick(new Date('2030-01-02T00:30:00Z'));                // 07:30 local
    assert.equal(rx.got.length, n);
    assert.ok((await owner.get('/api/alerts')).json.rules.find((x) => x.id === daily.id).waiting > 0);
    await alertsTick(new Date('2030-01-02T02:30:00Z'));                // 09:30 local
    assert.equal(rx.got.length, n + 1); assert.equal(rx.got.at(-1).body.kind, 'daily'); assert.match(rx.got.at(-1).body.title, /^Daily digest · Keys daily/);
    await alertsTick(new Date('2030-01-02T05:00:00Z'));
    assert.equal(rx.got.length, n + 1, 'one digest a day');

    // switched off and on: starts again from now
    await owner.call('PUT', `/api/alerts/rules/${rules[0]}`, { enabled: false });
    await change('new-caller', 'high', 'while-off');
    await owner.call('PUT', `/api/alerts/rules/${rules[0]}`, { enabled: true });
    const m = rx.got.length; await alertsTick(); assert.equal(rx.got.length, m, 'what happened while off is not posted');
  } finally {
    for (const id of rules) await owner.call('DELETE', `/api/alerts/rules/${id}`);
    await db.query(`DELETE FROM changes WHERE dedupe IN ('old-one','a','b','c','while-off')`);
    await db.query('DELETE FROM alert_destinations'); rx.close();
  }
});

test('alert messages for Slack: escaped, one line per match, the rest counted with a link', async () => {
  const { slackBody } = await import('../src/alerts.js');
  const items = Array.from({ length: 3 }, (_, i) => ({ title: `<b>&${i}|x`, subject: 'role', account: 'prod', environment: 'production', severity: 'high', url: `https://cm/#/i/${i}` }));
  const b = slackBody({ kind: 'instant', rule: { name: 'R' }, count: 60, items, more: 'https://cm/#/findings' });
  assert.match(b.text, /^\*R · 60 new\*/);
  assert.ok(b.text.includes('<https://cm/#/i/0|&lt;b&gt;&amp;0/x>'), b.text);
  assert.equal(b.text.split('\n').filter((l) => l.startsWith('•')).length, 3);
  assert.match(b.text, /…and 57 more\. <https:\/\/cm\/#\/findings\|See them all>/);
});

test('alert rules by account; old messages are removed without posting their matches again', async () => {
  const rx = await receiver();
  const { alertsTick, pruneDeliveries } = await import('../src/alerts.js');
  const { config } = await import('../src/config.js');
  const rules = [];
  try {
    const dest = (await owner.post('/api/alerts/destinations', { name: 'acct', kind: 'webhook', url: rx.url('/ok/3') })).json;
    // an account that does not exist is refused; one that does is kept and shown
    assert.equal((await owner.post('/api/alerts/rules', { name: 'x', trigger: 'key-age', accounts: ['00000000-0000-4000-8000-000000000000'], destinationId: dest.id })).status, 400);
    const keyIn = async (acct) => (await db.query(`SELECT count(*)::int n FROM iam_access_keys k JOIN roles r ON r.id=k.role_id WHERE r.account_id=$1 AND k.status='Active'
      AND k.deleted_at IS NULL AND r.deleted_at IS NULL AND k.created_at < now() - interval '90 days'`, [acct])).rows[0].n;
    const [inA, inB] = [await keyIn(accA), await keyIn(accB)];
    assert.ok(inA > 0 && inB > 0, 'the demo has old keys in both accounts');
    const r = await owner.post('/api/alerts/rules', { name: 'Old keys in A', trigger: 'key-age', accounts: [accA], destinationId: dest.id });
    assert.equal(r.status, 201, r.text); rules.push(r.json.id); assert.deepEqual(r.json.accounts, [accA]);
    await alertsTick();
    assert.equal(rx.got.length, 1); assert.equal(rx.got[0].body.count, inA, 'only account A');
    // widened to both: only B's keys are new
    assert.equal((await owner.call('PUT', `/api/alerts/rules/${r.json.id}`, { accounts: [accA, accB] })).status, 200);
    await alertsTick();
    assert.equal(rx.got.length, 2); assert.equal(rx.got[1].body.count, inB);

    // the messages age out: removed, but their matches stay sent
    const before = (await db.query('SELECT count(*)::int n FROM alert_deliveries WHERE rule_id=$1', [r.json.id])).rows[0].n;
    assert.equal(before, 2);
    await db.query(`UPDATE alert_deliveries SET created_at = now() - make_interval(days => $1 + 1) WHERE rule_id=$2`, [config.alerts.keepDays, r.json.id]);
    assert.ok(await pruneDeliveries(new Date(), { force: true }) >= 2);
    assert.equal((await db.query('SELECT count(*)::int n FROM alert_deliveries WHERE rule_id=$1', [r.json.id])).rows[0].n, 0);
    await alertsTick();
    assert.equal(rx.got.length, 2, 'nothing is posted again');
    assert.equal((await owner.get('/api/alerts')).json.rules.find((x) => x.id === r.json.id).waiting, 0);
    // the setting is saved like the rest of Configuration
    assert.equal((await owner.call('PUT', '/api/settings', { 'alerts.keepDays': 3 })).status, 400);
    assert.equal((await owner.call('PUT', '/api/settings', { 'alerts.keepDays': 30 })).status, 200);
    assert.equal((await owner.get('/api/alerts')).json.keepDays, 30);
    await owner.call('PUT', '/api/settings', { 'alerts.keepDays': null });
  } finally {
    for (const id of rules) await owner.call('DELETE', `/api/alerts/rules/${id}`);
    await db.query('DELETE FROM alert_destinations'); rx.close();
  }
});

test('search has trigram indexes, and a %text% search over a large estate uses them', async () => {
  const idx = (await db.query(`SELECT indexname FROM pg_indexes WHERE indexname LIKE '%_trgm'`)).rows.map((x) => x.indexname).sort();
  assert.deepEqual(idx, ['gcp_principals_display_trgm', 'gcp_principals_email_trgm', 'gcp_principals_member_trgm', 'iam_access_keys_id_trgm', 'roles_arn_trgm', 'roles_name_trgm']);
  const c = await db.pool.connect();
  try {
    await c.query('BEGIN');
    // an estate-sized table (rolled back afterwards), so the planner judges it as it would in production
    await c.query(`INSERT INTO roles(account_id, arn, name, kind, granted_count, trust_policy)
      SELECT $1, 'arn:aws:iam::222222222222:role/bulk-' || i, 'bulk-' || md5(i::text), 'custom', 1, '{}' FROM generate_series(1, 20000) i`, [accB]);
    // new rows wait in GIN's pending list until autovacuum flushes it; do that now, as a running estate would have
    await c.query(`SELECT gin_clean_pending_list('roles_name_trgm'), gin_clean_pending_list('roles_arn_trgm')`);
    await c.query('ANALYZE roles');
    const plan = (await c.query(`EXPLAIN SELECT id FROM roles r WHERE r.deleted_at IS NULL AND (r.name ILIKE '%deploy%' OR r.arn ILIKE '%deploy%')`)).rows.map((x) => x['QUERY PLAN']).join('\n');
    assert.match(plan, /roles_(name|arn)_trgm/, plan);
    await c.query('ROLLBACK');
  } finally { c.release(); }
});

// ---------- CSV exports and access reviews ----------
/** A fresh member limited to account B (the one from the RBAC test may be signed out by now). */
async function memberOfB(email) {
  const inv = await owner.post('/api/members/invite', { email, role: 'account_owner', scope_accounts: [accB] });
  const c = new Client(); await c.post('/api/auth/signup', { name: email, email, password: PW, invite: inv.json.link.split('invite=')[1] });
  return c;
}
const parseCsv = (text) => text.trim().split('\n').map((l) => l.match(/("([^"]|"")*"|[^,]*)(,|$)/g).map((c) => c.replace(/,$/, '').replace(/^"|"$/g, '').replace(/""/g, '"')));

test('CSV: the Roles and IAM users lists download with their filters, scoped, formula-safe', async () => {
  const all = await owner.call('GET', '/api/roles.csv');
  assert.equal(all.status, 200); assert.match(all.headers.get('content-type'), /text\/csv/); assert.match(all.headers.get('content-disposition'), /roles-\d{4}-\d{2}-\d{2}\.csv/);
  const rows = parseCsv(all.text);
  assert.equal(rows[0][0], 'Account'); assert.equal(rows.length - 1, (await owner.get('/api/roles?limit=1')).json.total);
  const high = parseCsv((await owner.call('GET', '/api/roles.csv?risks=High')).text);
  assert.ok(high.slice(1).every((r) => r[rows[0].indexOf('Risk')] === 'High')); assert.ok(high.length < rows.length);
  // a member limited to account B gets only B
  const scoped = parseCsv((await (await memberOfB('csv-b@kbi.id')).call('GET', '/api/roles.csv')).text);
  assert.ok(scoped.length > 1 && scoped.slice(1).every((r) => r[1] === '222222222222'));
  // IAM users: one line per key
  const u = parseCsv((await owner.call('GET', '/api/iam-users.csv')).text);
  const keys = (await owner.get('/api/iam-users?limit=200')).json.items.reduce((n, x) => n + Math.max(1, x.keys.length), 0);
  assert.equal(u.length - 1, keys); assert.ok(u[0].includes('Access key') && u[0].includes('Rotate'));
  assert.equal((await new Client().call('GET', '/api/roles.csv')).status, 401);
  const { toCsv } = await import('../src/csv.js');
  assert.equal(toCsv([['x', (r) => r]], ['=HYPERLINK("evil")', '-1', 'ok']), `x\n"'=HYPERLINK(""evil"")"\n'-1\nok\n`);
});

test('access reviews: a frozen snapshot, filtered and exported; both teams sign off; a signed review stays', async () => {
  const from = new Date(Date.now() - 30 * 864e5).toISOString().slice(0, 10), to = new Date().toISOString().slice(0, 10);
  // checks on the way in
  assert.equal((await owner.post('/api/reviews', { name: 'x', accounts: [accA], from: to, to: from })).json.field, 'to');
  assert.equal((await owner.post('/api/reviews', { name: 'x', accounts: [accA], from, to: '2999-01-01' })).status, 400);
  assert.equal((await owner.post('/api/reviews', { name: 'x', accounts: [], from, to })).status, 400);
  assert.equal((await reviewerClient.post('/api/reviews', { name: 'x', accounts: ['00000000-0000-4000-8000-000000000000'], from, to })).status, 400);
  const onlyB = await memberOfB('review-b@kbi.id');
  assert.equal((await onlyB.post('/api/reviews', { name: 'x', accounts: [accA], from, to })).status, 403, 'an account owner cannot create reviews');
  const c = await owner.post('/api/reviews', { name: 'Q4 2026 access review', accounts: [accA, accB], from, to });
  assert.equal(c.status, 201, c.text);
  const id = c.json.id;
  const r = (await owner.get(`/api/reviews/${id}`)).json;
  const live = (await owner.get('/api/roles?kinds=&limit=1')).json.total + (await owner.get('/api/iam-users?limit=1')).json.total;
  assert.equal(r.totals.identities, live); assert.equal(r.accounts.length, 2); assert.deepEqual(r.teams, ['infrasec', 'infosec']); assert.equal(r.status, 'open');
  assert.equal(r.from, from); assert.equal(r.createdBy, (await owner.get('/api/auth/me')).json.user.name);
  // items: paged and filtered
  const page = (await owner.get(`/api/reviews/${id}/items?limit=10`)).json;
  assert.equal(page.items.length, 10); assert.equal(page.total, live);
  const one = page.items[0];
  assert.ok(one.name && one.arn && one.permissions && one.period && Array.isArray(one.callers) && Array.isArray(one.findings));
  assert.ok((await owner.get(`/api/reviews/${id}/items?kind=users&limit=200`)).json.items.every((x) => x.kind === 'iam-user' && x.user && Array.isArray(x.user.keys)));
  assert.ok((await owner.get(`/api/reviews/${id}/items?risk=High&limit=200`)).json.items.every((x) => x.risk === 'High'));
  assert.ok((await owner.get(`/api/reviews/${id}/items?account=${accB}&limit=200`)).json.items.every((x) => x.awsAccountId === '222222222222'));
  const unused = (await owner.get(`/api/reviews/${id}/items?unused=1&limit=200`)).json;
  assert.equal(unused.total, r.totals.unusedInPeriod); assert.ok(unused.items.every((x) => x.period.calls === 0));
  // frozen: a later change does not show
  const victim = page.items[0];
  await db.query(`UPDATE roles SET risk='Low' WHERE arn=$1`, [victim.arn]);
  try { assert.equal((await owner.get(`/api/reviews/${id}/items?limit=1`)).json.items[0].risk, victim.risk); }
  finally { await db.query(`UPDATE roles SET risk=$2 WHERE arn=$1`, [victim.arn, victim.risk]); }
  // CSVs
  const ids = parseCsv((await owner.call('GET', `/api/reviews/${id}/identities.csv`)).text);
  assert.equal(ids.length - 1, live); assert.equal(ids[1][0], 'Q4 2026 access review');
  const dec = parseCsv((await owner.call('GET', `/api/reviews/${id}/decisions.csv`)).text);
  assert.equal(dec[0][5], 'Finding'); assert.ok(dec.length > 1);
  // who sees it: a member limited to B cannot see a review that covers A
  assert.equal((await onlyB.get(`/api/reviews/${id}`)).status, 404);
  assert.ok(!(await onlyB.get('/api/reviews')).json.items.some((x) => x.id === id));
  // sign-off: one per team; a member with no team or no approve permission cannot
  assert.equal((await onlyB.post(`/api/reviews/${id}/signoff`, {})).status, 403);
  assert.equal((await reviewerClient.post(`/api/reviews/${id}/signoff`, { note: 'Reviewed with the platform leads' })).status, 200);
  assert.equal((await reviewerClient.post(`/api/reviews/${id}/signoff`, {})).status, 409);
  assert.equal((await owner.call('DELETE', `/api/reviews/${id}`)).status, 409, 'a signed-off review is evidence');
  const me = (await owner.get('/api/auth/me')).json.user;
  await db.query(`UPDATE users SET team='infosec' WHERE id=$1`, [me.id]);
  try {
    const s = await owner.post(`/api/reviews/${id}/signoff`, {});
    assert.equal(s.status, 200); assert.equal(s.json.signed, true);
    const done = (await owner.get(`/api/reviews/${id}`)).json;
    assert.equal(done.status, 'signed'); assert.deepEqual(done.signoffs.map((x) => x.team), ['infrasec', 'infosec']);
    assert.equal(done.signoffs[0].note, 'Reviewed with the platform leads');
  } finally { await db.query(`UPDATE users SET team=$2 WHERE id=$1`, [me.id, me.team ?? null]); }
  assert.ok((await owner.get('/api/audit?action=review.signoff')).json.items.length >= 2);
  // an unsigned one can be removed
  const tmp = (await owner.post('/api/reviews', { name: 'tmp', accounts: [accB], from, to, teams: ['infosec'] })).json.id;
  assert.equal((await owner.call('DELETE', `/api/reviews/${tmp}`)).status, 200);
  assert.equal((await owner.get(`/api/reviews/${tmp}`)).status, 404);
});

test('display time zone: a workspace setting, validated, sent with the session', async () => {
  assert.equal((await owner.get('/api/auth/me')).json.display.timeZone, 'Asia/Jakarta');
  const bad = await owner.call('PUT', '/api/settings', { 'display.timeZone': 'Mars/Olympus_Mons' });
  assert.equal(bad.status, 400);
  assert.equal((await owner.call('PUT', '/api/settings', { 'display.timeZone': 'Asia/Singapore' })).status, 200);
  try {
    assert.equal((await owner.get('/api/auth/me')).json.display.timeZone, 'Asia/Singapore');
    assert.equal((await reviewerClient.get('/api/auth/me')).json.display.timeZone, 'Asia/Singapore', 'every member gets it, not only those who may change settings');
  } finally { await owner.call('PUT', '/api/settings', { 'display.timeZone': null }); }
  assert.equal((await owner.get('/api/auth/me')).json.display.timeZone, 'Asia/Jakarta');
});

test('change feed: the bell counts what is new by when it was recorded, Radar shows a range; seen is per person; scoped', async () => {
  const role = (await db.query(`SELECT id FROM roles WHERE account_id=$1 AND deleted_at IS NULL LIMIT 1`, [accA])).rows[0].id;
  const add = (key, daysAgo, sev = 'high') => db.query(`INSERT INTO changes(account_id, role_id, kind, severity, title, detail, dedupe, at) VALUES ($1,$2,'new-caller',$3,$4,'x',$5, now() - make_interval(days => $6)) RETURNING id`,
    [accA, role, sev, `feed test ${key}`, `feedtest:${key}`, daysAgo]);
  try {
    await add('recent', 0);
    await owner.post('/api/changes/seen');
    assert.equal((await owner.get('/api/changes/unread')).json.count, 0, 'everything seen');
    // recorded now, but it happened five days ago (a new caller found in older history): still new
    await add('late', 5, 'warn');
    const u = (await owner.get('/api/changes/unread')).json;
    assert.equal(u.count, 1); assert.equal(u.worst, 'warn'); assert.equal(u.items[0].title, 'feed test late');
    const week = (await owner.get('/api/changes?days=7')).json;
    assert.equal(week.days, 7); assert.ok(week.items.find((x) => x.title === 'feed test late').unread);
    assert.equal(week.items.find((x) => x.title === 'feed test recent').unread, false);
    assert.ok(!(await owner.get('/api/changes?days=1')).json.items.some((x) => x.title === 'feed test late'), 'outside the range');
    assert.equal((await owner.get('/api/changes?days=13')).json.days, 7, 'an odd range falls back to 7 days');
    // seen is per person: the reviewer has not looked yet
    assert.ok((await reviewerClient.get('/api/changes/unread')).json.count >= 2);
    await owner.post('/api/changes/seen');
    assert.equal((await owner.get('/api/changes/unread')).json.count, 0);
    assert.ok((await reviewerClient.get('/api/changes/unread')).json.count >= 2);
    // a member limited to account B does not see A's changes
    const onlyB = await memberOfB('feed-b@kbi.id');
    assert.ok(!(await onlyB.get('/api/changes/unread')).json.items.some((x) => x.title.startsWith('feed test')));
    assert.equal((await owner.get('/api/space/flags')).status, 404, 'the old bell endpoint is gone');
  } finally { await db.query(`DELETE FROM changes WHERE dedupe LIKE 'feedtest:%'`); }
});
