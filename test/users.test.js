import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { startPg } from './helpers/pg.js';
import { userFindings, withUserRisk } from '../src/analyzer/users.js';

process.env.AWS_MODE = 'demo'; process.env.LOOKUP_DELAY_MS = '0';
const DAY = 864e5, ago = (d) => new Date(Date.now() - d * DAY).toISOString();

// ---------------------------------------------------------------- the rules
test('credentials: old, unused and doubled keys; console passwords without MFA or unused', () => {
  const ids = (f) => f.map((x) => x.id);
  assert.deepEqual(ids(userFindings({ details: null, keys: [{ key_id: 'A', status: 'Active', created_at: ago(30), last_used_at: ago(1) }] })), []);
  const old = userFindings({ details: null, keys: [{ key_id: 'A', status: 'Active', created_at: ago(400), last_used_at: ago(1) }, { key_id: 'B', status: 'Active', created_at: ago(100), last_used_at: null }] });
  assert.deepEqual(ids(old), ['key-old', 'key-old', 'key-unused', 'key-two']);
  assert.equal(old[0].points, 25); assert.equal(old[1].points, 15);
  assert.deepEqual(ids(userFindings({ details: null, keys: [{ key_id: 'C', status: 'Inactive', created_at: ago(900) }] })), []);   // an inactive key cannot be used
  assert.deepEqual(ids(userFindings({ details: null, keys: [{ key_id: 'D', status: 'Active', created_at: ago(60), last_used_at: ago(120), trail_last_seen: ago(2) }] })), []);   // CloudTrail saw it recently
  const con = userFindings({ details: { password_enabled: true, password_created: ago(400), password_last_used: ago(200), mfa: [] }, keys: [{ key_id: 'E', status: 'Active', created_at: ago(10), last_used_at: ago(1) }] });
  assert.deepEqual(ids(con), ['console-no-mfa', 'password-unused', 'console-and-keys']);
  const r = withUserRisk({ risk: 'Low', riskScore: 5, riskReasons: ['x'] }, con);
  assert.equal(r.risk, 'High'); assert.equal(r.riskScore, 50); assert.equal(r.riskReasons.at(-1), 'x');
});

// ---------------------------------------------------------------- scanned, through the API
let pg, db, q, w, server, base, totp;
before(async () => {
  pg = await startPg(54362);
  db = await import('../src/db.js');
  await (await import('../src/migrate.js')).migrate(() => {});
  q = await import('../src/queue.js'); w = await import('../src/worker.js'); totp = await import('../src/auth/totp.js');
  const { createApp } = await import('../src/server.js');
  server = createApp().listen(0); base = `http://127.0.0.1:${server.address().port}`;
  await q.registerWorker();
});
after(async () => { server?.close(); await db?.closePool(); await pg?.stop(); });
class Client {
  constructor() { this.cookie = ''; this.csrf = ''; }
  async call(method, path, body) {
    const headers = { 'content-type': 'application/json' };
    if (this.cookie) headers.cookie = this.cookie; if (this.csrf) headers['x-csrf-token'] = this.csrf;
    const r = await fetch(base + path, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
    const sc = r.headers.get('set-cookie'); if (sc) this.cookie = sc.split(';')[0];
    const text = await r.text(); let json = null; try { json = JSON.parse(text); } catch { /* not json */ }
    if (json?.csrf) this.csrf = json.csrf;
    return { status: r.status, json };
  }
  get(p) { return this.call('GET', p); } post(p, b) { return this.call('POST', p, b ?? {}); }
}
const PW = 'correct horse battery staple';
const owner = new Client();
async function drain() { for (let j; (j = await q.claimJob());) { try { await w.runJob(j); } catch (e) { await q.failJob(j, e); } } }
let A, B;

test('a scan inventories IAM users with their keys, console sign-in, MFA, groups and group policies', async () => {
  await owner.post('/api/auth/signup', { name: 'Owner', email: 'owner@acme.example', password: PW, workspaceName: 'Acme' });
  const s = await owner.post('/api/auth/mfa/start'); await owner.post('/api/auth/mfa/confirm', { code: totp.code(s.json.secret) });
  A = (await owner.post('/api/accounts', { name: 'payments-prod', accountId: '111111111111', regions: ['ap-southeast-3'] })).json.id;
  B = (await owner.post('/api/accounts', { name: 'data-platform-stg', accountId: '222222222222', environment: 'staging', regions: ['ap-southeast-3'] })).json.id;
  await owner.post(`/api/accounts/${A}/verify`); await owner.post(`/api/accounts/${B}/verify`);
  await drain();
  const users = (await db.query(`SELECT r.name, d.password_enabled, d.groups, jsonb_array_length(d.mfa) AS mfa FROM roles r JOIN iam_user_details d ON d.role_id=r.id WHERE r.account_id=$1 ORDER BY r.name`, [A])).rows;
  assert.deepEqual(users.map((u) => u.name), ['alice.admin', 'ci-legacy', 'old-reporting', 'snapshot-bot']);
  const alice = users[0];
  assert.equal(alice.password_enabled, true); assert.deepEqual(alice.groups, ['Admins']); assert.equal(alice.mfa, 1);
  const pol = (await db.query(`SELECT p.kind, p.name FROM role_policies p JOIN roles r ON r.id=p.role_id WHERE r.account_id=$1 AND r.name='alice.admin'`, [A])).rows;
  assert.deepEqual(pol, [{ kind: 'group', name: 'Admins/AdministratorAccess' }]);
  const keys = (await db.query(`SELECT r.name, k.status, k.trail_calls, k.created_at FROM iam_access_keys k JOIN roles r ON r.id=k.role_id WHERE r.account_id=$1 ORDER BY r.name, k.created_at`, [A])).rows;
  assert.deepEqual(keys.map((k) => `${k.name}:${k.status}`), ['ci-legacy:Inactive', 'ci-legacy:Active', 'old-reporting:Active', 'snapshot-bot:Active']);
  assert.ok(Number(keys.find((k) => k.name === 'ci-legacy' && k.status === 'Active').trail_calls) > 0, 'CloudTrail calls counted on the key');
  assert.equal(Number(keys.find((k) => k.name === 'old-reporting').trail_calls), 0);
});

test("a user's calls are attributed to the key that made them and analysed like a role's", async () => {
  const ci = (await db.query(`SELECT * FROM roles WHERE account_id=$1 AND name='ci-legacy'`, [A])).rows[0];
  const who = (await db.query(`SELECT key, kind FROM principals WHERE role_id=$1`, [ci.id])).rows;
  assert.equal(who.length, 1); assert.match(who[0].key, /^key:AKIA[0-9A-F]{16}$/); assert.equal(who[0].kind, 'access-key');
  assert.ok(ci.used_count >= 2 && ci.unused_count > 0, JSON.stringify({ used: ci.used_count, unused: ci.unused_count }));
  // no session is kept for a long-lived key: Event history stays about role sessions
  assert.equal((await db.query(`SELECT count(*)::int n FROM track_sessions WHERE role_id=$1`, [ci.id])).rows[0].n, 0);
  assert.ok(ci.risk_reasons.some((r) => /Access key AKIA\w+ is \d+ days old/.test(r)));
});

test('the IAM users page: riskiest first, keys with age and last use, filters and totals', async () => {
  const r = (await owner.get('/api/iam-users?limit=100')).json;
  assert.equal(r.total, 8);                                                   // 4 per account
  assert.equal(r.items[0].risk, 'High');
  const by = (n, acct = 'payments-prod') => r.items.find((u) => u.name === n && u.account.name === acct);
  assert.equal(by('alice.admin').risk, 'High');                               // AdministratorAccess through a group
  const vendor = by('vendor-sync', 'data-platform-stg');
  assert.equal(vendor.flags.noMfa, true); assert.ok(vendor.reasons.includes('Console password without MFA'));
  const old = by('old-reporting');
  assert.equal(old.keys[0].neverUsed, true); assert.ok(old.keys[0].ageDays >= 799); assert.equal(old.flags.unusedKey, true); assert.equal(old.flags.oldKey, true);
  const ci = by('ci-legacy');
  assert.deepEqual(ci.keys.map((k) => k.status), ['Active', 'Inactive']);
  assert.ok(ci.keys[0].lastUsed && ci.keys[0].idleDays <= 1 && ci.keys[0].trailCalls > 0);
  assert.match(ci.keys[0].id, /^AKIA/);
  assert.equal(r.totals.users, 8); assert.equal(r.totals.consoleNoMfa, 1); assert.equal(r.totals.activeKeys, 7);
  assert.ok(r.totals.oldKeys >= 4);
  assert.deepEqual((await owner.get('/api/iam-users?flag=noMfa')).json.items.map((u) => u.name), ['vendor-sync']);
  assert.deepEqual((await owner.get(`/api/iam-users?accounts=${B}&q=snapshot`)).json.items.map((u) => u.account.name), ['data-platform-stg']);
  assert.equal((await owner.get('/api/iam-users?sort=keyAge')).json.items[0].name, 'old-reporting');
  const one = (await owner.get(`/api/iam-users/${ci.id}`)).json;
  assert.equal(one.callers[0].kind, 'access-key'); assert.ok(one.callers[0].calls30 > 0);
  assert.deepEqual(one.policies.map((p) => p.kind), ['inline']);
});

test('roles stay roles: the Roles list and its totals leave users out unless asked; Radar and Space can show either', async () => {
  assert.equal((await owner.get('/api/roles?limit=100')).json.total, 20);
  assert.equal((await owner.get('/api/roles?kinds=iam-user&limit=100')).json.total, 8);
  assert.equal((await owner.get('/api/overview')).json.totals.roles, 20);
  const radar = async (who) => (await owner.get(`/api/radar/estate${who ? `?who=${who}` : ''}`)).json.totals.roles;
  assert.deepEqual([await radar(''), await radar('roles'), await radar('users')], [28, 20, 8]);
  const acct = (await owner.get(`/api/radar/account/${A}?who=users`)).json.roles;
  assert.ok(acct.length === 4 && acct.every((x) => x.kind === 'iam-user'));
  const space = async (who) => (await owner.get(`/api/space${who ? `?who=${who}` : ''}`)).json.accounts.find((a) => a.id === A);
  const [all, users] = [await space(''), await space('users')];
  assert.ok(all.roles > users.roles && users.roles === 4);
  assert.ok(users.stars.length >= 2);                                          // ci-legacy and snapshot-bot call every day
  const inAcct = (await owner.get(`/api/space/account/${A}?who=users`)).json;
  assert.ok(inAcct.roleCount === 4 || inAcct.roles?.length <= 4, JSON.stringify(Object.keys(inAcct)));
});

test('members limited to an account see only its users; a scanner role that cannot read users skips them and keeps what is stored', async () => {
  const inv = await owner.post('/api/members/invite', { email: 'squad@acme.example', role: 'account_owner', scope_accounts: [B] });
  const squad = new Client(); await squad.post('/api/auth/signup', { name: 'Squad', email: 'squad@acme.example', password: PW, invite: inv.json.link.split('invite=')[1] });
  const mine = (await squad.get('/api/iam-users')).json;
  assert.equal(mine.total, 4); assert.ok(mine.items.every((u) => u.account.id === B));
  const other = (await owner.get(`/api/iam-users?accounts=${A}`)).json.items[0];
  assert.equal((await squad.get(`/api/iam-users/${other.id}`)).status, 404);

  const { demoGateway } = await import('../src/demo/gateway.js');
  const { inventoryUsers } = await import('../src/scanner/inventory.js');
  const gw = demoGateway({ account_id: '111111111111', regions: ['ap-southeast-3'], role_arn: 'x' });
  gw.listUsers = async () => { throw Object.assign(new Error('User is not authorized to perform: iam:ListUsers'), { name: 'AccessDenied' }); };
  const logs = [];
  const got = await inventoryUsers({ log: (m) => logs.push(m), progress: async () => {} }, { id: A }, gw);
  assert.equal(got, null); assert.match(logs[0], /iam:ListUsers/);
  assert.equal((await owner.get(`/api/iam-users?accounts=${A}`)).json.total, 4);
  // allowed to list users but not to read their keys or sign-in: skipped too, never a failed scan
  const gw2 = demoGateway({ account_id: '111111111111', regions: ['ap-southeast-3'], role_arn: 'x' });
  gw2.getUserDetail = async () => { throw Object.assign(new Error('User: x is not authorized to perform: iam:GetLoginProfile on resource: y'), { name: 'AccessDenied' }); };
  logs.length = 0;
  assert.equal(await inventoryUsers({ log: (m) => logs.push(m), progress: async () => {} }, { id: A }, gw2), null);
  assert.match(logs[0], /cannot call iam:GetLoginProfile/);
  assert.equal((await owner.get(`/api/iam-users?accounts=${A}`)).json.total, 4);
});

test('the scanner policy can read users, their keys and their groups', async () => {
  const { SCANNER_ALLOW } = await import('../src/onboarding.js');
  for (const a of ['iam:ListUsers', 'iam:ListAccessKeys', 'iam:GetAccessKeyLastUsed', 'iam:ListMFADevices', 'iam:GetLoginProfile', 'iam:ListGroupsForUser', 'iam:ListAttachedGroupPolicies']) assert.ok(SCANNER_ALLOW.includes(a), a);
  assert.ok(!SCANNER_ALLOW.some((a) => /CreateAccessKey|UpdateAccessKey|DeleteAccessKey/.test(a)));
});
