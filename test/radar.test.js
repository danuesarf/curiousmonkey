// Radar v3: snapshots and the changes they reveal, the estate's trails, and blast radius through role chaining.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { startPg } from './helpers/pg.js';

process.env.AWS_MODE = 'demo';
let pg, db, rh, api;
let A, B, roleId;                 // two accounts
const owner = { id: null, scope_accounts: null };
const day = (ago) => new Date(Date.now() - ago * 864e5).toISOString().slice(0, 10);

before(async () => {
  pg = await startPg(54345);
  db = await import('../src/db.js');
  await (await import('../src/migrate.js')).migrate(() => {});
  rh = await import('../src/radarHistory.js'); api = await import('../src/radarApi.js');
  await db.query(`INSERT INTO workspace(name, slug, external_id) VALUES ('KBI','kbi','ext-1')`);
  const acct = async (aws, name, env) => (await db.query(`INSERT INTO cloud_accounts(account_id, name, environment, role_arn, regions, status) VALUES ($1,$2,$3,'arn:x',$4,'connected') RETURNING id`,
    [aws, name, env, ['us-east-1']])).rows[0].id;
  A = await acct('111111111111', 'payments-prod', 'production'); B = await acct('222222222222', 'data-stg', 'staging');
  const role = async (acc, aws, name, granted, used, trust = {}) => (await db.query(
    `INSERT INTO roles(account_id, arn, name, kind, granted_count, used_count, unused_count, trust_policy) VALUES ($1,$2,$3,'custom',$4,$5,$6,$7) RETURNING id`,
    [acc, `arn:aws:iam::${aws}:role/${name}`, name, granted, used, granted - used, JSON.stringify(trust)])).rows[0].id;
  roleId = {
    deployer: await role(A, '111111111111', 'deployer', 400, 40),
    admin: await role(A, '111111111111', 'ops-admin', 20000, 10, { Statement: [{ Effect: 'Allow', Principal: { AWS: 'arn:aws:iam::111111111111:role/deployer' }, Action: 'sts:AssumeRole' }] }),
    reader: await role(B, '222222222222', 'data-reader', 50, 20),
  };
});
after(async () => { await db.closePool(); await pg.stop(); });

const principal = async (role, key, kind, display) => (await db.query(
  `INSERT INTO principals(role_id, key, kind, display, via, first_seen, last_seen) VALUES ($1,$2,$3,$4,'sts:AssumeRole',now(),now()) RETURNING id`, [role, key, kind, display])).rows[0].id;

test('the first snapshot records where things stand and raises nothing', async () => {
  const p = await principal(roleId.deployer, 'user:arn:aws:iam::111111111111:user/ci-bot', 'user', 'ci-bot (111111111111)');
  await db.query(`INSERT INTO activity_daily(role_id, principal_id, action, day, count) VALUES ($1,$2,'ecr:PutImage',current_date,5)`, [roleId.deployer, p]);
  assert.equal(await rh.snapshotAndDiff(A, day(31)), 0);
  const n = (await db.query('SELECT count(*)::int n FROM role_snapshots WHERE account_id=$1', [A])).rows[0].n;
  assert.equal(n, 2);
});

test('the next snapshot raises what changed: grew to admin, trimmed, first denied, new roles', async () => {
  await db.query('UPDATE roles SET granted_count=16000, unused_count=15960 WHERE id=$1', [roleId.deployer]);          // 400 -> admin-level
  await db.query('UPDATE roles SET granted_count=50, used_count=10, unused_count=40 WHERE id=$1', [roleId.admin]);   // 20000 -> 50
  await db.query(`UPDATE activity_daily SET error_count=3 WHERE role_id=$1`, [roleId.deployer]);
  await db.query(`INSERT INTO roles(account_id, arn, name, kind, granted_count) VALUES ($1,'arn:aws:iam::111111111111:role/new-one','new-one','custom',10)`, [A]);
  await rh.snapshotAndDiff(A, day(8));
  const ch = (await db.query('SELECT kind, severity, title FROM changes WHERE account_id=$1 ORDER BY kind', [A])).rows;
  assert.deepEqual(ch.map((c) => [c.kind, c.severity]), [['cleaned', 'good'], ['denied', 'high'], ['grew', 'high'], ['new-role', 'info']]);
  assert.match(ch.find((c) => c.kind === 'grew').title, /deployer gained admin-level/);
  await rh.snapshotAndDiff(A, day(8));                                                                                // the same day again records nothing new
  assert.equal((await db.query('SELECT count(*)::int n FROM changes WHERE account_id=$1', [A])).rows[0].n, 4);
});

test('the estate shows where each account was 30 days ago, and the trend compares like with like', async () => {
  await rh.snapshotAndDiff(A);
  const e = await api.estate(owner);
  const a = e.accounts.find((x) => x.id === A), b = e.accounts.find((x) => x.id === B);
  assert.ok(a.never30 != null && a.never != null);
  assert.ok(Math.abs(a.never30 - (360 + 19990) / 20400) < 1e-9);       // snapshot from 31 days ago
  assert.equal(b.never30, null);                                       // no history yet: no trail
  assert.equal(e.totals.trendAccounts, 1);
  assert.equal(a.pings, 4);
});

test('blast radius walks observed entries and trust policies, hop by hop, and hides what the viewer cannot see', async () => {
  // ci-bot enters deployer (observed); ops-admin trusts deployer by ARN (trust); deployer was seen entering data-reader in the other account
  await principal(roleId.reader, 'role:111111111111:deployer', 'role', 'role/deployer (111111111111)');
  const r = await api.blastRadius(owner, 'user:arn:aws:iam::111111111111:user/ci-bot');
  const by = Object.fromEntries(r.nodes.map((n) => [n.name, n]));
  assert.deepEqual([by.deployer.hop, by['ops-admin'].hop, by['data-reader'].hop], [1, 2, 2]);
  assert.equal(by['ops-admin'].edge, 'trust'); assert.equal(by['data-reader'].edge, 'observed');
  assert.equal(by['ops-admin'].parent, by.deployer.id);
  assert.equal(r.totals.accounts, 2);
  const scoped = await api.blastRadius({ scope_accounts: [A] }, 'user:arn:aws:iam::111111111111:user/ci-bot');
  assert.equal(scoped.nodes.some((n) => n.name === 'data-reader'), false);
  assert.equal(scoped.hidden, 1);
});

test('a new caller after the first full read is a ping; the same caller again is not', async () => {
  const role = { id: roleId.reader, name: 'data-reader', arn: 'arn:aws:iam::222222222222:role/data-reader' };
  const p = { key: 'role:333333333333:sandbox-runner', kind: 'role', display: 'role/sandbox-runner (333333333333)' };
  await db.tx(async (c) => { await rh.recordNewCaller(c, B, role, p, 'sts:AssumeRole', new Date()); await rh.recordNewCaller(c, B, role, p, 'sts:AssumeRole', new Date()); });
  const ch = (await db.query(`SELECT severity, detail FROM changes WHERE account_id=$1 AND kind='new-caller'`, [B])).rows;
  assert.equal(ch.length, 1);
  assert.equal(ch[0].severity, 'high');                                 // from another account
  assert.match(ch[0].detail, /another account/);
  const feed = await api.changeFeed(owner, { accountId: B });
  assert.equal(feed.items[0].role_name, 'data-reader');
});
