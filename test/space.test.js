// Space: the estate on a plane and one account, replayed by the hour.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { startPg } from './helpers/pg.js';

process.env.AWS_MODE = 'demo';
let pg, db, api;
let A, B, R;
const owner = { id: null, scope_accounts: null };
const hoursAgo = (h) => new Date(Date.now() - h * 36e5).toISOString();

before(async () => {
  pg = await startPg(54351);
  db = await import('../src/db.js');
  await (await import('../src/migrate.js')).migrate(() => {});
  api = await import('../src/spaceApi.js');
  await db.query(`INSERT INTO workspace(name, slug, external_id) VALUES ('KBI','kbi','ext-1')`);
  const acct = async (aws, name, env) => (await db.query(`INSERT INTO cloud_accounts(account_id, name, environment, role_arn, regions, status) VALUES ($1,$2,$3,'arn:x',$4,'connected') RETURNING id`,
    [aws, name, env, ['us-east-1']])).rows[0].id;
  A = await acct('111111111111', 'payments-prod', 'production'); B = await acct('222222222222', 'payments-stg', 'staging');
  const role = async (acc, aws, name, trust = {}) => (await db.query(
    `INSERT INTO roles(account_id, arn, name, kind, granted_count, used_count, unused_count, trust_policy) VALUES ($1,$2,$3,'custom',10,5,5,$4) RETURNING id`,
    [acc, `arn:aws:iam::${aws}:role/${name}`, name, JSON.stringify(trust)])).rows[0].id;
  R = {
    deploy: await role(A, '111111111111', 'deploy', { Statement: [
      { Effect: 'Allow', Principal: { Federated: 'arn:aws:iam::111111111111:oidc-provider/token.actions.githubusercontent.com' }, Action: 'sts:AssumeRoleWithWebIdentity',
        Condition: { StringLike: { 'token.actions.githubusercontent.com:sub': 'repo:krom-id/*' } } },
      { Effect: 'Allow', Principal: { AWS: 'arn:aws:iam::999999999999:root' }, Action: 'sts:AssumeRole' }] }),
    api: await role(A, '111111111111', 'payments-api'),
    idle: await role(A, '111111111111', 'old-batch'),
    release: await role(B, '222222222222', 'release'),
  };
  const p = (await db.query(`INSERT INTO principals(role_id, key, kind, display, via, first_seen, last_seen) VALUES ($1,'svc','service','ecs','sts:AssumeRole',now(),now()) RETURNING id`, [R.api])).rows[0].id;
  await db.query(`INSERT INTO activity_daily(role_id, principal_id, action, day, count, error_count) VALUES ($1,$2,'s3:GetObject',current_date,900,0),($1,$2,'kms:Decrypt',current_date,300,2),($3,$2,'ecs:UpdateService',current_date,40,0)`, [R.api, p, R.deploy]);
  const sess = (acc, role, key, at, calls, parent = null, denied = 0) => db.query(
    `INSERT INTO track_sessions(account_id, role_id, access_key_id, started_at, calls, denied, parent_key_id) VALUES ($1,$2,$3,$4,$5,$6,$7)`, [acc, role, key, at, calls, denied, parent]);
  // staging chains into production for the first time two hours ago
  await sess(B, R.release, 'ASIAB1', hoursAgo(2.2), 3);
  await sess(A, R.deploy, 'ASIAA1', hoursAgo(2), 12, 'ASIAB1');
  // production chains into staging every day: once ten days ago, once today
  await sess(A, R.api, 'ASIAA2', hoursAgo(240), 5);
  await sess(B, R.release, 'ASIAB2', hoursAgo(240), 1, 'ASIAA2');
  await sess(A, R.api, 'ASIAA3', hoursAgo(5), 50);
  await sess(B, R.release, 'ASIAB3', hoursAgo(5), 2, 'ASIAA3', 1);
  await db.query(`INSERT INTO changes(account_id, role_id, kind, severity, title, dedupe, at) VALUES ($1,$2,'denied','warn','kms:Decrypt refused','d1',$3)`, [A, R.api, hoursAgo(1)]);
  // who entered whom: staging's release role entered production's deploy role for the first time two hours ago;
  // production's payments-api has entered staging's release role for ten days
  const entered = async (role, key, display, first, last, n) => (await db.query(
    `INSERT INTO principals(role_id, key, kind, display, via, first_seen, last_seen, sessions_count) VALUES ($1,$2,'role',$3,'sts:AssumeRole',$4,$5,$6) RETURNING id`, [role, key, display, first, last, n])).rows[0].id;
  const up = await entered(R.deploy, 'role:222222222222:release', 'role/release (222222222222)', hoursAgo(2), hoursAgo(2), 1);
  const down = await entered(R.release, 'role:111111111111:payments-api', 'role/payments-api (111111111111)', hoursAgo(240), hoursAgo(5), 11);
  await entered(R.api, 'role:999999999999:vendor', 'role/vendor (999999999999)', hoursAgo(5), hoursAgo(5), 2);   // not in the org: not an account-to-account path
  await db.query(`INSERT INTO role_sessions(access_key_id, role_id, principal_id, started_at) VALUES ('ASIAA1',$1,$2,$3),('ASIAB3',$4,$5,$6)`, [R.deploy, up, hoursAgo(2), R.release, down, hoursAgo(5)]);
});
after(async () => { await db.closePool(); await pg.stop(); });

test('the estate: accounts by environment, stars for active roles, the hours they worked', async () => {
  const s = await api.spaceEstate(owner);
  const a = s.accounts.find((x) => x.id === A);
  assert.equal(a.environment, 'production');
  assert.equal(a.roles, 3); assert.equal(a.active, 2); assert.equal(a.cold, 1);
  assert.deepEqual(a.stars.map((x) => x.name), ['payments-api', 'deploy']);
  assert.equal(a.calls7, 1240);
  assert.equal(a.hourly.length, 24);
  assert.equal(a.hourly.reduce((t, h) => t + h.calls, 0), 62);           // the 10-day-old session is outside the replay
  assert.equal(a.hourly[21].calls + a.hourly[22].calls, 12);              // two hours ago
});

test('account to account: every entry recorded between your accounts, new when first seen today', async () => {
  const s = await api.spaceEstate(owner);
  assert.equal(s.chains.length, 2);
  const up = s.chains.find((c) => c.from === B && c.to === A), down = s.chains.find((c) => c.from === A && c.to === B);
  assert.equal(up.isNew, true); assert.deepEqual(up.roles.map((r) => [r.caller, r.role]), [['release', 'deploy']]);
  assert.equal(up.today, 1); assert.equal(up.hours.length, 1);
  assert.equal(down.isNew, false); assert.equal(down.sessions, 11); assert.equal(down.today, 1);
});

test('identities outside the org come from trust policies, the worst first', async () => {
  const s = await api.spaceEstate(owner);
  const groups = s.outside.items.map((x) => x.group).sort();
  assert.deepEqual(groups, ['external-account', 'oidc']);
  assert.ok(s.outside.items.every((x) => x.worst === 'high' && x.findings.length && x.targets[0].accountId === A));
  const gh = s.outside.items.find((x) => x.group === 'oidc').targets[0].edges[0];
  assert.equal(gh.role, 'deploy');
  assert.ok(gh.conditions.some((c) => c.includes('repo:krom-id/*')));
  assert.ok(gh.findings.some((f) => /wildcard/.test(f.title)));
  assert.equal(s.events.length, 1); assert.equal(s.events[0].hour, 22);
});

test('one account: roles clustered by the service they call most, services as towers', async () => {
  const s = await api.spaceAccount(owner, A);
  assert.deepEqual(s.services.map((x) => x.name), ['s3', 'kms', 'ecs']);
  assert.deepEqual(s.clusters.map((c) => [c.key, c.roles.map((r) => r.name)]), [['s3', ['payments-api']], ['ecs', ['deploy']]].sort((x, y) => (x[0] === 's3' ? -1 : 1)));
  assert.equal(s.coldCount, 1);
  assert.deepEqual(s.neighbours.map((n) => [n.name, n.links.map((l) => l.dir).sort()]), [['payments-stg', ['in', 'out']]]);
  assert.equal(await api.spaceAccount({ id: 'x', scope_accounts: [B] }, A), null);
});

test('Curious Monkey is its own identity: its sign-ins to the scanner roles are not account-to-account paths', async () => {
  const scan = async (acc, aws) => {
    const arn = `arn:aws:iam::${aws}:role/CuriousMonkeyScanner`;
    await db.query('UPDATE cloud_accounts SET role_arn=$2, last_scan_at=now() WHERE id=$1', [acc, arn]);
    return (await db.query(`INSERT INTO roles(account_id, arn, name, kind, trust_policy) VALUES ($1,$2,'CuriousMonkeyScanner','custom','{}') RETURNING id`, [acc, arn])).rows[0].id;
  };
  const sA = await scan(A, '111111111111'), sB = await scan(B, '222222222222');
  await db.query(`INSERT INTO workers(id, hostname, aws_identity) VALUES ('w1','h',$1)`, [JSON.stringify({ mode: 'aws', account: '222222222222', principal: 'arn:aws:iam::222222222222:user/CuriousMonkey' })]);
  const pin = async (role, key, kind, n) => (await db.query(`INSERT INTO principals(role_id, key, kind, display, via, first_seen, last_seen, sessions_count) VALUES ($1,$2,$3,'x','sts:AssumeRole',$4,$4,$5) RETURNING id`,
    [role, key, kind, hoursAgo(1), n])).rows[0].id;
  const cross = await pin(sA, 'acct:222222222222:AIDACURIOUSMONKEY001', 'account', 30);   // the target account's copy: no ARN
  await pin(sB, 'user:arn:aws:iam::222222222222:user/CuriousMonkey', 'user', 34);
  await db.query(`INSERT INTO role_sessions(access_key_id, role_id, principal_id, started_at) VALUES ('ASIACM1',$1,$2,$3)`, [sA, cross, hoursAgo(1)]);

  const s = await api.spaceEstate(owner);
  assert.equal(s.chains.length, 2, 'the scanner adds no account-to-account path');
  assert.equal(s.scanner.homeAccountId, B);
  const t = new Map(s.scanner.targets.map((x) => [x.accountId, x]));
  assert.equal(t.get(A).sessions, 30); assert.equal(t.get(A).role, 'CuriousMonkeyScanner'); assert.equal(t.get(A).hours.length, 1);
  assert.equal(t.get(B).sessions, 34);
  const one = await api.spaceAccount(owner, A);
  assert.deepEqual(one.scanner.targets.map((x) => [x.roleId, x.sessions]), [[sA, 30]]);
});

test('one account: chaining from a neighbour is one line per role here, however many roles it comes from', async () => {
  const other = (await db.query(`INSERT INTO roles(account_id, arn, name, kind) VALUES ($1,'arn:aws:iam::222222222222:role/hotfix','hotfix','custom') RETURNING id`, [B])).rows[0].id;
  const sess = (acc, role, key, at, parent = null) => db.query(
    `INSERT INTO track_sessions(account_id, role_id, access_key_id, started_at, calls, parent_key_id) VALUES ($1,$2,$3,$4,1,$5)`, [acc, role, key, at, parent]);
  // two more entries into deploy: one more from release, one from a second staging role
  await sess(B, R.release, 'ASIAB9', hoursAgo(3.2)); await sess(A, R.deploy, 'ASIAA9', hoursAgo(3), 'ASIAB9');
  await sess(B, other, 'ASIAB8', hoursAgo(4.2)); await sess(A, R.deploy, 'ASIAA8', hoursAgo(4), 'ASIAB8');
  const n = (await api.spaceAccount(owner, A)).neighbours.find((x) => x.name === 'payments-stg');
  const into = n.links.filter((l) => l.dir === 'in');
  assert.equal(into.length, 1);                                   // deploy, once, not once per staging role
  assert.equal(into[0].roleId, R.deploy);
  assert.equal(into[0].sessions, 3);
  assert.equal(into[0].otherRole, 'release +1 more');             // the busiest role on the other side, then a count
  assert.equal(n.sessions, n.links.reduce((t, l) => t + l.sessions, 0));
  assert.equal(n.moreLinks, 0);
});

test('the Space indexes are built without a transaction, valid, and migrating again changes nothing', async () => {
  const idx = (await db.query(`SELECT c.relname, i.indisvalid FROM pg_index i JOIN pg_class c ON c.oid = i.indexrelid
                               WHERE c.relname IN ('activity_daily_day_idx', 'track_sessions_chained_idx') ORDER BY 1`)).rows;
  assert.deepEqual(idx.map((x) => [x.relname, x.indisvalid]), [['activity_daily_day_idx', true], ['track_sessions_chained_idx', true]]);
  assert.equal(await (await import('../src/migrate.js')).migrate(() => {}), 0);
});
