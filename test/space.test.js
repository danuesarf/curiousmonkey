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

test('role chaining across accounts: a pair seen for the first time today is new', async () => {
  const s = await api.spaceEstate(owner);
  const up = s.chains.find((c) => c.from === B && c.to === A), down = s.chains.find((c) => c.from === A && c.to === B);
  assert.equal(up.isNew, true); assert.equal(up.sessions, 1);
  assert.equal(down.isNew, false); assert.equal(down.sessions, 1); assert.equal(down.denied, 1);
  assert.equal(up.hours.length, 1);
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
