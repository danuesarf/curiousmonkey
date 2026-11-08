// Event history: searching the calls kept per role session.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { startPg } from './helpers/pg.js';

process.env.AWS_MODE = 'demo';
let pg, db, ev;
let A, B, deploy, reader;
const owner = { id: null, scope_accounts: null };
const minsAgo = (m) => new Date(Math.floor((Date.now() - m * 6e4) / 1000) * 1000).toISOString();

before(async () => {
  pg = await startPg(54352);
  db = await import('../src/db.js');
  await (await import('../src/migrate.js')).migrate(() => {});
  ev = await import('../src/eventsApi.js');
  await db.query(`INSERT INTO workspace(name, slug, external_id) VALUES ('KBI','kbi','ext-1')`);
  const acct = async (aws, name) => (await db.query(`INSERT INTO cloud_accounts(account_id, name, environment, role_arn, regions, status) VALUES ($1,$2,'production','arn:x','{us-east-1}','connected') RETURNING id`, [aws, name])).rows[0].id;
  A = await acct('111111111111', 'payments-prod'); B = await acct('222222222222', 'data-stg');
  const role = async (acc, name) => (await db.query(`INSERT INTO roles(account_id, arn, name, kind) VALUES ($1,$2,$3,'custom') RETURNING id`, [acc, `arn:aws:iam::x:role/${name}`, name])).rows[0].id;
  deploy = await role(A, 'deploy'); reader = await role(B, 'reader');
  const sess = async (acc, r, key, name, ip, startMins) => (await db.query(
    `INSERT INTO track_sessions(account_id, role_id, access_key_id, session_name, caller_arn, source_ip, started_at, last_call_at) VALUES ($1,$2,$3,$4,$5,$6,$7,now()) RETURNING id`,
    [acc, r, key, name, `arn:aws:sts::x:assumed-role/x/${name}`, ip, minsAgo(startMins)])).rows[0].id;
  const s1 = await sess(A, deploy, 'ASIA1', 'github-actions', '10.0.1.5', 3000);
  const s2 = await sess(B, reader, 'ASIA2', 'dhimas@krom.id', '182.1.2.3', 60);
  const call = (s, id, mins, name, src, action, res = [], denied = false, err = null) => db.query(
    `INSERT INTO track_calls(session_id, event_id, at, action, event_source, event_name, resources, denied, error_code) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
    [s, id, minsAgo(mins), action, src, name, res, denied, err]);
  // deploy: calls spread over two days, so a search must walk back through several slices
  for (let i = 0; i < 30; i++) await call(s1, `d${String(i).padStart(2, '0')}`, 5 + i * 90, i % 3 ? 'UpdateService' : 'DescribeServices', 'ecs', i % 3 ? 'ecs:UpdateService' : 'ecs:DescribeServices', ['arn:aws:ecs:x:service/payments-api']);
  await call(s1, 'kms1', 7, 'Decrypt', 'kms', 'kms:Decrypt', ['arn:aws:kms:x:key/abc'], true, 'AccessDenied');
  await call(s2, 'r1', 30, 'GetObject', 's3', 's3:GetObject', ['arn:aws:s3:::kbi-reports/q3.csv']);
});
after(async () => { await db.closePool(); await pg.stop(); });

test('newest first, with the session and role each call came from', async () => {
  const r = await ev.searchEvents(owner, { range: '24h' });
  assert.equal(r.items[0].event_id, 'd00');
  assert.equal(r.items[1].event_id, 'kms1');
  assert.deepEqual([r.items[1].role_name, r.items[1].account_name, r.items[1].session_name, r.items[1].source_ip], ['deploy', 'payments-prod', 'github-actions', '10.0.1.5']);
  const times = r.items.map((x) => x.at); assert.deepEqual(times, [...times].sort().reverse());
});

test('search keys, plain words, negation and the denied filter', async () => {
  const ids = async (o) => (await ev.searchEvents(owner, { range: '7d', ...o })).items.map((x) => x.event_id);
  assert.deepEqual(await ids({ q: 'ip:182.1' }), ['r1']);
  assert.deepEqual(await ids({ q: 'kbi-reports' }), ['r1']);                       // a plain word finds a resource
  assert.deepEqual(await ids({ outcome: 'denied' }), ['kms1']);
  assert.deepEqual(await ids({ q: 'error:AccessDenied' }), ['kms1']);
  assert.equal((await ids({ q: 'role:deploy -action:Describe' })).filter((x) => x.startsWith('d')).length, 20);
  assert.deepEqual(await ids({ q: 'user:dhimas' }), ['r1']);
  assert.deepEqual(await ids({ account: B }), ['r1']);
});

test('paging walks back through time without gaps or repeats', async () => {
  const all = [];
  let next;
  for (let i = 0; i < 20; i++) {
    const r = await ev.searchEvents(owner, { range: '7d', role: deploy, limit: 7, before: next });
    all.push(...r.items.map((x) => x.event_id));
    next = r.next; if (!next) break;
  }
  assert.equal(all.length, 31); assert.equal(new Set(all).size, 31);
});

test('someone scoped to one account sees only its calls', async () => {
  const r = await ev.searchEvents({ id: 'x', scope_accounts: [B] }, { range: '7d' });
  assert.deepEqual(r.items.map((x) => x.event_id), ['r1']);
  assert.ok(ev.eventsCsv(r.items).split('\n')[1].includes('s3:GetObject'));
});
