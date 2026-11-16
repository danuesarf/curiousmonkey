// Database space per AWS account (exact and sampled), and the Logging API field-mask fallback that never reads whole entries.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { startPg } from './helpers/pg.js';

// modules that read the database URL are imported after Postgres starts
let pg, db, st, readWithMasks, resetLogMask, LOG_MASKS, logMaskInUse;
before(async () => {
  pg = await startPg(54368); db = await import('../src/db.js'); await (await import('../src/migrate.js')).migrate(() => {});
  st = await import('../src/accountStorage.js');
  ({ readWithMasks, resetLogMask, LOG_MASKS, logMaskInUse } = await import('../src/gcp/real.js'));
});
after(async () => { await db?.closePool(); await pg?.stop(); });

// ---------------------------------------------------------------- field masks
const entry = { timestamp: 't', protoPayload: { authenticationInfo: { principalEmail: 'a@b' }, authorizationInfo: [{ permission: 'x.y.z', granted: true }] } };
test('masks: the narrow mask when it works', async () => {
  resetLogMask();
  const asked = [];
  const r = await readWithMasks(async (m) => { asked.push(m); return { entries: [entry] }; });
  assert.deepEqual(asked, [LOG_MASKS[0]]); assert.equal(r.entries.length, 1);
});
test('masks: refused, or accepted but emptied, steps down; never a request without a mask', async () => {
  resetLogMask();
  const asked = [];
  await readWithMasks(async (m) => { asked.push(m); if (m === LOG_MASKS[0]) throw Object.assign(new Error('Invalid field selection protoPayload/authenticationInfo'), { status: 400 }); return { entries: [entry] }; });
  assert.deepEqual(asked, LOG_MASKS);
  assert.equal(logMaskInUse(), LOG_MASKS[1]);                            // later pages go straight to the one that works
  resetLogMask();
  const r = await readWithMasks(async (m) => (m === LOG_MASKS[0] ? { entries: [{ timestamp: 't' }] } : { entries: [entry] }));
  assert.equal(r.entries[0].protoPayload.authenticationInfo.principalEmail, 'a@b');
  // an empty page is not a dropped mask
  resetLogMask();
  assert.deepEqual((await readWithMasks(async () => ({ entries: [] }))).entries, []);
  assert.equal(logMaskInUse(), LOG_MASKS[0]);
});
test('masks: every mask failing is an error, then the next retry starts from the best mask', async () => {
  resetLogMask();
  const asked = [];
  await assert.rejects(readWithMasks(async (m) => { asked.push(m); return { entries: [{ timestamp: 't' }] }; }), (e) => e.status === 422 && /never read/.test(e.message));
  assert.ok(asked.every((m) => m) && asked.length === LOG_MASKS.length);
  assert.equal(logMaskInUse(), LOG_MASKS[0]);
  // other errors pass straight through without trying other masks
  const n = []; await assert.rejects(readWithMasks(async (m) => { n.push(m); throw Object.assign(new Error('PERMISSION_DENIED'), { status: 403 }); }), /PERMISSION/);
  assert.equal(n.length, 1);
});

// ---------------------------------------------------------------- storage per account

async function seed() {
  const q = db.query;
  const acct = async (n) => (await q(`INSERT INTO cloud_accounts(account_id, name, regions) VALUES ($1, $2, '{us-east-1}') RETURNING id`, [n, `acct-${n}`])).rows[0].id;
  const a = await acct('111111111111'), b = await acct('222222222222'), c = await acct('333333333333');
  for (const [id, roles] of [[a, 30], [b, 10], [c, 1]]) {
    await q(`INSERT INTO roles(account_id, arn, name, kind) SELECT $1::uuid, 'arn:' || $1::text || ':' || g, 'r' || g, 'custom' FROM generate_series(1, $2) g`, [id, roles]);
  }
  await q(`INSERT INTO principals(role_id, key, kind, display, via) SELECT id, 'k', 'aws', 'd', 'v' FROM roles`);
  // activity: 3,000 rows per role in a, 1,000 in b, 50 in c: 90,000 / 10,000 / 50
  await q(`INSERT INTO activity_daily(role_id, principal_id, action, day)
    SELECT r.id, p.id, 'svc:Act' || g, current_date FROM roles r JOIN principals p ON p.role_id = r.id JOIN cloud_accounts ca ON ca.id = r.account_id
      CROSS JOIN LATERAL generate_series(1, CASE ca.account_id WHEN '111111111111' THEN 3000 WHEN '222222222222' THEN 1000 ELSE 50 END) g`);
  await q('ANALYZE');
  return { a, b, c };
}

test('exact: every row counted, accounts add up to the tables they are in', async () => {
  const { a, b, c } = await seed();
  const r = await st.accountStorage();
  const by = new Map(r.items.map((i) => [i.account, i]));
  assert.equal(by.get(a).byTable.activity_daily[1], 90000);
  assert.equal(by.get(b).byTable.activity_daily[1], 10000);
  assert.equal(by.get(c).byTable.activity_daily[1], 50);
  assert.equal(by.get(a).byTable.roles[1], 30);
  assert.equal(by.get(a).sampled, false);
  const size = Number((await db.query(`SELECT pg_total_relation_size('activity_daily') b`)).rows[0].b);
  const split = r.items.reduce((s, i) => s + (i.byTable.activity_daily?.[0] || 0), 0);
  assert.ok(Math.abs(split - size) <= r.items.length, `${split} vs ${size}`);
  assert.ok(by.get(a).bytes > by.get(b).bytes && by.get(b).bytes > by.get(c).bytes);
  // the catalog finds tables reached through roles and through sessions, and prefers a table's own account column
  const t = new Map((await st.accountTables()).map((x) => [x.tbl, x]));
  assert.equal(t.get('activity_daily').ref, 'roles'); assert.equal(t.get('track_calls').ref, 'track_sessions');
  assert.equal(t.get('track_sessions').ref, 'cloud_accounts'); assert.equal(t.get('changes').col, 'account_id');
  assert.ok(!t.has('cloud_accounts'));
});

test('sampled: a big table split from a page sample lands close to the truth', async () => {
  const r = await st.accountStorage({ sampleRows: 5000 });                // forces a sample of activity_daily (100,050 rows)
  const by = new Map(r.items.map((i) => [i.account, i]));
  const ids = (await db.query(`SELECT id, account_id FROM cloud_accounts`)).rows;
  const id = (n) => ids.find((x) => x.account_id === n).id;
  const share = by.get(id('111111111111')).byTable.activity_daily[1] / 100050;
  assert.ok(by.get(id('111111111111')).sampled);
  assert.ok(Math.abs(share - 0.9) < 0.08, `share ${share}`);              // 90% of the rows
  assert.equal(by.get(id('333333333333')).byTable.activity_daily[1], 50);   // the smallest account is counted exactly, not sampled
  const total = r.items.reduce((s, i) => s + (i.byTable.activity_daily?.[1] || 0), 0);
  assert.ok(Math.abs(total - 100050) / 100050 < 0.1, `total ${total}`);
});

test('saved: latest per account and an hourly point; a removed account drops out', async () => {
  await st.accountStorage({ save: true });
  const rows = await st.storedAccountStorage();
  assert.equal(rows.length, 3);
  assert.ok(rows[0].bytes >= rows[1].bytes && rows[0].bytes_7d_ago == null);
  assert.equal(Number(rows[0].bytes), Number(rows[0].bytes_latest));                    // one sample so far: average = latest
  // the size shown is the 24-hour average of the hourly estimates
  await db.query(`INSERT INTO account_storage_samples(account_id, at, bytes) SELECT account_id, date_trunc('hour', now()) - interval '1 hour', bytes + 1000 FROM account_storage`);
  const avg = await st.storedAccountStorage();
  assert.ok(avg.every((x) => Number(x.bytes) === Number(x.bytes_latest) + 500));
  await db.query(`DELETE FROM account_storage_samples WHERE at < date_trunc('hour', now())`);
  assert.equal((await db.query('SELECT count(*)::int n FROM account_storage_samples')).rows[0].n, 3);
  await db.query(`INSERT INTO account_storage_samples(account_id, at, bytes) SELECT account_id, now() - interval '7 days 12 hours', 1 FROM account_storage`);
  assert.ok((await st.storedAccountStorage()).every((x) => Number(x.bytes_7d_ago) === 1));
  await db.query(`DELETE FROM cloud_accounts WHERE account_id = '333333333333'`);
  await st.accountStorage({ save: true });
  assert.equal((await st.storedAccountStorage()).length, 2);
});
