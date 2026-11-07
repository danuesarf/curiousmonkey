// Results are provisional until every region's history is read; approval waits for that.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { startPg } from './helpers/pg.js';

process.env.AWS_MODE = 'demo';
process.env.LOOKUP_DELAY_MS = '0';
let pg, db, h, q, w, rec;
const DAY = 864e5;
before(async () => {
  pg = await startPg(54339);
  db = await import('../src/db.js');
  await (await import('../src/migrate.js')).migrate(() => {});
  h = await import('../src/history.js'); q = await import('../src/queue.js'); w = await import('../src/worker.js'); rec = await import('../src/recommender/index.js');
  await q.registerWorker();
  await db.query(`INSERT INTO workspace(name, slug, external_id) VALUES ('KBI','kbi','ext-123')`);
});
after(async () => { await db.closePool(); await pg.stop(); });

const acct = { regions: ['us-east-1', 'ap-southeast-3'], event_source: 'event-history', lookback_days: 90 };
const cp = (region, firstDaysAgo, lastDaysAgo, caught) => ({ region, first_event_time: new Date(Date.now() - firstDaysAgo * DAY), last_event_time: new Date(Date.now() - lastDaysAgo * DAY), caught_up_at: caught ? new Date() : null });

test('a first read in progress is provisional, with progress and how far it has read', () => {
  const s = h.historyState(acct, [cp('us-east-1', 90, 60, false), cp('ap-southeast-3', 90, 30, false)]);
  assert.equal(s.complete, false);
  assert.ok(s.progress >= 48 && s.progress <= 51, String(s.progress));            // a third and two thirds
  assert.ok(Math.abs(s.readUpTo - (Date.now() - 60 * DAY)) < 1000);
  assert.equal(h.historyState(acct, [cp('us-east-1', 90, 60, false)]).regions[1].progress, 0);   // a region not started
});

test('once every region has caught up, it is complete, and it stays complete as the days pass', () => {
  assert.equal(h.historyState(acct, [cp('us-east-1', 90, 0, true), cp('ap-southeast-3', 90, 0, true)]).complete, true);
  assert.equal(h.historyState(acct, [cp('us-east-1', 89, 1.5, true), cp('ap-southeast-3', 89, 1.5, true)]).progress, 100);
});

test('widening the lookback reopens it until the older days are backfilled', () => {
  const wide = { ...acct, event_source: 's3', lookback_days: 365 };
  const s = h.historyState(wide, [cp('us-east-1', 90, 0, true), cp('ap-southeast-3', 90, 0, true)]);
  assert.equal(s.complete, false); assert.ok(s.progress > 20 && s.progress < 30, String(s.progress));
});

test('a real scan ends complete; approving waits until then', async () => {
  const A = (await db.query(`INSERT INTO cloud_accounts(account_id, name, role_arn, regions, status) VALUES ('111111111111','prod','arn:aws:iam::111111111111:role/x','{ap-southeast-3}','connected') RETURNING *`)).rows[0];
  await q.enqueueRun(A.id, { trigger: 'manual' });
  for (let j; (j = await q.claimJob());) { try { await w.runJob(j); } catch (e) { await q.failJob(j, e); } }
  assert.equal(await h.accountComplete(A.id), true);
  const role = (await db.query(`SELECT id FROM roles WHERE account_id=$1 AND name='payments-api-prod'`, [A.id])).rows[0];
  const draft = await rec.recommend(role.id, { llm: null });
  // pretend the read had not finished
  await db.query('UPDATE scan_checkpoints SET caught_up_at=NULL WHERE account_id=$1', [A.id]);
  await assert.rejects(rec.approve(draft.id, { id: null, team: 'infosec' }), /still being read/);
  await db.query('UPDATE scan_checkpoints SET caught_up_at=now() WHERE account_id=$1', [A.id]);
  const ok = await rec.approve(draft.id, { id: null, team: 'infosec' });
  assert.equal(ok.approved, true);
});

test('a provisional refresh runs one at a time per account', async () => {
  const { provisionalAnalyze } = await import('../src/scanner/analyzeJob.js');
  const A = (await db.query(`SELECT id FROM cloud_accounts LIMIT 1`)).rows[0].id;
  await db.query('UPDATE roles SET analyzed_at=NULL WHERE account_id=$1', [A]).catch(() => {});
  const [a, b] = await Promise.all([provisionalAnalyze(A), provisionalAnalyze(A)]);
  assert.deepEqual([a, b].sort(), [false, true]);
});
