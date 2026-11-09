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
const cp = (region, firstDaysAgo, lastDaysAgo, caught) => ({ region, first_event_time: new Date(Date.now() - firstDaysAgo * DAY), last_event_time: new Date(Date.now() - lastDaysAgo * DAY), caught_up_at: caught === 'now' ? new Date() : caught ? new Date(Date.now() - lastDaysAgo * DAY) : null });

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

test('a caught-up stamp with the read position far behind it is stale: still provisional', () => {
  // e.g. stamped by a migration while the first read was mid-way, then the read resumed after a lost worker
  const s = h.historyState(acct, [cp('us-east-1', 90, 0, true), cp('ap-southeast-3', 90, 11, 'now')]);
  assert.equal(s.complete, false);
  assert.equal(s.regions[1].complete, false);
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

test('freshness: how recent the newest read is, the least current region counting', () => {
  const now = Date.now(), at = (minAgo) => new Date(now - minAgo * 60e3);
  const s = h.historyState(acct, [{ ...cp('us-east-1', 90, 0, true), caught_up_at: at(5) }, { ...cp('ap-southeast-3', 90, 0, true), caught_up_at: at(50) }], now);
  assert.equal(s.complete, true);
  assert.ok(Math.abs(s.freshAt - at(50 + 15)) < 1000, 'the stalest region, less the delivery lag');
  assert.equal(h.historyState(acct, [cp('us-east-1', 90, 60, false)]).freshAt, null);
});

test('catch-up reads: accounts with complete history get an events-and-analyze run every N minutes', async () => {
  const { config } = await import('../src/config.js');
  const mk = async (aws, caught) => {
    const id = (await db.query(`INSERT INTO cloud_accounts(account_id, name, role_arn, regions, status) VALUES ($1,$1,'arn:aws:iam::1:role/x',$2,'connected') RETURNING id`, [aws, ['us-east-1']])).rows[0].id;
    await db.query(`INSERT INTO scan_checkpoints(account_id, region, source, first_event_time, last_event_time, caught_up_at) VALUES ($1,'us-east-1','event-history',now() - interval '91 days', now() - interval '20 minutes', $2)`,
      [id, caught ? new Date() : null]);
    return id;
  };
  const done = await mk('444444444441', true), reading = await mk('444444444442', false);
  const tailsOf = async (id) => (await db.query(`SELECT r.id, array_agg(j.kind ORDER BY j.kind) AS kinds FROM scan_runs r JOIN scan_jobs j ON j.run_id = r.id WHERE r.account_id=$1 AND r.trigger='tail' GROUP BY r.id`, [id])).rows;
  config.scanner.tailEveryMinutes = 0;
  await w.tailTick();
  assert.equal((await tailsOf(done)).length, 0, 'off');
  config.scanner.tailEveryMinutes = 30;
  await w.tailTick();
  const t = await tailsOf(done);
  assert.equal(t.length, 1);
  assert.deepEqual(t[0].kinds, ['analyze', 'events']);                       // no inventory, no Access Advisor
  assert.equal((await tailsOf(reading)).length, 0, 'an account still reading history is left to its own scan');
  await w.tailTick();
  assert.equal((await tailsOf(done)).length, 1, 'one in flight: nothing more');
  await db.query(`UPDATE scan_runs SET status='succeeded', created_at = now() - interval '10 minutes' WHERE id=$1`, [t[0].id]);
  await w.tailTick();
  assert.equal((await tailsOf(done)).length, 1, 'within the interval: nothing more');
  await db.query(`UPDATE scan_runs SET created_at = now() - interval '31 minutes' WHERE id=$1`, [t[0].id]);
  await w.tailTick();
  assert.equal((await tailsOf(done)).length, 2);
  config.scanner.tailEveryMinutes = 30;
});

test('a catch-up read that found no new events skips the analysis', async () => {
  const { runAnalyze } = await import('../src/scanner/analyzeJob.js');
  const id = (await db.query(`INSERT INTO cloud_accounts(account_id, name, role_arn, regions, status) VALUES ('444444444443','q','arn:aws:iam::1:role/x','{us-east-1}','connected') RETURNING id`)).rows[0].id;
  const run = await q.enqueueRun(id, { trigger: 'tail' });
  await db.query(`UPDATE scan_jobs SET progress='{"skipped":"up to date"}' WHERE run_id=$1 AND kind='events'`, [run]);
  assert.deepEqual(await runAnalyze({ job: { run_id: run, account_id: id }, alive() {}, async progress() {} }), { skipped: 'no new events' });
  await db.query(`UPDATE scan_jobs SET progress='{"events":3}' WHERE run_id=$1 AND kind='events'`, [run]);
  const out = await runAnalyze({ job: { run_id: run, account_id: id }, alive() {}, async progress() {} });
  assert.equal(out.skipped, undefined);
  assert.equal(out.changes, undefined, 'the daily snapshot is left to the daily scan');
});
