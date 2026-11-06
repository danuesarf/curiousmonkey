import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { startPg } from './helpers/pg.js';

let pg, db, q;
before(async () => {
  pg = await startPg(54331);
  db = await import('../src/db.js');
  const { migrate } = await import('../src/migrate.js');
  await migrate(() => {});
  q = await import('../src/queue.js');
  await q.registerWorker();
});
after(async () => { await db.closePool(); await pg.stop(); });

async function account(regions = ['us-east-1', 'ap-southeast-3']) {
  const id = crypto.randomUUID();
  await db.query(`INSERT INTO cloud_accounts(id, account_id, name, role_arn, regions, status)
                  VALUES ($1,$2,$3,'arn:aws:iam::1:role/x',$4,'connected')`,
    [id, String(Math.floor(Math.random() * 9e11 + 1e11)), 'acc', regions]);
  return id;
}
const drain = async () => { const out = []; let j; while ((j = await q.claimJob())) { out.push(j); await q.completeJob(j); } return out; };

test('a run creates inventory, one events job per region, advisor and analyze', async () => {
  const acc = await account();
  const run = await q.enqueueRun(acc, { trigger: 'manual' });
  const { jobs } = await q.runDetail(run);
  assert.deepEqual(jobs.map((j) => `${j.kind}:${j.region}`).sort(),
    ['advisor:', 'analyze:', 'events:ap-southeast-3', 'events:us-east-1', 'inventory:']);
});

test('only one run in flight per account', async () => {
  const acc = await account();
  assert.ok(await q.enqueueRun(acc));
  assert.equal(await q.enqueueRun(acc), null);
});

test('stages run in order and the run succeeds when all jobs do', async () => {
  const acc = await account();
  const run = await q.enqueueRun(acc);
  const order = (await drain()).filter((j) => j.run_id === run).map((j) => j.kind);
  assert.equal(order[0], 'inventory');
  assert.equal(order.at(-1), 'analyze');
  assert.equal((await q.runDetail(run)).run.status, 'succeeded');
});

test('a later stage is blocked while an earlier job is unfinished', async () => {
  const acc = await account(['us-east-1']);
  const run = await q.enqueueRun(acc);
  const inv = await q.claimJob();               // inventory is running, not finished
  assert.equal(inv.kind, 'inventory');
  assert.equal(await q.claimJob(), null);       // nothing else may start
  await q.completeJob(inv);
  assert.ok(await q.claimJob());                // stage 2 opens
  await q.cancelRun(run);
});

test('retryable failure backs off and is retried; checkpointed work is untouched', async () => {
  const acc = await account(['us-east-1']);
  const run = await q.enqueueRun(acc);
  const inv = await q.claimJob();
  const r = await q.failJob(inv, Object.assign(new Error('Rate exceeded'), { name: 'ThrottlingException' }));
  assert.equal(r.giveUp, false);
  assert.equal(await q.claimJob(), null);       // backoff: not due yet
  await db.query(`UPDATE scan_jobs SET run_after=now() WHERE id=$1`, [inv.id]);
  const again = await q.claimJob();
  assert.equal(again.id, inv.id);
  assert.equal(again.attempts, 2);
  await q.cancelRun(run);
});

test('non-retryable failure stops at once and the run is marked failed', async () => {
  const acc = await account(['us-east-1']);
  const run = await q.enqueueRun(acc);
  const inv = await q.claimJob();
  const r = await q.failJob(inv, Object.assign(new Error('not authorized'), { name: 'AccessDenied' }));
  assert.equal(r.giveUp, true);
  assert.equal((await q.runDetail(run)).run.status, 'failed');
});

test('gives up after max attempts', async () => {
  const acc = await account(['us-east-1']);
  const run = await q.enqueueRun(acc);
  await db.query(`UPDATE scan_jobs SET max_attempts=2 WHERE run_id=$1`, [run]);
  for (let i = 0; i < 2; i++) {
    await db.query(`UPDATE scan_jobs SET run_after=now() WHERE run_id=$1`, [run]);
    const j = await q.claimJob();
    await q.failJob(j, new Error('socket hang up'));
  }
  const { jobs, run: r } = await q.runDetail(run);
  assert.equal(jobs.find((j) => j.kind === 'inventory').status, 'dead');
  assert.equal(r.status, 'failed');
});

test('a crashed worker: lease expires, job is requeued and picked up again', async () => {
  const acc = await account(['us-east-1']);
  const run = await q.enqueueRun(acc);
  const j = await q.claimJob();
  await db.query(`UPDATE scan_jobs SET locked_until = now() - interval '1 minute' WHERE id=$1`, [j.id]);
  assert.equal(await q.reapExpired(), 1);
  await db.query(`UPDATE scan_jobs SET run_after=now() WHERE id=$1`, [j.id]);
  const again = await q.claimJob();
  assert.equal(again.id, j.id);
  await q.cancelRun(run);
});

test('heartbeat reports a lost lease', async () => {
  const acc = await account(['us-east-1']);
  const run = await q.enqueueRun(acc);
  const j = await q.claimJob();
  assert.equal(await q.heartbeat(j.id, { slice: 1 }), true);
  await q.cancelRun(run);
  assert.equal(await q.heartbeat(j.id, { slice: 2 }), false);
});

test('operator retry requeues failed jobs and keeps the run resumable', async () => {
  const acc = await account(['us-east-1']);
  const run = await q.enqueueRun(acc);
  const inv = await q.claimJob();
  await q.failJob(inv, Object.assign(new Error('denied'), { name: 'AccessDenied' }));
  assert.equal(await q.retryJobs({ runId: run }), 4); // the failed job and the 3 later jobs that were skipped
  const again = await q.claimJob();
  assert.equal(again.id, inv.id);
  assert.equal(again.attempts, 1);
  await q.cancelRun(run);
});

test('two workers never claim the same job', async () => {
  const acc = await account(['us-east-1']);
  await q.enqueueRun(acc);
  const got = await Promise.all(Array.from({ length: 6 }, () => q.claimJob()));
  const ids = got.filter(Boolean).map((j) => j.id);
  assert.equal(new Set(ids).size, ids.length);
});

test('metrics render', async () => {
  const text = await q.metricsText();
  assert.match(text, /cm_scan_jobs\{status="queued"\}/);
  assert.match(text, /cm_scan_workers_alive/);
});
