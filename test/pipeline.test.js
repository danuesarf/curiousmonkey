import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { startPg } from './helpers/pg.js';

process.env.AWS_MODE = 'demo';
process.env.LOOKUP_DELAY_MS = '0';
let pg, db, q, w, demo;
before(async () => {
  pg = await startPg(54332);
  db = await import('../src/db.js');
  await (await import('../src/migrate.js')).migrate(() => {});
  q = await import('../src/queue.js'); w = await import('../src/worker.js'); demo = await import('../src/demo/gateway.js');
  await q.registerWorker();
  await db.query(`INSERT INTO workspace(name, slug, external_id) VALUES ('KBI','kbi','ext-123')`);
});
after(async () => { await db.closePool(); await pg.stop(); });

const mkAccount = async (acct) => (await db.query(
  `INSERT INTO cloud_accounts(account_id, name, role_arn, regions, status) VALUES ($1,$1,'arn:aws:iam::'||$1||':role/CuriousMonkeyScanner','{ap-southeast-3,us-east-1}','connected') RETURNING id`, [acct])).rows[0].id;

async function drain() {
  for (let guard = 0; guard < 200; guard++) {
    const job = await q.claimJob();
    if (!job) {
      const open = (await db.query(`SELECT count(*)::int n FROM scan_jobs WHERE status='queued'`)).rows[0].n;
      if (!open) return;
      await db.query(`UPDATE scan_jobs SET run_after=now() WHERE status='queued'`);   // skip the backoff wait
      continue;
    }
    try { await w.runJob(job); } catch (e) { await q.failJob(job, e); }
  }
  throw new Error('queue did not drain');
}
const totals = async (acc) => (await db.query(
  `SELECT sum(d.count)::int AS calls, count(DISTINCT d.action)::int AS actions FROM activity_daily d JOIN roles r ON r.id=d.role_id WHERE r.account_id=$1`, [acc])).rows[0];
const role = async (acc, name) => (await db.query(`SELECT * FROM roles WHERE account_id=$1 AND name=$2`, [acc, name])).rows[0];

let A;
test('a full scan inventories roles of every kind and records who used them', async () => {
  A = await mkAccount('111111111111');
  const run = await q.enqueueRun(A);
  await drain();
  assert.equal((await q.runDetail(run)).run.status, 'succeeded');
  const roles = (await db.query(`SELECT name, kind FROM roles WHERE account_id=$1 ORDER BY name`, [A])).rows;
  assert.equal(roles.length, 10);
  assert.equal(roles.find((r) => r.name === 'AWSServiceRoleForECS').kind, 'service-linked');
  assert.equal(roles.find((r) => r.name.startsWith('AWSReservedSSO_')).kind, 'identity-center');
  const t = await totals(A);
  assert.ok(t.calls > 1000, `expected many calls, got ${t.calls}`);
});

test('inline and attached policies are both analysed', async () => {
  const r = await role(A, 'payments-api-prod');
  const kinds = (await db.query(`SELECT kind FROM role_policies WHERE role_id=$1 ORDER BY kind`, [r.id])).rows.map((x) => x.kind);
  assert.deepEqual(kinds, ['inline', 'managed']);
  const ssm = (await db.query(`SELECT status FROM role_actions WHERE role_id=$1 AND action='ssm:GetParameter'`, [r.id])).rows[0];
  assert.equal(ssm.status, 'used');                                  // granted by the attached managed policy, seen in events
});

test('used, unused and unconfirmed come out right for the payments role', async () => {
  const r = await role(A, 'payments-api-prod');
  const st = async (a) => (await db.query(`SELECT status, reason FROM role_actions WHERE role_id=$1 AND action=$2`, [r.id, a])).rows[0];
  assert.equal((await st('ec2:DescribeInstances')).status, 'used');
  assert.equal((await st('ec2:TerminateInstances')).status, 'unused');
  assert.equal((await st('s3:GetObject')).reason, 'data-event');
  assert.equal((await st('dynamodb:GetItem')).reason, 'data-event');
  assert.equal((await st('sqs:SendMessage')).reason, 'not-logged');
  assert.equal((await st('iam:PassRole')).reason, 'authorization-only');
});

test('PassRole is inferred from the role ARN seen in a RegisterTaskDefinition call', async () => {
  const r = await role(A, 'ci-deployer');
  assert.equal((await db.query(`SELECT status FROM role_actions WHERE role_id=$1 AND action='iam:PassRole'`, [r.id])).rows[0].status, 'used');
  const p = (await db.query(`SELECT passed_role_arn FROM passrole_observed WHERE role_id=$1`, [r.id])).rows;
  assert.match(p[0].passed_role_arn, /payments-task-exec/);
});

test('callers are shown with the conditions they met on entry', async () => {
  const r = await role(A, 'ci-deployer');
  const p = (await db.query(`SELECT * FROM principals WHERE role_id=$1`, [r.id])).rows[0];
  assert.equal(p.via, 'sts:AssumeRoleWithWebIdentity');
  assert.ok(p.caller.trust.matched);
  assert.ok(p.caller.trust.conditions.some((c) => c.includes('repo:krombank/platform:ref:refs/heads/main')));
});

test('an outside account user is flagged as an unexpected principal; denied calls do not count as use', async () => {
  const r = await role(A, 'legacy-admin');
  const flags = (await db.query(`SELECT category FROM flags WHERE role_id=$1`, [r.id])).rows.map((f) => f.category);
  assert.ok(flags.includes('wildcard'), `flags: ${flags}`); assert.ok(flags.includes('external-principal'), `flags: ${flags}`);
  assert.equal((await db.query(`SELECT risk, requires_both FROM roles WHERE id=$1`, [r.id])).rows[0].risk, 'High');
  assert.equal((await db.query(`SELECT status FROM role_actions WHERE role_id=$1 AND action='kms:ListKeys'`, [r.id])).rows[0].status, 'used'); // 2 of 3 calls succeeded
  const denied = (await db.query(`SELECT sum(error_count)::int n FROM activity_daily WHERE role_id=$1`, [r.id])).rows[0].n;
  assert.ok(denied > 0, `denied=${denied}`);
});

test('unused role is flagged idle; SSO goes to InfoSec, service-linked to InfraSec', async () => {
  const idle = await role(A, 'old-batch-runner');
  assert.ok((await db.query(`SELECT 1 FROM flags WHERE role_id=$1 AND category='role-idle'`, [idle.id])).rowCount);
  assert.equal((await role(A, 'AWSReservedSSO_PlatformEngineer_3f1c9a')).reviewer_team, 'infosec');
  assert.equal((await role(A, 'AWSServiceRoleForECS')).reviewer_team, 'infrasec');
});

test('buckets with data events are discovered', async () => {
  const d = (await db.query(`SELECT resource_type, arn_patterns FROM data_event_sources WHERE account_id=$1 ORDER BY resource_type`, [A])).rows;
  assert.equal(d.length, 2);
  assert.deepEqual(d.find((x) => x.resource_type === 'AWS::S3::Object').arn_patterns, ['arn:aws:s3:::kbi-payments-docs/']);
});

test('the next scan is incremental: it continues from the checkpoint and never double counts', async () => {
  const before = await totals(A);
  const cp0 = (await db.query(`SELECT last_event_time, first_event_time, events_read FROM scan_checkpoints WHERE account_id=$1 AND region='ap-southeast-3'`, [A])).rows[0];
  await db.query(`UPDATE scan_runs SET status='succeeded'`);
  const run = await q.enqueueRun(A, { trigger: 'schedule' });
  await drain();
  assert.equal((await q.runDetail(run)).run.status, 'succeeded');
  const after = await totals(A);
  const cp1 = (await db.query(`SELECT last_event_time, first_event_time, events_read FROM scan_checkpoints WHERE account_id=$1 AND region='ap-southeast-3'`, [A])).rows[0];
  assert.ok(new Date(cp1.last_event_time) >= new Date(cp0.last_event_time));
  assert.equal(String(cp1.first_event_time), String(cp0.first_event_time));        // history start never moves
  assert.ok(after.calls - before.calls < before.calls / 20, `second scan re-read history: ${before.calls} -> ${after.calls}`);
  // the slice-count shows we only read the new tail, not 90 days
  const ev = (await db.query(`SELECT progress FROM scan_jobs WHERE run_id=$1 AND kind='events' AND region='ap-southeast-3'`, [run])).rows[0].progress;
  assert.ok(ev.total <= 3, `expected a tiny tail, got ${ev.total} slices`);
});

test('a scan interrupted by throttling resumes from its checkpoint and ends with identical totals', async () => {
  const B = await mkAccount('222222222222');
  demo.resetDemoCalls(); globalThis.__demoFailAt = 60;
  const run = await q.enqueueRun(B);
  // drive only up to the failure
  let failed = false;
  while (!failed) {
    const job = await q.claimJob();
    if (!job) break;
    try { await w.runJob(job); } catch (e) { await q.failJob(job, e); failed = true; }
  }
  globalThis.__demoFailAt = 0;
  assert.ok(failed, 'the injected throttle should have fired');
  const mid = (await db.query(`SELECT last_event_time FROM scan_checkpoints WHERE account_id=$1`, [B])).rows;
  assert.ok(mid.length >= 1, 'progress made before the failure was kept');
  const job = (await db.query(`SELECT status, attempts, last_error FROM scan_jobs WHERE run_id=$1 AND status='queued' AND attempts>0`, [run])).rows[0];
  assert.match(job.last_error, /Rate exceeded/);
  await drain();
  assert.equal((await q.runDetail(run)).run.status, 'succeeded');
  const resumed = await totals(B);
  // reference: a third account scanned cleanly right now must match the interrupted one
  const C = await mkAccount('333333333333');
  await q.enqueueRun(C); await drain();
  const ref = await totals(C);
  assert.ok(Math.abs(resumed.calls - ref.calls) <= ref.calls * 0.002, `resumed ${resumed.calls} vs clean ${ref.calls}`);
});

test('a role chain in the trail links sessions: airflow-worker → data-etl → lake-reader', async () => {
  const rows = (await db.query(
    `SELECT r.name, s.access_key_id, s.parent_key_id FROM track_sessions s JOIN roles r ON r.id=s.role_id
      WHERE s.account_id=$1 AND r.name IN ('airflow-worker','data-etl','lake-reader')`, [A])).rows;
  const byKey = new Map(rows.map((x) => [x.access_key_id, x]));
  const lake = rows.find((x) => x.name === 'lake-reader');
  assert.ok(lake, 'lake-reader sessions recorded');
  const etl = byKey.get(lake.parent_key_id);
  assert.equal(etl?.name, 'data-etl');
  assert.equal(byKey.get(etl.parent_key_id)?.name, 'airflow-worker');
  const used = (await db.query(`SELECT status FROM role_actions ra JOIN roles r ON r.id=ra.role_id WHERE r.account_id=$1 AND r.name='airflow-worker' AND ra.action='sts:AssumeRole'`, [A])).rows[0];
  assert.equal(used?.status, 'used');                                // assuming the next role counts as use of the first
});

test('a track opened on the middle session still shows the jump it made onward', async () => {
  const { buildTrack } = await import('../src/sessions.js');
  const mid = (await db.query(
    `SELECT s.id FROM track_sessions s JOIN roles r ON r.id=s.role_id
      WHERE s.account_id=$1 AND r.name='data-etl' AND EXISTS (SELECT 1 FROM track_sessions c WHERE c.parent_key_id=s.access_key_id) LIMIT 1`, [A])).rows[0];
  const t = await buildTrack({ scope_accounts: null }, mid.id);
  assert.deepEqual(t.sessions.map((s) => s.role), ['airflow-worker', 'data-etl', 'lake-reader']);
  assert.ok(t.calls.some((c) => c.lane === 1 && c.jumpTo === 2));
  assert.ok(!t.calls.some((c) => c.jumpOutOfView));
});

test('rebuilding one region re-reads only that region, in the chosen slices, without double counting', async () => {
  const before = await totals(A);
  const run = (await db.query(`SELECT run_id FROM scan_jobs j JOIN scan_runs r ON r.id=j.run_id WHERE r.account_id=$1 ORDER BY r.created_at DESC LIMIT 1`, [A])).rows[0].run_id;
  const job = (await db.query(`SELECT * FROM scan_jobs WHERE run_id=$1 AND kind='events' AND region='us-east-1'`, [run])).rows[0];
  const other = (await db.query(`SELECT last_event_time FROM scan_checkpoints WHERE account_id=$1 AND region='ap-southeast-3'`, [A])).rows[0];

  assert.equal((await q.rebuildRegion({ jobId: job.id, sliceHours: 7 })).error, 'slice');
  const r = await q.rebuildRegion({ jobId: job.id, sliceHours: 1 });
  assert.equal(r.region, 'us-east-1');
  assert.equal(r.requeued, 2);                                                     // the region and the analysis after it
  assert.equal((await db.query(`SELECT count(*)::int n FROM scan_checkpoints WHERE account_id=$1 AND region='us-east-1'`, [A])).rows[0].n, 0);
  await drain();

  const after = (await db.query(`SELECT * FROM scan_jobs WHERE id=$1`, [job.id])).rows[0];
  assert.equal(after.status, 'succeeded');
  assert.equal(after.progress.sliceHours, 1);
  assert.ok(after.progress.total > 24 * 30, `expected hourly slices, got ${after.progress.total}`);
  assert.deepEqual(await totals(A), before);                                       // seen events are skipped
  const same = (await db.query(`SELECT last_event_time FROM scan_checkpoints WHERE account_id=$1 AND region='ap-southeast-3'`, [A])).rows[0];
  assert.deepEqual(same, other);                                                   // the other region was not touched
  assert.equal((await q.runDetail(run)).run.status, 'succeeded');
});

test('a worker lost mid-run makes the next attempt read in smaller slices', async () => {
  const job = (await db.query(`SELECT j.* FROM scan_jobs j JOIN scan_runs r ON r.id=j.run_id WHERE r.account_id=$1 AND j.kind='events' AND j.region='ap-southeast-3' ORDER BY r.created_at DESC LIMIT 1`, [A])).rows[0];
  await db.query(`UPDATE scan_jobs SET status='queued', attempts=1, last_error='worker lost: lease expired', options='{}' WHERE id=$1`, [job.id]);
  await drain();
  const after = (await db.query(`SELECT options, progress, status FROM scan_jobs WHERE id=$1`, [job.id])).rows[0];
  assert.equal(after.status, 'succeeded');
  assert.equal(Number(after.options.sliceHours), 3);
});
