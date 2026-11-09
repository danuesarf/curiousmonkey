// Event source (Event History vs S3 trail), longer lookback with backfill, credential modes and the account API.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { startPg } from './helpers/pg.js';

process.env.AWS_MODE = 'demo';
process.env.LOOKUP_DELAY_MS = '0';
let pg, db, q, w, trailDayPrefix, fileTimeFromKey, principalFromCallerArn, scannerPolicy, scannerSnippets;
before(async () => {
  pg = await startPg(54336);
  db = await import('../src/db.js');
  await (await import('../src/migrate.js')).migrate(() => {});
  q = await import('../src/queue.js'); w = await import('../src/worker.js');
  ({ trailDayPrefix, fileTimeFromKey } = await import('../src/aws/trailKeys.js'));
  ({ principalFromCallerArn } = await import('../src/aws/credentials.js'));
  ({ scannerPolicy, scannerSnippets } = await import('../src/onboarding.js'));
  await q.registerWorker();
  await db.query(`INSERT INTO workspace(name, slug, external_id) VALUES ('KBI','kbi','ext-123')`);
});
after(async () => { await db.closePool(); await pg.stop(); });

async function drain() {
  for (let guard = 0; guard < 400; guard++) {
    const job = await q.claimJob();
    if (!job) {
      const open = (await db.query(`SELECT count(*)::int n FROM scan_jobs WHERE status='queued'`)).rows[0].n;
      if (!open) return;
      await db.query(`UPDATE scan_jobs SET run_after=now() WHERE status='queued'`);
      continue;
    }
    try { await w.runJob(job); } catch (e) { await q.failJob(job, e); }
  }
  throw new Error('queue did not drain');
}
const calls = async (acc) => (await db.query(
  `SELECT coalesce(sum(d.count),0)::int AS n FROM activity_daily d JOIN roles r ON r.id=d.role_id WHERE r.account_id=$1`, [acc])).rows[0].n;
const cp = async (acc) => (await db.query(`SELECT * FROM scan_checkpoints WHERE account_id=$1 AND region='ap-southeast-3'`, [acc])).rows[0];
const DAY = 864e5;

test('trail key layout and file timestamps follow CloudTrail’s S3 naming', () => {
  const a = { account_id: '111111111111', s3_prefix: '/logs/', s3_org_id: 'o-abc123def4' };
  assert.equal(trailDayPrefix(a, 'us-east-1', new Date(Date.UTC(2026, 7, 9))), 'logs/AWSLogs/o-abc123def4/111111111111/CloudTrail/us-east-1/2026/08/09/');
  assert.equal(trailDayPrefix({ account_id: '1' }, 'eu-west-1', new Date(Date.UTC(2026, 0, 2))), 'AWSLogs/1/CloudTrail/eu-west-1/2026/01/02/');
  assert.equal(fileTimeFromKey('x/111_CloudTrail_us-east-1_20260809T0105Z_AbC.json.gz'), Date.UTC(2026, 7, 9, 1, 5));
  assert.equal(fileTimeFromKey('x/digest.json'), null);
});

test('session ARNs become the role ARN a trust policy can name', () => {
  assert.equal(principalFromCallerArn('arn:aws:sts::123456789012:assumed-role/curious-monkey-worker/i-0abc'), 'arn:aws:iam::123456789012:role/curious-monkey-worker');
  assert.equal(principalFromCallerArn('arn:aws:iam::123456789012:user/cm'), 'arn:aws:iam::123456789012:user/cm');
});

test('the S3 policy reads only the trail’s log files and keeps every other data Deny', () => {
  const p = scannerPolicy({ s3: { bucket: 'acme-org-cloudtrail', prefix: 'org' } });
  const deny = p.Statement.find((s) => s.Sid === 'NeverReadOtherObjects');
  assert.equal(deny.NotResource, 'arn:aws:s3:::acme-org-cloudtrail/org/AWSLogs/*');
  assert.ok(p.Statement.find((s) => s.Sid === 'NeverDecryptOutsideCloudTrail').Condition.Null);
  assert.ok(p.Statement.find((s) => s.Sid === 'NeverReadCustomerData').Action.includes('secretsmanager:GetSecretValue'));
  const plain = scannerPolicy({});
  assert.deepEqual(plain.Statement.find((s) => s.Sid === 'NeverReadObjectsOrDecrypt').Action, ['s3:GetObject', 's3:GetObjectVersion', 'kms:Decrypt']);
  const user = scannerSnippets({ mode: 'access_key', externalId: 'x' });
  assert.match(user.terraform, /aws_iam_user_policy/); assert.doesNotMatch(user.terraform, /ExternalId|aws_iam_access_key"/);
});

let A;
test('an account reading its trail from S3 scans fully and marks that trail’s data events readable', async () => {
  A = (await db.query(`INSERT INTO cloud_accounts(account_id, name, role_arn, regions, status, event_source, s3_bucket, lookback_days)
    VALUES ('333333333333','s3acct','arn:aws:iam::333333333333:role/CuriousMonkeyScanner','{ap-southeast-3}','connected','s3','acme-org-cloudtrail',90) RETURNING id`)).rows[0].id;
  const run = await q.enqueueRun(A, { trigger: 'manual' });
  await drain();
  assert.equal((await q.runDetail(run)).run.status, 'succeeded');
  assert.ok(await calls(A) > 0);
  const c = await cp(A);
  assert.equal(c.source, 's3');
  const readable = (await db.query(`SELECT bool_and(readable) r FROM data_event_sources WHERE account_id=$1`, [A])).rows[0].r;
  assert.equal(readable, true);
  const ev = (await db.query(`SELECT progress FROM scan_jobs WHERE run_id=$1 AND kind='events'`, [run])).rows[0].progress;
  assert.equal(ev.source, 's3'); assert.equal(typeof ev.etaSeconds, 'number'); assert.equal(ev.done, ev.total);
});

test('widening the lookback backfills older history without re-reading what is stored', async () => {
  const before = await calls(A), c0 = await cp(A);
  await db.query(`UPDATE cloud_accounts SET lookback_days=120 WHERE id=$1`, [A]);
  await db.query(`UPDATE scan_runs SET status='succeeded'`);
  const run = await q.enqueueRun(A, { trigger: 'manual' });
  await drain();
  assert.equal((await q.runDetail(run)).run.status, 'succeeded');
  const c1 = await cp(A);
  const movedDays = (new Date(c0.first_event_time) - new Date(c1.first_event_time)) / DAY;
  assert.ok(movedDays > 29 && movedDays < 31, `history start moved ${movedDays} days`);
  assert.ok(new Date(c1.last_event_time) >= new Date(c0.last_event_time));
  const after = await calls(A);
  assert.ok(after < before * 1.6, `backfill double counted: ${before} -> ${after}`);
  // a third scan has nothing old left to read
  await db.query(`UPDATE scan_runs SET status='succeeded'`);
  const r3 = await q.enqueueRun(A, { trigger: 'manual' });
  await drain();
  const ev = (await db.query(`SELECT progress FROM scan_jobs WHERE run_id=$1 AND kind='events'`, [r3])).rows[0].progress;
  assert.ok(!ev.total || ev.total <= 3, `expected only the new tail, got ${ev.total}`);
});

test('switching back to Event History keeps the checkpoint instead of starting over', async () => {
  const before = await calls(A);
  await db.query(`UPDATE cloud_accounts SET event_source='event-history', lookback_days=90 WHERE id=$1`, [A]);
  await db.query(`UPDATE scan_runs SET status='succeeded'`);
  await q.enqueueRun(A, { trigger: 'manual' });
  await drain();
  assert.equal((await cp(A)).source, 'event-history');
  assert.ok(await calls(A) - before < before / 20);
});

test('stored keys that are missing fail at once with a reason on the account', async () => {
  const id = (await db.query(`INSERT INTO cloud_accounts(account_id, name, regions, status, auth_mode, base_identity)
    VALUES ('444444444444','nokeys','{ap-southeast-3}','pending','access_key','stored') RETURNING id`)).rows[0].id;
  process.env.AWS_MODE = 'aws';
  const cfg = (await import('../src/config.js')).config; const prev = cfg.awsMode; cfg.awsMode = 'aws';
  try {
    await q.enqueueRun(id, { trigger: 'onboarding' });
    await drain();
  } finally { cfg.awsMode = prev; process.env.AWS_MODE = 'demo'; }
  const a = (await db.query('SELECT status, status_detail FROM cloud_accounts WHERE id=$1', [id])).rows[0];
  assert.equal(a.status, 'error'); assert.match(a.status_detail.message, /stored access keys/);
  const job = (await db.query(`SELECT j.attempts, j.status FROM scan_jobs j JOIN scan_runs r ON r.id=j.run_id WHERE r.account_id=$1 AND j.kind='inventory'`, [id])).rows[0];
  assert.equal(job.attempts, 1);                     // not retried five times
});
