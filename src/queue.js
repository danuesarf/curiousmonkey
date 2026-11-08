// Postgres job queue for scans. No external broker: jobs are rows, claimed with SKIP LOCKED,
// protected by a lease that heartbeats extend. A dead worker's lease expires and the reaper requeues the job.
import os from 'node:os';
import crypto from 'node:crypto';
import { query, tx } from './db.js';

export const LEASE_SECONDS = 90;
export const workerId = `${os.hostname()}:${process.pid}:${crypto.randomBytes(3).toString('hex')}`;

// Errors worth retrying: throttling, network, 5xx, and an expired role session (a new attempt assumes the role again).
// Credential and permission problems are not. Expired *base* keys are raised as non-retryable by the credentials module.
const NON_RETRYABLE = /AccessDenied|UnauthorizedOperation|InvalidClientTokenId|ValidationError|InvalidParameter|NoSuchEntity|not_found|ExternalId/i;
const RETRYABLE = /ExpiredToken|security token included in the request is expired|Throttl|Rate exceeded|TooManyRequests|ECONNRESET|ETIMEDOUT|EAI_AGAIN|socket hang up|ServiceUnavailable|InternalFailure|RequestTimeout|5\d\d/i;

export function classifyError(e) {
  const text = `${e?.name || ''} ${e?.code || ''} ${e?.message || ''}`;
  if (e?.retryable === true) return true;
  if (e?.retryable === false) return false;
  if (RETRYABLE.test(text)) return true;
  if (NON_RETRYABLE.test(text)) return false;
  return true; // unknown errors get the benefit of the doubt, up to max_attempts
}

export const backoffSeconds = (attempt) => {
  const base = Math.min(30 * 2 ** (attempt - 1), 1800); // 30s, 60s, 2m, 4m ... capped at 30m
  return Math.round(base * (0.8 + Math.random() * 0.4));
};

// ---- enqueueing ----
const STAGES = [
  { stage: 1, kind: 'inventory' },
  { stage: 2, kind: 'events' },   // per region
  { stage: 2, kind: 'advisor' },
  { stage: 3, kind: 'analyze' },
];

/** Create a run and its jobs. Returns null if the account already has a run in flight. */
export async function enqueueRun(accountId, { trigger = 'schedule', requestedBy = null } = {}) {
  return tx(async (c) => {
    await c.query('SELECT pg_advisory_xact_lock(hashtext($1))', [`run:${accountId}`]);
    const busy = await c.query(
      `SELECT id FROM scan_runs WHERE account_id=$1 AND status IN ('queued','running') LIMIT 1`, [accountId]);
    if (busy.rowCount) return null;
    const acc = (await c.query('SELECT regions FROM cloud_accounts WHERE id=$1', [accountId])).rows[0];
    if (!acc) throw new Error('account not found');
    const run = (await c.query(
      `INSERT INTO scan_runs(account_id, trigger, requested_by, status) VALUES ($1,$2,$3,'queued') RETURNING id`,
      [accountId, trigger, requestedBy])).rows[0];
    for (const s of STAGES) {
      const regions = s.kind === 'events' ? acc.regions : [''];
      for (const region of regions) {
        await c.query(
          `INSERT INTO scan_jobs(run_id, account_id, kind, region, stage) VALUES ($1,$2,$3,$4,$5)`,
          [run.id, accountId, s.kind, region, s.stage]);
      }
    }
    return run.id;
  });
}

// ---- worker side ----
export async function registerWorker(version = '0.1.0') {
  await query(
    `INSERT INTO workers(id, hostname, version) VALUES ($1,$2,$3)
     ON CONFLICT (id) DO UPDATE SET heartbeat_at=now(), stopped_at=NULL`, [workerId, os.hostname(), version]);
}
export const workerBeat = (jobId = null) =>
  query(`UPDATE workers SET heartbeat_at=now(), current_job=$2 WHERE id=$1`, [workerId, jobId]);
export const workerStop = () =>
  query(`UPDATE workers SET stopped_at=now(), current_job=NULL WHERE id=$1`, [workerId]);

/**
 * Claim one runnable job: queued, due, and every job of an earlier stage in the same run has succeeded.
 * A failed/dead earlier job blocks the run (it is shown as failed and can be retried by hand).
 */
export async function claimJob() {
  return tx(async (c) => {
    const { rows } = await c.query(
      `SELECT j.id FROM scan_jobs j
        WHERE j.status='queued' AND j.run_after <= now()
          AND NOT EXISTS (SELECT 1 FROM scan_jobs p
                           WHERE p.run_id=j.run_id AND p.stage < j.stage AND p.status <> 'succeeded')
        ORDER BY j.stage, j.run_after, j.created_at
        LIMIT 1
        FOR UPDATE OF j SKIP LOCKED`);
    if (!rows.length) return null;
    const job = (await c.query(
      `UPDATE scan_jobs SET status='running', attempts=attempts+1, locked_by=$2,
              locked_until = now() + make_interval(secs => $3), heartbeat_at=now(),
              started_at = COALESCE(started_at, now())
        WHERE id=$1 RETURNING *`, [rows[0].id, workerId, LEASE_SECONDS])).rows[0];
    await c.query(
      `UPDATE scan_runs SET status='running', started_at = COALESCE(started_at, now()) WHERE id=$1 AND status='queued'`,
      [job.run_id]);
    await c.query(`UPDATE workers SET current_job=$2, heartbeat_at=now() WHERE id=$1`, [workerId, job.id]);
    await c.query(`INSERT INTO scan_job_log(job_id, message, detail) VALUES ($1,$2,$3)`,
      [job.id, `attempt ${job.attempts} started on ${workerId}`, null]);
    return job;
  });
}

/** Extend the lease and record progress. Returns false if we lost the job (reaped or canceled). */
export async function heartbeat(jobId, progress) {
  const r = await query(
    `UPDATE scan_jobs SET locked_until = now() + make_interval(secs => $3), heartbeat_at=now(),
            progress = COALESCE($4::jsonb, progress)
      WHERE id=$1 AND locked_by=$2 AND status='running'`,
    [jobId, workerId, LEASE_SECONDS, progress ? JSON.stringify(progress) : null]);
  return r.rowCount === 1;
}

export async function jobLog(jobId, message, detail = null, level = 'info') {
  await query(`INSERT INTO scan_job_log(job_id, level, message, detail) VALUES ($1,$2,$3,$4)`,
    [jobId, level, message, detail ? JSON.stringify(detail) : null]);
}

export async function completeJob(job, progress) {
  await tx(async (c) => {
    await c.query(
      `UPDATE scan_jobs SET status='succeeded', finished_at=now(), locked_by=NULL, locked_until=NULL,
              last_error=NULL, progress = COALESCE($3::jsonb, progress)
        WHERE id=$1 AND locked_by=$2`, [job.id, workerId, progress ? JSON.stringify(progress) : null]);
    await c.query(`UPDATE workers SET jobs_done=jobs_done+1, current_job=NULL WHERE id=$1`, [workerId]);
    await c.query(`INSERT INTO scan_job_log(job_id, message) VALUES ($1,'succeeded')`, [job.id]);
    await finishRunIfDone(c, job.run_id);
  });
}

/** Retry with backoff, or give up. The checkpoint tables mean a retry never redoes finished slices. */
export async function failJob(job, err) {
  const retryable = classifyError(err);
  const msg = String(err?.message || err).slice(0, 2000);
  const giveUp = !retryable || job.attempts >= job.max_attempts;
  await tx(async (c) => {
    if (giveUp) {
      await c.query(
        `UPDATE scan_jobs SET status=$3, finished_at=now(), locked_by=NULL, locked_until=NULL,
                last_error=$4, error_retryable=$5 WHERE id=$1 AND locked_by=$2`,
        [job.id, workerId, retryable ? 'dead' : 'failed', msg, retryable]);
    } else {
      await c.query(
        `UPDATE scan_jobs SET status='queued', locked_by=NULL, locked_until=NULL, last_error=$3,
                error_retryable=$4, run_after = now() + make_interval(secs => $5) WHERE id=$1 AND locked_by=$2`,
        [job.id, workerId, msg, retryable, backoffSeconds(job.attempts)]);
    }
    await c.query(`UPDATE workers SET jobs_failed=jobs_failed+1, current_job=NULL WHERE id=$1`, [workerId]);
    await c.query(`INSERT INTO scan_job_log(job_id, level, message) VALUES ($1,'error',$2)`,
      [job.id, `${giveUp ? (retryable ? 'gave up after retries' : 'failed, not retryable') : 'will retry'}: ${msg}`]);
    if (giveUp) await finishRunIfDone(c, job.run_id);
  });
  return { giveUp, retryable };
}

/** Requeue running jobs whose lease expired (worker crashed, pod evicted). */
export async function reapExpired() {
  const { rows } = await query(
    `UPDATE scan_jobs SET
        status = CASE WHEN attempts >= max_attempts THEN 'dead' ELSE 'queued' END,
        finished_at = CASE WHEN attempts >= max_attempts THEN now() END,
        locked_by=NULL, locked_until=NULL,
        last_error = 'worker lost: lease expired',
        error_retryable = true,
        run_after = now() + make_interval(secs => 10)
      WHERE status='running' AND locked_until < now()
      RETURNING id, run_id, status`);
  for (const r of rows) {
    await jobLog(r.id, `lease expired, job ${r.status === 'dead' ? 'marked dead' : 'requeued'}`, null, 'warn');
    if (r.status === 'dead') await tx((c) => finishRunIfDone(c, r.run_id));
  }
  return rows.length;
}

/** A job that can never run (an earlier stage gave up) is skipped, so the run can finish as failed/partial. */
async function skipBlocked(c, runId) {
  const r = await c.query(
    `UPDATE scan_jobs j SET status='canceled', finished_at=now()
      WHERE j.run_id=$1 AND j.status='queued'
        AND EXISTS (SELECT 1 FROM scan_jobs p WHERE p.run_id=j.run_id AND p.stage < j.stage AND p.status IN ('failed','dead','canceled'))
      RETURNING j.id`, [runId]);
  for (const x of r.rows) await c.query(`INSERT INTO scan_job_log(job_id, level, message) VALUES ($1,'warn','skipped: an earlier stage failed')`, [x.id]);
}

async function finishRunIfDone(c, runId) {
  await skipBlocked(c, runId);
  const { rows } = await c.query(
    `SELECT count(*) FILTER (WHERE status IN ('queued','running')) AS open,
            count(*) FILTER (WHERE status IN ('failed','dead')) AS bad,
            count(*) FILTER (WHERE status='succeeded') AS ok
       FROM scan_jobs WHERE run_id=$1`, [runId]);
  const { open, bad, ok } = rows[0];
  if (open > 0) return;
  const status = bad === 0 ? 'succeeded' : ok > 0 ? 'partial' : 'failed';
  const run = (await c.query(
    `UPDATE scan_runs SET status=$2, finished_at=now() WHERE id=$1 AND status IN ('queued','running') RETURNING account_id`,
    [runId, status])).rows[0];
  if (run && status !== 'failed') await c.query(`UPDATE cloud_accounts SET last_scan_at=now() WHERE id=$1`, [run.account_id]);
}

// ---- operator actions (used by the monitoring UI) ----
/** Retry failed/dead jobs of a run (or one job). Keeps checkpoints, so work resumes where it stopped. */
export async function retryJobs({ runId, jobId }) {
  return tx(async (c) => {
    const { rows } = await c.query(
      `UPDATE scan_jobs SET status='queued', attempts=0, run_after=now(), finished_at=NULL, last_error=last_error
        WHERE status IN ('failed','dead','canceled') AND ($1::uuid IS NULL OR run_id=$1) AND ($2::uuid IS NULL OR id=$2)
        RETURNING id, run_id`, [runId ?? null, jobId ?? null]);
    for (const r of rows) await c.query(`INSERT INTO scan_job_log(job_id, message) VALUES ($1,'retried by an operator')`, [r.id]);
    const runs = [...new Set(rows.map((r) => r.run_id))];
    if (runs.length) await c.query(`UPDATE scan_runs SET status='queued', finished_at=NULL, error=NULL WHERE id = ANY($1)`, [runs]);
    return rows.length;
  });
}

export const SLICE_CHOICES = [6, 2, 1, 0.5, 0.25];

/**
 * Read one account's region again from the start of its lookback. The region's checkpoint is dropped, so the
 * events job walks every slice again, optionally in smaller slices. Events already applied stay recorded in
 * seen_events and are skipped, so usage is never counted twice. The run's later jobs (analyze) are requeued too.
 */
export async function rebuildRegion({ jobId, sliceHours = null }) {
  return tx(async (c) => {
    const job = (await c.query(`SELECT * FROM scan_jobs WHERE id=$1 FOR UPDATE`, [jobId])).rows[0];
    if (!job) return { error: 'not-found' };
    if (job.kind !== 'events') return { error: 'not-events' };
    if (job.status === 'running') return { error: 'running' };
    if (sliceHours != null && !SLICE_CHOICES.includes(sliceHours)) return { error: 'slice' };
    await c.query(`DELETE FROM scan_checkpoints WHERE account_id=$1 AND region=$2`, [job.account_id, job.region]);
    await c.query(
      `UPDATE scan_jobs SET status='queued', attempts=0, run_after=now(), finished_at=NULL, last_error=NULL, error_retryable=NULL,
              locked_by=NULL, locked_until=NULL, progress='{}', options = options - 'sliceHours' || $2::jsonb
        WHERE id=$1`, [job.id, JSON.stringify(sliceHours ? { sliceHours } : {})]);
    await c.query(`INSERT INTO scan_job_log(job_id, message) VALUES ($1,$2)`,
      [job.id, `rebuild requested by an operator: reading ${job.region} again from the start${sliceHours ? ` in ${sliceHours} h slices` : ''}`]);
    const later = await c.query(
      `UPDATE scan_jobs SET status='queued', attempts=0, run_after=now(), finished_at=NULL
        WHERE run_id=$1 AND stage > $2 AND status IN ('succeeded','failed','dead','canceled') RETURNING id`, [job.run_id, job.stage]);
    for (const r of later.rows) await c.query(`INSERT INTO scan_job_log(job_id, message) VALUES ($1,'requeued: a region of this scan is being rebuilt')`, [r.id]);
    await c.query(`UPDATE scan_runs SET status='queued', finished_at=NULL, error=NULL WHERE id=$1`, [job.run_id]);
    return { requeued: 1 + later.rowCount, accountId: job.account_id, region: job.region };
  });
}

export async function cancelRun(runId) {
  return tx(async (c) => {
    const r = await c.query(
      `UPDATE scan_jobs SET status='canceled', finished_at=now(), locked_by=NULL, locked_until=NULL
        WHERE run_id=$1 AND status IN ('queued','running')`, [runId]);
    await c.query(`UPDATE scan_runs SET status='failed', finished_at=now(), error='canceled by an operator' WHERE id=$1 AND status IN ('queued','running')`, [runId]);
    return r.rowCount;
  });
}

// ---- monitoring ----
export async function queueOverview() {
  const [counts, workers, runs, oldest, throughput] = await Promise.all([
    query(`SELECT status, count(*)::int AS n FROM scan_jobs GROUP BY status`),
    query(`SELECT id, hostname, version, started_at, heartbeat_at, current_job, jobs_done, jobs_failed, stopped_at,
                  (stopped_at IS NULL AND heartbeat_at > now() - interval '60 seconds') AS alive
             FROM workers WHERE stopped_at IS NULL OR stopped_at > now() - interval '1 day'
            ORDER BY started_at DESC LIMIT 50`),
    query(`SELECT r.id, r.status, r.trigger, r.created_at, r.started_at, r.finished_at, r.error,
                  a.name AS account_name, a.account_id AS aws_account_id,
                  count(j.*)::int AS jobs,
                  count(*) FILTER (WHERE j.status='succeeded')::int AS jobs_ok,
                  count(*) FILTER (WHERE j.status IN ('failed','dead'))::int AS jobs_bad,
                  max((j.progress->>'etaSeconds')::int) FILTER (WHERE j.status='running') AS eta_seconds,
                  count(*) FILTER (WHERE j.status='running')::int AS jobs_running
             FROM scan_runs r JOIN cloud_accounts a ON a.id=r.account_id
             LEFT JOIN scan_jobs j ON j.run_id=r.id
            GROUP BY r.id, a.name, a.account_id ORDER BY r.created_at DESC LIMIT 30`),
    query(`SELECT extract(epoch FROM now() - min(run_after))::int AS secs FROM scan_jobs WHERE status='queued' AND run_after <= now()`),
    query(`SELECT count(*)::int AS n FROM scan_jobs WHERE status='succeeded' AND finished_at > now() - interval '1 hour'`),
  ]);
  const byStatus = Object.fromEntries(counts.rows.map((r) => [r.status, r.n]));
  return {
    jobs: byStatus,
    workers: workers.rows,
    runs: runs.rows,
    oldestWaitingSeconds: oldest.rows[0].secs ?? 0,
    succeededLastHour: throughput.rows[0].n,
  };
}

export async function runDetail(runId) {
  const run = (await query(
    `SELECT r.*, a.name AS account_name, a.account_id AS aws_account_id FROM scan_runs r
       JOIN cloud_accounts a ON a.id=r.account_id WHERE r.id=$1`, [runId])).rows[0];
  if (!run) return null;
  const jobs = (await query(
    `SELECT id, kind, region, stage, status, attempts, max_attempts, run_after, locked_by, heartbeat_at,
            progress, options, last_error, error_retryable, started_at, finished_at
       FROM scan_jobs WHERE run_id=$1 ORDER BY stage, kind, region`, [runId])).rows;
  return { run, jobs };
}

export async function jobLogs(jobId, limit = 200) {
  return (await query(
    `SELECT at, level, message, detail FROM scan_job_log WHERE job_id=$1 ORDER BY id DESC LIMIT $2`, [jobId, limit])).rows.reverse();
}

/** Prometheus text format for /metrics. */
export async function metricsText() {
  const o = await queueOverview();
  const lines = [];
  const g = (name, help, value, labels = '') => {
    lines.push(`# HELP ${name} ${help}`, `# TYPE ${name} gauge`, `${name}${labels} ${value}`);
  };
  lines.push('# HELP cm_scan_jobs Scan jobs by status', '# TYPE cm_scan_jobs gauge');
  for (const s of ['queued', 'running', 'succeeded', 'failed', 'dead', 'canceled']) {
    lines.push(`cm_scan_jobs{status="${s}"} ${o.jobs[s] || 0}`);
  }
  g('cm_scan_oldest_waiting_seconds', 'Age of the oldest runnable queued job', o.oldestWaitingSeconds);
  g('cm_scan_workers_alive', 'Workers with a recent heartbeat', o.workers.filter((w) => w.alive).length);
  g('cm_scan_jobs_succeeded_last_hour', 'Jobs finished in the last hour', o.succeededLastHour);
  const checkpoint = (await query(
    `SELECT extract(epoch FROM now() - min(last_event_time))::int AS lag FROM scan_checkpoints`)).rows[0];
  g('cm_scan_checkpoint_lag_seconds', 'How far behind the slowest checkpoint is', checkpoint.lag ?? 0);
  return lines.join('\n') + '\n';
}
