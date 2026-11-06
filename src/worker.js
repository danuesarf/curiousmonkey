// Background worker: claims scan jobs from Postgres and runs them. Run as many replicas as you like.
import { fileURLToPath } from 'node:url';
import { config, assertConfig } from './config.js';
import { pool, query, closePool } from './db.js';
import { migrate } from './migrate.js';
import {
  workerId, registerWorker, workerBeat, workerStop, claimJob, heartbeat, jobLog,
  completeJob, failJob, reapExpired, enqueueRun,
} from './queue.js';
import { handlers } from './scanner/jobs.js';

const log = (level, msg, extra = {}) =>
  console.log(JSON.stringify({ t: new Date().toISOString(), level, worker: workerId, msg, ...extra }));
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

export class LeaseLost extends Error {
  constructor() { super('lease lost'); this.name = 'LeaseLost'; this.retryable = true; }
}

/** Run one claimed job with a heartbeat. The handler gets a ctx it must use to report progress. */
export async function runJob(job) {
  const handler = handlers[job.kind];
  if (!handler) throw Object.assign(new Error(`no handler for ${job.kind}`), { retryable: false });
  let lost = false;
  let latest = job.progress || {};
  const beat = setInterval(async () => {
    try { if (!(await heartbeat(job.id, latest))) lost = true; } catch { /* next tick */ }
  }, 20_000);
  const ctx = {
    job,
    alive() { if (lost) throw new LeaseLost(); },          // handlers call this between slices
    async progress(p) {                                    // persisted at once, so the UI is live
      latest = { ...latest, ...p };
      if (!(await heartbeat(job.id, latest))) { lost = true; throw new LeaseLost(); }
    },
    log: (msg, detail, level) => jobLog(job.id, msg, detail, level),
  };
  try {
    const result = await handler(ctx);
    ctx.alive();
    await completeJob(job, { ...latest, ...(result || {}), finished: true });
  } finally {
    clearInterval(beat);
  }
}

async function loop(stop, slot) {
  while (!stop.stopped) {
    let job = null;
    try {
      job = await claimJob();
    } catch (e) {
      log('error', 'claim failed', { error: e.message });
      await sleep(2000);
      continue;
    }
    if (!job) { await sleep(config.schedule.pollSeconds * 1000 * (0.5 + Math.random())); continue; }
    log('info', 'job started', { job: job.id, kind: job.kind, region: job.region, attempt: job.attempts, slot });
    try {
      await runJob(job);
      log('info', 'job succeeded', { job: job.id, kind: job.kind });
    } catch (e) {
      if (e.name === 'LeaseLost') { log('warn', 'lease lost, abandoning job', { job: job.id }); continue; }
      const r = await failJob(job, e).catch((x) => { log('error', 'failJob failed', { error: x.message }); return {}; });
      log('warn', 'job failed', { job: job.id, kind: job.kind, error: e.message, giveUp: r.giveUp });
    }
  }
}

// ---- daily schedule ----
// Any worker may run the scheduler; the advisory lock makes exactly one of them do it per tick.
function localParts(tz, d = new Date()) {
  const f = new Intl.DateTimeFormat('en-GB', { timeZone: tz, hour12: false, year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit' });
  const p = Object.fromEntries(f.formatToParts(d).map((x) => [x.type, x.value]));
  return { day: `${p.year}-${p.month}-${p.day}`, hm: `${p.hour}:${p.minute}` };
}

export async function scheduleTick(now = new Date()) {
  const client = await pool.connect();
  try {
    const got = (await client.query('SELECT pg_try_advisory_lock(727002) AS ok')).rows[0].ok;
    if (!got) return 0;
    try {
      const { day, hm } = localParts(config.schedule.tz, now);
      if (hm < config.schedule.at) return 0;
      // A run today (any trigger) means the daily one is satisfied; catches up if the cluster was down at 01:00.
      const { rows } = await client.query(
        `SELECT a.id FROM cloud_accounts a
          WHERE a.status='connected'
            AND NOT EXISTS (SELECT 1 FROM scan_runs r WHERE r.account_id=a.id
                             AND (r.created_at AT TIME ZONE $1)::date = $2::date
                             AND r.trigger IN ('schedule'))`,
        [config.schedule.tz, day]);
      let n = 0;
      for (const a of rows) if (await enqueueRun(a.id, { trigger: 'schedule' })) n++;
      if (n) log('info', 'daily scans queued', { accounts: n });
      return n;
    } finally {
      await client.query('SELECT pg_advisory_unlock(727002)');
    }
  } finally {
    client.release();
  }
}

export async function startWorker({ concurrency = Number(process.env.WORKER_CONCURRENCY || 2), scheduler = true } = {}) {
  const stop = { stopped: false };
  await registerWorker();
  const timers = [
    setInterval(() => workerBeat().catch(() => {}), 15_000),
    setInterval(() => reapExpired().then((n) => n && log('warn', 'reaped expired jobs', { n })).catch(() => {}), 30_000),
  ];
  if (scheduler) timers.push(setInterval(() => scheduleTick().catch((e) => log('error', 'schedule failed', { error: e.message })), 60_000));
  const loops = Array.from({ length: concurrency }, (_, i) => loop(stop, i));
  log('info', 'worker started', { concurrency, scheduler });
  return {
    async stop() {
      stop.stopped = true;
      timers.forEach(clearInterval);
      await Promise.allSettled(loops);   // in-flight jobs finish their slice; leftover work resumes elsewhere
      await workerStop().catch(() => {});
    },
  };
}

// The worker never serves the portal and never migrates. The API (or the migrate job) owns the schema;
// the worker just waits until it exists. Its only listener is a tiny health/metrics port for probes.
async function waitForSchema() {
  for (let i = 0; ; i++) {
    try {
      const { rows } = await query(`SELECT to_regclass('public.scan_jobs') AS t`);
      if (rows[0].t) return;
    } catch { /* database not up yet */ }
    if (i % 5 === 0) log('info', 'waiting for database schema');
    await sleep(3000);
  }
}

async function startHealthServer(port) {
  const http = await import('node:http');
  const { metricsText } = await import('./queue.js');
  const srv = http.createServer(async (req, res) => {
    try {
      if (req.url === '/healthz') {
        await query('SELECT 1');                       // liveness: process is up and can reach Postgres
        res.writeHead(200).end('ok');
      } else if (req.url === '/metrics') {
        res.writeHead(200, { 'content-type': 'text/plain; version=0.0.4' }).end(await metricsText());
      } else res.writeHead(404).end();
    } catch (e) { res.writeHead(503).end(e.message); }
  });
  srv.listen(port, '0.0.0.0');
  return srv;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  assertConfig();
  if (process.env.WORKER_RUN_MIGRATIONS === 'true') await migrate((m) => log('info', m));
  await waitForSchema();
  const health = await startHealthServer(Number(process.env.WORKER_HEALTH_PORT || 8081));
  const w = await startWorker();
  const shutdown = async (sig) => {
    log('info', `${sig} received, draining`);
    // If a job outlives the grace period, Kubernetes kills us; the lease expires and another worker resumes.
    health.close();
    await w.stop();
    await closePool();
    process.exit(0);
  };
  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT', () => shutdown('SIGINT'));
}
