// Workers page: process telemetry, what is being read right now, and advice on what is missing.
import { query } from './db.js';
import { config } from './config.js';
import { markLostWorkers } from './queue.js';
import { effectiveLookback } from './settings.js';

const MB = 1024 * 1024;
const RANGES = { '1h': [60, '15 seconds'], '6h': [360, '2 minutes'], '24h': [1440, '5 minutes'] };

export async function workerStatus({ range = '1h' } = {}) {
  await markLostWorkers().catch(() => {});
  const [minutes, bin] = RANGES[range] || RANGES['1h'];
  const [ws, samples, jobs, fails, queue, accts] = await Promise.all([
    query(`SELECT id, hostname, version, started_at, heartbeat_at, current_job, jobs_done, jobs_failed, stopped_at, end_reason, concurrency, runtime, telemetry, aws_identity,
                  (stopped_at IS NULL AND heartbeat_at > now() - interval '60 seconds') AS alive
             FROM workers WHERE stopped_at IS NULL OR stopped_at > now() - interval '24 hours' ORDER BY started_at DESC LIMIT 100`),
    query(`SELECT worker_id, date_bin($2::interval, at, timestamptz '2000-01-01') AS t,
                  max(rss) AS rss, max(heap_used) AS heap_used, max(heap_limit) AS heap_limit, max(mem_used) AS mem_used, max(mem_limit) AS mem_limit,
                  avg(cpu_pct)::real AS cpu_pct, max(cpu_limit) AS cpu_limit, max(loop_p99_ms) AS loop_p99_ms, max(active_jobs) AS active_jobs,
                  sum(events)::int AS events, sum(s3_files)::int AS s3_files, sum(s3_bytes)::bigint AS s3_bytes, sum(api_calls)::int AS api_calls
             FROM worker_samples WHERE at > now() - make_interval(mins => $1) GROUP BY worker_id, t ORDER BY t`, [minutes, bin]),
    query(`SELECT j.id, j.run_id, j.kind, j.region, j.status, j.attempts, j.max_attempts, j.progress, j.options, j.last_error, j.heartbeat_at, j.started_at, j.run_after, j.locked_by,
                  a.id AS account_id, a.name AS account_name, a.account_id AS aws_account_id, a.event_source, a.lookback_days
             FROM scan_jobs j JOIN cloud_accounts a ON a.id=j.account_id
            WHERE j.status IN ('running','queued') OR (j.status IN ('dead','failed') AND j.finished_at > now() - interval '24 hours')
            ORDER BY CASE j.status WHEN 'running' THEN 0 WHEN 'queued' THEN 1 ELSE 2 END, j.started_at NULLS LAST LIMIT 200`),
    query(`SELECT left(last_error, 120) AS error, count(*)::int AS n, max(finished_at) AS last FROM scan_jobs
            WHERE status IN ('dead','failed') AND finished_at > now() - interval '24 hours' GROUP BY 1 ORDER BY n DESC LIMIT 10`),
    query(`SELECT count(*) FILTER (WHERE status='queued' AND run_after <= now())::int AS ready,
                  count(*) FILTER (WHERE status='running')::int AS running,
                  extract(epoch FROM now() - min(run_after) FILTER (WHERE status='queued' AND run_after <= now()))::int AS oldest_wait_s
             FROM scan_jobs`),
    query(`SELECT a.id, a.name, a.event_source, a.lookback_days, a.regions, c.region, c.gap_detected, c.first_event_time, c.caught_up_at
             FROM cloud_accounts a LEFT JOIN scan_checkpoints c ON c.account_id=a.id`),
  ]);
  const workers = ws.rows.map((w) => ({ ...w, series: samples.rows.filter((s) => s.worker_id === w.id).map((s) => ({
    t: s.t, rss: +s.rss, heapUsed: +s.heap_used, heapLimit: +s.heap_limit, memUsed: s.mem_used == null ? null : +s.mem_used, memLimit: s.mem_limit == null ? null : +s.mem_limit,
    cpuPct: s.cpu_pct, cpuLimit: s.cpu_limit, loopP99Ms: s.loop_p99_ms, activeJobs: s.active_jobs, events: s.events, s3Files: s.s3_files, s3Bytes: +s.s3_bytes, apiCalls: s.api_calls })) }));

  const now = Date.now();
  const reading = jobs.rows.map((j) => {
    const p = j.progress || {};
    const at = p.at ? new Date(p.at).getTime() : null;
    const stalled = j.status === 'running' && ((at && now - at > 15 * 60e3) || (!at && j.started_at && now - new Date(j.started_at) > 15 * 60e3));
    return { ...j, stalled, sinceProgressS: at ? Math.round((now - at) / 1000) : null };
  });
  const q = queue.rows[0];
  const advice = advise({ workers, reading, fails: fails.rows, queue: q, accounts: accts.rows });
  return { range, workers, reading, failures: fails.rows, queue: q, advice, settings: { sliceHours: config.scanner.sliceHours, maxLookbackDays: config.scanner.maxLookbackDays } };
}

// ---- advice ----
// Each item: { level: 'critical'|'warning'|'info'|'good', area: 'memory'|'cpu'|'capacity'|'reading'|'setup', title, detail, fix }
export function advise({ workers, reading, fails, queue, accounts }) {
  const out = [];
  const add = (level, area, title, detail, fix) => out.push({ level, area, title, detail, fix });
  const alive = workers.filter((w) => w.alive);
  const lost = workers.filter((w) => !w.alive && w.end_reason && w.end_reason !== 'stopped');
  const oom = lost.filter((w) => /memory/.test(w.end_reason));

  if (!alive.length) add('critical', 'capacity', 'No worker is running', 'Queued scans wait until a worker checks in.', 'Start the worker (npm run worker, or the worker Deployment).');
  if (oom.length) add('critical', 'memory', `${oom.length} worker restart${oom.length > 1 ? 's' : ''} in 24 h were most likely out of memory`,
    'The process stopped heartbeating while its heap or container memory was near the limit.',
    'Give the worker more memory, or lower Configuration → slice size so each slice holds fewer events. Check `kubectl describe pod` for OOMKilled.');
  else if (lost.length) add('warning', 'capacity', `${lost.length} worker${lost.length > 1 ? 's' : ''} stopped without shutting down in 24 h`,
    'They stopped heartbeating; their jobs were requeued after the lease expired.', 'Check the worker logs and pod events for crashes or evictions.');

  for (const w of alive) {
    const t = w.telemetry || {}, rt = w.runtime || {};
    const name = w.hostname;
    const heapPeak = Math.max(0, ...w.series.map((s) => s.heapUsed / (s.heapLimit || Infinity)), t.heapUsed / (t.heapLimit || Infinity) || 0);
    if (heapPeak > 0.85) add('critical', 'memory', `${name}: heap reached ${Math.round(heapPeak * 100)}% of its limit`, `The V8 heap limit is ${mb(t.heapLimit)}. Past it the process crashes with “JavaScript heap out of memory”.`,
      'Raise the heap with NODE_OPTIONS=--max-old-space-size (about 75% of the container memory), or lower the slice size.');
    else if (heapPeak > 0.7) add('warning', 'memory', `${name}: heap peaked at ${Math.round(heapPeak * 100)}% of its limit`, `Limit ${mb(t.heapLimit)}.`, 'Watch it during the next big backfill; raise the heap if it keeps climbing.');

    if (rt.memLimit && rt.heapLimit && rt.heapLimit < rt.memLimit * 0.5)
      add('info', 'memory', `${name}: the heap may use only ${mb(rt.heapLimit)} of ${mb(rt.memLimit)} container memory`,
        'Node sizes its heap conservatively, so most of the container memory is unused while the heap can still run out.',
        `Set NODE_OPTIONS=--max-old-space-size=${Math.round((rt.memLimit * 0.75) / MB)} on the worker.`);
    if (!rt.memLimit && rt.cgroup !== null) add('warning', 'setup', `${name}: no container memory limit`, 'The worker can take memory from everything else on the node, and Kubernetes cannot schedule it fairly.', 'Set resources.requests and resources.limits for memory on the worker.');
    if (rt.cgroup == null) add('info', 'setup', `${name}: not running in a container`, 'Container memory and CPU limits cannot be read, so only process figures are shown.', null);
    const memPeak = t.memLimit ? Math.max(0, ...w.series.map((s) => (s.memUsed || 0) / (s.memLimit || Infinity)), t.memUsed / t.memLimit) : 0;
    if (memPeak > 0.9) add('critical', 'memory', `${name}: container memory reached ${Math.round(memPeak * 100)}% of its limit`, 'The kernel kills the process (OOMKilled) at 100%.', 'Raise the memory limit or lower the slice size.');
    if (t.oomKills > 0) add('critical', 'memory', `${name}: the container OOM killer has fired ${t.oomKills} time${t.oomKills > 1 ? 's' : ''}`, 'Reported by the cgroup since the container started.', 'Raise the memory limit.');

    const cores = rt.cpuLimit || rt.availableCores || 1;
    const cpuAvg = avg(w.series.map((s) => s.cpuPct));
    if (cpuAvg != null && cpuAvg / 100 > cores * 0.85) add('warning', 'cpu', `${name}: CPU is at its limit (${Math.round(cpuAvg)}% of one core, limit ${cores} core${cores > 1 ? 's' : ''})`,
      'Reading is CPU-bound: decompressing and parsing trail files competes with the database writes.', 'Raise the CPU limit, or run another worker replica.');
    if (!rt.cpuLimit && rt.cgroup) add('info', 'setup', `${name}: no CPU limit`, 'Fine for a dedicated node; on a shared node set a request so the scheduler reserves CPU.', 'Set resources.requests.cpu on the worker.');
    const lag = Math.max(0, ...w.series.map((s) => s.loopP99Ms || 0));
    if (lag > 500) add('warning', 'cpu', `${name}: event loop stalled for up to ${Math.round(lag)} ms`, 'While the loop is blocked, heartbeats are late; past 90 s the job lease expires.', 'Usually a very large slice being sorted or written; lower the slice size.');
    if ((w.concurrency || rt.concurrency || 2) > cores * 2) add('info', 'cpu', `${name}: ${w.concurrency} job slots on ${cores} core${cores > 1 ? 's' : ''}`, 'More slots than the CPU can serve make each job slower, not the scan faster.', 'Lower WORKER_CONCURRENCY or raise the CPU limit.');
  }
  if (alive.length === 1) add('info', 'capacity', 'Only one worker', 'If it restarts, scans pause until it is back; jobs resume from their checkpoints.', 'Run 2 replicas for continuity; they share the queue safely.');

  // capacity
  if (queue.ready > 0 && queue.oldest_wait_s > 600) {
    const slots = alive.reduce((n, w) => n + (w.concurrency || 2), 0);
    add('warning', 'capacity', `${queue.ready} job${queue.ready > 1 ? 's' : ''} waiting, the oldest for ${dur(queue.oldest_wait_s)}`, `All ${slots} job slot${slots === 1 ? ' is' : 's are'} busy.`, 'Add a worker replica or raise WORKER_CONCURRENCY, if CPU and memory allow.');
  }

  // reading
  const stalled = reading.filter((j) => j.stalled);
  for (const j of stalled) add('warning', 'reading', `${j.account_name} ${j.region}: no progress for ${dur(j.sinceProgressS ?? 900)}`, 'The job is running but has not finished a slice. A huge slice, or a call hanging on AWS.', 'Look at its log on the Scans page. If it does not move, Rebuild the region with a smaller slice.');
  const dead = reading.filter((j) => ['dead', 'failed'].includes(j.status));
  const deadMem = dead.filter((j) => /lease expired|heap|memory/i.test(j.last_error || ''));
  if (deadMem.length) add('critical', 'reading', `${deadMem.length} region read${deadMem.length > 1 ? 's' : ''} gave up after the worker died`, deadMem.map((j) => `${j.account_name} ${j.region}`).join(', '), 'Rebuild each region on the Scans page with 1 h slices.');
  const deadAccess = dead.filter((j) => /AccessDenied|not authorized|InvalidClientTokenId|ExpiredToken/i.test(j.last_error || ''));
  if (deadAccess.length) add('critical', 'reading', `${deadAccess.length} read${deadAccess.length > 1 ? 's' : ''} failed on permissions`, deadAccess.map((j) => `${j.account_name} ${j.region}: ${String(j.last_error).slice(0, 80)}`).join('; '), 'Fix the scanner role, bucket policy or KMS key policy for that account, then Retry.');
  const slowEh = reading.filter((j) => j.kind === 'events' && j.status === 'running' && j.event_source === 'event-history' && (j.progress?.etaSeconds || 0) > 3 * 3600);
  for (const j of slowEh) add('info', 'reading', `${j.account_name} ${j.region}: Event History needs ${dur(j.progress.etaSeconds)} more`, 'AWS allows 2 LookupEvents calls a second per region, so a busy account reads slowly.', 'Switch the account to its S3 trail: no request limit, and history beyond 90 days.');
  const gaps = accounts.filter((a) => a.gap_detected);
  if (gaps.length) add('warning', 'reading', `${gaps.length} region${gaps.length > 1 ? 's have' : ' has'} a gap in history`, gaps.map((a) => `${a.name} ${a.region}`).join(', '), 'Scans stopped for longer than the source keeps events. Read the S3 trail, which keeps them longer, or accept the gap.');
  const neverRead = accounts.filter((a) => a.region == null);
  if (neverRead.length) add('info', 'reading', `${new Set(neverRead.map((a) => a.id)).size} account${neverRead.length > 1 ? 's have' : ' has'} never been read`, [...new Set(neverRead.map((a) => a.name))].join(', '), 'Run a scan for them from Accounts.');
  const capped = [...new Map(accounts.filter((a) => a.event_source === 's3' && a.lookback_days > effectiveLookback(a)).map((a) => [a.id, a])).values()];
  if (capped.length) add('info', 'reading', `${capped.length} account${capped.length > 1 ? 's ask' : ' asks'} for more history than the workspace maximum`, capped.map((a) => `${a.name} (${a.lookback_days} days)`).join(', '), 'Raise the maximum lookback under Configuration if you want it.');
  for (const f of fails.filter((x) => x.n >= 3 && !/lease expired|AccessDenied/i.test(x.error || ''))) add('warning', 'reading', `${f.n} jobs failed with the same error in 24 h`, f.error, 'Open one of them on the Scans page and read its log.');

  if (!out.some((o) => o.level === 'critical' || o.level === 'warning')) add('good', 'capacity', 'Nothing needs attention', 'Workers have headroom and every read is moving.', null);
  const order = { critical: 0, warning: 1, info: 2, good: 3 };
  return out.sort((a, b) => order[a.level] - order[b.level]);
}
const avg = (xs) => { const v = xs.filter((x) => x != null); return v.length ? v.reduce((a, b) => a + b, 0) / v.length : null; };
const mb = (b) => (b == null ? '—' : b >= 1024 * MB ? `${(b / 1024 / MB).toFixed(1)} GB` : `${Math.round(b / MB)} MB`);
const dur = (s) => (s >= 3600 ? `${Math.round(s / 360) / 10} h` : `${Math.max(1, Math.round(s / 60))} min`);
