// Process and container telemetry for the worker: memory against its limits, CPU against its quota, event-loop
// delay, and reading throughput. Sampled with the heartbeat, stored for 24 hours, shown on the Workers page.
import fs from 'node:fs';
import os from 'node:os';
import v8 from 'node:v8';
import { monitorEventLoopDelay } from 'node:perf_hooks';
import { parserCount } from './scanner/decode.js';

const read = (p) => { try { return fs.readFileSync(p, 'utf8').trim(); } catch { return null; } };
const num = (v) => (v == null || v === '' || v === 'max' || !Number.isFinite(Number(v)) || Number(v) > 2 ** 60 ? null : Number(v));

/** Container limits from cgroup v2, falling back to v1. null where there is no limit or no cgroup. */
export function cgroup() {
  const v2 = read('/sys/fs/cgroup/memory.max') != null;
  if (v2) {
    const [quota, period] = (read('/sys/fs/cgroup/cpu.max') || 'max 100000').split(/\s+/);
    const events = Object.fromEntries((read('/sys/fs/cgroup/memory.events') || '').split('\n').filter(Boolean).map((l) => l.split(/\s+/)).map(([k, v]) => [k, Number(v)]));
    const usage = (read('/sys/fs/cgroup/cpu.stat') || '').match(/usage_usec (\d+)/);
    return { version: 2, memLimit: num(read('/sys/fs/cgroup/memory.max')), memUsed: num(read('/sys/fs/cgroup/memory.current')),
      cpuLimit: num(quota) && num(period) ? num(quota) / num(period) : null, cpuUsageUs: usage ? Number(usage[1]) : null, oomKills: events.oom_kill ?? null };
  }
  const lim = num(read('/sys/fs/cgroup/memory/memory.limit_in_bytes'));
  const q = num(read('/sys/fs/cgroup/cpu/cpu.cfs_quota_us')), p = num(read('/sys/fs/cgroup/cpu/cpu.cfs_period_us'));
  const u = num(read('/sys/fs/cgroup/cpuacct/cpuacct.usage'));
  return { version: lim != null || q != null ? 1 : null, memLimit: lim, memUsed: num(read('/sys/fs/cgroup/memory/memory.usage_in_bytes')),
    cpuLimit: q && q > 0 && p ? q / p : null, cpuUsageUs: u != null ? u / 1000 : null, oomKills: null };
}

/** Facts about the process that do not change while it runs. */
export function runtime(concurrency) {
  const cg = cgroup();
  return { node: process.version, platform: `${os.platform()} ${os.arch()}`, pid: process.pid, hostCores: os.cpus().length,
    availableCores: os.availableParallelism?.() ?? os.cpus().length, cpuLimit: cg.cpuLimit, memLimit: cg.memLimit, hostMemory: os.totalmem(),
    heapLimit: v8.getHeapStatistics().heap_size_limit, cgroup: cg.version, concurrency, parserThreads: parserCount(),
    nodeOptions: (process.env.NODE_OPTIONS || '').replace(/--require\s+\S+/g, '').trim() || null };
}

// Counters bumped by the code that reads events; drained into each sample.
const counters = { events: 0, s3Files: 0, s3Bytes: 0, apiCalls: 0, throttles: 0 };
export const bump = (k, n = 1) => { counters[k] = (counters[k] || 0) + n; };

let active = 0;
export const jobStarted = () => { active++; };
export const jobEnded = () => { active = Math.max(0, active - 1); };

const loop = monitorEventLoopDelay({ resolution: 20 });
loop.enable();
let last = { t: process.hrtime.bigint(), cpu: process.cpuUsage() };

/** One sample since the previous call. */
export function sample() {
  const now = process.hrtime.bigint();
  const cpu = process.cpuUsage();
  const wallUs = Number(now - last.t) / 1000;
  const usedUs = (cpu.user - last.cpu.user) + (cpu.system - last.cpu.system);
  last = { t: now, cpu };
  const m = process.memoryUsage();
  const h = v8.getHeapStatistics();
  const cg = cgroup();
  const s = {
    at: new Date().toISOString(), uptimeS: Math.round(process.uptime()),
    rss: m.rss, heapUsed: m.heapUsed, heapTotal: m.heapTotal, heapLimit: h.heap_size_limit, external: m.external + (m.arrayBuffers || 0),
    memUsed: cg.memUsed, memLimit: cg.memLimit, oomKills: cg.oomKills,
    cpuPct: wallUs > 0 ? Math.round((usedUs / wallUs) * 1000) / 10 : null,           // % of one core
    cpuLimit: cg.cpuLimit, cores: os.availableParallelism?.() ?? os.cpus().length, load1: os.loadavg()[0],
    loopP99Ms: Math.round(loop.percentile(99) / 1e4) / 100, loopMaxMs: Math.round(loop.max / 1e4) / 100,
    activeJobs: active, ...counters,
  };
  loop.reset();
  for (const k of Object.keys(counters)) counters[k] = 0;
  return s;
}
