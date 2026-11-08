// Workers: process telemetry (memory, CPU, event loop), what is being read right now, and what is missing.
import { h, svg, get, num, ago, fmtDate } from '../lib.js';

const MB = 1024 * 1024;
const bytes = (b) => (b == null ? '—' : b >= 1024 * MB ? `${(b / 1024 / MB).toFixed(2)} GB` : `${Math.round(b / MB)} MB`);
const pct = (a, b) => (a != null && b ? Math.round((a / b) * 100) : null);
const dur = (s) => (s == null ? '—' : s >= 86400 ? `${Math.floor(s / 86400)} d ${Math.round((s % 86400) / 3600)} h` : s >= 3600 ? `${Math.floor(s / 3600)} h ${Math.round((s % 3600) / 60)} min` : s >= 60 ? `${Math.round(s / 60)} min` : `${s} s`);
const LEVEL = { critical: ['Critical', 'lv-critical', '!'], warning: ['Warning', 'lv-warning', '▲'], info: ['Suggestion', 'lv-info', 'i'], good: ['All good', 'lv-good', '✓'] };
const AREA = { memory: 'Memory', cpu: 'CPU', capacity: 'Capacity', reading: 'Reading', setup: 'Setup' };

export async function workersPage(ctx) {
  let range = '1h';
  const root = h('div', { class: 'stack-lg workers-page' });
  async function draw() {
    const d = await get(`/ops/workers?range=${range}`);
    const alive = d.workers.filter((w) => w.alive);
    const gone = d.workers.filter((w) => !w.alive);
    const rangeBtns = h('div', { class: 'seg', role: 'group', 'aria-label': 'Chart range' }, ['1h', '6h', '24h'].map((r) =>
      h('button', { class: r === range ? 'on' : '', 'aria-pressed': String(r === range), onClick: () => { range = r; draw(); } }, r)));
    root.replaceChildren(
      h('header', { class: 'head row' }, h('div', null, h('div', { class: 'eyebrow' }, 'WORKERS'), h('h1', null, 'Worker status'),
        h('p', { class: 'muted' }, 'Memory, CPU and throughput of every worker, what each one is reading, and what to change. Refreshes every 15 seconds.')),
        h('span', { class: 'grow' }), rangeBtns),
      adviceCard(d.advice),
      h('div', { class: 'tiles' },
        tile('Workers alive', `${alive.length}`, `${alive.reduce((n, w) => n + (w.telemetry?.activeJobs || 0), 0)} of ${alive.reduce((n, w) => n + (w.concurrency || 2), 0)} job slots busy`),
        tile('Jobs running', num(d.queue.running), `${num(d.queue.ready)} ready to start`),
        tile('Oldest waiting', d.queue.ready ? dur(d.queue.oldest_wait_s) : '—', 'queued and due'),
        tile('Restarts, 24 h', `${gone.filter((w) => w.end_reason && w.end_reason !== 'stopped').length}`, `${gone.filter((w) => /memory/.test(w.end_reason || '')).length} likely out of memory`)),
      ...alive.map((w) => workerCard(w, range)),
      !alive.length && h('div', { class: 'alert bad' }, 'No worker has checked in in the last minute.'),
      readingCard(d.reading, d.settings),
      gone.length > 0 && restartsCard(gone),
      d.failures.length > 0 && h('section', { class: 'card' }, h('div', { class: 'card-h' }, h('h2', null, 'Failures in the last 24 hours')),
        h('table', { class: 'small' }, h('thead', null, h('tr', null, ['Error', 'Jobs', 'Last'].map((x) => h('th', null, x)))),
          h('tbody', null, d.failures.map((f) => h('tr', null, h('td', { class: 'mono small err' }, f.error || '—'), h('td', null, f.n), h('td', null, ago(f.last))))))));
  }
  draw().catch((e) => root.replaceChildren(h('div', { class: 'alert bad' }, e.message)));
  const t = setInterval(() => draw().catch(() => {}), 15000);
  ctx.onLeave(() => clearInterval(t));
  return root;
}

const tile = (label, value, sub) => h('div', { class: 'tile' }, h('span', { class: 'small muted' }, label), h('b', null, value), sub && h('span', { class: 'tiny muted' }, sub));

function adviceCard(items) {
  return h('section', { class: 'card' }, h('div', { class: 'card-h' }, h('h2', null, 'What needs attention')),
    h('ul', { class: 'advice' }, items.map((a) => {
      const [label, cls, icon] = LEVEL[a.level];
      return h('li', { class: cls },
        h('span', { class: 'lv', 'aria-label': label, title: label }, icon),
        h('div', null, h('div', null, h('b', null, a.title), h('span', { class: 'tiny muted' }, ` · ${AREA[a.area] || a.area} · ${label}`)),
          a.detail && h('div', { class: 'small muted' }, a.detail), a.fix && h('div', { class: 'small fix' }, h('b', null, 'Fix: '), a.fix)));
    })));
}

// ---- one worker ----
function workerCard(w, range) {
  const t = w.telemetry || {}, rt = w.runtime || {};
  const cores = rt.cpuLimit || rt.availableCores || t.cores || 1;
  const s = w.series;
  const last = s.at(-1) || {};
  const binMin = range === '1h' ? 0.25 : range === '6h' ? 2 : 5;
  const meter = (label, used, limit, fmt, sub) => {
    const p = pct(used, limit);
    const cls = p == null ? '' : p >= 85 ? 'hot' : p >= 70 ? 'warm' : '';
    const bar = h('div', { class: 'wgauge', role: 'img', 'aria-label': `${label}: ${p ?? '—'}%` }); const i = h('i', { class: cls }); i.style.width = `${Math.min(100, p || 0)}%`; bar.append(i);
    return h('div', { class: 'meter-tile' }, h('div', { class: 'row' }, h('span', { class: 'small muted' }, label), h('span', { class: 'grow' }), h('b', null, p == null ? '—' : `${p}%`)),
      bar, h('span', { class: 'tiny muted' }, `${fmt(used)} of ${limit ? fmt(limit) : 'no limit'}${sub ? ` · ${sub}` : ''}`));
  };
  return h('section', { class: 'card' },
    h('div', { class: 'card-h' }, h('div', null, h('h2', null, w.hostname), h('div', { class: 'tiny muted mono' }, w.id)),
      h('div', { class: 'row small muted' }, h('span', { class: 'dot ok' }), `up ${dur(t.uptimeS)}`, ` · ${rt.node || ''}`, ` · ${t.activeJobs ?? 0}/${w.concurrency || rt.concurrency || 2} slots busy`, ` · ${w.jobs_done} done, ${w.jobs_failed} failed`)),
    h('div', { class: 'card-b stack' },
      h('div', { class: 'meters' },
        meter('V8 heap', t.heapUsed, t.heapLimit, bytes, 'crashes at 100%'),
        meter('Container memory', t.memUsed, t.memLimit, bytes, t.memLimit ? 'OOMKilled at 100%' : 'not limited'),
        meter('CPU', t.cpuPct, cores * 100, (v) => (v == null ? '—' : `${Math.round(v)}%`), `${cores} core${cores > 1 ? 's' : ''}${rt.cpuLimit ? ' (limit)' : ' (host)'}`),
        h('div', { class: 'meter-tile' }, h('span', { class: 'small muted' }, 'Process memory (RSS)'), h('b', null, bytes(t.rss)), h('span', { class: 'tiny muted' }, `buffers ${bytes(t.external)}`)),
        h('div', { class: 'meter-tile' }, h('span', { class: 'small muted' }, 'Event loop delay p99'), h('b', null, t.loopP99Ms == null ? '—' : `${t.loopP99Ms} ms`), h('span', { class: 'tiny muted' }, `max ${t.loopMaxMs ?? '—'} ms · leases expire after 90 s`)),
        h('div', { class: 'meter-tile' }, h('span', { class: 'small muted' }, 'Reading now'), h('b', null, last.events != null ? `${num(Math.round(last.events / (binMin * 60)))}/s` : '—'),
          h('span', { class: 'tiny muted' }, last.s3Files ? `${num(last.s3Files)} files · ${bytes(last.s3Bytes / (binMin * 60))}/s from S3` : `${num(last.apiCalls || 0)} AWS calls in the last sample`))),
      s.length < 2 ? h('p', { class: 'muted small' }, 'Charts appear after a few samples (one every 15 seconds).') : h('div', { class: 'charts' },
        chart('V8 heap used', s.map((x) => [x.t, x.heapUsed]), { limit: last.heapLimit, limitLabel: 'heap limit', fmt: bytes }),
        chart('Container memory', s.map((x) => [x.t, x.memUsed]), { limit: last.memLimit, limitLabel: 'memory limit', fmt: bytes, empty: 'No container limit to read.' }),
        chart('CPU, % of one core', s.map((x) => [x.t, x.cpuPct]), { limit: cores * 100, limitLabel: `${cores} core${cores > 1 ? 's' : ''}`, fmt: (v) => `${Math.round(v)}%` }),
        chart('Event loop delay p99', s.map((x) => [x.t, x.loopP99Ms]), { fmt: (v) => `${Math.round(v)} ms` }),
        chart('Events read per minute', s.map((x) => [x.t, x.events == null ? null : x.events / binMin]), { fmt: (v) => num(Math.round(v)) })),
      h('details', null, h('summary', { class: 'small muted' }, 'Runtime details'),
        h('dl', { class: 'kv small' },
          h('dt', null, 'Node'), h('dd', null, `${rt.node || '—'} · ${rt.platform || ''}`),
          h('dt', null, 'Heap limit'), h('dd', null, bytes(rt.heapLimit), rt.nodeOptions ? h('span', { class: 'mono tiny muted' }, ` NODE_OPTIONS=${rt.nodeOptions}`) : h('span', { class: 'tiny muted' }, ' (Node default)')),
          h('dt', null, 'Container'), h('dd', null, rt.cgroup ? `cgroup v${rt.cgroup} · memory ${bytes(rt.memLimit) || 'unlimited'} · CPU ${rt.cpuLimit ?? 'unlimited'}` : 'not in a container'),
          h('dt', null, 'Host'), h('dd', null, `${rt.hostCores} cores · ${bytes(rt.hostMemory)}`),
          h('dt', null, 'AWS identity'), h('dd', { class: 'mono tiny' }, w.aws_identity?.arn || w.aws_identity?.error || '—'),
          h('dt', null, 'Started'), h('dd', null, fmtDate(w.started_at))))));
}

/** One series, one axis; an optional limit drawn as a reference line. Crosshair tooltip on hover. */
function chart(title, pts, { limit = null, limitLabel = '', fmt = String, empty = 'No data.' } = {}) {
  const P = pts.filter(([, v]) => v != null).map(([t, v]) => [new Date(t).getTime(), v]);
  const box = h('figure', { class: 'mini-chart' }, h('figcaption', { class: 'small' }, title));
  if (P.length < 2) { box.append(h('div', { class: 'tiny muted empty-chart' }, empty)); return box; }
  const W = 320, H = 120, L = 6, R = 6, T = 10, B = 18;
  const t0 = P[0][0], t1 = P.at(-1)[0];
  const vmax = Math.max(...P.map((p) => p[1]), limit || 0) * 1.08 || 1;
  const x = (t) => L + ((t - t0) / Math.max(1, t1 - t0)) * (W - L - R);
  const y = (v) => T + (1 - v / vmax) * (H - T - B);
  const path = P.map(([t, v], i) => `${i ? 'L' : 'M'}${x(t).toFixed(1)},${y(v).toFixed(1)}`).join('');
  const area = `${path}L${x(t1).toFixed(1)},${y(0)}L${x(t0).toFixed(1)},${y(0)}Z`;
  const hm = (t) => new Date(t).toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit', timeZone: 'Asia/Jakarta' });
  const cross = svg('line', { y1: T, y2: H - B, class: 'cross', visibility: 'hidden' });
  const dot = svg('circle', { r: 4, class: 'hover-dot', visibility: 'hidden' });
  const tip = h('div', { class: 'chart-tip', hidden: true });
  const s = svg('svg', { viewBox: `0 0 ${W} ${H}`, class: 'mini', role: 'img', 'aria-label': `${title}: latest ${fmt(P.at(-1)[1])}${limit ? `, limit ${fmt(limit)}` : ''}` },
    svg('line', { x1: L, x2: W - R, y1: y(0), y2: y(0), class: 'base' }),
    limit && svg('line', { x1: L, x2: W - R, y1: y(limit), y2: y(limit), class: 'limit' }),
    limit && svg('text', { x: W - R, y: y(limit) - 3, 'text-anchor': 'end', class: 'lim-label' }, `${limitLabel} ${fmt(limit)}`),
    svg('path', { d: area, class: 'area' }), svg('path', { d: path, class: 'line' }),
    svg('text', { x: L, y: H - 4, class: 'axis' }, hm(t0)), svg('text', { x: W - R, y: H - 4, 'text-anchor': 'end', class: 'axis' }, hm(t1)),
    cross, dot);
  const wrap = h('div', { class: 'mini-wrap' }, s, tip);
  s.addEventListener('mousemove', (e) => {
    const r = s.getBoundingClientRect();
    const tx = t0 + (((e.clientX - r.left) / r.width) * W - L) / (W - L - R) * (t1 - t0);
    let best = P[0]; for (const p of P) if (Math.abs(p[0] - tx) < Math.abs(best[0] - tx)) best = p;
    const px = x(best[0]), py = y(best[1]);
    cross.setAttribute('x1', px); cross.setAttribute('x2', px); cross.setAttribute('visibility', 'visible');
    dot.setAttribute('cx', px); dot.setAttribute('cy', py); dot.setAttribute('visibility', 'visible');
    tip.hidden = false; tip.textContent = `${hm(best[0])} · ${fmt(best[1])}${limit ? ` (${pct(best[1], limit)}% of limit)` : ''}`;
    tip.style.left = `${(px / W) * 100}%`;
  });
  s.addEventListener('mouseleave', () => { cross.setAttribute('visibility', 'hidden'); dot.setAttribute('visibility', 'hidden'); tip.hidden = true; });
  box.append(wrap, h('div', { class: 'tiny muted' }, `now ${fmt(P.at(-1)[1])} · peak ${fmt(Math.max(...P.map((p) => p[1])))}`));
  return box;
}

// ---- reading monitor ----
function readingCard(rows, settings) {
  const ev = rows.filter((j) => j.kind === 'events');
  const other = rows.filter((j) => j.kind !== 'events' && ['running', 'queued'].includes(j.status));
  const status = (j) => {
    if (j.stalled) return h('span', { class: 'badge b-high' }, 'stalled');
    return h('span', { class: `badge ${{ running: 'b-banana', queued: 'b-neutral', dead: 'b-high', failed: 'b-high' }[j.status]}` }, j.status);
  };
  const prog = (j) => {
    const p = j.progress || {};
    if (!p.total) return j.status === 'queued' ? (new Date(j.run_after) > new Date() ? `retry ${ago(j.run_after).replace(' ago', '')}` : 'waiting for a slot') : '—';
    const bar = h('div', { class: 'wgauge thin' }); const i = h('i'); i.style.width = `${(p.done / p.total) * 100}%`; bar.append(i);
    return h('div', null, h('div', { class: 'row nowrap' }, bar, h('span', { class: 'tiny' }, `${num(p.done)}/${num(p.total)}`)),
      h('div', { class: 'tiny muted' }, [`${num(p.events)} events`, p.slice && `${p.direction === 'backfill' ? 'back to' : 'up to'} ${p.slice.slice(0, 10)}`, j.status === 'running' && p.eventsPerSecond != null && `${num(p.eventsPerSecond)}/s`].filter(Boolean).join(' · ')));
  };
  const note = (j) => {
    if (j.stalled) return h('span', { class: 'err' }, `no slice finished for ${dur(j.sinceProgressS ?? 900)}`);
    if (j.last_error) return h('span', { class: 'err' }, j.last_error.slice(0, 120));
    if (j.status === 'running' && j.progress?.etaSeconds != null) return `about ${dur(j.progress.etaSeconds)} left`;
    return '';
  };
  return h('section', { class: 'card' },
    h('div', { class: 'card-h' }, h('div', null, h('h2', null, 'Reading now'), h('p', { class: 'muted small' }, `CloudTrail reads that are running, waiting, or gave up in the last 24 hours. Default slice ${settings.sliceHours} h.`))),
    ev.length ? h('div', { class: 'scroll' }, h('table', { class: 'small' },
      h('thead', null, h('tr', null, ['Account', 'Region', 'Source', 'Status', 'Progress', 'Slice', 'Attempt', 'Last progress', 'Note'].map((x) => h('th', null, x)))),
      h('tbody', null, ev.map((j) => h('tr', { class: j.stalled || ['dead', 'failed'].includes(j.status) ? 'row-bad' : '' },
        h('td', null, h('div', { class: 'name' }, j.account_name), h('div', { class: 'tiny muted mono' }, j.aws_account_id)),
        h('td', { class: 'mono' }, j.region), h('td', null, j.event_source === 's3' ? 'S3 trail' : 'Event History'),
        h('td', null, status(j)), h('td', null, prog(j)),
        h('td', null, `${Number(j.progress?.sliceHours || j.options?.sliceHours || settings.sliceHours)} h`),
        h('td', null, `${j.attempts}/${j.max_attempts}`),
        h('td', null, j.sinceProgressS != null ? `${dur(j.sinceProgressS)} ago` : '—'),
        h('td', { class: 'small' }, note(j))))))) : h('div', { class: 'empty' }, 'Nothing is being read right now.'),
    other.length > 0 && h('p', { class: 'small muted card-b' }, `Also ${other.length} other job${other.length > 1 ? 's' : ''} (inventory, advisor, analyze) running or waiting.`));
}

function restartsCard(gone) {
  return h('section', { class: 'card' }, h('div', { class: 'card-h' }, h('div', null, h('h2', null, 'Workers that ended, last 24 hours'),
    h('p', { class: 'muted small' }, 'A worker that stopped heartbeating without shutting down is “lost”. If its last sample had the heap or container memory near the limit, it is marked as likely out of memory.'))),
    h('div', { class: 'scroll' }, h('table', { class: 'small' }, h('thead', null, h('tr', null, ['Worker', 'Ran', 'Ended', 'Reason', 'Heap at the end', 'Container memory at the end', 'Jobs'].map((x) => h('th', null, x)))),
      h('tbody', null, gone.map((w) => {
        const t = w.telemetry || {};
        const oom = /memory/.test(w.end_reason || '');
        return h('tr', { class: oom ? 'row-bad' : '' },
          h('td', null, h('div', null, w.hostname), h('div', { class: 'tiny muted mono' }, w.id)),
          h('td', null, dur(Math.round((new Date(w.stopped_at || w.heartbeat_at) - new Date(w.started_at)) / 1000))),
          h('td', null, ago(w.stopped_at || w.heartbeat_at)),
          h('td', null, h('span', { class: `badge ${oom ? 'b-high' : w.end_reason === 'stopped' ? 'b-neutral' : 'b-medium'}` }, w.end_reason || 'unknown')),
          h('td', null, t.heapLimit ? `${bytes(t.heapUsed)} of ${bytes(t.heapLimit)} (${pct(t.heapUsed, t.heapLimit)}%)` : '—'),
          h('td', null, t.memLimit ? `${bytes(t.memUsed)} of ${bytes(t.memLimit)} (${pct(t.memUsed, t.memLimit)}%)` : '—'),
          h('td', null, `${w.jobs_done} done, ${w.jobs_failed} failed`));
      })))));
}
