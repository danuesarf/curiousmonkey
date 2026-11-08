import { h, get, post, num, ago, fmtDate, toast, modal, api, confirmDialog } from '../lib.js';
import { session } from '../main.js';
import { dial } from './sector.js';

const ST = { succeeded: 'b-green', running: 'b-banana', queued: 'b-neutral', failed: 'b-high', dead: 'b-high', canceled: 'b-neutral', partial: 'b-medium' };
const secs = (s) => (s >= 3600 ? `${Math.round(s / 3600)} h` : s >= 60 ? `${Math.round(s / 60)} min` : `${s} s`);

export async function opsPage(ctx) {
  const canScan = session.user.permissions.includes('scan');
  let openRun = null;
  const root = h('div', { class: 'stack-lg' });
  async function draw() {
    const o = await get('/ops/overview');
    const alive = o.workers.filter((w) => w.alive);
    const detail = openRun ? await get(`/ops/runs/${openRun}`).catch(() => null) : null;
    root.replaceChildren(...[
      h('header', { class: 'head' }, h('div', null, h('div', { class: 'eyebrow' }, 'SCANS'), h('h1', null, 'Scan activity'), h('p', { class: 'muted' }, 'Scans run in a separate worker. If one stops, it resumes from its last saved checkpoint. Refreshes every 5 seconds.'))),
      !alive.length && h('div', { class: 'alert bad' }, 'No worker has checked in recently. Queued scans will wait until one starts.'),
      o.oldestWaitingSeconds > 600 && h('div', { class: 'alert warn' }, `The oldest waiting job has been queued for ${secs(o.oldestWaitingSeconds)}. Add worker replicas or check the worker logs.`),
      h('div', { class: 'tiles' }, ...['queued', 'running', 'succeeded', 'failed', 'dead'].map((k) => h('div', { class: 'tile' }, h('span', { class: 'small muted' }, `Jobs ${k}`), h('b', null, num(o.jobs[k] || 0)))),
        h('div', { class: 'tile' }, h('span', { class: 'small muted' }, 'Workers alive'), h('b', null, `${alive.length}`), h('span', { class: 'tiny muted' }, `${o.succeededLastHour} jobs done in the last hour`))),
      h('section', { class: 'card' }, h('div', { class: 'card-h' }, h('h2', null, 'Workers')), o.workers.length ? h('div', { class: 'scroll' }, h('table', null, h('thead', null, h('tr', null, ['Worker', 'Status', 'Heartbeat', 'Done', 'Failed', 'Started'].map((x) => h('th', null, x)))),
        h('tbody', null, o.workers.map((w) => h('tr', null, h('td', { class: 'mono small' }, w.id), h('td', null, h('span', { class: `dot ${w.alive ? 'ok' : 'bad'}` }), ' ', w.alive ? (w.current_job ? 'working' : 'idle') : w.stopped_at ? 'stopped' : 'lost'),
          h('td', { class: 'small' }, ago(w.heartbeat_at)), h('td', null, w.jobs_done), h('td', null, w.jobs_failed), h('td', { class: 'small' }, ago(w.started_at))))))) : h('div', { class: 'empty' }, 'No worker has registered yet.')),
      h('section', { class: 'card' }, h('div', { class: 'card-h' }, h('h2', null, 'Recent scans')), h('div', { class: 'scroll' }, h('table', null, h('thead', null, h('tr', null, ['Account', 'Trigger', 'Status', 'Jobs', 'Started', 'Duration', ''].map((x) => h('th', null, x)))),
        h('tbody', null, o.runs.map((r) => h('tr', { class: 'link', onClick: () => { openRun = openRun === r.id ? null : r.id; draw(); } },
          h('td', null, h('div', { class: 'name' }, r.account_name), h('div', { class: 'tiny muted' }, r.aws_account_id)), h('td', null, r.trigger), h('td', null, h('span', { class: `badge ${ST[r.status]}` }, r.status)),
          h('td', { class: 'small' }, `${r.jobs_ok}/${r.jobs} done${r.jobs_bad ? `, ${r.jobs_bad} failed` : ''}`), h('td', { class: 'small' }, ago(r.started_at || r.created_at)),
          h('td', { class: 'small' }, r.finished_at && r.started_at ? secs(Math.round((new Date(r.finished_at) - new Date(r.started_at)) / 1000)) : r.status === 'running' ? (r.eta_seconds != null ? `running, ${etaText(r.eta_seconds)} left` : 'running') : '—'),
          h('td', { class: 'small' }, openRun === r.id ? 'Hide' : 'Details'))))))),
      detail && runPanel(detail, canScan, draw)].filter(Boolean));
  }
  const runPanel = (d, canScan, redraw) => h('section', { class: 'card' },
    h('div', { class: 'card-h' }, h('div', { class: 'row' }, h('h2', null, `${d.run.account_name}: scan ${d.run.status}`), runEta(d.jobs) != null && h('span', { class: 'badge b-banana' }, `${etaText(runEta(d.jobs))} left`)), canScan && h('div', { class: 'row' },
      d.jobs.some((j) => ['failed', 'dead', 'canceled'].includes(j.status)) && h('button', { class: 'btn sm primary', onClick: async () => { const r = await post(`/ops/runs/${d.run.id}/retry`); toast(`Requeued ${r.requeued} job(s). They resume from saved checkpoints.`); redraw(); } }, 'Retry failed jobs'),
      ['queued', 'running'].includes(d.run.status) && h('button', { class: 'btn sm danger', onClick: async () => { if (await confirmDialog({ title: 'Cancel this scan?', message: 'Jobs that already finished keep their results, and a later scan continues from the saved checkpoints.', confirmLabel: 'Cancel scan', danger: true })) { await post(`/ops/runs/${d.run.id}/cancel`); redraw(); } } }, 'Cancel'))),
    h('div', { class: 'scroll' }, h('table', null, h('thead', null, h('tr', null, ['Step', 'Status', 'Attempts', 'Progress', 'Error', ''].map((x) => h('th', null, x)))),
      h('tbody', null, d.jobs.map((j) => h('tr', null, h('td', null, h('span', { class: 'name' }, j.kind), j.region && h('span', { class: 'small muted mono nowrap' }, ` ${j.region}`)), h('td', null, h('span', { class: `badge ${ST[j.status]}` }, j.status)),
        h('td', null, `${j.attempts}/${j.max_attempts}`), h('td', { class: 'small' }, progress(j)),
        h('td', { class: 'small', style: null }, j.last_error ? h('span', { class: 'err' }, j.last_error.slice(0, 160), j.error_retryable === false ? ' (not retryable)' : '') : '', j.status === 'queued' && j.attempts > 0 && new Date(j.run_after) > new Date() && h('div', { class: 'muted' }, `retrying ${ago(j.run_after).replace('ago', '')}`)),
        h('td', null, h('div', { class: 'row' }, h('button', { class: 'btn sm', onClick: async () => { const l = await get(`/ops/jobs/${j.id}/log`); modal(`${j.kind} ${j.region || ''} log`, h('pre', null, l.items.map((x) => `${fmtDate(x.at)}  ${x.level.padEnd(5)} ${x.message}`).join('\n') || 'No log lines.')); } }, 'Log'),
          canScan && ['failed', 'dead', 'canceled'].includes(j.status) && h('button', { class: 'btn sm', onClick: async () => { await post(`/ops/jobs/${j.id}/retry`); redraw(); } }, 'Retry'),
          canScan && j.kind === 'events' && !['running', 'queued'].includes(j.status) && h('button', { class: 'btn sm', onClick: () => rebuildDialog(d.run, j, redraw) }, 'Rebuild')))))))));
  draw().catch((e) => root.replaceChildren(h('div', { class: 'alert bad' }, e.message)));
  const t = setInterval(() => draw().catch(() => {}), 5000);
  ctx.onLeave(() => clearInterval(t));
  return root;
}
// Read one region of one account again from the start, optionally in smaller slices.
function rebuildDialog(run, j, redraw) {
  const cur = Number(j.options?.sliceHours) || null;
  const sel = h('select', null, [['', 'Workspace default'], ['2', '2 hours'], ['1', '1 hour'], ['0.5', '30 minutes'], ['0.25', '15 minutes']]
    .map(([v, t]) => h('option', { value: v }, t)));
  sel.value = cur ? String(cur) : '1';                // 1 h is the useful default when a region needs rebuilding
  let bg;
  const go = h('button', { class: 'btn primary', onClick: async () => {
    go.disabled = true;
    try {
      const r = await post(`/ops/jobs/${j.id}/rebuild`, { sliceHours: sel.value ? Number(sel.value) : null });
      toast(`Rebuilding ${j.region}. ${r.requeued > 1 ? 'Analysis runs again when it finishes.' : ''}`);
      bg.remove(); redraw();
    } catch (e) { toast(e.message, true); go.disabled = false; }
  } }, `Rebuild ${j.region}`);
  bg = modal(`Rebuild ${run.account_name} · ${j.region}`, h('div', { class: 'stack' },
    h('p', null, `Reads ${j.region} again from the start of the lookback, for this account only. Other regions and accounts are not touched.`),
    h('p', { class: 'small muted' }, 'Events already recorded are recognised and skipped, so nothing is counted twice. The region shows as incomplete until the read finishes, and analysis runs again afterwards.'),
    h('div', { class: 'field' }, h('label', null, 'Slice size', sel),
      h('span', { class: 'hint' }, 'Smaller slices hold fewer events in memory at once. Use 1 hour or less when the worker keeps getting lost on a busy region.'))),
    h('div', { class: 'actions' }, go, h('button', { class: 'btn', onClick: () => bg.remove() }, 'Cancel')));
}

function progress(j) {
  const p = j.progress || {};
  if (p.phase === 'events' && p.total) {
    const parts = [`${p.source === 's3' ? 'S3 trail' : 'Event History'}: slice ${num(p.done)} of ${num(p.total)}`, `${num(p.events)} events`];
    if (p.slice) parts.push(`${p.direction === 'backfill' ? 'back to' : 'up to'} ${p.slice.slice(0, 10)}`);
    if (p.sliceHours && p.sliceHours !== 6) parts.push(`${p.sliceHours >= 1 ? `${p.sliceHours} h` : `${p.sliceHours * 60} min`} slices`);
    if (j.status === 'running' && p.eventsPerSecond != null) parts.push(`${num(p.eventsPerSecond)}/s`);
    return h('span', { class: 'row', style: 'gap:8px;flex-wrap:nowrap' }, dial(p.done / p.total, 20), h('span', null, parts.join(' · ')), j.status === 'running' && p.etaSeconds != null && p.done < p.total && h('b', { class: 'eta' }, ` · ${etaText(p.etaSeconds)} left`));
  }
  if (p.total && p.done != null) return `${p.phase || j.kind}: ${p.done}/${p.total}`;
  if (p.finished) return 'finished';
  return j.status === 'running' ? 'starting…' : '';
}
const etaText = (s) => (s < 60 ? 'under a minute' : s < 3600 ? `about ${Math.round(s / 60)} min` : `about ${(Math.round(s / 1800) / 2)} h`);
/** Longest remaining time among running event jobs. Regions run side by side, so the slowest one decides. */
export function runEta(jobs) {
  const etas = jobs.filter((j) => j.status === 'running' && j.progress?.etaSeconds != null).map((j) => j.progress.etaSeconds);
  return etas.length ? Math.max(...etas) : null;
}
