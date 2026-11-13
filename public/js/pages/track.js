// Track: one role session, call by call, and every role it jumped into.
// Each session is a lane. A call that assumed another role is a portal; the session it created
// starts from that portal on its own lane, in its own colour. Replay sends a comet along the path,
// pulses each node as it lands and flashes the matching rows in the call log.
import { h, svg, get, num, fmtDate, fmtClock, ago, paint, r1 } from '../lib.js';
import { go } from '../main.js';

const LANE = ['#6fe3b0', '#8ec5ff', '#c9a7ff', '#ffb38a', '#f6e016', '#7fe0e0'];
const laneColor = (i) => LANE[i % LANE.length];
const MAX_STEPS = 160;
const time = (d) => fmtClock(d, true);
const reduced = () => matchMedia('(prefers-reduced-motion: reduce)').matches;

export async function trackPage(ctx) {
  const roleId = ctx.params.get('role'), account = ctx.params.get('account'), from = ctx.params.get('from');
  const v = await trackView({ role: roleId, account, from, session: ctx.params.get('session'),
    // in a window over another page the address bar belongs to that page
    onSelect: (id) => ctx.inWindow || history.replaceState(null, '', `#/track?${new URLSearchParams({ ...(roleId ? { role: roleId } : {}), ...(account ? { account } : {}), ...(from ? { from } : {}), session: id })}`),
    empty: ctx.inWindow ? null : h('a', { class: 'btn sm', href: '#/' }, 'Back to radar') });
  ctx.setCrumbs(h('a', { href: '#/' }, 'Radar'), 'Track', v.title);
  ctx.onLeave(() => v.stop());
  return v.el;
}

/**
 * The track view on its own: a list of sessions (for a role, an account, or all), the chosen one call by call, and
 * its replay. Mounted by the Track page and by Space. `onSelect(sessionId)` is told when another session is chosen.
 * Returns { el, stop, title }; call stop() when the view goes away.
 */
export async function trackView({ role: roleId = null, account = null, from = null, session: wanted = null, onSelect = () => {}, empty = null } = {}) {
  const qs = new URLSearchParams(); if (roleId) qs.set('role', roleId); if (account) qs.set('account', account); if (from) qs.set('from', from);
  const list = await get(`/sessions?${qs}`);
  const title = roleId && list.items[0] ? list.items[0].role : 'All roles';
  if (!list.items.length) {
    return { title, stop: () => {}, el: h('div', { class: 'stack-lg' }, h('div', { class: 'card card-b stack' }, h('h2', null, 'No sessions to replay yet'),
      h('p', { class: 'muted' }, `Sessions are recorded from AssumeRole events as history is read, and kept for ${list.retentionDays} days. A session that started before the stored history still shows, marked as started earlier.`),
      empty)) };
  }
  let current = list.items.find((s) => s.id === wanted) || list.items[0];

  const left = h('aside', { class: 'left' });
  const scene = h('div', { class: 'scene track-scene' });
  const right = h('aside', { class: 'right' });
  const controls = h('div', { class: 'track-controls' });
  const log = h('div', { class: 'track-log', role: 'log', 'aria-label': 'Calls in this track' });
  let stop = () => {};

  function drawList() {
    left.replaceChildren(h('div', { class: 'stack' }, h('div', { class: 'eyebrow' }, 'TRACK · ONE SESSION, CALL BY CALL'),
      h('p', { class: 'tiny muted' }, `Sessions kept for ${list.retentionDays} days. Ones that jumped into another role are marked.`)),
    h('div', { class: 'stack' }, list.items.map((s) => h('button', { class: 'session-btn', 'aria-pressed': String(s.id === current.id), onClick: () => { current = s; onSelect(s.id); drawList(); load(); } },
      h('span', { class: 'row', style: 'justify-content:space-between' }, h('b', { class: 'mono tiny' }, s.sessionName || s.id.slice(0, 8)),
        h('span', { class: 'row', style: 'gap:4px' }, s.isJump && h('span', { class: 'tag', style: 'border-color:#2e4f6b;color:#8ec5ff' }, 'JUMPED IN'), s.hasJumps && h('span', { class: 'tag', style: 'border-color:#2e4f6b;color:#8ec5ff' }, 'JUMPS ⇢'),
          s.denied > 0 && h('span', { class: 'tag bad' }, `${s.denied} denied`))),
      h('span', { class: 'tiny' }, s.role),
      h('span', { class: 'tiny muted' }, `${s.principal || s.callerArn || 'Unknown caller'} · ${num(s.calls)} calls · ${s.startKnown ? ago(s.startedAt) : 'started earlier'}`)))));
  }

  async function load() {
    stop();
    scene.replaceChildren(h('div', { class: 'hud' }, h('span', { class: 'spin' })));
    const t = await get(`/sessions/${current.id}/track`);
    render(t);
  }

  function render(t) {
    // ---- steps: consecutive calls with the same action on one lane collapse into one node ----
    const steps = [];
    const last = new Map();
    t.calls.forEach((c, i) => {
      const prev = last.get(c.lane);
      if (prev && prev === steps[steps.length - 1] && prev.action === c.action && prev.jumpTo == null && c.jumpTo == null && !c.jumpOutOfView && !prev.jumpOutOfView && prev.denied === c.denied) {
        prev.calls.push(i); prev.lastAt = c.at; return;
      }
      const st = { lane: c.lane, action: c.action, denied: c.denied, errorCode: c.errorCode, jumpTo: c.jumpTo, jumpOutOfView: c.jumpOutOfView, at: c.at, lastAt: c.at, calls: [i], resources: c.resources };
      steps.push(st); last.set(c.lane, st);
    });
    const truncated = steps.length > MAX_STEPS; const shown = steps.slice(0, MAX_STEPS);
    const lanes = t.sessions;
    const W = Math.max(900, 290 + shown.length * 64), LH = 124, H = 130 + lanes.length * LH;
    const X = (i) => 230 + i * 64, Y = (lane) => 110 + lane * LH;
    shown.forEach((s, i) => { s.x = X(i); s.y = Y(s.lane); s.i = i; });

    // ---- segments leading into each step ----
    const lastOnLane = new Map(); const portalFor = new Map(); // child lane -> portal step
    for (const s of shown) if (s.jumpTo != null) portalFor.set(s.jumpTo, s);
    const origin = { x: 120, y: Y(0) };
    const segs = shown.map((s) => {
      const prev = lastOnLane.get(s.lane); lastOnLane.set(s.lane, s);
      if (prev) return { from: prev, d: `M${prev.x} ${prev.y} L${s.x} ${s.y}`, kind: 'lane' };
      const portal = portalFor.get(s.lane);
      if (portal) { const mx = r1((portal.x + s.x) / 2); return { from: portal, d: `M${portal.x} ${portal.y} C${mx} ${portal.y} ${mx} ${s.y} ${s.x} ${s.y}`, kind: 'jump' }; }
      if (s.lane === 0) return { from: origin, d: `M${origin.x} ${origin.y} L${s.x} ${s.y}`, kind: 'entry' };
      return { from: { x: 120, y: s.y }, d: `M120 ${s.y} L${s.x} ${s.y}`, kind: 'entry' };
    });

    // ---- draw ----
    const stage = svg('svg', { class: 'track-stage', width: W, height: H, viewBox: `0 0 ${W} ${H}`, role: 'img', 'aria-label': `Track of ${lanes.length} session${lanes.length > 1 ? 's' : ''}, ${t.calls.length} calls` });
    const defs = svg('defs', null, svg('filter', { id: 'tglow', x: '-100%', y: '-100%', width: '300%', height: '300%' }, svg('feGaussianBlur', { stdDeviation: 3, result: 'b' }),
      svg('feMerge', null, svg('feMergeNode', { in: 'b' }), svg('feMergeNode', { in: 'SourceGraphic' }))));
    const gLanes = svg('g'), gSegs = svg('g'), gNodes = svg('g'), gFx = svg('g', { 'pointer-events': 'none' });
    lanes.forEach((l, i) => {
      const y = Y(i), c = laneColor(i);
      gLanes.append(svg('path', { d: `M40 ${y} H${W - 20}`, stroke: c, 'stroke-opacity': 0.12, 'stroke-dasharray': '2 6' }),
        svg('text', { x: 40, y: y - 52, fill: c, 'font-family': 'Geist Mono, monospace', 'font-size': 11, 'letter-spacing': 1 }, `LANE ${i + 1} · ${l.role.toUpperCase()}`),
        svg('text', { x: 40, y: y - 38, fill: '#7e978a', 'font-family': 'Geist, sans-serif', 'font-size': 11 }, `${l.account} · ${l.awsAccountId}${l.sessionName ? ` · ${l.sessionName}` : ''}${l.startKnown ? '' : ' · started before stored history'}`));
    });
    // origin: whoever started the chain
    gNodes.append(svg('path', { d: `M${origin.x} ${origin.y - 9} L${origin.x + 9} ${origin.y} L${origin.x} ${origin.y + 9} L${origin.x - 9} ${origin.y} Z`, fill: '#e3efe8' }),
      svg('text', { x: origin.x, y: origin.y + 26, 'text-anchor': 'middle', fill: '#e3efe8', 'font-family': 'Geist Mono, monospace', 'font-size': 10 }, short(t.origin.caller, 22)),
      svg('text', { x: origin.x, y: origin.y + 39, 'text-anchor': 'middle', fill: '#7e978a', 'font-size': 10 }, t.origin.via || ''));
    lanes.forEach((l, i) => { if (i > 0 && l.parentLane == null) gNodes.append(svg('text', { x: 120, y: Y(i) + 22, 'text-anchor': 'middle', fill: '#7e978a', 'font-size': 10 }, 'from a session'), svg('text', { x: 120, y: Y(i) + 34, 'text-anchor': 'middle', fill: '#7e978a', 'font-size': 10 }, 'not in view')); });

    const segEls = segs.map((sg, i) => {
      const c = laneColor(shown[i].lane);
      const base = svg('path', { d: sg.d, fill: 'none', stroke: c, 'stroke-opacity': 0.22, 'stroke-width': sg.kind === 'jump' ? 1.6 : 1.2, 'stroke-dasharray': sg.kind === 'jump' ? '5 4' : null });
      const lit = svg('path', { d: sg.d, fill: 'none', stroke: c, 'stroke-width': sg.kind === 'jump' ? 2.2 : 1.8, opacity: 0, class: reduced() ? null : 'flowing' });
      gSegs.append(base, lit);
      return { base, lit };
    });
    const nodeEls = shown.map((s) => {
      const c = s.denied ? '#ff5a4f' : laneColor(s.lane);
      const g = svg('g', { style: 'cursor:pointer', tabindex: 0, role: 'button', 'aria-label': `${s.action}${s.calls.length > 1 ? ` ×${s.calls.length}` : ''}${s.denied ? ', denied' : ''}`, onClick: () => { seek(s.i); pick(s); } });
      const portal = s.jumpTo != null || s.jumpOutOfView;
      const core = portal
        ? svg('g', null, svg('circle', { cx: s.x, cy: s.y, r: 11, fill: '#030d08', stroke: '#8ec5ff', 'stroke-width': 1.6 }), svg('circle', { cx: s.x, cy: s.y, r: 6, fill: 'none', stroke: '#8ec5ff', 'stroke-dasharray': '2 2' }),
          svg('text', { x: s.x, y: s.y + 4, 'text-anchor': 'middle', fill: '#8ec5ff', 'font-size': 10, 'font-weight': 700 }, '⇣'))
        : svg('circle', { cx: s.x, cy: s.y, r: r1(5 + Math.min(4, Math.log2(s.calls.length))), fill: '#030d08', stroke: c, 'stroke-width': 1.6 });
      g.append(core);
      if (s.denied) g.append(svg('path', { d: `M${s.x - 4} ${s.y - 4} L${s.x + 4} ${s.y + 4} M${s.x + 4} ${s.y - 4} L${s.x - 4} ${s.y + 4}`, stroke: '#ff5a4f', 'stroke-width': 1.8 }));
      const up = s.i % 2 === 0;
      g.append(svg('text', { x: s.x, y: up ? s.y - 16 : s.y + 24, 'text-anchor': 'middle', fill: s.denied ? '#ff5a4f' : '#a9bfb2', 'font-family': 'Geist Mono, monospace', 'font-size': 9.5 },
        `${short(s.action.split(':')[1] || s.action, 16)}${s.calls.length > 1 ? ` ×${s.calls.length}` : ''}`));
      if (s.jumpOutOfView) g.append(svg('text', { x: s.x, y: s.y + 38, 'text-anchor': 'middle', fill: '#8ec5ff', 'font-size': 9.5 }, 'into a role outside view'));
      gNodes.append(g);
      return { g, core };
    });
    const comet = svg('circle', { r: 5, fill: '#f6e016', filter: 'url(#tglow)', opacity: 0 });
    const tail = svg('circle', { r: 9, fill: '#f6e016', opacity: 0, 'fill-opacity': 0.25 });
    gFx.append(tail, comet);
    stage.append(defs, gLanes, gSegs, gNodes, gFx);

    const wrap = h('div', { class: 'track-wrap' }, stage);
    scene.replaceChildren(wrap,
      h('div', { class: 'hud' }, h('div', { class: 'hot' }, '● TRACK'), h('div', null, `${lanes.length} SESSION${lanes.length > 1 ? 'S' : ''} · ${num(t.calls.length)} CALLS · ${lanes.length - 1} JUMP${lanes.length === 2 ? '' : 'S'}`),
        t.hidden > 0 && h('div', { style: 'color:#8ec5ff' }, `${t.hidden} MORE SESSION${t.hidden > 1 ? 'S' : ''} IN ACCOUNTS YOU CANNOT SEE`),
        truncated && h('div', { style: 'color:#f0b45a' }, `SHOWING FIRST ${MAX_STEPS} OF ${steps.length} STEPS`)),
      h('div', { class: 'legend' },
        lanes.slice(0, 4).map((l, i) => h('span', null, dot(laneColor(i)), `Lane ${i + 1}`)),
        h('span', null, h('b', { style: 'color:#8ec5ff' }, '⇣'), 'Assumed another role (jump)'), h('span', null, h('b', { style: 'color:#ff5a4f' }, '×'), 'Denied')));

    // ---- call log ----
    const rowFor = new Map();
    const head = h('div', { class: 'r head' }, h('span', null, 'Time'), h('span', null, 'Action'), h('span', null, 'Resources'), h('span', null, 'Result'));
    const rows = t.calls.slice(0, 600).map((c, i) => {
      const r = h('div', { class: `r future${c.denied ? ' denied' : ''}` },
        h('span', { class: 'mono' }, dot(laneColor(c.lane), 'lane-dot'), time(c.at)),
        h('span', { class: 'mono' }, c.action, c.jumpTo != null && h('span', { style: 'color:#8ec5ff' }, ` ⇢ lane ${c.jumpTo + 1}`)),
        h('span', { class: 'mono muted', style: 'overflow:hidden;text-overflow:ellipsis;white-space:nowrap' }, (c.resources || []).join(', ') || '—'),
        h('span', { class: 'mono', style: c.denied ? 'color:#ff5a4f' : 'color:#6fe3b0' }, c.denied ? c.errorCode || 'Denied' : 'OK'));
      rowFor.set(i, r); return r;
    });
    log.replaceChildren(head, ...rows);

    // ---- replay ----
    let pos = -1, playing = false, speed = 1, raf = 0, startT = 0;
    const scrub = h('input', { type: 'range', min: -1, max: shown.length - 1, value: -1, 'aria-label': 'Replay position' });
    const playBtn = h('button', { class: 'btn sm primary', onClick: () => (playing ? pause() : play()) }, 'Play');
    const speedSel = h('select', { 'aria-label': 'Replay speed' }, [1, 2, 4, 8].map((s) => h('option', { value: s }, `${s}×`)));
    speedSel.addEventListener('change', () => { speed = Number(speedSel.value); });
    scrub.addEventListener('input', () => { pause(); seek(Number(scrub.value)); });
    const counter = h('span', { class: 'mono tiny muted' });
    controls.replaceChildren(playBtn, h('button', { class: 'btn sm', onClick: () => { pause(); seek(-1); play(); } }, 'Restart'), speedSel, scrub, counter);

    function paint() {
      shown.forEach((s, i) => {
        const done = i <= pos; const c = s.denied ? '#ff5a4f' : laneColor(s.lane);
        segEls[i].lit.setAttribute('opacity', done ? 0.9 : 0);
        const core = nodeEls[i].core; const ring = core.tagName === 'circle' ? core : core.firstChild;
        ring.setAttribute('fill', paint(done && core.tagName === 'circle' ? c : '#030d08'));
        ring.setAttribute('filter', done ? 'url(#tglow)' : '');
      });
      shown.forEach((s, i) => s.calls.forEach((ci) => { const r = rowFor.get(ci); if (r) { r.classList.toggle('past', i <= pos); r.classList.toggle('future', i > pos); } }));
      scrub.value = pos; counter.textContent = `${Math.max(0, pos + 1)} / ${shown.length}`;
    }
    function seek(i) { pos = Math.max(-1, Math.min(shown.length - 1, i)); comet.setAttribute('opacity', 0); tail.setAttribute('opacity', 0); paint(); }
    function land(i) {
      const s = shown[i]; pos = i; paint();
      if (!reduced()) {
        const c = s.denied ? '#ff5a4f' : (s.jumpTo != null ? '#8ec5ff' : laneColor(s.lane));
        for (const [delay, max] of [[0, 26], [160, 40]]) {
          const ring = svg('circle', { cx: s.x, cy: s.y, r: 6, fill: 'none', stroke: c, 'stroke-width': 2 });
          const a1 = svg('animate', { attributeName: 'r', from: 6, to: max, dur: '0.9s', begin: 'indefinite', fill: 'freeze' });
          const a2 = svg('animate', { attributeName: 'opacity', from: 0.9, to: 0, dur: '0.9s', begin: 'indefinite', fill: 'freeze' });
          ring.append(a1, a2); gFx.insertBefore(ring, tail);
          setTimeout(() => { try { a1.beginElement(); a2.beginElement(); } catch { /* not supported */ } }, delay);
          setTimeout(() => ring.remove(), 1200 + delay);
        }
      }
      let first = true;
      for (const ci of s.calls) {
        const r = rowFor.get(ci); if (!r) continue;
        r.classList.remove('hit', 'hitbad'); void r.offsetWidth; r.classList.add(s.denied ? 'hitbad' : 'hit');
        if (first) { first = false; const top = r.offsetTop - log.clientHeight / 2; log.scrollTo({ top, behavior: reduced() ? 'auto' : 'smooth' }); }
      }
      // keep the landing node in view
      const sx = s.x - wrap.clientWidth / 2; if (Math.abs(wrap.scrollLeft - sx) > wrap.clientWidth / 3) wrap.scrollTo({ left: sx, behavior: reduced() ? 'auto' : 'smooth' });
      pick(s, true);
    }
    function frame(now) {
      if (!playing) return;
      const next = pos + 1;
      if (next >= shown.length) { pause(); return; }
      const dur = (segs[next].kind === 'jump' ? 1100 : 650) / speed;
      const seg = segEls[next].base; const len = seg.getTotalLength();
      const k = Math.min(1, (now - startT) / dur);
      const p = seg.getPointAtLength(len * k), q = seg.getPointAtLength(Math.max(0, len * k - 10));
      comet.setAttribute('cx', p.x); comet.setAttribute('cy', p.y); comet.setAttribute('opacity', 1);
      comet.setAttribute('fill', paint(segs[next].kind === 'jump' ? '#8ec5ff' : '#f6e016'));
      tail.setAttribute('cx', q.x); tail.setAttribute('cy', q.y); tail.setAttribute('opacity', 1);
      segEls[next].lit.setAttribute('opacity', r1(0.9 * k * 10) / 10);
      if (k >= 1) { land(next); startT = now + 120 / speed; }
      raf = requestAnimationFrame(frame);
    }
    function play() {
      if (!shown.length) return;
      if (pos >= shown.length - 1) seek(-1);
      if (reduced()) { // no motion: step through without the comet
        playing = true; playBtn.textContent = 'Pause';
        const tick = () => { if (!playing) return; if (pos + 1 >= shown.length) return pause(); land(pos + 1); raf = setTimeout(tick, 700 / speed); };
        tick(); return;
      }
      playing = true; playBtn.textContent = 'Pause'; startT = performance.now(); raf = requestAnimationFrame(frame);
    }
    function pause() { playing = false; playBtn.textContent = 'Play'; cancelAnimationFrame(raf); clearTimeout(raf); comet.setAttribute('opacity', 0); tail.setAttribute('opacity', 0); }
    stop = pause;

    // ---- right panel: the session, its entry conditions, the jumps, and the picked node ----
    const facts = (l) => [
      ['Entered by', l.principal || l.callerArn || 'Unknown'], ['How', l.via || '—'], ['Session name', l.sessionName || '—'],
      ['MFA', l.mfa == null ? 'Not reported' : l.mfa ? 'Yes' : 'No'], ['Source IP', l.sourceIp || '—'], ['Source identity', l.sourceIdentity || '—'],
      ['Started', l.startKnown ? fmtDate(l.startedAt) : 'Before stored history'], ['Calls', `${num(l.calls)}${l.denied ? ` · ${num(l.denied)} denied` : ''}`],
    ];
    const nodeBox = h('div', { class: 'stack' });
    function pick(s, quiet) {
      const l = lanes[s.lane]; const first = t.calls[s.calls[0]];
      nodeBox.replaceChildren(h('div', { class: 'eyebrow' }, quiet ? 'NOW' : 'PICKED'),
        h('div', { class: 'readout' }, h('div', { class: 'mono', style: `color:${s.denied ? '#ff5a4f' : laneColor(s.lane)}` }, s.action),
          h('div', { class: 'tiny muted' }, `${l.role} · ${time(s.at)}${s.calls.length > 1 ? ` – ${time(s.lastAt)} · ${s.calls.length} calls` : ''}`),
          (first.resources || []).length > 0 && h('div', { class: 'mono tiny', style: 'overflow-wrap:anywhere' }, first.resources.slice(0, 3).join(', ')),
          s.denied && h('div', { class: 'tiny', style: 'color:#ff5a4f' }, s.errorCode || 'Denied'),
          s.jumpTo != null && h('div', { class: 'tiny', style: 'color:#8ec5ff' }, `Assumed ${lanes[s.jumpTo].role} in ${lanes[s.jumpTo].account}. Its calls continue on lane ${s.jumpTo + 1}.`),
          s.jumpOutOfView && h('div', { class: 'tiny', style: 'color:#8ec5ff' }, 'Assumed a role in an account that is not connected or not in your scope, so its calls are not shown.')));
    }
    const sel = lanes.find((l) => l.id === t.sessionId) || lanes[0];
    const trust = sel.trust;
    right.replaceChildren(
      h('div', { class: 'stack' }, h('div', { class: 'eyebrow' }, 'SESSION'), h('h2', null, sel.role), h('div', { class: 'tiny muted' }, `${sel.account} · ${sel.awsAccountId}`)),
      h('div', { class: `cond-box${trust?.matched && trust.conditions?.length ? '' : ' warn'}` },
        h('div', { class: 'stack', style: 'gap:4px' }, h('div', { class: 'eyebrow' }, 'CONDITIONS MET ON ENTRY'),
          h('div', { class: 'mono tiny', style: 'overflow-wrap:anywhere' }, !trust ? 'Not known: the AssumeRole is older than the stored history.'
            : !trust.matched ? 'Not matched to a statement in the trust policy.' : trust.conditions.length ? trust.conditions.join(' · ') : `Trust statement ${trust.statement ?? ''} matched, with no condition.`))),
      h('dl', { class: 'facts' }, facts(sel).flatMap(([k, v]) => [h('dt', null, k), h('dd', { class: 'mono tiny' }, v)])),
      lanes.length > 1 && h('div', { class: 'jump-box' }, h('div', { class: 'eyebrow', style: 'color:#8ec5ff' }, 'ROLE JUMPS IN THIS TRACK'),
        lanes.map((l, i) => h('div', { class: 'row tiny' }, dot(laneColor(i)), h('span', { class: 'grow' }, `${l.role} · ${l.account}`),
          l.parentLane != null ? h('span', { class: 'muted' }, `from lane ${l.parentLane + 1}`) : h('span', { class: 'muted' }, i === 0 ? 'start' : 'parent not in view'),
          l.id !== sel.id && h('button', { class: 'btn sm', onClick: () => { current = { ...current, id: l.id }; drawList(); load(); } }, 'Focus')))),
      nodeBox,
      h('div', { class: 'row', style: 'margin-top:auto' }, h('a', { class: 'btn sm grow', href: `#/roles/${sel.roleId}` }, 'Role details'), h('a', { class: 'btn sm grow', href: `#/roles/${sel.roleId}/scan` }, 'Sector scan')));
    if (shown[0]) pick(shown[0]);
    paint();
    if (!reduced()) setTimeout(() => play(), 400);
  }

  drawList(); load();
  return { title, stop: () => stop(), el: h('div', { class: 'stack track-page', style: 'gap:0' }, h('div', { class: 'scene-layout' }, left, scene, right), controls, log) };
}

function dot(c, cls) { const e = h('span', { class: cls || null, 'aria-hidden': 'true' }); Object.assign(e.style, { display: 'inline-block', width: '8px', height: '8px', borderRadius: '50%', background: c, marginRight: '6px' }); return e; }
const short = (s, n) => (String(s).length > n ? `${String(s).slice(0, n - 1)}…` : String(s));
void go;
