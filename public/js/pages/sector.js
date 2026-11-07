// Sector scan: one role cut two ways.
//   rings   = access level (List on the inside, Permissions management on the rim)
//   sectors = AWS service, sized by how many of its permissions the role holds
//   dots    = permissions; lit = called, amber = unconfirmed, dim = never called
import { h, svg, get, num, ago, fmtDate, riskBadge } from '../lib.js';

const LEVELS = ['List', 'Read', 'Write', 'Tagging', 'Permissions management', 'Unknown'];
const REASON = {
  'data-event': 'Data events not logged', 'authorization-only': 'Authorization only', 'not-logged': 'Never logged by CloudTrail',
  'before-window': 'Older than the history read', 'service-unknown': 'Service used, action not visible', 'unmapped-event': 'Event name not identified yet',
};
const r1 = (v) => Math.round(v * 10) / 10;

export async function sectorPage(ctx, roleId) {
  const d = await get(`/roles/${roleId}/sector`);
  const role = d.role, hist = d.history || { complete: true, progress: 100 };
  ctx.setCrumbs(h('a', { href: '#/' }, 'Radar'), h('a', { href: `#/roles/${role.id}` }, role.name), 'Sector scan');

  // services: biggest first, the tail folded into "other"
  const bySvc = new Map();
  for (const s of d.services) {
    if (!bySvc.has(s.service)) bySvc.set(s.service, { service: s.service, total: 0, used: 0, unconfirmed: 0, cells: {} });
    const o = bySvc.get(s.service); o.total += s.total; o.used += s.used; o.unconfirmed += s.unconfirmed; o.cells[s.level] = s;
  }
  let svcs = [...bySvc.values()].sort((a, b) => b.total - a.total);
  if (svcs.length > 14) {
    const rest = svcs.slice(13); const other = { service: `${rest.length} other services`, total: 0, used: 0, unconfirmed: 0, cells: {}, other: true };
    for (const s of rest) { other.total += s.total; other.used += s.used; other.unconfirmed += s.unconfirmed;
      for (const [lv, c] of Object.entries(s.cells)) { const t = other.cells[lv] ||= { total: 0, used: 0, unconfirmed: 0 }; t.total += c.total; t.used += c.used; t.unconfirmed += c.unconfirmed; } }
    svcs = [...svcs.slice(0, 13), other];
  }
  const grand = Math.max(1, svcs.reduce((a, s) => a + s.total, 0));
  // each service gets an arc proportional to its size, with a floor so small ones stay clickable
  const minArc = 8, spare = 360 - svcs.length * minArc;
  let a0 = -90;
  for (const s of svcs) { s.a0 = a0; s.a1 = a0 + minArc + (spare * s.total) / grand; a0 = s.a1; }
  const levels = LEVELS.filter((l) => d.levels.some((x) => x.level === l));
  const st = { level: null, svc: null, spin: 0 };

  const stage = svg('svg', { class: 'stage', viewBox: '0 0 800 720', role: 'img', 'aria-label': `Sector scan of ${role.name}: rings are access levels, sectors are services.` });
  const CX = 400, CY = 360, R0 = 70, R1 = 320;
  const ringR = (i) => R0 + ((R1 - R0) * i) / levels.length;
  const pt = (deg, r) => { const a = ((deg + st.spin) * Math.PI) / 180; return [r1(CX + Math.cos(a) * r), r1(CY + Math.sin(a) * r)]; };
  const arc = (d0, d1, ra, rb) => {
    const [x0, y0] = pt(d0, ra), [x1, y1] = pt(d1, ra), [x2, y2] = pt(d1, rb), [x3, y3] = pt(d0, rb); const big = d1 - d0 > 180 ? 1 : 0;
    return `M${x0} ${y0} A${ra} ${ra} 0 ${big} 1 ${x1} ${y1} L${x2} ${y2} A${rb} ${rb} 0 ${big} 0 ${x3} ${y3} Z`;
  };
  // deterministic dots per cell
  const rand = (seed) => { let x = seed % 2147483647 || 7; return () => { x = (x * 16807) % 2147483647; return (x - 1) / 2147483646; }; };
  const hash = (s) => [...s].reduce((a, c) => (a * 31 + c.charCodeAt(0)) % 2147483647, 11);

  function draw() {
    const kids = [svg('circle', { cx: CX, cy: CY, r: R1 + 12, fill: '#051209', stroke: '#1f4a35' })];
    levels.forEach((lv, i) => {
      kids.push(svg('circle', { cx: CX, cy: CY, r: ringR(i + 1), fill: 'none', stroke: st.level === lv ? '#f6e016' : '#16392a', 'stroke-dasharray': st.level === lv ? null : '3 5' }));
      kids.push(svg('text', { x: CX + 4, y: r1(CY - (ringR(i) + ringR(i + 1)) / 2 + 4), fill: st.level === lv ? '#f6e016' : '#7e978a', 'font-family': 'Geist Mono, monospace', 'font-size': 9.5 }, lv.toUpperCase()));
    });
    for (const s of svcs) {
      const hot = st.svc === s.service;
      const g = svg('g', { style: 'cursor:pointer', onClick: () => { st.svc = hot ? null : s.service; draw(); readout(); } });
      g.append(svg('path', { d: arc(s.a0, s.a1, R0, R1), fill: hot ? 'rgba(246,224,22,.06)' : 'transparent', stroke: '#16392a' }));
      levels.forEach((lv, i) => {
        const c = s.cells[lv]; if (!c) return;
        const dim = st.level && st.level !== lv;
        const rnd = rand(hash(s.service + lv));
        const n = Math.min(c.total, 60), scale = c.total / n;
        for (let k = 0; k < n; k++) {
          const used = k * scale < c.used, unc = !used && k * scale < c.used + c.unconfirmed;
          const deg = s.a0 + 1.5 + rnd() * (s.a1 - s.a0 - 3), r = ringR(i) + 5 + rnd() * (ringR(i + 1) - ringR(i) - 10);
          const [x, y] = pt(deg, r);
          g.append(svg('circle', { cx: x, cy: y, r: used ? 3.2 : unc ? 2.4 : 1.5, fill: used ? '#f6e016' : unc ? '#f0b45a' : '#5f8c73',
            opacity: dim ? 0.12 : used ? 1 : unc ? 0.85 : 0.5, filter: used && !dim ? 'url(#glow)' : null }));
        }
      });
      const mid = (s.a0 + s.a1) / 2, [lx, ly] = pt(mid, R1 + 26), right = lx >= CX;
      if (s.a1 - s.a0 > 11 || hot) g.append(svg('text', { x: lx, y: ly, 'text-anchor': Math.abs(lx - CX) < 30 ? 'middle' : right ? 'start' : 'end', fill: hot ? '#f6e016' : '#a9bfb2', 'font-family': 'Geist Mono, monospace', 'font-size': 10.5 }, s.service));
      kids.push(g);
    }
    kids.unshift(svg('defs', null, svg('filter', { id: 'glow', x: '-80%', y: '-80%', width: '260%', height: '260%' }, svg('feGaussianBlur', { stdDeviation: 2.2, result: 'b' }),
      svg('feMerge', null, svg('feMergeNode', { in: 'b' }), svg('feMergeNode', { in: 'SourceGraphic' })))));
    kids.push(svg('circle', { cx: CX, cy: CY, r: R0, fill: '#030d08', stroke: '#1f4a35' }),
      svg('text', { x: CX, y: CY - 4, 'text-anchor': 'middle', fill: '#f6e016', 'font-size': 26, 'font-weight': 500 }, `${hist.complete ? '' : '≥'}${num(role.used)}`),
      svg('text', { x: CX, y: CY + 16, 'text-anchor': 'middle', fill: '#a9bfb2', 'font-size': 11 }, `of ${num(role.granted)} used`));
    if (!matchMedia('(prefers-reduced-motion: reduce)').matches) {
      kids.push(svg('g', { transform: `translate(${CX} ${CY})`, 'pointer-events': 'none' }, svg('g', null,
        svg('path', { d: `M${R0} 0 L${R1} 0`, stroke: '#f6e016', 'stroke-opacity': 0.55, 'stroke-width': 2 }),
        svg('animateTransform', { attributeName: 'transform', type: 'rotate', from: '0', to: '360', dur: '9s', repeatCount: 'indefinite' }))));
    }
    stage.replaceChildren(...kids);
  }
  let drag = null;
  stage.addEventListener('pointerdown', (e) => { if (e.target.closest('g[style]')) return; drag = { x: e.clientX, spin: st.spin }; stage.setPointerCapture(e.pointerId); });
  stage.addEventListener('pointermove', (e) => { if (!drag) return; st.spin = drag.spin + (e.clientX - drag.x) * 0.4; draw(); });
  stage.addEventListener('pointerup', () => { drag = null; });

  const slices = h('div', { class: 'stack' });
  const drawSlices = () => slices.replaceChildren(
    h('button', { class: 'slice-btn', 'aria-pressed': String(!st.level), onClick: () => { st.level = null; drawSlices(); draw(); readout(); } }, h('span', { class: 'grow' }, 'All access levels'), h('span', { class: 'mono tiny muted' }, num(role.granted))),
    ...levels.map((lv) => { const x = d.levels.find((l) => l.level === lv);
      return h('button', { class: 'slice-btn', 'aria-pressed': String(st.level === lv), onClick: () => { st.level = st.level === lv ? null : lv; drawSlices(); draw(); readout(); } },
        dial(x.used / Math.max(x.total, 1)), h('span', { class: 'grow' }, lv), h('span', { class: 'mono tiny muted' }, `${num(x.used)}/${num(x.total)}`)); }));
  drawSlices();

  const right = h('aside', { class: 'right' });
  function readout() {
    const usedList = d.used.filter((u) => (!st.level || u.level === st.level) && (!st.svc || u.action.split(':')[0] === st.svc)).slice(0, 12);
    const svc = svcs.find((s) => s.service === st.svc);
    const unc = d.unconfirmed.filter((u) => !st.svc || u.service === st.svc);
    right.replaceChildren(
      h('div', { class: 'stack' }, h('div', { class: 'eyebrow' }, 'READOUT'),
        h('h2', null, svc ? svc.service : st.level || 'Whole role'),
        h('div', { class: 'tiny muted' }, svc ? `${num(svc.total)} permissions granted in this service` : st.level ? `${num(d.levels.find((l) => l.level === st.level).total)} permissions at this level` : `${role.account} · ${role.kind}`)),
      !hist.complete && h('div', { class: 'alert warn' }, h('b', { class: 'mono tiny' }, `PROVISIONAL · ${hist.progress}% OF HISTORY READ`), h('br'), 'More dots will light as older calls are read.'),
      svc && h('div', { class: 'readout' }, h('div', { class: 'split3' },
        h('div', null, h('div', { style: 'color:#f6e016' }, num(svc.used)), h('div', { class: 'muted' }, 'called')),
        h('div', null, h('div', { style: 'color:#f0b45a' }, num(svc.unconfirmed)), h('div', { class: 'muted' }, 'unconfirmed')),
        h('div', null, h('div', { style: 'color:#8fb5a1' }, num(svc.total - svc.used - svc.unconfirmed)), h('div', { class: 'muted' }, 'never called')))),
      h('section', { class: 'stack' }, h('div', { class: 'eyebrow' }, 'CALLED'),
        usedList.length ? usedList.map((u) => h('div', { class: 'row' }, h('span', { class: 'mono tiny grow' }, u.action), h('span', { class: 'mono tiny muted', title: fmtDate(u.last_seen) }, `${num(u.event_count)} · ${ago(u.last_seen)}`)))
          : h('p', { class: 'tiny muted' }, 'Nothing called in this slice in the history read so far.')),
      unc.length > 0 && h('section', { class: 'stack' }, h('div', { class: 'eyebrow', style: 'color:#f0b45a' }, 'UNCONFIRMED · WHY'),
        unc.slice(0, 8).map((u) => h('div', { class: 'row' }, h('span', { class: 'tiny grow' }, `${u.service} · ${REASON[u.reason] || u.reason || 'Unknown'}`), h('span', { class: 'mono tiny muted' }, num(u.n)),
          u.reason === 'unmapped-event' && h('a', { class: 'unk-tag', href: `#/roles/${role.id}?identify=` }, 'Identify')))),
      d.denied.length > 0 && h('section', { class: 'stack' }, h('div', { class: 'eyebrow', style: 'color:#ff6b5e' }, 'DENIED'),
        d.denied.slice(0, 6).map((x) => h('div', { class: 'row' }, h('span', { class: 'mono tiny grow' }, x.action), h('span', { class: 'mono tiny', style: 'color:#ff6b5e' }, num(x.n))))),
      h('div', { class: 'stack', style: 'margin-top:auto' }, h('a', { class: 'btn primary', href: `#/roles/${role.id}/recommendation` }, 'Open recommendation'),
        h('div', { class: 'row' }, h('a', { class: 'btn sm grow', href: `#/track?role=${role.id}` }, 'Track a session'), h('a', { class: 'btn sm grow', href: `#/roles/${role.id}` }, 'Role details'))));
  }

  draw(); readout();
  return h('div', { class: 'scene-layout sector-page' },
    h('aside', { class: 'left' },
      h('div', { class: 'stack' }, h('div', { class: 'eyebrow' }, 'SECTOR SCAN'), h('h2', null, role.name), h('div', { class: 'row' }, riskBadge(role.risk), h('span', { class: 'tiny muted' }, role.account))),
      h('div', { class: 'stack' }, h('div', { class: 'eyebrow' }, 'SLICE BY ACCESS LEVEL'), slices),
      h('p', { class: 'tiny muted' }, 'Click a sector to read one service. Drag to turn the dish.')),
    h('div', { class: 'scene' }, stage,
      h('div', { class: 'hud' }, h('div', { class: 'hot' }, `● SECTOR SCAN${hist.complete ? '' : ' · FILLING IN'}`), h('div', null, `${svcs.length} SERVICES · ${levels.length} ACCESS LEVELS`)),
      h('div', { class: 'legend' }, h('span', null, legendDot('#f6e016', 7), 'Called'), h('span', null, legendDot('#f0b45a', 6), 'Unconfirmed'), h('span', null, legendDot('#5f8c73', 4), 'Never called'))),
    right);
}

function legendDot(c, s) { const e = h('span', { 'aria-hidden': 'true' }); Object.assign(e.style, { display: 'inline-block', width: `${s}px`, height: `${s}px`, borderRadius: '50%', background: c }); return e; }

export function dial(frac, size = 22) {
  const C = 2 * Math.PI * 8;
  return svg('svg', { class: 'dial', width: size, height: size, viewBox: '0 0 20 20', 'aria-hidden': 'true' },
    svg('circle', { cx: 10, cy: 10, r: 8, fill: 'none', stroke: '#1f4a35', 'stroke-width': 2.5 }),
    svg('circle', { cx: 10, cy: 10, r: 8, fill: 'none', stroke: '#f6e016', 'stroke-width': 2.5, 'stroke-dasharray': `${(C * Math.max(0, Math.min(1, frac))).toFixed(1)} ${C.toFixed(1)}`, transform: 'rotate(-90 10 10)' }));
}
