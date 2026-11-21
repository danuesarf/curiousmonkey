// Networking → Space: the networks as a scene, like Space does for identities. AWS is the plane in front, Google
// Cloud the plane behind; each account or project is a zone, each VPC or network a ring on it (subnets around the
// rim: public ones raised and amber), its way out a beam up to the internet above. Transit gateways, Direct Connect
// gateways and hubs float between the planes; VPN peers, offices and networks outside your estate sit off the edges.
// Lines are arcs above the planes. With VPC flow logs read, a line carries light while it carries traffic, the hour
// bar replays the last 24 hours, a line with nothing on it in days is dashed and marked NOT USED.
// Drag to turn, Shift+drag or two fingers to move, wheel or pinch to zoom.
import { h, svg, num } from '../lib.js';
import { wheelKind } from './spaceRelated.js';

const W = 1400, H = 820, D = 2600, HOME = { az: 0, el: 40 };
const f = (v) => Math.round(v * 10) / 10;
const KIND_COLOR = { peering: '#8ec5ff', tgw: '#6fe3b0', 'tgw-peering': '#6fe3b0', vpn: '#f6e016', dx: '#ff9f6b', 'client-vpn': '#7fd1ff', privatelink: '#d6a2ff', psc: '#d6a2ff', ncc: '#6fe3b0', interconnect: '#c59bff', internet: '#7e978a' };
const RED = '#ff6b5e', AMBER = '#f0b45a', IDLE = '#5f6f68';
const human = (b) => (b >= 1e9 ? `${(b / 1e9).toFixed(1)} GB` : b >= 1e6 ? `${(b / 1e6).toFixed(1)} MB` : b >= 1e3 ? `${Math.round(b / 1e3)} kB` : `${b} B`);

function ctrl(a, b, lift) {
  const dx = b[0] - a[0], dy = b[1] - a[1], dist = Math.hypot(dx, dy) || 1, A = lift != null ? lift : 40 + 0.22 * dist;
  return [(a[0] + b[0]) / 2, (a[1] + b[1]) / 2, (a[2] + b[2]) / 2 + 2 * A];
}
function arc(a, b, P, lift) {
  const c = ctrl(a, b, lift), pts = [];
  for (let i = 0; i <= 24; i++) { const t = i / 24, u = 1 - t; pts.push(P(u * u * a[0] + 2 * u * t * c[0] + t * t * b[0], u * u * a[1] + 2 * u * t * c[1] + t * t * b[1], u * u * a[2] + 2 * u * t * c[2] + t * t * b[2])); }
  return { pts, d: `M${pts.map((p) => `${f(p[0])} ${f(p[1])}`).join(' L')}` };
}

/** Lays the scene out in plane coordinates from the overview (/api/network). */
function layout(d, envColor) {
  const P = new Map(), zones = [];
  const ringsOf = (cloud, owner) => d.nodes.filter((n) => n.cloud === cloud && n.owner === owner && !n.stub && (n.kind === 'vpc' || n.kind === 'network'));
  const field = (cloud, y0, y1) => {
    const owners = d.owners.filter((o) => o.cloud === cloud && ringsOf(cloud, o.owner).length);
    const widths = owners.map((o) => Math.max(260, Math.ceil(ringsOf(cloud, o.owner).length / 2) * 230));
    const total = widths.reduce((a, b) => a + b, 0) + Math.max(0, owners.length - 1) * 40;
    let x = -total / 2;
    owners.forEach((o, i) => {
      const w = widths[i], rings = ringsOf(cloud, o.owner).sort((a, b) => (a.isDefault ? 1 : 0) - (b.isDefault ? 1 : 0) || a.label.localeCompare(b.label));
      zones.push({ x0: x, x1: x + w, y0, y1, owner: o, color: envColor(o.environment), cloud });
      rings.forEach((n, k) => {
        const col = Math.floor(k / 2), row = k % 2, cols = Math.ceil(rings.length / 2);
        const cx = x + (w / cols) * (col + 0.5), cy = y0 + (y1 - y0) * (rings.length === 1 ? 0.5 : row ? 0.72 : 0.28);
        P.set(n.id, { x: cx, y: cy, z: 0, r: Math.min(84, 34 + 7 * Math.sqrt(n.subnets?.total || 1)) });
      });
      x += w + 40;
    });
    return total;
  };
  const wa = field('aws', -560, -70), wg = field('gcp', 110, 560);
  const span = Math.max(wa, wg, 900) / 2;
  // hubs between the planes, under what they connect; peers and outsiders off the edges
  const near = (id) => { const xs = d.links.filter((l) => l.from === id || l.to === id).map((l) => P.get(l.from === id ? l.to : l.from)?.x).filter((x) => x != null); return xs.length ? xs.reduce((a, b) => a + b, 0) / xs.length : 0; };
  const hubs = d.nodes.filter((n) => ['tgw', 'dxgw', 'hub'].includes(n.kind));
  // in a row between the planes, near what they connect, at least 170 apart
  const xs = hubs.map((n) => ({ n, x: near(n.id) })).sort((a, b) => a.x - b.x);
  for (let i = 1; i < xs.length; i++) if (xs[i].x - xs[i - 1].x < 170) xs[i].x = xs[i - 1].x + 170;
  const shift = xs.length ? (xs[0].x + xs[xs.length - 1].x) / 2 - xs.reduce((a, b) => a + b.x, 0) / xs.length : 0;
  xs.forEach(({ n, x }, i) => P.set(n.id, { x: x - shift, y: 20, z: 80 + (i % 2) * 30, r: 16, hub: true }));
  const outer = d.nodes.filter((n) => n.kind === 'peer' || (n.stub && n.kind !== 'tgw'));
  const left = [], right = [];
  for (const n of outer) (n.cloud === 'gcp' || (n.kind === 'peer' && d.links.some((l) => (l.from === n.id || l.to === n.id) && [l.from, l.to].some((x) => x.startsWith('gcp:')))) ? right : left).push(n);
  left.forEach((n, i) => P.set(n.id, { x: -span - 220, y: -520 + i * (480 / Math.max(1, left.length - 1 || 1)), z: 20, r: 14, outer: true }));
  right.forEach((n, i) => P.set(n.id, { x: span + 220, y: 130 + i * (430 / Math.max(1, right.length - 1 || 1)), z: 20, r: 14, outer: true }));
  P.set('internet', { x: 0, y: 0, z: 470, r: 26 });
  return { P, zones, span };
}

/**
 * The scene, in `host`. `pick(id)` selects a node or a line (the page shows its panel); `sel()` says what is selected.
 * Returns { el, redraw(), destroy() }.
 */
export function networkScene(d, { pick, sel, envColor, onHour }) {
  const L = layout(d, envColor);
  const st = { az: HOME.az, el: HOME.el, zoom: 1, px: 0, py: 0, hour: 23, playing: false, internet: true };
  const hasFlows = d.links.some((l) => l.usage && l.usage.state !== 'unknown');
  const hourly = Array.from({ length: 24 }, (_, i) => d.links.reduce((n, l) => n + (l.kind === 'internet' ? 0 : l.usage?.hourly?.[i]?.bytes || 0), 0));
  const stage = svg('svg', { class: 'ns-stage', viewBox: `0 0 ${W} ${H}`, role: 'img', 'aria-label': 'Network scene' });
  const defs = svg('defs', null, svg('filter', { id: 'ns-glow', x: '-50%', y: '-50%', width: '200%', height: '200%' }, svg('feGaussianBlur', { stdDeviation: 2.4 })),
    svg('radialGradient', { id: 'ns-sky' }, svg('stop', { offset: '0%', 'stop-color': '#8ec5ff', 'stop-opacity': 0.5 }), svg('stop', { offset: '100%', 'stop-color': '#8ec5ff', 'stop-opacity': 0 })));
  const layer = svg('g');
  stage.append(defs, layer);

  const view = (azd, eld) => { const el = (eld * Math.PI) / 180, ce = Math.cos(el), se = Math.sin(el), az = (azd * Math.PI) / 180, c = Math.cos(az), s = Math.sin(az);
    return (x, y, z) => { const X = x * c - y * s, Y = x * s + y * c, vy = Y + D * ce, vz = z - D * se, dep = vy * ce - vz * se; return [X / dep, (vy * se + vz * ce) / dep, dep]; }; };
  // framed once, at the starting angle, so the whole scene fills the view; turning keeps the scale, zoom changes it
  const fit = (() => {
    const v = view(HOME.az, HOME.el), pts = [];
    for (const z of L.zones) pts.push([z.x0, z.y0, 0], [z.x1, z.y0, 0], [z.x1, z.y1, 0], [z.x0, z.y1, 0]);
    for (const p of L.P.values()) pts.push([p.x, p.y, p.z]);
    let x0 = Infinity, x1 = -Infinity, u0 = Infinity, u1 = -Infinity;
    for (const [x, y, z] of pts) { const [X, U] = v(x, y, z); x0 = Math.min(x0, X); x1 = Math.max(x1, X); u0 = Math.min(u0, U); u1 = Math.max(u1, U); }
    const F = Math.min((W - 80) / Math.max(1e-6, x1 - x0), (H - 70) / Math.max(1e-6, u1 - u0));
    return { F, cx: (x0 + x1) / 2, cu: (u0 + u1) / 2 };
  })();
  function camera() {
    const v = view(st.az, st.el), F = fit.F * st.zoom, CX = W / 2 - F * fit.cx + st.px, CY = H / 2 + 10 + F * fit.cu + st.py;
    return (x, y, z = 0) => { const [X, U, dep] = v(x, y, z); return [CX + F * X, CY - F * U, dep, (st.zoom * D) / dep]; };
  }
  const usageWidth = (l, bytes) => (bytes > 0 ? Math.min(5, 1.2 + Math.log10(1 + bytes) / 2.2) : 1.2);

  function draw() {
    const P = camera(), cur = sel(), out = [];
    const rel = new Set(); if (cur) { rel.add(cur); for (const l of d.links) if (l.id === cur || l.from === cur || l.to === cur) { rel.add(l.id); rel.add(l.from); rel.add(l.to); } }
    const fade = (id) => (cur && !rel.has(id) ? 0.16 : 1);
    // the planes and their zones
    for (const z of L.zones) {
      const pts = [[z.x0, z.y0], [z.x1, z.y0], [z.x1, z.y1], [z.x0, z.y1]].map(([x, y]) => P(x, y, 0));
      out.push(svg('path', { d: `M${pts.map((p) => `${f(p[0])} ${f(p[1])}`).join(' L')} Z`, fill: z.color, 'fill-opacity': 0.06, stroke: z.color, 'stroke-opacity': 0.55, 'stroke-dasharray': z.cloud === 'gcp' ? '5 4' : null }));
      const lp = P(z.x0 + 10, z.y0 + 4, 0);
      out.push(svg('text', { x: f(lp[0]), y: f(lp[1] - 6), class: 'ns-zone', fill: z.color }, `${z.cloud === 'aws' ? 'AWS' : 'GOOGLE CLOUD'} · ${z.owner.name}`));
    }
    const ent = (id) => { const p = L.P.get(id); return p ? [p.x, p.y, p.z] : null; };
    // lines
    const parts = [];
    for (const l of d.links) {
      if (l.kind === 'internet' && !st.internet) continue;
      const a = ent(l.from), b = ent(l.to); if (!a || !b) continue;
      const u = l.usage || { state: 'unknown' };
      const hourBytes = u.hourly ? u.hourly[st.hour].bytes : 0;
      const color = l.kind === 'internet' && (d.nodes.find((n) => n.id === (l.from === 'internet' ? l.to : l.from))?.worst === 'high') ? RED : KIND_COLOR[l.kind] || '#a9bfb2';
      const top = l.kind === 'internet' ? [a[0], a[1], 90] : a;
      const g = arc(top, b, P, l.kind === 'internet' ? 30 : null);
      const on = cur === l.id;
      let stroke = color, dash = null, op = 0.85, w = usageWidth(l, u.bytes);
      if (u.state === 'unused') { stroke = IDLE; dash = '7 6'; op = 0.75; w = 1.4; }
      else if (u.state === 'unknown') { op = l.kind === 'internet' ? 0.35 : 0.6; }
      if (hasFlows && u.hourly && !hourBytes && u.state === 'used') op *= 0.55;
      out.push(svg('g', { opacity: fade(l.id) },
        svg('path', { d: g.d, fill: 'none', stroke, 'stroke-width': f(on ? w + 1.8 : w), 'stroke-dasharray': dash, opacity: op, 'stroke-linecap': 'round' }),
        hourBytes > 0 && svg('path', { d: g.d, fill: 'none', stroke, 'stroke-width': f(w + 3), opacity: 0.35, filter: 'url(#ns-glow)' }),
        svg('path', { d: g.d, fill: 'none', stroke: '#000', 'stroke-opacity': 0, 'stroke-width': 14, class: 'ns-hit', onClick: () => pick(l.id) },
          svg('title', null, `${l.kind}${l.name ? ` · ${l.name}` : ''} · ${u.state === 'used' ? `used, ${human(u.bytes)} in ${d.flowDays || 7} days` : u.state === 'unused' ? `not used in ${Math.floor(u.coveredDays)} days of flow logs` : u.state === 'quiet' ? 'nothing yet (flow logs read for less than 3 days)' : 'use not known (no flow logs on either side)'}`))));
      if (u.state === 'unused' && (on || !cur)) { const m = g.pts[12]; out.push(svg('g', { opacity: fade(l.id), class: 'ns-tag', onClick: () => pick(l.id) }, svg('rect', { x: f(m[0] - 32), y: f(m[1] - 9), width: 64, height: 16, rx: 2, fill: '#030d08', stroke: IDLE }), svg('text', { x: f(m[0]), y: f(m[1] + 3), 'text-anchor': 'middle', class: 'ns-tag-t', fill: '#a9bfb2' }, 'NOT USED'))); }
      if (l.kind === 'vpn' && l.tunnels?.length && (l.up ?? 0) < l.tunnels.length) { const m = g.pts[12]; out.push(svg('g', { opacity: fade(l.id), class: 'ns-tag', onClick: () => pick(l.id) }, svg('rect', { x: f(m[0] - 30), y: f(m[1] + 10), width: 60, height: 16, rx: 2, fill: '#030d08', stroke: RED }), svg('text', { x: f(m[0]), y: f(m[1] + 22), 'text-anchor': 'middle', class: 'ns-tag-t', fill: RED }, `${l.up}/${l.tunnels.length} UP`))); }
      // light travelling along a line that carried traffic in the hour shown
      if (hourBytes > 0 && !document.hidden && !matchMedia('(prefers-reduced-motion: reduce)').matches) {
        const n = Math.min(3, 1 + Math.floor(Math.log10(1 + hourBytes) / 3));
        for (let i = 0; i < n; i++) parts.push(svg('circle', { r: 2.6, fill: stroke, filter: 'url(#ns-glow)', opacity: fade(l.id) },
          svg('animateMotion', { dur: `${f(2.4 + (i * 0.7))}s`, repeatCount: 'indefinite', path: g.d, begin: `${f(-i * 0.8)}s` })));
      }
    }
    // the internet, above
    const sky = P(0, 0, 470);
    out.push(svg('g', { class: 'ns-node', opacity: fade('internet'), onClick: () => pick('internet') },
      svg('ellipse', { cx: f(sky[0]), cy: f(sky[1]), rx: f(120 * sky[3] * 1.6), ry: f(36 * sky[3] * 1.6), fill: 'url(#ns-sky)' }),
      svg('text', { x: f(sky[0]), y: f(sky[1] + 4), 'text-anchor': 'middle', class: 'ns-sky-t' }, 'INTERNET')));
    // rings, hubs and peers, far ones first
    const nodes = d.nodes.filter((n) => L.P.has(n.id) && n.id !== 'internet').map((n) => ({ n, p: L.P.get(n.id), c: P(L.P.get(n.id).x, L.P.get(n.id).y, L.P.get(n.id).z) })).sort((a, b) => b.c[2] - a.c[2]);
    for (const { n, p, c } of nodes) {
      const k = c[3], on = cur === n.id, worst = n.worst === 'high' ? RED : n.worst === 'medium' ? AMBER : null;
      const g = [];
      if (p.hub || p.outer) {
        const r = p.r * k * 1.4;
        g.push(svg('line', { x1: f(c[0]), y1: f(c[1]), x2: f(P(p.x, p.y, 0)[0]), y2: f(P(p.x, p.y, 0)[1]), stroke: '#2a4a3a', 'stroke-dasharray': '2 3' }));
        g.push(svg(p.hub ? 'rect' : 'circle', p.hub ? { x: f(c[0] - r), y: f(c[1] - r * 0.6), width: f(2 * r), height: f(1.2 * r), rx: 3, fill: '#0b2418', stroke: on ? '#f6e016' : n.kind === 'dxgw' ? KIND_COLOR.dx : '#6fe3b0', 'stroke-width': on ? 2.4 : 1.4 }
          : { cx: f(c[0]), cy: f(c[1]), r: f(r * 0.8), fill: '#07170f', stroke: on ? '#f6e016' : n.stub ? AMBER : '#a9bfb2', 'stroke-width': on ? 2.4 : 1.2, 'stroke-dasharray': n.stub ? '3 3' : null }));
        g.push(svg('text', { x: f(c[0]), y: f(c[1] + r + 12), 'text-anchor': 'middle', class: 'ns-label' }, n.label.length > 28 ? `${n.label.slice(0, 27)}…` : n.label));
      } else {
        const ring = (z, rr) => { const pts = []; for (let i = 0; i <= 40; i++) { const a = (i / 40) * Math.PI * 2; const q = P(p.x + Math.cos(a) * rr, p.y + Math.sin(a) * rr * 0.9, z); pts.push(`${f(q[0])} ${f(q[1])}`); } return `M${pts.join(' L')} Z`; };
        const color = envColor(n.environment);
        g.push(svg('path', { d: ring(0, p.r), fill: color, 'fill-opacity': 0.12, stroke: on ? '#f6e016' : worst || color, 'stroke-width': on ? 2.6 : worst ? 2 : 1.3 }));
        // subnets around the rim: public ones raised and amber
        const total = Math.min(n.subnets?.total || 0, 24), pub = n.subnets?.public || 0;
        for (let i = 0; i < total; i++) {
          const a = (i / Math.max(1, total)) * Math.PI * 2 - Math.PI / 2, x = p.x + Math.cos(a) * p.r * 0.72, y = p.y + Math.sin(a) * p.r * 0.65, isPub = i < pub;
          const b0 = P(x, y, 0), b1 = P(x, y, isPub ? 22 : 4);
          g.push(svg('line', { x1: f(b0[0]), y1: f(b0[1]), x2: f(b1[0]), y2: f(b1[1]), stroke: isPub ? AMBER : '#6fe3b0', 'stroke-width': f(Math.max(1.5, 3 * k)), 'stroke-linecap': 'round' }));
        }
        // the way out: a beam up from the ring (internet gateway, NAT, Cloud NAT, external addresses)
        if (d.links.some((l) => l.kind === 'internet' && (l.from === n.id || l.to === n.id))) {
          const b0 = P(p.x, p.y, 0), b1 = P(p.x, p.y, 90);
          g.push(svg('line', { x1: f(b0[0]), y1: f(b0[1]), x2: f(b1[0]), y2: f(b1[1]), stroke: n.exposed ? RED : '#7e978a', 'stroke-width': f(Math.max(1.2, 2.2 * k)), opacity: 0.8 }));
          if (n.exposed) g.push(svg('circle', { cx: f(b1[0]), cy: f(b1[1]), r: f(4 + 2 * k), fill: RED, class: 'ns-pulse' }));
        }
        const lp = P(p.x, p.y - p.r * 1.02, 0);   // under the ring's front edge
        g.push(svg('text', { x: f(lp[0]), y: f(lp[1] + 14), 'text-anchor': 'middle', class: 'ns-label strong' }, n.label.length > 24 ? `${n.label.slice(0, 23)}…` : n.label),
          svg('text', { x: f(lp[0]), y: f(lp[1] + 27), 'text-anchor': 'middle', class: 'ns-sub' }, `${(n.cidrs || []).slice(0, 1).join('')}${n.flowDays ? ` · flow logs ${n.flowDays} d` : ''}`));
      }
      out.push(svg('g', { class: 'ns-node', opacity: fade(n.id), onClick: () => pick(n.id), tabindex: 0, role: 'button', 'aria-label': n.label,
        onKeydown: (e) => { if (e.key === 'Enter') pick(n.id); } }, g, svg('title', null, `${n.label}${n.ownerLabel ? ` · ${n.ownerLabel}` : ''}`)));
    }
    layer.replaceChildren(...out, ...parts);
  }

  // ---------------------------------------------------------------- the hour bar
  const max = Math.max(1, ...hourly);
  const bars = h('div', { class: 'ns-bars' });
  const hourText = h('span', { class: 'mono small' });
  const start = new Date(d.hourStart).getTime();
  const label = (i) => new Date(start + i * 36e5).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  const drawBars = () => {
    bars.replaceChildren(...hourly.map((v, i) => h('button', { type: 'button', class: `ns-bar${i === st.hour ? ' on' : ''}`, title: `${label(i)} · ${human(v)}`, onClick: () => { st.hour = i; st.playing = false; playBtn.textContent = '▶'; tick(); } },
      h('span', { style: `height:${Math.max(2, Math.round((v / max) * 34))}px` }))));
    hourText.textContent = hasFlows ? `${label(st.hour)}–${label(st.hour + 1)} · ${human(hourly[st.hour])} on the lines` : 'no flow logs read: lines show what is allowed, not what is used';
  };
  const tick = () => { drawBars(); draw(); onHour?.(st.hour); };
  const playBtn = h('button', { class: 'btn sm', 'aria-label': 'Replay the last 24 hours' }, '▶');
  let timer = null;
  playBtn.addEventListener('click', () => {
    st.playing = !st.playing; playBtn.textContent = st.playing ? '❚❚' : '▶';
    clearInterval(timer);
    if (st.playing) timer = setInterval(() => { st.hour = (st.hour + 1) % 24; tick(); }, 1200);
  });
  const internetBox = h('input', { type: 'checkbox', checked: true });
  internetBox.addEventListener('change', () => { st.internet = internetBox.checked; draw(); });

  // ---------------------------------------------------------------- turning, moving, zooming
  const wrap = h('div', { class: 'ns-wrap' }, stage);
  let drag = null; const mem = {};
  wrap.addEventListener('pointerdown', (e) => { if (e.target.closest('.ns-node, .ns-hit, .ns-tag')) return; drag = { x: e.clientX, y: e.clientY, az: st.az, el: st.el, px: st.px, py: st.py, pan: e.shiftKey || e.button === 1 }; wrap.setPointerCapture(e.pointerId); wrap.classList.add('grabbing'); });
  wrap.addEventListener('pointermove', (e) => {
    if (!drag) return;
    const r = stage.getBoundingClientRect(), k = W / r.width, dx = (e.clientX - drag.x) * k, dy = (e.clientY - drag.y) * k;
    if (drag.pan) { st.px = drag.px + dx; st.py = drag.py + dy; } else { st.az = drag.az + dx * 0.25; st.el = Math.max(8, Math.min(80, drag.el + dy * 0.2)); }
    draw();
  });
  wrap.addEventListener('pointerup', () => { drag = null; wrap.classList.remove('grabbing'); });
  wrap.addEventListener('wheel', (e) => {
    e.preventDefault();
    const kind = wheelKind(e, mem), r = stage.getBoundingClientRect(), k = W / r.width;
    if (kind === 'pan') { st.px -= e.deltaX * k; st.py -= e.deltaY * k; }
    else { const z = Math.exp(-e.deltaY * (kind === 'pinch' ? 0.01 : 0.0015)); st.zoom = Math.max(0.35, Math.min(4, st.zoom * z)); }
    draw();
  }, { passive: false });
  const reset = () => { Object.assign(st, { az: HOME.az, el: HOME.el, zoom: 1, px: 0, py: 0 }); draw(); };
  const btn = (t, fn, aria) => { const b = h('button', { class: 'btn sm', 'aria-label': aria || t }, t); b.addEventListener('click', fn); return b; };
  const el = h('div', { class: 'ns' },
    h('div', { class: 'filters' }, h('span', { class: 'small muted' }, 'Drag to turn · Shift+drag or two fingers to move · wheel or pinch to zoom'),
      h('label', { class: 'small row', style: 'gap:6px' }, internetBox, 'Beams to the internet'), h('span', { style: 'flex:1' }),
      btn('⟲', () => { st.az -= 15; draw(); }, 'Turn left'), btn('⟳', () => { st.az += 15; draw(); }, 'Turn right'), btn('+', () => { st.zoom = Math.min(4, st.zoom * 1.2); draw(); }, 'Zoom in'), btn('−', () => { st.zoom = Math.max(0.35, st.zoom / 1.2); draw(); }, 'Zoom out'), btn('Reset', reset)),
    wrap,
    h('div', { class: 'ns-time' }, playBtn, bars, hourText));
  tick();
  return { el, redraw: draw, destroy: () => clearInterval(timer) };
}
