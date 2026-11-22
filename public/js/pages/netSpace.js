// Networking → Space: the networks as a scene, like Space does for identities. AWS is on the left, Google Cloud on
// the right; each account or project is a zone, each VPC or network a ring on it (subnets around the rim: public ones
// raised and amber), its way out a beam up to the internet above. A member account's part of a VPC another account
// shares with it is a smaller dashed ring in the member's zone, its share line arcing to the VPC. Transit gateways,
// Direct Connect gateways and hubs float in the aisle between the clouds; VPN peers, offices and networks outside your
// estate stand in front of the zones, near what they connect to. Where everything goes is netSpaceLayout.js.
// Lines are arcs above the planes. With VPC flow logs read, a line carries light while it carries traffic, the hour
// bar replays the last 24 hours (◀ ▶ step back through the days kept), a line with nothing on it in days is dashed
// and marked NOT USED.
// Drag to turn, Shift+drag or two fingers to move, wheel or pinch to zoom.
import { h, svg, get, fmtClock, fmtStamp } from '../lib.js';
import { wheelKind } from './spaceRelated.js';
import { spaceLayout, placeLabels, textBox } from './netSpaceLayout.js';

const W = 1400, H = 820, HOME = { az: 0, el: 56 };
const f = (v) => Math.round(v * 10) / 10;
const KIND_COLOR = { share: '#b9a3ff', peering: '#8ec5ff', tgw: '#6fe3b0', 'tgw-peering': '#6fe3b0', vpn: '#f6e016', dx: '#ff9f6b', 'client-vpn': '#7fd1ff', privatelink: '#d6a2ff', psc: '#d6a2ff', ncc: '#6fe3b0', interconnect: '#c59bff', internet: '#7e978a' };
const RED = '#ff6b5e', AMBER = '#f0b45a', IDLE = '#5f6f68';
const human = (b) => (b >= 1e9 ? `${(b / 1e9).toFixed(1)} GB` : b >= 1e6 ? `${(b / 1e6).toFixed(1)} MB` : b >= 1e3 ? `${Math.round(b / 1e3)} kB` : `${b} B`);

// a line's curve: up from the planes by how far it goes (no higher than the internet floats, so it stays in view)
function ctrl(a, b, lift) {
  const dist = Math.hypot(b[0] - a[0], b[1] - a[1]) || 1, A = lift != null ? lift : Math.min(300, 40 + 0.22 * dist);
  return [(a[0] + b[0]) / 2, (a[1] + b[1]) / 2, (a[2] + b[2]) / 2 + 2 * A];
}
function arc(a, b, P, lift) {
  const c = ctrl(a, b, lift), pts = [];
  for (let i = 0; i <= 24; i++) { const t = i / 24, u = 1 - t; pts.push(P(u * u * a[0] + 2 * u * t * c[0] + t * t * b[0], u * u * a[1] + 2 * u * t * c[1] + t * t * b[1], u * u * a[2] + 2 * u * t * c[2] + t * t * b[2])); }
  return { pts, d: `M${pts.map((p) => `${f(p[0])} ${f(p[1])}`).join(' L')}` };
}
const clamp = (v, lo, hi) => Math.max(lo, Math.min(hi, v));
const cut = (s, n) => (s.length > n ? `${s.slice(0, n - 1)}…` : s);

/**
 * The scene. `pick(id)` selects a node or a line (the page shows its panel); `sel()` says what is selected;
 * `match(node)` false dims a node (the page's search); `envRank(id)` orders environments; `tools` go at the front of
 * the bar above; `internet()` and `onInternet(on)` keep the beams to the internet on or off across redraws.
 * Returns { el, redraw(), destroy() }. With hundreds of VPCs and peers the names that would overlap one another are
 * left out (the most telling kept: what is selected, the zones, what is exposed); zooming in brings them back.
 */
export function networkScene(d, { pick, sel, envColor, envRank, onHour, match = () => true, tools = [], internet = () => true, onInternet = () => {} }) {
  const L = spaceLayout(d, { envRank });
  // the camera stands back by about the scene's size, so a large estate is not squashed by perspective
  const D = Math.max(2600, 1.1 * Math.max(L.bounds.x1 - L.bounds.x0, L.bounds.y1 - L.bounds.y0));
  const byId = new Map(d.nodes.map((n) => [n.id, n]));
  const outIds = new Set(d.links.filter((l) => l.kind === 'internet').flatMap((l) => [l.from, l.to]));
  const st = { az: HOME.az, el: HOME.el, zoom: 1, px: 0, py: 0, hour: 23, day: 0, playing: false, internet: internet() };
  // the bigger the scene, the further in one may zoom
  const ZMAX = clamp(4 * Math.sqrt((L.bounds.x1 - L.bounds.x0) / 2400), 4, 14);
  const hasFlows = d.links.some((l) => l.usage && l.usage.state !== 'unknown');
  const dense = d.links.length > 80;   // many lines: those whose use is not known are drawn fainter
  // a line's use in a few words, for its tooltip: which VPCs' flow logs it waits for when it is not known
  const nodeLabel = (id) => byId.get(id)?.label || id.split(':').pop();
  const useTitle = (u) => {
    const days = Math.floor(u.coveredDays || 0), n = [...(u.unlogged || []), ...Array(u.unloggedHidden || 0).fill(null)];
    if (u.state === 'used') return `used, ${human(u.bytes)}${days >= 1 ? ` in ${days} day${days > 1 ? 's' : ''} of flow logs` : ' seen in flow logs'}`;
    if (u.state === 'unused') return `not used in ${days} days of flow logs`;
    if (u.state === 'quiet') return u.firstSeen ? 'nothing yet (there for less than 3 days)' : 'nothing yet (flow logs read for less than 3 days)';
    // VPCs in accounts this person cannot see are counted, not named (they come last)
    const named = n.filter(Boolean);
    return n.length ? `use not known (${named.length ? named.slice(0, 2).map(nodeLabel).join(', ') : `${n.length} VPC${n.length > 1 ? 's' : ''} you cannot see`}${named.length && n.length > Math.min(2, named.length) ? ` and ${n.length - Math.min(2, named.length)} more` : ''} ${n.length === 1 ? 'has' : 'have'} no flow logs read)` : 'use not known (no flow logs on either side)';
  };
  // the lines' traffic by the hour on the day shown: the last 24 hours, or an earlier day, fetched when it is picked
  const days = new Map([[0, { start: new Date(d.hourStart).getTime(), hours: new Map(d.links.map((l) => [l.id, l.usage?.hourly || null])) }]]);
  let byLine = days.get(0).hours;
  const totals = () => Array.from({ length: 24 }, (_, i) => d.links.reduce((n, l) => n + (l.kind === 'internet' ? 0 : byLine.get(l.id)?.[i]?.bytes || 0), 0));
  let hourly = totals();
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
  // P(x, y, z) -> [screen x, screen y, depth, screen units per plane unit there]
  function camera() {
    const v = view(st.az, st.el), F = fit.F * st.zoom, CX = W / 2 - F * fit.cx + st.px, CY = H / 2 + 10 + F * fit.cu + st.py;
    return (x, y, z = 0) => { const [X, U, dep] = v(x, y, z); return [CX + F * X, CY - F * U, dep, F / dep]; };
  }
  const usageWidth = (l, bytes) => (bytes > 0 ? Math.min(5, 1.2 + Math.log10(1 + bytes) / 2.2) : 1.2);

  function draw() {
    const P = camera(), cur = sel(), out = [], parts = [];
    const rel = new Set(); if (cur) { rel.add(cur); for (const l of d.links) if (l.id === cur || l.from === cur || l.to === cur) { rel.add(l.id); rel.add(l.from); rel.add(l.to); } }
    const found = (id) => { const n = byId.get(id); return !n || match(n); };
    const fade = (id) => (cur && !rel.has(id) ? 0.16 : found(id) ? 1 : 0.14);
    // a line fades with what it joins when a search leaves both ends out
    const lfade = (l) => (cur ? (rel.has(l.id) ? 1 : 0.16) : found(l.from) || found(l.to) ? 1 : 0.14);
    // which names are drawn: what is selected and what it touches first, what the search finds before what it does not
    const lift = (id) => (cur && rel.has(id) ? 1000 : 0) - (found(id) ? 0 : 300) - (cur && !rel.has(id) ? 200 : 0);
    // label boxes, and what each draws once it is known which are kept: on top of everything, so no ring, peer or
    // line drawn after it covers a name
    const cands = [], later = [], top = [];
    // make(dx, dy) draws it, moved by how far from its own place it went (to one of `alts`: the same box elsewhere)
    const label = (box, prio, make, alts) => { const i = cands.push({ ...box, prio, alts }) - 1; later.push([i, make]); return i; };
    // the planes and their zones
    for (const z of L.zones) {
      const pts = [[z.x0, z.y0], [z.x1, z.y0], [z.x1, z.y1], [z.x0, z.y1]].map(([x, y]) => P(x, y, 0)), color = envColor(z.owner.environment);
      out.push(svg('path', { d: `M${pts.map((p) => `${f(p[0])} ${f(p[1])}`).join(' L')} Z`, fill: color, 'fill-opacity': 0.06, stroke: color, 'stroke-opacity': 0.55, 'stroke-dasharray': z.cloud === 'gcp' ? '5 4' : null }));
      const lp = P(z.x0 + 10, z.y1 - 4, 0), text = `${z.cloud === 'aws' ? 'AWS' : 'GOOGLE CLOUD'} · ${z.owner.name}`;   // on the back edge, clear of the ring labels
      label(textBox('zone', text, lp[0], lp[1] - 6, 'start'), 600 + lift(`${z.cloud}|${z.owner.owner}`), () => svg('text', { x: f(lp[0]), y: f(lp[1] - 6), class: 'ns-zone', fill: color }, text));
    }
    const ent = (id) => { const p = L.P.get(id); return p ? [p.x, p.y, p.z] : null; };
    // lines
    for (const l of d.links) {
      if (l.kind === 'internet' && !st.internet) continue;
      const a = ent(l.from), b = ent(l.to); if (!a || !b) continue;
      const u = l.usage || { state: 'unknown' };
      const hrs = byLine.get(l.id), hourBytes = hrs ? hrs[st.hour].bytes : 0;
      const color = l.kind === 'internet' && byId.get(l.from === 'internet' ? l.to : l.from)?.worst === 'high' ? RED : KIND_COLOR[l.kind] || '#a9bfb2';
      const top = l.kind === 'internet' ? [a[0], a[1], 90] : a;
      const g = arc(top, b, P, l.kind === 'internet' ? 30 : null);
      const on = cur === l.id;
      let stroke = color, dash = null, op = 0.85, w = usageWidth(l, u.bytes);
      if (u.state === 'unused') { stroke = IDLE; dash = '7 6'; op = 0.75; w = 1.4; }
      else if (u.state === 'unknown') { op = l.kind === 'internet' ? (dense ? 0.22 : 0.35) : dense ? 0.42 : 0.6; }
      if (hasFlows && hrs && !hourBytes && u.state === 'used') op *= 0.55;
      out.push(svg('g', { opacity: lfade(l) },
        svg('path', { d: g.d, fill: 'none', stroke, 'stroke-width': f(on ? w + 1.8 : w), 'stroke-dasharray': dash, opacity: op, 'stroke-linecap': 'round' }),
        hourBytes > 0 && svg('path', { d: g.d, fill: 'none', stroke, 'stroke-width': f(w + 3), opacity: 0.35, filter: 'url(#ns-glow)' }),
        svg('path', { d: g.d, fill: 'none', stroke: '#000', 'stroke-opacity': 0, 'stroke-width': 14, class: 'ns-hit', onClick: () => pick(l.id) },
          svg('title', null, `${l.kind}${l.name ? ` · ${l.name}` : ''} · ${useTitle(u)}`))));
      // a line's tags: in its middle, or further along it when a name is there (names of VPCs come first)
      const m = g.pts[12], idle = u.state === 'unused' && (on || !cur), along = [8, 16, 5, 19].map((k) => g.pts[k]);
      const tag = (x, y, w, stroke, fill, text) => svg('g', { opacity: lfade(l), class: 'ns-tag', onClick: () => pick(l.id) },
        svg('rect', { x: f(x - w / 2), y: f(y - 8), width: w, height: 16, rx: 2, fill: '#030d08', stroke }), svg('text', { x: f(x), y: f(y + 4), 'text-anchor': 'middle', class: 'ns-tag-t', fill }, text));
      if (idle) label({ x: m[0] - 34, y: m[1] - 10, w: 68, h: 20 }, 280 + lift(l.id), (dx, dy) => tag(m[0] + dx, m[1] - 1 + dy, 64, IDLE, '#a9bfb2', 'NOT USED'), along.map((q) => ({ x: q[0] - 34, y: q[1] - 10 })));
      if (l.kind === 'vpn' && l.tunnels?.length && (l.up ?? 0) < l.tunnels.length) {
        // on the line it is about, under NOT USED when both
        const dy0 = idle ? 18 : 0;
        label({ x: m[0] - 32, y: m[1] - 10 + dy0, w: 64, h: 20 }, 300 + lift(l.id), (dx, dy) => tag(m[0] + dx, m[1] + dy0 + dy, 60, RED, RED, `${l.up}/${l.tunnels.length} UP`), along.map((q) => ({ x: q[0] - 32, y: q[1] - 10 + dy0 })));
      }
      // light travelling along a line that carried traffic in the hour shown
      if (hourBytes > 0 && !document.hidden && !matchMedia('(prefers-reduced-motion: reduce)').matches) {
        const n = Math.min(3, 1 + Math.floor(Math.log10(1 + hourBytes) / 3));
        for (let i = 0; i < n; i++) parts.push(svg('circle', { r: 2.6, fill: stroke, filter: 'url(#ns-glow)', opacity: lfade(l) },
          svg('animateMotion', { dur: `${f(2.4 + (i * 0.7))}s`, repeatCount: 'indefinite', path: g.d, begin: `${f(-i * 0.8)}s` })));
      }
    }
    // the internet, above
    const ip = L.P.get('internet'), sky = P(ip.x, ip.y, ip.z), skyR = clamp(300 * sky[3], 70, 230);
    out.push(svg('g', { class: 'ns-node', opacity: fade('internet'), onClick: () => pick('internet') },
      svg('ellipse', { cx: f(sky[0]), cy: f(sky[1]), rx: f(skyR), ry: f(skyR * 0.3), fill: 'url(#ns-sky)' }),
      svg('text', { x: f(sky[0]), y: f(sky[1] + 4), 'text-anchor': 'middle', class: 'ns-sky-t' }, 'INTERNET')));
    // rings, hubs and peers, far ones first
    const nodes = d.nodes.filter((n) => L.P.has(n.id) && n.id !== 'internet').map((n) => { const p = L.P.get(n.id); return { n, p, c: P(p.x, p.y, p.z) }; }).sort((a, b) => b.c[2] - a.c[2]);
    for (const { n, p, c } of nodes) {
      const s = c[3], on = cur === n.id, worst = n.worst === 'high' ? RED : n.worst === 'medium' ? AMBER : null;
      const g = [];
      // a node's name: faded with it, and a click on it picks it
      const named = (...texts) => svg('g', { class: 'ns-node', opacity: fade(n.id), onClick: () => pick(n.id) }, ...texts);
      if (p.hub || p.outer) {
        // sized on the planes' scale: small when the scene is large and far, never a blot or a speck
        const r = clamp(p.r * s, 3.5, 30), base = P(p.x, p.y, 0);
        g.push(svg('line', { x1: f(c[0]), y1: f(c[1]), x2: f(base[0]), y2: f(base[1]), stroke: '#2a4a3a', 'stroke-dasharray': '2 3' }));
        g.push(svg(p.hub ? 'rect' : 'circle', p.hub ? { x: f(c[0] - r), y: f(c[1] - r * 0.6), width: f(2 * r), height: f(1.2 * r), rx: 3, fill: '#0b2418', stroke: on ? '#f6e016' : n.kind === 'dxgw' ? KIND_COLOR.dx : '#6fe3b0', 'stroke-width': on ? 2.4 : 1.4 }
          : { cx: f(c[0]), cy: f(c[1]), r: f(r * 0.8), fill: '#07170f', stroke: on ? '#f6e016' : n.stub ? AMBER : '#a9bfb2', 'stroke-width': on ? 2.4 : 1.2, 'stroke-dasharray': n.stub ? '3 3' : null }));
        // its name under it, or above it when a neighbour's is in the way
        const text = cut(n.label, 28), y = c[1] + r + 12, box = textBox('label', text, c[0], y), up = -(2 * r + 18);
        label(box, (p.hub ? 420 : 220) + (n.worst === 'high' ? 40 : 0) + lift(n.id), (dx, dy) => named(svg('text', { x: f(c[0]), y: f(y + dy), 'text-anchor': 'middle', class: 'ns-label' }, text)), [{ x: box.x, y: box.y + up }]);
      } else {
        const ring = (z, rr) => { const pts = []; for (let i = 0; i <= 40; i++) { const a = (i / 40) * Math.PI * 2; const q = P(p.x + Math.cos(a) * rr, p.y + Math.sin(a) * rr * 0.9, z); pts.push(`${f(q[0])} ${f(q[1])}`); } return `M${pts.join(' L')} Z`; };
        const color = envColor(n.environment);
        g.push(svg('path', { d: ring(0, p.r), fill: p.slice ? KIND_COLOR.share : color, 'fill-opacity': p.slice ? 0.06 : 0.12, stroke: on ? '#f6e016' : worst || (p.slice ? KIND_COLOR.share : color),
          'stroke-width': on ? 2.6 : worst ? 2 : 1.3, 'stroke-dasharray': p.slice ? '5 4' : null }));
        // subnets around the rim: public ones raised and amber
        const total = Math.min(n.subnets?.total || 0, 24), pub = n.subnets?.public || 0, tick = f(clamp(6 * s, 0.8, 3.5));
        for (let i = 0; i < total; i++) {
          const a = (i / Math.max(1, total)) * Math.PI * 2 - Math.PI / 2, x = p.x + Math.cos(a) * p.r * 0.72, y = p.y + Math.sin(a) * p.r * 0.65, isPub = i < pub;
          const b0 = P(x, y, 0), b1 = P(x, y, isPub ? 22 : 4);
          g.push(svg('line', { x1: f(b0[0]), y1: f(b0[1]), x2: f(b1[0]), y2: f(b1[1]), stroke: isPub ? AMBER : '#6fe3b0', 'stroke-width': tick, 'stroke-linecap': 'round' }));
        }
        // the way out: a beam up from the ring (internet gateway, NAT, Cloud NAT, external addresses)
        if (!p.slice && outIds.has(n.id)) {
          const b0 = P(p.x, p.y, 0), b1 = P(p.x, p.y, 90);
          g.push(svg('line', { x1: f(b0[0]), y1: f(b0[1]), x2: f(b1[0]), y2: f(b1[1]), stroke: n.exposed ? RED : '#7e978a', 'stroke-width': f(clamp(4 * s, 1, 2.6)), opacity: 0.8 }));
          if (n.exposed) g.push(svg('circle', { cx: f(b1[0]), cy: f(b1[1]), r: f(clamp(12 * s, 2.5, 7)), fill: RED, class: 'ns-pulse' }));
        }
        const lp = P(p.x, p.y - p.r * 1.02, 0);   // under the ring's front edge
        const name = cut(n.label, 24), sub = p.slice ? `shared by ${n.vpcOwnerName || n.vpcOwner} · ${n.attachedOnly ? 'nothing running' : n.cloud === 'gcp' ? `${n.instances || 0} instance${n.instances === 1 ? '' : 's'}` : `${n.interfaces || 0} interface${n.interfaces === 1 ? '' : 's'}`}`
          : `${(n.cidrs || []).slice(0, 1).join('')}${n.shared ? ` · shared ×${(n.tenants || []).length - 1}` : ''}${n.flowDays ? ` · flow logs ${n.flowDays} d` : ''}`;
        const prio = (p.slice ? 260 : 300) + (n.worst === 'high' ? 60 : n.worst === 'medium' ? 25 : 0) + (n.exposed ? 30 : 0) + p.r / 10 + lift(n.id);
        const ni = label(textBox('strong', name, lp[0], lp[1] + 14), prio, () => named(svg('text', { x: f(lp[0]), y: f(lp[1] + 14), 'text-anchor': 'middle', class: 'ns-label strong' }, name)));
        if (sub) { const si = label(textBox('sub', sub, lp[0], lp[1] + 27), prio - 250, () => named(svg('text', { x: f(lp[0]), y: f(lp[1] + 27), 'text-anchor': 'middle', class: 'ns-sub' }, sub))); cands[si].needs = ni; }
      }
      out.push(svg('g', { class: 'ns-node', opacity: fade(n.id), onClick: () => pick(n.id), tabindex: 0, role: 'button', 'aria-label': n.label,
        onKeydown: (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); pick(n.id); } } }, g, svg('title', null, `${n.label}${n.ownerLabel ? ` · ${n.ownerLabel}` : ''}`)));
    }
    // the names that fit, over everything else
    const kept = placeLabels(cands, { view: { w: W, h: H } });
    for (const [i, make] of later) if (kept.has(i)) top.push(make(cands[i].at.x - cands[i].x, cands[i].at.y - cands[i].y));
    layer.replaceChildren(...out, ...parts, ...top);
  }

  // ---------------------------------------------------------------- the hour bar
  let max = Math.max(1, ...hourly);
  const bars = h('div', { class: 'ns-bars' });
  const hourText = h('span', { class: 'mono small' });
  let start = days.get(0).start;
  const label = (i) => fmtClock(start + i * 36e5);   // in the workspace's time zone, as everywhere else
  // ◀ ▶: a day further back, or nearer, through the days the flow logs are kept
  const LAST = Math.max(0, (d.flow?.lookbackDays || 7) - 1);
  const dayText = h('span', { class: 'mono tiny muted ns-day-t' });
  const dayBtn = (t, delta, aria) => { const b = h('button', { type: 'button', class: 'btn sm', 'aria-label': aria, title: aria }, t); b.addEventListener('click', () => showDay(st.day + delta)); return b; };
  const earlier = dayBtn('‹', 1, 'The 24 hours before'), later = dayBtn('›', -1, 'The 24 hours after');
  async function showDay(n) {
    if (n < 0 || n > LAST || n === st.day) return;
    if (!days.has(n)) {
      earlier.disabled = later.disabled = true;
      try { const r = await get(`/network/hours?day=${n}`); days.set(n, { start: new Date(r.hourStart).getTime(), hours: new Map(Object.entries(r.hours)) }); }
      catch { drawBars(); return; }
    }
    st.day = n; ({ start, hours: byLine } = days.get(n)); hourly = totals(); max = Math.max(1, ...hourly);
    tick();
  }
  const drawBars = () => {
    earlier.disabled = !hasFlows || st.day >= LAST; later.disabled = st.day === 0;
    dayText.textContent = st.day ? `${fmtStamp(start)} – ${fmtStamp(start + 864e5)}` : 'the last 24 hours';
    bars.replaceChildren(...hourly.map((v, i) => h('button', { type: 'button', class: `ns-bar${i === st.hour ? ' on' : ''}`, title: `${label(i)} · ${human(v)}`, onClick: () => { st.hour = i; st.playing = false; playBtn.textContent = '▶'; tick(); } },
      h('span', { style: `height:${Math.max(2, Math.round((v / max) * 34))}px` }))));
    hourText.textContent = hasFlows ? `${st.day ? fmtStamp(start + st.hour * 36e5) : label(st.hour)}–${label(st.hour + 1)} · ${human(hourly[st.hour])} on the lines` : 'no flow logs read: lines show what is allowed, not what is used';
  };
  const tick = () => { drawBars(); draw(); onHour?.(st.hour); };
  const playBtn = h('button', { class: 'btn sm', 'aria-label': 'Replay these 24 hours' }, '▶');
  let timer = null;
  playBtn.addEventListener('click', () => {
    st.playing = !st.playing; playBtn.textContent = st.playing ? '❚❚' : '▶';
    clearInterval(timer);
    if (st.playing) timer = setInterval(() => { if (document.hidden) return; st.hour = (st.hour + 1) % 24; tick(); }, 1200);
  });
  const internetBox = h('input', { type: 'checkbox', checked: st.internet });
  internetBox.addEventListener('change', () => { st.internet = internetBox.checked; onInternet(st.internet); draw(); });

  // ---------------------------------------------------------------- turning, moving, zooming
  const wrap = h('div', { class: 'ns-wrap' }, stage);
  let drag = null; const mem = {};
  wrap.addEventListener('pointerdown', (e) => { if (e.target.closest('.ns-node, .ns-hit, .ns-tag')) return; drag = { x: e.clientX, y: e.clientY, az: st.az, el: st.el, px: st.px, py: st.py, pan: e.shiftKey || e.button === 1 }; wrap.setPointerCapture(e.pointerId); wrap.classList.add('grabbing'); });
  // at most one drawing a frame: a large scene takes a while to draw, and pointer events come faster
  let queued = 0;
  const soon = () => { if (!queued) queued = requestAnimationFrame(() => { queued = 0; draw(); }); };
  // the stage keeps its proportions in a box of any shape (centred): screen pixels to its units
  const fitIn = () => { const r = stage.getBoundingClientRect(), sc = Math.min(r.width / W, r.height / H) || 1; return { r, sc, ox: (r.width - W * sc) / 2, oy: (r.height - H * sc) / 2 }; };
  wrap.addEventListener('pointermove', (e) => {
    if (!drag) return;
    const k = 1 / fitIn().sc, dx = (e.clientX - drag.x) * k, dy = (e.clientY - drag.y) * k;
    if (drag.pan) { st.px = drag.px + dx; st.py = drag.py + dy; } else { st.az = drag.az + dx * 0.25; st.el = Math.max(8, Math.min(80, drag.el + dy * 0.2)); }
    soon();
  });
  // zoom keeping the point at (sx, sy) on the stage where it is (the pointer's, or the middle)
  const zoomTo = (zoom, sx = W / 2, sy = H / 2 + 10) => {
    const z = clamp(zoom, 0.35, ZMAX), k = z / st.zoom;
    st.px = sx - W / 2 - k * (sx - W / 2 - st.px); st.py = sy - H / 2 - 10 - k * (sy - H / 2 - 10 - st.py); st.zoom = z;
  };
  const drop = () => { drag = null; wrap.classList.remove('grabbing'); };
  wrap.addEventListener('pointerup', drop); wrap.addEventListener('pointercancel', drop); wrap.addEventListener('lostpointercapture', drop);
  wrap.addEventListener('wheel', (e) => {
    e.preventDefault();
    const kind = wheelKind(e, mem), { r, sc, ox, oy } = fitIn();
    if (kind === 'pan') { st.px -= e.deltaX / sc; st.py -= e.deltaY / sc; }
    else zoomTo(st.zoom * Math.exp(-e.deltaY * (kind === 'pinch' ? 0.01 : 0.0015)), (e.clientX - r.left - ox) / sc, (e.clientY - r.top - oy) / sc);
    soon();
  }, { passive: false });
  const reset = () => { Object.assign(st, { az: HOME.az, el: HOME.el, zoom: 1, px: 0, py: 0 }); draw(); };
  const btn = (t, fn, aria) => { const b = h('button', { class: 'btn sm', 'aria-label': aria || t }, t); b.addEventListener('click', fn); return b; };
  const el = h('div', { class: 'ns' },
    h('div', { class: 'filters' }, ...tools, h('span', { class: 'small muted', title: 'Drag to turn. Shift+drag or two fingers to move. Wheel or pinch to zoom. Esc lets go of what is selected.' }, 'Drag: turn · Shift+drag: move · wheel: zoom'),
      h('label', { class: 'small row', style: 'gap:6px' }, internetBox, 'Beams to the internet'), h('span', { style: 'flex:1' }),
      btn('⟲', () => { st.az -= 15; draw(); }, 'Turn left'), btn('⟳', () => { st.az += 15; draw(); }, 'Turn right'), btn('+', () => { zoomTo(st.zoom * 1.25); draw(); }, 'Zoom in'), btn('−', () => { zoomTo(st.zoom / 1.25); draw(); }, 'Zoom out'), btn('Reset', reset)),
    wrap,
    h('div', { class: 'ns-time' }, h('div', { class: 'ns-day' }, playBtn, h('div', { class: 'ns-day-nav' }, earlier, dayText, later)), bars, hourText));
  tick();
  return { el, redraw: draw, destroy: () => { clearInterval(timer); cancelAnimationFrame(queued); } };
}
