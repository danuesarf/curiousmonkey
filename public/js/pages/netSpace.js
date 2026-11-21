// Networking → Space: the networks as a scene, like Space does for identities. AWS is on the left, Google Cloud on
// the right; each account or project is a zone, each VPC or network a ring on it (subnets around the rim: public ones
// raised and amber), its way out a beam up to the internet above. A member account's part of a VPC another account
// shares with it is a smaller dashed ring in the member's zone, its share line arcing to the VPC. Transit gateways, Direct Connect gateways and hubs
// float in the aisle between the clouds; VPN peers, offices and networks outside your estate sit off the outer edges.
// Lines are arcs above the planes. With VPC flow logs read, a line carries light while it carries traffic, the hour
// bar replays the last 24 hours (◀ ▶ step back through the days kept), a line with nothing on it in days is dashed
// and marked NOT USED.
// Drag to turn, Shift+drag or two fingers to move, wheel or pinch to zoom.
import { h, svg, get, fmtClock, fmtStamp } from '../lib.js';
import { wheelKind } from './spaceRelated.js';

const W = 1400, H = 820, D = 2600, HOME = { az: 0, el: 56 };
const f = (v) => Math.round(v * 10) / 10;
const KIND_COLOR = { share: '#b9a3ff', peering: '#8ec5ff', tgw: '#6fe3b0', 'tgw-peering': '#6fe3b0', vpn: '#f6e016', dx: '#ff9f6b', 'client-vpn': '#7fd1ff', privatelink: '#d6a2ff', psc: '#d6a2ff', ncc: '#6fe3b0', interconnect: '#c59bff', internet: '#7e978a' };
const RED = '#ff6b5e', AMBER = '#f0b45a', IDLE = '#5f6f68';
const human = (b) => (b >= 1e9 ? `${(b / 1e9).toFixed(1)} GB` : b >= 1e6 ? `${(b / 1e6).toFixed(1)} MB` : b >= 1e3 ? `${Math.round(b / 1e3)} kB` : `${b} B`);

// `bow`: how far the control point moves sideways (x). A line between accounts or projects stacked in one cloud's column
// with another between them bows out past the column's outer edge, or it would run front to back straight over the
// zones and rings between them (seen from above, rising and going back both move a line up the screen, so lifting
// alone does not separate them)
function ctrl(a, b, lift, bow = 0) {
  const dx = b[0] - a[0], dy = b[1] - a[1], dist = Math.hypot(dx, dy) || 1, A = lift != null ? lift : 40 + 0.22 * dist;
  return [(a[0] + b[0]) / 2 + bow, (a[1] + b[1]) / 2, (a[2] + b[2]) / 2 + 2 * A];
}
function arc(a, b, P, lift, bow = 0) {
  const c = ctrl(a, b, lift, bow), pts = [];
  for (let i = 0; i <= 24; i++) { const t = i / 24, u = 1 - t; pts.push(P(u * u * a[0] + 2 * u * t * c[0] + t * t * b[0], u * u * a[1] + 2 * u * t * c[1] + t * t * b[1], u * u * a[2] + 2 * u * t * c[2] + t * t * b[2])); }
  return { pts, d: `M${pts.map((p) => `${f(p[0])} ${f(p[1])}`).join(' L')}` };
}

/**
 * Lays the scene out in plane coordinates from the overview (/api/network): AWS on the left, Google Cloud on the
 * right, each account or project a zone (stacked from front to back), its VPCs or networks two to a row; hubs in the
 * aisle between the clouds; peers and outsiders off the outer edge of their cloud; the internet above the aisle.
 */
function layout(d, envColor) {
  const P = new Map(), zones = [];
  const FW = 640, AISLE = 170;   // a cloud's width, and half the aisle between them
  // an account's own VPCs or networks, and its part of VPCs shared with it (a smaller, dashed ring)
  const ringsOf = (cloud, owner) => d.nodes.filter((n) => n.cloud === cloud && n.owner === owner && !n.stub && (n.kind === 'vpc' || n.kind === 'network' || n.kind === 'slice'));
  const field = (cloud, x0) => {
    const owners = d.owners.filter((o) => o.cloud === cloud && ringsOf(cloud, o.owner).length);
    const depths = owners.map((o) => Math.max(280, Math.ceil(ringsOf(cloud, o.owner).length / 2) * 260));
    const total = depths.reduce((a, b) => a + b, 0) + Math.max(0, owners.length - 1) * 40;
    let y = -total / 2;
    owners.forEach((o, i) => {
      const dep = depths[i], rings = ringsOf(cloud, o.owner).sort((a, b) => (a.kind === 'slice' ? 1 : 0) - (b.kind === 'slice' ? 1 : 0) || (a.isDefault ? 1 : 0) - (b.isDefault ? 1 : 0) || a.label.localeCompare(b.label));
      zones.push({ x0, x1: x0 + FW, y0: y, y1: y + dep, owner: o, color: envColor(o.environment), cloud });
      const rows = Math.ceil(rings.length / 2);
      rings.forEach((n, k) => {
        const row = Math.floor(k / 2), col = k % 2, last = k === rings.length - 1 && rings.length % 2;
        const cx = x0 + FW * (last ? 0.5 : col ? 0.73 : 0.27), cy = y + (dep / rows) * (row + 0.5);
        P.set(n.id, { x: cx, y: cy, z: 0, r: Math.min(84, 34 + 7 * Math.sqrt(n.subnets?.total || 1)) * (n.kind === 'slice' ? 0.8 : 1), slice: n.kind === 'slice' });
      });
      y += dep + 40;
    });
    return total;
  };
  const da = field('aws', -AISLE - FW), dg = field('gcp', AISLE);
  const depth = Math.max(da, dg, 500);
  // hubs in the aisle, on their own cloud's side of it (transit and Direct Connect gateways towards AWS, Network
  // Connectivity Center hubs towards Google Cloud), level with what they connect, at least 150 apart on each side
  const near = (id) => { const ys = d.links.filter((l) => l.from === id || l.to === id).map((l) => P.get(l.from === id ? l.to : l.from)?.y).filter((y) => y != null); return ys.length ? ys.reduce((a, b) => a + b, 0) / ys.length : 0; };
  for (const side of [-1, 1]) {
    const ys = d.nodes.filter((n) => ['tgw', 'dxgw', 'hub'].includes(n.kind) && (n.cloud === 'gcp' ? 1 : -1) === side).map((n) => ({ n, y: near(n.id) })).sort((a, b) => a.y - b.y);
    const want = ys.reduce((a, b) => a + b.y, 0) / (ys.length || 1);
    for (let i = 1; i < ys.length; i++) if (ys[i].y - ys[i - 1].y < 150) ys[i].y = ys[i - 1].y + 150;
    // spreading them out pushes them back: bring the group to where it wanted to be on average
    const shift = ys.reduce((a, b) => a + b.y, 0) / (ys.length || 1) - want;
    ys.forEach(({ n, y }, i) => P.set(n.id, { x: side * (AISLE * 0.5 + (i % 2) * 24), y: y - shift, z: 80 + (i % 2) * 30, r: 16, hub: true }));
  }
  // peers and outsiders: off the outer edge of the cloud they connect to
  const outer = d.nodes.filter((n) => n.kind === 'peer' || (n.stub && n.kind !== 'tgw'));
  const left = [], right = [];
  for (const n of outer) (n.cloud === 'gcp' || (n.kind === 'peer' && d.links.some((l) => (l.from === n.id || l.to === n.id) && [l.from, l.to].some((x) => x.startsWith('gcp:')))) ? right : left).push(n);
  const spread = (list, x) => list.forEach((n, i) => P.set(n.id, { x, y: list.length === 1 ? 0 : -depth / 2 + (depth * i) / (list.length - 1), z: 20, r: 14, outer: true }));
  spread(left, -AISLE - FW - 200); spread(right, AISLE + FW + 200);
  P.set('internet', { x: 0, y: depth / 2 + 40, z: 300, r: 26 });
  return { P, zones, span: AISLE + FW, aisle: AISLE };
}

/**
 * The scene. `pick(id)` selects a node or a line (the page shows its panel); `sel()` says what is selected;
 * `match(node)` false dims a node (the page's search); `tools` go at the front of the bar above; `internet()` and
 * `onInternet(on)` keep the beams to the internet on or off across redraws. Returns { el, redraw(), destroy() }.
 */
export function networkScene(d, { pick, sel, envColor, onHour, match = () => true, tools = [], internet = () => true, onInternet = () => {} }) {
  const L = layout(d, envColor);
  // a line between two accounts or projects on the same cloud's plane with another zone between them goes round the
  // outside of the plane, its middle just past the outer edge, clear of the zones and rings it would cross
  const inColumn = (p) => Math.abs(p[0]) >= L.aisle * 0.99 && Math.abs(p[0]) <= L.span + 1;
  const zoneAt = (p) => L.zones.filter((z) => Math.sign(z.x0 + z.x1) === Math.sign(p[0])).sort((x, y) => x.y0 - y.y0).findIndex((z) => p[1] >= z.y0 && p[1] <= z.y1);
  const bowOf = (a, b) => {
    if (!inColumn(a) || !inColumn(b) || Math.sign(a[0]) !== Math.sign(b[0])) return 0;
    const za = zoneAt(a), zb = zoneAt(b);
    if (za < 0 || zb < 0 || Math.abs(za - zb) < 2) return 0;
    const side = Math.sign(a[0]);
    return side * Math.max(0, 2 * (L.span + 40 - side * (a[0] + b[0]) / 2));
  };
  const st = { az: HOME.az, el: HOME.el, zoom: 1, px: 0, py: 0, hour: 23, day: 0, playing: false, internet: internet() };
  const hasFlows = d.links.some((l) => l.usage && l.usage.state !== 'unknown');
  // a line's use in a few words, for its tooltip: which VPCs' flow logs it waits for when it is not known
  const nodeLabel = (id) => d.nodes.find((n) => n.id === id)?.label || id.split(':').pop();
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
    for (const z of L.zones) pts.push([Math.sign(z.x0 + z.x1) * (L.span + 60), (z.y0 + z.y1) / 2, 0]);   // room for lines round the outside
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
    const byId = new Map(d.nodes.map((n) => [n.id, n]));
    const found = (id) => { const n = byId.get(id); return !n || match(n); };
    const fade = (id) => (cur && !rel.has(id) ? 0.16 : found(id) ? 1 : 0.14);
    // a line fades with what it joins when a search leaves both ends out
    const lfade = (l) => (cur ? (rel.has(l.id) ? 1 : 0.16) : found(l.from) || found(l.to) ? 1 : 0.14);
    // the planes and their zones
    for (const z of L.zones) {
      const pts = [[z.x0, z.y0], [z.x1, z.y0], [z.x1, z.y1], [z.x0, z.y1]].map(([x, y]) => P(x, y, 0));
      out.push(svg('path', { d: `M${pts.map((p) => `${f(p[0])} ${f(p[1])}`).join(' L')} Z`, fill: z.color, 'fill-opacity': 0.06, stroke: z.color, 'stroke-opacity': 0.55, 'stroke-dasharray': z.cloud === 'gcp' ? '5 4' : null }));
      const lp = P(z.x0 + 10, z.y1 - 4, 0);   // on the back edge, clear of the ring labels
      out.push(svg('text', { x: f(lp[0]), y: f(lp[1] - 6), class: 'ns-zone', fill: z.color }, `${z.cloud === 'aws' ? 'AWS' : 'GOOGLE CLOUD'} · ${z.owner.name}`));
    }
    const ent = (id) => { const p = L.P.get(id); return p ? [p.x, p.y, p.z] : null; };
    // lines
    const parts = [];
    for (const l of d.links) {
      if (l.kind === 'internet' && !st.internet) continue;
      const a = ent(l.from), b = ent(l.to); if (!a || !b) continue;
      const u = l.usage || { state: 'unknown' };
      const hrs = byLine.get(l.id), hourBytes = hrs ? hrs[st.hour].bytes : 0;
      const color = l.kind === 'internet' && (d.nodes.find((n) => n.id === (l.from === 'internet' ? l.to : l.from))?.worst === 'high') ? RED : KIND_COLOR[l.kind] || '#a9bfb2';
      const top = l.kind === 'internet' ? [a[0], a[1], 90] : a;
      const g = arc(top, b, P, l.kind === 'internet' ? 30 : null, l.kind === 'internet' ? 0 : bowOf(a, b));
      const on = cur === l.id;
      let stroke = color, dash = null, op = 0.85, w = usageWidth(l, u.bytes);
      if (u.state === 'unused') { stroke = IDLE; dash = '7 6'; op = 0.75; w = 1.4; }
      else if (u.state === 'unknown') { op = l.kind === 'internet' ? 0.35 : 0.6; }
      if (hasFlows && hrs && !hourBytes && u.state === 'used') op *= 0.55;
      out.push(svg('g', { opacity: lfade(l) },
        svg('path', { d: g.d, fill: 'none', stroke, 'stroke-width': f(on ? w + 1.8 : w), 'stroke-dasharray': dash, opacity: op, 'stroke-linecap': 'round' }),
        hourBytes > 0 && svg('path', { d: g.d, fill: 'none', stroke, 'stroke-width': f(w + 3), opacity: 0.35, filter: 'url(#ns-glow)' }),
        svg('path', { d: g.d, fill: 'none', stroke: '#000', 'stroke-opacity': 0, 'stroke-width': 14, class: 'ns-hit', onClick: () => pick(l.id) },
          svg('title', null, `${l.kind}${l.name ? ` · ${l.name}` : ''} · ${useTitle(u)}`))));
      if (u.state === 'unused' && (on || !cur)) { const m = g.pts[12]; out.push(svg('g', { opacity: lfade(l), class: 'ns-tag', onClick: () => pick(l.id) }, svg('rect', { x: f(m[0] - 32), y: f(m[1] - 9), width: 64, height: 16, rx: 2, fill: '#030d08', stroke: IDLE }), svg('text', { x: f(m[0]), y: f(m[1] + 3), 'text-anchor': 'middle', class: 'ns-tag-t', fill: '#a9bfb2' }, 'NOT USED'))); }
      if (l.kind === 'vpn' && l.tunnels?.length && (l.up ?? 0) < l.tunnels.length) { const m = g.pts[12]; const dy = u.state === 'unused' && (on || !cur) ? 18 : 0;
        // on the line it is about (above or below it, it lands on a ring or a zone's name), under NOT USED when both
        out.push(svg('g', { opacity: lfade(l), class: 'ns-tag', onClick: () => pick(l.id) }, svg('rect', { x: f(m[0] - 30), y: f(m[1] - 8 + dy), width: 60, height: 16, rx: 2, fill: '#030d08', stroke: RED }), svg('text', { x: f(m[0]), y: f(m[1] + 4 + dy), 'text-anchor': 'middle', class: 'ns-tag-t', fill: RED }, `${l.up}/${l.tunnels.length} UP`))); }
      // light travelling along a line that carried traffic in the hour shown
      if (hourBytes > 0 && !document.hidden && !matchMedia('(prefers-reduced-motion: reduce)').matches) {
        const n = Math.min(3, 1 + Math.floor(Math.log10(1 + hourBytes) / 3));
        for (let i = 0; i < n; i++) parts.push(svg('circle', { r: 2.6, fill: stroke, filter: 'url(#ns-glow)', opacity: lfade(l) },
          svg('animateMotion', { dur: `${f(2.4 + (i * 0.7))}s`, repeatCount: 'indefinite', path: g.d, begin: `${f(-i * 0.8)}s` })));
      }
    }
    // the internet, above
    const sky = P(L.P.get('internet').x, L.P.get('internet').y, L.P.get('internet').z);
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
        g.push(svg('path', { d: ring(0, p.r), fill: p.slice ? KIND_COLOR.share : color, 'fill-opacity': p.slice ? 0.06 : 0.12, stroke: on ? '#f6e016' : worst || (p.slice ? KIND_COLOR.share : color),
          'stroke-width': on ? 2.6 : worst ? 2 : 1.3, 'stroke-dasharray': p.slice ? '5 4' : null }));
        // subnets around the rim: public ones raised and amber
        const total = Math.min(n.subnets?.total || 0, 24), pub = n.subnets?.public || 0;
        for (let i = 0; i < total; i++) {
          const a = (i / Math.max(1, total)) * Math.PI * 2 - Math.PI / 2, x = p.x + Math.cos(a) * p.r * 0.72, y = p.y + Math.sin(a) * p.r * 0.65, isPub = i < pub;
          const b0 = P(x, y, 0), b1 = P(x, y, isPub ? 22 : 4);
          g.push(svg('line', { x1: f(b0[0]), y1: f(b0[1]), x2: f(b1[0]), y2: f(b1[1]), stroke: isPub ? AMBER : '#6fe3b0', 'stroke-width': f(Math.max(1.5, 3 * k)), 'stroke-linecap': 'round' }));
        }
        // the way out: a beam up from the ring (internet gateway, NAT, Cloud NAT, external addresses)
        if (!p.slice && d.links.some((l) => l.kind === 'internet' && (l.from === n.id || l.to === n.id))) {
          const b0 = P(p.x, p.y, 0), b1 = P(p.x, p.y, 90);
          g.push(svg('line', { x1: f(b0[0]), y1: f(b0[1]), x2: f(b1[0]), y2: f(b1[1]), stroke: n.exposed ? RED : '#7e978a', 'stroke-width': f(Math.max(1.2, 2.2 * k)), opacity: 0.8 }));
          if (n.exposed) g.push(svg('circle', { cx: f(b1[0]), cy: f(b1[1]), r: f(4 + 2 * k), fill: RED, class: 'ns-pulse' }));
        }
        const lp = P(p.x, p.y - p.r * 1.02, 0);   // under the ring's front edge
        g.push(svg('text', { x: f(lp[0]), y: f(lp[1] + 14), 'text-anchor': 'middle', class: 'ns-label strong' }, n.label.length > 24 ? `${n.label.slice(0, 23)}…` : n.label),
          svg('text', { x: f(lp[0]), y: f(lp[1] + 27), 'text-anchor': 'middle', class: 'ns-sub' }, p.slice ? `shared by ${n.vpcOwnerName || n.vpcOwner} · ${n.attachedOnly ? 'nothing running' : n.cloud === 'gcp' ? `${n.instances || 0} instance${n.instances === 1 ? '' : 's'}` : `${n.interfaces || 0} interface${n.interfaces === 1 ? '' : 's'}`}`
            : `${(n.cidrs || []).slice(0, 1).join('')}${n.shared ? ` · shared ×${(n.tenants || []).length - 1}` : ''}${n.flowDays ? ` · flow logs ${n.flowDays} d` : ''}`));
      }
      out.push(svg('g', { class: 'ns-node', opacity: fade(n.id), onClick: () => pick(n.id), tabindex: 0, role: 'button', 'aria-label': n.label,
        onKeydown: (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); pick(n.id); } } }, g, svg('title', null, `${n.label}${n.ownerLabel ? ` · ${n.ownerLabel}` : ''}`)));
    }
    layer.replaceChildren(...out, ...parts);
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
  wrap.addEventListener('pointermove', (e) => {
    if (!drag) return;
    const r = stage.getBoundingClientRect(), k = W / r.width, dx = (e.clientX - drag.x) * k, dy = (e.clientY - drag.y) * k;
    if (drag.pan) { st.px = drag.px + dx; st.py = drag.py + dy; } else { st.az = drag.az + dx * 0.25; st.el = Math.max(8, Math.min(80, drag.el + dy * 0.2)); }
    draw();
  });
  const drop = () => { drag = null; wrap.classList.remove('grabbing'); };
  wrap.addEventListener('pointerup', drop); wrap.addEventListener('pointercancel', drop); wrap.addEventListener('lostpointercapture', drop);
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
    h('div', { class: 'filters' }, ...tools, h('span', { class: 'small muted', title: 'Drag to turn. Shift+drag or two fingers to move. Wheel or pinch to zoom. Esc lets go of what is selected.' }, 'Drag: turn · Shift+drag: move · wheel: zoom'),
      h('label', { class: 'small row', style: 'gap:6px' }, internetBox, 'Beams to the internet'), h('span', { style: 'flex:1' }),
      btn('⟲', () => { st.az -= 15; draw(); }, 'Turn left'), btn('⟳', () => { st.az += 15; draw(); }, 'Turn right'), btn('+', () => { st.zoom = Math.min(4, st.zoom * 1.2); draw(); }, 'Zoom in'), btn('−', () => { st.zoom = Math.max(0.35, st.zoom / 1.2); draw(); }, 'Zoom out'), btn('Reset', reset)),
    wrap,
    h('div', { class: 'ns-time' }, h('div', { class: 'ns-day' }, playBtn, h('div', { class: 'ns-day-nav' }, earlier, dayText, later)), bars, hourText));
  tick();
  return { el, redraw: draw, destroy: () => clearInterval(timer) };
}
