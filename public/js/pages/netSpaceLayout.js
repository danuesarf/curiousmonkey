// Networking → Space: where everything goes, apart from drawing it, so the layout can be tested on an estate of
// hundreds of VPCs, peers and accounts (test/networkLarge.test.js). Plane coordinates: x across (AWS left of the aisle,
// Google Cloud right of it), y from front to back, z up. Nothing here touches the page.

export const CELL_W = 250, CELL_D = 270, PAD = 44, GAP = 80, AISLE = 210;
const OUT_X = 200, OUT_Y = 180;   // the grid of peers and outsiders in front of the planes
export const HUB_R = 34, OUT_R = 26;             // their sizes, in plane units

/** A ring's radius: a VPC or network by its subnets; a member account's part of a shared one is smaller. */
export const ringR = (n) => Math.min(84, 34 + 7 * Math.sqrt(n.subnets?.total || 1)) * (n.kind === 'slice' ? 0.8 : 1);
const isRing = (n) => !n.stub && (n.kind === 'vpc' || n.kind === 'network' || n.kind === 'slice');
const isHub = (n) => ['tgw', 'dxgw', 'hub'].includes(n.kind);
const isOuter = (n) => n.kind === 'peer' || (n.stub && !isHub(n));

/**
 * Zones in shelves from the front back, each shelf filled outwards from the aisle, a smaller zone stacking behind
 * the one before it in a column when it fits in the shelf's depth. The widest a shelf gets is `width`. Sets each
 * zone's `u` (out from the aisle) and `v` (back from the front); returns the field's width and depth.
 */
export function packZones(zs, width) {
  let cur = null, w = 0, depth = 0;
  for (const z of zs) {
    const col = cur?.cols.at(-1);
    if (col && col.used + GAP + z.d <= cur.d && z.w <= col.w) { z.u = col.u; z.v = cur.v + col.used + GAP; col.used += GAP + z.d; continue; }
    if (cur && cur.w + GAP + z.w <= width) { z.u = cur.w + GAP; z.v = cur.v; cur.cols.push({ u: z.u, w: z.w, used: z.d }); cur.w = z.u + z.w; w = Math.max(w, cur.w); continue; }
    cur = { v: cur ? cur.v + cur.d + GAP : 0, d: z.d, w: z.w, cols: [{ u: 0, w: z.w, used: z.d }] };
    z.u = 0; z.v = cur.v; w = Math.max(w, z.w); depth = cur.v + cur.d;
  }
  return { width: w, depth };
}

/**
 * The layout from the overview (/api/network). `envRank(id)` orders environments (the workspace's order). Returns
 * P: node id -> { x, y, z, r, ... }, zones [{ x0, x1, y0, y1, owner, cloud }], and the scene's extent.
 */
export function spaceLayout(d, { envRank = () => 0 } = {}) {
  const P = new Map(), zones = [];
  const nodes = d.nodes || [], links = d.links || [];
  const nb = new Map();   // node id -> the ids it has lines to
  for (const l of links) { (nb.get(l.from) || nb.set(l.from, []).get(l.from)).push(l.to); (nb.get(l.to) || nb.set(l.to, []).get(l.to)).push(l.from); }
  const byOwner = new Map();
  for (const n of nodes) if (n.cloud && isRing(n)) { const k = `${n.cloud}|${n.owner}`; (byOwner.get(k) || byOwner.set(k, []).get(k)).push(n); }
  let depth = 0, outer = { aws: 0, gcp: 0 };
  for (const [cloud, side] of [['aws', -1], ['gcp', 1]]) {
    // a zone per account or project, its rings in a grid about as wide as it is deep: its own VPCs or networks
    // first, then its parts of others' shared ones, default VPCs last
    const zs = (d.owners || []).filter((o) => o.cloud === cloud && byOwner.has(`${cloud}|${o.owner}`)).map((o) => {
      const rings = byOwner.get(`${cloud}|${o.owner}`).slice().sort((a, b) => (a.kind === 'slice' ? 1 : 0) - (b.kind === 'slice' ? 1 : 0) || (a.isDefault ? 1 : 0) - (b.isDefault ? 1 : 0)
        || String(a.label).localeCompare(String(b.label), undefined, { numeric: true }));
      const n = rings.length, cols = Math.max(1, Math.min(n, Math.ceil(Math.sqrt(n * 1.6)))), rows = Math.ceil(n / cols);
      return { owner: o, rings, cols, rows, w: cols * CELL_W + 2 * PAD, d: rows * CELL_D + 2 * PAD };
    }).sort((a, b) => b.rings.length - a.rings.length || envRank(a.owner.environment) - envRank(b.owner.environment) || String(a.owner.name).localeCompare(String(b.owner.name)));
    if (!zs.length) continue;
    // as wide as about one and a half times as deep, so the scene fills a wide view
    const area = zs.reduce((s, z) => s + (z.w + GAP) * (z.d + GAP), 0);
    const field = packZones(zs, Math.max(...zs.map((z) => z.w), Math.sqrt(area * 1.5)));
    depth = Math.max(depth, field.depth); outer[cloud] = AISLE + field.width;
    for (const z of zs) {
      const x0 = side < 0 ? -AISLE - z.u - z.w : AISLE + z.u, y0 = z.v;
      zones.push({ x0, x1: x0 + z.w, y0, y1: y0 + z.d, owner: z.owner, cloud });
      // row by row from the back (the top of the screen), left to right
      z.rings.forEach((n, k) => {
        const row = Math.floor(k / z.cols), inRow = Math.min(z.cols, z.rings.length - row * z.cols), col = k % z.cols;
        const x = x0 + PAD + CELL_W * (col + 0.5 + (z.cols - inRow) / 2);   // a short last row centred
        P.set(n.id, { x, y: y0 + z.d - PAD - CELL_D * (row + 0.5), z: 0, r: ringR(n), slice: n.kind === 'slice' });
      });
    }
  }
  depth = Math.max(depth, 400);
  // hubs in the aisle, on their own cloud's side of it, level with what they connect to, at least 150 apart
  const ysOf = (id) => (nb.get(id) || []).map((x) => P.get(x)?.y).filter((y) => y != null);
  for (const side of [-1, 1]) {
    const hs = nodes.filter((n) => isHub(n) && (n.cloud === 'gcp' ? 1 : -1) === side).map((n) => { const ys = ysOf(n.id); return { n, y: ys.length ? ys.reduce((a, b) => a + b, 0) / ys.length : depth * 0.15 }; })
      .sort((a, b) => a.y - b.y || String(a.n.label).localeCompare(String(b.n.label)));
    const want = hs.reduce((a, b) => a + b.y, 0) / (hs.length || 1);
    for (let i = 1; i < hs.length; i++) if (hs[i].y - hs[i - 1].y < 150) hs[i].y = hs[i - 1].y + 150;
    const shift = hs.reduce((a, b) => a + b.y, 0) / (hs.length || 1) - want;   // spreading pushed them back: bring them forward again
    hs.forEach(({ n, y }, i) => P.set(n.id, { x: side * (AISLE * 0.5 + (i % 2) * 34), y: y - shift, z: 80 + (i % 2) * 30, r: HUB_R, hub: true }));
  }
  // peers and outsiders: in front of the planes, in blocks near what they connect to (a transit gateway's VPN peers
  // together, in name order), a block where it overlaps none placed before
  const taken = new Set(), groups = new Map();
  for (const n of nodes.filter(isOuter)) {
    const to = [...new Set(nb.get(n.id) || [])].filter((x) => P.has(x)).sort();
    const key = to.join(' ') || `~${n.cloud || ''}`;
    (groups.get(key) || groups.set(key, { to, list: [] }).get(key)).list.push(n);
  }
  const order = [...groups.values()].map((g) => ({ ...g, x: g.to.length ? g.to.reduce((s, id) => s + P.get(id).x, 0) / g.to.length : 0 }))
    .sort((a, b) => b.list.length - a.list.length || a.x - b.x);
  for (const g of order) {
    const list = g.list.sort((a, b) => String(a.label).localeCompare(String(b.label), undefined, { numeric: true }));
    // a block about four times as wide as deep (36 VPN peers: 12 across, 3 rows)
    const cols = Math.min(list.length, Math.max(8, Math.ceil(Math.sqrt(list.length * 4)))), rows = Math.ceil(list.length / cols), mid = Math.round(g.x / OUT_X - (cols - 1) / 2);
    // the free spot nearest to it: a row further forward costs as much as two and a half slots aside, so the band
    // stays shallow and spreads across the width of the planes
    let best = null;
    for (let r0 = 0; r0 < 24; r0++) {
      for (let off = 0; off <= 48; off++) {
        const cost = off * OUT_X + r0 * OUT_X * 2.5;
        if (best && cost >= best.cost) break;
        for (const i0 of off ? [mid - off, mid + off] : [mid]) {
          let free = true;
          for (let r = r0; r < r0 + rows && free; r++) for (let i = i0; i < i0 + cols; i++) if (taken.has(`${r}:${i}`)) { free = false; break; }
          if (free) { best = { r0, i0, cost }; break; }
        }
      }
    }
    list.forEach((n, k) => {
      const r = best.r0 + Math.floor(k / cols), i = best.i0 + (k % cols);
      taken.add(`${r}:${i}`);
      P.set(n.id, { x: i * OUT_X, y: -OUT_Y * (r + 1), z: 20, r: OUT_R, outer: true });
    });
  }
  P.set('internet', { x: 0, y: depth + 200, z: 320, r: 26 });
  // the extent, for framing
  let x0 = -AISLE, x1 = AISLE, y0 = 0, y1 = depth;
  for (const z of zones) { x0 = Math.min(x0, z.x0); x1 = Math.max(x1, z.x1); }
  for (const p of P.values()) { x0 = Math.min(x0, p.x - (p.r || 0)); x1 = Math.max(x1, p.x + (p.r || 0)); y0 = Math.min(y0, p.y - (p.r || 0)); y1 = Math.max(y1, p.y + (p.r || 0)); }
  return { P, zones, depth, aisle: AISLE, bounds: { x0, x1, y0, y1 }, outer };
}

/**
 * Which labels to show: the most important first, each only where it overlaps none already shown (and is on
 * screen). `list`: [{ x, y, w, h, prio, alts?, needs? }] boxes in screen units, x and y their top left; `alts` are
 * other places it may go ([{ x, y }], tried in order when its own is taken: a peer's name above it rather than
 * under); `needs` the index of a label it is shown only with. Returns the indices kept; each kept label's `at` is
 * where it went ({ x, y }).
 */
export function placeLabels(list, { margin = 2, view = null } = {}) {
  const CELL = 48, grid = new Map(), kept = new Set(), at = new Map();
  const order = list.map((_, i) => i).filter((i) => list[i]).sort((a, b) => list[b].prio - list[a].prio || a - b);
  const hit = (a, b) => a.x < b.x + b.w + margin && b.x < a.x + a.w + margin && a.y < b.y + b.h + margin && b.y < a.y + a.h + margin;
  const cells = (b, fn) => { for (let cx = Math.floor(b.x / CELL); cx <= Math.floor((b.x + b.w) / CELL); cx++) for (let cy = Math.floor(b.y / CELL); cy <= Math.floor((b.y + b.h) / CELL); cy++) if (fn(`${cx},${cy}`) === false) return false; return true; };
  const free = (b) => (!view || !(b.x > view.w || b.y > view.h || b.x + b.w < 0 || b.y + b.h < 0))
    && cells(b, (k) => !(grid.get(k) || []).some((j) => hit(at.get(j), b)));
  for (const i of order) {
    const l = list[i];
    if (l.needs != null && !kept.has(l.needs)) continue;
    const spot = [{ x: l.x, y: l.y }, ...(l.alts || [])].map((p) => ({ x: p.x, y: p.y, w: l.w, h: l.h })).find(free);
    if (!spot) continue;
    kept.add(i); at.set(i, spot); l.at = { x: spot.x, y: spot.y };
    cells(spot, (k) => { (grid.get(k) || grid.set(k, []).get(k)).push(i); });
  }
  return kept;
}

// how wide a label is, in the scene's units, by its font (public/app.css: .ns-zone, .ns-label, .ns-sub, .ns-tag-t)
export const TEXT = { zone: [7.6, 13], strong: [7.1, 15], label: [6.2, 13], sub: [6.1, 12], tag: [6.4, 16] };
export const textBox = (kind, s, x, y, anchor = 'middle') => {
  const [cw, h] = TEXT[kind], w = String(s).length * cw + 4;
  return { x: anchor === 'middle' ? x - w / 2 : anchor === 'end' ? x - w : x, y: y - h + 3, w, h };
};
