// Radar: every role on one scope, seen from above.
//   distance from the centre = share of granted permissions never called, in four zones
//   slice                    = account
//   shape                    = kind of role; size = permissions granted
// Only roles that need attention are bright; up to ten get a short tag. Quiet roles that crowd together fold into
// one numbered blob, which splits as you zoom in. Names live in the ranked list on the left.
import { h, svg, get, num, ago } from '../lib.js';
import { go } from '../main.js';

const KIND_LABEL = { custom: 'Custom', 'identity-center': 'Identity Center', 'service-linked': 'Service-linked' };
const ZONES = [
  { name: 'Tight', label: 'TIGHT · <25% NEVER CALLED', color: '#9fe8c4', fill: '#06160e', sw: '#6fe3b0', range: 'under 25% never called' },
  { name: 'Loose', label: 'LOOSE · 25–75%', color: '#c9d98a', fill: '#081a10', sw: '#b8c75a', range: '25–75% never called' },
  { name: 'Bloated', label: 'BLOATED · >75%', color: '#ffd89a', fill: '#0b1c11', sw: '#f0b45a', range: 'over 75% never called' },
  { name: 'Dead', label: 'DEAD · NO CALLS IN HISTORY', color: '#ffb3aa', fill: '#130f0b', sw: '#ff6b5e', range: 'no calls at all' },
];
const RZ = [34, 104, 214, 272, 316];          // zone radii: tight | loose | bloated | dead
const CX = 400, CY = 400, GAP = 4, MAX_ROWS = 300, ADMIN = 15000;
const FILTERS = [
  ['high', 'High risk', (r) => r.risk === 'High'], ['unk', 'Unidentified', (r) => r.unidentified.length > 0], ['denied', 'Denied', (r) => r.denied > 0],
  ['bloated', 'Bloated', (r) => r.zone === 2], ['dead', 'Dead', (r) => r.zone === 3],
];
const r1 = (v) => Math.round(v * 10) / 10;
const P = (deg, r) => { const a = ((deg - 90) * Math.PI) / 180; return [r1(CX + Math.cos(a) * r), r1(CY + Math.sin(a) * r)]; };
const disc = (r) => `M${CX - r} ${CY}a${r} ${r} 0 1 0 ${2 * r} 0a${r} ${r} 0 1 0 ${-2 * r} 0Z`;
const riskClass = (r) => ({ High: 'b-high', Medium: 'b-medium', Low: 'b-low' })[r] || 'b-neutral';
const hash = (s) => [...s].reduce((a, c) => (a * 31 + c.charCodeAt(0)) % 2147483647, 7);
const shape = (kind, x, y, s) => kind === 'identity-center' ? `M${r1(x - s)} ${r1(y - s)}h${r1(2 * s)}v${r1(2 * s)}h${r1(-2 * s)}Z`
  : kind === 'service-linked' ? `M${x} ${r1(y - s * 1.3)}L${r1(x + s * 1.3)} ${y}L${x} ${r1(y + s * 1.3)}L${r1(x - s * 1.3)} ${y}Z`
  : `M${r1(x - s)} ${y}a${s} ${s} 0 1 0 ${r1(2 * s)} 0a${s} ${s} 0 1 0 ${r1(-2 * s)} 0Z`;
const size = (r) => r1(1.8 + Math.log10(r.granted_count + 1) * 0.9);

export async function radarPage(ctx) {
  const account = ctx.params.get('account') || '';
  const q = account ? `?account=${account}` : '';
  const [data, accts] = await Promise.all([get(`/radar${q}`), get('/accounts')]);
  ctx.setCrumbs('Radar', account ? accts.items.find((a) => a.id === account)?.name || '' : 'All accounts');
  if (!data.roles.length) {
    return h('div', { class: 'stack-lg' }, h('div', { class: 'card empty' }, accts.items.length
      ? 'Roles appear here as soon as the first scan has listed them.' : 'No accounts yet. ', !accts.items.length && h('a', { href: '#/accounts/new' }, 'Connect an AWS account')));
  }

  // ---- shape the data ----
  const roles = data.roles.map((r) => {
    const g = Math.max(r.granted_count, 1);
    const zone = r.calls === 0 ? 3 : r.unused_count / g < 0.25 ? 0 : r.unused_count / g < 0.75 ? 1 : 2;
    const never = r.calls === 0 ? 1 : r.unused_count / g;
    const score = (r.risk === 'High' ? 3 : r.risk === 'Medium' ? 0.5 : 0) + (r.unidentified.length ? 2 : 0) + (r.denied ? 1.5 : 0) + (r.granted_count > ADMIN ? 1 : 0) + Math.log10(g) * 0.15;
    const hs = hash(r.id); return { ...r, zone, never, score, jit: (hs % 1000) / 1000, jit2: ((hs >> 10) % 1000) / 1000 };
  });
  const ranked = roles.slice().sort((a, b) => b.score - a.score || a.name.localeCompare(b.name));
  ranked.forEach((r, i) => { r.rank = i; });
  const byId = new Map(roles.map((r) => [r.id, r]));
  const accounts = data.accounts.filter((a) => roles.some((r) => r.account_id === a.id));
  const provisionalAny = roles.some((r) => r.provisional);

  // account slices, sized by role count
  const span = 360 - GAP * accounts.length; let a0 = 0;
  const slices = accounts.map((a) => {
    const list = roles.filter((r) => r.account_id === a.id); const w = (span * list.length) / roles.length;
    const s = { ...a, list, a0: a0 + GAP / 2, a1: a0 + GAP / 2 + w }; a0 += w + GAP; return s;
  });
  for (const s of slices) {
    for (let z = 0; z < 4; z++) {
      const inZone = s.list.filter((r) => r.zone === z).sort((a, b) => a.name.localeCompare(b.name));
      inZone.forEach((r, k) => {
        const ang = s.a0 + 2 + ((k + 0.2 + r.jit * 0.6) / inZone.length) * (s.a1 - s.a0 - 4);
        const t = z === 3 ? r.jit2 : z === 0 ? r.never / 0.25 : z === 1 ? (r.never - 0.25) / 0.5 : (r.never - 0.75) / 0.25;
        const rad = RZ[z] + 8 + Math.max(0, Math.min(1, t)) * (RZ[z + 1] - RZ[z] - 16);
        [r.x, r.y] = P(ang, rad); r.ang = ang; r.rad = rad; r.slice = s;
      });
    }
  }

  const st = { sel: ranked[0].id, filter: null, fold: true, zoom: 1, cx: CX, cy: CY, search: '', callers: [] };
  const attention = (r) => r.risk === 'High' || r.unidentified.length > 0 || r.denied > 0;
  const fnOf = () => (st.filter ? FILTERS.find((f) => f[0] === st.filter)[2] : null);
  const litOf = () => { const fn = fnOf(); return (r) => (fn ? fn(r) : attention(r)); };
  const tagsFor = () => { const lit = litOf(); return new Map(ranked.filter(lit).slice(0, 10).map((r, i) => [r.id, `R-${String(i + 1).padStart(2, '0')}`])); };

  // ---- the scope ----
  const stage = svg('svg', { class: 'stage', viewBox: '-110 0 1020 800', preserveAspectRatio: 'xMidYMid meet', role: 'img',
    'aria-label': 'Radar of roles seen from above. Distance from the centre is the share of permissions never called, in four zones; each account has its own slice.' });
  const hud = h('div', { class: 'hud' });
  const still = matchMedia('(prefers-reduced-motion: reduce)').matches;

  function draw() {
    const fn = fnOf(), lit = litOf(), tagOf = tagsFor(), sel = byId.get(st.sel);
    const k = [];
    k.push(svg('defs', null,
      svg('filter', { id: 'g2', x: '-80%', y: '-80%', width: '260%', height: '260%' }, svg('feGaussianBlur', { stdDeviation: 2.4, result: 'b' }),
        svg('feMerge', null, svg('feMergeNode', { in: 'b' }), svg('feMergeNode', { in: 'SourceGraphic' }))),
      svg('radialGradient', { id: 'sw2', cx: 0, cy: 0, r: 330, gradientUnits: 'userSpaceOnUse' },
        svg('stop', { offset: 0, 'stop-color': '#f6e016', 'stop-opacity': 0.16 }), svg('stop', { offset: 1, 'stop-color': '#f6e016', 'stop-opacity': 0.02 }))));
    ZONES.forEach((z, i) => k.push(svg('path', { d: `${disc(RZ[i + 1])} ${i ? disc(RZ[i]) : ''}`, fill: z.fill, 'fill-rule': 'evenodd', stroke: '#1a4231' })));
    for (const s of slices) {
      const [ex0, ey0] = P(s.a0 - GAP / 2, RZ[0]), [ex1, ey1] = P(s.a0 - GAP / 2, 322), [ax0, ay0] = P(s.a0, 322), [ax1, ay1] = P(s.a1, 322);
      const mid = (s.a0 + s.a1) / 2; const [lx, lyRaw] = P(mid, 340); const ly = r1(lyRaw + (lyRaw < CY ? -8 : 6));
      const anchor = Math.abs(lx - CX) < 40 ? 'middle' : lx > CX ? 'start' : 'end';
      const sub = `${s.list.length} roles · ${s.list.filter((r) => r.zone >= 2).length} bloated or dead${s.complete ? '' : ` · ${s.progress}% read`}`;
      const fit = (w) => (anchor === 'start' ? Math.min(lx, 906 - w) : anchor === 'end' ? Math.max(lx, -106 + w) : lx);
      const lxc = fit(s.name.length * 7.3), lxs = fit(sub.length * 5.6);
      const g = svg('g', { style: 'cursor:pointer', onClick: () => go(`#/?account=${s.id}`) },
        svg('title', null, `Show only ${s.name}`),
        slices.length > 1 ? svg('path', { d: `M${ex0} ${ey0} L${ex1} ${ey1}`, stroke: '#2a5c45', 'stroke-width': 1.2 }) : null,
        svg('path', { d: `M${ax0} ${ay0} A322 322 0 ${s.a1 - s.a0 > 180 ? 1 : 0} 1 ${ax1} ${ay1}`, fill: 'none', stroke: s.complete ? '#2f6e52' : '#8a7d12', 'stroke-width': 3, 'stroke-dasharray': s.complete ? null : '6 4' }),
        svg('text', { x: r1(lxc), y: ly, 'text-anchor': anchor, fill: '#e3efe8', 'font-family': 'Geist Mono, monospace', 'font-size': 12 }, s.name),
        svg('text', { x: r1(lxs), y: ly + 14, 'text-anchor': anchor, fill: '#7e978a', 'font-size': 11 }, sub));
      k.push(g);
    }
    if (!still) k.push(svg('g', { transform: `translate(${CX} ${CY})`, 'pointer-events': 'none' }, svg('g', null,
      svg('path', { d: 'M0 0 L330 0 A330 330 0 0 0 285.8 -165 Z', fill: 'url(#sw2)' }), svg('path', { d: 'M0 0 L330 0', stroke: '#f6e016', 'stroke-opacity': 0.55, 'stroke-width': 2 }),
      svg('animateTransform', { attributeName: 'transform', type: 'rotate', from: '0', to: '360', dur: '8s', repeatCount: 'indefinite' }))));
    const zoneBoxes = [], zs = 1 / Math.sqrt(st.zoom);
    ZONES.forEach((z, i) => {
      const y = r1(CY - (RZ[i] + RZ[i + 1]) / 2 + 3.5 * zs), bw = (z.label.length * 6.6 + 10) * zs, bh = 16 * zs;
      zoneBoxes.push([CX - bw / 2, y - 11.5 * zs, CX + bw / 2, y - 11.5 * zs + bh]);
      k.push(svg('rect', { x: r1(CX - bw / 2), y: r1(y - 11.5 * zs), width: r1(bw), height: r1(bh), fill: '#030d08', opacity: 0.85, 'pointer-events': 'none' }),
        svg('text', { x: CX, y, 'text-anchor': 'middle', fill: z.color, 'font-family': 'Geist Mono, monospace', 'font-size': r1(10 * zs), 'letter-spacing': r1(1.2 * zs), 'pointer-events': 'none' }, z.label));
    });

    // quiet roles: fold crowded bins; bins get finer as you zoom in, so blobs split
    const perSlice = Math.max(3, Math.round(3 * st.zoom * st.zoom));
    const bins = new Map();
    for (const r of roles) {
      if (lit(r) || r.id === sel.id) continue;
      const s = r.slice; const b = Math.min(perSlice - 1, Math.floor(((r.ang - s.a0) / (s.a1 - s.a0)) * perSlice));
      const key = `${s.id}:${r.zone}:${b}`; if (!bins.has(key)) bins.set(key, []); bins.get(key).push(r);
    }
    const dim = fn ? 0.25 : 0.55;
    for (const list of bins.values()) {
      if (st.fold && list.length >= 4) {
        const x = r1(list.reduce((a, r) => a + r.x, 0) / list.length), y = r1(list.reduce((a, r) => a + r.y, 0) / list.length);
        const rr = r1(7 + Math.sqrt(list.length) * 2.2);
        k.push(svg('g', { style: 'cursor:zoom-in', onClick: (e) => { e.stopPropagation(); zoomAt(x, y, Math.min(4, st.zoom * 1.8)); } },
          svg('title', null, `${list.length} quiet roles: ${list.slice(0, 6).map((r) => r.name).join(', ')}${list.length > 6 ? '…' : ''}. Click to zoom in.`),
          svg('circle', { cx: x, cy: y, r: rr, fill: '#0c2a1d', stroke: '#3c7d5f', opacity: fn ? 0.45 : 0.95 }),
          svg('text', { x, y: y + 3.5, 'text-anchor': 'middle', fill: '#a9bfb2', 'font-family': 'Geist Mono, monospace', 'font-size': 10, opacity: fn ? 0.45 : 1 }, list.length)));
      } else for (const r of list) {
        k.push(svg('path', { d: shape(r.kind, r.x, r.y, size(r)), fill: r.provisional ? 'none' : '#3f9a73', stroke: r.provisional ? '#3f9a73' : null, opacity: dim, style: 'cursor:pointer',
          onClick: (e) => { e.stopPropagation(); select(r.id); } }, svg('title', null, `${r.name} · ${r.account_name} · ${Math.round(r.never * 100)}% never called`)));
      }
    }

    // selected role's callers (filled in once its details arrive)
    st.callers.forEach((c, i, all) => {
      const ang = sel.ang + (i - (all.length - 1) / 2) * 14; const [x, y] = P(ang, 330); const left = x < CX;
      const [mx, my] = P((ang + sel.ang) / 2, (330 + sel.rad) / 2 + 20);
      k.push(svg('path', { d: `M${x} ${y} Q${mx} ${my} ${sel.x} ${sel.y}`, fill: 'none', stroke: c.ok ? '#6fe3b0' : '#f0b45a', 'stroke-width': 1.5, class: still ? null : 'live' }),
        svg('path', { d: `M${x} ${y - 5} L${x + 5} ${y} L${x} ${y + 5} L${x - 5} ${y} Z`, fill: '#e3efe8' }),
        svg('text', { x: left ? x - 10 : x + 10, y: y - 1, 'text-anchor': left ? 'end' : 'start', fill: '#e3efe8', 'font-family': 'Geist Mono, monospace', 'font-size': 11 }, short(c.name, Math.max(8, Math.floor((left ? x + 100 : 896 - x) / 6.8)))),
        svg('text', { x: left ? x - 10 : x + 10, y: y + 12, 'text-anchor': left ? 'end' : 'start', fill: '#7e978a', 'font-size': 10 }, c.kind));
    });

    // roles that need attention, then the selection
    const hot = roles.filter((r) => lit(r) || r.id === sel.id).sort((a, b) => (a.id === sel.id) - (b.id === sel.id));
    for (const r of hot) {
      const s = size(r) + 1, isSel = r.id === sel.id, hi = r.risk === 'High';
      const col = isSel ? '#f6e016' : hi ? '#ff8a7a' : '#6fe3b0';
      const g = svg('g', { style: 'cursor:pointer', onClick: (e) => { e.stopPropagation(); select(r.id); }, onDblclick: () => go(`#/roles/${r.id}/scan`) },
        svg('title', null, `${r.name} · ${r.account_name} · ${Math.round(r.never * 100)}% never called`));
      if (r.unidentified.length) g.append(svg('circle', { cx: r.x, cy: r.y, r: r1(s + 5), fill: 'none', stroke: '#f0b45a', 'stroke-width': 1.4, 'stroke-dasharray': '3 2', class: still ? null : 'blink' }));
      g.append(svg('path', { d: shape(r.kind, r.x, r.y, s), fill: r.provisional ? '#030d08' : col, stroke: col, 'stroke-width': 1.4, filter: 'url(#g2)' }));
      if (r.denied) g.append(svg('path', { d: `M${r1(r.x + s + 3)} ${r1(r.y - s - 6)} l5 5 m0 -5 l-5 5`, stroke: '#ff6b5e', 'stroke-width': 1.8 }));
      if (isSel) g.append(svg('circle', { cx: r.x, cy: r.y, r: r1(s + 9), fill: 'none', stroke: '#f6e016', 'stroke-width': 1.5 }));
      k.push(g);
    }

    // tags, pushed outward, skipping collisions (sizes divided by zoom so they stay readable)
    const zf = 1 / Math.sqrt(st.zoom), placed = [...zoneBoxes];
    const tagged = roles.filter((r) => tagOf.has(r.id)).sort((a, b) => a.rank - b.rank);
    if (!tagOf.has(sel.id)) tagged.unshift(sel);
    for (const r of tagged) {
      const text = tagOf.get(r.id) || 'SEL', bw = (text.length * 6.6 + 10) * zf, bh = 18 * zf;
      for (const push of [16, 30, 46, -18]) {
        const [tx0, ty0] = P(r.ang, r.rad + push * zf); const left = tx0 < CX;
        const bx = left ? tx0 - bw : tx0, by = ty0 - bh / 2, box = [bx, by, bx + bw, by + bh];
        if (placed.some((q) => box[0] < q[2] + 2 && box[2] > q[0] - 2 && box[1] < q[3] + 2 && box[3] > q[1] - 2)) continue;
        placed.push(box);
        const color = r.id === sel.id ? '#f6e016' : r.risk === 'High' ? '#ff8a7a' : r.unidentified.length ? '#f0b45a' : '#6fe3b0';
        k.push(svg('g', { style: 'cursor:pointer', onClick: (e) => { e.stopPropagation(); select(r.id); } },
          svg('path', { d: `M${r.x} ${r.y} L${r1(left ? bx + bw : bx)} ${r1(by + bh / 2)}`, stroke: color, 'stroke-width': zf, opacity: 0.7 }),
          svg('rect', { x: r1(bx), y: r1(by), width: r1(bw), height: r1(bh), fill: '#030d08', stroke: color, 'stroke-width': zf }),
          svg('text', { x: r1(bx + 5 * zf), y: r1(by + 13 * zf), fill: color, 'font-family': 'Geist Mono, monospace', 'font-size': r1(10.5 * zf), 'font-weight': 500 }, text)));
        break;
      }
    }
    stage.replaceChildren(...k);
    const vw = 1020 / st.zoom, vh = 800 / st.zoom;
    stage.setAttribute('viewBox', `${r1(st.cx - vw / 2)} ${r1(st.cy - vh / 2)} ${r1(vw)} ${r1(vh)}`);
    hud.replaceChildren(
      h('div', { class: 'hot' }, `● RADAR · ${slices.length} ACCOUNT${slices.length > 1 ? 'S' : ''} · ${num(roles.length)} ROLES${provisionalAny ? ' · FILLING IN' : ''}`),
      h('div', null, `${roles.filter(attention).length} NEED ATTENTION · ${tagOf.size} TAGGED · ${st.fold ? 'QUIET ROLES FOLDED' : 'ALL DOTS'}`),
      h('div', null, `DISTANCE = SHARE NEVER CALLED · SLICE = ACCOUNT${st.zoom > 1.05 ? ` · ZOOM ${st.zoom.toFixed(1)}×` : ''}`));
  }

  // ---- zoom and pan ----
  let frame = 0; const redraw = () => { if (!frame) frame = requestAnimationFrame(() => { frame = 0; draw(); }); };
  const clampView = () => { if (st.zoom <= 1) { st.cx = CX; st.cy = CY; return; } st.cx = Math.max(40, Math.min(760, st.cx)); st.cy = Math.max(40, Math.min(760, st.cy)); };
  function zoomAt(x, y, z) { st.zoom = Math.max(1, Math.min(4, z)); st.cx = x; st.cy = y; clampView(); draw(); }
  const toLocal = (e) => { const pt = stage.createSVGPoint(); pt.x = e.clientX; pt.y = e.clientY; return pt.matrixTransform(stage.getScreenCTM().inverse()); };
  stage.addEventListener('wheel', (e) => {
    e.preventDefault(); const p = toLocal(e); const z = Math.max(1, Math.min(4, st.zoom * (e.deltaY > 0 ? 0.9 : 1.11)));
    st.cx = p.x - (p.x - st.cx) * (st.zoom / z); st.cy = p.y - (p.y - st.cy) * (st.zoom / z); st.zoom = z; clampView(); redraw();
  }, { passive: false });
  let drag = null;
  stage.addEventListener('pointerdown', (e) => { if (st.zoom > 1) { drag = { x: e.clientX, y: e.clientY, cx: st.cx, cy: st.cy, k: Math.max(1020 / st.zoom / stage.getBoundingClientRect().width, 800 / st.zoom / stage.getBoundingClientRect().height) }; } });
  stage.addEventListener('pointermove', (e) => {
    if (!drag) return; if (!drag.cap) { if (Math.abs(e.clientX - drag.x) + Math.abs(e.clientY - drag.y) < 4) return; drag.cap = true; stage.setPointerCapture(e.pointerId); }
    st.cx = drag.cx - (e.clientX - drag.x) * drag.k; st.cy = drag.cy - (e.clientY - drag.y) * drag.k; clampView(); redraw();
  });
  stage.addEventListener('pointerup', () => { drag = null; });
  const foldBtn = h('button', { 'aria-pressed': 'true', style: 'width:auto;padding:0 10px;font-family:var(--mono);font-size:10.5px;letter-spacing:.06em', onClick: () => { st.fold = !st.fold; foldBtn.setAttribute('aria-pressed', String(st.fold)); foldBtn.textContent = st.fold ? 'FOLDED' : 'ALL DOTS'; draw(); } }, 'FOLDED');
  const tools = h('div', { class: 'scene-tools', style: 'align-items:flex-end' }, foldBtn,
    h('button', { 'aria-label': 'Zoom in', onClick: () => zoomAt(st.cx, st.cy, st.zoom * 1.4) }, '+'),
    h('button', { 'aria-label': 'Zoom out', onClick: () => zoomAt(st.cx, st.cy, st.zoom / 1.4) }, '−'),
    h('button', { 'aria-label': 'Reset view', onClick: () => zoomAt(CX, CY, 1) }, '⟲'));

  // ---- left: ranked list ----
  const acctSel = h('select', { 'aria-label': 'Account' }, h('option', { value: '' }, 'All accounts'),
    accts.items.map((a) => h('option', { value: a.id, selected: a.id === account }, a.name)));
  acctSel.addEventListener('change', () => go(acctSel.value ? `#/?account=${acctSel.value}` : '#/'));
  const chipBox = h('div', { class: 'row', style: 'flex-wrap:wrap;gap:6px' });
  const drawChips = () => chipBox.replaceChildren(...FILTERS.map(([key, label, f]) => h('button', { class: 'chip', 'aria-pressed': String(st.filter === key),
    onClick: () => { st.filter = st.filter === key ? null : key; refresh(); } }, label, h('span', { class: 'mono tiny', style: 'opacity:.8' }, ` ${roles.filter(f).length}`))));
  const search = h('input', { type: 'search', placeholder: 'Find a role', 'aria-label': 'Find a role' });
  search.addEventListener('input', () => { st.search = search.value.toLowerCase(); drawList(); });
  const countEl = h('span', { class: 'mono tiny muted' });
  const list = h('div', { class: 'rank-list' });
  function drawList() {
    const fn = fnOf(), lit = litOf(), tagOf = tagsFor();
    const all = ranked.filter((r) => (!fn || fn(r)) && (!st.search || r.name.toLowerCase().includes(st.search)));
    countEl.textContent = fn || st.search ? `${all.length} of ${roles.length}` : String(roles.length);
    list.replaceChildren(...all.slice(0, MAX_ROWS).map((r) => {
      const pct = Math.round(r.never * 100), tag = tagOf.get(r.id) || '', c = ZONES[r.zone].sw;
      const bar = h('span', { class: 'rbar' }, h('i')); bar.firstChild.style.width = `${pct}%`; bar.firstChild.style.background = c;
      const b = h('button', { class: `rank-row${lit(r) || fn ? '' : ' quiet'}`, 'aria-pressed': String(r.id === st.sel), onClick: () => select(r.id, true) },
        h('span', { class: `rtag${tag ? (r.risk === 'High' ? ' hi' : r.unidentified.length ? ' unk' : '') : ' none'}` }, tag || '·'),
        h('span', { class: 'rbody' },
          h('span', { class: 'rname' }, h('span', { class: 'n' }, r.name), r.unidentified.length > 0 && h('span', { class: 'unk-tag' }, 'UNK'), r.denied > 0 && h('span', { class: 'mono tiny', style: 'color:#ff6b5e' }, `×${num(r.denied)}`)),
          h('span', { class: 'rmeta' }, h('span', { class: 'm' }, `${r.account_name} · ${ZONES[r.zone].name}${r.provisional ? ' · provisional' : ''}`), bar, h('span', { class: 'mono', style: `color:${c};width:32px;text-align:right` }, `${pct}%`))));
      return b;
    }), all.length > MAX_ROWS ? h('p', { class: 'tiny muted', style: 'padding:8px' }, `${num(all.length - MAX_ROWS)} more. Narrow with a filter or search.`) : null,
    !all.length ? h('p', { class: 'tiny muted', style: 'padding:8px' }, 'No roles match.') : null);
  }

  // ---- right: locked on ----
  const inspector = h('aside', { class: 'right' });
  let seq = 0;
  async function select(id, center) {
    st.sel = id; st.callers = [];
    const r = byId.get(id);
    if (center && st.zoom > 1) { st.cx = r.x; st.cy = r.y; clampView(); }
    draw(); drawList();
    const my = ++seq;
    inspector.replaceChildren(h('div', { class: 'eyebrow' }, 'LOCKED ON'), h('h2', null, r.name), h('span', { class: 'spin' }));
    const [d, sec] = await Promise.all([get(`/roles/${id}`), get(`/roles/${id}/sector`)]);
    if (my !== seq) return;
    const callers = d.principals.filter((p) => p.kind !== 'session').slice(0, 4);
    st.callers = callers.slice(0, 3).map((p) => ({ name: p.display, kind: p.via || p.kind, ok: !!(p.caller?.trust?.matched) }));
    draw();
    const prov = r.provisional, ge = prov ? '≥ ' : '', le = prov ? '≤ ' : '';
    const tag = tagsFor().get(id);
    const usedBar = h('span', { class: 'bar' }, h('i', { class: 'u' }), h('i', { class: 'c' }));
    usedBar.children[0].style.width = `${Math.max(0.5, (r.used_count / Math.max(r.granted_count, 1)) * 100)}%`; usedBar.children[0].style.minWidth = '3px';
    usedBar.children[1].style.width = `${(r.unconfirmed_count / Math.max(r.granted_count, 1)) * 100}%`;
    const why = [];
    if (r.risk === 'High') why.push([r.calls === 0 ? `Holds ${num(r.granted_count)} permissions and made no calls in the history read.` : `Holds ${num(r.granted_count)} permissions; ${Math.round(r.never * 100)}% never called.`, '#ff8a7a']);
    if (r.unidentified.length) why.push([`${r.unidentified.length} unidentified event name${r.unidentified.length > 1 ? 's' : ''}: those services stay unconfirmed until settled.`, '#f0b45a']);
    if (r.denied) why.push([`${num(r.denied)} denied call${r.denied > 1 ? 's' : ''}: something tried a permission it lacks.`, '#ff8a7a']);
    if (r.granted_count > ADMIN) why.push(['Admin-level grant (AdministratorAccess or similar).', '#ffd89a']);
    if (!why.length) why.push([`Nothing urgent. ${ZONES[r.zone].name} zone.`, '#9fe8c4']);
    const max = Math.max(1, ...sec.used.map((u) => Number(u.event_count)));
    inspector.replaceChildren(
      h('div', { class: 'stack' },
        h('div', { class: 'eyebrow' }, `LOCKED ON · ${tag || 'UNTAGGED'}`),
        h('div', { class: 'row', style: 'align-items:flex-start' }, h('h2', { class: 'grow', style: 'overflow-wrap:anywhere' }, r.name), h('span', { class: `badge ${riskClass(r.risk)}` }, r.risk)),
        h('div', { class: 'tiny muted' }, `${r.account_name} · ${r.aws_account_id} · ${KIND_LABEL[r.kind] || r.kind}`)),
      prov && h('div', { class: 'alert warn' }, h('b', { class: 'mono tiny' }, `PROVISIONAL · ${r.progress}% OF HISTORY READ`), h('br'),
        'Used counts can still go up and “never called” can still go down, so this role cannot be approved yet.'),
      h('div', { class: 'readout' },
        h('div', { class: 'big' }, h('b', null, `${ge}${num(r.used_count)}`), h('span', { class: 'muted' }, `of ${num(r.granted_count)} permissions used`)),
        usedBar,
        h('div', { class: 'split3' },
          h('div', null, h('div', { style: 'color:#f6e016' }, `${ge}${num(r.used_count)}`), h('div', { class: 'muted' }, 'used')),
          h('div', null, h('div', { style: 'color:#f0b45a' }, num(r.unconfirmed_count)), h('div', { class: 'muted' }, 'unconfirmed')),
          h('div', null, h('div', { style: 'color:#8fb5a1' }, `${le}${num(r.unused_count)}`), h('div', { class: 'muted' }, 'never called'))),
        h('div', { class: 'tiny muted' }, 'Zone ', h('b', { style: 'color:var(--ink);font-weight:500' }, ZONES[r.zone].name), ` · ${num(r.calls)} calls stored`)),
      h('section', { class: 'stack' }, h('div', { class: 'eyebrow' }, 'WHY IT IS RANKED HERE'),
        why.map(([text, c]) => { const e = h('div', { class: 'small', style: 'padding:2px 0 2px 10px;line-height:1.45' }, text); e.style.borderLeft = `2px solid ${c}`; return e; })),
      r.unidentified.length > 0 && h('div', { class: 'unk-box' },
        h('div', { class: 'eyebrow', style: 'color:#f0b45a' }, `UNIDENTIFIED CALLS · ${r.unidentified.length}`),
        r.unidentified.slice(0, 4).map((u) => h('a', { class: 'mono tiny', href: `#/roles/${r.id}?identify=${encodeURIComponent(u)}`, style: 'color:#f0b45a' }, u)),
        h('a', { class: 'btn sm amber', href: `#/roles/${r.id}?identify=` }, 'Identify')),
      h('section', { class: 'stack' }, h('div', { class: 'eyebrow' }, 'WHO ENTERED · CONDITIONS MET'),
        callers.length ? callers.map((p) => {
          const t = p.caller?.trust;
          const cond = t?.matched ? (t.conditions.length ? t.conditions.join(' · ') : 'No condition in trust policy') : 'Not matched to a trust statement';
          return h('div', { class: `callerline${t?.matched && t.conditions.length ? '' : ' warn'}` }, h('span', { style: 'overflow-wrap:anywhere' }, p.display),
            h('span', { class: 'tiny muted' }, `${p.via || ''} · ${num(p.sessions_count)} sessions · last ${ago(p.last_seen)}`), h('span', { class: 'cond' }, cond));
        }) : h('p', { class: 'tiny muted' }, 'Nobody seen entering in the history read so far.')),
      sec.used.length > 0 && h('section', { class: 'stack' }, h('div', { class: 'eyebrow' }, prov ? 'ACTIONS CALLED · SO FAR' : 'ACTIONS CALLED'),
        sec.used.slice(0, 5).map((u) => {
          const bar = h('span', { class: 'bar' }, h('i', { class: 'u' })); bar.firstChild.style.width = `${(Number(u.event_count) / max) * 100}%`; bar.style.height = '3px';
          return h('div', { class: 'stack', style: 'gap:3px' }, h('div', { class: 'row' }, h('span', { class: 'mono tiny grow', style: 'overflow-wrap:anywhere' }, u.action), h('span', { class: 'mono tiny muted' }, num(u.event_count))), bar);
        })),
      h('div', { class: 'stack', style: 'margin-top:auto' },
        h('a', { class: 'btn primary', href: `#/roles/${r.id}/scan` }, 'Sector scan'),
        h('div', { class: 'row' }, h('a', { class: 'btn sm grow', href: `#/track?role=${r.id}` }, 'Track a session'), h('a', { class: 'btn sm grow', href: `#/roles/${r.id}` }, 'Role details'))));
  }

  // ---- footer: the estate by zone ----
  const zoneFoot = h('div', { class: 'zone-foot' });
  function drawFoot() {
    const keys = [null, null, 'bloated', 'dead'];
    const bar = h('div', { class: 'zbar' }, ZONES.map((z, i) => {
      const n = roles.filter((r) => r.zone === i).length;
      const b = h('button', { 'aria-label': `${z.name}: ${n} roles${keys[i] ? '. Filter to these.' : ''}`, disabled: !keys[i], onClick: () => { st.filter = st.filter === keys[i] ? null : keys[i]; refresh(); } });
      Object.assign(b.style, { flex: String(Math.max(n, 0.0001)), background: z.sw, opacity: !st.filter || st.filter === keys[i] ? '0.9' : '0.3' }); return b;
    }));
    zoneFoot.replaceChildren(
      h('div', { class: 'zf-l' }, h('div', { class: 'eyebrow' }, 'ESTATE BY ZONE'), h('div', { class: 'tiny muted' }, 'Every role, by how much of what it holds it never calls.')),
      h('div', { class: 'zf-m' }, bar, h('div', { class: 'row tiny muted', style: 'gap:20px;flex-wrap:wrap' }, ZONES.map((z, i) => {
        const sw = h('span', { 'aria-hidden': 'true' }); Object.assign(sw.style, { width: '10px', height: '10px', background: z.sw, display: 'inline-block' });
        return h('span', { class: 'row', style: 'gap:6px' }, sw, h('b', { style: 'color:var(--ink);font-weight:500' }, z.name), `${roles.filter((r) => r.zone === i).length} roles · ${z.range}`);
      }))),
      h('div', { class: 'zf-r' }, h('div', { class: 'eyebrow' }, 'HISTORY'),
        h('div', { class: 'tiny muted' }, slices.every((s) => s.complete) ? `All ${slices.length} account${slices.length > 1 ? 's' : ''} read · results final`
          : `${slices.filter((s) => !s.complete).map((s) => `${s.name} ${s.progress}%`).join(' · ')} · results provisional`),
        h('a', { href: '#/scans', class: 'tiny' }, 'Open scans')));
  }

  function refresh() { drawChips(); drawList(); drawFoot(); draw(); }
  refresh(); select(st.sel);

  const legend = h('div', { class: 'legend' },
    h('span', null, mark('circle'), 'Custom'), h('span', null, mark('square'), 'Identity Center'), h('span', null, mark('diamond'), 'Service-linked'),
    h('span', null, 'Size = permissions granted'), h('span', null, mark('unk'), 'Unidentified calls'), h('span', null, h('b', { style: 'color:#ff6b5e' }, '×'), 'Denied calls'),
    h('span', null, mark('blob'), 'Folded quiet roles (click to zoom)'), provisionalAny && h('span', null, mark('hollow'), 'Provisional'));
  return h('div', { class: 'stack radar-page', style: 'gap:0' },
    h('div', { class: 'scene-layout radar-layout' },
      h('aside', { class: 'left' },
        h('div', { class: 'stack', style: 'gap:10px' },
          h('div', { class: 'row', style: 'justify-content:space-between' }, h('span', { class: 'eyebrow' }, 'CONTACTS · BY PRIORITY'), countEl),
          acctSel, chipBox, search),
        list),
      h('div', { class: 'scene' }, stage, hud, tools, legend),
      inspector),
    zoneFoot);
}

function mark(kind) {
  const s = svg('svg', { width: 12, height: 12, viewBox: '0 0 12 12', 'aria-hidden': 'true' });
  if (kind === 'circle') s.append(svg('circle', { cx: 6, cy: 6, r: 4.5, fill: '#6fe3b0' }));
  if (kind === 'square') s.append(svg('rect', { x: 2, y: 2, width: 8, height: 8, fill: '#6fe3b0' }));
  if (kind === 'diamond') s.append(svg('path', { d: 'M6 0.5L11.5 6L6 11.5L0.5 6Z', fill: '#6fe3b0' }));
  if (kind === 'unk') s.append(svg('circle', { cx: 6, cy: 6, r: 5, fill: 'none', stroke: '#f0b45a', 'stroke-dasharray': '3 2' }));
  if (kind === 'blob') s.append(svg('circle', { cx: 6, cy: 6, r: 5.5, fill: '#0c2a1d', stroke: '#3c7d5f' }));
  if (kind === 'hollow') s.append(svg('circle', { cx: 6, cy: 6, r: 4.5, fill: 'none', stroke: '#6fe3b0', 'stroke-width': 1.5 }));
  return s;
}
const short = (s, n) => (String(s).length > n ? `${String(s).slice(0, n - 1)}…` : String(s));
