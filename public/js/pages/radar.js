// Radar: every role as a contact on a tilted dish.
//   distance from the centre = share of granted permissions never called
//   height above the dish    = call volume
//   bearing                  = kind of role
// Drag to orbit and tilt, scroll to zoom, click a contact to lock on.
import { h, svg, get, num, ago, fmtDate } from '../lib.js';
import { go } from '../main.js';

const KIND_SECTOR = { custom: [0, 210, 'CUSTOM ROLES'], 'identity-center': [210, 290, 'IDENTITY CENTER'], 'service-linked': [290, 360, 'SERVICE-LINKED'] };
const KIND_LABEL = { custom: 'Custom', 'identity-center': 'Identity Center', 'service-linked': 'Service-linked' };
const LAYERS = [['callers', 'Callers'], ['roles', 'Roles'], ['never', 'Never called'], ['denied', 'Denied calls'], ['unknown', 'Unidentified calls'], ['provisional', 'Provisional markers']];
const riskClass = (r) => ({ High: 'b-high', Medium: 'b-medium', Low: 'b-low' })[r] || 'b-neutral';
const clamp = (v, a, b) => Math.max(a, Math.min(b, v));
const r1 = (v) => Math.round(v * 10) / 10;
const short = (s, n = 24) => (s.length > n ? `${s.slice(0, n - 1)}…` : s);

export async function radarPage(ctx) {
  const account = ctx.params.get('account') || '';
  const q = account ? `?account=${account}` : '';
  const [data, signal, accts] = await Promise.all([get(`/radar${q}`), get(`/signal${q}`), get('/accounts')]);
  ctx.setCrumbs('Radar', account ? accts.items.find((a) => a.id === account)?.name || '' : 'All accounts');
  if (!data.roles.length) {
    return h('div', { class: 'stack-lg' }, h('div', { class: 'card empty' }, accts.items.length
      ? 'Roles appear here as soon as the first scan has listed them.' : 'No accounts yet. ', !accts.items.length && h('a', { href: '#/accounts/new' }, 'Connect an AWS account')));
  }

  const roles = data.roles.map((r) => ({ ...r, range: clamp(r.granted_count ? r.unused_count / r.granted_count : 0, 0.08, 0.96) }));
  // bearings: each kind of role gets its own sector, contacts spread evenly inside it
  for (const [kind, [a0, a1]] of Object.entries(KIND_SECTOR)) {
    const list = roles.filter((r) => r.kind === kind).sort((x, y) => x.name.localeCompare(y.name));
    list.forEach((r, i) => { r.bearing = a0 + ((i + 0.5) * (a1 - a0)) / list.length; });
  }
  const byId = new Map(roles.map((r) => [r.id, r]));
  const st = { sel: roles[0].id, off: new Set(), orbit: 20, tilt: 22, zoom: 1, filter: '' };
  const provisionalAny = roles.some((r) => r.provisional);

  // seeded scatter for "never called" so it does not jump between frames
  const chaffFor = (r) => {
    let seed = [...r.id].reduce((a, c) => (a * 31 + c.charCodeAt(0)) % 2147483647, 7) || 7;
    const rnd = () => { seed = (seed * 16807) % 2147483647; return (seed - 1) / 2147483646; };
    const n = Math.round(Math.log10(Math.max(r.unused_count, 0) + 1) * 8);
    return Array.from({ length: n }, () => [r.bearing + (rnd() - 0.5) * 18, clamp(r.range + (rnd() - 0.5) * 0.12, 0.04, 1), 0.25 + rnd() * 0.45]);
  };
  roles.forEach((r) => { r.chaff = chaffFor(r); });

  const stage = svg('svg', { class: 'stage', viewBox: '0 0 800 720', preserveAspectRatio: 'xMidYMid meet', role: 'img', 'aria-label': 'Radar of roles. Distance from the centre is the share of permissions never called; height is call volume.' });
  const hud = h('div', { class: 'hud' });

  function draw() {
    const CX = 400, CY = 410, R = 320 * st.zoom, tilt = (st.tilt * Math.PI) / 180;
    const RY = R * Math.sin(tilt), lift = Math.cos(tilt);
    const plane = (bearing, range) => { const a = ((bearing + st.orbit) * Math.PI) / 180; return [r1(CX + Math.cos(a) * R * range), r1(CY + Math.sin(a) * RY * range)]; };
    const on = (k) => !st.off.has(k);
    const sel = byId.get(st.sel);
    const kids = [];
    kids.push(svg('defs', null,
      svg('filter', { id: 'glow', x: '-50%', y: '-50%', width: '200%', height: '200%' }, svg('feGaussianBlur', { stdDeviation: 3, result: 'b' }),
        svg('feMerge', null, svg('feMergeNode', { in: 'b' }), svg('feMergeNode', { in: 'SourceGraphic' }))),
      svg('radialGradient', { id: 'sweep', cx: 0, cy: 0, r: 1, gradientUnits: 'userSpaceOnUse', gradientTransform: `scale(${R})` },
        svg('stop', { offset: 0, 'stop-color': '#f6e016', 'stop-opacity': 0.22 }), svg('stop', { offset: 1, 'stop-color': '#f6e016', 'stop-opacity': 0.03 }))));
    kids.push(svg('ellipse', { cx: CX, cy: CY, rx: r1(R * 1.04), ry: r1(RY * 1.04 + 1), fill: '#051209', stroke: '#1f4a35' }));
    for (const f of [0.25, 0.5, 0.75, 1]) {
      kids.push(svg('ellipse', { cx: CX, cy: CY, rx: r1(R * f), ry: r1(RY * f + 0.5), fill: 'none', stroke: '#16392a', 'stroke-dasharray': f === 1 ? null : '3 5' }));
      kids.push(svg('text', { x: CX + 6, y: r1(CY - RY * f - 4), fill: '#7e978a', 'font-family': 'Geist Mono, monospace', 'font-size': 10 }, `${f * 100}%`));
    }
    for (let d = 0; d < 360; d += 30) { const [x, y] = plane(d, 1.03); kids.push(svg('path', { d: `M${CX} ${CY} L${x} ${y}`, stroke: '#16392a' })); }
    for (const [kind, [a0, a1, label]] of Object.entries(KIND_SECTOR)) {
      if (!roles.some((r) => r.kind === kind)) continue;
      const [x, y] = plane((a0 + a1) / 2, 1.13);
      kids.push(svg('text', { x, y: y + 4, 'text-anchor': 'middle', fill: '#a9bfb2', 'font-family': 'Geist Mono, monospace', 'font-size': 10, 'letter-spacing': 1 }, label));
    }
    // the sweep turns on the dish
    kids.push(svg('g', { transform: `translate(${CX} ${CY}) scale(1 ${r1(Math.max(RY, 1) / R * 1000) / 1000})` },
      svg('g', null, svg('path', { d: `M0 0 L${R} 0 A${R} ${R} 0 0 0 ${r1(R * 0.866)} ${r1(-R * 0.5)} Z`, fill: 'url(#sweep)' }),
        svg('path', { d: `M0 0 L${R} 0`, stroke: '#f6e016', 'stroke-opacity': 0.8, 'stroke-width': 2.4 }),
        matchMedia('(prefers-reduced-motion: reduce)').matches ? null : svg('animateTransform', { attributeName: 'transform', type: 'rotate', from: '0', to: '360', dur: '7s', repeatCount: 'indefinite' }))));

    const pos = new Map();
    const labels = [];
    for (const r of roles) {
      const [px, py] = plane(r.bearing, r.range);
      const height = (28 + Math.log10(r.calls + 1) * 30) * lift * st.zoom;
      pos.set(r.id, { px, py, x: px, y: r1(py - height) });
      if (on('never')) for (const [b, rg, o] of r.chaff) { const [x, y] = plane(b, rg); kids.push(svg('circle', { cx: x, cy: y, r: 1.3, fill: '#5f8c73', opacity: r1(o * 100) / 100 })); }
    }
    if (on('callers') && on('roles')) {
      data.callers.forEach((c, i) => {
        const targets = c.roles.map((id) => pos.get(id)).filter(Boolean);
        if (!targets.length) return;
        const mean = c.roles.map((id) => byId.get(id)?.bearing).filter((b) => b != null);
        const b = mean.reduce((a, x) => a + x, 0) / mean.length + ((i % 5) - 2) * 6;
        const [cx, cyp] = plane(b, 1.07); const cy = r1(cyp - 8);
        c.at = [cx, cy, b];
        for (const t of targets) {
          const hot = c.roles.includes(st.sel);
          kids.push(svg('path', { d: `M${cx} ${cy} Q${r1((cx + t.x) / 2)} ${r1(Math.min(cy, t.y) - 60 * st.zoom)} ${t.x} ${t.y}`, fill: 'none', stroke: '#6fe3b0', 'stroke-width': hot ? 1.6 : 1, opacity: hot ? 0.9 : 0.25, class: hot ? 'live' : null }));
        }
      });
    }
    for (const r of roles) {
      if (!on('roles')) break;
      const p = pos.get(r.id); const isSel = r.id === st.sel; const ring = isSel ? '#f6e016' : '#6fe3b0';
      const g = svg('g', { style: 'cursor:pointer', onClick: (e) => { e.stopPropagation(); select(r.id); }, onDblclick: () => go(`#/roles/${r.id}/scan`) });
      g.append(svg('ellipse', { cx: p.px, cy: p.py, rx: 9, ry: 3.2, fill: ring, opacity: 0.35 }),
        svg('path', { d: `M${p.px} ${p.py} L${p.x} ${p.y + 6}`, stroke: ring, 'stroke-dasharray': r.provisional ? '2 3' : null, opacity: 0.8 }));
      if (r.provisional && on('provisional')) { const [ix, iy] = plane(r.bearing, Math.max(0.04, r.range - 0.22)); g.append(svg('path', { d: `M${p.px} ${p.py} L${ix} ${iy}`, stroke: '#f6e016', 'stroke-dasharray': '2 3', opacity: 0.8 })); }
      g.append(svg('circle', { cx: p.x, cy: p.y, r: isSel ? 17 : 10, fill: 'none', stroke: ring, opacity: isSel ? 1 : 0.35 }),
        svg('circle', { cx: p.x, cy: p.y, r: r1(4.5 + Math.log10(r.calls + 1) * 1.2), fill: r.provisional ? '#030d08' : '#6fe3b0', stroke: '#6fe3b0', 'stroke-width': 1.5, filter: 'url(#glow)' }));
      const right = p.x >= 400;
      labels.push({ pri: isSel ? 0 : r.risk === 'High' ? 1 : r.unidentified.length ? 2 : 3 + 1 / (r.calls + 1), x: right ? p.x + 16 : p.x - 16, y: p.y, right, g,
        a: short(r.name.replace(/^AWSReservedSSO_/, 'SSO_')), b: `${Math.round(r.range * 100)}% never called${r.provisional ? ' · provisional' : ''}`, hot: isSel, mono: true });
      if (on('unknown') && r.unidentified.length) {
        g.append(svg('circle', { cx: p.x - 20, cy: p.y + 16, r: 7, fill: '#030d08', stroke: '#f0b45a', 'stroke-width': 1.4, 'stroke-dasharray': '3 2', class: 'blink' }),
          svg('text', { x: p.x - 20, y: p.y + 19, 'text-anchor': 'middle', fill: '#f0b45a', 'font-family': 'Geist Mono, monospace', 'font-size': 7, 'font-weight': 600 }, '?'));
      }
      if (on('denied') && r.denied > 0) {
        for (let i = 0; i < Math.min(3, Math.ceil(Math.log10(r.denied + 1))); i++) {
          const dx = p.x + 18 + i * 9, dy = p.y + 14;
          g.append(svg('path', { d: `M${dx - 4} ${dy - 4} L${dx + 4} ${dy + 4} M${dx + 4} ${dy - 4} L${dx - 4} ${dy + 4}`, stroke: '#ff6b5e', 'stroke-width': 1.8, class: 'blink' }));
        }
      }
      kids.push(g);
    }
    if (on('callers')) for (const c of data.callers) {
      if (!c.at) continue;
      const [x, y] = c.at; const left = x < 400;
      kids.push(svg('path', { d: `M${x} ${y - 5} L${x + 5} ${y} L${x} ${y + 5} L${x - 5} ${y} Z`, fill: '#e3efe8' }));
      labels.push({ pri: c.roles.includes(st.sel) ? 0.5 : 5, x: left ? x - 10 : x + 10, y, right: !left, a: short(c.display || c.key, 22), b: c.kind, caller: true });
    }
    // place labels in priority order, skipping any that would overlap one already placed
    const placed = [];
    for (const l of labels.sort((a, b) => a.pri - b.pri)) {
      const w = Math.max(l.a.length * 6.7, l.b.length * 5.6) + 4;
      let x0 = l.right ? l.x : l.x - w;
      if (x0 < 2 || x0 + w > 798) { l.right = !l.right; l.x = l.right ? l.x + 32 : l.x - 32; x0 = l.right ? l.x : l.x - w; }   // flip to the other side
      const box = [x0, l.y - 12, x0 + w, l.y + 14];
      if (box[0] < 2 || box[2] > 798) continue;
      if (l.pri >= 1 && placed.some((q) => box[0] < q[2] && box[2] > q[0] && box[1] < q[3] && box[3] > q[1])) continue;
      placed.push(box);
      const anchor = l.right ? 'start' : 'end';
      const t1 = svg('text', { x: l.x, y: l.y - 2, 'text-anchor': anchor, fill: l.hot ? '#f6e016' : '#e3efe8', 'font-family': 'Geist Mono, monospace', 'font-size': l.caller ? 10.5 : 11, 'pointer-events': 'none' }, l.a);
      const t2 = svg('text', { x: l.x, y: l.y + 11, 'text-anchor': anchor, fill: '#7e978a', 'font-family': l.caller ? 'Geist, sans-serif' : 'Geist Mono, monospace', 'font-size': 9.5, 'pointer-events': 'none' }, l.b);
      const bg = svg('rect', { x: r1(x0), y: l.y - 12, width: r1(w), height: 26, fill: '#030d08', opacity: 0.72, 'pointer-events': 'none' });
      kids.push(bg, t1, t2);
    }
    stage.replaceChildren(...kids);
    const events = signal.days.reduce((a, d) => a + d.calls + d.denied, 0);
    hud.replaceChildren(
      h('div', { class: 'hot' }, `● RADAR${provisionalAny ? ' · FILLING IN' : ''}`),
      h('div', null, `${num(events)} CALLS STORED · ${roles.length} ROLES · ${data.callers.length} CALLERS`),
      h('div', null, `ORBIT ${Math.round(((st.orbit % 360) + 360) % 360)}° · TILT ${Math.round(st.tilt)}° · ZOOM ${st.zoom.toFixed(1)}×`));
    drawContacts();
  }

  // ---- interaction: drag to orbit and tilt, wheel to zoom ----
  let drag = null, frame = 0;
  const redraw = () => { if (!frame) frame = requestAnimationFrame(() => { frame = 0; draw(); }); };
  stage.addEventListener('pointerdown', (e) => { drag = { x: e.clientX, y: e.clientY, orbit: st.orbit, tilt: st.tilt, moved: false }; stage.setPointerCapture(e.pointerId); });
  stage.addEventListener('pointermove', (e) => {
    if (!drag) return;
    const dx = e.clientX - drag.x, dy = e.clientY - drag.y;
    if (Math.abs(dx) + Math.abs(dy) > 3) drag.moved = true;
    st.orbit = drag.orbit + dx * 0.4; st.tilt = clamp(drag.tilt - dy * 0.25, 10, 88); redraw();
  });
  stage.addEventListener('pointerup', () => { drag = null; });
  stage.addEventListener('wheel', (e) => { e.preventDefault(); st.zoom = clamp(st.zoom * (e.deltaY > 0 ? 0.92 : 1.08), 0.6, 2.2); redraw(); }, { passive: false });

  const tools = h('div', { class: 'scene-tools' },
    h('button', { 'aria-label': 'Zoom in', onClick: () => { st.zoom = clamp(st.zoom * 1.15, 0.6, 2.2); draw(); } }, '+'),
    h('button', { 'aria-label': 'Zoom out', onClick: () => { st.zoom = clamp(st.zoom / 1.15, 0.6, 2.2); draw(); } }, '−'),
    h('button', { 'aria-label': 'Top-down view', onClick: () => { st.tilt = st.tilt > 80 ? 22 : 88; draw(); } }, '2D'),
    h('button', { 'aria-label': 'Reset camera', onClick: () => { Object.assign(st, { orbit: 20, tilt: 22, zoom: 1 }); draw(); } }, '⟲'));

  // ---- left: account, layers, contacts ----
  const acctSel = h('select', { 'aria-label': 'Account' }, h('option', { value: '' }, 'All accounts'),
    accts.items.map((a) => h('option', { value: a.id, selected: a.id === account }, a.name)));
  acctSel.addEventListener('change', () => go(acctSel.value ? `#/?account=${acctSel.value}` : '#/'));
  const layerBox = h('div', { class: 'stack', style: null });
  const drawLayers = () => layerBox.replaceChildren(...LAYERS.map(([k, label]) => h('button', {
    class: 'layer', 'aria-pressed': String(!st.off.has(k)), onClick: () => { st.off.has(k) ? st.off.delete(k) : st.off.add(k); drawLayers(); draw(); } }, label,
    h('span', { class: 'n' }, k === 'roles' ? roles.length : k === 'callers' ? data.callers.length : k === 'never' ? num(roles.reduce((a, r) => a + r.unused_count, 0))
      : k === 'denied' ? num(roles.reduce((a, r) => a + r.denied, 0)) : k === 'unknown' ? roles.filter((r) => r.unidentified.length).length : provisionalAny ? 'on' : '–'))));
  drawLayers();
  const search = h('input', { type: 'search', placeholder: 'Find a role', 'aria-label': 'Find a role' });
  search.addEventListener('input', () => { st.filter = search.value.toLowerCase(); drawContacts(); });
  const contacts = h('div', { class: 'stack', style: null });
  function drawContacts() {
    const list = roles.filter((r) => !st.filter || r.name.toLowerCase().includes(st.filter)).sort((a, b) => b.range - a.range).slice(0, 80);
    contacts.replaceChildren(...list.map((r) => {
      const b = h('button', { class: 'contact', 'aria-pressed': String(r.id === st.sel), onClick: () => select(r.id) },
        h('span', { class: 'top', title: `${r.name} · ${r.account_name}` }, h('span', null, r.name), h('span', { class: 'mono tiny', style: null }, `${Math.round(r.range * 100)}%`)),
        h('span', { class: 'tiny muted' }, r.account_name), h('span', { class: 'bar' }, h('i', { class: 'c' })));
      const bar = b.querySelector('i'); bar.style.width = `${r.range * 100}%`; bar.style.background = r.range > 0.9 ? '#ff6b5e' : r.range > 0.5 ? '#f0b45a' : '#6fe3b0';
      return b;
    }));
  }

  // ---- right: locked on ----
  const inspector = h('aside', { class: 'right' });
  let seq = 0;
  async function select(id) {
    st.sel = id; draw();
    const my = ++seq; const r = byId.get(id);
    inspector.replaceChildren(h('div', { class: 'eyebrow' }, 'LOCKED ON'), h('h2', null, r.name), h('span', { class: 'spin' }));
    const [d, sec] = await Promise.all([get(`/roles/${id}`), get(`/roles/${id}/sector`)]);
    if (my !== seq) return;
    const prov = r.provisional, ge = prov ? '≥ ' : '', le = prov ? '≤ ' : '';
    const callers = d.principals.filter((p) => p.kind !== 'session').slice(0, 4);
    const usedBar = h('span', { class: 'bar', style: null }, h('i', { class: 'u' }), h('i', { class: 'c' }));
    usedBar.children[0].style.width = `${Math.max(1, (r.used_count / Math.max(r.granted_count, 1)) * 100)}%`; usedBar.children[0].style.minWidth = '3px';
    usedBar.children[1].style.width = `${(r.unconfirmed_count / Math.max(r.granted_count, 1)) * 100}%`;
    const max = Math.max(1, ...sec.used.map((u) => Number(u.event_count)));
    inspector.replaceChildren(
      h('div', { class: 'stack', style: null },
        h('div', { class: 'eyebrow' }, 'LOCKED ON'),
        h('div', { class: 'row' }, h('h2', { style: null }, r.name), h('span', { class: `badge ${riskClass(r.risk)}` }, r.risk)),
        h('div', { class: 'tiny muted' }, `${r.account_name} · ${r.aws_account_id} · ${KIND_LABEL[r.kind]}`)),
      prov && h('div', { class: 'alert warn' }, h('b', { class: 'mono tiny' }, `PROVISIONAL · ${r.progress}% OF HISTORY READ`), h('br'),
        'Used counts can still go up and “never called” can still go down, so this role cannot be approved yet.'),
      h('div', { class: 'readout' },
        h('div', { class: 'big' }, h('b', null, `${ge}${num(r.used_count)}`), h('span', { class: 'muted' }, `of ${num(r.granted_count)} permissions used`)),
        usedBar,
        h('div', { class: 'split3' },
          h('div', null, h('div', { style: 'color:#f6e016' }, `${ge}${num(r.used_count)}`), h('div', { class: 'muted' }, 'used')),
          h('div', null, h('div', { style: 'color:#f0b45a' }, num(r.unconfirmed_count)), h('div', { class: 'muted' }, 'unconfirmed')),
          h('div', null, h('div', { style: 'color:#8fb5a1' }, `${le}${num(r.unused_count)}`), h('div', { class: 'muted' }, 'never called')))),
      r.unidentified.length > 0 && h('div', { class: 'unk-box' },
        h('div', { class: 'eyebrow', style: 'color:#f0b45a' }, `UNIDENTIFIED CALLS · ${r.unidentified.length}`),
        r.unidentified.slice(0, 4).map((u) => h('a', { class: 'mono tiny', href: `#/roles/${r.id}?identify=${encodeURIComponent(u)}`, style: 'color:#f0b45a' }, `Identify ${u}`))),
      h('section', { class: 'stack', style: null }, h('div', { class: 'eyebrow' }, 'WHO ENTERED · CONDITIONS MET'),
        callers.length ? callers.map((p) => {
          const t = p.caller?.trust;
          const cond = t?.matched ? (t.conditions.length ? t.conditions.join(' · ') : 'No condition in trust policy') : 'Not matched to a trust statement';
          return h('div', { class: `callerline${t?.matched && t.conditions.length ? '' : ' warn'}` }, h('span', null, p.display),
            h('span', { class: 'tiny muted' }, `${p.via || ''} · ${num(p.sessions_count)} sessions · last ${ago(p.last_seen)}`), h('span', { class: 'cond' }, cond));
        }) : h('p', { class: 'tiny muted' }, 'Nobody seen entering in the history read so far.')),
      h('section', { class: 'stack', style: null }, h('div', { class: 'eyebrow' }, prov ? 'ACTIONS CALLED · SO FAR' : 'ACTIONS CALLED'),
        sec.used.length ? sec.used.slice(0, 6).map((u) => {
          const bar = h('span', { class: 'bar', style: null }, h('i', { class: 'u' })); bar.firstChild.style.width = `${(Number(u.event_count) / max) * 100}%`; bar.style.height = '3px';
          return h('div', { class: 'stack', style: null }, h('div', { class: 'row', style: null }, h('span', { class: 'mono tiny grow' }, u.action), h('span', { class: 'mono tiny muted' }, num(u.event_count))), bar);
        }) : h('p', { class: 'tiny muted' }, 'None yet.')),
      h('div', { class: 'stack', style: 'margin-top:auto' },
        h('a', { class: 'btn primary', href: `#/roles/${r.id}/scan` }, 'Sector scan'),
        h('div', { class: 'row' }, h('a', { class: 'btn sm grow', href: `#/track?role=${r.id}` }, 'Track a session'), h('a', { class: 'btn sm grow', href: `#/roles/${r.id}` }, 'Role details'))));
  }

  // ---- bottom: signal ----
  const sig = signalStrip(signal);
  draw(); drawContacts(); select(st.sel);
  return h('div', { class: 'stack', style: 'gap:0;min-height:calc(100vh - 52px)' },
    h('div', { class: 'scene-layout' },
      h('aside', { class: 'left' }, h('div', { class: 'stack', style: null }, h('div', { class: 'eyebrow' }, 'ACCOUNT'), acctSel),
        h('div', { class: 'stack', style: null }, h('div', { class: 'eyebrow' }, 'LAYERS'), layerBox),
        h('div', { class: 'stack', style: null }, h('div', { class: 'eyebrow' }, 'CONTACTS · RANGE = NEVER CALLED'), search, contacts)),
      h('div', { class: 'scene' }, stage, hud, tools,
        h('div', { class: 'legend' },
          h('span', null, legendMark('diamond'), 'Caller'), h('span', null, legendMark('dot', '#6fe3b0'), 'Role'), h('span', null, legendMark('ring', '#6fe3b0'), 'Role, provisional'),
          h('span', null, legendMark('dash', '#f6e016'), 'May move inward as history arrives'), h('span', null, legendMark('dot', '#5f8c73', 6), 'Never called'),
          h('span', null, h('b', { style: 'color:#ff6b5e' }, '×'), 'Denied'), h('span', null, legendMark('ring', '#f0b45a', 10, true), 'Unidentified calls')),
        h('div', { class: 'hint-br' }, 'Drag to orbit · scroll to zoom · double-click to open its sector scan')),
      inspector),
    sig);
}

function legendMark(kind, color = '#e3efe8', size = 10, dashed = false) {
  const s = h('span', { 'aria-hidden': 'true' });
  Object.assign(s.style, { display: 'inline-block', width: `${size}px`, height: `${size}px`, boxSizing: 'border-box' });
  if (kind === 'diamond') Object.assign(s.style, { width: '8px', height: '8px', transform: 'rotate(45deg)', background: color });
  if (kind === 'dot') Object.assign(s.style, { borderRadius: '50%', background: color });
  if (kind === 'ring') Object.assign(s.style, { borderRadius: '50%', border: `1.5px ${dashed ? 'dashed' : 'solid'} ${color}` });
  if (kind === 'dash') Object.assign(s.style, { width: '14px', height: '0', borderTop: `1px dashed ${color}` });
  return s;
}

/** Calls per day, with the part of history not read yet hatched. */
export function signalStrip(signal) {
  const from = new Date(signal.from).getTime(), to = new Date(signal.to).getTime(), span = Math.max(to - from, 1);
  const X = (t) => r1(((t - from) / span) * 1000);
  const max = Math.max(1, ...signal.days.map((d) => d.calls));
  const pts = signal.days.map((d) => `${X(new Date(d.day).getTime() + 432e5)},${r1(74 - (d.calls / max) * 64)}`).join(' ');
  const unreadX = signal.readUpTo ? X(new Date(signal.readUpTo).getTime()) : null;
  const ticks = signal.days.filter((d) => d.denied > 0).map((d) => { const x = X(new Date(d.day).getTime() + 432e5); return svg('path', { d: `M${x} 62 L${x} 76`, stroke: '#ff6b5e', 'stroke-width': 2, 'vector-effect': 'non-scaling-stroke' }); });
  const label = (t) => new Date(t).toLocaleDateString('en-GB', { day: '2-digit', month: 'short' }).toUpperCase();
  return h('div', { class: 'signal' },
    h('div', null, h('div', { class: 'eyebrow' }, 'SIGNAL'), h('div', { class: 'tiny muted' }, 'Calls per day across the roles shown.'),
      h('div', { class: 'mono tiny' }, signal.complete ? 'History complete' : `Read up to ${signal.readUpTo ? fmtDate(signal.readUpTo) : '…'}`)),
    h('div', null,
      h('div', { class: 'row tiny muted', style: 'justify-content:space-between' }, h('span', null, 'Calls per day'),
        h('span', { class: 'mono' }, h('span', { style: 'color:#6fe3b0' }, '━ '), 'read  ', h('span', { style: 'color:#ff6b5e' }, '| '), 'denied  ', !signal.complete && [h('span', { style: 'color:#f6e016' }, '▨ '), 'not read yet'])),
      svg('svg', { viewBox: '0 0 1000 80', preserveAspectRatio: 'none', role: 'img', 'aria-label': 'Calls per day over the stored history' },
        svg('defs', null, svg('pattern', { id: 'hatch', width: 8, height: 8, patternUnits: 'userSpaceOnUse', patternTransform: 'rotate(45)' }, svg('rect', { width: 2, height: 8, fill: '#f6e016', 'fill-opacity': 0.18 }))),
        svg('path', { d: 'M0 79 H1000', stroke: '#143425' }),
        pts && svg('polyline', { points: pts, fill: 'none', stroke: '#6fe3b0', 'stroke-width': 1.2, 'vector-effect': 'non-scaling-stroke' }), ...ticks,
        unreadX != null && svg('rect', { x: unreadX, y: 0, width: r1(1000 - unreadX), height: 80, fill: 'url(#hatch)' }),
        unreadX != null && svg('rect', { x: unreadX, y: 0, width: 1.5, height: 80, fill: '#f6e016' })),
      h('div', { class: 'row mono tiny faint', style: 'justify-content:space-between' }, [0, 1 / 3, 2 / 3, 1].map((f) => h('span', null, label(from + span * f))))),
    h('div', null, h('div', { class: 'eyebrow' }, 'READING NOW'), h('div', { class: 'tiny muted' }, signal.complete ? 'Up to date.' : 'History is still being read; the hatched part fills in as it arrives.'),
      h('a', { href: '#/scans', class: 'tiny' }, 'Open scans')));
}
