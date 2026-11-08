// Space: the estate as a tilted plane, replayed by the hour.
//   Estate       — the plane is the organization, split into zones by environment. Each account is a ring with one star
//                  per busy role: higher and brighter = more calls in 7 days. Roles with no recorded call lie grey on the
//                  floor, and the dashed grey part of each ring is that share. Identities outside the org that trust
//                  policies let in float off the plane: close and low = the worst trust, far and high = trust that is
//                  pinned. Role chaining between accounts arcs above the plane and lights up in the hours it happened.
//   One account  — services the account calls stand as towers at the centre; roles cluster around the service they
//                  call most; neighbouring accounts sit just past the edge; cold roles ring the floor.
// The bar under the scene picks the hour (the last 24, in WIB); play steps through them.
import { h, svg, get, num, ago } from '../lib.js';
import { go } from '../main.js';

const W = 1000, H = 900;
// one colour per environment, checked together with every pair compared (colour-blind ΔE ≥ 10, normal vision ≥ 18).
// base = rings, paths, swatches; hot/dim = the brightest and faintest stars. Red is never an environment.
const ENV = {
  production: { name: 'Production', base: '#c68405', dim: '#8a5d0a', hot: '#ffd27f' },
  staging: { name: 'Staging', base: '#4b95f0', dim: '#3a6db0', hot: '#b3d4ff' },
  development: { name: 'Development', base: '#37ac78', dim: '#2a7f59', hot: '#a6ecc8' },
  sandbox: { name: 'Sandbox', base: '#a947a3', dim: '#7c3878', hot: '#f2b0ec' },
};
const ORDER = ['production', 'staging', 'development', 'sandbox'];   // east to west across the plane
const RED = '#ff5a4f', WARN = '#fab219', COLD = '#7a8780', OUT = '#c3cbd9';
const TONE = { high: RED, warn: WARN, info: '#ffffff', good: '#6fe3b0', medium: WARN, low: '#d5dceb' };
const KIND = { 'new-caller': 'NEW CALLER', denied: '⚠ DENIED', grew: 'GREW', unidentified: 'UNIDENTIFIED', 'new-role': 'NEW ROLE', dead: 'COLD', cleaned: 'CLEANED', 'new-path': 'NEW PATH' };
const GLYPH = { oidc: 'oidc', saml: 'saml', 'external-account': 'account', public: 'web' };

const f = (n) => Math.round(n * 10) / 10;
const o2 = (n) => Math.round(n * 100) / 100;
const kfmt = (n) => (n >= 1e6 ? `${(n / 1e6).toFixed(1)}M` : n >= 1e4 ? `${Math.round(n / 1e3)}k` : num(Math.round(n)));
const still = () => matchMedia('(prefers-reduced-motion: reduce)').matches;
const lg = (n) => Math.log10(n + 1);
function rng(seed) { let a = seed >>> 0; return () => { a = (a + 0x6D2B79F5) | 0; let t = Math.imul(a ^ (a >>> 15), 1 | a); t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t; return ((t ^ (t >>> 14)) >>> 0) / 4294967296; }; }
const hash = (s) => { let x = 2166136261; for (const c of String(s)) x = Math.imul(x ^ c.charCodeAt(0), 16777619); return x >>> 0; };
const edgeDist = (a) => Math.min(560 / Math.max(1e-6, Math.abs(Math.cos(a))), 380 / Math.max(1e-6, Math.abs(Math.sin(a))));
const off = (deg, gap, z) => { const a = (deg * Math.PI) / 180, r = edgeDist(a) + gap; return { x: Math.cos(a) * r, y: Math.sin(a) * r, z }; };
// how close an outside identity sits says how worrying its trust is
const PLACE = { high: [55, 40], medium: [95, 90], low: [160, 180], info: [175, 210], none: [175, 210] };

function glyph(kind, x, y, s) {
  const ring = (n, rot) => Array.from({ length: n }, (_, i) => { const a = rot + (i / n) * Math.PI * 2; return `${f(x + Math.cos(a) * s)} ${f(y + Math.sin(a) * s)}`; });
  if (kind === 'oidc') return `M${ring(6, 0).join(' L')} Z`;
  if (kind === 'saml') return `M${ring(4, -Math.PI / 2).join(' L')} Z`;
  if (kind === 'web') return `M${ring(3, -Math.PI / 2).join(' L')} Z`;
  if (kind === 'service') return `M${ring(6, Math.PI / 6).join(' L')} Z`;
  return `M${f(x - s)} ${f(y)} a${f(s)} ${f(s)} 0 1 0 ${f(2 * s)} 0 a${f(s)} ${f(s)} 0 1 0 ${f(-2 * s)} 0 Z`;
}
function ctrl3(a, b, side, lift) {
  const dx = b[0] - a[0], dy = b[1] - a[1], dist = Math.hypot(dx, dy) || 1, A = lift != null ? lift : 46 + 0.24 * dist, o = side * 0.09 * dist;
  return [(a[0] + b[0]) / 2 - (dy / dist) * o, (a[1] + b[1]) / 2 + (dx / dist) * o, (a[2] + b[2]) / 2 + 2 * A];
}
const apex3 = (a, b, side, lift) => { const c = ctrl3(a, b, side, lift); return [0, 1, 2].map((i) => 0.25 * a[i] + 0.5 * c[i] + 0.25 * b[i]); };
function arc3(a, b, side, P, lift) {
  const c = ctrl3(a, b, side, lift), pts = [];
  for (let i = 0; i <= 24; i++) { const t = i / 24, u = 1 - t; pts.push(P(u * u * a[0] + 2 * u * t * c[0] + t * t * b[0], u * u * a[1] + 2 * u * t * c[1] + t * t * b[1], u * u * a[2] + 2 * u * t * c[2] + t * t * b[2])); }
  const d = (n) => `M${pts.slice(0, n + 1).map((p) => `${f(p[0])} ${f(p[1])}`).join(' L')}`;
  return { pts, d: d(24), part: (t) => d(Math.round(t * 24)) };
}
// role stars on a phyllotaxis spiral: busiest at the core, cold ones on the rim, on the floor
function cloud(cx, cy, R, active, cold, seed) {
  const r = rng(seed), o = r() * Math.PI * 2, n = active.length + cold;
  return [...active.map((s, i) => ({ ...s, cold: false })), ...Array.from({ length: cold }, () => ({ cold: true, calls7: 0 }))].map((s, i) => {
    const rad = R * 0.9 * Math.sqrt((i + 0.6) / Math.max(1, n)), a = o + i * 2.39996;
    return { ...s, x: cx + Math.cos(a) * rad, y: cy + Math.sin(a) * rad, z: s.cold ? 0 : 14 + 24 * lg(s.calls7) };
  });
}

// ---------- the estate: zones by environment, accounts on a grid inside each ----------
function estateModel(d) {
  const envs = ORDER.filter((e) => d.accounts.some((a) => a.environment === e));
  const weight = (e) => Math.max(1, d.accounts.filter((a) => a.environment === e).length) ** 0.75;
  const totalW = envs.reduce((s, e) => s + weight(e), 0);
  let x1 = 560;
  const zones = [], groups = [];
  for (const env of envs) {
    const w = (1120 * weight(env)) / totalW, x0 = x1 - w, list = d.accounts.filter((a) => a.environment === env);
    zones.push({ id: env, x0, x1, y0: -380, y1: 380 });
    const cols = Math.max(1, Math.round(Math.sqrt((list.length * w) / 760))), rows = Math.ceil(list.length / cols), cw = w / cols, ch = 760 / rows;
    list.forEach((a, i) => {
      const cx = x0 + cw * (i % cols + 0.5), cy = 380 - ch * (Math.floor(i / cols) + 0.5);
      const R = Math.max(14, Math.min(18 + Math.sqrt(a.roles) * 5.5, 0.4 * Math.min(cw, ch)));
      const coldDots = Math.min(a.cold, 16);
      groups.push({ ...a, env, x: cx, y: cy, R, coldShare: a.roles ? a.cold / a.roles : 0, label: a.name,
        prof: a.hourly.map((b) => b.calls), stars: cloud(cx, cy, R, a.stars, coldDots, hash(a.id)) });
    });
    x1 = x0;
  }
  const by = new Map(groups.map((g) => [g.id, g]));
  const sources = d.outside.items.map((s, i, all) => {
    const deg = all.length === 1 ? 90 : 18 + (144 * i) / (all.length - 1), [gap, z] = PLACE[s.worst] || PLACE.none;
    return { ...s, id: `src:${s.key}`, kind: GLYPH[s.group] || 'account', risk: s.worst, ...off(deg, gap, z) };
  });
  const links = [];
  for (const c of d.chains) if (by.has(c.from) && by.has(c.to)) links.push({ from: c.from, to: c.to, kind: c.isNew ? 'new' : 'chain', vol: Math.min(3, 1 + lg(c.sessions)), at: c.hours, sessions: c.sessions, denied: c.denied });
  for (const s of sources) for (const t of s.targets) if (by.has(t.accountId)) links.push({ from: s.id, to: t.accountId, kind: s.worst === 'high' ? 'extHigh' : s.worst === 'medium' ? 'extWarn' : 'ext', vol: 1, at: null });
  const name = (id) => by.get(id)?.name || 'an account';
  const events = [
    ...d.events.map((e) => ({ id: e.id, kind: KIND[e.kind] || e.kind.toUpperCase(), tone: e.severity, hour: e.hour, text: e.title, where: `${name(e.accountId)}${e.roleName ? ` · ${e.roleName}` : ''}`, target: e.accountId })),
    ...d.chains.filter((c) => c.isNew && by.has(c.from) && by.has(c.to)).map((c) => ({ id: `n${c.from}${c.to}`, kind: 'NEW PATH', tone: 'info', hour: c.hours[0] ?? 23, text: `${name(c.from)} chained into ${name(c.to)} for the first time`, where: `${c.sessions} session${c.sessions === 1 ? '' : 's'} today`, target: c.to })),
  ].sort((a, b) => b.hour - a.hour);
  return { view: 'estate', zones, groups, by, sources, hidden: d.outside.hidden, links, events, hourStart: new Date(d.hourStart).getTime(),
    defaultSel: events[0]?.target || [...groups].sort((a, b) => b.calls7 - a.calls7)[0]?.id || null };
}

// ---------- one account: services at the core, roles clustered round the service they call most ----------
function accountModel(d) {
  const env = d.account.environment;
  const towers = d.services.map((s, i, all) => { const a = (i / Math.max(1, all.length)) * Math.PI * 2 + 0.4; return { ...s, id: `svc:${s.name}`, x: Math.cos(a) * 132, y: Math.sin(a) * 104, h: 26 + 22 * lg(s.calls) }; });
  const tower = new Map(towers.map((t) => [t.name, t]));
  const groups = d.clusters.map((c, i, all) => {
    const deg = 150 - (360 * i) / Math.max(1, all.length), x = Math.cos((deg * Math.PI) / 180) * 345, y = Math.sin((deg * Math.PI) / 180) * 252;
    const roles = c.roles.map((r) => ({ ...r }));
    [...roles].sort((m, n) => n.calls7 - m.calls7).forEach((r, k, arr) => { const rad = 58 * Math.sqrt((k + 0.5) / arr.length), a = 0.7 + k * 2.39996; Object.assign(r, { x: x + Math.cos(a) * rad, y: y + Math.sin(a) * rad, z: 14 + 24 * lg(r.calls7), cold: false }); });
    const prof = Array.from({ length: 24 }, (_, hr) => roles.reduce((s, r) => s + r.hourly[hr], 0));
    return { id: `cl:${c.key}`, key: c.key, env, label: c.key === 'other' ? 'Other services' : c.key === 'quiet this week' ? 'Quiet this week' : `Mostly ${c.key}`, x, y, R: 72, roles, stars: roles, more: c.more,
      calls7: roles.reduce((s, r) => s + r.calls7, 0), coldShare: 0, prof };
  });
  const roles = groups.flatMap((g) => g.roles.map((r) => Object.assign(r, { cluster: g })));
  const byRole = new Map(roles.map((r) => [r.id, r]));
  const rr = rng(hash(d.account.id));
  const nRim = Math.min(d.coldCount, 80);
  const rim = Array.from({ length: nRim }, (_, i) => { const a = (i / nRim) * Math.PI * 2 + rr() * 0.18; return { x: Math.cos(a) * (500 + rr() * 34), y: Math.sin(a) * (332 + rr() * 26) }; });
  const sources = d.outside.items.map((s, i, all) => { const deg = all.length === 1 ? 90 : 25 + (130 * i) / (all.length - 1), [gap, z] = PLACE[s.worst] || PLACE.none; return { ...s, id: `src:${s.key}`, kind: GLYPH[s.group] || 'account', risk: s.worst, ...off(deg, gap, z) }; });
  const fars = d.neighbours.map((n, i, all) => ({ ...n, ...off(all.length === 1 ? 200 : 190 + (150 * i) / (all.length - 1), 95, 0), env: ORDER.includes(n.environment) ? n.environment : 'production' }));
  const links = [];
  for (const g of groups) {
    const per = new Map();
    for (const r of g.roles) for (const s of r.services) if (tower.has(s.name)) per.set(s.name, (per.get(s.name) || 0) + s.calls);
    for (const [s, v] of per) links.push({ from: g.id, to: `svc:${s}`, kind: 'use', vol: lg(v) / 5 });
  }
  for (const r of roles) for (const s of r.services) if (tower.has(s.name)) links.push({ from: r.id, to: `svc:${s.name}`, kind: s.denied > 0 && s.denied >= s.calls * 0.05 ? 'denied' : 'use1', owner: r.id, vol: 1, denied: s.denied });
  for (const s of sources) for (const t of s.targets) for (const id of t.roles) if (byRole.has(id)) links.push({ from: s.id, to: id, kind: s.worst === 'high' ? 'extHigh' : s.worst === 'medium' ? 'extWarn' : 'ext', vol: 1 });
  for (const n of fars) for (const l of n.links) if (byRole.has(l.roleId)) links.push(l.dir === 'in' ? { from: `far:${n.id}`, to: l.roleId, kind: 'in', vol: 2 } : { from: l.roleId, to: `far:${n.id}`, kind: 'out', vol: 2 });
  const events = d.events.map((e) => ({ id: e.id, kind: KIND[e.kind] || e.kind.toUpperCase(), tone: e.severity, hour: e.hour, text: e.title, where: e.roleName || d.account.name, target: e.roleId && byRole.has(e.roleId) ? e.roleId : null }));
  return { view: 'account', account: d.account, zones: [], groups, roles, byRole, towers, rim, sources, fars, links, events, hidden: d.outside.hidden,
    coldCount: d.coldCount, roleCount: d.roleCount, hourStart: new Date(d.hourStart).getTime(),
    defaultSel: events.find((e) => e.target)?.target || [...roles].sort((a, b) => b.calls7 - a.calls7)[0]?.id || null };
}

export async function spacePage(ctx) {
  const view = ctx.params.get('view') === 'account' ? 'account' : 'estate';
  const est = await get('/space');
  if (!est.accounts.length) return h('div', { class: 'stack' }, h('h1', null, 'Space'), h('p', { class: 'muted' }, 'No accounts yet. Connect one to see it here.'), h('a', { class: 'btn primary', href: '#/accounts/new' }, 'Connect an account'));
  const accountId = ctx.params.get('account') || [...est.accounts].sort((a, b) => b.calls7 - a.calls7)[0].id;
  const M = view === 'estate' ? estateModel(est) : accountModel(await get(`/space/account/${accountId}`));
  ctx.setCrumbs(h('a', { href: '#/space' }, 'Space'), ...(view === 'account' ? [M.account.name] : []));
  const st = { sel: M.defaultSel, hour: M.events.find((e) => e.target === M.defaultSel)?.hour ?? 23, playing: false, az: -14, el: 33, zone: '', timer: null, fit: null, dragging: false };
  const left = h('aside', { class: 'left' }), right = h('aside', { class: 'right' });
  const stage = svg('svg', { class: 'space-svg', viewBox: `0 0 ${W} ${H}`, role: 'img' });
  const box = h('div', { class: 'space-box' }, stage);
  const hud = h('div', { class: 'space-hud', 'aria-live': 'polite' }), cam = h('div', { class: 'space-cam', role: 'group', 'aria-label': 'Camera' });
  const bar = h('div', { class: 'space-timeline' });
  const scene = h('div', { class: 'scene space-scene' }, h('div', { class: 'space-stage' }, box, hud, cam), bar);
  const page = h('div', { class: 'stack space-page', style: 'gap:0' }, h('div', { class: 'scene-layout space-layout' }, left, scene, right));
  const set = (patch) => { Object.assign(st, patch); render(); };
  const stop = () => { if (st.timer) { clearInterval(st.timer); st.timer = null; } };
  ctx.onLeave(stop);

  // drag to orbit: the framing is held while dragging, then refitted
  let drag = null;
  stage.addEventListener('pointerdown', (ev) => { drag = { x: ev.clientX, y: ev.clientY, az: st.az, el: st.el, moved: false }; stage.setPointerCapture(ev.pointerId); });
  stage.addEventListener('pointermove', (ev) => {
    if (!drag) return; const dx = ev.clientX - drag.x, dy = ev.clientY - drag.y;
    if (!drag.moved && Math.hypot(dx, dy) < 5) return;
    drag.moved = true; st.dragging = true;
    const az = Math.round(drag.az - dx * 0.35), el = Math.max(18, Math.min(70, Math.round(drag.el + dy * 0.2)));
    if (az !== st.az || el !== st.el) { st.az = az; st.el = el; if (!drag.raf) drag.raf = requestAnimationFrame(() => { drag && (drag.raf = 0); render(); }); }
  });
  const endDrag = () => { if (drag?.moved) { st.dragging = false; st.fit = null; render(); setTimeout(() => { drag = null; }, 0); } else drag = null; };
  stage.addEventListener('pointerup', endDrag); stage.addEventListener('pointercancel', endDrag);
  stage.addEventListener('click', (ev) => { if (drag?.moved) { ev.stopPropagation(); return; } if (ev.target === stage) set({ sel: null }); });

  function camera(fitPts) {
    const D = 2600, el = (st.el * Math.PI) / 180, ce = Math.cos(el), se = Math.sin(el), az = (st.az * Math.PI) / 180, ca = Math.cos(az), sa = Math.sin(az);
    const p = (x, y, z) => { const X = x * ca - y * sa, Y = x * sa + y * ca, vy = Y + D * ce, vz = z - D * se, dep = vy * ce - vz * se; return [X / dep, (vy * se + vz * ce) / dep, dep]; };
    if (!st.fit || (!st.dragging && st.fit.key !== `${st.az}|${st.el}`)) {
      let x0 = 1e9, x1 = -1e9, u0 = 1e9, u1 = -1e9;
      for (const [x, y, z] of fitPts) { const [X, U] = p(x, y, z); x0 = Math.min(x0, X); x1 = Math.max(x1, X); u0 = Math.min(u0, U); u1 = Math.max(u1, U); }
      const F = Math.min((W - 60) / (x1 - x0), (H - 150) / (u1 - u0));
      st.fit = { key: `${st.az}|${st.el}`, D, F, CX: W / 2 - (F * (x0 + x1)) / 2, CY: 96 + F * u1 + (H - 150 - F * (u1 - u0)) / 2 };
    }
    const { F, CX, CY } = st.fit;
    return (x, y, z = 0) => { const [X, U, dep] = p(x, y, z); return [CX + F * X, CY - F * U, dep, F / dep]; };
  }
  const hourLabel = (b) => new Date(M.hourStart + b * 36e5).toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit', timeZone: 'Asia/Jakarta' });

  function render() {
    const hour = st.hour, sel = st.sel, motion = !still() && !st.dragging, focus = M.view === 'estate' ? st.zone : '';
    const dimOf = (env) => (!focus ? 1 : focus === 'outer' ? 0.3 : env === focus ? 1 : 0.22);
    // where every path starts and ends
    const ent = new Map();
    for (const g of M.groups) ent.set(g.id, { p3: [g.x, g.y, 22], env: g.env });
    for (const s of M.sources) ent.set(s.id, { p3: [s.x, s.y, s.z], env: 'outer' });
    if (M.view === 'account') { for (const t of M.towers) ent.set(t.id, { p3: [t.x, t.y, t.h], env: 'svc' }); for (const r of M.roles) ent.set(r.id, { p3: [r.x, r.y, r.z], env: r.cluster.env }); for (const n of M.fars) ent.set(`far:${n.id}`, { p3: [n.x, n.y, 8], env: n.env }); }
    const liftOf = (l, a, b) => (l.kind === 'use' ? 30 : l.kind === 'use1' ? 34 : l.kind === 'denied' && M.view === 'account' ? 40 : /^ext/.test(l.kind) ? 26 + 0.07 * Math.hypot(b[0] - a[0], b[1] - a[1]) : null);
    const fitPts = [[-560, -380, 0], [560, -380, 0], [560, 380, 0], [-560, 380, 0], [0, -440, 0], ...M.sources.flatMap((s) => [[s.x, s.y, s.z + 14], [s.x, s.y, 0]]), ...(M.fars || []).flatMap((n) => [[n.x - 50, n.y - 50, 0], [n.x + 50, n.y + 50, 0]])];
    if (M.view === 'estate') fitPts.push([-760, 0, 0], [760, 0, 0]);
    for (const l of M.links) { const a = ent.get(l.from), b = ent.get(l.to); if (a && b) fitPts.push(apex3(a.p3, b.p3, l.from < l.to ? 1 : -1, liftOf(l, a.p3, b.p3))); }
    const P = camera(fitPts), ref = st.fit.F / st.fit.D, sinEl = Math.sin((st.el * Math.PI) / 180);
    const path = (pts) => `M${pts.map((p) => `${f(p[0])} ${f(p[1])}`).join(' L')}`;
    const ring3 = (cx, cy, r, a0, a1, n = 44) => path(Array.from({ length: n + 1 }, (_, i) => { const a = a0 + ((a1 - a0) * i) / n; return P(cx + Math.cos(a) * r, cy + Math.sin(a) * r, 0); }));
    const pick = (id) => (ev) => { ev.stopPropagation(); set({ sel: sel === id ? null : id }); };
    const out = { floor: [], halo: [], rings: [], towers: [], stems: [], stars: [], arcs: [], parts: [], sparks: [], sats: [], marks: [], hits: [], labels: [] };
    const tops = new Map(), blocks = [[0, 0, 400, 76], [W - 330, 0, W, 58]];
    const fits = (r) => r[0] >= 4 && r[2] <= W - 4 && r[1] >= 4 && r[3] <= H - 4 && !blocks.some((o) => r[0] < o[2] && r[2] > o[0] && r[1] < o[3] && r[3] > o[1]);

    // the plane, its grid, the zones
    const corners = [[-560, -380], [560, -380], [560, 380], [-560, 380]].map(([x, y]) => P(x, y, 0));
    out.floor.push(svg('path', { d: `${path(corners)} Z`, fill: 'url(#sp-floor)', stroke: '#2a8a5c', 'stroke-width': 1.2 }));
    for (let i = 1; i < 14; i++) { const x = -560 + i * 80, a = P(x, -380), b = P(x, 380); out.floor.push(svg('line', { x1: f(a[0]), y1: f(a[1]), x2: f(b[0]), y2: f(b[1]), stroke: '#1d6a45', 'stroke-width': 0.7, opacity: 0.4 })); }
    for (let i = 1; i < 10; i++) { const y = -380 + i * 76, a = P(-560, y), b = P(560, y); out.floor.push(svg('line', { x1: f(a[0]), y1: f(a[1]), x2: f(b[0]), y2: f(b[1]), stroke: '#1d6a45', 'stroke-width': 0.7, opacity: 0.4 })); }
    for (const z of M.zones) {
      const E = ENV[z.id], pts = [[z.x0 + 8, -372], [z.x1 - 8, -372], [z.x1 - 8, 372], [z.x0 + 8, 372]].map(([x, y]) => P(x, y, 0)), l = P((z.x0 + z.x1) / 2, -380, 0);
      const label = E.name.toUpperCase(), w = label.length * 8.7;
      blocks.push([l[0] - w / 2 - 4, l[1] + 12, l[0] + w / 2 + 4, l[1] + 29]);
      out.floor.push(svg('g', { opacity: !focus || focus === z.id ? 1 : 0.35 }, svg('path', { d: `${path(pts)} Z`, fill: E.base, 'fill-opacity': 0.06, stroke: E.base, 'stroke-dasharray': '4 5' }),
        svg('text', { x: f(l[0]), y: f(l[1] + 24), 'text-anchor': 'middle', fill: E.hot, class: 'sp-zone' }, label)));
    }
    if (M.view === 'account' && M.rim.length) { const l = P(0, -380, 0); out.floor.push(svg('text', { x: f(l[0]), y: f(l[1] + 24), 'text-anchor': 'middle', fill: '#b6c2bb', class: 'sp-zone' }, `GREY DOTS ROUND THE EDGE · ${M.coldCount} ROLES WITH NO RECORDED CALL`)); blocks.push([l[0] - 230, l[1] + 12, l[0] + 230, l[1] + 29]); }

    // accounts / clusters
    const maxHour = Math.max(1, ...M.groups.flatMap((g) => g.prof));
    const maxLog = Math.max(1, ...M.groups.flatMap((g) => g.stars.map((s) => lg(s.calls7))));
    const evNow = M.events.filter((e) => e.hour === hour);
    const selRole = M.view === 'account' ? M.byRole.get(sel) : null;
    const cands = [];
    for (const g of M.groups) {
      const E = ENV[g.env], dim = dimOf(g.env), c = P(g.x, g.y, 0), rx = g.R * 1.8 * c[3];
      out.halo.push(svg('ellipse', { cx: f(c[0]), cy: f(c[1]), rx: f(rx), ry: f(rx * sinEl), fill: `url(#sp-h-${g.env})`, opacity: o2((0.08 + 0.64 * Math.sqrt(g.prof[hour] / maxHour)) * dim) }));
      const a0 = -Math.PI / 2, act = (1 - g.coldShare) * Math.PI * 2;
      out.rings.push(svg('path', { d: ring3(g.x, g.y, g.R, a0, a0 + act), fill: 'none', stroke: E.base, 'stroke-width': 1.5, opacity: o2(0.95 * dim) }));
      if (g.coldShare > 0.001) out.rings.push(svg('path', { d: ring3(g.x, g.y, g.R, a0 + act, a0 + Math.PI * 2), fill: 'none', stroke: COLD, 'stroke-width': 1.2, 'stroke-dasharray': '2 3', opacity: o2(0.9 * dim) }));
      const k0 = M.view === 'account' ? 1.55 : 1;
      let bx0 = 1e9, by0 = 1e9, bx1 = -1e9, by1 = -1e9, topZ = 0;
      g.stars.forEach((s, i) => {
        const p = P(s.x, s.y, s.z), lv = lg(s.calls7) / maxLog, k = Math.max(0.72, p[3] / ref) * k0;
        out.stars.push([p[2], svg('circle', { cx: f(p[0]), cy: f(p[1]), r: f((s.cold ? 1 : 0.8 + 0.42 * lg(s.calls7)) * k), fill: s.cold ? COLD : lv > 0.8 ? E.hot : lv > 0.45 ? E.base : E.dim, opacity: o2((s.cold ? 0.7 : 0.95) * dim), filter: !s.cold && i < 3 && dim === 1 ? 'url(#sp-glow)' : null })]);
        if (!s.cold && i < (M.view === 'account' ? 6 : 3)) { const b = P(s.x, s.y, 0); out.stems.push(svg('line', { x1: f(b[0]), y1: f(b[1]), x2: f(p[0]), y2: f(p[1]), stroke: E.base, 'stroke-width': 0.8, opacity: o2(0.4 * dim) })); }
        bx0 = Math.min(bx0, p[0]); by0 = Math.min(by0, p[1]); bx1 = Math.max(bx1, p[0]); by1 = Math.max(by1, p[1]); topZ = Math.max(topZ, s.z);
      });
      const t = P(g.x, g.y, topZ + 10), fp = [P(g.x - g.R, g.y), P(g.x + g.R, g.y), P(g.x, g.y - g.R), P(g.x, g.y + g.R)];
      tops.set(g.id, t);
      const target = M.view === 'estate' ? g.id : g.roles[0]?.id;
      const hc = P(g.x, g.y, 30);
      out.hits.push(svg('g', { class: 'sp-hit', onClick: pick(target) }, svg('title', null, M.view === 'estate' ? `${g.name} · ${ENV[g.env].name} · ${g.roles} roles · ${kfmt(g.calls7)} calls in 7 days` : `${g.label} · ${g.roles.length} roles`),
        svg('circle', { cx: f(hc[0]), cy: f(hc[1]), r: f(Math.max(16, g.R * c[3] * 1.15)), fill: '#000', opacity: 0 })));
      const isSel = M.view === 'estate' ? sel === g.id : selRole?.cluster === g;
      cands.push({ pr: (isSel ? 3000 : 0) + (evNow.some((e) => e.target === g.id) ? 900 : 0) + lg(g.calls7) * 40 + (dim < 1 ? -500 : 0), x: t[0], y: t[1], text: g.label, color: dim < 1 ? '#3c5a4b' : E.base, pick: pick(target), below: fp[2][1] - t[1] + 14 });
      if (M.view === 'estate' && sel === g.id) {
        const x0 = Math.min(bx0, ...fp.map((q) => q[0])) - 6, y0 = Math.min(by0, t[1]) - 6, x1 = Math.max(bx1, ...fp.map((q) => q[0])) + 6, y1 = Math.max(by1, ...fp.map((q) => q[1])) + 6, q = 9;
        out.marks.push(svg('path', { d: ring3(g.x, g.y, g.R * 1.16, 0, Math.PI * 2, 56), fill: 'none', stroke: '#fff', 'stroke-width': 1.6 }));
        out.marks.push(svg('path', { d: `M${f(x0)} ${f(y0 + q)} L${f(x0)} ${f(y0)} L${f(x0 + q)} ${f(y0)} M${f(x1 - q)} ${f(y0)} L${f(x1)} ${f(y0)} L${f(x1)} ${f(y0 + q)} M${f(x1)} ${f(y1 - q)} L${f(x1)} ${f(y1)} L${f(x1 - q)} ${f(y1)} M${f(x0 + q)} ${f(y1)} L${f(x0)} ${f(y1)} L${f(x0)} ${f(y1 - q)}`, fill: 'none', stroke: '#fff', 'stroke-width': 1.4, opacity: 0.9 }));
      }
    }
    if (M.view === 'account') {
      for (const r of M.roles) {
        const p = P(r.x, r.y, r.z); tops.set(r.id, p);
        out.hits.push(svg('g', { class: 'sp-hit', onClick: pick(r.id) }, svg('title', null, `${r.name} · ${kfmt(r.calls7)} calls in 7 days`), svg('circle', { cx: f(p[0]), cy: f(p[1]), r: 7, fill: '#000', opacity: 0 })));
        if (sel === r.id) { out.marks.push(svg('path', { d: glyph('account', p[0], p[1], 9), fill: 'none', stroke: '#fff', 'stroke-width': 1.6 })); out.marks.push(svg('path', { d: ring3(r.cluster.x, r.cluster.y, r.cluster.R * 1.12, 0, Math.PI * 2, 56), fill: 'none', stroke: '#fff', 'stroke-width': 1.1, opacity: 0.55 })); }
      }
      for (const s of M.rim) { const p = P(s.x, s.y, 0); out.stars.push([p[2], svg('circle', { cx: f(p[0]), cy: f(p[1]), r: f(2.1 * Math.max(0.72, p[3] / ref)), fill: '#8d9a93', opacity: 0.85 })]); }
      for (const t of M.towers) {
        const b = P(t.x, t.y, 0), tp = P(t.x, t.y, t.h), k = Math.max(0.72, tp[3] / ref);
        out.towers.push(svg('g', null, svg('line', { x1: f(b[0]), y1: f(b[1]), x2: f(b[0]), y2: f(tp[1]), stroke: '#9cc7b4', 'stroke-width': f(1.4 * k), opacity: 0.55 }),
          svg('ellipse', { cx: f(b[0]), cy: f(b[1]), rx: f(9 * k), ry: f(9 * k * sinEl), fill: 'none', stroke: '#9cc7b4', 'stroke-width': 0.9, opacity: 0.6 }),
          svg('path', { d: glyph('service', tp[0], tp[1], 6 * k), fill: '#eef7f2', stroke: '#fff', 'stroke-width': 0.6, filter: 'url(#sp-glow)' })));
        out.hits.push(svg('g', { class: 'sp-hit', onClick: pick(t.id) }, svg('title', null, `${t.name} · ${kfmt(t.calls)} calls in 7 days`), svg('circle', { cx: f(tp[0]), cy: f(tp[1]), r: 14, fill: '#000', opacity: 0 })));
        tops.set(t.id, tp);
        cands.push({ pr: 1500 + lg(t.calls) * 40 + (sel === t.id ? 3000 : 0), x: tp[0], y: tp[1] - 4, text: t.name, color: '#9cc7b4', pick: pick(t.id), below: 26 });
        if (sel === t.id) out.marks.push(svg('path', { d: glyph('account', tp[0], tp[1], 11), fill: 'none', stroke: '#fff', 'stroke-width': 1.6 }));
      }
      for (const n of M.fars) {
        const E = ENV[n.env], c = P(n.x, n.y, 0), id = `far:${n.id}`;
        out.rings.push(svg('g', { class: 'sp-hit', onClick: pick(id) }, svg('title', null, `${n.name} · neighbouring account`), svg('path', { d: ring3(n.x, n.y, 40, 0, Math.PI * 2, 36), fill: E.base, 'fill-opacity': 0.12, stroke: E.base, 'stroke-width': 1.3 }),
          svg('text', { x: f(c[0]), y: f(c[1] + 40 * c[3] * sinEl + 16), 'text-anchor': 'middle', fill: E.hot, class: 'sp-small' }, n.name)));
        tops.set(id, P(n.x, n.y, 10));
        if (sel === id) out.marks.push(svg('path', { d: ring3(n.x, n.y, 50, 0, Math.PI * 2, 40), fill: 'none', stroke: '#fff', 'stroke-width': 1.6 }));
      }
    }

    // outside the org
    const sats = M.sources.map((s) => {
      const p = P(s.x, s.y, s.z), g0 = P(s.x, s.y, 0), k = Math.max(0.75, Math.min(1.3, p[3] / ref)), size = 6.5 * k;
      blocks.push([p[0] - 13, p[1] - 13, p[0] + 13, p[1] + 13]); tops.set(s.id, p);
      if (sel === s.id) out.marks.push(svg('path', { d: glyph('account', p[0], p[1], 17), fill: 'none', stroke: '#fff', 'stroke-width': 1.6 }));
      return { s, p, g0, k, size };
    });

    // paths above the plane
    const flagC = [];
    const rnd = rng(7);
    for (const l of M.links) {
      const a = ent.get(l.from), b = ent.get(l.to); if (!a || !b) continue;
      const t = l.from === sel || l.to === sel || (selRole && l.owner === selRole.id);
      const past = l.at ? l.at.some((x) => x <= hour) : true, now = l.at ? l.at.includes(hour) : false;
      let show = true, color = OUT, w = 1, o = 0.22, dash = null, cls = null, cut = 1, flow = 0, flag = null;
      if (l.kind === 'chain') { color = ENV[a.env]?.base || OUT; w = 0.6 + 0.4 * l.vol; o = t || now ? 0.95 : 0.4; flow = t || now ? Math.round(l.vol) : 0; if (l.denied && (t || now)) flag = { text: `⚠ ${l.denied} DENIED`, bg: RED }; }
      else if (l.kind === 'new') { show = past || t; color = '#fff'; w = 1.8; dash = '6 5'; cls = 'sp-dash'; o = now || t ? 1 : 0.5; flow = now || t ? 2 : 0; flag = { text: 'NEW PATH', bg: '#fff' }; }
      else if (l.kind === 'denied') { color = RED; w = 1.5; dash = '4 4'; cut = 0.72; o = t ? 1 : 0.45; flow = t ? 2 : 0; flag = { text: `⚠ ${l.denied} DENIED`, bg: RED }; }
      else if (l.kind === 'ext') { o = t ? 0.9 : 0.2; flow = t ? 1 : 0; }
      else if (l.kind === 'extWarn') { color = WARN; o = t ? 0.95 : 0.35; flow = t ? 1 : 0; if (t) flag = { text: 'LOOSE TRUST', bg: WARN }; }
      else if (l.kind === 'extHigh') { color = RED; w = 1.4; o = t ? 1 : 0.5; flow = t ? 1 : 0; if (t) flag = { text: '⚠ RISKY TRUST', bg: RED }; }
      else if (l.kind === 'use') { color = ENV[a.env].base; w = 0.5 + 1.6 * l.vol; o = selRole ? 0.12 : 0.28; }
      else if (l.kind === 'use1') { show = t; color = ENV[a.env].hot; w = 1.4; o = 0.95; flow = 1; }
      else if (l.kind === 'in' || l.kind === 'out') { color = ENV[(ent.get(l.kind === 'in' ? l.from : l.to)).env]?.base || OUT; w = 1.3; o = t ? 0.95 : 0.45; flow = t ? 2 : 1; }
      if (!show) continue;
      if (focus && focus !== 'outer' && a.env !== focus && b.env !== focus) o *= 0.25;
      if (focus === 'outer' && a.env !== 'outer' && b.env !== 'outer') o *= 0.25;
      const g3 = arc3(a.p3, b.p3, l.from < l.to ? 1 : -1, P, liftOf(l, a.p3, b.p3));
      out.arcs.push(svg('path', { d: cut < 1 ? g3.part(cut) : g3.d, fill: 'none', stroke: color, 'stroke-width': f(w), opacity: o2(o), 'stroke-dasharray': dash, class: cls, 'stroke-linecap': 'round' }));
      if (cut < 1 && t) { const q = g3.pts[Math.round(cut * 24)]; out.sparks.push(svg('g', null, svg('circle', { cx: f(q[0]), cy: f(q[1]), r: 5, fill: 'none', stroke: RED, 'stroke-width': 1.4, class: 'sp-pulse' }))); }
      if (motion) for (let i = 0; i < flow; i++) {
        const dur = 3.4, begin = `${f(-(i * dur) / flow - rnd() * 0.8)}s`, c = l.kind === 'denied' ? RED : color;
        out.parts.push(svg('circle', { r: 2.2, fill: c, filter: 'url(#sp-glow)', opacity: 0 },
          svg('animateMotion', { path: g3.d, dur: `${dur}s`, begin, repeatCount: 'indefinite', keyPoints: cut < 1 ? `0;${cut}` : '0;1', keyTimes: '0;1', calcMode: 'linear' }),
          svg('animate', { attributeName: 'opacity', values: '0;0.95;0.95;0', keyTimes: '0;0.1;0.8;1', dur: `${dur}s`, begin, repeatCount: 'indefinite' })));
      }
      if (flag && (now || t)) { const q = g3.pts[cut < 1 ? 10 : 12]; flagC.push({ x: q[0], y: q[1], text: flag.text, bg: flag.bg, pr: now ? 1 : 0 }); }
    }

    // the card beside the selection goes where it hides the least
    const b = sel ? detail(sel) : null;
    let card = null;
    if (b && tops.has(sel)) {
      const [ax, ay] = tops.get(sel), cw = 300, px = 0.83;
      const head = 16 * Math.ceil((b.eyebrow.length + b.tags.reduce((s, t) => s + t.t.length + 3, 0)) / 30) + 21 * Math.ceil(b.title.length / 24) + 15 * Math.ceil(b.sub.length / 34) + 10;
      const ch = Math.round((24 + head + b.rows.reduce((s, r) => s + 22 + 17 * Math.ceil(r.v.length / 34), 0) + 58) / px);
      const imp = [...[...tops].filter(([id]) => id !== sel).map(([, q]) => q), ...flagC.map((q) => [q.x, q.y])];
      const tries = [];
      for (const d of [50, 130]) tries.push([ax + d, ay - ch * 0.3], [ax - d - cw, ay - ch * 0.3], [ax - cw / 2, ay - ch - d], [ax - cw / 2, ay + d]);
      tries.push([12, 86], [W - cw - 12, 66], [12, H - ch - 12], [W - cw - 12, H - ch - 12]);
      const starPts = out.stars.map(([, el]) => [+el.getAttribute('cx'), +el.getAttribute('cy')]);
      const best = tries.map(([x, y]) => {
        const x0 = Math.max(10, Math.min(W - cw - 10, x)), y0 = Math.max(80, Math.min(H - ch - 12, y));
        const inside = (q) => q[0] > x0 - 10 && q[0] < x0 + cw + 10 && q[1] > y0 - 10 && q[1] < y0 + ch + 10;
        return { x0, y0, score: (inside([ax, ay]) ? 1000 : 0) + imp.filter(inside).length * 30 + starPts.filter(inside).length + Math.hypot(x0 + cw / 2 - ax, y0 + ch / 2 - ay) / 25 };
      }).sort((p, q) => p.score - q.score)[0];
      blocks.push([best.x0 - 6, best.y0 - 6, best.x0 + cw + 6, best.y0 + ch + 6]);
      out.marks.push(svg('line', { x1: f(ax), y1: f(ay), x2: f(Math.max(best.x0, Math.min(best.x0 + cw, ax))), y2: f(Math.max(best.y0, Math.min(best.y0 + ch, ay))), stroke: '#fff', 'stroke-width': 1, opacity: 0.75 }), svg('circle', { cx: f(ax), cy: f(ay), r: 3, fill: '#fff' }));
      card = cardEl(b, `left:${f(best.x0 / 10)}%;top:${f(best.y0 / 9)}%;width:${cw / 10}%`);
    }

    // labels: outside identities, event tags, then the selection and busy things. What would overlap keeps its tooltip
    for (const { s, p } of [...sats].sort((a, c) => (c.s.risk === 'high') - (a.s.risk === 'high'))) {
      const w = Math.max(s.label.length * 6.7, s.sub.length * 6.15) + 4;
      const tries = [['start', p[0] + 15, p[1] - 2], ['end', p[0] - 15, p[1] - 2], ['middle', p[0], p[1] - 32], ['middle', p[0], p[1] + 26]];
      let pl = null;
      for (const [anchor, lx, ly] of tries) { const x0 = anchor === 'start' ? lx : anchor === 'end' ? lx - w : lx - w / 2, r = [x0, ly - 11, x0 + w, ly + 17]; if (fits(r)) { pl = [anchor, lx, ly]; blocks.push(r); break; } }
      s.place = pl || (p[0] < W / 2 ? tries[0] : tries[1]);
    }
    for (const { s, p, g0, k, size } of sats) {
      const [anchor, lx, ly] = s.place, ring = s.risk === 'high' ? RED : s.risk === 'medium' ? WARN : null;
      out.sats.push(svg('g', { class: 'sp-hit', onClick: pick(s.id), opacity: focus && focus !== 'outer' ? 0.35 : 1 },
        svg('title', null, `${s.label} · ${s.sub}${s.findings.length ? ` · ${s.findings.join('; ')}` : ''}`),
        svg('line', { x1: f(p[0]), y1: f(p[1]), x2: f(g0[0]), y2: f(g0[1]), stroke: '#8b98ad', 'stroke-width': 0.8, 'stroke-dasharray': '1.5 3.5' }),
        svg('ellipse', { cx: f(g0[0]), cy: f(g0[1]), rx: f(7 * k), ry: f(7 * k * sinEl), fill: 'none', stroke: '#8b98ad', 'stroke-width': 0.8, opacity: 0.7 }),
        svg('circle', { cx: f(p[0]), cy: f(p[1]), r: 16, fill: '#000', opacity: 0 }),
        svg('path', { d: glyph(s.kind, p[0], p[1], size), fill: '#d5dceb', stroke: '#fff', 'stroke-width': 0.8, filter: 'url(#sp-glow)' }),
        ring && svg('circle', { cx: f(p[0]), cy: f(p[1]), r: f(size + 6), fill: 'none', stroke: ring, 'stroke-width': 1.5, 'stroke-dasharray': s.risk === 'high' ? null : '3 3', class: 'sp-pulse' }),
        svg('text', { x: f(lx), y: f(ly), 'text-anchor': anchor, fill: '#e6ebf4', class: 'sp-name' }, s.label),
        svg('text', { x: f(lx), y: f(ly + 13), 'text-anchor': anchor, fill: s.risk === 'high' ? '#ffb0a6' : '#a9b4c6', class: 'sp-small' }, s.sub)));
    }
    for (const c of flagC.sort((a, x) => x.pr - a.pr)) {
      const bw = Math.round(c.text.length * 6.3 + 14);
      for (const [dx, dy] of [[0, -22], [bw / 2 + 12, -14], [-bw / 2 - 12, -14], [0, 22], [0, -44]]) {
        const cx = c.x + dx, cy = c.y + dy, r = [cx - bw / 2, cy - 9, cx + bw / 2, cy + 9];
        if (!fits(r)) continue;
        blocks.push(r);
        out.labels.push(svg('g', { 'pointer-events': 'none' }, svg('line', { x1: f(c.x), y1: f(c.y), x2: f(cx), y2: f(dy < 0 ? r[3] : r[1]), stroke: c.bg, 'stroke-width': 0.9, opacity: 0.8 }),
          svg('rect', { x: f(r[0]), y: f(r[1]), width: bw, height: 18, rx: 2, fill: c.bg }), svg('text', { x: f(cx), y: f(cy + 3.5), 'text-anchor': 'middle', fill: '#05110b', class: 'sp-flag' }, c.text)));
        break;
      }
    }
    for (const c of cands.sort((a, x) => x.pr - a.pr)) {
      const bw = Math.round(c.text.length * 6.5 + 16);
      for (const [dx, dy] of [[0, -24], [bw / 2 + 14, -14], [-bw / 2 - 14, -14], [0, -46], [0, c.below]]) {
        const cx = c.x + dx, cy = c.y + dy, r = [cx - bw / 2, cy - 10, cx + bw / 2, cy + 10];
        if (!fits(r)) continue;
        blocks.push(r);
        out.labels.push(svg('g', { class: 'sp-hit', onClick: c.pick }, svg('line', { x1: f(c.x), y1: f(c.y), x2: f(cx), y2: f(dy < 0 ? r[3] : r[1]), stroke: c.color, 'stroke-width': 0.8, opacity: 0.7 }),
          svg('rect', { x: f(r[0]), y: f(r[1]), width: bw, height: 20, rx: 3, fill: '#03100b', 'fill-opacity': 0.88, stroke: c.color }), svg('text', { x: f(cx), y: f(cy + 3.6), 'text-anchor': 'middle', fill: '#e3efe8', class: 'sp-pill' }, c.text)));
        break;
      }
    }

    out.stars.sort((a, c) => c[0] - a[0]);
    stage.setAttribute('aria-label', M.view === 'estate'
      ? `Your organization as a tilted plane: ${M.groups.length} accounts in zones by environment, one star per busy role, higher the more it is called; identities outside the org float off the plane. Showing ${hourLabel(hour)}.`
      : `${M.account.name} as a plane: services as towers in the middle, roles clustered round the service they call most, cold roles grey round the edge. Showing ${hourLabel(hour)}.`);
    stage.replaceChildren(
      svg('defs', null,
        svg('filter', { id: 'sp-glow', x: '-100%', y: '-100%', width: '300%', height: '300%' }, svg('feGaussianBlur', { stdDeviation: 1.8, result: 'b' }), svg('feMerge', null, svg('feMergeNode', { in: 'b' }), svg('feMergeNode', { in: 'SourceGraphic' }))),
        svg('linearGradient', { id: 'sp-floor', x1: 0, y1: 0, x2: 0, y2: 1 }, svg('stop', { offset: 0, 'stop-color': '#031009' }), svg('stop', { offset: 1, 'stop-color': '#072a1b' })),
        ...Object.entries(ENV).map(([k, e]) => svg('radialGradient', { id: `sp-h-${k}` }, svg('stop', { offset: 0, 'stop-color': e.base, 'stop-opacity': 0.8 }), svg('stop', { offset: 0.5, 'stop-color': e.base, 'stop-opacity': 0.24 }), svg('stop', { offset: 1, 'stop-color': e.base, 'stop-opacity': 0 })))),
      svg('g', { 'pointer-events': 'none' }, ...out.floor), svg('g', { 'pointer-events': 'none' }, ...out.halo), ...out.rings, svg('g', { 'pointer-events': 'none' }, ...out.towers, ...out.stems, ...out.stars.map(([, el]) => el)),
      svg('g', { 'pointer-events': 'none' }, ...out.arcs, ...out.parts, ...out.sparks), ...out.sats, svg('g', { 'pointer-events': 'none' }, ...out.marks), ...out.hits, ...out.labels);
    box.querySelector('.sp-card')?.remove();
    if (card) box.append(card);
    renderSide(); renderBar();
  }

  // ---------- the card ----------
  function detail(id) {
    const row = (k, v, tone) => ({ k, v: String(v), tone });
    const tag = (t, c) => ({ t, c });
    if (M.view === 'estate') {
      const g = M.by.get(id);
      if (g) {
        const look = M.events.find((e) => e.target === g.id);
        const ins = M.links.filter((l) => l.to === g.id && (l.kind === 'chain' || l.kind === 'new')).map((l) => `${M.by.get(l.from).name}${l.kind === 'new' ? ' (new)' : ''}`);
        const outs = M.links.filter((l) => l.from === g.id && (l.kind === 'chain' || l.kind === 'new')).map((l) => M.by.get(l.to).name);
        const today = g.hourly.reduce((s, x) => s + x.sessions, 0);
        return { eyebrow: `ACCOUNT · ${ENV[g.env].name.toUpperCase()}${g.ou ? ` · ${g.ou}` : ''}`, title: g.name, sub: g.awsAccountId, swatch: ENV[g.env].base,
          tags: [...(g.high ? [tag(`${g.high} HIGH`, RED)] : []), ...(look ? [tag(look.kind, TONE[look.tone] || '#fff')] : [])],
          rows: [row('Roles', `${g.roles} · ${g.active} called · ${g.cold} never called`), row('Calls', `${kfmt(g.calls7)} in 7 days · ${today} sessions today`),
            ...(look ? [row('Look at', `${look.text} (${hourLabel(look.hour)})`, 'bad')] : [row('Entered from', ins.length ? ins.join(', ') : 'no other account today'), row('Reaches', outs.length ? outs.join(', ') : 'no other account today')])],
          actions: [['Zoom in', `#/space?view=account&account=${g.id}`, true], ['Account radar', `#/?view=account&account=${g.id}`]] };
      }
    }
    const s = M.sources.find((x) => x.id === id);
    if (s) {
      const where = M.view === 'estate' ? s.targets.map((t) => M.by.get(t.accountId)?.name).filter(Boolean).join(', ') : s.targets.flatMap((t) => t.roles).map((r) => M.byRole.get(r)?.name).filter(Boolean).join(', ') || M.account.name;
      return { eyebrow: `OUTSIDE · ${s.group.toUpperCase()}`, title: s.label, sub: s.sub, swatch: '#d5dceb', round: true,
        tags: s.risk === 'high' ? [tag('⚠ HIGH', RED)] : s.risk === 'medium' ? [tag('LOOSE TRUST', WARN)] : [],
        rows: [row('Can enter', where), row('Trust', s.findings.length ? s.findings.join('; ') : 'conditions pinned: nothing to flag', s.findings.length ? 'bad' : 'ok'),
          row('Seen', s.sessions ? `${num(s.sessions)} sessions · last ${ago(s.lastSeen)}` : 'never seen coming in')],
        actions: [['Trust map', `#/trust?q=${encodeURIComponent(s.group === 'external-account' ? `from:${s.key.replace(/^acct:/, '')}` : s.group === 'public' ? 'source:public' : `provider:"${s.label}"`)}`, true]] };
    }
    if (M.view !== 'account') return null;
    const r = M.byRole.get(id);
    if (r) {
      const callers = M.sources.filter((x) => x.targets.some((t) => t.roles.includes(r.id))).map((x) => x.label);
      const chained = M.fars.flatMap((n) => n.links.filter((l) => l.roleId === r.id).map((l) => `${l.dir === 'in' ? 'from' : 'into'} ${n.name} · ${l.otherRole}`));
      return { eyebrow: `ROLE · ${r.cluster.label.toUpperCase()}`, title: r.name, sub: `${M.account.name} · ${M.account.awsAccountId}`, swatch: ENV[r.cluster.env].base, round: true,
        tags: [...(r.risk === 'High' ? [tag('HIGH', RED)] : []), ...(r.denied7 ? [tag(`⚠ ${num(r.denied7)} DENIED`, RED)] : [])],
        rows: [row('Calls', `${kfmt(r.calls7)} in 7 days · into ${r.services.map((x) => x.name).join(', ') || 'nothing'}`),
          row('Entered by', [...callers, ...chained].join(', ') || 'only callers inside this account'),
          ...(r.denied7 ? [row('Look at', `${num(r.denied7)} calls refused in 7 days: ${r.services.filter((x) => x.denied).map((x) => `${x.name} ×${x.denied}`).join(', ')}`, 'bad')] : [])],
        actions: [['Open role', `#/roles/${r.id}`, true], ['Blast radius', `#/?view=blast&key=${encodeURIComponent(`role:${M.account.awsAccountId}:${r.name}`)}`]] };
    }
    const t = M.towers.find((x) => x.id === id);
    if (t) {
      const users = M.roles.filter((x) => x.services.some((v) => v.name === t.name)).sort((a, c) => c.calls7 - a.calls7);
      return { eyebrow: 'AWS SERVICE', title: t.name, sub: `${users.length} roles call it`, swatch: '#eef7f2', tags: [],
        rows: [row('Calls', `${kfmt(t.calls)} in 7 days`), row('Busiest', users.slice(0, 3).map((x) => x.name).join(', ') || '—')], actions: [] };
    }
    const n = M.fars.find((x) => `far:${x.id}` === id);
    if (n) return { eyebrow: 'NEIGHBOURING ACCOUNT', title: n.name, sub: `${n.links.reduce((s, l) => s + l.sessions, 0)} chained sessions in 7 days`, swatch: ENV[n.env].base, tags: [],
      rows: n.links.slice(0, 3).map((l) => row(l.dir === 'in' ? 'Comes in' : 'Goes out', `${l.otherRole} ${l.dir === 'in' ? '→' : '←'} ${M.byRole.get(l.roleId)?.name || 'a role here'}`)),
      actions: [['Open in Space', `#/space?view=account&account=${n.id}`, true]] };
    return null;
  }
  function cardEl(b, pos) {
    const el = h('div', { class: 'sp-card', role: 'dialog', 'aria-label': b.title, style: pos },
      h('div', { class: 'sp-card-head' },
        h('div', { class: 'sp-card-titles' },
          h('div', { class: 'sp-eyebrow' }, h('span', null, b.eyebrow), ...b.tags.map((t) => h('span', { class: 'sp-tag', style: `color:${t.c};border-color:${t.c}` }, t.t))),
          h('div', { class: 'sp-card-title' }, h('span', { class: 'sp-swatch', style: `background:${b.swatch}${b.round ? ';border-radius:50%' : ''}` }), h('b', null, b.title)),
          h('span', { class: 'sp-card-sub' }, b.sub)),
        h('button', { class: 'sp-x', 'aria-label': 'Close', onClick: () => set({ sel: null }) }, '×')),
      h('dl', null, ...b.rows.map((r) => h('div', null, h('dt', null, r.k), h('dd', { class: r.tone ? `sp-${r.tone}` : null }, r.v)))),
      b.actions.length ? h('div', { class: 'sp-card-actions' }, ...b.actions.map(([label, href, primary]) => h('a', { class: primary ? 'btn primary small' : 'btn small', href }, label))) : null);
    el.addEventListener('pointerdown', (ev) => ev.stopPropagation());
    return el;
  }

  // ---------- beside the plane ----------
  function renderSide() {
    const focus = st.zone, selRole = M.view === 'account' ? M.byRole.get(st.sel) : null;
    const card = (on, chip, name, val, meta, onClick) => h('button', { class: 'sp-zonecard', 'aria-pressed': String(on), onClick }, h('span', { class: 'sp-chip', style: chip }),
      h('span', { class: 'sp-zc-body' }, h('span', { class: 'sp-zc-top' }, h('span', null, name), h('span', { class: 'mono' }, val)), h('span', { class: 'sp-zc-meta' }, meta)));
    const row = (on, dot, name, meta, val, onClick) => h('button', { class: 'sp-row', 'aria-pressed': String(on), title: name, onClick }, h('span', { class: 'sp-dot', style: dot }),
      h('span', { class: 'sp-row-body' }, h('span', { class: 'sp-row-name' }, name), h('span', { class: 'sp-row-meta' }, meta)), h('span', { class: 'mono sp-row-val' }, val));
    const tabs = h('div', { class: 'rtabs', role: 'tablist', 'aria-label': 'Space view' },
      h('button', { role: 'tab', 'aria-selected': String(M.view === 'estate'), onClick: () => go('#/space') }, 'Estate'),
      h('button', { role: 'tab', 'aria-selected': String(M.view === 'account'), onClick: () => go(`#/space?view=account&account=${accountId}`) }, 'One account'));
    if (M.view === 'estate') {
      const zones = M.zones.map((z) => {
        const gs = M.groups.filter((g) => g.env === z.id), roles = gs.reduce((s, g) => s + g.roles, 0), cold = gs.reduce((s, g) => s + g.cold, 0);
        return card(focus === z.id, `background:${ENV[z.id].base}`, ENV[z.id].name, kfmt(gs.reduce((s, g) => s + g.calls7, 0)), `${gs.length} accounts · ${roles ? Math.round((100 * cold) / roles) : 0}% cold`, () => set({ zone: focus === z.id ? '' : z.id }));
      });
      const highs = M.sources.filter((s) => s.risk === 'high').length, loose = M.sources.filter((s) => s.risk === 'medium').length;
      zones.push(card(focus === 'outer', 'background:#d5dceb;transform:rotate(45deg);width:10px;height:10px;margin:0 1px', 'Outside your org', String(M.sources.length + M.hidden), `${highs} risky · ${loose} loose trust`, () => set({ zone: focus === 'outer' ? '' : 'outer' })));
      const list = M.groups.filter((g) => !focus || focus === 'outer' || g.env === focus).sort((a, b) => b.calls7 - a.calls7);
      left.replaceChildren(tabs, h('h2', { class: 'eyebrow' }, 'Zones · click to focus'), h('div', { class: 'sp-cards' }, ...zones),
        h('div', { class: 'sp-listhead' }, h('h2', { class: 'eyebrow' }, 'Accounts · 7-day calls'), h('span', { class: 'mono faint' }, String(list.length))),
        h('div', { class: 'sp-list' }, ...list.map((g) => row(st.sel === g.id, `background:${ENV[g.env].base}`, g.name, g.awsAccountId, kfmt(g.calls7), () => set({ sel: st.sel === g.id ? null : g.id })))));
    } else {
      const cur = selRole?.cluster || M.groups[0];
      const accounts = h('select', { class: 'sp-select', 'aria-label': 'Account', onChange: (ev) => go(`#/space?view=account&account=${ev.target.value}`) },
        ...est.accounts.map((a) => h('option', { value: a.id, selected: a.id === accountId }, a.name)));
      left.replaceChildren(tabs, accounts, h('h2', { class: 'eyebrow' }, 'Roles by the service they call most'),
        h('div', { class: 'sp-cards' }, ...M.groups.map((g) => card(cur === g, `border:2px solid ${ENV[g.env].base};border-radius:50%`, g.label, kfmt(g.calls7), `${g.roles.length + g.more} roles`, () => g.roles[0] && set({ sel: g.roles[0].id })))),
        h('div', { class: 'sp-listhead' }, h('h2', { class: 'eyebrow' }, `${cur ? cur.label : 'Roles'} · roles`), h('span', { class: 'mono faint' }, String(cur ? cur.roles.length : 0))),
        h('div', { class: 'sp-list' }, ...(cur ? cur.roles : []).map((r) => row(st.sel === r.id, `background:${r.denied7 ? RED : ENV[r.cluster.env].base};border-radius:50%`, r.name, r.services.map((x) => x.name).join(' · ') || 'quiet this week', kfmt(r.calls7), () => set({ sel: st.sel === r.id ? null : r.id })))));
    }
    const feed = M.events.length ? M.events.slice(0, 12).map((e) => h('button', { class: 'sp-feed', 'aria-pressed': String(st.sel === e.target && st.hour === e.hour), style: `border-left-color:${TONE[e.tone] || '#fff'}`,
      onClick: () => set({ sel: e.target || st.sel, hour: e.hour }) },
      h('span', { class: 'sp-feed-top' }, h('span', { style: `color:${TONE[e.tone] || '#fff'}` }, e.kind), h('span', { class: 'faint' }, hourLabel(e.hour))), h('span', { class: 'sp-feed-text' }, e.text), h('span', { class: 'faint tiny' }, e.where)))
      : [h('p', { class: 'muted small' }, 'Nothing flagged in the last 24 hours.')];
    const sw = (style) => h('span', { class: 'sp-sw', style });
    const legend = M.view === 'estate' ? [
      [sw('width:30px;height:12px;background:linear-gradient(180deg,#031009,#0b3a26);border:1px solid #2a8a5c'), 'The green plane is your organization; each ring on it is one account'],
      ...M.zones.map((z) => [sw(`width:12px;height:12px;margin:0 9px;background:${ENV[z.id].base}`), ENV[z.id].name]),
      [sw('width:8px;height:8px;margin:0 11px;border-radius:50%;background:#ffd27f'), 'One dot per busy role. Higher and brighter = more calls in 7 days'],
      [sw(`width:30px;border-top:2px dashed ${COLD}`), 'Grey on the floor: cold, never called. The dashed grey part of a ring is the cold share'],
      [sw(`width:30px;height:10px;border-radius:50%;background:radial-gradient(${ENV.production.base},transparent 70%)`), 'Glow under a ring: calls in the hour you picked'],
      [sw('width:10px;height:10px;margin:0 10px;background:#d5dceb;transform:rotate(45deg)'), 'White shapes off the plane are outside your org. Close and low = risky trust, far and high = pinned'],
      [sw('width:30px;border-top:2px dashed #fff'), 'White dashed path: role chaining first seen today'],
      [sw(`width:30px;border-top:2px solid ${RED}`), 'Red is always a problem and always carries a ⚠ tag'],
    ] : [
      [sw('width:30px;height:12px;background:linear-gradient(180deg,#031009,#0b3a26);border:1px solid #2a8a5c'), `The plane is one account: ${M.account.name}`],
      [sw('width:6px;height:14px;margin:0 12px;background:linear-gradient(#eef7f2 0 4px,#9cc7b4 4px 5px,transparent 5px)'), 'Tower: an AWS service. Taller = more calls into it in 7 days'],
      [sw(`width:12px;height:12px;margin:0 9px;border-radius:50%;border:2px solid ${ENV[M.account.environment].base}`), 'Ring: roles that call the same service most'],
      [sw('width:6px;height:6px;margin:0 12px;border-radius:50%;background:#8d9a93'), 'Grey dots round the edge: roles never called'],
      [sw(`width:30px;border-top:2px solid ${ENV[M.account.environment].base}`), 'Thin paths: which services each ring calls. Click a role for its own'],
      [sw('width:12px;height:12px;margin:0 9px;border-radius:50%;border:1.5px solid #9cc7b4'), 'Rings past the edge: accounts that chain in or out'],
      [sw(`width:30px;border-top:2px solid ${RED}`), 'Red is always a problem and always carries a ⚠ tag'],
    ];
    right.replaceChildren(h('section', { class: 'sp-section' }, h('h2', { class: 'eyebrow' }, M.view === 'estate' ? 'Needs a look · last 24 h' : 'In this account · last 24 h'), ...feed),
      h('section', { class: 'sp-section sp-legend' }, h('h2', { class: 'eyebrow' }, 'How to read it'), ...legend.map(([s, t]) => h('div', null, s, h('span', null, t))),
        M.hidden ? h('p', { class: 'faint tiny' }, `${M.hidden} more identities outside the org are in the `, h('a', { href: '#/trust' }, 'Trust map'), '.') : null));
  }
  function renderBar() {
    const hour = st.hour, perHour = Array.from({ length: 24 }, (_, i) => M.groups.reduce((s, g) => s + g.prof[i], 0)), max = Math.max(1, ...perHour);
    const nowEv = M.events.filter((e) => e.hour === hour);
    const play = h('button', { class: 'sp-play', 'aria-label': st.playing ? 'Pause the day' : 'Play the day, one hour at a time', 'aria-pressed': String(st.playing),
      onClick: () => { if (st.playing) { stop(); set({ playing: false }); } else { st.playing = true; st.timer = setInterval(() => { if (!page.isConnected) return stop(); set({ hour: (st.hour + 1) % 24 }); }, 1400); render(); } } },
      svg('svg', { width: 14, height: 14, viewBox: '0 0 14 14', 'aria-hidden': 'true' }, st.playing ? svg('path', { d: 'M3 2v10M11 2v10', stroke: 'currentColor', 'stroke-width': 2.4 }) : svg('path', { d: 'M3 1.5 L12 7 L3 12.5 Z', fill: 'currentColor' })));
    const input = h('input', { type: 'range', min: 0, max: 23, step: 1, value: hour, 'aria-label': 'Hour of the last 24 to show (calls counted in sessions started that hour)', 'aria-valuetext': `${hourLabel(hour)} WIB`,
      onInput: (ev) => { stop(); set({ hour: Number(ev.target.value), playing: false }); } });
    const focused = document.activeElement?.classList?.contains('sp-range');
    input.classList.add('sp-range');
    bar.replaceChildren(play, h('div', { class: 'sp-bar-body' },
      h('div', { class: 'sp-bar-head' }, h('span', null, `${hourLabel(hour)}–${hourLabel(hour + 1)} WIB${hour === 23 ? ' · NOW' : ''} · ${kfmt(perHour[hour])} CALLS`),
        h('span', { style: `color:${nowEv.length ? TONE[nowEv[0].tone] || '#fff' : 'var(--faint)'}` }, nowEv.length ? nowEv.map((e) => `${e.kind}: ${e.text}`).join(' · ') : 'nothing flagged this hour')),
      h('div', { class: 'sp-scrub' }, ...perHour.map((v, i) => { const ev = M.events.find((e) => e.hour === i);
        return h('span', { class: 'sp-col' }, h('span', { class: `sp-fill${i === hour ? ' on' : ''}`, style: `height:${Math.max(3, Math.round((v / max) * 28))}px` }), ev ? h('span', { class: 'sp-mark', style: `background:${TONE[ev.tone] || '#fff'}` }) : null); }), input),
      h('div', { class: 'sp-ticks' }, ...[0, 6, 12, 18, 23].map((i) => h('span', null, i === 23 ? 'now' : hourLabel(i))))));
    if (focused) input.focus();
    hud.replaceChildren(h('div', { class: 'sp-hud-a' }, `● ${M.view === 'estate' ? 'ESTATE' : `${M.account.name.toUpperCase()} · ${M.account.awsAccountId}`} · ${hourLabel(hour)} WIB`),
      h('div', null, M.view === 'estate' ? `${M.groups.length} ACCOUNTS · ${num(M.groups.reduce((s, g) => s + g.roles, 0))} ROLES · ${M.sources.length + M.hidden} OUTSIDE` : `${M.roleCount} ROLES · ${M.roles.length} CALLED THIS WEEK · ${M.towers.length} SERVICES`),
      h('div', null, M.view === 'estate' ? 'HEIGHT = CALLS IN 7 DAYS (LOG) · DRAG TO ORBIT' : 'TOWER = CALLS INTO A SERVICE · DRAG TO ORBIT'));
    cam.replaceChildren(h('span', { class: 'eyebrow' }, 'Camera'), ...[['◀', 'Rotate left', () => set({ az: st.az - 20 })], ['▶', 'Rotate right', () => set({ az: st.az + 20 })],
      ['▲', 'Look from higher', () => set({ el: Math.min(70, st.el + 8) })], ['▼', 'Look from lower', () => set({ el: Math.max(18, st.el - 8) })], ['Reset', 'Reset the camera', () => set({ az: -14, el: 33 })]]
      .map(([icon, label, fn]) => h('button', { 'aria-label': label, title: label, onClick: fn }, icon)));
  }

  render();
  return page;
}
