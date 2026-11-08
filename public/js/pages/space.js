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
// one colour per environment, checked together with every pair compared (colour-blind ΔE ≥ 10, normal vision ≥ 17).
// Shared is a muted olive: the only non-red hue that still clears both floors next to the other four.
// base = rings, paths, swatches; hot/dim = the brightest and faintest stars. Red is never an environment.
const ENV = {
  production: { name: 'Production', base: '#c68405', dim: '#8a5d0a', hot: '#ffd27f' },
  shared: { name: 'Shared', base: '#676815', dim: '#4a4b10', hot: '#dcd98f' },
  staging: { name: 'Staging', base: '#4b95f0', dim: '#3a6db0', hot: '#b3d4ff' },
  development: { name: 'Development', base: '#37ac78', dim: '#2a7f59', hot: '#a6ecc8' },
  sandbox: { name: 'Sandbox', base: '#a947a3', dim: '#7c3878', hot: '#f2b0ec' },
};
const ORDER = ['production', 'shared', 'staging', 'development', 'sandbox'];   // east to west across the plane
const RED = '#ff5a4f', WARN = '#fab219', COLD = '#7a8780', OUT = '#c3cbd9';
const TONE = { high: RED, warn: WARN, info: '#ffffff', good: '#6fe3b0', medium: WARN, low: '#d5dceb' };
const KIND = { 'new-caller': 'NEW CALLER', denied: '⚠ DENIED', grew: 'GREW', unidentified: 'UNIDENTIFIED', 'new-role': 'NEW ROLE', dead: 'COLD', cleaned: 'CLEANED', 'new-path': 'NEW PATH' };
const CM = '#c79a6b', CM_ID = 'cm';                 // Curious Monkey, this portal's own scanner: its own colour and shape
const GLYPH = { oidc: 'oidc', saml: 'saml', 'external-account': 'account', public: 'web' };

const f = (n) => Math.round(n * 10) / 10;
// Identity Center roles read as their permission set: AWSReservedSSO_BackendEngineerNonPrdFA_462eef168f348eab → BackendEngineerNonPrdFA
const pretty = (name) => { const m = String(name).match(/^AWSReservedSSO_(.+?)_[0-9a-f]{16}$/); return m ? { label: m[1], kind: 'SSO permission set' } : { label: String(name), kind: '' }; };
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
  if (kind === 'monkey') { const e = s * 0.45, c = (cx, cy, r) => `M${f(cx - r)} ${f(cy)} a${f(r)} ${f(r)} 0 1 0 ${f(2 * r)} 0 a${f(r)} ${f(r)} 0 1 0 ${f(-2 * r)} 0 Z`; return `${c(x, y, s)} ${c(x - s * 0.95, y - s * 0.35, e)} ${c(x + s * 0.95, y - s * 0.35, e)}`; }
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
      const R = a.planned ? Math.max(14, Math.min(34, 0.4 * Math.min(cw, ch))) : Math.max(14, Math.min(18 + Math.sqrt(a.roles) * 5.5, 0.4 * Math.min(cw, ch)));
      const coldDots = Math.min(a.cold, 16);
      groups.push({ ...a, env, x: cx, y: cy, R, coldShare: a.roles ? a.cold / a.roles : 0, label: a.planned ? `${a.name} · planned` : a.name,
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
  for (const c of d.chains) if (by.has(c.from) && by.has(c.to)) links.push({ ...c, kind: c.isNew ? 'new' : 'chain', vol: Math.min(3, 1 + lg(c.sessions) / 2), at: c.hours.length ? c.hours : null, denied: 0 });
  for (const s of sources) for (const t of s.targets) if (by.has(t.accountId)) links.push({ from: s.id, to: t.accountId, kind: s.worst === 'high' ? 'extHigh' : s.worst === 'medium' ? 'extWarn' : 'ext', vol: 1, at: null, edges: t.edges || [], roles: t.roles.length });
  // Curious Monkey floats above the account its identity lives in (or off the plane when that one is not connected),
  // one dotted path to the scanner role in every account it reads
  let scanner = null;
  if (d.scanner) {
    const home = by.get(d.scanner.homeAccountId);
    scanner = { ...d.scanner, id: CM_ID, ...(home ? { x: home.x, y: home.y, z: 190 } : off(350, 110, 170)), home: home?.id || null };
    for (const t of d.scanner.targets) if (by.has(t.accountId)) links.push({ from: CM_ID, to: t.accountId, kind: 'scan', vol: 1, at: t.hours, target: t });
  }
  links.forEach((l, i) => { l.id = `link:${i}`; });
  const name = (id) => by.get(id)?.name || 'an account';
  const events = [
    ...d.events.map((e) => ({ id: e.id, kind: KIND[e.kind] || e.kind.toUpperCase(), tone: e.severity, hour: e.hour, text: e.title, where: `${name(e.accountId)}${e.roleName ? ` · ${e.roleName}` : ''}`, target: e.accountId })),
    ...d.chains.filter((c) => c.isNew && by.has(c.from) && by.has(c.to)).map((c) => ({ id: `n${c.from}${c.to}`, kind: 'NEW PATH', tone: 'info', hour: c.hours[0] ?? 23, text: `${name(c.from)} entered ${name(c.to)} for the first time`, where: c.roles.slice(0, 2).map((r) => `${r.caller} → ${r.role}`).join(' · '), target: c.to })),
  ].sort((a, b) => b.hour - a.hour);
  return { view: 'estate', zones, groups, by, sources, scanner, hidden: d.outside.hidden, links, events, hourStart: new Date(d.hourStart).getTime(),
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
  // each outside identity gets one path, to a gate at the edge of the plane facing it; the fan from the gate to every role
  // it can enter is drawn only while it is selected
  const gates = sources.map((s) => { const a = Math.atan2(s.y, s.x), r = edgeDist(a) - 22, roles = s.targets.flatMap((t) => t.roles); return { id: `gate:${s.key}`, src: s.id, x: Math.cos(a) * r, y: Math.sin(a) * r, roles, risk: s.risk }; });
  for (const g of gates) {
    const s = sources.find((x) => x.id === g.src);
    links.push({ from: s.id, to: g.id, kind: s.worst === 'high' ? 'extHigh' : s.worst === 'medium' ? 'extWarn' : 'ext', vol: 1, edges: s.targets.flatMap((t) => t.edges || []), roles: g.roles.length });
    for (const id of g.roles) if (byRole.has(id)) links.push({ from: g.id, to: id, kind: 'fan', src: s.id, risk: s.worst, vol: 1 });
  }
  let scanner = null;
  if (d.scanner) {
    scanner = { ...d.scanner, id: CM_ID, ...off(8, 100, 170) };
    for (const t of d.scanner.targets) if (byRole.has(t.roleId)) links.push({ from: CM_ID, to: t.roleId, kind: 'scan', vol: 1, at: t.hours, target: t });
  }
  for (const n of fars) for (const l of n.links) if (byRole.has(l.roleId)) links.push(l.dir === 'in' ? { from: `far:${n.id}`, to: l.roleId, kind: 'in', vol: 2 } : { from: l.roleId, to: `far:${n.id}`, kind: 'out', vol: 2 });
  links.forEach((l, i) => { l.id = `link:${i}`; });
  const events = d.events.map((e) => ({ id: e.id, kind: KIND[e.kind] || e.kind.toUpperCase(), tone: e.severity, hour: e.hour, text: e.title, where: e.roleName || d.account.name, target: e.roleId && byRole.has(e.roleId) ? e.roleId : null }));
  for (const t of towers) t.denied = roles.reduce((n, r) => n + (r.services.find((v) => v.name === t.name)?.denied || 0), 0);
  return { view: 'account', account: d.account, zones: [], groups, roles, byRole, towers, gates, rim, sources, scanner, fars, links, events, hidden: d.outside.hidden,
    coldCount: d.coldCount, roleCount: d.roleCount, hourStart: new Date(d.hourStart).getTime(),
    defaultSel: events.find((e) => e.target)?.target || [...roles].sort((a, b) => b.calls7 - a.calls7)[0]?.id || null };
}

export async function spacePage(ctx) {
  const view = ctx.params.get('view') === 'account' ? 'account' : 'estate';
  const est = await get('/space');
  if (!est.accounts.length) return h('div', { class: 'stack' }, h('h1', null, 'Space'), h('p', { class: 'muted' }, 'No accounts yet. Connect one to see it here.'), h('a', { class: 'btn primary', href: '#/accounts/new' }, 'Connect an account'));
  const live = est.accounts.filter((a) => !a.planned);
  const accountId = ctx.params.get('account') || [...(live.length ? live : est.accounts)].sort((a, b) => b.calls7 - a.calls7)[0].id;
  const M = view === 'estate' ? estateModel(est) : accountModel(await get(`/space/account/${accountId}`));
  ctx.setCrumbs(h('a', { href: '#/space' }, 'Space'), ...(view === 'account' ? [M.account.name] : []));
  const st = { sel: M.defaultSel, hour: M.events.find((e) => e.target === M.defaultSel)?.hour ?? 23, playing: false, az: -14, el: 33, zoom: 1.15, zone: '', timer: null, fit: null, dragging: false };
  const left = h('aside', { class: 'left' }), right = h('aside', { class: 'right' });
  const stage = svg('svg', { class: 'space-svg', viewBox: `0 0 ${W} ${H}`, role: 'img' });
  const box = h('div', { class: 'space-box' }, stage);
  const hud = h('div', { class: 'space-hud', 'aria-live': 'polite' }), cam = h('div', { class: 'space-cam', role: 'group', 'aria-label': 'Camera' });
  const bar = h('div', { class: 'space-timeline' });
  const scene = h('div', { class: 'scene space-scene' }, h('div', { class: 'space-stage' }, box, hud, cam), bar);
  const page = h('div', { class: 'stack space-page', style: 'gap:0' }, h('div', { class: 'scene-layout space-layout' }, left, scene, right));
  const set = (patch) => { if ('sel' in patch && patch.sel !== st.sel) { st.filter = ''; st.showAll = false; } Object.assign(st, patch); render(); };
  const stop = () => { if (st.timer) { clearInterval(st.timer); st.timer = null; } };
  ctx.onLeave(stop);

  // drag to orbit: the framing is held while dragging, then refitted
  let drag = null;
  // the pointer is captured only once a drag has really started: capturing on press would send every click to the
  // scene itself instead of the thing under the pointer, and nothing could be clicked
  stage.addEventListener('pointerdown', (ev) => { if (ev.button === 0) drag = { x: ev.clientX, y: ev.clientY, az: st.az, el: st.el, moved: false, id: ev.pointerId }; });
  stage.addEventListener('pointermove', (ev) => {
    if (!drag) return; const dx = ev.clientX - drag.x, dy = ev.clientY - drag.y;
    if (!drag.moved && Math.hypot(dx, dy) < 5) return;
    if (!drag.moved) { try { stage.setPointerCapture(drag.id); } catch { /* pointer already gone */ } }
    drag.moved = true; st.dragging = true;
    const az = Math.round(drag.az - dx * 0.35), el = Math.max(18, Math.min(70, Math.round(drag.el + dy * 0.2)));
    if (az !== st.az || el !== st.el) { st.az = az; st.el = el; if (!drag.raf) drag.raf = requestAnimationFrame(() => { drag && (drag.raf = 0); render(); }); }
  });
  const endDrag = () => { if (drag?.moved) { st.dragging = false; render(); setTimeout(() => { drag = null; }, 0); } else drag = null; };
  // zoom only when asked: the wheel, or the + and − buttons
  stage.addEventListener('wheel', (ev) => { ev.preventDefault(); set({ zoom: Math.max(0.6, Math.min(3, st.zoom * Math.exp(-ev.deltaY * 0.0015))) }); }, { passive: false });
  stage.addEventListener('pointerup', endDrag); stage.addEventListener('pointercancel', endDrag);
  stage.addEventListener('click', (ev) => { if (drag?.moved) { ev.stopPropagation(); return; } if (ev.target === stage) set({ sel: null }); });

  function camera(fitPts) {
    const D = 2600, el = (st.el * Math.PI) / 180, ce = Math.cos(el), se = Math.sin(el), az = (st.az * Math.PI) / 180, ca = Math.cos(az), sa = Math.sin(az);
    const view = (az, elr) => { const c = Math.cos(az), s2 = Math.sin(az), ce2 = Math.cos(elr), se2 = Math.sin(elr);
      return (x, y, z) => { const X = x * c - y * s2, Y = x * s2 + y * c, vy = Y + D * ce2, vz = z - D * se2, dep = vy * ce2 - vz * se2; return [X / dep, (vy * se2 + vz * ce2) / dep, dep]; }; };
    const p = view(az, el);
    if (!st.fit) {
      // framed once, over every angle the camera can take, so rotating and tilting never change the scale.
      // The frame is centred on the plane, not on what happens to be in view.
      let ext = 0, top = 0, bottom = 0;
      for (let a = 0; a < 360; a += 15) for (let e = 18; e <= 70; e += 13) {
        const q = view((a * Math.PI) / 180, (e * Math.PI) / 180), [ox, ou] = q(0, 0, 0);
        for (const [x, y, z] of fitPts) { const [X, U] = q(x, y, z); ext = Math.max(ext, Math.abs(X - ox)); top = Math.max(top, U - ou); bottom = Math.max(bottom, ou - U); }
      }
      const F = Math.min((W - 40) / (2 * ext), (H - 130) / (top + bottom));
      st.fit = { D, F, top, bottom };
    }
    const F = st.fit.F * st.zoom, [ox, ou] = p(0, 0, 0);
    const CX = W / 2 - F * ox, CY = 90 + st.fit.F * st.fit.top + ((H - 130) - st.fit.F * (st.fit.top + st.fit.bottom)) / 2 + F * ou;
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
    if (M.scanner) ent.set(CM_ID, { p3: [M.scanner.x, M.scanner.y, M.scanner.z], env: 'scanner' });
    if (M.view === 'account') { for (const t of M.towers) ent.set(t.id, { p3: [t.x, t.y, t.h], env: 'svc' }); for (const r of M.roles) ent.set(r.id, { p3: [r.x, r.y, r.z], env: r.cluster.env }); for (const n of M.fars) ent.set(`far:${n.id}`, { p3: [n.x, n.y, 8], env: n.env }); for (const g of M.gates) ent.set(g.id, { p3: [g.x, g.y, 4], env: 'outer' }); }
    const liftOf = (l, a, b) => (l.kind === 'scan' ? 10 : l.kind === 'fan' ? 24 + 0.06 * Math.hypot(b[0] - a[0], b[1] - a[1]) : l.kind === 'use' ? 30 : l.kind === 'use1' ? 34 : l.kind === 'denied' && M.view === 'account' ? 40 : /^ext/.test(l.kind) ? 26 + 0.07 * Math.hypot(b[0] - a[0], b[1] - a[1]) : null);
    const fitPts = [[-560, -380, 0], [560, -380, 0], [560, 380, 0], [-560, 380, 0], [0, -440, 0], ...M.sources.flatMap((s) => [[s.x, s.y, s.z + 14], [s.x, s.y, 0]]), ...(M.fars || []).flatMap((n) => [[n.x - 50, n.y - 50, 0], [n.x + 50, n.y + 50, 0]])];
    if (M.view === 'estate') fitPts.push([-760, 0, 0], [760, 0, 0]);
    if (M.scanner) fitPts.push([M.scanner.x, M.scanner.y, M.scanner.z + 20]);
    for (const l of M.links) { const a = ent.get(l.from), b = ent.get(l.to); if (a && b) fitPts.push(apex3(a.p3, b.p3, l.from < l.to ? 1 : -1, liftOf(l, a.p3, b.p3))); }
    const P = camera(fitPts), ref = (st.fit.F * st.zoom) / st.fit.D, sinEl = Math.sin((st.el * Math.PI) / 180);
    const path = (pts) => `M${pts.map((p) => `${f(p[0])} ${f(p[1])}`).join(' L')}`;
    const ring3 = (cx, cy, r, a0, a1, n = 44) => path(Array.from({ length: n + 1 }, (_, i) => { const a = a0 + ((a1 - a0) * i) / n; return P(cx + Math.cos(a) * r, cy + Math.sin(a) * r, 0); }));
    const pick = (id) => (ev) => { ev.stopPropagation(); set({ sel: sel === id ? null : id }); };
    const out = { floor: [], halo: [], rings: [], towers: [], stems: [], stars: [], arcs: [], paths: [], parts: [], sparks: [], sats: [], marks: [], hits: [], labels: [] };
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
      const a0 = -Math.PI / 2, act = (1 - g.coldShare) * Math.PI * 2;
      if (g.planned) out.rings.push(svg('path', { d: ring3(g.x, g.y, g.R, 0, Math.PI * 2, 48), fill: E.base, 'fill-opacity': 0.05, stroke: E.hot, 'stroke-width': 1.3, 'stroke-dasharray': '3 5', opacity: o2(0.85 * dim) }));
      else out.halo.push(svg('ellipse', { cx: f(c[0]), cy: f(c[1]), rx: f(rx), ry: f(rx * sinEl), fill: `url(#sp-h-${g.env})`, opacity: o2((0.08 + 0.64 * Math.sqrt(g.prof[hour] / maxHour)) * dim) }));
      if (!g.planned) out.rings.push(svg('path', { d: ring3(g.x, g.y, g.R, a0, a0 + act), fill: 'none', stroke: E.base, 'stroke-width': 1.5, opacity: o2(0.95 * dim) }));
      if (!g.planned && g.coldShare > 0.001) out.rings.push(svg('path', { d: ring3(g.x, g.y, g.R, a0 + act, a0 + Math.PI * 2), fill: 'none', stroke: COLD, 'stroke-width': 1.2, 'stroke-dasharray': '2 3', opacity: o2(0.9 * dim) }));
      const k0 = M.view === 'account' ? 1.55 : 1;
      let bx0 = 1e9, by0 = 1e9, bx1 = -1e9, by1 = -1e9, topZ = 0;
      if (g.planned) { const q = P(g.x, g.y, 0); bx0 = bx1 = q[0]; by0 = by1 = q[1]; }
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
      out.hits.push(svg('g', { class: 'sp-hit', onClick: pick(target) }, svg('title', null, M.view === 'estate' ? (g.planned ? `${g.name} · ${ENV[g.env].name} · planned, not onboarded yet` : `${g.name} · ${ENV[g.env].name} · ${g.roles} roles · ${kfmt(g.calls7)} calls in 7 days`) : `${g.label} · ${g.roles.length} roles`),
        svg('circle', { cx: f(hc[0]), cy: f(hc[1]), r: f(Math.max(16, g.R * c[3] * 1.15)), fill: '#000', opacity: 0 })));
      const isSel = M.view === 'estate' ? sel === g.id : selRole?.cluster === g;
      cands.push({ pr: (isSel ? 3000 : 0) + (evNow.some((e) => e.target === g.id) ? 900 : 0) + lg(g.calls7) * 40 + (dim < 1 ? -500 : 0) + (g.planned ? -200 : 0), x: t[0], y: t[1], text: g.label, color: dim < 1 ? '#3c5a4b' : g.planned ? '#8d9a93' : E.base, pick: pick(target), below: fp[2][1] - t[1] + 14 });
      if (M.view === 'estate' && sel === g.id) {
        const x0 = Math.min(bx0, ...fp.map((q) => q[0])) - 6, y0 = Math.min(by0, t[1]) - 6, x1 = Math.max(bx1, ...fp.map((q) => q[0])) + 6, y1 = Math.max(by1, ...fp.map((q) => q[1])) + 6, q = 9;
        out.marks.push(svg('path', { d: ring3(g.x, g.y, g.R * 1.16, 0, Math.PI * 2, 56), fill: 'none', stroke: '#fff', 'stroke-width': 1.6 }));
        out.marks.push(svg('path', { d: `M${f(x0)} ${f(y0 + q)} L${f(x0)} ${f(y0)} L${f(x0 + q)} ${f(y0)} M${f(x1 - q)} ${f(y0)} L${f(x1)} ${f(y0)} L${f(x1)} ${f(y0 + q)} M${f(x1)} ${f(y1 - q)} L${f(x1)} ${f(y1)} L${f(x1 - q)} ${f(y1)} M${f(x0 + q)} ${f(y1)} L${f(x0)} ${f(y1)} L${f(x0)} ${f(y1 - q)}`, fill: 'none', stroke: '#fff', 'stroke-width': 1.4, opacity: 0.9 }));
      }
    }
    if (M.view === 'account') {
      for (const r of M.roles) {
        const p = P(r.x, r.y, r.z); tops.set(r.id, p);
        out.hits.push(svg('g', { class: 'sp-hit', onClick: pick(r.id) }, svg('title', null, `${pretty(r.name).label} · ${kfmt(r.calls7)} calls in 7 days`), svg('circle', { cx: f(p[0]), cy: f(p[1]), r: 7, fill: '#000', opacity: 0 })));
        if (sel === r.id) { out.marks.push(svg('path', { d: glyph('account', p[0], p[1], 9), fill: 'none', stroke: '#fff', 'stroke-width': 1.6 })); out.marks.push(svg('path', { d: ring3(r.cluster.x, r.cluster.y, r.cluster.R * 1.12, 0, Math.PI * 2, 56), fill: 'none', stroke: '#fff', 'stroke-width': 1.1, opacity: 0.55 })); }
      }
      for (const s of M.rim) { const p = P(s.x, s.y, 0); out.stars.push([p[2], svg('circle', { cx: f(p[0]), cy: f(p[1]), r: f(2.1 * Math.max(0.72, p[3] / ref)), fill: '#8d9a93', opacity: 0.85 })]); }
      for (const t of M.towers) {
        const b = P(t.x, t.y, 0), tp = P(t.x, t.y, t.h), k = Math.max(0.72, tp[3] / ref);
        out.towers.push(svg('g', null, svg('line', { x1: f(b[0]), y1: f(b[1]), x2: f(b[0]), y2: f(tp[1]), stroke: '#9cc7b4', 'stroke-width': f(1.4 * k), opacity: 0.55 }),
          svg('ellipse', { cx: f(b[0]), cy: f(b[1]), rx: f(9 * k), ry: f(9 * k * sinEl), fill: 'none', stroke: '#9cc7b4', 'stroke-width': 0.9, opacity: 0.6 }),
          svg('path', { d: glyph('service', tp[0], tp[1], 6 * k), fill: '#eef7f2', stroke: '#fff', 'stroke-width': 0.6, filter: 'url(#sp-glow)' }),
          t.denied ? svg('circle', { cx: f(tp[0]), cy: f(tp[1]), r: f(11 * k), fill: 'none', stroke: RED, 'stroke-width': 1.4, class: 'sp-pulse' }) : null));
        out.hits.push(svg('g', { class: 'sp-hit', onClick: pick(t.id) }, svg('title', null, `${t.name} · ${kfmt(t.calls)} calls in 7 days${t.denied ? ` · ⚠ ${num(t.denied)} refused` : ''}`), svg('circle', { cx: f(tp[0]), cy: f(tp[1]), r: 14, fill: '#000', opacity: 0 })));
        tops.set(t.id, tp);
        cands.push({ pr: 1500 + lg(t.calls) * 40 + (sel === t.id ? 3000 : 0), x: tp[0], y: tp[1] - 4, text: t.name, color: '#9cc7b4', pick: pick(t.id), below: 26 });
        if (sel === t.id) out.marks.push(svg('path', { d: glyph('account', tp[0], tp[1], 11), fill: 'none', stroke: '#fff', 'stroke-width': 1.6 }));
      }
      for (const g of M.gates) {
        const c = P(g.x, g.y, 0), k = Math.max(0.75, c[3] / ref), col = g.risk === 'high' ? RED : g.risk === 'medium' ? WARN : '#d5dceb', on = sel === g.src;
        out.rings.push(svg('g', { class: 'sp-hit', onClick: pick(g.src) }, svg('title', null, `${g.roles.length} roles can be entered from here · click for the list`),
          svg('path', { d: glyph('saml', c[0], c[1], 7 * k), fill: '#03100b', stroke: col, 'stroke-width': on ? 2 : 1.3 }),
          svg('text', { x: f(c[0]), y: f(c[1] + 4 * k), 'text-anchor': 'middle', fill: col, class: 'sp-small', style: 'font-size:9px' }, String(g.roles.length))));
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
      const t = l.from === sel || l.to === sel || sel === l.id || (selRole && l.owner === selRole.id);
      const past = l.at ? l.at.some((x) => x <= hour) : true, now = l.at ? l.at.includes(hour) : false;
      let show = true, color = OUT, w = 1, o = 0.22, dash = null, cls = null, cut = 1, flow = 0, flag = null;
      if (l.kind === 'chain') { color = ENV[a.env]?.base || OUT; w = 0.6 + 0.4 * l.vol; o = t || now ? 0.95 : l.today ? 0.45 : 0.22; flow = t || now ? Math.max(1, Math.round(l.vol)) : 0; }
      else if (l.kind === 'new') { show = true; color = '#fff'; w = 1.8; dash = '6 5'; cls = 'sp-dash'; o = now || t ? 1 : 0.5; flow = now || t ? 2 : 0; flag = { text: 'NEW PATH', bg: '#fff' }; }
      else if (l.kind === 'denied') { show = !!t; color = RED; w = 1.5; dash = '4 4'; cut = 0.72; o = 1; flow = 2; flag = { text: `⚠ ${l.denied} DENIED`, bg: RED }; }
      else if (l.kind === 'fan') { show = sel === l.src; color = l.risk === 'high' ? RED : l.risk === 'medium' ? WARN : OUT; w = 0.8; o = 0.55; }
      else if (l.kind === 'ext') { o = t ? 0.9 : 0.2; flow = t ? 1 : 0; }
      else if (l.kind === 'extWarn') { color = WARN; o = t ? 0.95 : 0.35; flow = t ? 1 : 0; if (t) flag = { text: 'LOOSE TRUST', bg: WARN }; }
      else if (l.kind === 'extHigh') { color = RED; w = 1.4; o = t ? 1 : 0.5; flow = t ? 1 : 0; if (t) flag = { text: '⚠ RISKY TRUST', bg: RED }; }
      else if (l.kind === 'use') { color = ENV[a.env].base; w = 0.5 + 1.6 * l.vol; o = selRole ? 0.12 : 0.28; }
      else if (l.kind === 'use1') { show = t; color = ENV[a.env].hot; w = 1.4; o = 0.95; flow = 1; }
      else if (l.kind === 'scan') { color = CM; w = 1.1; dash = '1.5 4'; o = t || now ? 0.95 : 0.3; flow = now ? 1 : 0; }
      else if (l.kind === 'in' || l.kind === 'out') { color = ENV[(ent.get(l.kind === 'in' ? l.from : l.to)).env]?.base || OUT; w = 1.3; o = t ? 0.95 : 0.45; flow = t ? 2 : 1; }
      if (!show) continue;
      if (focus && focus !== 'outer' && a.env !== focus && b.env !== focus) o *= 0.25;
      if (focus === 'outer' && a.env !== 'outer' && b.env !== 'outer') o *= 0.25;
      const g3 = arc3(a.p3, b.p3, l.from < l.to ? 1 : -1, P, liftOf(l, a.p3, b.p3));
      out.arcs.push(svg('path', { d: cut < 1 ? g3.part(cut) : g3.d, fill: 'none', stroke: color, 'stroke-width': f(sel === l.id ? w + 1.2 : w), opacity: o2(o), 'stroke-dasharray': dash, class: cls, 'stroke-linecap': 'round' }));
      // every path but the per-cluster service bundles can be clicked: a wide invisible stroke along it
      const ext = /^ext/.test(l.kind), mid = g3.pts[ext ? 6 : 12];
      tops.set(l.id, mid);
      if (l.kind !== 'use' && l.kind !== 'fan' && o > 0.15) out.paths.push(svg('path', { class: 'sp-hit', d: cut < 1 ? g3.part(cut) : g3.d, fill: 'none', stroke: '#000', 'stroke-opacity': 0, 'stroke-width': 12, 'pointer-events': 'stroke', onClick: pick(l.id) },
        svg('title', null, linkTitle(l))));
      if (sel === l.id) out.marks.push(svg('circle', { cx: f(mid[0]), cy: f(mid[1]), r: 6, fill: 'none', stroke: '#fff', 'stroke-width': 1.6 }));
      if (cut < 1 && t) { const q = g3.pts[Math.round(cut * 24)]; out.sparks.push(svg('g', null, svg('circle', { cx: f(q[0]), cy: f(q[1]), r: 5, fill: 'none', stroke: RED, 'stroke-width': 1.4, class: 'sp-pulse' }))); }
      if (motion) for (let i = 0; i < flow; i++) {
        const dur = 3.4, begin = `${f(-(i * dur) / flow - rnd() * 0.8)}s`, c = l.kind === 'denied' ? RED : color;
        out.parts.push(svg('circle', { r: 2.2, fill: c, filter: 'url(#sp-glow)', opacity: 0 },
          svg('animateMotion', { path: g3.d, dur: `${dur}s`, begin, repeatCount: 'indefinite', keyPoints: cut < 1 ? `0;${cut}` : '0;1', keyTimes: '0;1', calcMode: 'linear' }),
          svg('animate', { attributeName: 'opacity', values: '0;0.95;0.95;0', keyTimes: '0;0.1;0.8;1', dur: `${dur}s`, begin, repeatCount: 'indefinite' })));
      }
      if (flag && (now || t)) { const q = g3.pts[cut < 1 ? 10 : ext ? 6 : 12]; flagC.push({ x: q[0], y: q[1], text: flag.text, bg: flag.bg, pr: (sel === l.id ? 2 : 0) + (now ? 1 : 0), pick: pick(l.id) }); }
    }

    // the selection is marked on the map; its details are in the sidebar
    if (sel && tops.has(sel)) { const [ax, ay] = tops.get(sel); out.marks.push(svg('circle', { cx: f(ax), cy: f(ay), r: 3, fill: '#fff' })); }

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
    if (M.scanner) {
      const sc = M.scanner, p = P(sc.x, sc.y, sc.z), g0 = P(sc.x, sc.y, 0), on = sel === CM_ID, today = sc.targets.filter((t) => t.hours.includes(hour)).length;
      tops.set(CM_ID, p);
      const label = 'Curious Monkey', sub = `this portal's scanner · ${sc.targets.length} account${sc.targets.length === 1 ? '' : 's'}`;
      const w = Math.max(label.length * 6.7, sub.length * 6.15) + 4;
      const tries = [['start', p[0] + 18, p[1] - 2], ['end', p[0] - 18, p[1] - 2], ['middle', p[0], p[1] - 30]];
      let pl = tries[0];
      for (const tr of tries) { const x0 = tr[0] === 'start' ? tr[1] : tr[0] === 'end' ? tr[1] - w : tr[1] - w / 2, r = [x0, tr[2] - 11, x0 + w, tr[2] + 17]; if (fits(r)) { pl = tr; blocks.push(r); break; } }
      blocks.push([p[0] - 16, p[1] - 16, p[0] + 16, p[1] + 16]);
      if (on) out.marks.push(svg('circle', { cx: f(p[0]), cy: f(p[1]), r: 17, fill: 'none', stroke: '#fff', 'stroke-width': 1.6 }));
      out.sats.push(svg('g', { class: 'sp-hit', onClick: pick(CM_ID), opacity: focus ? 0.4 : 1 },
        svg('title', null, `Curious Monkey · this portal's scanner${today ? ` · reading ${today} account${today === 1 ? '' : 's'} in this hour` : ''} · click for where it reads`),
        svg('line', { x1: f(p[0]), y1: f(p[1]), x2: f(g0[0]), y2: f(g0[1]), stroke: CM, 'stroke-width': 0.8, 'stroke-dasharray': '1.5 3.5', opacity: 0.7 }),
        svg('circle', { cx: f(p[0]), cy: f(p[1]), r: 16, fill: '#000', opacity: 0 }),
        svg('path', { d: glyph('monkey', p[0], p[1], 7), fill: CM, stroke: '#fff', 'stroke-width': 0.8, filter: 'url(#sp-glow)' }),
        today ? svg('circle', { cx: f(p[0]), cy: f(p[1]), r: 13, fill: 'none', stroke: CM, 'stroke-width': 1.2, class: 'sp-pulse' }) : null,
        svg('text', { x: f(pl[1]), y: f(pl[2]), 'text-anchor': pl[0], fill: '#f3e3d0', class: 'sp-name' }, label),
        svg('text', { x: f(pl[1]), y: f(pl[2] + 13), 'text-anchor': pl[0], fill: '#c9b39b', class: 'sp-small' }, sub)));
    }
    for (const c of flagC.sort((a, x) => x.pr - a.pr)) {
      const bw = Math.round(c.text.length * 6.3 + 14);
      for (const [dx, dy] of [[0, -22], [bw / 2 + 12, -14], [-bw / 2 - 12, -14], [0, 22], [0, -44]]) {
        const cx = c.x + dx, cy = c.y + dy, r = [cx - bw / 2, cy - 9, cx + bw / 2, cy + 9];
        if (!fits(r)) continue;
        blocks.push(r);
        out.labels.push(svg('g', { class: 'sp-hit', onClick: c.pick }, svg('title', null, 'What is this about?'), svg('line', { x1: f(c.x), y1: f(c.y), x2: f(cx), y2: f(dy < 0 ? r[3] : r[1]), stroke: c.bg, 'stroke-width': 0.9, opacity: 0.8 }),
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
      svg('g', { 'pointer-events': 'none' }, ...out.arcs, ...out.parts, ...out.sparks), ...out.paths, ...out.sats, svg('g', { 'pointer-events': 'none' }, ...out.marks), ...out.hits, ...out.labels);
    const typing = document.activeElement?.classList?.contains('sp-filter');
    renderSide(); renderBar();
    if (typing) { const i = right.querySelector('.sp-filter'); if (i) { i.focus(); i.setSelectionRange(i.value.length, i.value.length); } }
  }

  // ---------- the card ----------
  function nameOf(id) {
    if (M.view === 'estate' && M.by.has(id)) return M.by.get(id).name;
    if (id === CM_ID) return 'Curious Monkey';
    const s = M.sources.find((x) => x.id === id); if (s) return s.label;
    if (M.view === 'account') {
      if (M.byRole.has(id)) return M.byRole.get(id).name;
      const t = M.towers.find((x) => x.id === id); if (t) return t.name;
      const n = M.fars.find((x) => `far:${x.id}` === id); if (n) return n.name;
      const g = M.groups.find((x) => x.id === id); if (g) return g.label;
    }
    return 'somewhere';
  }
  function linkTitle(l) {
    const a = nameOf(l.from), b = nameOf(l.to);
    if (/^ext/.test(l.kind)) return `${a} can enter ${b}${l.kind === 'extHigh' ? ' · risky trust' : l.kind === 'extWarn' ? ' · loose trust' : ''} · click for the trust statement`;
    if (l.kind === 'chain' || l.kind === 'new') return `${a} entered ${b} · ${num(l.sessions)} sessions in 90 days${l.today ? ` · ${l.today} today` : ''}${l.kind === 'new' ? ' · first seen today' : ''} · click for who`;
    if (l.kind === 'denied') return `${a} → ${b} · ${l.denied} calls refused in 7 days`;
    if (l.kind === 'scan') return `Curious Monkey reads ${b} through ${pretty(l.target.role).label} · ${num(l.target.sessions)} sign-ins in 90 days · click for more`;
    return `${a} → ${b}`;
  }
  const clip = (t, n = 170) => (t.length > n ? `${t.slice(0, n - 1)}…` : t);
  function linkDetail(l) {
    const row = (k, v, tone) => ({ k, v: String(v), tone });
    const a = nameOf(l.from), b = nameOf(l.to);
    if (/^ext/.test(l.kind)) {
      const s = M.sources.find((x) => x.id === l.from), edges = l.edges || [];
      const acct = M.view === 'estate' ? M.by.get(l.to) : M.account;
      // the worst statement in full, the rest by name
      const e = edges[0], rows = [];
      if (e) {
        rows.push(row(edges.length > 1 ? 'Worst statement · role' : 'Role it can enter', pretty(e.role).label));
        rows.push(row('Why it is flagged', e.findings.length ? clip(e.findings.map((x) => `${x.title}${x.detail ? `: ${x.detail}` : ''}`).join(' · '), 220) : 'nothing flagged', e.findings.some((x) => x.severity === 'high') ? 'bad' : null));
        rows.push(row('Trusts', clip(e.principal, 120)));
        rows.push(row('Only when', e.conditions.length ? clip(e.conditions.join(' and '), 160) : 'no conditions', e.conditions.length ? null : 'bad'));
        rows.push(row('Used', e.sessions ? `${num(e.sessions)} sessions, last ${ago(e.lastSeen)}` : 'never seen used'));
      }
      const q = `account:${acct.awsAccountId} ${s.group === 'external-account' ? `from:${s.key.replace(/^acct:/, '')}` : s.group === 'public' ? 'source:public' : `provider:"${s.label}"`}`;
      return { eyebrow: `TRUST · ${s.group.toUpperCase()}`, title: `${a} → ${b}`, sub: `can enter ${edges.length || l.roles || 1} role${(edges.length || l.roles || 1) === 1 ? '' : 's'} in ${acct.name}`, swatch: l.kind === 'extHigh' ? RED : l.kind === 'extWarn' ? WARN : '#d5dceb', round: true,
        tags: l.kind === 'extHigh' ? [{ t: '⚠ RISKY TRUST', c: RED }] : l.kind === 'extWarn' ? [{ t: 'LOOSE TRUST', c: WARN }] : [],
        rows: rows.length ? rows : [row('Trust', s.findings.join('; ') || 'nothing flagged')],
        lists: edges.length > 1 ? [{ title: 'Roles it can enter', items: roleItems(edges, []) }] : [],
        actions: [['Trust map', `#/trust?q=${encodeURIComponent(q)}`, true], ...(edges[0] ? [['Open role', `#/roles/${edges[0].roleId}`]] : [])] };
    }
    if (l.kind === 'scan') {
      const t = l.target, acct = M.view === 'estate' ? M.by.get(t.accountId) : M.account;
      return { eyebrow: 'CURIOUS MONKEY · SCANNER', title: `Curious Monkey → ${acct?.name || b}`, sub: `reads it through ${t.role}`, swatch: CM, round: true, tags: [],
        rows: [row('Scanner role', t.role), row('Signed in', t.sessions ? `${num(t.sessions)} times in 90 days, last ${ago(t.lastSeen)}` : 'not seen in CloudTrail yet'),
          row('Today', t.hours.length ? t.hours.map(hourLabel).join(', ') : 'no sign-in in the last 24 h'), row('Last scan', t.lastScan ? ago(t.lastScan) : 'never')],
        actions: [['Open role', `#/roles/${t.roleId}`, true], ['Its calls', `#/events?account=${t.accountId}&role=${t.roleId}&range=24h`]] };
    }
    if (l.kind === 'chain' || l.kind === 'new') {
      const who = [];
      if (l.moreRoles) who.push(row('And', `${l.moreRoles} more role pairs not listed`));
      const top = l.roles[0];
      return { eyebrow: l.kind === 'new' ? 'ACCOUNT TO ACCOUNT · FIRST SEEN TODAY' : 'ACCOUNT TO ACCOUNT', title: `${a} → ${b}`, sub: `${num(l.sessions)} sessions in 90 days · last ${ago(l.lastSeen)}`, swatch: l.kind === 'new' ? '#fff' : ENV[M.by.get(l.from).env].base, round: true,
        tags: l.kind === 'new' ? [{ t: 'NEW PATH', c: '#fff' }] : [],
        lists: [{ title: 'Who entered what', items: l.roles.map((r) => ({ label: `${pretty(r.caller).label} → ${pretty(r.role).label}`, meta: `last ${ago(r.lastSeen)}`, value: `${num(r.sessions)}`, href: `#/roles/${r.roleId}` })) }],
        rows: [...who, row('Today', l.today ? `${num(l.today)} session${l.today === 1 ? '' : 's'} at ${l.hours.map((x) => hourLabel(x)).join(', ')} WIB` : 'nothing today')],
        actions: [...(top ? [['Its calls', `#/events?role=${top.roleId}&q=${encodeURIComponent(`user:${top.caller.replace(/^user\//, '')}`)}&range=7d`, true]] : []), [`Open ${b}`, `#/space?view=account&account=${l.to}`], ...(top ? [['Role', `#/roles/${top.roleId}`]] : [])] };
    }
    if (l.kind === 'denied') return { eyebrow: 'REFUSED CALLS', title: `${a} → ${b}`, sub: '7 days', swatch: RED, round: true, tags: [{ t: `⚠ ${num(l.denied)} DENIED`, c: RED }],
      rows: [row('What it means', `${num(l.denied)} calls from ${a} to ${b} were refused by IAM. A missing permission, or something trying what it should not.`, 'bad')], actions: [['Open role', `#/roles/${l.from}`, true]] };
    if (l.kind === 'in' || l.kind === 'out') return { eyebrow: 'ROLE CHAINING · 7 DAYS', title: `${a} → ${b}`, sub: 'between this account and a neighbour', swatch: '#9cc7b4', round: true, tags: [], rows: [], actions: [] };
    if (l.kind === 'use1') return { eyebrow: 'CALLS · 7 DAYS', title: `${a} → ${b}`, sub: '', swatch: '#9cc7b4', round: true, tags: [], rows: [], actions: [] };
    return null;
  }
  function detail(id) {
    const row = (k, v, tone) => ({ k, v: String(v), tone });
    const tag = (t, c) => ({ t, c });
    if (id?.startsWith('link:')) { const l = M.links.find((x) => x.id === id); return l ? linkDetail(l) : null; }
    if (id === CM_ID && M.scanner) {
      const sc = M.scanner, acctName = (aid) => (M.view === 'estate' ? M.by.get(aid)?.name : M.account.name) || 'an account';
      const linkOf = (t) => M.links.find((l) => l.kind === 'scan' && l.target === t)?.id || null;
      const home = M.view === 'estate' && sc.home ? M.by.get(sc.home).name : null;
      return { eyebrow: "CURIOUS MONKEY · THIS PORTAL'S SCANNER", title: 'Curious Monkey', sub: home ? `runs as an identity in ${home}` : sc.homeAws ? `runs as an identity in ${sc.homeAws}` : 'the workers that scan your accounts', swatch: CM, round: true, tags: [],
        rows: [...sc.identities.slice(0, 3).map((x) => row('Identity', x.replace(/^arn:aws[a-z-]*:iam::/, ''))),
          row('Signs in to', `${sc.targets.length} account${sc.targets.length === 1 ? '' : 's'}`),
          row('This hour', `${sc.targets.filter((t) => t.hours.includes(st.hour)).length} of them`)],
        lists: [{ title: 'Where it reads', items: [...sc.targets].sort((a, b) => b.sessions - a.sessions).map((t) => ({ label: acctName(t.accountId), meta: `${pretty(t.role).label} · ${t.sessions ? `last ${ago(t.lastSeen)}` : 'no sign-in seen yet'}`, value: num(t.sessions), pick: linkOf(t), href: linkOf(t) ? null : `#/roles/${t.roleId}` })), empty: 'no scanner role found' }],
        actions: [['Workers', '#/workers', true], ['Accounts', '#/accounts']] };
    }
    if (M.view === 'estate') {
      const g = M.by.get(id);
      if (g?.planned) return { eyebrow: `PLANNED · ${ENV[g.env].name.toUpperCase()}${g.ou ? ` · ${g.ou}` : ''}`, title: g.name, sub: g.awsAccountId, swatch: ENV[g.env].base, tags: [tag('NOT ONBOARDED', '#d5dceb')],
        rows: [...(g.note ? [row('Note', g.note)] : []), row('Status', 'A placeholder: nothing is read from this account until it is onboarded.')],
        actions: [['Onboard', `#/accounts/new?from=${g.id}`, true], ['Accounts', '#/accounts']] };
      if (g) {
        const look = M.events.find((e) => e.target === g.id);
        const ins = M.links.filter((l) => l.to === g.id && (l.kind === 'chain' || l.kind === 'new')).map((l) => `${M.by.get(l.from).name}${l.kind === 'new' ? ' (new)' : ''}`);
        const outs = M.links.filter((l) => l.from === g.id && (l.kind === 'chain' || l.kind === 'new')).map((l) => M.by.get(l.to).name);
        const none = 'no other account in 90 days';
        const today = g.hourly.reduce((s, x) => s + x.sessions, 0);
        return { eyebrow: `ACCOUNT · ${ENV[g.env].name.toUpperCase()}${g.ou ? ` · ${g.ou}` : ''}`, title: g.name, sub: g.awsAccountId, swatch: ENV[g.env].base,
          tags: [...(g.high ? [{ t: `⚠ ${g.high} HIGH-RISK ROLE${g.high === 1 ? '' : 'S'}`, c: RED, href: `#/roles?accounts=${g.id}&risks=High` }] : []), ...(look ? [tag(look.kind, TONE[look.tone] || '#fff')] : [])],
          rows: [row('Roles', `${g.roles} · ${g.active} called · ${g.cold} never called`), row('Calls', `${kfmt(g.calls7)} in 7 days · ${today} sessions today`),
            ...(look ? [row('Look at', `${look.text} (${hourLabel(look.hour)})`, 'bad')] : [])],
          lists: [{ title: 'Entered from', items: M.links.filter((l) => l.to === g.id && (l.kind === 'chain' || l.kind === 'new')).map((l) => ({ label: M.by.get(l.from).name, meta: `${l.roles.length} role pair${l.roles.length === 1 ? '' : 's'} · last ${ago(l.lastSeen)}${l.kind === 'new' ? ' · new today' : ''}`, value: num(l.sessions), pick: l.id })), empty: none },
            { title: 'Reaches', items: M.links.filter((l) => l.from === g.id && (l.kind === 'chain' || l.kind === 'new')).map((l) => ({ label: M.by.get(l.to).name, meta: `${l.roles.length} role pair${l.roles.length === 1 ? '' : 's'} · last ${ago(l.lastSeen)}`, value: num(l.sessions), pick: l.id })), empty: none }],
          actions: [['Zoom in', `#/space?view=account&account=${g.id}`, true], ['Its calls', `#/events?account=${g.id}`], ['Account radar', `#/?view=account&account=${g.id}`]] };
      }
    }
    const s = M.sources.find((x) => x.id === id);
    if (s) {
      const items = M.view === 'estate'
        ? s.targets.map((t) => ({ label: M.by.get(t.accountId)?.name || 'an account', meta: `${t.roles.length} role${t.roles.length === 1 ? '' : 's'}${t.sessions ? ` · ${num(t.sessions)} sessions` : ''}`, pick: t.accountId }))
        : roleItems(s.targets.flatMap((t) => t.edges || []), s.targets.flatMap((t) => t.roles));
      return { eyebrow: `OUTSIDE · ${s.group.toUpperCase()}`, title: s.label, sub: s.sub, swatch: '#d5dceb', round: true,
        tags: s.risk === 'high' ? [tag('⚠ HIGH', RED)] : s.risk === 'medium' ? [tag('LOOSE TRUST', WARN)] : [],
        rows: [row('Trust', s.findings.length ? s.findings.join('; ') : 'conditions pinned: nothing to flag', s.findings.length ? 'bad' : 'ok'),
          row('Seen', s.sessions ? `${num(s.sessions)} sessions · last ${ago(s.lastSeen)}` : 'never seen coming in')],
        lists: [{ title: M.view === 'estate' ? 'Accounts it can enter' : 'Roles it can enter', items }],
        actions: [['Trust map', `#/trust?q=${encodeURIComponent(s.group === 'external-account' ? `from:${s.key.replace(/^acct:/, '')}` : s.group === 'public' ? 'source:public' : `provider:"${s.label}"`)}`, true]] };
    }
    if (M.view !== 'account') return null;
    const r = M.byRole.get(id);
    if (r) {
      const p = pretty(r.name);
      const callers = M.sources.filter((x) => x.targets.some((t) => t.roles.includes(r.id))).map((x) => ({ label: x.label, meta: x.sub, tone: x.risk === 'high' ? 'bad' : null, pick: x.id }));
      const cmT = M.scanner?.targets.find((t) => t.roleId === r.id);
      if (cmT) callers.unshift({ label: 'Curious Monkey', meta: `this portal's scanner · last ${ago(cmT.lastSeen)}`, value: num(cmT.sessions), pick: CM_ID });
      const chained = M.fars.flatMap((n) => n.links.filter((l) => l.roleId === r.id).map((l) => ({ label: `${n.name} · ${l.otherRole}`, meta: l.dir === 'in' ? 'chains in' : 'it chains out to', value: `${l.sessions}`, pick: `far:${n.id}` })));
      return { eyebrow: `ROLE · ${r.cluster.label.toUpperCase()}`, title: p.label, sub: p.kind ? `${p.kind} · ${r.name}` : `${M.account.name} · ${M.account.awsAccountId}`, swatch: ENV[r.cluster.env].base, round: true,
        tags: [...(r.risk === 'High' ? [{ t: '⚠ HIGH RISK', c: RED, href: `#/roles/${r.id}` }] : []), ...(r.denied7 ? [tag(`⚠ ${num(r.denied7)} DENIED`, RED)] : [])],
        rows: [row('Calls', `${kfmt(r.calls7)} in 7 days`)],
        lists: [{ title: 'Calls into', items: r.services.map((v) => ({ label: v.name, value: kfmt(v.calls), meta: v.denied ? `⚠ ${num(v.denied)} refused` : null, tone: v.denied ? 'bad' : null, pick: `svc:${v.name}` })) },
          { title: 'Entered by', items: [...callers, ...chained], empty: 'only callers inside this account' }],
        actions: [['Open role', `#/roles/${r.id}`, true], ['Its calls', `#/events?role=${r.id}&range=7d`], ['Blast radius', `#/?view=blast&key=${encodeURIComponent(`role:${M.account.awsAccountId}:${r.name}`)}`]] };
    }
    const t = M.towers.find((x) => x.id === id);
    if (t) {
      const users = M.roles.map((x) => ({ x, v: x.services.find((v) => v.name === t.name) })).filter((u) => u.v).sort((a, c) => c.v.calls - a.v.calls);
      return { eyebrow: 'AWS SERVICE', title: t.name, sub: `${users.length} roles call it`, swatch: '#eef7f2', tags: t.denied ? [tag(`⚠ ${num(t.denied)} REFUSED`, RED)] : [],
        rows: [row('Calls', `${kfmt(t.calls)} in 7 days`)],
        lists: [{ title: 'Roles that call it', items: users.map(({ x, v }) => ({ label: pretty(x.name).label, meta: v.denied ? `⚠ ${num(v.denied)} refused` : pretty(x.name).kind || null, value: kfmt(v.calls), tone: v.denied ? 'bad' : null, pick: x.id })) }],
        actions: [['Its calls', `#/events?account=${M.account.id}&q=${encodeURIComponent(`action:${t.name}:`)}&range=7d`, true]] };
    }
    const n = M.fars.find((x) => `far:${x.id}` === id);
    if (n) return { eyebrow: 'NEIGHBOURING ACCOUNT', title: n.name, sub: `${n.links.reduce((a, l) => a + l.sessions, 0)} chained sessions in 7 days`, swatch: ENV[n.env].base, tags: [], rows: [],
      lists: [{ title: 'Role chaining', items: n.links.map((l) => ({ label: `${l.otherRole} ${l.dir === 'in' ? '→' : '←'} ${pretty(M.byRole.get(l.roleId)?.name || 'a role here').label}`, meta: l.dir === 'in' ? 'comes in' : 'goes out', value: String(l.sessions), pick: l.roleId })) }],
      actions: [['Open in Space', `#/space?view=account&account=${n.id}`, true]] };
    return null;
  }
  // roles an outside identity can enter, readable: permission-set names, what was flagged, whether it was used
  function roleItems(edges, ids) {
    const seen = new Set(), out = [];
    for (const e of edges) {
      if (seen.has(e.roleId)) continue; seen.add(e.roleId);
      const p = pretty(e.role), drawn = M.byRole?.get(e.roleId);
      out.push({ label: p.label, meta: [e.findings.length ? `⚠ ${e.findings[0].title}` : null, e.sessions ? `used ${num(e.sessions)}×, last ${ago(e.lastSeen)}` : 'never used', drawn ? drawn.cluster.label : null].filter(Boolean).join(' · '),
        tone: e.worst === 'high' ? 'bad' : null, pick: drawn ? e.roleId : null, href: drawn ? null : `#/roles/${e.roleId}` });
    }
    for (const rid of ids) if (!seen.has(rid)) { seen.add(rid); const x = M.byRole?.get(rid); out.push({ label: x ? pretty(x.name).label : 'a role', pick: x ? rid : null, href: x ? null : `#/roles/${rid}` }); }
    return out.sort((a, b) => (a.tone === 'bad' ? 0 : 1) - (b.tone === 'bad' ? 0 : 1) || a.label.localeCompare(b.label));
  }
  function panelEl(b) {
    const list = (L) => {
      const ul = h('ul', { class: 'sp-items' }), more = h('button', { class: 'btn sm sp-more' });
      const item = (it) => {
        const body = [h('span', { class: 'sp-item-main' }, h('span', { class: 'sp-item-label' }, it.label), it.meta ? h('span', { class: 'sp-item-meta' }, it.meta) : null), it.value != null ? h('span', { class: 'mono sp-item-val' }, it.value) : null];
        return h('li', { class: it.tone ? `sp-${it.tone}` : null }, it.pick ? h('button', { class: 'sp-item', title: it.label, onClick: () => set({ sel: it.pick }) }, ...body)
          : it.href ? h('a', { class: 'sp-item', href: it.href, title: it.label }, ...body) : h('div', { class: 'sp-item' }, ...body));
      };
      const draw = () => {
        const q = (st.filter || '').toLowerCase(), m = L.items.filter((it) => !q || `${it.label} ${it.meta || ''}`.toLowerCase().includes(q));
        const shown = st.showAll ? m : m.slice(0, 25);
        ul.replaceChildren(...(m.length ? shown.map(item) : [h('li', { class: 'muted small sp-empty' }, q ? 'Nothing matches.' : L.empty || 'None.')]));
        more.hidden = m.length <= shown.length; more.textContent = `Show all ${m.length}`;
      };
      more.addEventListener('click', () => { st.showAll = true; draw(); });
      const filter = L.items.length > 8 && h('input', { type: 'search', class: 'sp-filter', placeholder: `Filter ${L.items.length}…`, 'aria-label': `Filter ${L.title}`, value: st.filter || '',
        onInput: (ev) => { st.filter = ev.target.value; st.showAll = false; draw(); } });
      draw();
      return h('section', { class: 'sp-list-block' }, h('div', { class: 'sp-lh' }, h('h3', { class: 'eyebrow' }, L.title), h('span', { class: 'mono faint' }, String(L.items.length))), filter || null, ul, more);
    };
    return h('section', { class: 'sp-panel', 'aria-label': `Selected: ${b.title}` },
      h('div', { class: 'sp-card-head' },
        h('div', { class: 'sp-card-titles' },
          h('div', { class: 'sp-eyebrow' }, h('span', null, b.eyebrow), ...b.tags.map((t) => t.href ? h('a', { class: 'sp-tag sp-tag-link', href: t.href, title: 'Show them', style: `color:${t.c};border-color:${t.c}` }, `${t.t} →`) : h('span', { class: 'sp-tag', style: `color:${t.c};border-color:${t.c}` }, t.t))),
          h('div', { class: 'sp-card-title' }, h('span', { class: 'sp-swatch', style: `background:${b.swatch}${b.round ? ';border-radius:50%' : ''}` }), h('b', null, b.title)),
          b.sub ? h('span', { class: 'sp-card-sub' }, b.sub) : null),
        h('button', { class: 'sp-x', 'aria-label': 'Close', onClick: () => set({ sel: null }) }, '×')),
      b.rows.length ? h('dl', null, ...b.rows.map((r) => h('div', null, h('dt', null, r.k), h('dd', { class: r.tone ? `sp-${r.tone}` : null }, r.v)))) : null,
      ...(b.lists || []).map(list),
      b.actions.length ? h('div', { class: 'sp-card-actions' }, ...b.actions.map(([label, href, primary]) => h('a', { class: primary ? 'btn primary small' : 'btn small', href }, label))) : null);
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
        const planned = gs.filter((g) => g.planned).length;
        return card(focus === z.id, `background:${ENV[z.id].base}`, ENV[z.id].name, kfmt(gs.reduce((s, g) => s + g.calls7, 0)), `${gs.length - planned} accounts · ${roles ? Math.round((100 * cold) / roles) : 0}% cold${planned ? ` · ${planned} planned` : ''}`, () => set({ zone: focus === z.id ? '' : z.id }));
      });
      const highs = M.sources.filter((s) => s.risk === 'high').length, loose = M.sources.filter((s) => s.risk === 'medium').length;
      zones.push(card(focus === 'outer', 'background:#d5dceb;transform:rotate(45deg);width:10px;height:10px;margin:0 1px', 'Outside your org', String(M.sources.length + M.hidden), `${highs} risky · ${loose} loose trust`, () => set({ zone: focus === 'outer' ? '' : 'outer' })));
      const list = M.groups.filter((g) => !focus || focus === 'outer' || g.env === focus).sort((a, b) => b.calls7 - a.calls7);
      left.replaceChildren(tabs, h('h2', { class: 'eyebrow' }, 'Zones · click to focus'), h('div', { class: 'sp-cards' }, ...zones),
        h('div', { class: 'sp-listhead' }, h('h2', { class: 'eyebrow' }, 'Accounts · 7-day calls'), h('span', { class: 'mono faint' }, String(list.length))),
        h('div', { class: 'sp-list' }, ...list.map((g) => row(st.sel === g.id, g.planned ? `border:1.5px dashed ${ENV[g.env].hot}` : `background:${ENV[g.env].base}`, g.name, g.planned ? `${g.awsAccountId} · planned` : g.awsAccountId, g.planned ? '—' : kfmt(g.calls7), () => set({ sel: st.sel === g.id ? null : g.id })))));
    } else {
      const cur = selRole?.cluster || M.groups[0];
      const accounts = h('select', { class: 'sp-select', 'aria-label': 'Account', onChange: (ev) => go(`#/space?view=account&account=${ev.target.value}`) },
        ...est.accounts.filter((a) => !a.planned).map((a) => h('option', { value: a.id, selected: a.id === accountId }, a.name)));
      left.replaceChildren(tabs, accounts, h('h2', { class: 'eyebrow' }, 'Roles by the service they call most'),
        h('div', { class: 'sp-cards' }, ...M.groups.map((g) => card(cur === g, `border:2px solid ${ENV[g.env].base};border-radius:50%`, g.label, kfmt(g.calls7), `${g.roles.length + g.more} roles`, () => g.roles[0] && set({ sel: g.roles[0].id })))),
        h('div', { class: 'sp-listhead' }, h('h2', { class: 'eyebrow' }, `${cur ? cur.label : 'Roles'} · roles`), h('span', { class: 'mono faint' }, String(cur ? cur.roles.length : 0))),
        h('div', { class: 'sp-list' }, ...(cur ? cur.roles : []).map((r) => row(st.sel === r.id, `background:${r.denied7 ? RED : ENV[r.cluster.env].base};border-radius:50%`, pretty(r.name).label, r.services.map((x) => x.name).join(' · ') || 'quiet this week', kfmt(r.calls7), () => set({ sel: st.sel === r.id ? null : r.id })))));
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
      ...(M.groups.some((g) => g.planned) ? [[sw('width:12px;height:12px;margin:0 9px;border-radius:50%;border:1.5px dashed #d5dceb'), 'Dashed empty ring: planned, not onboarded yet']] : []),
      [sw(`width:30px;height:10px;border-radius:50%;background:radial-gradient(${ENV.production.base},transparent 70%)`), 'Glow under a ring: calls in the hour you picked'],
      [sw('width:10px;height:10px;margin:0 10px;background:#d5dceb;transform:rotate(45deg)'), 'White shapes off the plane are outside your org. Close and low = risky trust, far and high = pinned'],
      [sw('width:30px;border-top:2px solid #4b95f0'), 'Path between accounts: a role or user in one entered a role in the other (90 days). Bright in the hours it happened'],
      [sw('width:30px;border-top:2px dashed #fff'), 'White dashed path: first seen today'],
      ...(M.scanner ? [[sw(`width:12px;height:12px;margin:0 9px;border-radius:50%;background:${CM}`), 'Curious Monkey: this portal. Its dotted paths are the scanner signing in to each account, kept apart from account-to-account paths']] : []),
      [sw(`width:30px;border-top:2px solid ${RED}`), 'Red is always a problem and always carries a ⚠ tag'],
    ] : [
      [sw('width:30px;height:12px;background:linear-gradient(180deg,#031009,#0b3a26);border:1px solid #2a8a5c'), `The plane is one account: ${M.account.name}`],
      [sw('width:6px;height:14px;margin:0 12px;background:linear-gradient(#eef7f2 0 4px,#9cc7b4 4px 5px,transparent 5px)'), 'Tower: an AWS service. Taller = more calls into it in 7 days'],
      [sw(`width:12px;height:12px;margin:0 9px;border-radius:50%;border:2px solid ${ENV[M.account.environment].base}`), 'Ring: roles that call the same service most'],
      [sw('width:6px;height:6px;margin:0 12px;border-radius:50%;background:#8d9a93'), 'Grey dots round the edge: roles never called'],
      [sw(`width:30px;border-top:2px solid ${ENV[M.account.environment].base}`), 'Thin paths: which services each ring calls. Click a role for its own'],
      [sw('width:12px;height:12px;margin:0 9px;border-radius:50%;border:1.5px solid #9cc7b4'), 'Rings past the edge: accounts that chain in or out'],
      ...(M.scanner ? [[sw(`width:12px;height:12px;margin:0 9px;border-radius:50%;background:${CM}`), 'Curious Monkey: this portal, signing in to its scanner role here']] : []),
      [sw('width:10px;height:10px;margin:0 10px;border:1.5px solid #d5dceb;transform:rotate(45deg)'), 'Diamond at the edge: where an identity from outside comes in. The number is how many roles it can enter; click it for the list'],
      [sw(`width:12px;height:12px;margin:0 9px;border-radius:50%;border:1.5px solid ${RED}`), 'Red ring on a service: calls to it were refused this week'],
      [sw(`width:30px;border-top:2px solid ${RED}`), 'Red is always a problem and always carries a ⚠ tag'],
    ];
    const b = st.sel ? detail(st.sel) : null;
    right.replaceChildren(...(b ? [panelEl(b)] : []), h('section', { class: 'sp-section' }, h('h2', { class: 'eyebrow' }, M.view === 'estate' ? 'Needs a look · last 24 h' : 'In this account · last 24 h'), ...feed),
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
      h('div', null, M.view === 'estate' ? 'HEIGHT = CALLS IN 7 DAYS (LOG) · DRAG TO ORBIT · SCROLL TO ZOOM' : 'TOWER = CALLS INTO A SERVICE · DRAG TO ORBIT · SCROLL TO ZOOM'));
    cam.replaceChildren(h('span', { class: 'eyebrow' }, 'Camera'), ...[['◀', 'Rotate left', () => set({ az: st.az - 20 })], ['▶', 'Rotate right', () => set({ az: st.az + 20 })],
      ['▲', 'Look from higher', () => set({ el: Math.min(70, st.el + 8) })], ['▼', 'Look from lower', () => set({ el: Math.max(18, st.el - 8) })], ['+', 'Zoom in', () => set({ zoom: Math.min(3, st.zoom * 1.25) })], ['−', 'Zoom out', () => set({ zoom: Math.max(0.6, st.zoom / 1.25) })], ['Reset', 'Reset the camera', () => set({ az: -14, el: 33, zoom: 1.15 })]]
      .map(([icon, label, fn]) => h('button', { 'aria-label': label, title: label, onClick: fn }, icon)));
  }

  render();
  return page;
}
