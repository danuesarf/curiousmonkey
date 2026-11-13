// Space: the estate as a tilted plane, replayed by the hour.
//   Estate       — the plane is the organization, split into zones by environment. Each account is a ring with one star
//                  per busy role: higher and brighter = more calls in 7 days. Roles with no recorded call lie grey on the
//                  floor, and the dashed grey part of each ring is that share. Identities outside the org that trust
//                  policies let in float off the plane: close and low = the worst trust, far and high = trust that is
//                  pinned. Role chaining between accounts arcs above the plane and lights up in the hours it happened.
//   One account  — services the account calls stand as towers at the centre; roles cluster around the service they
//                  call most; neighbouring accounts sit just past the edge; cold roles ring the floor.
// The bar under the scene picks the hour (the last 24, in WIB); play steps through them.
import { h, svg, get, getCached, num, ago, loadEnvironments, envPalette, whoControl, whoOf, whoQs } from '../lib.js';
import { go, windowIcon } from '../main.js';
import { related, dirFilter, FADE } from './spaceRelated.js';

const W = 1000, H = 900;
// one colour per environment, checked together with every pair compared (colour-blind ΔE ≥ 10, normal vision ≥ 17).
// Shared is a muted olive: the only non-red hue that still clears both floors next to the other four.
// base = rings, paths, swatches; hot/dim = the brightest and faintest stars. Red is never an environment.
// environments as set on the Configuration page: colours, and their order east to west across the plane
let ENV = {}, ORDER = [];
const useEnvironments = (list) => { ENV = Object.fromEntries(list.map((e) => [e.id, { name: e.name, ...envPalette(e.color) }])); ORDER = list.map((e) => e.id); };
const RED = '#ff5a4f', WARN = '#fab219', COLD = '#7a8780', OUT = '#c3cbd9';
const TONE = { high: RED, warn: WARN, info: '#ffffff', good: '#6fe3b0', medium: WARN, low: '#d5dceb' };
const KIND = { 'new-caller': 'NEW CALLER', denied: '⚠ DENIED', grew: 'GREW', unidentified: 'UNIDENTIFIED', 'new-role': 'NEW ROLE', dead: 'COLD', cleaned: 'CLEANED', 'new-path': 'NEW PATH' };
const CM = '#c79a6b', CM_ID = 'cm';
const GCP = '#7fb2ff', DY = 440;          // Google Cloud: its colour, and how far apart the two fields sit                 // Curious Monkey, this portal's own scanner: its own colour and shape
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

// ---------- Google Cloud: a second field behind the AWS one, the same zones, paths between the two ----------
// AWS moves forward, Google Cloud sits behind. A project is a ring; each service account a star, higher the more it
// can do, red when it is high risk. Paths between the fields are where one cloud can sign in to the other.
const isGcp = (id) => String(id).startsWith('gcp:');
function withGcp(M, g) {
  const aws = { id: 'aws', label: 'AWS', x0: -560, x1: 560, y0: -380, y1: 380 };
  if (!g?.projects?.length) { M.planes = [aws]; return M; }
  for (const x of M.groups) { x.y += DY; x.stars.forEach((st) => { st.y += DY; }); }
  for (const z of M.zones) { z.y0 += DY; z.y1 += DY; z.cloud = 'aws'; }
  for (const x of M.sources) x.y += DY;
  if (M.scanner) M.scanner.y += DY;
  M.planes = [{ ...aws, y0: -380 + DY, y1: 380 + DY }, { id: 'gcp', label: 'GOOGLE CLOUD', x0: -560, x1: 560, y0: -380 - DY, y1: 380 - DY }];
  const envs = ORDER.filter((e) => g.projects.some((p) => p.environment === e));
  const weight = (e) => Math.max(1, g.projects.filter((p) => p.environment === e).length) ** 0.75;
  const totalW = envs.reduce((n, e) => n + weight(e), 0);
  let x1 = 560;
  const gz = [], gg = [];
  for (const env of envs) {
    const w = (1120 * weight(env)) / totalW, x0 = x1 - w, list = g.projects.filter((p) => p.environment === env);
    gz.push({ id: env, x0, x1, y0: -380 - DY, y1: 380 - DY, cloud: 'gcp' });
    const cols = Math.max(1, Math.round(Math.sqrt((list.length * w) / 760))), rows = Math.ceil(list.length / cols), cw = w / cols, ch = 760 / rows;
    list.forEach((p, i) => {
      const cx = x0 + cw * (i % cols + 0.5), cy = 380 - ch * (Math.floor(i / cols) + 0.5) - DY;
      const R = Math.max(14, Math.min(18 + Math.sqrt(p.accounts.length) * 5.5, 0.4 * Math.min(cw, ch)));
      const stars = cloud(cx, cy, R, p.accounts.filter((a) => !a.managed).map((a) => ({ id: `gsa:${a.id}`, sa: a, risk: a.risk, calls7: a.permissions })), 0, hash(p.projectId));
      gg.push({ id: `gcp:${p.projectId}`, cloud: 'gcp', project: p, name: p.projectId, label: p.projectId, env, x: cx, y: cy, R, coldShare: 0, prof: Array(24).fill(0), hourly: [], stars,
        roles: p.accounts.length, cold: 0, high: p.risky, calls7: 0, keys: p.keys });
    });
    x1 = x0;
  }
  M.zones.push(...gz); M.groups.push(...gg);
  for (const x of gg) M.by.set(x.id, x);
  // identities from outside the organization, off the far edge of the Google Cloud field
  const outs = g.outside.filter((o) => o.targets.some((t) => M.by.has(`gcp:${t.projectId}`)));
  const srcs = outs.map((o, i) => {
    const deg = outs.length === 1 ? 270 : 222 + (96 * i) / (outs.length - 1), [gap, z] = PLACE[o.worst] || PLACE.none, at = off(deg, gap, z);
    return { id: `gsrc:${o.key}`, key: o.key, gcp: true, label: o.label, sub: o.sub, group: o.group, kind: o.group === 'oidc' ? 'oidc' : o.group === 'public' ? 'web' : 'account', risk: o.worst, findings: [],
      principal: o.principal || null, targets: o.targets.map((t) => ({ accountId: `gcp:${t.projectId}`, roles: t.principals, edges: [] })), sessions: 0, ...at, y: at.y - DY };
  });
  M.sources.push(...srcs);
  for (const x of srcs) for (const t of x.targets) M.links.push({ from: x.id, to: t.accountId, kind: x.risk === 'high' ? 'extHigh' : x.risk === 'medium' ? 'extWarn' : 'ext', vol: 1, at: null, edges: [], roles: t.roles.length, gcp: true });
  // the paths between the clouds, one per pair of account and project
  const pairs = new Map();
  const add = (from, to, dir, l) => {
    if (!M.by.has(from) || !M.by.has(to)) return;
    const k = `${from}|${to}`;
    if (!pairs.has(k)) pairs.set(k, { from, to, kind: 'xcloud', dir, vol: 1, at: null, pairs: [] });
    const x = pairs.get(k); x.pairs.push(l); if (l.broad) x.kind = 'xcloudHigh';
  };
  for (const l of g.links.awsToGcp) if (l.awsAccount && l.gcpProject) add(l.awsAccount, `gcp:${l.gcpProject}`, 'aws-gcp', l);
  for (const l of g.links.gcpToAws) if (l.awsAccount && l.gcpProject) add(`gcp:${l.gcpProject}`, l.awsAccount, 'gcp-aws', l);
  M.links.push(...pairs.values());
  M.links.forEach((l, i) => { l.id = `link:${i}`; });
  M.gcp = { projects: gg, sources: srcs, xlinks: [...pairs.values()], providers: g.providers };
  return M;
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
  const fars = d.neighbours.map((n, i, all) => ({ ...n, ...off(all.length === 1 ? 200 : 190 + (150 * i) / (all.length - 1), 95, 0), env: ORDER.includes(n.environment) ? n.environment : ORDER[0] }));
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
  // your other accounts: what chained in or out (used) and what trust policies allow (allowed). A line with no role
  // here named (a whole account trusted, or a role not drawn) starts at a door on the edge facing that account.
  const doors = [];
  for (const n of fars) {
    let door = null;
    for (const l of n.links) {
      let here = byRole.has(l.roleId) ? l.roleId : null;
      if (!here) {
        if (!door) { const a = Math.atan2(n.y, n.x), r = edgeDist(a) - 20; door = { id: `door:${n.id}`, far: `far:${n.id}`, x: Math.cos(a) * r, y: Math.sin(a) * r, n: 0, env: n.env }; doors.push(door); }
        door.n++; here = door.id;
      }
      const used = l.sessions > 0, base = { kind: l.dir, vol: used ? 2 : 1, used, allowed: l.allowed || 0, sessions: l.sessions, worst: l.worst || 'none', otherRole: l.otherRole };
      links.push(l.dir === 'in' ? { ...base, from: `far:${n.id}`, to: here } : { ...base, from: here, to: `far:${n.id}` });
    }
  }
  links.forEach((l, i) => { l.id = `link:${i}`; });
  const events = d.events.map((e) => ({ id: e.id, kind: KIND[e.kind] || e.kind.toUpperCase(), tone: e.severity, hour: e.hour, text: e.title, where: e.roleName || d.account.name, target: e.roleId && byRole.has(e.roleId) ? e.roleId : null }));
  for (const t of towers) t.denied = roles.reduce((n, r) => n + (r.services.find((v) => v.name === t.name)?.denied || 0), 0);
  return { view: 'account', account: d.account, zones: [], groups, roles, byRole, towers, gates, doors, rim, sources, scanner, fars, links, events, hidden: d.outside.hidden,
    coldCount: d.coldCount, roleCount: d.roleCount, hourStart: new Date(d.hourStart).getTime(),
    defaultSel: events.find((e) => e.target)?.target || [...roles].sort((a, b) => b.calls7 - a.calls7)[0]?.id || null };
}

export async function spacePage(ctx) {
  const view = ctx.params.get('view') === 'account' ? 'account' : 'estate';
  // both views are fetched together and remembered briefly, so zooming into an account and back does not wait twice
  const who = whoOf(ctx.params), wq = whoQs(who);
  const wanted = view === 'account' && ctx.params.get('account') ? getCached(`/space/account/${ctx.params.get('account')}${wq}`) : null;
  wanted?.catch(() => {});
  const [est, envs, gcpData] = await Promise.all([getCached(`/space${wq}`), loadEnvironments(), view === 'estate' && who !== 'users' ? getCached('/space/gcp').catch(() => null) : null]);
  useEnvironments(envs);
  // a Google service account an AWS role trusts is drawn as a path between the fields, not as an outside identity
  const hasGcp = !!gcpData?.projects?.length;
  // users have no trust policy: the identities that roles let in, and the scanner's role, are not part of their picture
  if (who === 'users') { est.outside = { items: [], hidden: 0 }; est.scanner = null; }
  const noun = who === 'users' ? 'IAM users' : who === 'roles' ? 'roles' : 'roles and users', Noun = noun[0].toUpperCase() + noun.slice(1);
  if (hasGcp) est.outside = { ...est.outside, items: est.outside.items.filter((x) => !/^Google Cloud · /.test(x.label)) };
  if (!est.accounts.length) return h('div', { class: 'stack' }, h('h1', null, 'Space'), h('p', { class: 'muted' }, 'No accounts yet. Connect one to see it here.'), h('a', { class: 'btn primary', href: '#/accounts/new' }, 'Connect an account'));
  const live = est.accounts.filter((a) => !a.planned);
  const accountId = ctx.params.get('account') || [...(live.length ? live : est.accounts)].sort((a, b) => b.calls7 - a.calls7)[0].id;
  const M = view === 'estate' ? withGcp(estateModel(est), gcpData) : accountModel(await (wanted || getCached(`/space/account/${accountId}${wq}`)));
  if (!M.planes) M.planes = [{ id: 'aws', label: 'AWS', x0: -560, x1: 560, y0: -380, y1: 380 }];
  const awsGroups = () => M.groups.filter((x) => x.cloud !== 'gcp');
  ctx.setCrumbs(h('a', { href: '#/space' }, 'Space'), ...(view === 'account' ? [M.account.name] : []));
  const st = { dir: 'both', sel: null, lit: false, hour: 23, playing: false, az: -14, el: 33, zoom: 1.15, px: 0, py: 0, zone: '', timer: null, fit: null, dragging: false };
  // the bell (and links) can open Space on one thing at one hour; otherwise nothing is picked and the overview shows
  { const want = ctx.params.get('sel'), hr = Number(ctx.params.get('hour'));
    if (want && (M.view === 'estate' ? M.by.has(want) : M.byRole.has(want))) { st.sel = want; st.lit = true; }
    if (ctx.params.get('hour') != null && hr >= 0 && hr <= 23) st.hour = Math.floor(hr); }
  const left = h('aside', { class: 'left' }), right = h('aside', { class: 'right' });
  const stage = svg('svg', { class: 'space-svg', viewBox: `0 0 ${W} ${H}`, role: 'img' });
  const box = h('div', { class: 'space-box' }, stage);
  const hud = h('div', { class: 'space-hud', 'aria-live': 'polite' }), cam = h('div', { class: 'space-cam', role: 'group', 'aria-label': 'Camera' });
  const bar = h('div', { class: 'space-timeline' });
  const scene = h('div', { class: 'scene space-scene' }, h('div', { class: 'space-stage' }, box, hud, cam), bar);
  const page = h('div', { class: 'stack space-page', style: 'gap:0' }, h('div', { class: 'scene-layout space-layout' }, left, scene, right));
  // the page opens with something described in the sidebar but the whole scene lit; once the user picks something,
  // everything not connected to it fades so what belongs to what is plain
  const set = (patch) => { if ('sel' in patch && patch.sel !== st.sel) { st.filter = ''; st.showAll = false; if (M.view === 'estate' && M.by.has(patch.sel) && !M.by.get(patch.sel).planned && !isGcp(patch.sel)) getCached(`/space/account/${patch.sel}${wq}`).catch(() => {}); } if ('sel' in patch) st.lit = !!patch.sel; Object.assign(st, patch); render(); };
  const stop = () => { if (st.timer) { clearInterval(st.timer); st.timer = null; } };
  ctx.onLeave(() => stop());

  // ---------- sessions (Track): a role's sessions in the sidebar, replayed over the scene without leaving Space ----------
  const sessions = new Map();          // role id -> sessions, or 'loading'
  const sessionsFor = (roleId) => {
    if (!sessions.has(roleId)) {
      sessions.set(roleId, 'loading');
      get(`/sessions?role=${encodeURIComponent(roleId)}`).then((r) => sessions.set(roleId, r.items), () => sessions.set(roleId, []))
        .then(() => { if (st.sel === roleId) render(); });
    }
    return sessions.get(roleId);
  };
  // Anything that would leave Space opens in a window over it instead (sessions, calls, a role, the trust map).
  // The window's page is fetched and built when it opens and dropped when it closes; Space stays as it was underneath.
  const openWin = (hash, title, eyebrow) => { stop(); st.playing = false; ctx.openWindow(hash, { title, eyebrow }); };
  const leaves = (href) => typeof href === 'string' && href.startsWith('#/') && !href.startsWith('#/space');
  const openTrack = (opts, label) => openWin(`#/track?${new URLSearchParams(Object.entries(opts).filter(([, v]) => v))}`, label, 'TRACK · ONE SESSION, CALL BY CALL');
  const sessionItems = (roleId, label) => {
    const l = sessionsFor(roleId);
    return Array.isArray(l) ? l.map((x) => ({ label: x.sessionName || x.id.slice(0, 8), tone: x.denied ? 'bad' : null, value: num(x.calls),
      meta: [x.principal || x.callerArn || 'unknown caller', x.denied ? `⚠ ${num(x.denied)} denied` : null, x.hasJumps ? 'jumped into another role' : null, x.isJump ? 'jumped in' : null,
        x.startKnown ? ago(x.startedAt) : 'started earlier'].filter(Boolean).join(' · '),
      opens: true, onClick: () => openTrack({ role: roleId, session: x.id }, label) })) : [];
  };

  // drag to orbit: the framing is held while dragging, then refitted
  const clampPan = (v, size) => Math.max(-size * 0.9 * st.zoom, Math.min(size * 0.9 * st.zoom, v));
  let drag = null;
  // the pointer is captured only once a drag has really started: capturing on press would send every click to the
  // scene itself instead of the thing under the pointer, and nothing could be clicked
  // plain drag orbits; Shift+drag, or dragging with the right or middle button, moves the view sideways and up and down
  stage.addEventListener('pointerdown', (ev) => { if (ev.button <= 2) drag = { x: ev.clientX, y: ev.clientY, az: st.az, el: st.el, px: st.px, py: st.py, pan: ev.shiftKey || ev.button !== 0, moved: false, id: ev.pointerId }; });
  stage.addEventListener('contextmenu', (ev) => ev.preventDefault());
  stage.addEventListener('pointermove', (ev) => {
    if (!drag) return; const dx = ev.clientX - drag.x, dy = ev.clientY - drag.y;
    if (!drag.moved && Math.hypot(dx, dy) < 5) return;
    if (!drag.moved) { try { stage.setPointerCapture(drag.id); } catch { /* pointer already gone */ } }
    drag.moved = true; st.dragging = true;
    if (drag.pan) {
      const k = W / (stage.getBoundingClientRect().width || W);
      st.px = clampPan(drag.px + dx * k, W); st.py = clampPan(drag.py + dy * k, H);
      if (!drag.raf) drag.raf = requestAnimationFrame(() => { drag && (drag.raf = 0); render(); });
      return;
    }
    const az = Math.round(drag.az - dx * 0.35), el = Math.max(18, Math.min(70, Math.round(drag.el + dy * 0.2)));
    if (az !== st.az || el !== st.el) { st.az = az; st.el = el; if (!drag.raf) drag.raf = requestAnimationFrame(() => { drag && (drag.raf = 0); render(); }); }
  });
  const endDrag = () => { if (drag?.moved) { st.dragging = false; render(); setTimeout(() => { drag = null; }, 0); } else drag = null; };
  // zoom only when asked: the wheel, or the + and − buttons
  // a sideways swipe (or Shift+wheel) moves the view left and right
  stage.addEventListener('wheel', (ev) => { ev.preventDefault();
    if (Math.abs(ev.deltaX) > Math.abs(ev.deltaY) || ev.shiftKey) { set({ px: clampPan(st.px - (ev.deltaX || ev.deltaY) * 0.8, W) }); return; }
    set({ zoom: Math.max(0.6, Math.min(3, st.zoom * Math.exp(-ev.deltaY * 0.0015))) }); }, { passive: false });
  stage.setAttribute('tabindex', '0');
  stage.addEventListener('keydown', (ev) => {
    const d = { ArrowLeft: [90, 0], ArrowRight: [-90, 0], ArrowUp: [0, 60], ArrowDown: [0, -60] }[ev.key]; if (!d) return;
    ev.preventDefault(); set({ px: clampPan(st.px + d[0], W), py: clampPan(st.py + d[1], H) });
  });
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
    const CX = W / 2 - F * ox + st.px, CY = 90 + st.fit.F * st.fit.top + ((H - 130) - st.fit.F * (st.fit.top + st.fit.bottom)) / 2 + F * ou + st.py;
    return (x, y, z = 0) => { const [X, U, dep] = p(x, y, z); return [CX + F * X, CY - F * U, dep, F / dep]; };
  }
  const hourLabel = (b) => new Date(M.hourStart + b * 36e5).toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit', timeZone: 'Asia/Jakarta' });

  function render() {
    const hour = st.hour, sel = st.sel, motion = !still() && !st.dragging, focus = M.view === 'estate' ? st.zone : '';
    const dimOf = (env) => (!focus ? 1 : focus === 'outer' ? 0.3 : env === focus ? 1 : 0.22);
    const rel = st.lit && sel ? related(M, sel) : null;
    const dirs = dirFilter(st.dir, M, sel);
    const fade = (...ids) => (!rel || ids.some((x) => rel.has(x)) ? 1 : FADE);
    // where every path starts and ends
    const ent = new Map();
    for (const g of M.groups) ent.set(g.id, { p3: [g.x, g.y, 22], env: g.env });
    for (const s of M.sources) ent.set(s.id, { p3: [s.x, s.y, s.z], env: 'outer' });
    if (M.scanner) ent.set(CM_ID, { p3: [M.scanner.x, M.scanner.y, M.scanner.z], env: 'scanner' });
    if (M.view === 'account') { for (const t of M.towers) ent.set(t.id, { p3: [t.x, t.y, t.h], env: 'svc' }); for (const r of M.roles) ent.set(r.id, { p3: [r.x, r.y, r.z], env: r.cluster.env }); for (const n of M.fars) ent.set(`far:${n.id}`, { p3: [n.x, n.y, 8], env: n.env }); for (const g of M.gates) ent.set(g.id, { p3: [g.x, g.y, 4], env: 'outer' }); for (const d of M.doors) ent.set(d.id, { p3: [d.x, d.y, 4], env: d.env }); }
    const liftOf = (l, a, b) => (/^xcloud/.test(l.kind) ? 70 + 0.12 * Math.hypot(b[0] - a[0], b[1] - a[1]) : l.kind === 'scan' ? 10 : l.kind === 'fan' ? 24 + 0.06 * Math.hypot(b[0] - a[0], b[1] - a[1]) : l.kind === 'use' ? 30 : l.kind === 'use1' ? 34 : l.kind === 'denied' && M.view === 'account' ? 40 : /^ext/.test(l.kind) ? 26 + 0.07 * Math.hypot(b[0] - a[0], b[1] - a[1]) : null);
    const fitPts = [...M.planes.flatMap((q) => [[q.x0, q.y0, 0], [q.x1, q.y0, 0], [q.x1, q.y1, 0], [q.x0, q.y1, 0], [0, q.y0 - 60, 0]]), ...M.sources.flatMap((s) => [[s.x, s.y, s.z + 14], [s.x, s.y, 0]]), ...(M.fars || []).flatMap((n) => [[n.x - 50, n.y - 50, 0], [n.x + 50, n.y + 50, 0]])];
    if (M.view === 'estate') for (const q of M.planes) fitPts.push([-760 - (M.planes.length > 1 ? 120 : 0), (q.y0 + q.y1) / 2, 0], [760, (q.y0 + q.y1) / 2, 0]);
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
    for (const q of M.planes) {
      const g = q.id === 'gcp', edge = g ? '#3d7bd6' : '#2a8a5c', grid = g ? '#1d4a7a' : '#1d6a45';
      const corners = [[q.x0, q.y0], [q.x1, q.y0], [q.x1, q.y1], [q.x0, q.y1]].map(([x, y]) => P(x, y, 0));
      out.floor.push(svg('path', { d: `${path(corners)} Z`, fill: g ? 'url(#sp-floor-g)' : 'url(#sp-floor)', stroke: edge, 'stroke-width': 1.2 }));
      for (let i = 1; i < 14; i++) { const x = q.x0 + i * 80, a = P(x, q.y0), b = P(x, q.y1); out.floor.push(svg('line', { x1: f(a[0]), y1: f(a[1]), x2: f(b[0]), y2: f(b[1]), stroke: grid, 'stroke-width': 0.7, opacity: 0.4 })); }
      for (let i = 1; i < 10; i++) { const y = q.y0 + i * 76, a = P(q.x0, y), b = P(q.x1, y); out.floor.push(svg('line', { x1: f(a[0]), y1: f(a[1]), x2: f(b[0]), y2: f(b[1]), stroke: grid, 'stroke-width': 0.7, opacity: 0.4 })); }
      if (M.planes.length > 1) { const l = P(q.x0 - 30, (q.y0 + q.y1) / 2, 0); blocks.push([l[0] - q.label.length * 9.6 - 4, l[1] - 13, l[0] + 4, l[1] + 5]); out.floor.push(svg('text', { x: f(l[0]), y: f(l[1]), 'text-anchor': 'end', fill: g ? GCP : '#6fe3b0', class: 'sp-plane' }, q.label)); }
    }
    for (const z of M.zones) {
      const E = ENV[z.id], pts = [[z.x0 + 8, z.y0 + 8], [z.x1 - 8, z.y0 + 8], [z.x1 - 8, z.y1 - 8], [z.x0 + 8, z.y1 - 8]].map(([x, y]) => P(x, y, 0)), l = P((z.x0 + z.x1) / 2, z.y0, 0);
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
      const E = ENV[g.env], dim = dimOf(g.env) * fade(g.id), c = P(g.x, g.y, 0), rx = g.R * 1.8 * c[3];
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
        const sd = M.view === 'account' ? dimOf(g.env) * fade(s.id) : dim;
        // an IAM user is a small square, a role a dot
        const sr = (s.cold ? 1 : 0.8 + 0.42 * lg(s.calls7)) * k, sfill = s.cold ? COLD : s.risk === 'High' ? RED : lv > 0.8 ? E.hot : lv > 0.45 ? E.base : E.dim;
        const sopts = { fill: sfill, opacity: o2((s.cold ? 0.7 : 0.95) * sd), filter: !s.cold && i < 3 && sd === 1 ? 'url(#sp-glow)' : null };
        out.stars.push([p[2], (s.kind || s.role?.kind) === 'iam-user' ? svg('rect', { x: f(p[0] - sr), y: f(p[1] - sr), width: f(2 * sr), height: f(2 * sr), ...sopts }) : svg('circle', { cx: f(p[0]), cy: f(p[1]), r: f(sr), ...sopts })]);
        if (!s.cold && i < (M.view === 'account' ? 6 : 3)) { const b = P(s.x, s.y, 0); out.stems.push(svg('line', { x1: f(b[0]), y1: f(b[1]), x2: f(p[0]), y2: f(p[1]), stroke: E.base, 'stroke-width': 0.8, opacity: o2(0.4 * sd) })); }
        bx0 = Math.min(bx0, p[0]); by0 = Math.min(by0, p[1]); bx1 = Math.max(bx1, p[0]); by1 = Math.max(by1, p[1]); topZ = Math.max(topZ, s.z);
      });
      const t = P(g.x, g.y, topZ + 10), fp = [P(g.x - g.R, g.y), P(g.x + g.R, g.y), P(g.x, g.y - g.R), P(g.x, g.y + g.R)];
      tops.set(g.id, t);
      const target = M.view === 'estate' ? g.id : g.roles[0]?.id;
      const hc = P(g.x, g.y, 30);
      out.hits.push(svg('g', { class: 'sp-hit', onClick: pick(target) }, svg('title', null, g.cloud === 'gcp' ? `${g.name} · Google Cloud · ${ENV[g.env].name} · ${g.roles} service accounts${g.high ? ` · ${g.high} high risk` : ''}` : M.view === 'estate' ? (g.planned ? `${g.name} · ${ENV[g.env].name} · planned, not onboarded yet` : `${g.name} · ${ENV[g.env].name} · ${g.roles} roles · ${kfmt(g.calls7)} calls in 7 days`) : `${g.label} · ${g.roles.length} roles`),
        svg('circle', { cx: f(hc[0]), cy: f(hc[1]), r: f(Math.max(16, g.R * c[3] * 1.15)), fill: '#000', opacity: 0 })));
      const isSel = M.view === 'estate' ? sel === g.id : selRole?.cluster === g;
      cands.push({ pr: (isSel ? 3000 : 0) + (evNow.some((e) => e.target === g.id) ? 900 : 0) + lg(g.calls7) * 40 + (dim < 1 ? -500 : 0) + (g.planned ? -200 : 0), x: t[0], y: t[1], text: g.label, color: dim < 1 ? '#3c5a4b' : g.planned ? '#8d9a93' : E.base, faded: dim < 0.5, pick: pick(target), below: fp[2][1] - t[1] + 14 });
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
      for (const s of M.rim) { const p = P(s.x, s.y, 0); out.stars.push([p[2], svg('circle', { cx: f(p[0]), cy: f(p[1]), r: f(2.1 * Math.max(0.72, p[3] / ref)), fill: '#8d9a93', opacity: o2(0.85 * (rel ? FADE : 1)) })]); }
      for (const t of M.towers) {
        const b = P(t.x, t.y, 0), tp = P(t.x, t.y, t.h), k = Math.max(0.72, tp[3] / ref);
        out.towers.push(svg('g', { opacity: fade(t.id) }, svg('line', { x1: f(b[0]), y1: f(b[1]), x2: f(b[0]), y2: f(tp[1]), stroke: '#9cc7b4', 'stroke-width': f(1.4 * k), opacity: 0.55 }),
          svg('ellipse', { cx: f(b[0]), cy: f(b[1]), rx: f(9 * k), ry: f(9 * k * sinEl), fill: 'none', stroke: '#9cc7b4', 'stroke-width': 0.9, opacity: 0.6 }),
          svg('path', { d: glyph('service', tp[0], tp[1], 6 * k), fill: '#eef7f2', stroke: '#fff', 'stroke-width': 0.6, filter: 'url(#sp-glow)' }),
          t.denied ? svg('circle', { cx: f(tp[0]), cy: f(tp[1]), r: f(11 * k), fill: 'none', stroke: RED, 'stroke-width': 1.4, class: 'sp-pulse' }) : null));
        out.hits.push(svg('g', { class: 'sp-hit', onClick: pick(t.id) }, svg('title', null, `${t.name} · ${kfmt(t.calls)} calls in 7 days${t.denied ? ` · ⚠ ${num(t.denied)} refused` : ''}`), svg('circle', { cx: f(tp[0]), cy: f(tp[1]), r: 14, fill: '#000', opacity: 0 })));
        tops.set(t.id, tp);
        cands.push({ pr: 1500 + lg(t.calls) * 40 + (sel === t.id ? 3000 : 0) - (fade(t.id) < 1 ? 1400 : 0), x: tp[0], y: tp[1] - 4, text: t.name, color: '#9cc7b4', faded: fade(t.id) < 1, pick: pick(t.id), below: 26 });
        if (sel === t.id) out.marks.push(svg('path', { d: glyph('account', tp[0], tp[1], 11), fill: 'none', stroke: '#fff', 'stroke-width': 1.6 }));
      }
      for (const g of M.gates) {
        if (!dirs.inside) continue;
        const c = P(g.x, g.y, 0), k = Math.max(0.75, c[3] / ref), col = g.risk === 'high' ? RED : g.risk === 'medium' ? WARN : '#d5dceb', on = sel === g.src;
        out.rings.push(svg('g', { class: 'sp-hit', onClick: pick(g.src), opacity: fade(g.id, g.src) }, svg('title', null, `${g.roles.length} roles can be entered from here · click for the list`),
          svg('path', { d: glyph('saml', c[0], c[1], 7 * k), fill: '#03100b', stroke: col, 'stroke-width': on ? 2 : 1.3 }),
          svg('text', { x: f(c[0]), y: f(c[1] + 4 * k), 'text-anchor': 'middle', fill: col, class: 'sp-small', style: 'font-size:9px' }, String(g.roles.length))));
      }
      for (const d of M.doors) {
        if (!M.links.some((l) => (l.from === d.id || l.to === d.id) && dirs.link(l))) continue;
        const c = P(d.x, d.y, 0), k = Math.max(0.75, c[3] / ref), E = ENV[d.env] || ENV[ORDER[0]];
        out.rings.push(svg('g', { class: 'sp-hit', onClick: pick(d.far), opacity: fade(d.id, d.far) }, svg('title', null, `${d.n} way${d.n === 1 ? '' : 's'} with no single role here: the whole account, or roles not drawn · click for the list`),
          svg('path', { d: glyph('account', c[0], c[1], 6 * k), fill: '#03100b', stroke: E.hot, 'stroke-width': 1.2 }),
          svg('text', { x: f(c[0]), y: f(c[1] + 3.5 * k), 'text-anchor': 'middle', fill: E.hot, class: 'sp-small', style: 'font-size:8px' }, String(d.n))));
      }
      for (const n of M.fars) {
        const E = ENV[n.env], c = P(n.x, n.y, 0), id = `far:${n.id}`;
        if (!M.links.some((l) => (l.from === id || l.to === id) && dirs.link(l))) continue;
        out.rings.push(svg('g', { class: 'sp-hit', onClick: pick(id), opacity: fade(id) }, svg('title', null, `${n.name} · neighbouring account`), svg('path', { d: ring3(n.x, n.y, 40, 0, Math.PI * 2, 36), fill: E.base, 'fill-opacity': 0.12, stroke: E.base, 'stroke-width': 1.3 }),
          svg('text', { x: f(c[0]), y: f(c[1] + 40 * c[3] * sinEl + 16), 'text-anchor': 'middle', fill: E.hot, class: 'sp-small' }, n.name)));
        tops.set(id, P(n.x, n.y, 10));
        if (sel === id) out.marks.push(svg('path', { d: ring3(n.x, n.y, 50, 0, Math.PI * 2, 40), fill: 'none', stroke: '#fff', 'stroke-width': 1.6 }));
      }
    }

    // outside the org
    const sats = M.sources.filter((s) => dirs.source(s.id)).map((s) => {
      const p = P(s.x, s.y, s.z), g0 = P(s.x, s.y, 0), k = Math.max(0.75, Math.min(1.3, p[3] / ref)), size = 6.5 * k;
      blocks.push([p[0] - 13, p[1] - 13, p[0] + 13, p[1] + 13]); tops.set(s.id, p);
      if (sel === s.id) out.marks.push(svg('path', { d: glyph('account', p[0], p[1], 17), fill: 'none', stroke: '#fff', 'stroke-width': 1.6 }));
      return { s, p, g0, k, size };
    });

    // paths above the plane
    const flagC = [];
    const rnd = rng(7);
    for (const l of M.links) {
      const a = ent.get(l.from), b = ent.get(l.to); if (!a || !b || !dirs.link(l)) continue;
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
      else if (l.kind === 'xcloud') { color = GCP; w = 1.5; o = t ? 1 : 0.6; flow = t ? 2 : 1; if (t) flag = { text: l.dir === 'aws-gcp' ? 'AWS → GOOGLE CLOUD' : 'GOOGLE CLOUD → AWS', bg: GCP }; }
      else if (l.kind === 'xcloudHigh') { color = RED; w = 1.7; o = t ? 1 : 0.7; flow = t ? 2 : 1; flag = t || !sel ? { text: '⚠ ANY AWS ROLE', bg: RED } : null; }
      else if (l.kind === 'scan') { color = CM; w = 1.1; dash = '1.5 4'; o = t || now ? 0.95 : 0.3; flow = now ? 1 : 0; }
      else if (l.kind === 'in' || l.kind === 'out') {
        color = l.worst === 'high' ? RED : ENV[(ent.get(l.kind === 'in' ? l.from : l.to)).env]?.base || OUT;
        if (l.used === false) { w = 1; dash = '3 4'; o = t ? 0.9 : 0.35; flow = 0; } else { w = 1.3; o = t ? 0.95 : 0.45; flow = t ? 2 : 1; }
        if (l.worst === 'high' && t) flag = { text: '⚠ RISKY TRUST', bg: RED };
      }
      if (!show) continue;
      const on = !rel || rel.has(l.id);
      if (!on) { o *= FADE; flow = 0; flag = null; }
      if (focus && focus !== 'outer' && a.env !== focus && b.env !== focus) o *= 0.25;
      if (focus === 'outer' && a.env !== 'outer' && b.env !== 'outer') o *= 0.25;
      const g3 = arc3(a.p3, b.p3, l.from < l.to ? 1 : -1, P, liftOf(l, a.p3, b.p3));
      out.arcs.push(svg('path', { d: cut < 1 ? g3.part(cut) : g3.d, fill: 'none', stroke: color, 'stroke-width': f(sel === l.id ? w + 1.2 : w), opacity: o2(o), 'stroke-dasharray': dash, class: cls, 'stroke-linecap': 'round' }));
      // every path but the per-cluster service bundles can be clicked: a wide invisible stroke along it
      const ext = /^ext/.test(l.kind), mid = g3.pts[ext ? 6 : 12];
      tops.set(l.id, mid);
      if (l.kind !== 'use' && l.kind !== 'fan' && (o > 0.15 || (rel && !on && o > 0.15 * FADE))) out.paths.push(svg('path', { class: 'sp-hit', d: cut < 1 ? g3.part(cut) : g3.d, fill: 'none', stroke: '#000', 'stroke-opacity': 0, 'stroke-width': 12, 'pointer-events': 'stroke', onClick: pick(l.id) },
        svg('title', null, linkTitle(l))));
      if (sel === l.id) out.marks.push(svg('circle', { cx: f(mid[0]), cy: f(mid[1]), r: 6, fill: 'none', stroke: '#fff', 'stroke-width': 1.6 }));
      if (cut < 1 && t) { const q = g3.pts[Math.round(cut * 24)]; out.sparks.push(svg('g', null, svg('circle', { cx: f(q[0]), cy: f(q[1]), r: 5, fill: 'none', stroke: RED, 'stroke-width': 1.4, class: 'sp-pulse' }))); }
      if (motion) for (let i = 0; i < flow; i++) {
        const dur = 3.4, begin = `${f(-(i * dur) / flow - rnd() * 0.8)}s`, c = l.kind === 'denied' ? RED : color;
        out.parts.push(svg('circle', { r: 2.2, fill: c, filter: 'url(#sp-glow)', opacity: 0 },
          svg('animateMotion', { path: g3.d, dur: `${dur}s`, begin, repeatCount: 'indefinite', keyPoints: cut < 1 ? `0;${cut}` : '0;1', keyTimes: '0;1', calcMode: 'linear' }),
          svg('animate', { attributeName: 'opacity', values: '0;0.95;0.95;0', keyTimes: '0;0.1;0.8;1', dur: `${dur}s`, begin, repeatCount: 'indefinite' })));
      }
      if (flag && (now || t || l.kind === 'xcloudHigh')) { const q = g3.pts[cut < 1 ? 10 : ext ? 6 : 12]; flagC.push({ x: q[0], y: q[1], text: flag.text, bg: flag.bg, pr: (sel === l.id ? 2 : 0) + (now ? 1 : 0), pick: pick(l.id) }); }
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
      out.sats.push(svg('g', { class: 'sp-hit', onClick: pick(s.id), opacity: (focus && focus !== 'outer' ? 0.35 : 1) * fade(s.id) },
        svg('title', null, `${s.label} · ${s.sub}${s.findings.length ? ` · ${s.findings.join('; ')}` : ''}`),
        svg('line', { x1: f(p[0]), y1: f(p[1]), x2: f(g0[0]), y2: f(g0[1]), stroke: '#8b98ad', 'stroke-width': 0.8, 'stroke-dasharray': '1.5 3.5' }),
        svg('ellipse', { cx: f(g0[0]), cy: f(g0[1]), rx: f(7 * k), ry: f(7 * k * sinEl), fill: 'none', stroke: '#8b98ad', 'stroke-width': 0.8, opacity: 0.7 }),
        svg('circle', { cx: f(p[0]), cy: f(p[1]), r: 16, fill: '#000', opacity: 0 }),
        svg('path', { d: glyph(s.kind, p[0], p[1], size), fill: '#d5dceb', stroke: '#fff', 'stroke-width': 0.8, filter: 'url(#sp-glow)' }),
        ring && svg('circle', { cx: f(p[0]), cy: f(p[1]), r: f(size + 6), fill: 'none', stroke: ring, 'stroke-width': 1.5, 'stroke-dasharray': s.risk === 'high' ? null : '3 3', class: 'sp-pulse' }),
        svg('text', { x: f(lx), y: f(ly), 'text-anchor': anchor, fill: '#e6ebf4', class: 'sp-name' }, s.label),
        svg('text', { x: f(lx), y: f(ly + 13), 'text-anchor': anchor, fill: s.risk === 'high' ? '#ffb0a6' : '#a9b4c6', class: 'sp-small' }, s.sub)));
    }
    if (M.scanner && dirs.inside) {
      const sc = M.scanner, p = P(sc.x, sc.y, sc.z), g0 = P(sc.x, sc.y, 0), on = sel === CM_ID, today = sc.targets.filter((t) => t.hours.includes(hour)).length;
      tops.set(CM_ID, p);
      const label = 'Curious Monkey', sub = `this portal's scanner · ${sc.targets.length} account${sc.targets.length === 1 ? '' : 's'}`;
      const w = Math.max(label.length * 6.7, sub.length * 6.15) + 4;
      const tries = [['start', p[0] + 18, p[1] - 2], ['end', p[0] - 18, p[1] - 2], ['middle', p[0], p[1] - 30]];
      let pl = tries[0];
      for (const tr of tries) { const x0 = tr[0] === 'start' ? tr[1] : tr[0] === 'end' ? tr[1] - w : tr[1] - w / 2, r = [x0, tr[2] - 11, x0 + w, tr[2] + 17]; if (fits(r)) { pl = tr; blocks.push(r); break; } }
      blocks.push([p[0] - 16, p[1] - 16, p[0] + 16, p[1] + 16]);
      if (on) out.marks.push(svg('circle', { cx: f(p[0]), cy: f(p[1]), r: 17, fill: 'none', stroke: '#fff', 'stroke-width': 1.6 }));
      out.sats.push(svg('g', { class: 'sp-hit', onClick: pick(CM_ID), opacity: (focus ? 0.4 : 1) * fade(CM_ID) },
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
        if (c.faded && rel) out.labels[out.labels.length - 1].setAttribute('opacity', FADE + 0.15);
        break;
      }
    }

    out.stars.sort((a, c) => c[0] - a[0]);
    stage.setAttribute('aria-label', M.view === 'estate'
      ? `Your organization as a tilted plane${M.gcp ? ', with Google Cloud as a second plane behind it' : ''}: ${awsGroups().length} accounts in zones by environment, one star per busy role, higher the more it is called; identities outside the org float off the plane. Showing ${hourLabel(hour)}.`
      : `${M.account.name} as a plane: services as towers in the middle, roles clustered round the service they call most, cold roles grey round the edge. Showing ${hourLabel(hour)}.`);
    stage.replaceChildren(
      svg('defs', null,
        svg('filter', { id: 'sp-glow', x: '-100%', y: '-100%', width: '300%', height: '300%' }, svg('feGaussianBlur', { stdDeviation: 1.8, result: 'b' }), svg('feMerge', null, svg('feMergeNode', { in: 'b' }), svg('feMergeNode', { in: 'SourceGraphic' }))),
        svg('linearGradient', { id: 'sp-floor', x1: 0, y1: 0, x2: 0, y2: 1 }, svg('stop', { offset: 0, 'stop-color': '#031009' }), svg('stop', { offset: 1, 'stop-color': '#072a1b' })),
        svg('linearGradient', { id: 'sp-floor-g', x1: 0, y1: 0, x2: 0, y2: 1 }, svg('stop', { offset: 0, 'stop-color': '#030a14' }), svg('stop', { offset: 1, 'stop-color': '#0a1f3a' })),
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
      if (String(id).startsWith('door:')) return `${M.account.name} (whole account)`;
      const g = M.groups.find((x) => x.id === id); if (g) return g.label;
    }
    return 'somewhere';
  }
  function linkTitle(l) {
    const a = nameOf(l.from), b = nameOf(l.to);
    if (/^xcloud/.test(l.kind)) return `${a} → ${b} · ${l.pairs.length} way${l.pairs.length === 1 ? '' : 's'} between the clouds${l.kind === 'xcloudHigh' ? ' · any AWS role can use it' : ''} · click for which`;
    if (/^ext/.test(l.kind) && l.gcp) return `${a} can get into ${b} in Google Cloud · click for who`;
    if (/^ext/.test(l.kind)) return `${a} can enter ${b}${l.kind === 'extHigh' ? ' · risky trust' : l.kind === 'extWarn' ? ' · loose trust' : ''} · click for the trust statement`;
    if (l.kind === 'chain' || l.kind === 'new') return `${a} entered ${b} · ${num(l.sessions)} sessions in 90 days${l.today ? ` · ${l.today} today` : ''}${l.kind === 'new' ? ' · first seen today' : ''} · click for who`;
    if (l.kind === 'denied') return `${a} → ${b} · ${l.denied} calls refused in 7 days`;
    if (l.kind === 'in' || l.kind === 'out') return `${a} → ${b} · ${l.sessions ? `used, ${num(l.sessions)} sessions in 7 days` : 'not used in 7 days'}${l.allowed ? ` · allowed by trust` : ''}${l.worst === 'high' ? ' · risky trust' : ''} · click for the list`;
    if (l.kind === 'scan') return `Curious Monkey reads ${b} through ${pretty(l.target.role).label} · ${num(l.target.sessions)} sign-ins in 90 days · click for more`;
    return `${a} → ${b}`;
  }
  const clip = (t, n = 170) => (t.length > n ? `${t.slice(0, n - 1)}…` : t);
  function linkDetail(l) {
    const row = (k, v, tone) => ({ k, v: String(v), tone });
    const a = nameOf(l.from), b = nameOf(l.to);
    if (/^xcloud/.test(l.kind)) {
      const into = l.dir === 'aws-gcp';
      const items = l.pairs.map((x) => into
        ? { label: `${x.awsRole || 'any role'} → ${x.gcpEmail ? x.gcpEmail.split('@')[0] : `${x.grant} on ${x.gcpProject}`}`, meta: [x.via === 'direct' ? 'holds roles itself' : 'becomes the service account', `pool ${x.pool}`, x.conditions.length ? `when ${x.conditions[0]}` : 'no condition'].join(' · '),
          tone: x.broad ? 'bad' : null, window: x.gcpPrincipal ? `#/gcp/principals/${x.gcpPrincipal}` : null, winTitle: x.gcpEmail || x.label, winEyebrow: 'GOOGLE CLOUD · IDENTITY', href: !x.gcpPrincipal && x.awsRoleId ? `#/roles/${x.awsRoleId}` : null }
        : { label: `${x.gcpEmail ? x.gcpEmail.split('@')[0] : x.uniqueId} → ${x.awsRole}`, meta: `trusted by unique ID ${x.uniqueId} in statement ${x.statement + 1}`, window: `#/roles/${x.awsRoleId}`, winTitle: x.awsRole, winEyebrow: 'AWS · ROLE' });
      const broad = l.pairs.filter((x) => x.broad).length;
      return { eyebrow: into ? 'ACROSS CLOUDS · AWS → GOOGLE CLOUD' : 'ACROSS CLOUDS · GOOGLE CLOUD → AWS', title: `${a} → ${b}`, swatch: l.kind === 'xcloudHigh' ? RED : GCP, round: true,
        sub: into ? `${l.pairs.length} way${l.pairs.length === 1 ? '' : 's'} for AWS identities to act in Google Cloud through workload identity federation` : `${l.pairs.length} AWS role${l.pairs.length === 1 ? '' : 's'} trusting a Google service account`,
        tags: broad ? [{ t: `⚠ ANY ROLE IN ${a.toUpperCase()}`, c: RED }] : [],
        summary: into ? (broad ? `The pool has no attribute condition, so every role and user in ${a} can use ${broad === 1 ? 'one of these' : `${broad} of these`}. Pin it to the role that needs it.` : 'Each is pinned to one AWS role.')
          : 'Code running as these service accounts can get an AWS session in the role, with no AWS key.',
        rows: [], lists: [{ title: into ? 'AWS role → Google Cloud identity' : 'Service account → AWS role', items }],
        actions: into ? [['Identities from AWS', '#/roles?cloud=gcp&source=aws', true]] : [['Trust map', `#/trust?q=${encodeURIComponent('provider:google')}`, true]] };
    }
    if (/^ext/.test(l.kind) && l.gcp) {
      const src = M.sources.find((x) => x.id === l.from), g = M.by.get(l.to);
      return { eyebrow: 'GOOGLE CLOUD · FROM OUTSIDE', title: `${a} → ${b}`, sub: src.sub, swatch: l.kind === 'extHigh' ? RED : l.kind === 'extWarn' ? WARN : '#d5dceb', round: true,
        tags: l.kind === 'extHigh' ? [{ t: '⚠ ANY IDENTITY', c: RED }] : l.kind === 'extWarn' ? [{ t: 'OUTSIDE YOUR DOMAIN', c: WARN }] : [], rows: [],
        lists: [{ title: `In ${g.name}`, items: (src.targets.find((t) => t.accountId === l.to)?.roles || []).map((pid) => ({ label: gcpName(pid), window: `#/gcp/principals/${pid}`, winTitle: gcpName(pid), winEyebrow: 'GOOGLE CLOUD · IDENTITY' })) }],
        actions: [['Identities', `#/roles?cloud=gcp&project=${encodeURIComponent(g.name)}`, true]] };
    }
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
      const q = `account:${acct.awsAccountId} ${trustQ(s)}`;
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
        actions: [...(top ? [['Its calls', `#/events?role=${top.roleId}&q=${encodeURIComponent(`user:${top.caller.replace(/^user\//, '')}`)}&range=7d`, true]] : []), [`Open ${b}`, `#/space?view=account&account=${l.to}`], ['Track sessions', () => openTrack(top ? { role: top.roleId } : { account: l.to }, top ? `${top.role} in ${b}` : b)], ...(top ? [['Role', `#/roles/${top.roleId}`]] : [])] };
    }
    if (l.kind === 'denied') return { eyebrow: 'REFUSED CALLS', title: `${a} → ${b}`, sub: '7 days', swatch: RED, round: true, tags: [{ t: `⚠ ${num(l.denied)} DENIED`, c: RED }],
      rows: [row('What it means', `${num(l.denied)} calls from ${a} to ${b} were refused by IAM. A missing permission, or something trying what it should not.`, 'bad')], actions: [['Open role', `#/roles/${l.from}`, true]] };
    if (l.kind === 'in' || l.kind === 'out') return { eyebrow: 'ROLE CHAINING · 7 DAYS', title: `${a} → ${b}`, sub: 'between this account and a neighbour', swatch: '#9cc7b4', round: true, tags: [], rows: [], actions: [] };
    if (l.kind === 'use1') return { eyebrow: 'CALLS · 7 DAYS', title: `${a} → ${b}`, sub: '', swatch: '#9cc7b4', round: true, tags: [], rows: [], actions: [] };
    return null;
  }
  // the Trust map query for one outside identity
  const trustQ = (x) => (x.group === 'external-account' ? `from:${x.key.replace(/^acct:/, '')}` : x.group === 'public' ? 'source:public' : `provider:"${x.label}"`);
  // nothing picked: what the whole scene says, and where to start
  function overview() {
    const order = { high: 0, medium: 1 };
    const ways = [...M.sources].filter((x) => !x.gcp || x.risk === 'high').sort((a, b) => (order[a.risk] ?? 2) - (order[b.risk] ?? 2) || (b.sessions || 0) - (a.sessions || 0)).slice(0, 6)
      .map((x) => ({ label: x.label, icon: GLYPH[x.group] || 'account', tone: x.risk === 'high' ? 'bad' : x.risk === 'medium' ? 'warn' : null, meta: [x.sub, x.findings[0] || 'conditions pinned', x.sessions ? `used ${num(x.sessions)}×` : 'never used'].join(' · '), pick: x.id }));
    const risky = M.sources.filter((x) => x.risk === 'high').length, loose = M.sources.filter((x) => x.risk === 'medium').length;
    if (M.view === 'estate') {
      const live = awsGroups().filter((g) => !g.planned), roles = live.reduce((n, g) => n + g.roles, 0), cold = live.reduce((n, g) => n + g.cold, 0), high = live.reduce((n, g) => n + g.high, 0);
      return { eyebrow: 'OVERVIEW', title: 'Your estate', sub: 'Click anything on the map for its details', swatch: '#2a8a5c', closable: false, tags: [],
        summary: `${live.length} account${live.length === 1 ? '' : 's'} with ${num(roles)} ${noun}. ${roles ? Math.round((100 * cold) / roles) : 0}% of them were never called. ${M.sources.filter((x) => !x.gcp).length + M.hidden} identities outside your org can get in${risky ? `, ${risky} through risky trust` : ''}.${M.gcp ? ` Behind it, Google Cloud: ${M.gcp.projects.length} projects, ${num(M.gcp.projects.reduce((n, g) => n + g.roles, 0))} service accounts, ${M.gcp.xlinks.reduce((n, l) => n + l.pairs.length, 0)} paths between the clouds.` : ''}`,
        stats: [{ k: 'Accounts', v: num(live.length) }, { k: Noun, v: num(roles) }, { k: 'Never called', v: num(cold), tone: roles && cold / roles > 0.5 ? 'warn' : null },
          { k: 'High-risk roles', v: num(high), tone: high ? 'bad' : null }, { k: 'Risky ways in', v: num(risky), tone: risky ? 'bad' : null }, { k: 'Loose ways in', v: num(loose), tone: loose ? 'warn' : null }],
        rows: [],
        lists: [{ title: 'Ways in to check first', hint: 'Identities outside your org, worst trust first.', items: ways, empty: 'No identity outside your org can get in.' },
          ...(M.gcp ? [{ title: 'Between AWS and Google Cloud', hint: 'Where an identity in one cloud can act in the other. Red: any role in the AWS account can use it.',
            items: M.gcp.xlinks.map((l) => ({ label: `${nameOf(l.from)} → ${nameOf(l.to)}`, meta: l.pairs.map((x) => (l.dir === 'aws-gcp' ? `${x.awsRole || 'any role'} → ${x.gcpEmail ? x.gcpEmail.split('@')[0] : 'direct'}` : `${(x.gcpEmail || '').split('@')[0]} → ${x.awsRole}`)).join(' · '),
              tone: l.kind === 'xcloudHigh' ? 'bad' : null, pick: l.id })), empty: 'No path between the clouds.' }] : []),
          { title: `Accounts with high-risk ${noun}`, items: live.filter((g) => g.high).sort((a, b) => b.high - a.high).slice(0, 6).map((g) => ({ label: g.name, icon: 'account', meta: `${ENV[g.env].name} · ${num(g.roles)} ${noun}`, value: `${g.high} high`, tone: 'bad', pick: g.id })), empty: `No account has a high-risk one.` }],
        actions: [['Trust map', '#/trust', true], ['All roles', '#/roles'], ['All calls', '#/events']] };
    }
    const denied = M.roles.filter((r) => r.denied7).sort((a, b) => b.denied7 - a.denied7);
    return { eyebrow: `OVERVIEW · ${ENV[M.account.environment]?.name.toUpperCase() || ''}`, title: M.account.name, sub: `${M.account.awsAccountId} · click anything on the map for its details`, swatch: ENV[M.account.environment]?.base || '#2a8a5c', closable: false, tags: [],
      summary: `${num(M.roleCount)} roles, ${num(M.roles.length)} called this week across ${M.towers.length} services. ${M.sources.length + M.hidden} identities outside your org and ${M.fars.length} of your other accounts connect to it.`,
      stats: [{ k: 'Roles', v: num(M.roleCount) }, { k: 'Called · 7 d', v: num(M.roles.length) }, { k: 'Never called', v: num(M.rim.length), tone: M.roleCount && M.rim.length / M.roleCount > 0.5 ? 'warn' : null },
        { k: 'Refused calls', v: num(denied.reduce((n, r) => n + r.denied7, 0)), tone: denied.length ? 'bad' : null }, { k: 'Risky ways in', v: num(risky), tone: risky ? 'bad' : null }, { k: 'Other accounts', v: num(M.fars.length) }],
      rows: [],
      lists: [{ title: 'Ways in to check first', hint: 'Identities outside your org, worst trust first.', items: ways, empty: 'No identity outside your org can get in.' },
        ...(denied.length ? [{ title: 'Roles with refused calls', items: denied.slice(0, 6).map((r) => ({ label: pretty(r.name).label, meta: r.cluster.label, value: num(r.denied7), tone: 'bad', pick: r.id })) }] : []),
        { title: 'Busiest roles', items: [...M.roles].sort((a, b) => b.calls7 - a.calls7).slice(0, 6).map((r) => ({ label: pretty(r.name).label, meta: r.services.map((x) => x.name).slice(0, 3).join(' · '), value: kfmt(r.calls7), pick: r.id })) }],
      actions: [['Its calls', `#/events?account=${M.account.id}`, true], ['Track sessions', () => openTrack({ account: M.account.id }, M.account.name)], ['Trust map', `#/trust?q=${encodeURIComponent(`account:${M.account.awsAccountId}`)}`], ['Back to estate', '#/space']] };
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
    if (M.view === 'estate' && isGcp(id) && M.by.has(id)) return projectDetail(M.by.get(id));
    if (M.view === 'estate') {
      const g = M.by.get(id);
      if (g?.planned) return { eyebrow: `PLANNED · ${ENV[g.env].name.toUpperCase()}${g.ou ? ` · ${g.ou}` : ''}`, title: g.name, sub: g.awsAccountId, swatch: ENV[g.env].base, tags: [tag('NOT ONBOARDED', '#d5dceb')],
        rows: [...(g.note ? [row('Note', g.note)] : []), row('Status', 'A placeholder: nothing is read from this account until it is onboarded.')],
        actions: [['Onboard', `#/accounts/new?from=${g.id}`, true], ['Accounts', '#/accounts']] };
      if (g) {
        const look = M.events.find((e) => e.target === g.id);
        const chain = (l) => l.kind === 'chain' || l.kind === 'new';
        const fromOut = M.sources.map((x) => ({ x, t: x.targets.find((t) => t.accountId === g.id) })).filter((o) => o.t)
          .sort((a, b) => ({ high: 0, medium: 1 }[a.x.risk] ?? 2) - ({ high: 0, medium: 1 }[b.x.risk] ?? 2) || (b.t.sessions || 0) - (a.t.sessions || 0));
        const ins = M.links.filter((l) => l.to === g.id && chain(l)), outs = M.links.filter((l) => l.from === g.id && chain(l));
        const scan = M.scanner?.targets.find((t) => t.accountId === g.id);
        const today = g.hourly.reduce((n, x) => n + x.sessions, 0), risky = fromOut.filter((o) => o.x.risk === 'high').length;
        const plural = (n, one, many = `${one}s`) => `${n} ${n === 1 ? one : many}`;
        return { eyebrow: `ACCOUNT · ${ENV[g.env].name.toUpperCase()}${g.ou ? ` · ${g.ou}` : ''}`, title: g.name, sub: g.awsAccountId, swatch: ENV[g.env].base,
          tags: [...(g.high ? [{ t: `⚠ ${g.high} HIGH-RISK ROLE${g.high === 1 ? '' : 'S'}`, c: RED, href: `#/roles?accounts=${g.id}&risks=High` }] : []), ...(look ? [tag(look.kind, TONE[look.tone] || '#fff')] : [])],
          summary: `${plural(fromOut.length, 'identity', 'identities')} from outside your org${risky ? ` (${risky} with risky trust)` : ''} and ${ins.length} of your other accounts can get in. It reaches ${plural(outs.length, 'other account')}.`,
          stats: [{ k: 'Roles', v: num(g.roles) }, { k: 'Never called', v: num(g.cold), tone: g.roles && g.cold / g.roles > 0.5 ? 'warn' : null, hint: g.roles ? `${Math.round((100 * g.cold) / g.roles)}% of its roles` : '' },
            { k: 'High risk', v: num(g.high), tone: g.high ? 'bad' : null }, { k: 'Calls · 7 d', v: kfmt(g.calls7) }, { k: 'Sessions · 24 h', v: num(today) }, { k: 'Ways in', v: num(fromOut.length + ins.length), tone: risky ? 'bad' : null }],
          rows: look ? [row('Look at', `${look.text} (${hourLabel(look.hour)})`, 'bad')] : [],
          lists: [
            { title: 'Who can get in · from outside your org', hint: 'Sign-in providers, pipelines, vendors and other AWS accounts that a trust policy here lets in.',
              items: fromOut.map(({ x, t }) => ({ label: x.label, icon: GLYPH[x.group] || 'account', tone: x.risk === 'high' ? 'bad' : x.risk === 'medium' ? 'warn' : null,
                meta: [x.sub, plural(t.roles.length, 'role'), t.sessions ? `used ${num(t.sessions)}×` : 'never seen coming in'].join(' · '), pick: x.id,
                window: `#/trust?q=${encodeURIComponent(`account:${g.awsAccountId} ${trustQ(x)}`)}`, winTitle: `${x.label} → ${g.name}` })), empty: 'No trust policy here lets anyone outside your org in.' },
            { title: 'Who can get in · your other accounts', hint: 'Seen entering a role here in the last 90 days. Click one to replay those sessions.',
              items: [...ins.map((l) => ({ label: M.by.get(l.from).name, icon: 'account', meta: `${plural(l.roles.length, 'role pair')} · last ${ago(l.lastSeen)}${l.kind === 'new' ? ' · new today' : ''}`, value: num(l.sessions), pick: l.id,
                window: `#/track?account=${g.id}&from=${l.from}`, winTitle: `${M.by.get(l.from).name} → ${g.name}`, winEyebrow: 'TRACK · SESSIONS THAT CAME IN' })),
              ...(scan ? [{ label: 'Curious Monkey', icon: 'cm', meta: `this portal's scanner · ${scan.sessions ? `last ${ago(scan.lastSeen)}` : 'no sign-in seen yet'}`, value: num(scan.sessions), pick: CM_ID }] : [])], empty: 'None of your other accounts entered it in 90 days.' },
            { title: 'Where it goes', hint: 'Accounts a role or user here entered in the last 90 days. Click one to replay those sessions.',
              items: outs.map((l) => ({ label: M.by.get(l.to).name, icon: 'account', meta: `${plural(l.roles.length, 'role pair')} · last ${ago(l.lastSeen)}`, value: num(l.sessions), pick: l.id,
                window: `#/track?account=${l.to}&from=${g.id}`, winTitle: `${g.name} → ${M.by.get(l.to).name}`, winEyebrow: 'TRACK · SESSIONS THAT WENT OUT' })), empty: 'It entered no other account in 90 days.' },
            ...(M.gcp ? [{ title: 'Google Cloud', hint: 'Where roles here can act in Google Cloud, and which Google service accounts can sign in here.',
              items: M.links.filter((l) => /^xcloud/.test(l.kind) && (l.from === g.id || l.to === g.id)).flatMap((l) => l.pairs.map((x) => (l.dir === 'aws-gcp'
                ? { label: `${x.awsRole || 'any role'} → ${x.gcpEmail ? x.gcpEmail.split('@')[0] : `${x.gcpProject} (direct)`}`, meta: `in ${x.gcpProject}${x.broad ? ' · the pool has no condition' : ''}`, tone: x.broad ? 'bad' : null, pick: l.id,
                  window: x.gcpPrincipal ? `#/gcp/principals/${x.gcpPrincipal}` : null, winTitle: x.gcpEmail || x.label, winEyebrow: 'GOOGLE CLOUD · IDENTITY' }
                : { label: `${(x.gcpEmail || '').split('@')[0]} → ${x.awsRole}`, meta: `from ${x.gcpProject}`, pick: l.id, window: `#/roles/${x.awsRoleId}`, winTitle: x.awsRole, winEyebrow: 'AWS · ROLE' }))),
              empty: 'No path to or from Google Cloud.' }] : [])],
          actions: [['Zoom in', `#/space?view=account&account=${g.id}${whoQs(who, '&')}`, true], ['Its calls', `#/events?account=${g.id}`], ['Track sessions', () => openTrack({ account: g.id }, g.name)], ['Account radar', `#/?view=account&account=${g.id}`]] };
      }
    }
    const s = M.sources.find((x) => x.id === id);
    if (s?.gcp) {
      return { eyebrow: `GOOGLE CLOUD · ${s.group === 'oidc' ? 'FEDERATED' : s.group === 'public' ? 'PUBLIC' : 'OUTSIDE YOUR DOMAIN'}`, title: s.label, sub: s.sub, swatch: '#d5dceb', round: true,
        tags: s.risk === 'high' ? [tag('⚠ HIGH', RED)] : s.risk === 'medium' ? [tag('OUTSIDE', WARN)] : [], rows: [],
        lists: [{ title: 'Projects it can get into', items: s.targets.map((t) => ({ label: M.by.get(t.accountId)?.name || t.accountId, meta: `${t.roles.length} identit${t.roles.length === 1 ? 'y' : 'ies'}`, pick: t.accountId })) }],
        actions: s.principal ? [['Open identity', `#/gcp/principals/${s.principal}`, true]] : [['Federated identities', '#/roles?cloud=gcp&source=wif', true]] };
    }
    if (s) {
      const items = M.view === 'estate'
        ? s.targets.map((t) => ({ label: M.by.get(t.accountId)?.name || 'an account', meta: `${t.roles.length} role${t.roles.length === 1 ? '' : 's'}${t.sessions ? ` · ${num(t.sessions)} sessions` : ''}`, pick: t.accountId }))
        : roleItems(s.targets.flatMap((t) => t.edges || []), s.targets.flatMap((t) => t.roles));
      return { eyebrow: `OUTSIDE · ${s.group.toUpperCase()}`, title: s.label, sub: s.sub, swatch: '#d5dceb', round: true,
        tags: s.risk === 'high' ? [tag('⚠ HIGH', RED)] : s.risk === 'medium' ? [tag('LOOSE TRUST', WARN)] : [],
        rows: [row('Trust', s.findings.length ? s.findings.join('; ') : 'conditions pinned: nothing to flag', s.findings.length ? 'bad' : 'ok'),
          row('Seen', s.sessions ? `${num(s.sessions)} sessions · last ${ago(s.lastSeen)}` : 'never seen coming in')],
        lists: [{ title: M.view === 'estate' ? 'Accounts it can enter' : 'Roles it can enter', items }],
        actions: [['Trust map', `#/trust?q=${encodeURIComponent(trustQ(s))}`, true]] };
    }
    if (M.view !== 'account') return null;
    const r = M.byRole.get(id);
    if (r) {
      const p = pretty(r.name);
      const callers = M.sources.filter((x) => x.targets.some((t) => t.roles.includes(r.id))).map((x) => ({ label: x.label, icon: GLYPH[x.group] || 'account', meta: x.sub, tone: x.risk === 'high' ? 'bad' : null, pick: x.id }));
      const cmT = M.scanner?.targets.find((t) => t.roleId === r.id);
      if (cmT) callers.unshift({ label: 'Curious Monkey', icon: 'cm', meta: `this portal's scanner · last ${ago(cmT.lastSeen)}`, value: num(cmT.sessions), pick: CM_ID });
      const way = (dir) => M.fars.flatMap((n) => n.links.filter((l) => l.roleId === r.id && l.dir === dir).map((l) => ({ label: `${n.name} · ${l.otherRole}`,
        meta: [l.sessions ? `used · ${num(l.sessions)} sessions` : 'not used in 7 days', l.allowed ? 'allowed by trust' : 'seen chaining'].join(' · '), value: l.sessions ? num(l.sessions) : '—', tone: l.worst === 'high' ? 'bad' : null, pick: `far:${n.id}` })));
      const chained = st.dir === 'out' ? [] : way('in'), goes = st.dir === 'in' ? [] : way('out');
      const isUser = r.kind === 'iam-user';
      return { eyebrow: `${isUser ? 'IAM USER' : 'ROLE'} · ${r.cluster.label.toUpperCase()}`, title: p.label, sub: p.kind ? `${p.kind} · ${r.name}` : `${M.account.name} · ${M.account.awsAccountId}`, swatch: ENV[r.cluster.env].base, round: true,
        tags: [...(r.risk === 'High' ? [{ t: '⚠ HIGH RISK', c: RED, href: `#/roles/${r.id}` }] : []), ...(r.denied7 ? [tag(`⚠ ${num(r.denied7)} DENIED`, RED)] : [])],
        summary: `${r.calls7 ? `Called ${kfmt(r.calls7)} times this week into ${r.services.length} service${r.services.length === 1 ? '' : 's'}.` : 'Quiet this week.'} ${callers.length + chained.length} can enter it${goes.length ? `; it can go on to ${goes.length} role${goes.length === 1 ? '' : 's'} elsewhere` : ''}.`,
        stats: [{ k: 'Calls · 7 d', v: kfmt(r.calls7) }, { k: 'Refused', v: num(r.denied7 || 0), tone: r.denied7 ? 'bad' : null }, { k: 'Can enter it', v: num(callers.length + chained.length), tone: callers.some((c) => c.tone === 'bad') ? 'bad' : null }],
        rows: [],
        lists: [{ title: 'Calls into', items: r.services.map((v) => ({ label: v.name, value: kfmt(v.calls), meta: v.denied ? `⚠ ${num(v.denied)} refused` : null, tone: v.denied ? 'bad' : null, pick: `svc:${v.name}` })) },
          ...(st.dir === 'out' ? [] : [{ title: 'Entered by', items: [...callers, ...chained], empty: 'only callers inside this account' }]),
          ...(st.dir === 'in' ? [] : [{ title: 'Can go to', items: goes, empty: 'no role in your other accounts trusts it' }]),
          { title: 'Sessions · click to replay', items: sessionItems(r.id, p.label), empty: sessions.get(r.id) === 'loading' ? 'Loading…' : 'No sessions recorded in the last 30 days' }],
        actions: isUser ? [['Keys and sign-in', `#/users/${r.id}`, true], ['Permission analysis', `#/roles/${r.id}`]]
          : [['Open role', `#/roles/${r.id}`, true], ['Its calls', `#/events?role=${r.id}&range=7d`], ['Track sessions', () => openTrack({ role: r.id }, p.label)]] };
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
    if (n) {
      const here = (l) => (l.roleId && M.byRole.get(l.roleId) ? pretty(M.byRole.get(l.roleId).name).label : l.roleId ? 'a role here' : `${M.account.name} (whole account)`);
      const item = (l) => ({ label: l.dir === 'in' ? `${l.otherRole || n.name} → ${here(l)}` : `${here(l)} → ${l.otherRole || 'a role there'}`,
        meta: [l.sessions ? `used · ${num(l.sessions)} sessions in 7 days` : null, l.allowed ? `allowed by ${l.allowed} trust statement${l.allowed === 1 ? '' : 's'}` : 'not in a trust policy (seen chaining)', l.allowed && !l.sessions ? 'not used in 7 days' : null].filter(Boolean).join(' · '),
        value: l.sessions ? String(l.sessions) : '—', tone: l.worst === 'high' ? 'bad' : null, pick: l.roleId && M.byRole.has(l.roleId) ? l.roleId : null, href: l.roleId && !M.byRole.has(l.roleId) ? `#/roles/${l.roleId}` : null });
      const ins = n.links.filter((l) => l.dir === 'in'), outs = n.links.filter((l) => l.dir === 'out');
      return { eyebrow: 'YOUR OTHER ACCOUNT', title: n.name, sub: `${n.awsAccountId || ''}${n.sessions ? ` · ${num(n.sessions)} chained sessions in 7 days` : ' · no chaining seen in 7 days'}`, swatch: ENV[n.env].base, tags: [], rows: [],
        lists: [
          ...(st.dir !== 'out' ? [{ title: `Can come in · ${ins.length}`, items: ins.map(item), empty: `Nothing in ${n.name} can enter ${M.account.name}.` }] : []),
          ...(st.dir !== 'in' ? [{ title: `Can go out to it · ${outs.length}`, items: outs.map(item), empty: `${M.account.name} cannot enter ${n.name}.` }] : []),
          ...(n.moreLinks ? [{ title: `${n.moreLinks} more not shown`, items: [] }] : []),
        ],
        actions: [['Open in Space', `#/space?view=account&account=${n.id}`, true], ['Trust map', `#/trust?q=${encodeURIComponent(`from:${n.awsAccountId || ''}`)}`]] };
    }
    return null;
  }
  function gcpName(pid) {
    for (const g of M.gcp?.projects || []) { const a = g.project.accounts.find((x) => x.id === pid); if (a) return a.email; }
    return 'an identity';
  }
  // one Google Cloud project: its service accounts, and the paths to and from AWS and outside
  function projectDetail(g) {
    const p = g.project, plural = (n, one, many = `${one}s`) => `${n} ${n === 1 ? one : many}`, tag = (t, c) => ({ t, c });
    const ins = M.links.filter((l) => l.to === g.id && l.kind.startsWith('xcloud')), outs = M.links.filter((l) => l.from === g.id && l.kind.startsWith('xcloud'));
    const fromOut = M.sources.filter((x) => x.gcp && x.targets.some((t) => t.accountId === g.id));
    const broad = ins.some((l) => l.kind === 'xcloudHigh');
    const sa = (a) => ({ label: a.email.split('@')[0], meta: [a.reasons[0]?.title, a.keys ? `${a.keys} key${a.keys === 1 ? '' : 's'}` : null, ...(a.sources.aws || []).map((x) => `from ${x}`), `${num(a.permissions)} permissions`].filter(Boolean).join(' · '),
      tone: a.risk === 'High' ? 'bad' : a.risk === 'Medium' ? 'warn' : null, window: `#/gcp/principals/${a.id}`, winTitle: a.email, winEyebrow: 'GOOGLE CLOUD · SERVICE ACCOUNT' });
    return { eyebrow: `GOOGLE CLOUD PROJECT · ${ENV[g.env].name.toUpperCase()}`, title: p.projectId, sub: p.name !== p.projectId ? p.name : `project ${p.number}`, swatch: ENV[g.env].base,
      tags: [...(p.risky ? [{ t: `⚠ ${p.risky} HIGH-RISK SERVICE ACCOUNT${p.risky === 1 ? '' : 'S'}`, c: RED, href: `#/roles?cloud=gcp&project=${encodeURIComponent(p.projectId)}` }] : []), ...(broad ? [tag('⚠ ANY AWS ROLE CAN GET IN', RED)] : [])],
      summary: `${plural(p.accounts.length, 'service account')}${p.keys ? `, ${plural(p.keys, 'user-managed key')}` : ''}. ${ins.length ? `${plural(ins.reduce((n, l) => n + l.pairs.length, 0), 'way')} in from AWS` : 'Nothing from AWS gets in'}${outs.length ? `; it reaches ${plural(outs.length, 'AWS account')}` : ''}${fromOut.length ? `; ${plural(fromOut.length, 'identity', 'identities')} from outside your organization` : ''}.`,
      stats: [{ k: 'Service accounts', v: num(p.accounts.length) }, { k: 'High risk', v: num(p.risky), tone: p.risky ? 'bad' : null }, { k: 'Keys', v: num(p.keys), tone: p.keys ? 'warn' : null },
        { k: 'From AWS', v: num(ins.reduce((n, l) => n + l.pairs.length, 0)), tone: broad ? 'bad' : null }, { k: 'Into AWS', v: num(outs.reduce((n, l) => n + l.pairs.length, 0)) }, { k: 'From outside', v: num(fromOut.length), tone: fromOut.some((x) => x.risk === 'high') ? 'bad' : null }],
      rows: [],
      lists: [
        { title: 'From AWS · into this project', hint: 'AWS roles that can become a service account here, or hold roles here, through workload identity federation.',
          items: ins.flatMap((l) => l.pairs.map((x) => ({ label: `${x.awsAccountName} · ${x.awsRole || 'any role'}`, meta: `→ ${x.gcpEmail ? x.gcpEmail.split('@')[0] : 'holds roles directly'}${x.broad ? ' · no condition on the pool' : ''}`, tone: x.broad ? 'bad' : null, pick: l.id,
            window: x.gcpPrincipal ? `#/gcp/principals/${x.gcpPrincipal}` : null, winTitle: x.gcpEmail || x.label, winEyebrow: 'GOOGLE CLOUD · IDENTITY' }))), empty: 'No AWS identity can get in.' },
        { title: 'Into AWS · from this project', hint: 'AWS roles whose trust policy accepts a service account here.',
          items: outs.flatMap((l) => l.pairs.map((x) => ({ label: `${x.gcpEmail.split('@')[0]} → ${x.awsRole}`, meta: x.awsAccountName, pick: l.id, window: `#/roles/${x.awsRoleId}`, winTitle: x.awsRole, winEyebrow: 'AWS · ROLE' }))), empty: 'No AWS role trusts a service account here.' },
        ...(fromOut.length ? [{ title: 'From outside your organization', items: fromOut.map((x) => ({ label: x.label, icon: x.kind, meta: x.sub, tone: x.risk === 'high' ? 'bad' : x.risk === 'medium' ? 'warn' : null, pick: x.id })) }] : []),
        { title: 'Service accounts', hint: 'Riskiest first. Click one for what it can do and who can become it.', items: p.accounts.filter((a) => !a.managed).map(sa), empty: 'None.' }],
      actions: [['Identities', `#/roles?cloud=gcp&project=${encodeURIComponent(p.projectId)}`, true], ['Connections', '#/accounts?cloud=gcp']] };
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
  // The right-hand panel, top to bottom: what it is, one sentence on what matters, the numbers, what you can do,
  // then who and what it connects to. A row or button with the window mark opens a window over Space; ◎ finds it on the map.
  const ICONS = { oidc: 'M6 1.5l4.5 2.6v5.2L6 11.9 1.5 9.3V4.1z', saml: 'M6 1l5 5-5 5-5-5z', account: 'M6 6m-4.5 0a4.5 4.5 0 1 0 9 0a4.5 4.5 0 1 0-9 0', web: 'M6 6m-4.5 0a4.5 4.5 0 1 0 9 0a4.5 4.5 0 1 0-9 0M1.5 6h9M6 1.5c2 2 2 7 0 9M6 1.5c-2 2-2 7 0 9', cm: 'M6 6m-4 0a4 4 0 1 0 8 0a4 4 0 1 0-8 0' };
  const icon = (kind) => svg('svg', { class: `sp-ico sp-ico-${kind}`, width: 12, height: 12, viewBox: '0 0 12 12', 'aria-hidden': 'true' }, svg('path', { d: ICONS[kind] || ICONS.account, fill: kind === 'cm' ? CM : 'none', stroke: kind === 'cm' ? CM : 'currentColor', 'stroke-width': 1.2 }));
  function panelEl(b) {
    const list = (L) => {
      const ul = h('ul', { class: 'sp-items' }), more = h('button', { class: 'btn sm sp-more' });
      const item = (it) => {
        const open = it.window || (leaves(it.href) ? it.href : null);
        const act = it.onClick || (open ? () => openWin(open, it.winTitle || it.label, it.winEyebrow) : it.pick ? () => set({ sel: it.pick }) : null);
        const body = [it.icon ? icon(it.icon) : null, h('span', { class: 'sp-item-main' }, h('span', { class: 'sp-item-label' }, it.label), it.meta ? h('span', { class: 'sp-item-meta' }, it.meta) : null),
          it.value != null ? h('span', { class: 'mono sp-item-val' }, it.value) : null, open || it.opens ? windowIcon() : null];
        const tip = open || it.opens ? `${it.label} · opens in a window` : it.label;
        const main = act ? h('button', { class: 'sp-item', title: tip, onClick: act }, ...body) : it.href ? h('a', { class: 'sp-item', href: it.href, title: it.label }, ...body) : h('div', { class: 'sp-item' }, ...body);
        const locate = (open || it.onClick) && it.pick ? h('button', { class: 'sp-locate', title: 'Show it on the map', 'aria-label': `Show ${it.label} on the map`, onClick: () => set({ sel: it.pick }) }, '◎') : null;
        return h('li', { class: it.tone ? `sp-${it.tone}` : null }, main, locate);
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
      return h('section', { class: 'sp-list-block' }, h('div', { class: 'sp-lh' }, h('h3', null, L.title), h('span', { class: `mono sp-count${L.items.length ? '' : ' zero'}` }, String(L.items.length))),
        L.hint && L.items.length ? h('p', { class: 'sp-hint' }, L.hint) : null, filter || null, ul, more);
    };
    const action = ([label, href, primary]) => {
      const cls = primary ? 'btn primary small' : 'btn small';
      if (typeof href === 'function') return h('button', { class: cls, title: `${label} · opens in a window`, onClick: href }, label, windowIcon());
      if (leaves(href)) return h('button', { class: cls, title: `${label} · opens in a window`, onClick: () => openWin(href, `${label} · ${b.title}`) }, label, windowIcon());
      return h('a', { class: cls, href, title: `${label} · stays in Space` }, label, ' →');
    };
    const tagEl = (t) => (t.href ? h('button', { class: 'sp-tag sp-tag-link', title: 'Show them · opens in a window', style: `color:${t.c};border-color:${t.c}`, onClick: () => openWin(t.href, t.t.replace(/^⚠ /, '')) }, t.t, windowIcon())
      : h('span', { class: 'sp-tag', style: `color:${t.c};border-color:${t.c}` }, t.t));
    return h('section', { class: 'sp-panel', 'aria-label': `${b.closable === false ? '' : 'Selected: '}${b.title}` },
      h('div', { class: 'sp-card-head' },
        h('div', { class: 'sp-card-titles' },
          h('div', { class: 'sp-eyebrow' }, h('span', null, b.eyebrow)),
          h('div', { class: 'sp-card-title' }, h('span', { class: 'sp-swatch', style: `background:${b.swatch}${b.round ? ';border-radius:50%' : ''}` }), h('b', null, b.title)),
          b.sub ? h('span', { class: 'sp-card-sub' }, b.sub) : null),
        b.closable === false ? null : h('button', { class: 'sp-x', 'aria-label': 'Close and show the overview', title: 'Close and show the overview', onClick: () => set({ sel: null }) }, '×')),
      b.tags.length ? h('div', { class: 'sp-tags' }, ...b.tags.map(tagEl)) : null,
      b.summary ? h('p', { class: 'sp-sum' }, b.summary) : null,
      b.stats?.length ? h('div', { class: 'sp-stats' }, ...b.stats.map((x) => h('div', { class: `sp-stat${x.tone ? ` sp-${x.tone}` : ''}`, title: x.hint || null }, h('b', { class: 'mono' }, x.v), h('span', null, x.k)))) : null,
      b.rows.length ? h('dl', null, ...b.rows.map((r) => h('div', null, h('dt', null, r.k), h('dd', { class: r.tone ? `sp-${r.tone}` : null }, r.v)))) : null,
      b.actions.length ? h('div', { class: 'sp-card-actions' }, ...b.actions.map(action)) : null,
      ...(b.lists || []).map(list));
  }

  // ---------- beside the plane ----------
  function renderSide() {
    const focus = st.zone, selRole = M.view === 'account' ? M.byRole.get(st.sel) : null;
    const card = (on, chip, name, val, meta, onClick) => h('button', { class: 'sp-zonecard', 'aria-pressed': String(on), onClick }, h('span', { class: 'sp-chip', style: chip }),
      h('span', { class: 'sp-zc-body' }, h('span', { class: 'sp-zc-top' }, h('span', null, name), h('span', { class: 'mono' }, val)), h('span', { class: 'sp-zc-meta' }, meta)));
    const row = (on, dot, name, meta, val, onClick) => h('button', { class: 'sp-row', 'aria-pressed': String(on), title: name, onClick }, h('span', { class: 'sp-dot', style: dot }),
      h('span', { class: 'sp-row-body' }, h('span', { class: 'sp-row-name' }, name), h('span', { class: 'sp-row-meta' }, meta)), h('span', { class: 'mono sp-row-val' }, val));
    const views = h('div', { class: 'rtabs', role: 'tablist', 'aria-label': 'Space view' },
      h('button', { role: 'tab', 'aria-selected': String(M.view === 'estate'), onClick: () => go(`#/space${wq}`) }, 'Estate'),
      h('button', { role: 'tab', 'aria-selected': String(M.view === 'account'), onClick: () => go(`#/space?view=account&account=${accountId}${whoQs(who, '&')}`) }, 'One account'));
    // who can get in, where it can go, or both
    const picked = M.view === 'estate' && M.by.has(st.sel) ? M.by.get(st.sel) : null;
    const whose = M.view === 'account' ? M.account.name : picked ? picked.name : 'your accounts';
    const ways = (dir) => (M.view === 'account' || picked ? M.links.filter((l) => dirFilter(dir, M, st.sel).link(l) && /^(ext|extWarn|extHigh|in|out|chain|new)$/.test(l.kind)).length : null);
    const dirBtn = (dir, label, tip) => { const n = dir === 'both' ? null : ways(dir);
      return h('button', { role: 'radio', 'aria-checked': String(st.dir === dir), title: tip, onClick: () => set({ dir }) }, label, n != null ? h('span', { class: 'mono faint', style: 'margin-left:6px' }, String(n)) : null); };
    const dirs = h('div', { class: 'sp-dir' },
      h('h2', { class: 'eyebrow' }, `Show paths · ${whose}`),
      h('div', { class: 'rtabs', role: 'radiogroup', 'aria-label': 'Direction' },
        dirBtn('both', 'Both', 'Everything in and out'),
        dirBtn('in', 'In', `Who can get into ${whose}: outside identities, your other accounts, the scanner`),
        dirBtn('out', 'Out', `Where ${whose} can go: other accounts whose roles trust it, or that it chained into`)),
      M.view === 'estate' && !picked && st.dir !== 'both' ? h('p', { class: 'faint tiny', style: 'margin:4px 0 0' }, st.dir === 'in' ? 'Into your org from outside. Pick an account for its own.' : 'Between your accounts. Pick an account for its own.') : null);
    const pickWho = (k) => { const p = new URLSearchParams(ctx.params); if (k === 'all') p.delete('who'); else p.set('who', k); go(`#/space?${p}`); };
    const tabs = h('div', { class: 'stack', style: 'gap:12px' }, views, whoControl(who, pickWho), dirs);
    if (M.view === 'estate') {
      const zones = M.zones.map((z) => {
        if (z.cloud === 'gcp') return null;
        const gs = awsGroups().filter((g) => g.env === z.id), roles = gs.reduce((s, g) => s + g.roles, 0), cold = gs.reduce((s, g) => s + g.cold, 0);
        if (!gs.length) return null;
        const planned = gs.filter((g) => g.planned).length;
        return card(focus === z.id, `background:${ENV[z.id].base}`, ENV[z.id].name, kfmt(gs.reduce((s, g) => s + g.calls7, 0)), `${gs.length - planned} accounts · ${roles ? Math.round((100 * cold) / roles) : 0}% cold${planned ? ` · ${planned} planned` : ''}`, () => set({ zone: focus === z.id ? '' : z.id }));
      });
      const highs = M.sources.filter((s) => s.risk === 'high').length, loose = M.sources.filter((s) => s.risk === 'medium').length;
      const zcards = zones.filter(Boolean);
      zcards.push(card(focus === 'outer', 'background:#d5dceb;transform:rotate(45deg);width:10px;height:10px;margin:0 1px', 'Outside your org', String(M.sources.length + M.hidden), `${highs} risky · ${loose} loose trust`, () => set({ zone: focus === 'outer' ? '' : 'outer' })));
      const list = awsGroups().filter((g) => !focus || focus === 'outer' || g.env === focus).sort((a, b) => b.calls7 - a.calls7);
      const projects = (M.gcp?.projects || []).filter((g) => !focus || focus === 'outer' || g.env === focus).sort((a, b) => b.high - a.high || b.roles - a.roles);
      left.replaceChildren(tabs, h('h2', { class: 'eyebrow' }, M.gcp ? 'Zones · both clouds · click to focus' : 'Zones · click to focus'), h('div', { class: 'sp-cards' }, ...zcards),
        h('div', { class: 'sp-listhead' }, h('h2', { class: 'eyebrow' }, 'Accounts · 7-day calls'), h('span', { class: 'mono faint' }, String(list.length))),
        h('div', { class: 'sp-list' }, ...list.map((g) => row(st.sel === g.id, g.planned ? `border:1.5px dashed ${ENV[g.env].hot}` : `background:${ENV[g.env].base}`, g.name, g.planned ? `${g.awsAccountId} · planned` : g.awsAccountId, g.planned ? '—' : kfmt(g.calls7), () => set({ sel: st.sel === g.id ? null : g.id })))),
        ...(M.gcp ? [h('div', { class: 'sp-listhead' }, h('h2', { class: 'eyebrow' }, 'Google Cloud projects · service accounts'), h('span', { class: 'mono faint' }, String(projects.length))),
          h('div', { class: 'sp-list' }, ...projects.map((g) => row(st.sel === g.id, `background:${ENV[g.env].base};border-radius:2px;outline:1px solid ${GCP}`, g.name, `${ENV[g.env].name}${g.high ? ` · ${g.high} high risk` : ''}`, String(g.roles), () => set({ sel: st.sel === g.id ? null : g.id }))))] : []));
    } else {
      const cur = selRole?.cluster || M.groups[0];
      const accounts = h('select', { class: 'sp-select', 'aria-label': 'Account', onChange: (ev) => go(`#/space?view=account&account=${ev.target.value}${whoQs(who, '&')}`) },
        ...est.accounts.filter((a) => !a.planned).map((a) => h('option', { value: a.id, selected: a.id === accountId }, a.name)));
      left.replaceChildren(tabs, accounts, h('h2', { class: 'eyebrow' }, 'Roles by the service they call most'),
        h('div', { class: 'sp-cards' }, ...M.groups.map((g) => card(cur === g, `border:2px solid ${ENV[g.env].base};border-radius:50%`, g.label, kfmt(g.calls7), `${g.roles.length + g.more} roles`, () => g.roles[0] && set({ sel: g.roles[0].id })))),
        h('div', { class: 'sp-listhead' }, h('h2', { class: 'eyebrow' }, `${cur ? cur.label : 'Roles'} · roles`), h('span', { class: 'mono faint' }, String(cur ? cur.roles.length : 0))),
        h('div', { class: 'sp-list' }, ...(cur ? cur.roles : []).map((r) => row(st.sel === r.id, `background:${r.denied7 ? RED : ENV[r.cluster.env].base};border-radius:50%`, pretty(r.name).label, r.services.map((x) => x.name).join(' · ') || 'quiet this week', kfmt(r.calls7), () => set({ sel: st.sel === r.id ? null : r.id })))));
    }
    const sw = (style) => h('span', { class: 'sp-sw', style });
    const legend = M.view === 'estate' ? [
      [sw('width:30px;height:12px;background:linear-gradient(180deg,#031009,#0b3a26);border:1px solid #2a8a5c'), M.gcp ? 'The green plane in front is AWS; each ring on it is one account' : 'The green plane is your organization; each ring on it is one account'],
      ...(M.gcp ? [[sw('width:30px;height:12px;background:linear-gradient(180deg,#030a14,#0a1f3a);border:1px solid #3d7bd6'), 'The blue plane behind is Google Cloud; each ring is a project, each dot a service account, higher the more it can do, red when high risk'],
        [sw(`width:30px;border-top:2px solid ${GCP}`), 'Blue arc between the planes: an AWS role can act in Google Cloud through federation, or a Google service account can sign in to an AWS role'],
        [sw(`width:30px;border-top:2px solid ${RED}`), 'Red arc between the planes: any role in that AWS account can use it (the pool has no condition)']] : []),
      ...M.zones.map((z) => [sw(`width:12px;height:12px;margin:0 9px;background:${ENV[z.id].base}`), ENV[z.id].name]),
      [sw('width:8px;height:8px;margin:0 11px;border-radius:50%;background:#ffd27f'), 'One dot per busy role. Higher and brighter = more calls in 7 days'],
      [sw('width:8px;height:8px;margin:0 11px;background:#ffd27f'), 'A square is an IAM user (long-lived keys); use Show · IAM users to see only them'],
      [sw(`width:30px;border-top:2px dashed ${COLD}`), 'Grey on the floor: cold, never called. The dashed grey part of a ring is the cold share'],
      ...(M.groups.some((g) => g.planned) ? [[sw('width:12px;height:12px;margin:0 9px;border-radius:50%;border:1.5px dashed #d5dceb'), 'Dashed empty ring: planned, not onboarded yet']] : []),
      [sw(`width:30px;height:10px;border-radius:50%;background:radial-gradient(${ENV[ORDER[0]].base},transparent 70%)`), 'Glow under a ring: calls in the hour you picked'],
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
    const b = (st.sel && detail(st.sel)) || overview();
    const key = h('details', { class: 'sp-legend' }, h('summary', null, 'How to read the map'), ...legend.map(([s, t]) => h('div', null, s, h('span', null, t))),
      M.hidden ? h('p', { class: 'faint tiny' }, `${M.hidden} more identities outside the org are in the Trust map.`) : null);
    key.open = !!st.legend; key.addEventListener('toggle', () => { st.legend = key.open; });
    const top = right.scrollTop, same = right.dataset.for === String(st.sel);
    right.replaceChildren(panelEl(b), key);
    right.dataset.for = String(st.sel); right.scrollTop = same ? top : 0;
  }
  function renderBar() {
    const hour = st.hour, perHour = Array.from({ length: 24 }, (_, i) => M.groups.reduce((s, g) => s + g.prof[i], 0)), max = Math.max(1, ...perHour);
    const nowEv = M.events.filter((e) => e.hour === hour);
    const play = h('button', { class: 'sp-play', 'aria-label': st.playing ? 'Pause the day' : 'Play the day, one hour at a time', 'aria-pressed': String(st.playing),
      onClick: () => { if (st.playing) { stop(); set({ playing: false }); } else { st.playing = true; st.timer = setInterval(() => { if (!page.isConnected) return stop(); set({ hour: (st.hour + 1) % 24 }); }, 1400); render(); } } },
      svg('svg', { width: 14, height: 14, viewBox: '0 0 14 14', 'aria-hidden': 'true' }, st.playing ? svg('path', { d: 'M3 2v10M11 2v10', stroke: 'currentColor', 'stroke-width': 2.4 }) : svg('path', { d: 'M3 1.5 L12 7 L3 12.5 Z', fill: 'currentColor' })));
    const input = h('input', { type: 'range', min: 0, max: 23, step: 1, value: hour, 'aria-label': 'Hour of the last 24 to show (calls made in that hour)', 'aria-valuetext': `${hourLabel(hour)} WIB`,
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
      h('div', null, M.view === 'estate' ? `${awsGroups().length} ACCOUNTS · ${num(awsGroups().reduce((s, g) => s + g.roles, 0))} ${noun.toUpperCase()} · ${M.sources.filter((x) => !x.gcp).length + M.hidden} OUTSIDE${M.gcp ? ` · GOOGLE CLOUD ${M.gcp.projects.length} PROJECTS · ${M.gcp.xlinks.reduce((n, l) => n + l.pairs.length, 0)} CROSS-CLOUD` : ''}` : `${M.roleCount} ROLES · ${M.roles.length} CALLED THIS WEEK · ${M.towers.length} SERVICES`),
      h('div', null, M.view === 'estate' ? 'HEIGHT = CALLS IN 7 DAYS (LOG) · DRAG TO TURN · SHIFT+DRAG TO MOVE · SCROLL TO ZOOM' : 'TOWER = CALLS INTO A SERVICE · DRAG TO TURN · SHIFT+DRAG TO MOVE · SCROLL TO ZOOM'));
    const btn = ([icon, label, fn]) => h('button', { 'aria-label': label, title: label, onClick: fn }, icon);
    const moved = st.px || st.py || st.az !== -14 || st.el !== 33 || st.zoom !== 1.15;
    cam.replaceChildren(
      h('div', { class: 'cam-row' }, h('span', { class: 'eyebrow' }, 'Move'), ...[['←', 'Move the view left', () => set({ px: clampPan(st.px + 120, W) })], ['→', 'Move the view right', () => set({ px: clampPan(st.px - 120, W) })],
        ['↑', 'Move the view up', () => set({ py: clampPan(st.py + 80, H) })], ['↓', 'Move the view down', () => set({ py: clampPan(st.py - 80, H) })]].map(btn)),
      h('div', { class: 'cam-row' }, h('span', { class: 'eyebrow' }, 'Turn'), ...[['⟲', 'Rotate left', () => set({ az: st.az - 20 })], ['⟳', 'Rotate right', () => set({ az: st.az + 20 })],
        ['▲', 'Look from higher', () => set({ el: Math.min(70, st.el + 8) })], ['▼', 'Look from lower', () => set({ el: Math.max(18, st.el - 8) })]].map(btn)),
      h('div', { class: 'cam-row' }, h('span', { class: 'eyebrow' }, 'Zoom'), ...[['+', 'Zoom in', () => set({ zoom: Math.min(3, st.zoom * 1.25) })], ['−', 'Zoom out', () => set({ zoom: Math.max(0.6, st.zoom / 1.25) })]].map(btn),
        h('button', { class: 'cam-reset', disabled: !moved, title: 'Back to the starting view', onClick: () => set({ az: -14, el: 33, zoom: 1.15, px: 0, py: 0 }) }, 'Reset')));
  }

  ctx.setNotices({ title: M.view === 'estate' ? 'Needs a look · last 24 h' : `In ${M.account.name} · last 24 h`,
    items: M.events.map((e) => ({ kind: e.kind, tone: e.tone, text: e.text, where: e.where, time: hourLabel(e.hour), onPick: () => set({ sel: e.target || st.sel, hour: e.hour }) })) });
  render();
  return page;
}
