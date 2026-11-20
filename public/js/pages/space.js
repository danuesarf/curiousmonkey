// Space: the estate as a tilted plane, replayed by the hour.
//   Estate       — the plane is the organization, split into zones by environment. Each account is a ring with one star
//                  per busy role: higher and brighter = more calls in 7 days. Roles with no recorded call lie grey on the
//                  floor, and the dashed grey part of each ring is that share. Identities outside the org that trust
//                  policies let in float off the plane: close and low = the worst trust, far and high = trust that is
//                  pinned. Role chaining between accounts arcs above the plane and lights up in the hours it happened.
//   One account  — services the account calls stand as towers at the centre; roles cluster around the service they
//                  call most; neighbouring accounts sit just past the edge; cold roles ring the floor.
// The bar under the scene picks the hour (the last 24, in the shown time zone); play steps through them.
import { h, svg, get, getCached, num, ago, loadEnvironments, envPalette, whoControl, whoOf, whoQs, COLOR, CHANGE_KIND, fmtClock, TZ_LABEL, TZ, paint, syncUrl, wallMode } from '../lib.js';
import { go, windowIcon } from '../main.js';
import { related, dirFilter, wayEnds, wheelKind, FADE } from './spaceRelated.js';
import { stripResources, estateResourceLinks, accountResources, worstRes } from './spaceResources.js';

const W = 1000, H = 900;
const HOME = { az: -14, el: 33, zoom: 1.15 };   // the starting camera; Reset and 0 go back to it
// one colour per environment, checked together with every pair compared (colour-blind ΔE ≥ 10, normal vision ≥ 17).
// Shared is a muted olive: the only non-red hue that still clears both floors next to the other four.
// base = rings, paths, swatches; hot/dim = the brightest and faintest stars. Red is never an environment.
// environments as set on the Configuration page: colours, and their order east to west across the plane
let ENV = {}, ORDER = [];
const useEnvironments = (list) => { ENV = Object.fromEntries(list.map((e) => [e.id, { name: e.name, ...envPalette(e.color) }])); ORDER = list.map((e) => e.id); };
const RED = COLOR.high, WARN = COLOR.warn, COLD = '#7a8780', OUT = '#c3cbd9';
const TONE = { high: RED, warn: WARN, info: '#ffffff', good: '#6fe3b0', medium: WARN, low: '#d5dceb' };
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
  if (kind === 'box') return `M${f(x - s)} ${f(y - s)} L${f(x + s)} ${f(y - s)} L${f(x + s)} ${f(y + s)} L${f(x - s)} ${f(y + s)} Z`;
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
  for (const s of sources) for (const t of s.targets) if (by.has(t.accountId) && t.roles.length) {
    const w = s.trustWorst ?? s.worst;
    links.push({ from: s.id, to: t.accountId, kind: w === 'high' ? 'extHigh' : w === 'medium' ? 'extWarn' : 'ext', vol: 1, at: null, edges: t.edges || [], roles: t.roles.length });
  }
  // resource access: a dashed path beside the trust one, from the same outside identity
  links.push(...estateResourceLinks(sources, (id) => by.has(id)));
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
    ...d.events.map((e) => ({ id: e.id, kind: CHANGE_KIND[e.kind] || e.kind.toUpperCase(), tone: e.severity, hour: e.hour, text: e.title, where: `${name(e.accountId)}${e.roleName ? ` · ${e.roleName}` : ''}`, target: e.accountId })),
    ...d.chains.filter((c) => c.isNew && by.has(c.from) && by.has(c.to)).map((c) => ({ id: `n${c.from}${c.to}`, kind: 'NEW PATH', tone: 'info', hour: c.hours[0] ?? 23, text: `${name(c.from)} entered ${name(c.to)} for the first time`, where: c.roles.slice(0, 2).map((r) => `${r.caller} → ${r.role}`).join(' · '), target: c.to })),
  ].sort((a, b) => b.hour - a.hour);
  return { view: 'estate', zones, groups, by, sources, scanner, hidden: d.outside.hidden, links, events, hourStart: new Date(d.hourStart).getTime(),
    defaultSel: events[0]?.target || [...groups].sort((a, b) => b.calls7 - a.calls7)[0]?.id || null };
}

// ---------- Google Cloud: a second field behind the AWS one, the same zones, paths between the two ----------
// AWS moves forward, Google Cloud sits behind. A project is a ring; each service account a star, higher the more it
// can do, red when it is high risk. Paths between the fields are where one cloud can sign in to the other.
const isGcp = (id) => String(id).startsWith('gcp:');
// Google Cloud services by the first part of their permissions
const GSVC = { storage: 'Cloud Storage', bigquery: 'BigQuery', pubsub: 'Pub/Sub', cloudkms: 'Cloud KMS', secretmanager: 'Secret Manager', run: 'Cloud Run', cloudfunctions: 'Cloud Functions',
  artifactregistry: 'Artifact Registry', dataflow: 'Dataflow', cloudsql: 'Cloud SQL', compute: 'Compute Engine', container: 'GKE', iam: 'IAM', resourcemanager: 'Resource Manager', logging: 'Logging' };
function withGcp(M, g, showRes = true) {
  const aws = { id: 'aws', label: 'AWS', x0: -560, x1: 560, y0: -380, y1: 380 };
  if (!g?.projects?.length) { M.planes = [aws]; return M; }
  // AWS in front (smaller y is nearer the camera), Google Cloud behind it
  // AWS's outside identities sit off its far edge, which now faces Google Cloud: move them to its left and right edges
  M.sources.filter((x) => !x.gcp).forEach((x, i) => {
    const left = i % 2 === 0, k = Math.floor(i / 2), [gap, z] = PLACE[x.risk] || PLACE.none;
    Object.assign(x, off(left ? 180 + k * 16 : 360 - k * 16, gap, z));
  });
  for (const x of M.groups) { x.y -= DY; x.stars.forEach((st) => { st.y -= DY; }); }
  for (const z of M.zones) { z.y0 -= DY; z.y1 -= DY; z.cloud = 'aws'; }
  for (const x of M.sources) x.y -= DY;
  if (M.scanner) M.scanner.y -= DY;
  M.planes = [{ ...aws, y0: -380 - DY, y1: 380 - DY }, { id: 'gcp', label: 'GOOGLE CLOUD', x0: -560, x1: 560, y0: -380 + DY, y1: 380 + DY }];
  const envs = ORDER.filter((e) => g.projects.some((p) => p.environment === e));
  const weight = (e) => Math.max(1, g.projects.filter((p) => p.environment === e).length) ** 0.75;
  const totalW = envs.reduce((n, e) => n + weight(e), 0);
  let x1 = 560;
  const gz = [], gg = [];
  for (const env of envs) {
    const w = (1120 * weight(env)) / totalW, x0 = x1 - w, list = g.projects.filter((p) => p.environment === env);
    gz.push({ id: env, x0, x1, y0: -380 + DY, y1: 380 + DY, cloud: 'gcp' });
    const cols = Math.max(1, Math.round(Math.sqrt((list.length * w) / 760))), rows = Math.ceil(list.length / cols), cw = w / cols, ch = 760 / rows;
    list.forEach((p, i) => {
      const cx = x0 + cw * (i % cols + 0.5), cy = -380 + ch * (Math.floor(i / cols) + 0.5) + DY;
      const R = Math.max(14, Math.min(18 + Math.sqrt(p.accounts.length) * 5.5, 0.4 * Math.min(cw, ch)));
      // like an account: with usage read, a star's height is its calls in 7 days and the never-called lie on the floor;
      // without it, the height is what it can do (permissions) and nothing is called cold
      const own = p.accounts.filter((a) => !a.managed), active = p.usage ? own.filter((a) => a.used) : own;
      const stars = cloud(cx, cy, R, active.map((a) => ({ id: `gsa:${a.id}`, sa: a, risk: a.risk, calls7: p.usage ? a.calls7 : a.permissions })), Math.min(p.cold, 16), hash(p.projectId));
      gg.push({ id: `gcp:${p.projectId}`, cloud: 'gcp', project: p, name: p.projectId, label: p.projectId, env, x: cx, y: cy, R, coldShare: own.length ? p.cold / own.length : 0,
        prof: p.hourly.map((b) => b.calls), hourly: p.hourly, stars, usage: p.usage, roles: own.length, cold: p.cold, high: p.risky, calls7: p.calls7, calls24h: p.calls24h, keys: p.keys,
        resources: showRes ? p.resources : null });
    });
    x1 = x0;
  }
  M.zones.push(...gz); M.groups.push(...gg);
  for (const x of gg) M.by.set(x.id, x);
  // identities from outside the organization, off the far edge of the Google Cloud field
  // the same as AWS's: trust (service accounts it can become, roles on the project) is a solid path, resources it can
  // use through their own IAM policy a dashed one beside it. Neighbours alternate height so their names do not collide.
  const trustOf = (t) => t.principals.length + t.direct.length;
  const outs = g.outside.map((o) => ({ ...o, targets: o.targets.filter((t) => M.by.has(`gcp:${t.projectId}`) && (trustOf(t) || (showRes && t.resources.length))) }))
    .filter((o) => o.targets.length).map((o) => (showRes ? o : { ...o, worst: o.trustWorst, resources: 0 }));
  const srcs = outs.map((o, i) => {
    const deg = outs.length === 1 ? 90 : 42 + (96 * i) / (outs.length - 1), [gap, z] = PLACE[o.worst] || PLACE.none, at = off(deg, gap + (i % 2) * 24, z + (i % 2) * 46);
    return { id: `gsrc:${o.key}`, key: o.key, gcp: true, label: o.label, sub: o.sub, group: o.group, kind: o.group === 'oidc' ? 'oidc' : o.group === 'public' ? 'web' : 'account', risk: o.worst, trustWorst: o.trustWorst,
      findings: o.findings || [], principal: o.principal || null, resources: o.resources,
      targets: o.targets.map((t) => ({ accountId: `gcp:${t.projectId}`, roles: t.principals, direct: t.direct, edges: t.edges, resources: showRes ? t.resources : [], resourceCount: showRes ? t.resourceCount : 0 })), sessions: 0, ...at, y: at.y + DY };
  });
  M.sources.push(...srcs);
  for (const x of srcs) for (const t of x.targets) {
    const tw = x.trustWorst ?? x.risk;
    if (t.roles.length || t.direct.length) M.links.push({ from: x.id, to: t.accountId, kind: tw === 'high' ? 'extHigh' : tw === 'medium' ? 'extWarn' : 'ext', vol: 1, at: null, edges: t.edges, roles: t.roles.length, gcp: true });
  }
  M.links.push(...estateResourceLinks(srcs, (id) => M.by.has(id)).map((l) => ({ ...l, gcp: true })));
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
    const weight = (r) => (d.cloud === 'gcp' && !d.usage ? r.permissions || 0 : r.calls7);   // a project without usage: what it can do
    [...roles].sort((m, n) => weight(n) - weight(m)).forEach((r, k, arr) => { const rad = 58 * Math.sqrt((k + 0.5) / arr.length), a = 0.7 + k * 2.39996; Object.assign(r, { x: x + Math.cos(a) * rad, y: y + Math.sin(a) * rad, z: 14 + 24 * lg(weight(r)), cold: false }); });
    const prof = Array.from({ length: 24 }, (_, hr) => roles.reduce((s, r) => s + r.hourly[hr], 0));
    const name = d.cloud === 'gcp' ? GSVC[c.key] || c.key : c.key;
    const label = c.key === 'other' ? 'Other services' : c.key === 'quiet this week' ? 'Quiet this week' : d.cloud === 'gcp' && !d.usage
      ? (c.key === 'every service' ? 'Owner, Editor or Viewer' : c.key === 'no roles' ? 'No roles' : c.key === 'custom' ? 'Custom roles' : `Can use ${name}`) : `Mostly ${name}`;
    return { id: `cl:${c.key}`, key: c.key, env, label, x, y, R: 72, roles, stars: roles, more: c.more,
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
    const edges = s.targets.flatMap((t) => t.edges || []), rs = s.targets.flatMap((t) => t.resources || []);
    const tw = s.trustWorst ?? s.worst, rw = worstRes(rs);
    if (g.roles.length) links.push({ from: s.id, to: g.id, kind: tw === 'high' ? 'extHigh' : tw === 'medium' ? 'extWarn' : 'ext', vol: 1, edges, roles: g.roles.length });
    if (rs.length) links.push({ from: s.id, to: g.id, kind: rw === 'high' ? 'resHigh' : rw === 'medium' ? 'resWarn' : 'res', vol: 1, resources: rs, resourceCount: s.targets.reduce((n, t) => n + (t.resourceCount || 0), 0) });
    for (const id of g.roles) if (byRole.has(id)) links.push({ from: g.id, to: id, kind: 'fan', src: s.id, risk: s.worst, vol: 1 });
  }
  // resource access: a box beside its service's tower for each exposed resource, fanned to from the gates
  const res = accountResources(d.resources, towers, gates, sources);
  links.push(...res.links);
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
  const events = d.events.map((e) => ({ id: e.id, kind: CHANGE_KIND[e.kind] || e.kind.toUpperCase(), tone: e.severity, hour: e.hour, text: e.title, where: e.roleName || d.account.name, target: e.roleId && byRole.has(e.roleId) ? e.roleId : null }));
  for (const t of towers) t.denied = roles.reduce((n, r) => n + (r.services.find((v) => v.name === t.name)?.denied || 0), 0);
  return { view: 'account', account: d.account, usage: d.usage !== false, zones: [], groups, roles, byRole, towers, gates, doors, rim, sources, scanner, fars, links, events, hidden: d.outside.hidden, resources: res.marks,
    coldCount: d.coldCount, roleCount: d.roleCount, hourStart: new Date(d.hourStart).getTime(),
    defaultSel: events.find((e) => e.target)?.target || [...roles].sort((a, b) => b.calls7 - a.calls7)[0]?.id || null };
}

export async function spacePage(ctx) {
  const view = ctx.params.get('view') === 'account' ? 'account' : 'estate';
  // both views are fetched together and remembered briefly, so zooming into an account and back does not wait twice
  // ?day=N: the 24 hours of N days ago (hourly counts are kept 30 days); links and fetches carry it along
  const day = Math.max(0, Math.min(29, Math.floor(Number(ctx.params.get('day')) || 0)));
  // resource access is a layer: on unless ?res=0
  const showRes = ctx.params.get('res') !== '0';
  const who = whoOf(ctx.params), wa = `${whoQs(who, '&')}${day ? `&day=${day}` : ''}${showRes ? '' : '&res=0'}`, wq = wa ? `?${wa.slice(1)}` : '';
  const apiQ0 = wq.replace(/[?&]res=0/, '').replace(/^&/, '?');
  // one account, or one Google Cloud project (account=gcp:<project id>), which comes in the same shape
  const oneUrl = (id) => (isGcp(id) ? `/space/gcp/project/${encodeURIComponent(id.slice(4))}${day ? `?day=${day}` : ''}` : `/space/account/${id}${apiQ0}`);
  const wanted = view === 'account' && ctx.params.get('account') ? getCached(oneUrl(ctx.params.get('account'))) : null;
  wanted?.catch(() => {});
  const apiQ = wq.replace(/[?&]res=0/, '').replace(/^&/, '?');
  const [est0, envs, gcpData] = await Promise.all([getCached(`/space${apiQ}`), loadEnvironments(), view === 'estate' && who !== 'users' ? getCached(`/space/gcp${day ? `?day=${day}` : ''}`).catch(() => null) : null]);
  useEnvironments(envs);
  // a copy: the cached answer is shared with the next visit, and the layer switch must not change it
  const est = showRes ? structuredClone(est0) : stripResources(est0);
  // a Google service account an AWS role trusts is drawn as a path between the fields, not as an outside identity
  const hasGcp = !!gcpData?.projects?.length;
  // users have no trust policy: the identities that roles let in, and the scanner's role, are not part of their picture
  if (who === 'users') { est.outside = { items: [], hidden: 0 }; est.scanner = null; }
  const noun = who === 'users' ? 'IAM users' : who === 'roles' ? 'roles' : 'roles and users', Noun = noun[0].toUpperCase() + noun.slice(1);
  if (hasGcp) est.outside = { ...est.outside, items: est.outside.items.filter((x) => !/^Google Cloud · /.test(x.label)) };
  if (!est.accounts.length) return h('div', { class: 'stack' }, h('h1', null, 'Space'), h('p', { class: 'muted' }, 'No accounts yet. Connect one to see it here.'), h('a', { class: 'btn primary', href: '#/accounts/new' }, 'Connect an account'));
  const live = est.accounts.filter((a) => !a.planned);
  const accountId = ctx.params.get('account') || [...(live.length ? live : est.accounts)].sort((a, b) => b.calls7 - a.calls7)[0].id;
  const M = view === 'estate' ? withGcp(estateModel(est), gcpData, showRes) : accountModel((showRes ? (x) => structuredClone(x) : stripResources)(await (wanted || getCached(oneUrl(accountId)))));
  // a Google Cloud project is drawn on the blue plane
  if (!M.planes) M.planes = [{ id: M.account?.cloud === 'gcp' ? 'gcp' : 'aws', label: M.account?.cloud === 'gcp' ? 'GOOGLE CLOUD' : 'AWS', x0: -560, x1: 560, y0: -380, y1: 380 }];
  // the words and links of one account, or of one Google Cloud project
  const G1 = M.view === 'account' && M.account.cloud === 'gcp', usage1 = !G1 || M.usage;
  const V = G1 ? { role: 'service account', roles: 'service accounts', Roles: 'Service accounts', ROLE: 'SERVICE ACCOUNT', ROLES: 'SERVICE ACCOUNTS', enter: 'become', svc: 'GOOGLE CLOUD SERVICE', others: 'AWS accounts',
    idLine: M.account.title && M.account.title !== M.account.name ? M.account.title : `project ${M.account.number}`, open: (id) => `#/identities/gcp/${id}`, openLabel: 'Open service account',
    trust: (q = '') => `#/trust?cloud=gcp&project=${encodeURIComponent(M.account.projectId)}${q ? `&q=${encodeURIComponent(q)}` : ''}`, resources: (q = M.account.projectId) => `#/resources?cloud=gcp&q=${encodeURIComponent(q)}` }
    : { role: 'role', roles: 'roles', Roles: 'Roles', ROLE: 'ROLE', ROLES: 'ROLES', enter: 'enter', svc: 'AWS SERVICE', others: 'other accounts', idLine: M.account?.awsAccountId || '', open: (id) => `#/identities/${id}`, openLabel: 'Open role',
      trust: (q = '') => `#/trust?q=${encodeURIComponent(q)}`, resources: () => `#/resources?accounts=${M.account?.id}` };
  // projects for the account picker: Google Cloud is not shown to members limited to some AWS accounts
  const gcpList = view === 'account' && who !== 'users' ? await getCached('/gcp/projects').then((r) => r.items, () => []) : [];
  const awsGroups = () => M.groups.filter((x) => x.cloud !== 'gcp');
  ctx.setCrumbs(h('a', { href: '#/space' }, 'Space'), ...(view === 'account' ? [M.account.name] : []));
  const st = { dir: 'both', sel: null, lit: false, hour: 23, playing: false, az: HOME.az, el: HOME.el, zoom: HOME.zoom, px: 0, py: 0, zone: '', timer: null, fit: null, dragging: false };
  // the bell (and links) can open Space on one thing at one hour; otherwise nothing is picked and the overview shows
  { const want = ctx.params.get('sel'), hr = Number(ctx.params.get('hour'));
    if (want && (M.view === 'estate' ? M.by.has(want) : M.byRole.has(want) || M.resources?.some((x) => x.id === want)) || M.sources.some((x) => x.id === want)) { st.sel = want; st.lit = true; }
    if (ctx.params.get('hour') != null && hr >= 0 && hr <= 23) st.hour = Math.floor(hr);
    if (['in', 'out'].includes(ctx.params.get('dir'))) st.dir = ctx.params.get('dir');
    if (M.view === 'estate' && (ctx.params.get('zone') === 'outer' || M.zones.some((z) => z.id === ctx.params.get('zone')))) st.zone = ctx.params.get('zone'); }
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
  // Esc closes the selection (not while a window, the palette or a field has the keyboard)
  const onKey = (ev) => { if (ev.key !== 'Escape' || ev.defaultPrevented || !st.sel || document.querySelector('.win, .palette, dialog[open]') || /^(INPUT|SELECT|TEXTAREA)$/.test(document.activeElement?.tagName)) return; set({ sel: null }); };
  document.addEventListener('keydown', onKey);
  ctx.onLeave(() => { stop(); document.removeEventListener('keydown', onKey); });

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
  // zoom only when asked: pinching, a mouse wheel, Ctrl/⌘+wheel, or the + and − buttons. A two-finger swipe on a
  // trackpad moves the view in any direction (Shift+wheel moves it sideways with a mouse).
  const wheelMem = {};
  stage.addEventListener('wheel', (ev) => { ev.preventDefault();
    const kind = wheelKind(ev, wheelMem);
    if (kind === 'pan') {
      const k = W / (stage.getBoundingClientRect().width || W), dx = ev.shiftKey && !ev.deltaX ? ev.deltaY : ev.deltaX, dy = ev.shiftKey && !ev.deltaX ? 0 : ev.deltaY;
      set({ px: clampPan(st.px - dx * k, W), py: clampPan(st.py - dy * k, H) }); return;
    }
    // a pinch sends small steps with Ctrl held: zoom faster per unit so it follows the fingers
    const z2 = Math.max(0.6, Math.min(3, st.zoom * Math.exp(-ev.deltaY * (kind === 'pinch' ? 0.01 : 0.0015))));
    const m = stage.getScreenCTM(), q = m ? new DOMPoint(ev.clientX, ev.clientY).matrixTransform(m.inverse()) : null;
    if (!q || !st.cam) return set({ zoom: z2 });
    set(zoomAbout(q.x, q.y, z2)); }, { passive: false });
  // the camera change that zooms to z2 while the scene point at (sx, sy) stays where it is on screen
  const zoomAbout = (sx, sy, z2) => {
    const { CX, CY, F, ox, ou } = st.cam, r = z2 / st.zoom, F2 = F * r;
    return { zoom: z2, px: clampPan(st.px + (sx - CX) * (1 - r) + (F2 - F) * ox, W), py: clampPan(st.py + (sy - CY) * (1 - r) - (F2 - F) * ou, H) };
  };
  // fly to something: zoom in and bring it to the middle (double-click a thing, or F with it picked)
  let lastPick = null;
  const whereIs = (id) => {
    if (M.view === 'estate' && M.by.has(id)) { const g = M.by.get(id); return [g.x, g.y, 0]; }
    if (M.view === 'account' && M.byRole.has(id)) { const r = M.byRole.get(id); return [r.x, r.y, r.z]; }
    const s = M.sources.find((x) => x.id === id); if (s) return [s.x, s.y, s.z];
    if (id === CM_ID && M.scanner) return [M.scanner.x, M.scanner.y, M.scanner.z];
    return null;
  };
  const flyTo = (id) => {
    const at = whereIs(id); if (!at) return false;
    st.zoom = Math.max(st.zoom, M.view === 'estate' ? 2 : 1.8); render();
    const q = camera()(...at);
    set({ px: clampPan(st.px + W / 2 - q[0], W), py: clampPan(st.py + H / 2 - q[1], H) });
    return true;
  };
  stage.addEventListener('dblclick', (ev) => { ev.preventDefault(); if (lastPick && Date.now() - lastPick.at < 800) { st.sel = lastPick.id; st.lit = true; flyTo(lastPick.id); } });
  stage.setAttribute('tabindex', '0');
  stage.addEventListener('keydown', (ev) => {
    const z = { '+': 1.25, '=': 1.25, '-': 0.8, _: 0.8 }[ev.key];
    if (z) { ev.preventDefault(); set({ zoom: Math.max(0.6, Math.min(3, st.zoom * z)) }); return; }
    if (ev.key === '0') { ev.preventDefault(); set({ ...HOME, px: 0, py: 0 }); return; }
    if ((ev.key === 'f' || ev.key === 'F') && st.sel) { ev.preventDefault(); flyTo(st.sel); return; }
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
    if (!st.fit && fitPts) {
      // framed once, for the starting angle, so the scene fills the view. Turning the camera keeps this scale: only
      // the zoom changes the size (refitting for each angle made the scene grow and shrink on its own as it turned).
      // The frame is centred on the plane, not on what happens to be in view.
      const p0 = view((HOME.az * Math.PI) / 180, (HOME.el * Math.PI) / 180);
      let ext = 0, top = 0, bottom = 0;
      const [ox, ou] = p0(0, 0, 0);
      for (const [x, y, z] of fitPts) { const [X, U] = p0(x, y, z); ext = Math.max(ext, Math.abs(X - ox)); top = Math.max(top, U - ou); bottom = Math.max(bottom, ou - U); }
      const F = Math.min((W - 40) / (2 * ext), (H - 130) / (top + bottom));
      st.fit = { D, F, top, bottom };
    }
    const F = st.fit.F * st.zoom, [ox, ou] = p(0, 0, 0);
    const CX = W / 2 - F * ox + st.px, CY = 90 + st.fit.F * st.fit.top + ((H - 130) - st.fit.F * (st.fit.top + st.fit.bottom)) / 2 + F * ou + st.py;
    st.cam = { CX, CY, F, ox, ou };
    return (x, y, z = 0) => { const [X, U, dep] = p(x, y, z); return [CX + F * X, CY - F * U, dep, F / dep]; };
  }
  const hourLabel = (b) => fmtClock(M.hourStart + b * 36e5);

  // drawn text is enlarged when the scene is shown small, so it stays readable (about 11 px at least)
  let FZ = 1;
  const textScale = () => { const r = stage.getBoundingClientRect(), k = Math.min(r.width / W, r.height / H); FZ = k > 0 ? Math.max(1, Math.min(1.8, 11 / (10.5 * k))) : 1; stage.style.setProperty('--fz', FZ); };
  let lastSize = '';
  new ResizeObserver(() => { const r = stage.getBoundingClientRect(), s = `${Math.round(r.width)}x${Math.round(r.height)}`; if (s !== lastSize && r.width) { lastSize = s; render(); } }).observe(stage);
  function render() {
    textScale();
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
    if (M.view === 'account') { for (const t of M.towers) ent.set(t.id, { p3: [t.x, t.y, t.h], env: 'svc' }); for (const r of M.roles) ent.set(r.id, { p3: [r.x, r.y, r.z], env: r.cluster.env }); for (const n of M.fars) ent.set(`far:${n.id}`, { p3: [n.x, n.y, 8], env: n.env }); for (const g of M.gates) ent.set(g.id, { p3: [g.x, g.y, 4], env: 'outer' }); for (const d of M.doors) ent.set(d.id, { p3: [d.x, d.y, 4], env: d.env }); for (const r of M.resources || []) ent.set(r.id, { p3: [r.x, r.y, 8], env: 'outer' }); }
    const liftOf = (l, a, b) => (/^res(High|Warn)?$/.test(l.kind) ? 12 + 0.05 * Math.hypot(b[0] - a[0], b[1] - a[1]) : l.kind === 'resfan' ? 18 + 0.05 * Math.hypot(b[0] - a[0], b[1] - a[1]) : /^xcloud/.test(l.kind) ? 70 + 0.12 * Math.hypot(b[0] - a[0], b[1] - a[1]) : l.kind === 'scan' ? 10 : l.kind === 'fan' ? 24 + 0.06 * Math.hypot(b[0] - a[0], b[1] - a[1]) : l.kind === 'use' ? 30 : l.kind === 'use1' ? 34 : l.kind === 'denied' && M.view === 'account' ? 40 : /^ext/.test(l.kind) ? 26 + 0.07 * Math.hypot(b[0] - a[0], b[1] - a[1]) : null);
    const fitPts = [...M.planes.flatMap((q) => [[q.x0, q.y0, 0], [q.x1, q.y0, 0], [q.x1, q.y1, 0], [q.x0, q.y1, 0], [0, q.y0 - 60, 0]]), ...M.sources.flatMap((s) => [[s.x, s.y, s.z + 14], [s.x, s.y, 0], [s.x + (s.x < 0 ? -90 : 90), s.y, s.z + 14]]),   // and some room for its name
 ...(M.fars || []).flatMap((n) => [[n.x - 50, n.y - 50, 0], [n.x + 50, n.y + 50, 0]])];
    if (M.view === 'estate') for (const q of M.planes) fitPts.push([-760 - (M.planes.length > 1 ? 120 : 0), (q.y0 + q.y1) / 2, 0], [760, (q.y0 + q.y1) / 2, 0]);
    if (M.scanner) fitPts.push([M.scanner.x, M.scanner.y, M.scanner.z + 20]);
    for (const l of M.links) { const a = ent.get(l.from), b = ent.get(l.to); if (a && b) fitPts.push(apex3(a.p3, b.p3, l.from < l.to ? 1 : -1, liftOf(l, a.p3, b.p3))); }
    const P = camera(fitPts), ref = (st.fit.F * st.zoom) / st.fit.D, sinEl = Math.sin((st.el * Math.PI) / 180);
    const path = (pts) => `M${pts.map((p) => `${f(p[0])} ${f(p[1])}`).join(' L')}`;
    const ring3 = (cx, cy, r, a0, a1, n = 44) => path(Array.from({ length: n + 1 }, (_, i) => { const a = a0 + ((a1 - a0) * i) / n; return P(cx + Math.cos(a) * r, cy + Math.sin(a) * r, 0); }));
    const pick = (id) => (ev) => { ev.stopPropagation(); lastPick = { id, at: Date.now() }; set({ sel: sel === id ? null : id }); };
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
    if (M.view === 'account' && M.rim.length) { const l = P(0, -380, 0); out.floor.push(svg('text', { x: f(l[0]), y: f(l[1] + 24), 'text-anchor': 'middle', fill: '#b6c2bb', class: 'sp-zone' }, `GREY DOTS ROUND THE EDGE · ${M.coldCount} ${V.ROLES} WITH NO RECORDED CALL`)); blocks.push([l[0] - 230, l[1] + 12, l[0] + 230, l[1] + 29]); }

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
      // resource access: a small box on the ring, how many of its resources anyone or an outside account can use
      if (M.view === 'estate' && g.resources && (g.resources.public || g.resources.external)) {
        const n = g.resources.public + g.resources.external, q = P(g.x + g.R * 0.72, g.y - g.R * 0.72, 0), kk = Math.max(0.75, q[3] / ref);
        const col = g.resources.worst === 'high' ? RED : g.resources.worst === 'medium' ? WARN : '#d5dceb';
        out.rings.push(svg('g', { class: 'sp-hit', onClick: pick(g.id), opacity: o2(dim) },
          svg('title', null, `${g.name}: ${g.resources.public ? `${g.resources.public} resource${g.resources.public === 1 ? '' : 's'} open to anyone` : ''}${g.resources.public && g.resources.external ? ', ' : ''}${g.resources.external ? `${g.resources.external} shared outside the estate` : ''} · click for which`),
          svg('path', { d: glyph('box', q[0], q[1], 5.5 * kk), fill: '#03100b', stroke: col, 'stroke-width': 1.3 }),
          svg('text', { x: f(q[0]), y: f(q[1] + 3 * kk), 'text-anchor': 'middle', fill: col, class: 'sp-small', style: 'font-size:8px' }, String(n))));
      }
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
      out.hits.push(svg('g', { class: 'sp-hit', onClick: pick(target) }, svg('title', null, g.cloud === 'gcp' ? `${g.name} · Google Cloud · ${ENV[g.env].name} · ${g.roles} service accounts${g.usage ? ` · ${kfmt(g.calls7)} calls in 7 days` : ''}${g.high ? ` · ${g.high} high risk` : ''}` : M.view === 'estate' ? (g.planned ? `${g.name} · ${ENV[g.env].name} · planned, not onboarded yet` : `${g.name} · ${ENV[g.env].name} · ${g.roles} roles · ${kfmt(g.calls7)} calls in 7 days`) : `${g.label} · ${g.roles.length} roles`),
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
        out.hits.push(svg('g', { class: 'sp-hit', onClick: pick(r.id) }, svg('title', null, `${pretty(r.name).label} · ${usage1 ? `${kfmt(r.calls7)} calls in 7 days` : `${num(r.permissions || 0)} permissions`}`), svg('circle', { cx: f(p[0]), cy: f(p[1]), r: 7, fill: '#000', opacity: 0 })));
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
        const nr = g.res?.length || 0;
        out.rings.push(svg('g', { class: 'sp-hit', onClick: pick(g.src), opacity: fade(g.id, g.src) }, svg('title', null, `${g.roles.length ? `${g.roles.length} role${g.roles.length === 1 ? '' : 's'} can be entered` : ''}${g.roles.length && nr ? ' and ' : ''}${nr ? `${nr} resource${nr === 1 ? '' : 's'} used` : ''} from here · click for the list`),
          svg('path', { d: glyph('saml', c[0], c[1], 7 * k), fill: '#03100b', stroke: col, 'stroke-width': on ? 2 : 1.3 }),
          svg('text', { x: f(c[0]), y: f(c[1] + 4 * k), 'text-anchor': 'middle', fill: col, class: 'sp-small', style: 'font-size:9px' }, String(g.roles.length + nr))));
      }
      for (const d of M.doors) {
        if (!M.links.some((l) => (l.from === d.id || l.to === d.id) && dirs.link(l))) continue;
        const c = P(d.x, d.y, 0), k = Math.max(0.75, c[3] / ref), E = ENV[d.env] || ENV[ORDER[0]];
        out.rings.push(svg('g', { class: 'sp-hit', onClick: pick(d.far), opacity: fade(d.id, d.far) }, svg('title', null, `${d.n} way${d.n === 1 ? '' : 's'} with no single role here: the whole account, or roles not drawn · click for the list`),
          svg('path', { d: glyph('account', c[0], c[1], 6 * k), fill: '#03100b', stroke: E.hot, 'stroke-width': 1.2 }),
          svg('text', { x: f(c[0]), y: f(c[1] + 3.5 * k), 'text-anchor': 'middle', fill: E.hot, class: 'sp-small', style: 'font-size:8px' }, String(d.n))));
      }
      for (const r of M.resources || []) {
        if (!dirs.inside) continue;
        const b = P(r.x, r.y, 0), p = P(r.x, r.y, 8), k = Math.max(0.75, p[3] / ref), col = r.risk === 'high' ? RED : r.risk === 'medium' ? WARN : '#d5dceb', on = sel === r.id;
        tops.set(r.id, p);
        out.rings.push(svg('g', { class: 'sp-hit', onClick: pick(r.id), opacity: fade(r.id) }, svg('title', null, `${r.name} · ${r.service} · ${r.exposure === 'public' ? 'open to anyone' : 'shared outside the estate'} · click for who`),
          svg('line', { x1: f(b[0]), y1: f(b[1]), x2: f(p[0]), y2: f(p[1]), stroke: col, 'stroke-width': 0.7, opacity: 0.5 }),
          svg('path', { d: glyph('box', p[0], p[1], 4.2 * k), fill: r.exposure === 'public' ? col : '#03100b', 'fill-opacity': r.exposure === 'public' ? 0.85 : 1, stroke: col, 'stroke-width': on ? 2 : 1.2 }),
          svg('circle', { cx: f(p[0]), cy: f(p[1]), r: 9, fill: '#000', opacity: 0 })));
        if (on) out.marks.push(svg('path', { d: glyph('box', p[0], p[1], 9), fill: 'none', stroke: '#fff', 'stroke-width': 1.5 }));
        cands.push({ pr: (on ? 3000 : 0) + (r.risk === 'high' ? 600 : 200) - (fade(r.id) < 1 ? 1400 : 0), x: p[0], y: p[1], text: r.name, color: col, faded: fade(r.id) < 1, pick: pick(r.id), below: 18 });
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
      else if (l.kind === 'res' || l.kind === 'resWarn' || l.kind === 'resHigh') {
        color = l.kind === 'resHigh' ? RED : l.kind === 'resWarn' ? WARN : OUT; w = l.kind === 'resHigh' ? 1.3 : 1; dash = '5 4';
        o = t ? 1 : l.kind === 'resHigh' ? 0.5 : l.kind === 'resWarn' ? 0.35 : 0.2; flow = t ? 1 : 0;
        if (t && l.kind !== 'res') flag = { text: `${l.kind === 'resHigh' ? '⚠ ' : ''}${l.resourceCount} RESOURCE${l.resourceCount === 1 ? '' : 'S'} OPEN`, bg: l.kind === 'resHigh' ? RED : WARN };
      }
      else if (l.kind === 'resfan') { show = sel === l.src || sel === l.to; color = l.risk === 'high' ? RED : l.risk === 'medium' ? WARN : OUT; w = 0.9; dash = '3 3'; o = 0.7; }
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
      const ext = /^(ext|res)/.test(l.kind), mid = g3.pts[ext ? 6 : 12];
      tops.set(l.id, mid);
      if (l.kind !== 'use' && l.kind !== 'fan' && l.kind !== 'resfan' && (o > 0.15 || (rel && !on && o > 0.15 * FADE))) out.paths.push(svg('path', { class: 'sp-hit', d: cut < 1 ? g3.part(cut) : g3.d, fill: 'none', stroke: '#000', 'stroke-opacity': 0, 'stroke-width': 12, 'pointer-events': 'stroke', onClick: pick(l.id) },
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
      // text is drawn FZ times larger when the scene is shown small: measure it at that size
      const w = (Math.max(s.label.length * 6.7, s.sub.length * 6.15) + 4) * FZ;
      const tries = [['start', p[0] + 15, p[1] - 2], ['end', p[0] - 15, p[1] - 2], ['middle', p[0], p[1] - 32 * FZ], ['middle', p[0], p[1] + 26 * FZ]];
      let pl = null;
      for (const [anchor, lx, ly] of tries) { const x0 = anchor === 'start' ? lx : anchor === 'end' ? lx - w : lx - w / 2, r = [x0, ly - 11 * FZ, x0 + w, ly + 17 * FZ]; if (fits(r)) { pl = [anchor, lx, ly]; blocks.push(r); break; } }
      // nowhere free: no name on the map (it stays on hover and in the cards), unless it is the one picked
      s.place = pl || (sel === s.id ? (p[0] < W / 2 ? tries[0] : tries[1]) : null);
    }
    for (const { s, p, g0, k, size } of sats) {
      const [anchor, lx, ly] = s.place || [], ring = s.risk === 'high' ? RED : s.risk === 'medium' ? WARN : null;
      out.sats.push(svg('g', { class: 'sp-hit', onClick: pick(s.id), opacity: (focus && focus !== 'outer' ? 0.35 : 1) * fade(s.id) },
        svg('title', null, `${s.label} · ${s.sub}${s.findings.length ? ` · ${s.findings.join('; ')}` : ''}`),
        svg('line', { x1: f(p[0]), y1: f(p[1]), x2: f(g0[0]), y2: f(g0[1]), stroke: '#8b98ad', 'stroke-width': 0.8, 'stroke-dasharray': '1.5 3.5' }),
        svg('ellipse', { cx: f(g0[0]), cy: f(g0[1]), rx: f(7 * k), ry: f(7 * k * sinEl), fill: 'none', stroke: '#8b98ad', 'stroke-width': 0.8, opacity: 0.7 }),
        svg('circle', { cx: f(p[0]), cy: f(p[1]), r: 16, fill: '#000', opacity: 0 }),
        svg('path', { d: glyph(s.kind, p[0], p[1], size), fill: '#d5dceb', stroke: '#fff', 'stroke-width': 0.8, filter: 'url(#sp-glow)' }),
        ring && svg('circle', { cx: f(p[0]), cy: f(p[1]), r: f(size + 6), fill: 'none', stroke: ring, 'stroke-width': 1.5, 'stroke-dasharray': s.risk === 'high' ? null : '3 3', class: 'sp-pulse' }),
        s.place && svg('text', { x: f(lx), y: f(ly), 'text-anchor': anchor, fill: '#e6ebf4', class: 'sp-name' }, s.label),
        s.place && svg('text', { x: f(lx), y: f(ly + 13), 'text-anchor': anchor, fill: s.risk === 'high' ? '#ffb0a6' : '#a9b4c6', class: 'sp-small' }, s.sub)));
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
      const bw = Math.round((c.text.length * 6.3 + 14) * FZ), bh = 9 * FZ;
      for (const [dx, dy] of [[0, -22 * FZ], [bw / 2 + 12, -14 * FZ], [-bw / 2 - 12, -14 * FZ], [0, 22 * FZ], [0, -44 * FZ]]) {
        const cx = c.x + dx, cy = c.y + dy, r = [cx - bw / 2, cy - bh, cx + bw / 2, cy + bh];
        if (!fits(r)) continue;
        blocks.push(r);
        out.labels.push(svg('g', { class: 'sp-hit', onClick: c.pick }, svg('title', null, 'What is this about?'), svg('line', { x1: f(c.x), y1: f(c.y), x2: f(cx), y2: f(dy < 0 ? r[3] : r[1]), stroke: c.bg, 'stroke-width': 0.9, opacity: 0.8 }),
          svg('rect', { x: f(r[0]), y: f(r[1]), width: bw, height: f(2 * bh), rx: 2, fill: c.bg }), svg('text', { x: f(cx), y: f(cy + 3.5 * FZ), 'text-anchor': 'middle', fill: '#05110b', class: 'sp-flag' }, c.text)));
        break;
      }
    }
    // names: the picked one and anything flagged this hour always; otherwise only the busiest few, so a large estate
    // is not covered in labels (every ring still names itself on hover)
    let named = 0; const NAMES = M.view === 'estate' ? 12 : 20;
    for (const c of cands.sort((a, x) => x.pr - a.pr)) {
      if (named >= NAMES && c.pr < 900) continue;
      const bw = Math.round((c.text.length * 6.5 + 16) * FZ), bh = 10 * FZ;
      for (const [dx, dy] of [[0, -24 * FZ], [bw / 2 + 14, -14 * FZ], [-bw / 2 - 14, -14 * FZ], [0, -46 * FZ], [0, c.below * FZ]]) {
        const cx = c.x + dx, cy = c.y + dy, r = [cx - bw / 2, cy - bh, cx + bw / 2, cy + bh];
        if (!fits(r)) continue;
        blocks.push(r); named++;
        out.labels.push(svg('g', { class: 'sp-hit', onClick: c.pick }, svg('line', { x1: f(c.x), y1: f(c.y), x2: f(cx), y2: f(dy < 0 ? r[3] : r[1]), stroke: c.color, 'stroke-width': 0.8, opacity: 0.7 }),
          svg('rect', { x: f(r[0]), y: f(r[1]), width: bw, height: f(2 * bh), rx: 3, fill: '#03100b', 'fill-opacity': 0.88, stroke: c.color }), svg('text', { x: f(cx), y: f(cy + 3.6 * FZ), 'text-anchor': 'middle', fill: '#e3efe8', class: 'sp-pill' }, c.text)));
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
    // The side panels change only with what is picked and shown, not with the camera or (mostly) the hour: rebuilding
    // them on every frame cost time and took the keyboard focus away.
    const sKey = JSON.stringify([st.sel, st.zone, st.dir, st.lit, st.sel === CM_ID ? st.hour : null, (() => { const x = sessions.get(st.sel); return Array.isArray(x) ? x.length : x || null; })()]);
    if (sKey !== sideKey) { sideKey = sKey; keepFocus(renderSide); }
    renderBar();
    // what is shown goes in the address, so reload and a copied link give the same view
    if (!ctx.inWindow) syncUrl({ view: M.view === 'account' ? 'account' : null, account: M.view === 'account' ? accountId : null, who: who === 'all' ? null : who,
      sel: st.sel, zone: st.zone || null, dir: st.dir === 'both' ? null : st.dir, day: day || null, hour: st.hour === 23 ? null : st.hour, res: showRes ? null : '0' });
  }
  let sideKey = null;
  // When a panel is rebuilt, the control that had focus is found again in the new one by what it says
  function keepFocus(fn) {
    const a = document.activeElement, host = a && [left, right].find((x) => x.contains(a));
    if (!host) return fn();
    const key = (e) => `${e.tagName}|${e.className}|${e.getAttribute('aria-label') || ''}|${e.textContent.trim().slice(0, 80)}`, k = key(a), typing = a.classList.contains('sp-filter');
    fn();
    if (host.contains(a)) return;
    const m = [...host.querySelectorAll('button, a[href], input, select, summary')].find((e) => key(e) === k || (typing && e.classList.contains('sp-filter')));
    if (m) { m.focus({ preventScroll: true }); if (typing) m.setSelectionRange(m.value.length, m.value.length); }
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
      const rs = M.resources?.find((x) => x.id === id); if (rs) return rs.name;
      if (String(id).startsWith('gate:')) return M.account.name;
      const g = M.groups.find((x) => x.id === id); if (g) return g.label;
    }
    return 'somewhere';
  }
  function linkTitle(l) {
    const a = nameOf(l.from), b = nameOf(l.to);
    if (/^xcloud/.test(l.kind)) return `${a} → ${b} · ${l.pairs.length} way${l.pairs.length === 1 ? '' : 's'} between the clouds${l.kind === 'xcloudHigh' ? ' · any AWS role can use it' : ''} · click for which`;
    if (/^ext/.test(l.kind) && l.gcp) return `${a} can get into ${b} in Google Cloud · click for who`;
    if (/^res(High|Warn)?$/.test(l.kind)) return `${a} can use ${l.resourceCount} resource${l.resourceCount === 1 ? '' : 's'} in ${M.view === 'estate' ? b : M.account.name}${l.kind === 'resHigh' ? ' · data or admin access' : ''} · click for which`;
    if (/^ext/.test(l.kind)) return `${a} can enter ${b}${l.kind === 'extHigh' ? ' · risky trust' : l.kind === 'extWarn' ? ' · loose trust' : ''} · click for the trust statement`;
    if (l.kind === 'chain' || l.kind === 'new') return `${a} entered ${b} · ${num(l.sessions)} sessions in 90 days${l.today ? ` · ${l.today} today` : ''}${l.kind === 'new' ? ' · first seen today' : ''} · click for who`;
    if (l.kind === 'denied') return `${a} → ${b} · ${l.denied} calls refused in 7 days`;
    if (l.kind === 'in' || l.kind === 'out') return `${a} → ${b} · ${l.sessions ? `used, ${num(l.sessions)} sessions in 7 days` : 'not used in 7 days'}${l.allowed ? ` · allowed by trust` : ''}${l.worst === 'high' ? ' · risky trust' : ''} · click for the list`;
    if (l.kind === 'scan') return `Curious Monkey reads ${b} through ${pretty(l.target.role).label} · ${num(l.target.sessions)} sign-ins in 90 days · click for more`;
    return `${a} → ${b}`;
  }
  const clip = (t, n = 170) => (t.length > n ? `${t.slice(0, n - 1)}…` : t);
  // resources an outside identity can use, as panel rows: picked on the map when drawn, else opened in Resource access
  const SVC = { s3: 'S3', kms: 'KMS', dynamodb: 'DynamoDB', sqs: 'SQS', sns: 'SNS', secretsmanager: 'Secrets Manager', lambda: 'Lambda', ecr: 'ECR',
    ...GSVC };
  const resItems = (list, where) => list.map((r) => ({ label: r.name, icon: 'box', meta: [SVC[r.service] || r.service, where, r.expected ? 'marked expected' : r.title].filter(Boolean).join(' · '),
    tone: r.expected ? null : r.severity === 'high' ? 'bad' : 'warn', pick: M.view === 'account' && M.resources?.some((x) => x.rid === r.id) ? `res:${r.id}` : null,
    window: `#/resources?q=${encodeURIComponent(r.name)}&exposure=all`, winTitle: r.name, winEyebrow: 'RESOURCE ACCESS' }));
  function linkDetail(l) {
    const row = (k, v, tone) => ({ k, v: String(v), tone });
    const a = nameOf(l.from), b = nameOf(l.to);
    if (/^xcloud/.test(l.kind)) {
      const into = l.dir === 'aws-gcp';
      const items = l.pairs.map((x) => into
        ? { label: `${x.awsRole || 'any role'} → ${x.gcpEmail ? x.gcpEmail.split('@')[0] : `${x.grant} on ${x.gcpProject}`}`, meta: [x.via === 'direct' ? 'holds roles itself' : 'becomes the service account', `pool ${x.pool}`, x.conditions.length ? `when ${x.conditions[0]}` : 'no condition'].join(' · '),
          tone: x.broad ? 'bad' : null, window: x.gcpPrincipal ? `#/identities/gcp/${x.gcpPrincipal}` : null, winTitle: x.gcpEmail || x.label, winEyebrow: 'GOOGLE CLOUD · IDENTITY', href: !x.gcpPrincipal && x.awsRoleId ? `#/identities/${x.awsRoleId}` : null }
        : { label: `${x.gcpEmail ? x.gcpEmail.split('@')[0] : x.uniqueId} → ${x.awsRole}`, meta: `trusted by unique ID ${x.uniqueId} in statement ${x.statement + 1}`, window: `#/identities/${x.awsRoleId}`, winTitle: x.awsRole, winEyebrow: 'AWS · ROLE' });
      const broad = l.pairs.filter((x) => x.broad).length;
      return { eyebrow: into ? 'ACROSS CLOUDS · AWS → GOOGLE CLOUD' : 'ACROSS CLOUDS · GOOGLE CLOUD → AWS', title: `${a} → ${b}`, swatch: l.kind === 'xcloudHigh' ? RED : GCP, round: true,
        sub: into ? `${l.pairs.length} way${l.pairs.length === 1 ? '' : 's'} for AWS identities to act in Google Cloud through workload identity federation` : `${l.pairs.length} AWS role${l.pairs.length === 1 ? '' : 's'} trusting a Google service account`,
        tags: broad ? [{ t: `⚠ ANY ROLE IN ${a.toUpperCase()}`, c: RED }] : [],
        summary: into ? (broad ? `The pool has no attribute condition, so every role and user in ${a} can use ${broad === 1 ? 'one of these' : `${broad} of these`}. Pin it to the role that needs it.` : 'Each is pinned to one AWS role.')
          : 'Code running as these service accounts can get an AWS session in the role, with no AWS key.',
        rows: [], lists: [{ title: into ? 'AWS role → Google Cloud identity' : 'Service account → AWS role', items }],
        actions: into ? [['Identities from AWS', '#/identities?type=gcp&source=aws', true]] : [['Trust map', `#/trust?q=${encodeURIComponent('provider:google')}`, true]] };
    }
    if (/^res(High|Warn)?$/.test(l.kind)) {
      const s = M.sources.find((x) => x.id === l.from), acct = M.view === 'estate' ? M.by.get(l.to) : M.account;
      const open = l.resources.filter((r) => !r.expected).length;
      return { eyebrow: `RESOURCE ACCESS · ${s.group === 'public' ? 'ANYONE' : 'OUTSIDE YOUR ESTATE'}`, title: `${s.label} → ${acct.name}`, sub: `can use ${l.resourceCount} resource${l.resourceCount === 1 ? '' : 's'} through their own policies, without entering a role`,
        swatch: l.kind === 'resHigh' ? RED : l.kind === 'resWarn' ? WARN : '#d5dceb', round: true,
        tags: l.kind === 'resHigh' ? [{ t: '⚠ DATA OR ADMIN ACCESS', c: RED }] : l.kind === 'resWarn' ? [{ t: 'RESOURCE SHARED', c: WARN }] : [],
        rows: [row('Needs a decision', open ? `${open} of them` : 'none: every one is marked expected', open ? 'bad' : 'ok')],
        lists: [{ title: 'Resources it can use', items: resItems(l.resources, null), empty: 'none drawn' }],
        actions: [['Resource access', acct.cloud === 'gcp' ? `#/resources?cloud=gcp&q=${encodeURIComponent(acct.projectId || acct.name)}&exposure=${s.group === 'public' ? 'public' : 'external'}` : `#/resources?accounts=${acct.id}&exposure=${s.group === 'public' ? 'public' : 'external'}`, true]] };
    }
    if (/^ext/.test(l.kind) && l.gcp) {
      const src = M.sources.find((x) => x.id === l.from), g = M.by.get(l.to);
      return { eyebrow: 'GOOGLE CLOUD · FROM OUTSIDE', title: `${a} → ${b}`, sub: src.sub, swatch: l.kind === 'extHigh' ? RED : l.kind === 'extWarn' ? WARN : '#d5dceb', round: true,
        tags: l.kind === 'extHigh' ? [{ t: '⚠ ANY IDENTITY', c: RED }] : l.kind === 'extWarn' ? [{ t: 'OUTSIDE YOUR DOMAIN', c: WARN }] : [], rows: [],
        lists: (() => { const t = src.targets.find((x) => x.accountId === l.to) || { roles: [], direct: [], edges: [] };
          return [...(t.roles.length ? [{ title: `Service accounts it can become in ${g.name}`, items: t.roles.map((pid) => { const e = (t.edges || []).find((x) => x.roleId === pid);
            return { label: gcpName(pid), meta: e ? [e.actions[0], e.findings[0]?.title].filter(Boolean).join(' · ') : null, tone: e?.worst === 'high' ? 'bad' : e?.worst === 'medium' ? 'warn' : null, window: `#/identities/gcp/${pid}`, winTitle: gcpName(pid), winEyebrow: 'GOOGLE CLOUD · IDENTITY' }; }) }] : []),
            ...(t.direct?.length ? [{ title: 'Roles it holds itself', items: t.direct.map((d) => ({ label: d.role, meta: [d.what, d.findings[0]?.title].filter(Boolean).join(' · '), tone: d.worst === 'high' ? 'bad' : d.worst === 'medium' ? 'warn' : null })) }] : [])]; })(),
        actions: [['Trust map', `#/trust?cloud=gcp&project=${encodeURIComponent(g.name)}&q=${encodeURIComponent(src.label)}`, true], ['Identities', `#/identities?type=gcp&project=${encodeURIComponent(g.name)}`]] };
    }
    if (/^ext/.test(l.kind)) {
      const s = M.sources.find((x) => x.id === l.from), edges = l.edges || [];
      const acct = M.view === 'estate' ? M.by.get(l.to) : M.account;
      // the worst statement in full, the rest by name
      const e = edges[0], rows = [];
      if (e) {
        rows.push(row(edges.length > 1 ? `Worst statement · ${V.role}` : G1 ? 'Service account it can become' : 'Role it can enter', pretty(e.role).label));
        rows.push(row('Why it is flagged', e.findings.length ? clip(e.findings.map((x) => `${x.title}${x.detail ? `: ${x.detail}` : ''}`).join(' · '), 220) : 'nothing flagged', e.findings.some((x) => x.severity === 'high') ? 'bad' : null));
        rows.push(row(G1 ? 'Granted to' : 'Trusts', clip(e.principal, 120)));
        if (G1) rows.push(row('Through', e.actions?.[0] || '—'));
        rows.push(row('Only when', e.conditions.length ? clip(e.conditions.join(' and '), 160) : 'no conditions', e.conditions.length ? null : 'bad'));
        if (!G1) rows.push(row('Used', e.sessions ? `${num(e.sessions)} sessions, last ${ago(e.lastSeen)}` : 'never seen used'));
      }
      const direct = G1 ? s.targets.flatMap((t) => t.direct || []) : [];
      const q = `account:${acct.awsAccountId} ${trustQ(s)}`, nIn = edges.length || (G1 ? 0 : l.roles || 1);
      return { eyebrow: `TRUST · ${s.group.toUpperCase()}`, title: `${a} → ${b}`, sub: G1 ? [nIn ? `can become ${nIn} service account${nIn === 1 ? '' : 's'}` : null, direct.length ? `holds ${direct.length} role${direct.length === 1 ? '' : 's'} itself` : null].filter(Boolean).join(' and ') + ` in ${acct.name}` : `can enter ${nIn} role${nIn === 1 ? '' : 's'} in ${acct.name}`,
        swatch: l.kind === 'extHigh' ? RED : l.kind === 'extWarn' ? WARN : '#d5dceb', round: true,
        tags: l.kind === 'extHigh' ? [{ t: '⚠ RISKY TRUST', c: RED }] : l.kind === 'extWarn' ? [{ t: 'LOOSE TRUST', c: WARN }] : [],
        rows: rows.length ? rows : [row('Trust', s.findings.join('; ') || 'nothing flagged')],
        lists: [...(edges.length > 1 ? [{ title: G1 ? 'Service accounts it can become' : 'Roles it can enter', items: roleItems(edges, []) }] : []),
          ...(direct.length ? [{ title: 'Roles it holds itself', items: direct.map((d) => ({ label: d.role, meta: [d.what, d.findings[0]?.title].filter(Boolean).join(' · '), tone: d.worst === 'high' ? 'bad' : d.worst === 'medium' ? 'warn' : null })) }] : [])],
        actions: [['Trust map', G1 ? V.trust(s.label) : `#/trust?q=${encodeURIComponent(q)}`, true], ...(edges[0] ? [[V.openLabel, V.open(edges[0].roleId)]] : [])] };
    }
    if (l.kind === 'scan') {
      const t = l.target, acct = M.view === 'estate' ? M.by.get(t.accountId) : M.account;
      return { eyebrow: 'CURIOUS MONKEY · SCANNER', title: `Curious Monkey → ${acct?.name || b}`, sub: `reads it through ${t.role}`, swatch: CM, round: true, tags: [],
        rows: [row('Scanner role', t.role), row('Signed in', t.sessions ? `${num(t.sessions)} times in 90 days, last ${ago(t.lastSeen)}` : 'not seen in CloudTrail yet'),
          row('Today', t.hours.length ? t.hours.map(hourLabel).join(', ') : 'no sign-in in the last 24 h'), row('Last scan', t.lastScan ? ago(t.lastScan) : 'never')],
        actions: [['Open role', `#/identities/${t.roleId}`, true], ['Its calls', `#/events?account=${t.accountId}&role=${t.roleId}&range=24h`]] };
    }
    if (l.kind === 'chain' || l.kind === 'new') {
      const who = [];
      if (l.moreRoles) who.push(row('And', `${l.moreRoles} more role pairs not listed`));
      const top = l.roles[0];
      return { eyebrow: l.kind === 'new' ? 'ACCOUNT TO ACCOUNT · FIRST SEEN TODAY' : 'ACCOUNT TO ACCOUNT', title: `${a} → ${b}`, sub: `${num(l.sessions)} sessions in 90 days · last ${ago(l.lastSeen)}`, swatch: l.kind === 'new' ? '#fff' : ENV[M.by.get(l.from).env].base, round: true,
        tags: l.kind === 'new' ? [{ t: 'NEW PATH', c: '#fff' }] : [],
        lists: [{ title: 'Who entered what', items: l.roles.map((r) => ({ label: `${pretty(r.caller).label} → ${pretty(r.role).label}`, meta: `last ${ago(r.lastSeen)}`, value: `${num(r.sessions)}`, href: `#/identities/${r.roleId}` })) }],
        rows: [...who, row('Today', l.today ? `${num(l.today)} session${l.today === 1 ? '' : 's'} at ${l.hours.map((x) => hourLabel(x)).join(', ')} ${TZ_LABEL}` : 'nothing today')],
        actions: [...(top ? [['Its calls', `#/events?role=${top.roleId}&q=${encodeURIComponent(`user:${top.caller.replace(/^user\//, '')}`)}&range=7d`, true]] : []), [`Open ${b}`, `#/space?view=account&account=${l.to}`], ['Track sessions', () => openTrack(top ? { role: top.roleId } : { account: l.to }, top ? `${top.role} in ${b}` : b)], ...(top ? [['Role', `#/identities/${top.roleId}`]] : [])] };
    }
    if (l.kind === 'denied') return { eyebrow: 'REFUSED CALLS', title: `${a} → ${b}`, sub: '7 days', swatch: RED, round: true, tags: [{ t: `⚠ ${num(l.denied)} DENIED`, c: RED }],
      rows: [row('What it means', `${num(l.denied)} calls from ${a} to ${b} were refused by IAM. A missing permission, or something trying what it should not.`, 'bad')], actions: [['Open role', `#/identities/${l.from}`, true]] };
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
      .map((x) => { const roles = x.targets.some((t) => t.roles.length), res = x.targets.reduce((n, t) => n + (t.resourceCount || 0), 0);
        return { label: x.label, icon: GLYPH[x.group] || 'account', tone: x.risk === 'high' ? 'bad' : x.risk === 'medium' ? 'warn' : null, pick: x.id,
          meta: [x.sub, ...(roles ? [x.findings[0] || 'conditions pinned', x.sessions ? `used ${num(x.sessions)}×` : 'never used'] : []), ...(res ? [`${res} resource${res === 1 ? '' : 's'} open to it`] : [])].join(' · ') }; });
    const risky = M.sources.filter((x) => x.risk === 'high').length, loose = M.sources.filter((x) => x.risk === 'medium').length;
    if (M.view === 'estate') {
      const live = awsGroups().filter((g) => !g.planned), roles = live.reduce((n, g) => n + g.roles, 0), cold = live.reduce((n, g) => n + g.cold, 0), high = live.reduce((n, g) => n + g.high, 0);
      return { eyebrow: 'OVERVIEW', title: 'Your estate', sub: 'Click anything on the map for its details', swatch: '#2a8a5c', closable: false, tags: [],
        summary: `${live.length} account${live.length === 1 ? '' : 's'} with ${num(roles)} ${noun}. ${roles ? Math.round((100 * cold) / roles) : 0}% of them were never called. ${M.sources.filter((x) => !x.gcp).length + M.hidden} identities outside your org can get in${risky ? `, ${risky} with risky access` : ''}.${M.gcp ? ` Behind it, Google Cloud: ${M.gcp.projects.length} projects, ${num(M.gcp.projects.reduce((n, g) => n + g.roles, 0))} service accounts, ${M.gcp.xlinks.reduce((n, l) => n + l.pairs.length, 0)} paths between the clouds.` : ''}`,
        stats: [{ k: 'Accounts', v: num(live.length) }, { k: Noun, v: num(roles) }, { k: 'Never called', v: num(cold), tone: roles && cold / roles > 0.5 ? 'warn' : null },
          { k: 'High-risk roles', v: num(high), tone: high ? 'bad' : null }, { k: 'Risky ways in', v: num(risky), tone: risky ? 'bad' : null }, { k: 'Loose ways in', v: num(loose), tone: loose ? 'warn' : null },
          ...(showRes ? [(() => { const all = [...live, ...(M.gcp?.projects || [])], n = all.reduce((t, g) => t + (g.resources ? g.resources.public + g.resources.external : 0), 0), hi = all.some((g) => g.resources?.worst === 'high');
            return { k: 'Open resources', v: num(n), tone: hi ? 'bad' : n ? 'warn' : null, hint: M.gcp ? 'open to anyone, or to identities outside your estate, in both clouds' : 'open to anyone, or to accounts outside your estate' }; })()] : [])],
        rows: [],
        lists: [{ title: 'Ways in to check first', hint: 'Identities outside your org, worst first: trust into roles, and resource policies.', items: ways, empty: 'No identity outside your org can get in.',
          full: { label: 'See all in Trust map', href: '#/trust', eyebrow: 'TRUST MAP · EVERY WAY IN' } },
          ...(M.gcp ? [{ title: 'Between AWS and Google Cloud', hint: 'Where an identity in one cloud can act in the other. Red: any role in the AWS account can use it.',
            full: [{ label: 'Google into AWS: Trust map', href: '#/trust?q=provider:google', count: false, eyebrow: 'TRUST MAP · FROM GOOGLE' },
              { label: 'AWS into Google Cloud', href: '#/identities?type=gcp&source=aws', count: false, eyebrow: 'GOOGLE CLOUD · REACHABLE FROM AWS' }],
            items: M.gcp.xlinks.map((l) => ({ label: `${nameOf(l.from)} → ${nameOf(l.to)}`, meta: l.pairs.map((x) => (l.dir === 'aws-gcp' ? `${x.awsRole || 'any role'} → ${x.gcpEmail ? x.gcpEmail.split('@')[0] : 'direct'}` : `${(x.gcpEmail || '').split('@')[0]} → ${x.awsRole}`)).join(' · '),
              tone: l.kind === 'xcloudHigh' ? 'bad' : null, pick: l.id })), empty: 'No path between the clouds.' }] : []),
          { title: `Accounts with high-risk ${noun}`, items: live.filter((g) => g.high).sort((a, b) => b.high - a.high).slice(0, 6).map((g) => ({ label: g.name, icon: 'account', meta: `${ENV[g.env].name} · ${num(g.roles)} ${noun}`, value: `${g.high} high`, tone: 'bad', pick: g.id })), empty: `No account has a high-risk one.` }],
        actions: [['Trust map', '#/trust', true], ['All roles', '#/identities'], ['All calls', '#/events']] };
    }
    const denied = M.roles.filter((r) => r.denied7).sort((a, b) => b.denied7 - a.denied7);
    return { eyebrow: `OVERVIEW · ${G1 ? 'GOOGLE CLOUD PROJECT · ' : ''}${ENV[M.account.environment]?.name.toUpperCase() || ''}`, title: M.account.name, sub: `${V.idLine} · click anything on the map for its details`, swatch: ENV[M.account.environment]?.base || '#2a8a5c', closable: false, tags: [],
      summary: usage1 ? `${num(M.roleCount)} ${V.roles}, ${num(M.roles.length)} called this week across ${M.towers.length} services. ${M.sources.length + M.hidden} identities outside your org and ${M.fars.length} of your ${V.others} connect to it.`
        : `${num(M.roleCount)} service accounts. Calls are not read for this project, so each is placed by the service its roles reach most and towers count service accounts, not calls: turn on role usage from audit logs on its connection. ${M.sources.length + M.hidden} identities outside your org and ${M.fars.length} AWS accounts connect to it.`,
      stats: [{ k: V.Roles, v: num(M.roleCount) }, { k: 'Called · 7 d', v: usage1 ? num(M.roles.length) : '—' }, { k: 'Never called', v: usage1 ? num(M.rim.length) : '—', tone: usage1 && M.roleCount && M.rim.length / M.roleCount > 0.5 ? 'warn' : null },
        { k: 'Refused calls', v: usage1 ? num(denied.reduce((n, r) => n + r.denied7, 0)) : '—', tone: denied.length ? 'bad' : null }, { k: 'Risky ways in', v: num(risky), tone: risky ? 'bad' : null }, { k: G1 ? 'AWS accounts' : 'Other accounts', v: num(M.fars.length) },
        ...(showRes ? [{ k: 'Open resources', v: num(M.resources.length), tone: M.resources.some((r) => r.risk === 'high') ? 'bad' : M.resources.length ? 'warn' : null }] : [])],
      rows: [],
      lists: [{ title: 'Ways in to check first', hint: 'Identities outside your org, worst first: trust into roles, and resource policies.', items: ways, empty: 'No identity outside your org can get in.',
        full: { label: 'See all in Trust map', href: G1 ? V.trust() : V.trust(`account:${M.account.awsAccountId}`), eyebrow: `TRUST MAP · ${M.account.name.toUpperCase()}` } },
        ...(M.resources?.length ? [{ title: 'Resources open from outside', hint: `Their own ${G1 ? 'IAM policy lets in anyone, or an identity outside your organization' : 'policy lets in anyone, or an account outside your estate'}. Boxes beside the towers; filled = open to anyone.`,
          full: { label: 'See all in Resource access', href: V.resources(), eyebrow: `RESOURCE ACCESS · ${M.account.name.toUpperCase()}` },
          items: M.resources.slice(0, 8).map((r) => ({ label: r.name, icon: 'box', meta: `${SVC[r.service] || r.service} · ${r.exposure === 'public' ? 'anyone' : G1 ? 'outside identities' : 'outside accounts'}`, tone: r.risk === 'high' ? 'bad' : r.risk === 'medium' ? 'warn' : null, pick: r.id })) }] : []),
        ...(denied.length ? [{ title: `${V.Roles} with refused calls`, items: denied.slice(0, 6).map((r) => ({ label: pretty(r.name).label, meta: r.cluster.label, value: num(r.denied7), tone: 'bad', pick: r.id })) }] : []),
        usage1 ? { title: `Busiest ${V.roles}`, items: [...M.roles].sort((a, b) => b.calls7 - a.calls7).slice(0, 6).map((r) => ({ label: pretty(r.name).label, meta: r.services.map((x) => x.name).slice(0, 3).join(' · '), value: kfmt(r.calls7), pick: r.id })) }
          : { title: 'Service accounts that can do the most', items: [...M.roles].sort((a, b) => (b.permissions || 0) - (a.permissions || 0)).slice(0, 6).map((r) => ({ label: pretty(r.name).label, meta: r.services.map((x) => x.name).slice(0, 3).join(' · '), value: num(r.permissions || 0), pick: r.id })) }],
      actions: G1 ? [['Identities', `#/identities?type=gcp&project=${encodeURIComponent(M.account.projectId)}`, true], ['Trust map', V.trust()], ...(showRes ? [['Resource access', V.resources()]] : []), ['Back to estate', '#/space']]
        : [['Its calls', `#/events?account=${M.account.id}`, true], ['Track sessions', () => openTrack({ account: M.account.id }, M.account.name)], ['Trust map', `#/trust?q=${encodeURIComponent(`account:${M.account.awsAccountId}`)}`], ['Back to estate', '#/space']] };
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
        lists: [{ title: 'Where it reads', items: [...sc.targets].sort((a, b) => b.sessions - a.sessions).map((t) => ({ label: acctName(t.accountId), meta: `${pretty(t.role).label} · ${t.sessions ? `last ${ago(t.lastSeen)}` : 'no sign-in seen yet'}`, value: num(t.sessions), pick: linkOf(t), href: linkOf(t) ? null : `#/identities/${t.roleId}` })), empty: 'no scanner role found' }],
        actions: [['Workers', '#/operations/workers', true], ['Accounts', '#/accounts']] };
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
        const toGcp = new Set(M.links.filter((l) => l.from === g.id && /^xcloud/.test(l.kind)).map((l) => l.to)).size;
        const scan = M.scanner?.targets.find((t) => t.accountId === g.id);
        const today = g.hourly.reduce((n, x) => n + x.sessions, 0), risky = fromOut.filter((o) => o.x.risk === 'high').length;
        const plural = (n, one, many = `${one}s`) => `${n} ${n === 1 ? one : many}`;
        return { eyebrow: `ACCOUNT · ${ENV[g.env].name.toUpperCase()}${g.ou ? ` · ${g.ou}` : ''}`, title: g.name, sub: g.awsAccountId, swatch: ENV[g.env].base,
          tags: [...(g.high ? [{ t: `⚠ ${g.high} HIGH-RISK ROLE${g.high === 1 ? '' : 'S'}`, c: RED, href: `#/identities?accounts=${g.id}&risks=High` }] : []), ...(look ? [tag(look.kind, TONE[look.tone] || '#fff')] : [])],
          summary: `${plural(fromOut.length, 'identity', 'identities')} from outside your org${risky ? ` (${risky} with risky trust)` : ''} and ${ins.length} of your other accounts can get in. It reaches ${plural(outs.length, 'other account')}${toGcp ? ` and ${plural(toGcp, 'Google Cloud project')}` : ''}.`,
          stats: [{ k: 'Roles', v: num(g.roles) }, { k: 'Never called', v: num(g.cold), tone: g.roles && g.cold / g.roles > 0.5 ? 'warn' : null, hint: g.roles ? `${Math.round((100 * g.cold) / g.roles)}% of its roles` : '' },
            { k: 'High risk', v: num(g.high), tone: g.high ? 'bad' : null }, { k: 'Calls · 7 d', v: kfmt(g.calls7) }, { k: 'Sessions · 24 h', v: num(today) }, { k: 'Ways in', v: num(fromOut.length + ins.length), tone: risky ? 'bad' : null }],
          rows: [...(look ? [row('Look at', `${look.text} (${hourLabel(look.hour)})`, 'bad')] : []),
            ...(g.resources ? [row('Resources open', [g.resources.public ? `${g.resources.public} to anyone` : '', g.resources.external ? `${g.resources.external} to outside accounts` : ''].filter(Boolean).join(' · '), g.resources.worst === 'high' ? 'bad' : null)] : [])],
          lists: [
            ...(fromOut.some((o) => o.t.resources?.length) ? [{ title: 'Who can use its resources · from outside', hint: 'Resource policies that let in anyone, or an account outside your estate: no role to assume.',
              full: { label: 'See all in Resource access', href: `#/resources?accounts=${g.id}`, eyebrow: `RESOURCE ACCESS · ${g.name.toUpperCase()}` },
              items: fromOut.filter((o) => o.t.resources?.length).flatMap(({ x, t }) => resItems(t.resources, x.label)) }] : []),
            { title: 'Who can get in · from outside your org', hint: 'Sign-in providers, pipelines, vendors and other AWS accounts that a trust policy here lets in.',
              full: { label: 'See all in Trust map', href: `#/trust?q=${encodeURIComponent(`account:${g.awsAccountId}`)}`, eyebrow: `TRUST MAP · ${g.name.toUpperCase()}` },
              items: fromOut.map(({ x, t }) => ({ label: x.label, icon: GLYPH[x.group] || 'account', tone: x.risk === 'high' ? 'bad' : x.risk === 'medium' ? 'warn' : null,
                meta: [x.sub, t.roles.length ? plural(t.roles.length, 'role') : null, t.resources?.length ? plural(t.resourceCount || t.resources.length, 'resource') : null, t.roles.length ? (t.sessions ? `used ${num(t.sessions)}×` : 'never seen coming in') : null].filter(Boolean).join(' · '), pick: x.id,
                window: `#/trust?q=${encodeURIComponent(`account:${g.awsAccountId} ${trustQ(x)}`)}`, winTitle: `${x.label} → ${g.name}` })), empty: 'No trust policy here lets anyone outside your org in.' },
            { title: 'Who can get in · your other accounts', hint: 'Seen entering a role here in the last 90 days. Click one to replay those sessions. What their trust policies allow, used or not, is on the Trust map.',
              full: { label: 'Allowed by trust: Trust map', href: `#/trust?q=${encodeURIComponent(`account:${g.awsAccountId} source:connected`)}`, count: false, eyebrow: `TRUST MAP · YOUR ACCOUNTS → ${g.name.toUpperCase()}` },
              items: [...ins.map((l) => ({ label: M.by.get(l.from).name, icon: 'account', meta: `${plural(l.roles.length, 'role pair')} · last ${ago(l.lastSeen)}${l.kind === 'new' ? ' · new today' : ''}`, value: num(l.sessions), pick: l.id,
                window: `#/track?account=${g.id}&from=${l.from}`, winTitle: `${M.by.get(l.from).name} → ${g.name}`, winEyebrow: 'TRACK · SESSIONS THAT CAME IN' })),
              ...(scan ? [{ label: 'Curious Monkey', icon: 'cm', meta: `this portal's scanner · ${scan.sessions ? `last ${ago(scan.lastSeen)}` : 'no sign-in seen yet'}`, value: num(scan.sessions), pick: CM_ID }] : [])], empty: 'None of your other accounts entered it in 90 days.' },
            { title: 'Where it goes', hint: 'Accounts a role or user here entered in the last 90 days. Click one to replay those sessions.',
              items: outs.map((l) => ({ label: M.by.get(l.to).name, icon: 'account', meta: `${plural(l.roles.length, 'role pair')} · last ${ago(l.lastSeen)}`, value: num(l.sessions), pick: l.id,
                window: `#/track?account=${l.to}&from=${g.id}`, winTitle: `${g.name} → ${M.by.get(l.to).name}`, winEyebrow: 'TRACK · SESSIONS THAT WENT OUT' })), empty: 'It entered no other account in 90 days.' },
            ...(M.gcp ? [{ title: 'Google Cloud', hint: 'Where roles here can act in Google Cloud, and which Google service accounts can sign in here.',
              full: [{ label: 'Google into it: Trust map', href: `#/trust?q=${encodeURIComponent(`account:${g.awsAccountId} provider:google`)}`, count: false, eyebrow: 'TRUST MAP · FROM GOOGLE' },
                { label: 'It into Google Cloud', href: '#/identities?type=gcp&source=aws', count: false, eyebrow: 'GOOGLE CLOUD · REACHABLE FROM AWS' }],
              items: M.links.filter((l) => /^xcloud/.test(l.kind) && (l.from === g.id || l.to === g.id)).flatMap((l) => l.pairs.map((x) => (l.dir === 'aws-gcp'
                ? { label: `${x.awsRole || 'any role'} → ${x.gcpEmail ? x.gcpEmail.split('@')[0] : `${x.gcpProject} (direct)`}`, meta: `in ${x.gcpProject}${x.broad ? ' · the pool has no condition' : ''}`, tone: x.broad ? 'bad' : null, pick: l.id,
                  window: x.gcpPrincipal ? `#/identities/gcp/${x.gcpPrincipal}` : null, winTitle: x.gcpEmail || x.label, winEyebrow: 'GOOGLE CLOUD · IDENTITY' }
                : { label: `${(x.gcpEmail || '').split('@')[0]} → ${x.awsRole}`, meta: `from ${x.gcpProject}`, pick: l.id, window: `#/identities/${x.awsRoleId}`, winTitle: x.awsRole, winEyebrow: 'AWS · ROLE' }))),
              empty: 'No path to or from Google Cloud.' }] : [])],
          actions: [['Zoom in', `#/space?view=account&account=${g.id}${wa}`, true], ['Its calls', `#/events?account=${g.id}`], ['Track sessions', () => openTrack({ account: g.id }, g.name)], ['Account radar', `#/?view=account&account=${g.id}`]] };
      }
    }
    const rbox = M.view === 'account' ? M.resources?.find((x) => x.id === id) : null;
    if (rbox) {
      const who = M.sources.filter((x) => rbox.from.includes(x.id)).map((x) => ({ label: x.label, icon: GLYPH[x.group] || 'account', meta: x.sub, tone: x.risk === 'high' ? 'bad' : x.risk === 'medium' ? 'warn' : null, pick: x.id }));
      return { eyebrow: `RESOURCE · ${(SVC[rbox.service] || rbox.service).toUpperCase()}`, title: rbox.name, sub: `${M.account.name} · ${V.idLine}`, swatch: rbox.risk === 'high' ? RED : rbox.risk === 'medium' ? WARN : '#d5dceb',
        tags: [rbox.exposure === 'public' ? { t: '⚠ OPEN TO ANYONE', c: RED } : { t: 'SHARED OUTSIDE THE ESTATE', c: WARN }],
        summary: G1 ? `Its own IAM policy lets ${rbox.exposure === 'public' ? 'anyone' : 'an identity outside your organization'} use it directly, with no service account to become.`
          : `Its resource policy lets ${rbox.exposure === 'public' ? 'anyone' : 'an account outside your estate'} use it directly, with no role to assume. The trust map does not show this way in.`,
        rows: [], lists: [{ title: 'Who can use it', items: who, empty: 'the outsider is not among those drawn' }],
        actions: [['Open in Resource access', G1 ? `#/resources?cloud=gcp&q=${encodeURIComponent(rbox.name)}&exposure=all` : `#/resources?q=${encodeURIComponent(rbox.name)}&exposure=all&accounts=${M.account.id}`, true]] };
    }
    const s = M.sources.find((x) => x.id === id);
    if (s?.gcp) {
      // the same card as an AWS outsider: the projects it gets into (trust), the resources it can use, both together
      const withRoles = s.targets.filter((t) => t.roles.length || t.direct?.length), res = s.targets.flatMap((t) => (t.resources || []).map((r) => ({ ...r, accountId: t.accountId })));
      const both = withRoles.length && res.length, resOnly = !withRoles.length, pl = (n, w) => `${n} ${w}${n === 1 ? '' : 's'}`;
      return { eyebrow: `GOOGLE CLOUD · ${s.group === 'oidc' ? 'FEDERATED' : s.group === 'public' ? 'PUBLIC' : 'OUTSIDE YOUR DOMAIN'}${resOnly ? ' · RESOURCE ACCESS' : ''}`, title: s.label, sub: s.sub, swatch: '#d5dceb', round: true,
        tags: [...(s.risk === 'high' ? [tag('⚠ HIGH', RED)] : s.risk === 'medium' ? [tag(resOnly ? 'RESOURCE SHARED' : 'OUTSIDE', WARN)] : []), ...(both ? [tag('ROLES AND RESOURCES', '#d5dceb')] : [])],
        summary: both ? `Two ways in: it can become service accounts or holds roles in ${pl(withRoles.length, 'project')}, and can use ${pl(res.length, 'resource')} directly through their own IAM policy. Review both together.` : null,
        rows: [...(withRoles.length ? [row('Trust', s.findings.length ? s.findings.join('; ') : 'nothing flagged', s.findings.length ? 'bad' : 'ok')] : [row('Trust', 'it cannot become a service account or hold roles on a project')]),
          ...(res.length ? [row('Resources', `${res.length} it can use${res.some((r) => !r.expected) ? '' : ' · every one marked expected'}`, res.some((r) => !r.expected && r.severity === 'high') ? 'bad' : null)] : [])],
        lists: [...(withRoles.length ? [{ title: 'Projects it can get into', items: withRoles.map((t) => ({ label: M.by.get(t.accountId)?.name || t.accountId,
          meta: [t.roles.length ? pl(t.roles.length, 'service account') : null, t.direct?.length ? `${pl(t.direct.length, 'role')} on the project` : null].filter(Boolean).join(' · '), pick: t.accountId })) }] : []),
          ...(res.length ? [{ title: 'Resources it can use', hint: 'Through the resource\'s own IAM policy: a bucket, dataset, topic, key, secret, service, function or repository.', items: resItems(res, null).map((it, i) => ({ ...it, meta: `${M.by.get(res[i].accountId)?.name || ''} · ${it.meta}` })) }] : [])],
        actions: [...(withRoles.length ? [['Trust map', `#/trust?cloud=gcp&q=${encodeURIComponent(s.label)}`, true]] : []), ...(res.length ? [['Resource access', `#/resources?cloud=gcp&q=${encodeURIComponent(s.group === 'public' ? '' : s.label)}&exposure=${s.group === 'public' ? 'public' : 'external'}`, !withRoles.length]] : []),
          ...(s.principal ? [['Open identity', `#/identities/gcp/${s.principal}`]] : [])] };
    }
    if (s) {
      const withRoles = s.targets.filter((t) => t.roles.length), res = s.targets.flatMap((t) => (t.resources || []).map((r) => ({ ...r, accountId: t.accountId })));
      const items = M.view === 'estate'
        ? withRoles.map((t) => ({ label: M.by.get(t.accountId)?.name || 'an account', meta: `${t.roles.length} role${t.roles.length === 1 ? '' : 's'}${t.sessions ? ` · ${num(t.sessions)} sessions` : ''}`, pick: t.accountId }))
        : roleItems(s.targets.flatMap((t) => t.edges || []), s.targets.flatMap((t) => t.roles).filter((x) => !String(x).startsWith('direct:')));
      const direct = M.view === 'account' ? s.targets.flatMap((t) => t.direct || []) : [];
      const both = withRoles.length && res.length, resOnly = !withRoles.length;
      return { eyebrow: `OUTSIDE · ${s.group.toUpperCase()}${resOnly ? ' · RESOURCE ACCESS' : ''}`, title: s.label, sub: s.sub, swatch: '#d5dceb', round: true,
        tags: [...(s.risk === 'high' ? [tag('⚠ HIGH', RED)] : s.risk === 'medium' ? [tag(resOnly ? 'RESOURCE SHARED' : 'LOOSE TRUST', WARN)] : []), ...(both ? [tag('ROLES AND RESOURCES', '#d5dceb')] : [])],
        summary: both ? `Two ways in: it can enter ${withRoles.reduce((n, t) => n + t.roles.length, 0)} role${withRoles.length === 1 && withRoles[0].roles.length === 1 ? '' : 's'} through trust, and use ${res.length} resource${res.length === 1 ? '' : 's'} directly through their policies. Review both together.` : null,
        rows: [...(withRoles.length ? [row('Trust', s.findings.length ? s.findings.join('; ') : 'conditions pinned: nothing to flag', s.findings.length ? 'bad' : 'ok'),
          ...(G1 ? [] : [row('Seen', s.sessions ? `${num(s.sessions)} sessions · last ${ago(s.lastSeen)}` : 'never seen coming in')])] : [row('Trust', G1 ? 'it cannot become a service account or hold roles here' : 'no trust policy lets it into a role')]),
          ...(res.length ? [row('Resources', `${res.length} it can use without a role${res.some((r) => !r.expected) ? '' : ' · every one marked expected'}`, res.some((r) => !r.expected && r.severity === 'high') ? 'bad' : null)] : [])],
        lists: [...(withRoles.length && items.length ? [{ title: M.view === 'estate' ? 'Accounts it can enter' : G1 ? 'Service accounts it can become' : 'Roles it can enter', items }] : []),
          ...(direct.length ? [{ title: 'Roles it holds itself', hint: 'Granted to it straight on the project, folder or organization.', items: direct.map((d) => ({ label: d.role, meta: [d.what, d.findings[0]?.title].filter(Boolean).join(' · '), tone: d.worst === 'high' ? 'bad' : d.worst === 'medium' ? 'warn' : null })) }] : []),
          ...(res.length ? [{ title: 'Resources it can use', hint: 'Through the resource\'s own policy: a bucket, key, queue, topic, secret, function or repository.', items: resItems(res, null).map((it, i) => ({ ...it, meta: M.view === 'estate' ? `${M.by.get(res[i].accountId)?.name || ''} · ${it.meta}` : it.meta })) }] : [])],
        actions: [...(withRoles.length ? [['Trust map', G1 ? V.trust(s.label) : `#/trust?q=${encodeURIComponent(trustQ(s))}`, true]] : []),
          ...(res.length && G1 ? [['Resource access', `#/resources?cloud=gcp&q=${encodeURIComponent(s.group === 'public' ? M.account.projectId : s.label)}&exposure=${s.group === 'public' ? 'public' : 'external'}`, !withRoles.length]] : []),
          ...(res.length && !G1 ? [['Resource access', `#/resources?q=${encodeURIComponent(s.key.startsWith('acct:') ? s.key.slice(5) : s.group === 'public' ? '' : s.label)}&exposure=${s.group === 'public' ? 'public' : 'external'}`, !withRoles.length]] : [])] };
    }
    if (M.view !== 'account') return null;
    const r = M.byRole.get(id);
    if (r) {
      const p = pretty(r.name);
      const callers = M.sources.filter((x) => x.targets.some((t) => t.roles.includes(r.id))).map((x) => ({ label: x.label, icon: GLYPH[x.group] || 'account', meta: x.sub, tone: x.risk === 'high' ? 'bad' : null, pick: x.id }));
      const cmT = M.scanner?.targets.find((t) => t.roleId === r.id);
      if (cmT) callers.unshift({ label: 'Curious Monkey', icon: 'cm', meta: `this portal's scanner · last ${ago(cmT.lastSeen)}`, value: num(cmT.sessions), pick: CM_ID });
      const way = (dir) => M.fars.flatMap((n) => n.links.filter((l) => l.roleId === r.id && l.dir === dir).map((l) => ({ label: `${n.name} · ${l.otherRole}`,
        meta: G1 ? (dir === 'in' ? 'through workload identity federation' : 'trusts this service account') : [l.sessions ? `used · ${num(l.sessions)} sessions` : 'not used in 7 days', l.allowed ? 'allowed by trust' : 'seen chaining'].join(' · '), value: G1 ? null : l.sessions ? num(l.sessions) : '—', tone: l.worst === 'high' ? 'bad' : null, pick: `far:${n.id}` })));
      const chained = st.dir === 'out' ? [] : way('in'), goes = st.dir === 'in' ? [] : way('out');
      const isUser = r.kind === 'iam-user';
      if (G1) {
        // a service account: what it calls (or what its roles reach), who can become it, where it goes in AWS
        const n = callers.length + chained.length, pl = (k, w) => `${k} ${w}${k === 1 ? '' : 's'}`;
        return { eyebrow: `SERVICE ACCOUNT · ${r.cluster.label.toUpperCase()}`, title: p.label, sub: r.email || M.account.name, swatch: ENV[r.cluster.env].base, round: true,
          tags: [...(r.risk === 'High' ? [{ t: '⚠ HIGH RISK', c: RED, href: V.open(r.id) }] : []), ...(r.denied7 ? [tag(`⚠ ${num(r.denied7)} DENIED`, RED)] : []), ...(r.keys ? [tag(`${r.keys} KEY${r.keys === 1 ? '' : 'S'}`, WARN)] : [])],
          summary: `${usage1 ? (r.calls7 ? `Called ${kfmt(r.calls7)} times this week into ${pl(r.services.length, 'service')}.` : 'Quiet this week.') : `Its roles reach ${pl(r.services.length, 'service')}; calls are not read for this project.`} ${n} can become it${goes.length ? `; ${pl(goes.length, 'AWS role')} trust${goes.length === 1 ? 's' : ''} it` : ''}.`,
          stats: [usage1 ? { k: 'Calls · 7 d', v: kfmt(r.calls7) } : { k: 'Permissions', v: num(r.permissions || 0) }, { k: 'Refused', v: usage1 ? num(r.denied7 || 0) : '—', tone: r.denied7 ? 'bad' : null }, { k: 'Can become it', v: num(n), tone: callers.some((c) => c.tone === 'bad') ? 'bad' : null }],
          rows: [],
          lists: [{ title: usage1 ? 'Calls into' : 'Its roles reach', items: r.services.map((v) => ({ label: SVC[v.name] || v.name, value: usage1 ? kfmt(v.calls) : `${v.calls} role${v.calls === 1 ? '' : 's'}`, meta: v.denied ? `⚠ ${num(v.denied)} refused` : null, tone: v.denied ? 'bad' : null, pick: `svc:${v.name}` })) },
            ...(st.dir === 'out' ? [] : [{ title: 'Can become it', items: [...callers, ...chained], empty: 'only identities inside your organization' }]),
            ...(st.dir === 'in' ? [] : [{ title: 'Into AWS', items: goes, empty: 'no AWS role trusts it' }])],
          actions: [[V.openLabel, V.open(r.id), true], ...(usage1 ? [['Its usage', `${V.open(r.id)}?tab=usage`]] : []), ['Trust map', V.trust(r.email || p.label)]] };
      }
      return { eyebrow: `${isUser ? 'IAM USER' : 'ROLE'} · ${r.cluster.label.toUpperCase()}`, title: p.label, sub: p.kind ? `${p.kind} · ${r.name}` : `${M.account.name} · ${M.account.awsAccountId}`, swatch: ENV[r.cluster.env].base, round: true,
        tags: [...(r.risk === 'High' ? [{ t: '⚠ HIGH RISK', c: RED, href: `#/identities/${r.id}` }] : []), ...(r.denied7 ? [tag(`⚠ ${num(r.denied7)} DENIED`, RED)] : [])],
        summary: `${r.calls7 ? `Called ${kfmt(r.calls7)} times this week into ${r.services.length} service${r.services.length === 1 ? '' : 's'}.` : 'Quiet this week.'} ${callers.length + chained.length} can enter it${goes.length ? `; it can go on to ${goes.length} role${goes.length === 1 ? '' : 's'} elsewhere` : ''}.`,
        stats: [{ k: 'Calls · 7 d', v: kfmt(r.calls7) }, { k: 'Refused', v: num(r.denied7 || 0), tone: r.denied7 ? 'bad' : null }, { k: 'Can enter it', v: num(callers.length + chained.length), tone: callers.some((c) => c.tone === 'bad') ? 'bad' : null }],
        rows: [],
        lists: [{ title: 'Calls into', items: r.services.map((v) => ({ label: v.name, value: kfmt(v.calls), meta: v.denied ? `⚠ ${num(v.denied)} refused` : null, tone: v.denied ? 'bad' : null, pick: `svc:${v.name}` })) },
          ...(st.dir === 'out' ? [] : [{ title: 'Entered by', items: [...callers, ...chained], empty: 'only callers inside this account' }]),
          ...(st.dir === 'in' ? [] : [{ title: 'Can go to', items: goes, empty: 'no role in your other accounts trusts it' }]),
          { title: 'Sessions · click to replay', items: sessionItems(r.id, p.label), empty: sessions.get(r.id) === 'loading' ? 'Loading…' : 'No sessions recorded in the last 30 days' }],
        actions: isUser ? [['Keys and sign-in', `#/identities/${r.id}?tab=credentials`, true], ['Permission analysis', `#/identities/${r.id}?tab=permissions`]]
          : [['Open role', `#/identities/${r.id}`, true], ['Its calls', `#/events?role=${r.id}&range=7d`], ['Track sessions', () => openTrack({ role: r.id }, p.label)]] };
    }
    const t = M.towers.find((x) => x.id === id);
    if (t) {
      const users = M.roles.map((x) => ({ x, v: x.services.find((v) => v.name === t.name) })).filter((u) => u.v).sort((a, c) => c.v.calls - a.v.calls);
      const here = (M.resources || []).filter((x) => x.service === t.name);
      return { eyebrow: V.svc, title: G1 ? SVC[t.name] || t.name : t.name, sub: usage1 ? `${users.length} ${V.roles} call it` : `${users.length} service accounts have roles on it`, swatch: '#eef7f2', tags: t.denied ? [tag(`⚠ ${num(t.denied)} REFUSED`, RED)] : [],
        rows: [usage1 ? row('Calls', `${kfmt(t.calls)} in 7 days`) : row('Calls', 'not read for this project'), ...(here.length ? [row('Resources open', `${here.length} of its resources here`, here.some((x) => x.risk === 'high') ? 'bad' : null)] : [])],
        lists: [{ title: usage1 ? `${V.Roles} that call it` : 'Service accounts with roles on it', items: users.map(({ x, v }) => ({ label: pretty(x.name).label, meta: v.denied ? `⚠ ${num(v.denied)} refused` : pretty(x.name).kind || null, value: usage1 ? kfmt(v.calls) : null, tone: v.denied ? 'bad' : null, pick: x.id })) },
          ...(here.length ? [{ title: 'Resources open from outside', items: here.map((x) => ({ label: x.name, icon: 'box', meta: x.exposure === 'public' ? 'anyone' : 'outside identities', tone: x.risk === 'high' ? 'bad' : 'warn', pick: x.id })) }] : [])],
        actions: G1 ? (here.length && showRes ? [['Resource access', V.resources(), true]] : []) : [['Its calls', `#/events?account=${M.account.id}&q=${encodeURIComponent(`action:${t.name}:`)}&range=7d`, true]] };
    }
    const n = M.fars.find((x) => `far:${x.id}` === id);
    if (n) {
      const here = (l) => (l.roleId && M.byRole.get(l.roleId) ? pretty(M.byRole.get(l.roleId).name).label : l.roleId ? `a ${V.role} here` : G1 ? `${M.account.name} (roles held directly)` : `${M.account.name} (whole account)`);
      const item = (l) => ({ label: l.dir === 'in' ? `${l.otherRole || n.name} → ${here(l)}` : `${here(l)} → ${l.otherRole || 'a role there'}`,
        meta: G1 ? (l.dir === 'in' ? `through workload identity federation${l.worst === 'high' ? ' · no condition on the pool: any role in it' : ''}` : 'an AWS role trusts this service account')
          : [l.sessions ? `used · ${num(l.sessions)} sessions in 7 days` : null, l.allowed ? `allowed by ${l.allowed} trust statement${l.allowed === 1 ? '' : 's'}` : 'not in a trust policy (seen chaining)', l.allowed && !l.sessions ? 'not used in 7 days' : null].filter(Boolean).join(' · '),
        value: G1 ? null : l.sessions ? String(l.sessions) : '—', tone: l.worst === 'high' ? 'bad' : null, pick: l.roleId && M.byRole.has(l.roleId) ? l.roleId : null, href: l.roleId && !M.byRole.has(l.roleId) ? V.open(l.roleId) : null });
      const ins = n.links.filter((l) => l.dir === 'in'), outs = n.links.filter((l) => l.dir === 'out');
      return { eyebrow: G1 ? 'YOUR AWS ACCOUNT' : 'YOUR OTHER ACCOUNT', title: n.name, sub: G1 ? `${n.awsAccountId || ''} · paths between the clouds` : `${n.awsAccountId || ''}${n.sessions ? ` · ${num(n.sessions)} chained sessions in 7 days` : ' · no chaining seen in 7 days'}`, swatch: ENV[n.env].base, tags: [], rows: [],
        lists: [
          ...(st.dir !== 'out' ? [{ title: `Can come in · ${ins.length}`, items: ins.map(item), empty: `Nothing in ${n.name} can enter ${M.account.name}.` }] : []),
          ...(st.dir !== 'in' ? [{ title: `Can go out to it · ${outs.length}`, items: outs.map(item), empty: `${M.account.name} cannot enter ${n.name}.` }] : []),
          ...(n.moreLinks ? [{ title: `${n.moreLinks} more not shown`, items: [] }] : []),
        ],
        actions: [['Open in Space', `#/space?view=account&account=${n.id}`, true], G1 ? ['Trust map', `#/trust?q=${encodeURIComponent(`account:${n.awsAccountId || ''} provider:google`)}`] : ['Trust map', `#/trust?q=${encodeURIComponent(`from:${n.awsAccountId || ''}`)}`]] };
    }
    return null;
  }
  function gcpName(pid) {
    for (const g of M.gcp?.projects || []) { const a = g.project.accounts.find((x) => x.id === pid); if (a) return a.email; }
    return 'an identity';
  }
  // one Google Cloud project, card for card like an AWS account: who can use its resources, who can get in from
  // outside, from AWS and into AWS, its service accounts
  function projectDetail(g) {
    const row = (k, v, tone) => ({ k, v: String(v), tone });
    const p = g.project, plural = (n, one, many = `${one}s`) => `${n} ${n === 1 ? one : many}`, tag = (t, c) => ({ t, c });
    const ins = M.links.filter((l) => l.to === g.id && l.kind.startsWith('xcloud')), outs = M.links.filter((l) => l.from === g.id && l.kind.startsWith('xcloud'));
    const fromOut = M.sources.filter((x) => x.gcp).map((x) => ({ x, t: x.targets.find((t) => t.accountId === g.id) })).filter((o) => o.t)
      .sort((a, b) => ({ high: 0, medium: 1 }[a.x.risk] ?? 2) - ({ high: 0, medium: 1 }[b.x.risk] ?? 2));
    const trustIn = fromOut.filter((o) => o.t.roles.length || o.t.direct.length), risky = fromOut.filter((o) => o.x.risk === 'high').length;
    const broad = ins.some((l) => l.kind === 'xcloudHigh'), awsIn = new Set(ins.map((l) => l.from)).size, awsOut = new Set(outs.map((l) => l.to)).size;
    const sa = (a) => ({ label: a.email.split('@')[0], meta: [a.reasons[0]?.title, a.keys ? `${a.keys} key${a.keys === 1 ? '' : 's'}` : null, ...(a.sources.aws || []).map((x) => `from ${x}`), g.usage ? (a.used ? `${kfmt(a.calls7)} calls · 7 d` : 'never called') : `${num(a.permissions)} permissions`].filter(Boolean).join(' · '),
      tone: a.risk === 'High' ? 'bad' : a.risk === 'Medium' ? 'warn' : null, value: g.usage ? kfmt(a.calls7) : null, window: `#/identities/gcp/${a.id}`, winTitle: a.email, winEyebrow: 'GOOGLE CLOUD · SERVICE ACCOUNT' });
    const trustHref = (q = '') => `#/trust?cloud=gcp&project=${encodeURIComponent(p.projectId)}${q ? `&q=${encodeURIComponent(q)}` : ''}`;
    return { eyebrow: `GOOGLE CLOUD PROJECT · ${ENV[g.env].name.toUpperCase()}`, title: p.projectId, sub: p.name !== p.projectId ? p.name : `project ${p.number}`, swatch: ENV[g.env].base,
      tags: [...(p.risky ? [{ t: `⚠ ${p.risky} HIGH-RISK SERVICE ACCOUNT${p.risky === 1 ? '' : 'S'}`, c: RED, href: `#/identities?type=gcp&project=${encodeURIComponent(p.projectId)}&risk=High` }] : []), ...(broad ? [tag('⚠ ANY AWS ROLE CAN GET IN', RED)] : [])],
      summary: `${plural(trustIn.length, 'identity', 'identities')} from outside your organization${risky ? ` (${risky} with risky access)` : ''} and ${plural(awsIn, 'AWS account')} can get in. It reaches ${plural(awsOut, 'AWS account')}.${g.usage ? '' : ' Calls are not read for this project: turn on role usage from audit logs on its connection for heights, never-called service accounts and the hour by hour replay.'}`,
      stats: [{ k: 'Service accounts', v: num(g.roles) }, { k: 'Never called', v: g.usage ? num(g.cold) : '—', tone: g.usage && g.roles && g.cold / g.roles > 0.5 ? 'warn' : null, hint: g.usage ? `${g.roles ? Math.round((100 * g.cold) / g.roles) : 0}% of its service accounts` : 'usage not read' },
        { k: 'High risk', v: num(g.high), tone: g.high ? 'bad' : null }, { k: 'Calls · 7 d', v: g.usage ? kfmt(g.calls7) : '—' }, { k: 'Calls · 24 h', v: g.usage ? kfmt(g.calls24h) : '—' },
        { k: 'Ways in', v: num(trustIn.length + awsIn), tone: risky || broad ? 'bad' : null }],
      rows: [...(g.resources ? [row('Resources open', [g.resources.public ? `${g.resources.public} to anyone` : '', g.resources.external ? `${g.resources.external} to outside identities` : ''].filter(Boolean).join(' · '), g.resources.worst === 'high' ? 'bad' : null)] : []),
        ...(p.keys ? [row('Keys', `${plural(p.keys, 'user-managed key')} on its service accounts`, 'warn')] : [])],
      lists: [
        ...(fromOut.some((o) => o.t.resources?.length) ? [{ title: 'Who can use its resources · from outside', hint: 'Resource-level IAM that lets in anyone, or an identity outside your organization: no service account to become.',
          full: { label: 'See all in Resource access', href: `#/resources?cloud=gcp&q=${encodeURIComponent(p.projectId)}`, eyebrow: `RESOURCE ACCESS · ${p.projectId.toUpperCase()}` },
          items: fromOut.filter((o) => o.t.resources?.length).flatMap(({ x, t }) => resItems(t.resources, x.label)) }] : []),
        { title: 'Who can get in · from outside your organization', hint: 'Anyone, other domains, service accounts from projects your connections do not read, and federation that is not from AWS.',
          full: { label: 'See all in Trust map', href: trustHref(), eyebrow: `TRUST MAP · GOOGLE CLOUD · ${p.projectId.toUpperCase()}` },
          items: trustIn.map(({ x, t }) => ({ label: x.label, icon: x.kind, tone: x.risk === 'high' ? 'bad' : x.risk === 'medium' ? 'warn' : null, pick: x.id,
            meta: [x.sub, t.roles.length ? plural(t.roles.length, 'service account') : null, t.direct.length ? plural(t.direct.length, 'role') + ' on the project' : null, t.resources?.length ? plural(t.resourceCount || t.resources.length, 'resource') : null].filter(Boolean).join(' · '),
            window: trustHref(x.label), winTitle: `${x.label} → ${p.projectId}`, winEyebrow: 'TRUST MAP · GOOGLE CLOUD' })), empty: 'No identity outside your organization can get in.' },
        { title: 'Who can get in · from AWS', hint: 'AWS roles that can become a service account here, or hold roles here, through workload identity federation.',
          full: { label: 'Identities from AWS', href: '#/identities?type=gcp&source=aws', count: false, eyebrow: 'GOOGLE CLOUD · REACHABLE FROM AWS' },
          items: ins.flatMap((l) => l.pairs.map((x) => ({ label: `${x.awsAccountName} · ${x.awsRole || 'any role'}`, icon: 'account', meta: `→ ${x.gcpEmail ? x.gcpEmail.split('@')[0] : 'holds roles directly'}${x.broad ? ' · no condition on the pool' : ''}`, tone: x.broad ? 'bad' : null, pick: l.id,
            window: x.gcpPrincipal ? `#/identities/gcp/${x.gcpPrincipal}` : null, winTitle: x.gcpEmail || x.label, winEyebrow: 'GOOGLE CLOUD · IDENTITY' }))), empty: 'No AWS identity can get in.' },
        { title: 'Where it goes · into AWS', hint: 'AWS roles whose trust policy accepts a service account here.',
          items: outs.flatMap((l) => l.pairs.map((x) => ({ label: `${(x.gcpEmail || '').split('@')[0]} → ${x.awsRole}`, icon: 'account', meta: x.awsAccountName, pick: l.id, window: `#/identities/${x.awsRoleId}`, winTitle: x.awsRole, winEyebrow: 'AWS · ROLE' }))), empty: 'No AWS role trusts a service account here.' },
        { title: 'Service accounts', hint: g.usage ? 'Busiest first. Click one for what it can do and who can become it.' : 'Riskiest first. Click one for what it can do and who can become it.', items: p.accounts.filter((a) => !a.managed).map(sa), empty: 'None.' }],
      actions: [['Zoom in', `#/space?view=account&account=${encodeURIComponent(g.id)}${wa}`, true], ['Identities', `#/identities?type=gcp&project=${encodeURIComponent(p.projectId)}`], ['Trust map', trustHref()],
        ...(showRes ? [['Resource access', `#/resources?cloud=gcp&q=${encodeURIComponent(p.projectId)}`]] : [])] };
  }
  // roles an outside identity can enter, readable: permission-set names, what was flagged, whether it was used
  function roleItems(edges, ids) {
    const seen = new Set(), out = [];
    for (const e of edges) {
      if (seen.has(e.roleId)) continue; seen.add(e.roleId);
      const p = pretty(e.role), drawn = M.byRole?.get(e.roleId);
      out.push({ label: p.label, meta: [e.findings.length ? `⚠ ${e.findings[0].title}` : null, G1 ? e.actions?.[0] : e.sessions ? `used ${num(e.sessions)}×, last ${ago(e.lastSeen)}` : 'never used', drawn ? drawn.cluster.label : null].filter(Boolean).join(' · '),
        tone: e.worst === 'high' ? 'bad' : null, pick: drawn ? e.roleId : null, href: drawn ? null : V.open(e.roleId) });
    }
    for (const rid of ids) if (!seen.has(rid)) { seen.add(rid); const x = M.byRole?.get(rid); out.push({ label: x ? pretty(x.name).label : `a ${V.role}`, pick: x ? rid : null, href: x ? null : V.open(rid) }); }
    return out.sort((a, b) => (a.tone === 'bad' ? 0 : 1) - (b.tone === 'bad' ? 0 : 1) || a.label.localeCompare(b.label));
  }
  // The right-hand panel, top to bottom: what it is, one sentence on what matters, the numbers, what you can do,
  // then who and what it connects to. A row or button with the window mark opens a window over Space; ◎ finds it on the map.
  const ICONS = { oidc: 'M6 1.5l4.5 2.6v5.2L6 11.9 1.5 9.3V4.1z', saml: 'M6 1l5 5-5 5-5-5z', account: 'M6 6m-4.5 0a4.5 4.5 0 1 0 9 0a4.5 4.5 0 1 0-9 0', web: 'M6 6m-4.5 0a4.5 4.5 0 1 0 9 0a4.5 4.5 0 1 0-9 0M1.5 6h9M6 1.5c2 2 2 7 0 9M6 1.5c-2 2-2 7 0 9', cm: 'M6 6m-4 0a4 4 0 1 0 8 0a4 4 0 1 0-8 0', box: 'M2 2h8v8H2z' };
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
      // a list with `full` is a summary: its top few here, the whole list on the page it links to (Trust map, mostly)
      const fulls = [].concat(L.full || []);
      const draw = () => {
        const q = (st.filter || '').toLowerCase(), m = L.items.filter((it) => !q || `${it.label} ${it.meta || ''}`.toLowerCase().includes(q));
        const shown = fulls.length ? m.slice(0, L.max || 5) : st.showAll ? m : m.slice(0, 25);
        ul.replaceChildren(...(m.length ? shown.map(item) : [h('li', { class: 'muted small sp-empty' }, q ? 'Nothing matches.' : L.empty || 'None.')]));
        more.hidden = !!fulls.length || m.length <= shown.length; more.textContent = `Show all ${m.length}`;
      };
      more.addEventListener('click', () => { st.showAll = true; draw(); });
      const filter = !fulls.length && L.items.length > 8 && h('input', { type: 'search', class: 'sp-filter', placeholder: `Filter ${L.items.length}…`, 'aria-label': `Filter ${L.title}`, value: st.filter || '',
        onInput: (ev) => { st.filter = ev.target.value; st.showAll = false; draw(); } });
      draw();
      return h('section', { class: 'sp-list-block' }, h('div', { class: 'sp-lh' }, h('h3', null, L.title), h('span', { class: `mono sp-count${L.items.length ? '' : ' zero'}` }, String(L.items.length))),
        L.hint && L.items.length ? h('p', { class: 'sp-hint' }, L.hint) : null, filter || null, ul, more,
        ...fulls.map((f) => h('button', { class: 'btn sm sp-full', title: `${f.label} · opens in a window`, onClick: () => openWin(f.href, f.title || f.label, f.eyebrow) },
          L.items.length > (L.max || 5) && f.count !== false ? `${f.label} (${L.items.length})` : f.label, windowIcon())));
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
  // find on the map: type a name, pick it, and the view flies to it
  function findBox() {
    const all = M.view === 'estate'
      ? [...M.groups.filter((g) => !g.planned).map((g) => ({ id: g.id, label: g.name, meta: g.cloud === 'gcp' ? 'Google Cloud project' : 'account' })), ...M.sources.map((x) => ({ id: x.id, label: x.label, meta: 'outside your org' }))]
      : [...M.roles.map((r) => ({ id: r.id, label: pretty(r.name).label, meta: V.role })), ...M.sources.map((x) => ({ id: x.id, label: x.label, meta: 'outside your org' }))];
    const input = h('input', { type: 'search', class: 'sp-find', placeholder: G1 ? 'Find a service account' : `Find ${M.view === 'estate' ? (M.gcp ? 'an account or project' : 'an account') : 'a role'} on the map`, 'aria-label': 'Find on the map', autocomplete: 'off' });
    const list = h('div', { class: 'sp-find-list', role: 'listbox' });
    const choose = (it) => { input.value = ''; list.replaceChildren(); st.sel = it.id; st.lit = true; st.filter = ''; st.showAll = false; if (!flyTo(it.id)) render(); };
    const draw = () => { const q = input.value.trim().toLowerCase(); const m = q ? all.filter((x) => x.label.toLowerCase().includes(q)).slice(0, 8) : [];
      list.replaceChildren(...(q && !m.length ? [h('p', { class: 'tiny muted' }, 'Nothing by that name here.')] : m.map((it) => h('button', { class: 'sp-row', role: 'option', onClick: () => choose(it) },
        h('span', { class: 'sp-row-body' }, h('span', { class: 'sp-row-name' }, it.label), h('span', { class: 'sp-row-meta' }, it.meta)))))); };
    input.addEventListener('input', draw);
    input.addEventListener('keydown', (ev) => { if (ev.key === 'Enter') { const q = input.value.trim().toLowerCase(), it = all.find((x) => x.label.toLowerCase().includes(q)); if (q && it) { ev.preventDefault(); choose(it); } } else if (ev.key === 'Escape') { input.value = ''; draw(); } });
    return h('div', { class: 'stack', style: 'gap:4px' }, input, list);
  }

  function renderSide() {
    const focus = st.zone, selRole = M.view === 'account' ? M.byRole.get(st.sel) : null;
    const card = (on, chip, name, val, meta, onClick) => h('button', { class: 'sp-zonecard', 'aria-pressed': String(on), onClick }, h('span', { class: 'sp-chip', style: chip }),
      h('span', { class: 'sp-zc-body' }, h('span', { class: 'sp-zc-top' }, h('span', null, name), h('span', { class: 'mono' }, val)), h('span', { class: 'sp-zc-meta' }, meta)));
    const row = (on, dot, name, meta, val, onClick) => h('button', { class: 'sp-row', 'aria-pressed': String(on), title: name, onClick }, h('span', { class: 'sp-dot', style: dot }),
      h('span', { class: 'sp-row-body' }, h('span', { class: 'sp-row-name' }, name), h('span', { class: 'sp-row-meta' }, meta)), h('span', { class: 'mono sp-row-val' }, val));
    const views = h('div', { class: 'rtabs', role: 'tablist', 'aria-label': 'Space view' },
      h('button', { role: 'tab', 'aria-selected': String(M.view === 'estate'), onClick: () => go(`#/space${wq}`) }, 'Estate'),
      h('button', { role: 'tab', 'aria-selected': String(M.view === 'account'), onClick: () => go(`#/space?view=account&account=${encodeURIComponent(accountId)}${wa}`) }, G1 ? 'One project' : 'One account'));
    // who can get in, where it can go, or both
    const picked = M.view === 'estate' && M.by.has(st.sel) ? M.by.get(st.sel) : null;
    const whose = M.view === 'account' ? M.account.name : picked ? picked.name : 'your accounts';
    // In / Out count who is at the other end (an outside identity, another account or project), whatever the path: trust,
    // resource policies, chaining, federation between the clouds. The scanner is left out.
    const ways = (dir) => {
      return M.view === 'account' ? wayEnds(M, null, dir) : picked ? wayEnds(M, st.sel, dir) : null;
    };
    const dirBtn = (dir, label, tip) => { const n = dir === 'both' ? null : ways(dir);
      return h('button', { role: 'radio', 'aria-checked': String(st.dir === dir), title: tip, onClick: () => set({ dir }) }, label, n != null ? h('span', { class: 'mono faint', style: 'margin-left:6px' }, String(n)) : null); };
    const dirs = h('div', { class: 'sp-dir' },
      h('h2', { class: 'eyebrow' }, `Show paths · ${whose}`),
      h('div', { class: 'rtabs', role: 'radiogroup', 'aria-label': 'Direction' },
        dirBtn('both', 'Both', 'Everything in and out'),
        dirBtn('in', 'In', `Who can get into ${whose}: outside identities, your other accounts, the other cloud${picked ? ' (the number counts who, not ways)' : ''}`),
        dirBtn('out', 'Out', `Where ${whose} can go: other accounts it chained into, and the other cloud through federation${picked ? ' (the number counts where, not ways)' : ''}`)),
      M.view === 'estate' && !picked && st.dir !== 'both' ? h('p', { class: 'faint tiny', style: 'margin:4px 0 0' }, st.dir === 'in' ? 'Into your org from outside. Pick an account for its own.' : 'Between your accounts. Pick an account for its own.') : null);
    const pickWho = (k) => { const p = new URLSearchParams(ctx.params); if (k === 'all') p.delete('who'); else p.set('who', k); go(`#/space?${p}`); };
    // the resource access layer: on or off (the address keeps it)
    const resBox = h('input', { type: 'checkbox', checked: showRes });
    resBox.addEventListener('change', () => { const p = new URLSearchParams(location.hash.split('?')[1] || ''); if (resBox.checked) p.delete('res'); else p.set('res', '0'); go(`#/space?${p}`); });
    const resToggle = h('label', { class: 'row small', style: 'gap:6px', title: 'Resources (buckets, keys, queues, topics, secrets, functions, repositories) whose own policy lets in anyone or an account outside your estate' }, resBox, 'Resource access');
    // roles or IAM users is an AWS choice: a project has service accounts only
    const tabs = h('div', { class: 'stack', style: 'gap:12px' }, views, findBox(), G1 ? null : whoControl(who, pickWho), resToggle, dirs);
    if (M.view === 'estate') {
      const zones = M.zones.map((z) => {
        if (z.cloud === 'gcp' && M.zones.some((x) => x.id === z.id && x.cloud !== 'gcp')) return null;   // one card per environment, both clouds
        const gs = awsGroups().filter((g) => g.env === z.id), ps = (M.gcp?.projects || []).filter((g) => g.env === z.id);
        const all = [...gs, ...ps.filter((g) => g.usage)], roles = all.reduce((s, g) => s + g.roles, 0), cold = all.reduce((s, g) => s + g.cold, 0);
        if (!gs.length && !ps.length) return null;
        const planned = gs.filter((g) => g.planned).length;
        return card(focus === z.id, `background:${ENV[z.id].base}`, ENV[z.id].name, kfmt([...gs, ...ps].reduce((s, g) => s + g.calls7, 0)),
          [gs.length - planned ? `${gs.length - planned} accounts` : null, ps.length ? `${ps.length} project${ps.length === 1 ? '' : 's'}` : null, `${roles ? Math.round((100 * cold) / roles) : 0}% cold`, planned ? `${planned} planned` : null].filter(Boolean).join(' · '), () => set({ zone: focus === z.id ? '' : z.id }));
      });
      const highs = M.sources.filter((s) => s.risk === 'high').length, loose = M.sources.filter((s) => s.risk === 'medium').length;
      const zcards = zones.filter(Boolean);
      zcards.push(card(focus === 'outer', 'background:#d5dceb;transform:rotate(45deg);width:10px;height:10px;margin:0 1px', 'Outside your org', String(M.sources.length + M.hidden), `${highs} risky · ${loose} loose trust`, () => set({ zone: focus === 'outer' ? '' : 'outer' })));
      const list = awsGroups().filter((g) => !focus || focus === 'outer' || g.env === focus).sort((a, b) => b.calls7 - a.calls7);
      const projects = (M.gcp?.projects || []).filter((g) => !focus || focus === 'outer' || g.env === focus).sort((a, b) => b.calls7 - a.calls7 || b.high - a.high || b.roles - a.roles);
      left.replaceChildren(tabs, h('h2', { class: 'eyebrow' }, M.gcp ? 'Zones · both clouds · click to focus' : 'Zones · click to focus'), h('div', { class: 'sp-cards' }, ...zcards),
        h('div', { class: 'sp-listhead' }, h('h2', { class: 'eyebrow' }, 'Accounts · 7-day calls'), h('span', { class: 'mono faint' }, String(list.length))),
        h('div', { class: 'sp-list' }, ...list.map((g) => row(st.sel === g.id, g.planned ? `border:1.5px dashed ${ENV[g.env].hot}` : `background:${ENV[g.env].base}`, g.name, g.planned ? `${g.awsAccountId} · planned` : g.awsAccountId, g.planned ? '—' : kfmt(g.calls7), () => set({ sel: st.sel === g.id ? null : g.id })))),
        ...(M.gcp ? [h('div', { class: 'sp-listhead' }, h('h2', { class: 'eyebrow' }, 'Projects · 7-day calls'), h('span', { class: 'mono faint' }, String(projects.length))),
          h('div', { class: 'sp-list' }, ...projects.map((g) => row(st.sel === g.id, `background:${ENV[g.env].base};border-radius:2px;outline:1px solid ${GCP}`, g.name, `${num(g.roles)} service accounts${g.high ? ` · ${g.high} high risk` : ''}`, g.usage ? kfmt(g.calls7) : '—', () => set({ sel: st.sel === g.id ? null : g.id }))))] : []));
    } else {
      const cur = selRole?.cluster || M.groups[0];
      const opt = (value, label) => h('option', { value, selected: value === accountId }, label);
      const awsOpts = est.accounts.filter((a) => !a.planned).map((a) => opt(a.id, a.name)), gOpts = gcpList.map((p) => opt(`gcp:${p.projectId}`, p.projectId));
      const accounts = h('select', { class: 'sp-select', 'aria-label': gOpts.length ? 'Account or project' : 'Account', onChange: (ev) => go(`#/space?view=account&account=${encodeURIComponent(ev.target.value)}${wa}`) },
        ...(gOpts.length ? [h('optgroup', { label: 'AWS accounts' }, ...awsOpts), h('optgroup', { label: 'Google Cloud projects' }, ...gOpts)] : awsOpts));
      const val = (n) => (usage1 ? kfmt(n.calls7) : num(n.permissions || 0));
      left.replaceChildren(tabs, accounts, h('h2', { class: 'eyebrow' }, usage1 ? `${V.Roles} by the service they call most` : 'Service accounts by the service their roles reach most'),
        h('div', { class: 'sp-cards' }, ...M.groups.map((g) => card(cur === g, `border:2px solid ${ENV[g.env].base};border-radius:50%`, g.label, usage1 ? kfmt(g.calls7) : '—', `${g.roles.length + g.more} ${V.roles}`, () => g.roles[0] && set({ sel: g.roles[0].id })))),
        h('div', { class: 'sp-listhead' }, h('h2', { class: 'eyebrow' }, `${cur ? cur.label : V.Roles} · ${V.roles}`), h('span', { class: 'mono faint' }, String(cur ? cur.roles.length : 0))),
        h('div', { class: 'sp-list' }, ...(cur ? cur.roles : []).map((r) => row(st.sel === r.id, `background:${r.denied7 ? RED : ENV[r.cluster.env].base};border-radius:50%`, pretty(r.name).label, r.services.map((x) => (G1 ? SVC[x.name] || x.name : x.name)).join(' · ') || 'quiet this week', val(r), () => set({ sel: st.sel === r.id ? null : r.id })))));
    }
    const sw = (style) => h('span', { class: 'sp-sw', style });
    const legend = M.view === 'estate' ? [
      [sw('width:30px;height:12px;background:linear-gradient(180deg,#031009,#0b3a26);border:1px solid #2a8a5c'), M.gcp ? 'The green plane in front is AWS; each ring on it is one account' : 'The green plane is your organization; each ring on it is one account'],
      ...(M.gcp ? [[sw('width:30px;height:12px;background:linear-gradient(180deg,#030a14,#0a1f3a);border:1px solid #3d7bd6'), 'The blue plane behind is Google Cloud; each ring is a project, each dot a service account: higher the more it was called in 7 days (or, where calls are not read, the more it can do), red when high risk, grey on the floor when never called'],
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
      ...(showRes ? [[sw(`width:30px;border-top:2px dashed ${WARN}`), 'Dashed path from outside: it can use resources there (a bucket, key, queue, secret…) through their own policy, no role needed. Red: data or admin access'],
        [sw(`width:10px;height:10px;margin:0 10px;border:1.5px solid ${WARN}`), 'Small box on a ring: how many of its resources are open to anyone or outside accounts']] : []),
      [sw('width:30px;border-top:2px dashed #fff'), 'White dashed path: first seen today'],
      ...(M.scanner ? [[sw(`width:12px;height:12px;margin:0 9px;border-radius:50%;background:${CM}`), 'Curious Monkey: this portal. Its dotted paths are the scanner signing in to each account, kept apart from account-to-account paths']] : []),
      [sw(`width:30px;border-top:2px solid ${RED}`), 'Red is always a problem and always carries a ⚠ tag'],
    ] : [
      G1 ? [sw('width:30px;height:12px;background:linear-gradient(180deg,#030a14,#0a1f3a);border:1px solid #3d7bd6'), `The plane is one Google Cloud project: ${M.account.name}`]
        : [sw('width:30px;height:12px;background:linear-gradient(180deg,#031009,#0b3a26);border:1px solid #2a8a5c'), `The plane is one account: ${M.account.name}`],
      [sw('width:6px;height:14px;margin:0 12px;background:linear-gradient(#eef7f2 0 4px,#9cc7b4 4px 5px,transparent 5px)'), usage1 ? `Tower: ${G1 ? 'a Google Cloud service (storage, bigquery…)' : 'an AWS service'}. Taller = more calls into it in 7 days` : 'Tower: a Google Cloud service. Taller = more service accounts whose roles reach it (calls are not read)'],
      [sw(`width:12px;height:12px;margin:0 9px;border-radius:50%;border:2px solid ${ENV[M.account.environment].base}`), usage1 ? `Ring: ${V.roles} that call the same service most` : 'Ring: service accounts whose roles reach the same service most'],
      ...(usage1 ? [[sw('width:6px;height:6px;margin:0 12px;border-radius:50%;background:#8d9a93'), `Grey dots round the edge: ${V.roles} never called`]] : []),
      [sw(`width:30px;border-top:2px solid ${ENV[M.account.environment].base}`), `Thin paths: which services each ring ${usage1 ? 'calls' : 'can use'}. Click a ${V.role} for its own`],
      [sw('width:12px;height:12px;margin:0 9px;border-radius:50%;border:1.5px solid #9cc7b4'), G1 ? 'Rings past the edge: AWS accounts with federation in, or roles that trust a service account here' : 'Rings past the edge: accounts that chain in or out'],
      ...(M.scanner ? [[sw(`width:12px;height:12px;margin:0 9px;border-radius:50%;background:${CM}`), 'Curious Monkey: this portal, signing in to its scanner role here']] : []),
      [sw('width:10px;height:10px;margin:0 10px;border:1.5px solid #d5dceb;transform:rotate(45deg)'), `Diamond at the edge: where an identity from outside comes in. The number is how many ${V.roles} it can ${V.enter} (and resources it can use); click it for the list`],
      [sw(`width:12px;height:12px;margin:0 9px;border-radius:50%;border:1.5px solid ${RED}`), 'Red ring on a service: calls to it were refused this week'],
      ...(showRes ? [[sw(`width:9px;height:9px;margin:0 10px;background:${RED}`), `Box beside a tower: a resource of that service whose ${G1 ? 'IAM policy' : 'policy'} lets outsiders in. Filled = anyone, outlined = ${G1 ? 'an outside identity' : 'an outside account'}. Click it for who`],
        [sw(`width:30px;border-top:2px dashed ${WARN}`), `Dashed path to a gate: that outsider uses resources here, not ${V.roles}`]] : []),
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
  // The timeline is built once, then updated in place: rebuilding it would end a drag on the slider and drop focus.
  let tl = null;
  function renderBar() {
    const hour = st.hour;
    if (!tl) {
      const perHour = Array.from({ length: 24 }, (_, i) => M.groups.reduce((s, g) => s + g.prof[i], 0)), max = Math.max(1, ...perHour);
      const play = h('button', { class: 'sp-play', onClick: () => { if (st.playing) { stop(); set({ playing: false }); } else { st.playing = true; st.timer = setInterval(() => { if (!page.isConnected) return stop(); set({ hour: (st.hour + 1) % 24 }); }, 1400); render(); } } });
      const input = h('input', { type: 'range', class: 'sp-range', min: 0, max: 23, step: 1, value: hour, 'aria-label': 'Hour of the last 24 to show (calls made in that hour)',
        onInput: (ev) => { stop(); set({ hour: Number(ev.target.value), playing: false }); } });
      const when = h('span', { class: 'sp-when' }), what = h('span');
      const fills = perHour.map((v) => h('span', { class: 'sp-fill', style: `height:${Math.max(3, Math.round((v / max) * 28))}px` }));
      const daySel = h('select', { class: 'sp-day', 'aria-label': 'Which day to show, hour by hour' }, ...Array.from({ length: 30 }, (_, d) => h('option', { value: d, selected: d === day },
        d === 0 ? 'Last 24 h' : d === 1 ? 'Day before' : new Date(M.hourStart + 23 * 36e5 - (d - day) * 864e5).toLocaleDateString('en-GB', { day: '2-digit', month: 'short', timeZone: TZ }))));
      daySel.addEventListener('change', () => { stop(); const p = new URLSearchParams(location.hash.split('?')[1] || ''); +daySel.value ? p.set('day', daySel.value) : p.delete('day'); p.delete('hour'); go(`#/space?${p}`); });
      bar.replaceChildren(h('div', { class: 'stack', style: 'gap:6px;align-items:center' }, play, daySel), h('div', { class: 'sp-bar-body' }, h('div', { class: 'sp-bar-head' }, when, what),
        h('div', { class: 'sp-scrub' }, ...fills.map((fl, i) => { const ev = M.events.find((e) => e.hour === i); return h('span', { class: 'sp-col' }, fl, ev ? h('span', { class: 'sp-mark', style: `background:${TONE[ev.tone] || '#fff'}` }) : null); }), input),
        h('div', { class: 'sp-ticks' }, ...[0, 6, 12, 18, 23].map((i) => h('span', null, i === 23 && !day ? 'now' : hourLabel(i))))));
      tl = { play, input, when, what, fills, perHour, shown: null, playing: null };
    }
    if (tl.playing !== st.playing) {
      tl.playing = st.playing;
      tl.play.setAttribute('aria-label', st.playing ? 'Pause the day' : 'Play the day, one hour at a time'); tl.play.setAttribute('aria-pressed', String(st.playing));
      tl.play.replaceChildren(svg('svg', { width: 14, height: 14, viewBox: '0 0 14 14', 'aria-hidden': 'true' }, st.playing ? svg('path', { d: 'M3 2v10M11 2v10', stroke: 'currentColor', 'stroke-width': 2.4 }) : svg('path', { d: 'M3 1.5 L12 7 L3 12.5 Z', fill: 'currentColor' })));
    }
    if (tl.shown !== hour) {
      tl.shown = hour;
      const nowEv = M.events.filter((e) => e.hour === hour);
      if (Number(tl.input.value) !== hour) tl.input.value = hour;
      tl.input.setAttribute('aria-valuetext', `${hourLabel(hour)} ${TZ_LABEL}`);
      tl.fills.forEach((fl, i) => fl.classList.toggle('on', i === hour));
      tl.when.textContent = `${hourLabel(hour)}–${hourLabel(hour + 1)} ${TZ_LABEL}${hour === 23 && !day ? ' · NOW' : ''} · ${kfmt(tl.perHour[hour])} CALLS`;
      // each event's own text already says what kind it is
      tl.what.textContent = nowEv.length ? nowEv.map((e) => e.text).join(' · ') : 'nothing flagged this hour';
      tl.what.style.color = nowEv.length ? paint(TONE[nowEv[0].tone] || '#fff') : 'var(--faint)';
      tl.what.title = tl.what.textContent;
    }
    // the HUD is aria-live: rebuilt only when its words change, or every frame of a drag would be read out again
    { const next = [h('div', { class: 'sp-hud-a' }, `● ${M.view === 'estate' ? 'ESTATE' : `${M.account.name.toUpperCase()} · ${String(V.idLine).toUpperCase()}`} · ${hourLabel(hour)} ${TZ_LABEL}`),
      h('div', null, M.view === 'estate' ? `${awsGroups().length} ACCOUNTS · ${num(awsGroups().reduce((s, g) => s + g.roles, 0))} ${noun.toUpperCase()} · ${M.sources.filter((x) => !x.gcp).length + M.hidden} OUTSIDE${M.gcp ? ` · GOOGLE CLOUD ${M.gcp.projects.length} PROJECTS · ${M.gcp.xlinks.reduce((n, l) => n + l.pairs.length, 0)} CROSS-CLOUD` : ''}` : (usage1 ? `${M.roleCount} ${V.ROLES} · ${M.roles.length} CALLED THIS WEEK · ${M.towers.length} SERVICES` : `${M.roleCount} ${V.ROLES} · CALLS NOT READ · ${M.towers.length} SERVICES`)),
      h('div', null, M.view === 'estate' ? 'HEIGHT = CALLS IN 7 DAYS (LOG) · DRAG TO TURN · SHIFT+DRAG OR TWO FINGERS TO MOVE · PINCH OR WHEEL TO ZOOM' : `${usage1 ? 'TOWER = CALLS INTO A SERVICE' : 'TOWER = SERVICE ACCOUNTS ITS ROLES REACH'} · DRAG TO TURN · SHIFT+DRAG OR TWO FINGERS TO MOVE · PINCH OR WHEEL TO ZOOM`)];
      const t = next.map((x) => x.textContent).join('\n'); if (hud.dataset.t !== t) { hud.dataset.t = t; hud.replaceChildren(...next); } }
    const btn = ([icon, label, fn]) => h('button', { 'aria-label': label, title: label, onClick: fn }, icon);
    const moved = st.px || st.py || st.az !== HOME.az || st.el !== HOME.el || st.zoom !== HOME.zoom;
    if (cam.firstChild) { cam.querySelector('.cam-reset').disabled = !moved; return; }
    cam.replaceChildren(
      h('div', { class: 'cam-row' }, h('span', { class: 'eyebrow' }, 'Move'), ...[['←', 'Move the view left', () => set({ px: clampPan(st.px + 120, W) })], ['→', 'Move the view right', () => set({ px: clampPan(st.px - 120, W) })],
        ['↑', 'Move the view up', () => set({ py: clampPan(st.py + 80, H) })], ['↓', 'Move the view down', () => set({ py: clampPan(st.py - 80, H) })]].map(btn)),
      h('div', { class: 'cam-row' }, h('span', { class: 'eyebrow' }, 'Turn'), ...[['⟲', 'Rotate left', () => set({ az: st.az - 20 })], ['⟳', 'Rotate right', () => set({ az: st.az + 20 })],
        ['▲', 'Look from higher', () => set({ el: Math.min(70, st.el + 8) })], ['▼', 'Look from lower', () => set({ el: Math.max(18, st.el - 8) })]].map(btn)),
      h('div', { class: 'cam-row' }, h('span', { class: 'eyebrow' }, 'Zoom'), ...[['+', 'Zoom in', () => set({ zoom: Math.min(3, st.zoom * 1.25) })], ['−', 'Zoom out', () => set({ zoom: Math.max(0.6, st.zoom / 1.25) })],
          ['⌖', 'Go to what is picked (or press F, or double-click it)', () => { if (st.sel) flyTo(st.sel); }]].map(btn),
        wall.button, h('button', { class: 'cam-reset', disabled: !moved, title: 'Back to the starting view', onClick: () => set({ ...HOME, px: 0, py: 0 }) }, 'Reset')));
  }

  // a change picked in the bell that this scene shows (the last 24 hours) is selected here, at its hour
  const wall = wallMode(ctx);
  ctx.setChangePicker((c) => { const e = M.events.find((x) => x.id === `c${c.id}`); if (!e) return false; set({ sel: e.target || st.sel, hour: e.hour }); return true; });
  render();
  // on the wall the day plays by itself
  if (wall.on && !st.playing) { st.playing = true; st.timer = setInterval(() => { if (!page.isConnected) return stop(); set({ hour: (st.hour + 1) % 24 }); }, 2400); render(); }
  return page;
}
