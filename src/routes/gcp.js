// Google Cloud: connections, principals (the Roles page's Google Cloud tab), one principal, and Google Cloud's side
// of Space. Members limited to some AWS accounts do not see Google Cloud: its data is not split by account.
import { Router } from 'express';
import { z } from 'zod';
import { config } from '../config.js';
import { query } from '../db.js';
import { audit } from '../audit.js';
import { requireUser, requirePerm } from '../auth/sessions.js';
import { encrypt } from '../auth/crypto.js';
import { cachedWarm, scopeKey, clearCache } from '../cache.js';
import { isEnvironment, resolveEnvironment, environmentOf, defaultEnvironment } from '../environments.js';
import { gcpSnippets, awsRoleOf } from '../gcp/onboarding.js';
import { gcpGateway, hierarchy } from '../gcp/scan.js';
import { crossLinks } from '../gcp/links.js';

export const gcp = Router();
gcp.use(requireUser);
const wrap = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);
const uuid = z.string().uuid();
const NotFound = () => Object.assign(new Error('Not found'), { status: 404 });
const unscoped = (req, res, next) => (req.user.scope_accounts ? res.status(404).json({ error: 'not_found', message: 'Google Cloud is not visible to members limited to some AWS accounts.' }) : next());

// ---------- connections ----------
const Wif = z.object({
  projectNumber: z.string().trim().regex(/^\d{6,20}$/, 'The project number is digits (not the project ID).'),
  poolId: z.string().trim().regex(/^[a-z][a-z0-9-]{3,31}$/, 'Use the pool ID, such as curious-monkey.'),
  providerId: z.string().trim().regex(/^[a-z][a-z0-9-]{3,31}$/, 'Use the provider ID (4 to 32 characters), such as aws-scanner.'),
  serviceAccount: z.string().trim().toLowerCase().regex(/^[a-z0-9-]+@[a-z0-9-]+\.iam\.gserviceaccount\.com$/, 'Use a service account email.').or(z.literal('')).optional(),
});
const scopeId = (t, v) => (t === 'project' ? /^[a-z][a-z0-9-]{4,28}[a-z0-9]$/.test(v) : /^\d{6,20}$/.test(v));
const ConnBase = z.object({
  name: z.string().trim().min(1).max(80),
  scopeType: z.enum(['organization', 'folder', 'project']),
  scopeId: z.string().trim().max(40),
  environment: z.string().trim().max(40).optional(),
  authMode: z.enum(['wif', 'key']),
  wif: Wif.optional(),
  key: z.string().max(20000).optional(),
});
const scopeCheck = (b, ctx) => {
  if (b.scopeType && b.scopeId != null && !scopeId(b.scopeType, b.scopeId)) ctx.addIssue({ code: 'custom', path: ['scopeId'], message: b.scopeType === 'project' ? 'Use the project ID, such as acme-payments-prod.' : `Use the numeric ${b.scopeType} ID.` });
};
const Conn = ConnBase.superRefine(scopeCheck);
function parseKey(text) {
  let k; try { k = JSON.parse(text); } catch { throw Object.assign(new Error('The key is not valid JSON. Paste the whole file gcloud created.'), { status: 400 }); }
  if (k.type !== 'service_account' || !k.client_email || !k.private_key) throw Object.assign(new Error('That is not a service account key file (type service_account, with client_email and private_key).'), { status: 400 });
  return { enc: encrypt(JSON.stringify(k)), hint: `${k.client_email} · key ${String(k.private_key_id || '').slice(0, 8)}` };
}
const view = (c, counts = {}) => ({
  id: c.id, name: c.name, scopeType: c.scope_type, scopeId: c.scope_id, authMode: c.auth_mode, environment: c.environment,
  wif: c.auth_mode === 'wif' ? c.wif : null, keyHint: c.auth_mode === 'key' ? c.key_hint : null,
  status: c.status, detail: c.status_detail, lastScanAt: c.last_scan_at, nextScanAt: c.next_scan_at, scanning: !!(c.lease_until && new Date(c.lease_until) > new Date()), progress: c.progress,
  ...counts,
});

gcp.get('/gcp/connections', requirePerm('view'), unscoped, wrap(async (req, res) => {
  const [rows, counts] = await Promise.all([
    query('SELECT * FROM gcp_connections ORDER BY name'),
    query(`SELECT connection_id, count(*) FILTER (WHERE kind='serviceAccount')::int AS sas, count(*) FILTER (WHERE risk='High')::int AS high, count(*)::int AS principals,
           (SELECT count(*)::int FROM gcp_projects p WHERE p.connection_id = x.connection_id) AS projects FROM gcp_principals x GROUP BY connection_id`),
  ]);
  const by = new Map(counts.rows.map((r) => [r.connection_id, r]));
  res.json({ items: rows.rows.map((c) => view(c, { projects: by.get(c.id)?.projects || 0, serviceAccounts: by.get(c.id)?.sas || 0, high: by.get(c.id)?.high || 0, principals: by.get(c.id)?.principals || 0 })), awsMode: config.awsMode });
}));

/** The gcloud commands for a scope, with federation pinned to the AWS role this app's worker runs as. */
gcp.get('/gcp/onboarding', requirePerm('accounts'), unscoped, wrap(async (req, res) => {
  const q = z.object({ scopeType: z.enum(['organization', 'folder', 'project']).default('organization'), scopeId: z.string().max(40).optional(), mode: z.enum(['wif', 'key']).default('wif'),
    home: z.string().max(40).optional(), homeNumber: z.string().max(20).optional() }).parse(req.query);
  const w = (await query(`SELECT aws_identity FROM workers WHERE aws_identity IS NOT NULL ORDER BY heartbeat_at DESC LIMIT 1`)).rows[0];
  const aws = awsRoleOf(config.scanner.principalArn || w?.aws_identity?.arn);
  res.json({ ...gcpSnippets({ ...q, home: q.home || undefined, homeNumber: q.homeNumber || undefined, aws }), aws });
}));

/** Try the credentials and the scope before saving: who we are, and that the scope can be read. */
gcp.post('/gcp/connections/test', requirePerm('accounts'), unscoped, wrap(async (req, res) => {
  const b = ConnBase.partial({ name: true }).extend({ id: uuid.optional() }).superRefine(scopeCheck).parse(req.body);
  const stored = b.id ? (await query('SELECT * FROM gcp_connections WHERE id=$1', [b.id])).rows[0] : null;
  const conn = { id: b.id || 'test', scope_type: b.scopeType, scope_id: b.scopeId, auth_mode: b.authMode, wif: b.wif || stored?.wif || null,
    key_enc: b.key ? parseKey(b.key).enc : stored?.key_enc || null };
  try {
    const gw = gcpGateway(conn);
    const who = await gw.whoami();
    const { projects } = await hierarchy(conn, gw);
    const top = conn.scope_type === 'organization' ? `organizations/${conn.scope_id}` : conn.scope_type === 'folder' ? `folders/${conn.scope_id}` : `projects/${conn.scope_id}`;
    const pol = await gw.iamPolicy(top);
    await audit(req, 'gcp.test', { type: 'gcp' }, { scope: top, ok: true });
    res.json({ ok: true, identity: who.email, projects: projects.length, policyReadable: !!pol, sample: projects.slice(0, 5).map((p) => p.projectId) });
  } catch (e) {
    await audit(req, 'gcp.test', { type: 'gcp' }, { ok: false, error: String(e.message).slice(0, 200) });
    res.json({ ok: false, message: e.message });
  }
}));

gcp.post('/gcp/connections', requirePerm('accounts'), unscoped, wrap(async (req, res) => {
  const b = Conn.parse(req.body);
  if (b.authMode === 'wif' && !b.wif) return res.status(400).json({ error: 'invalid', message: 'Fill in the federation details.' });
  if (b.authMode === 'key' && !b.key) return res.status(400).json({ error: 'invalid', message: 'Paste the service account key.' });
  const key = b.authMode === 'key' ? parseKey(b.key) : null;
  const env = b.environment ? resolveEnvironment(b.environment) : defaultEnvironment();
  if (!isEnvironment(env)) return res.status(400).json({ error: 'invalid', message: 'Pick one of the environments.' });
  try {
    const c = (await query(`INSERT INTO gcp_connections(name, scope_type, scope_id, auth_mode, wif, key_enc, key_hint, environment, created_by) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING *`,
      [b.name, b.scopeType, b.scopeId, b.authMode, b.authMode === 'wif' ? JSON.stringify({ ...b.wif, serviceAccount: b.wif.serviceAccount || '' }) : null, key?.enc || null, key?.hint || null, env, req.user.id])).rows[0];
    await audit(req, 'gcp.connect', { type: 'gcp', id: c.id }, { name: b.name, scope: `${b.scopeType}/${b.scopeId}`, auth: b.authMode });
    clearCache();
    res.status(201).json(view(c));
  } catch (e) {
    if (e.code === '23505') return res.status(409).json({ error: 'exists', message: `That ${b.scopeType} is already connected.` });
    throw e;
  }
}));

gcp.patch('/gcp/connections/:id', requirePerm('accounts'), unscoped, wrap(async (req, res) => {
  const id = uuid.parse(req.params.id);
  const c = (await query('SELECT * FROM gcp_connections WHERE id=$1', [id])).rows[0]; if (!c) throw NotFound();
  const b = ConnBase.omit({ scopeType: true, scopeId: true }).partial().parse(req.body);   // the scope is fixed: remove and connect again to change it
  const next = { name: b.name ?? c.name, environment: b.environment ? resolveEnvironment(b.environment) : c.environment, auth_mode: b.authMode ?? c.auth_mode, wif: b.wif ? { ...b.wif, serviceAccount: b.wif.serviceAccount || '' } : c.wif, key_enc: c.key_enc, key_hint: c.key_hint };
  if (!isEnvironment(next.environment)) return res.status(400).json({ error: 'invalid', message: 'Pick one of the environments.' });
  if (b.key) Object.assign(next, (({ enc, hint }) => ({ key_enc: enc, key_hint: hint }))(parseKey(b.key)));
  if (next.auth_mode === 'key' && !next.key_enc) return res.status(400).json({ error: 'invalid', message: 'Paste the service account key.' });
  if (next.auth_mode === 'wif' && !next.wif) return res.status(400).json({ error: 'invalid', message: 'Fill in the federation details.' });
  const accessChanged = next.auth_mode !== c.auth_mode || JSON.stringify(next.wif) !== JSON.stringify(c.wif) || !!b.key;
  await query(`UPDATE gcp_connections SET name=$2, environment=$3, auth_mode=$4, wif=$5, key_enc=$6, key_hint=$7, next_scan_at = CASE WHEN $8 THEN now() ELSE next_scan_at END WHERE id=$1`,
    [id, next.name, next.environment, next.auth_mode, next.auth_mode === 'wif' ? JSON.stringify(next.wif) : null, next.auth_mode === 'key' ? next.key_enc : null, next.auth_mode === 'key' ? next.key_hint : null, accessChanged]);
  await audit(req, 'gcp.update', { type: 'gcp', id }, { name: next.name, environment: next.environment, auth: next.auth_mode, keyReplaced: !!b.key });
  clearCache();
  res.json(view((await query('SELECT * FROM gcp_connections WHERE id=$1', [id])).rows[0]));
}));

gcp.delete('/gcp/connections/:id', requirePerm('accounts'), unscoped, wrap(async (req, res) => {
  const id = uuid.parse(req.params.id);
  const c = (await query('DELETE FROM gcp_connections WHERE id=$1 RETURNING name, scope_type, scope_id', [id])).rows[0]; if (!c) throw NotFound();
  await audit(req, 'gcp.remove', { type: 'gcp', id }, { name: c.name, scope: `${c.scope_type}/${c.scope_id}` });
  clearCache();
  res.json({ ok: true });
}));

gcp.post('/gcp/connections/:id/scan', requirePerm('scan'), unscoped, wrap(async (req, res) => {
  const id = uuid.parse(req.params.id);
  const r = await query(`UPDATE gcp_connections SET next_scan_at = now() WHERE id=$1 RETURNING id`, [id]); if (!r.rowCount) throw NotFound();
  await audit(req, 'gcp.scan', { type: 'gcp', id });
  res.status(202).json({ ok: true, message: 'Queued. A worker starts within 30 seconds.' });
}));

gcp.put('/gcp/connections/:id/projects/:project/environment', requirePerm('accounts'), unscoped, wrap(async (req, res) => {
  const id = uuid.parse(req.params.id);
  const { environment } = z.object({ environment: z.string().max(40).nullable() }).parse(req.body);
  const env = environment == null ? null : resolveEnvironment(environment);
  if (env && !isEnvironment(env)) return res.status(400).json({ error: 'invalid', message: 'Pick one of the environments.' });
  const r = await query('UPDATE gcp_projects SET environment=$3 WHERE connection_id=$1 AND project_id=$2', [id, req.params.project, env]); if (!r.rowCount) throw NotFound();
  await audit(req, 'gcp.project_environment', { type: 'gcp', id }, { project: req.params.project, environment: env });
  clearCache();
  res.json({ ok: true });
}));

/** Every project with the environment it lands in: chosen here, then its env/environment label, then the connection's. */
export async function gcpProjects() {
  const r = await query(`SELECT p.*, c.environment AS default_env, c.name AS connection_name FROM gcp_projects p JOIN gcp_connections c ON c.id = p.connection_id ORDER BY p.project_id`);
  const seen = new Set();
  return r.rows.filter((p) => !seen.has(p.project_id) && seen.add(p.project_id)).map((p) => {
    const label = p.labels?.env || p.labels?.environment || p.labels?.stage || null;
    const fromLabel = label && isEnvironment(resolveEnvironment(label)) ? resolveEnvironment(label) : null;
    return { projectId: p.project_id, number: p.number, name: p.name || p.project_id, connection: p.connection_id, connectionName: p.connection_name, parent: p.parent,
      environment: environmentOf(p.environment || fromLabel || p.default_env), environmentSource: p.environment ? 'set' : fromLabel ? 'label' : 'connection', labels: p.labels };
  });
}
gcp.get('/gcp/projects', requirePerm('view'), unscoped, wrap(async (req, res) => res.json({ items: await gcpProjects() })));

// ---------- principals ----------
const KIND_LABEL = { serviceAccount: 'Service account', user: 'User', group: 'Group', domain: 'Domain', public: 'Public', federated: 'Federated identity', gke: 'GKE workload', deleted: 'Deleted', other: 'Other' };
const row = (p) => ({ id: p.id, member: p.member, kind: p.kind, kindLabel: KIND_LABEL[p.kind] || p.kind, email: p.email, name: p.display_name, project: p.project_id, uniqueId: p.unique_id,
  disabled: p.disabled, managed: p.managed_by === 'google', risk: p.risk, riskScore: p.risk_score, reasons: p.risk_reasons, permissions: p.permissions, reach: p.reach,
  roles: p.roles.length, keys: p.keys.filter((k) => !k.disabled).length, sources: summarizeSources(p.sources), origin: p.origin, connection: p.connection_id });
function summarizeSources(list) {
  const by = {};
  for (const s of list || []) by[s.via] = (by[s.via] || 0) + 1;
  const aws = (list || []).filter((s) => s.origin?.cloud === 'aws').map((s) => s.origin.label);
  return { ...by, aws: [...new Set(aws)] };
}

gcp.get('/gcp/principals', requirePerm('view'), unscoped, wrap(async (req, res) => {
  const q = z.object({ q: z.string().max(200).optional(), kind: z.string().max(40).optional(), risk: z.enum(['High', 'Medium', 'Low']).optional(), project: z.string().max(60).optional(),
    source: z.enum(['key', 'wif', 'aws', 'impersonate', 'gke']).optional(), hideManaged: z.enum(['1', '0']).optional(),
    sort: z.enum(['risk', 'permissions', 'name', 'reach']).default('risk'), limit: z.coerce.number().int().min(1).max(200).default(50), offset: z.coerce.number().int().min(0).default(0) }).parse(req.query);
  const w = ['TRUE'], p = [];
  const add = (sql, v) => { p.push(v); w.push(sql.replace('?', `$${p.length}`)); };
  if (q.q) add(`(member ILIKE ? OR coalesce(display_name,'') ILIKE $${p.length + 1})`, `%${q.q.replace(/[%_]/g, '\\$&')}%`);
  if (q.kind) add('kind = ?', q.kind);
  if (q.risk) add('risk = ?', q.risk);
  if (q.project) add('(project_id = ? OR $' + (p.length + 1) + ' = ANY(reach))', q.project);
  if (q.source === 'key') w.push(`jsonb_array_length(keys) > 0`);
  if (q.source === 'wif') w.push(`(sources @> '[{"via":"wif"}]' OR kind = 'federated')`);
  if (q.source === 'aws') w.push(`(sources @> '[{"origin":{"cloud":"aws"}}]' OR origin @> '{"cloud":"aws"}')`);
  if (q.source === 'impersonate') w.push(`sources @> '[{"via":"token"}]'`);
  if (q.source === 'gke') w.push(`sources @> '[{"via":"gke"}]'`);
  if (q.hideManaged === '1') w.push('managed_by IS NULL');
  const order = { risk: `CASE risk WHEN 'High' THEN 0 WHEN 'Medium' THEN 1 ELSE 2 END, risk_score DESC, member`, permissions: 'permissions DESC, member', name: 'coalesce(email, member)', reach: 'cardinality(reach) DESC, permissions DESC' }[q.sort];
  const where = w.join(' AND ');
  // an organization and a project inside it may both be connected: the first copy of each member is shown
  const base = `SELECT DISTINCT ON (member) * FROM gcp_principals WHERE ${where} ORDER BY member, analyzed_at DESC`;
  const [items, total, facets] = await Promise.all([
    query(`SELECT * FROM (${base}) x ORDER BY ${order} LIMIT ${q.limit} OFFSET ${q.offset}`, p),
    query(`SELECT count(*)::int n FROM (${base}) x`, p),
    query(`SELECT kind, risk, count(*)::int n FROM (SELECT DISTINCT ON (member) kind, risk FROM gcp_principals ORDER BY member) x GROUP BY kind, risk`),
  ]);
  const kinds = {}, risks = {};
  for (const f of facets.rows) { kinds[f.kind] = (kinds[f.kind] || 0) + f.n; risks[f.risk] = (risks[f.risk] || 0) + f.n; }
  res.json({ items: items.rows.map(row), total: total.rows[0].n, facets: { kinds, risks, kindLabels: KIND_LABEL }, projects: await gcpProjects() });
}));

gcp.get('/gcp/principals/:id', requirePerm('view'), unscoped, wrap(async (req, res) => {
  const id = uuid.parse(req.params.id);
  const p = (await query('SELECT * FROM gcp_principals WHERE id=$1', [id])).rows[0]; if (!p) throw NotFound();
  const [conn, titles, becomes, links, projects] = await Promise.all([
    query('SELECT id, name, scope_type, scope_id, last_scan_at FROM gcp_connections WHERE id=$1', [p.connection_id]),
    query('SELECT name, title, cardinality(permissions) AS n FROM gcp_role_defs WHERE name = ANY($1)', [p.roles.map((r) => r.role)]),
    query(`SELECT id, member, email, project_id, risk, sources FROM gcp_principals WHERE connection_id=$1 AND sources @> $2::jsonb`, [p.connection_id, JSON.stringify([{ member: p.member }])]),
    crossLinks(),
    gcpProjects(),
  ]);
  const t = new Map(titles.rows.map((r) => [r.name, r.title]));
  const env = new Map(projects.map((x) => [x.projectId, x.environment]));
  res.json({
    ...row(p), roles: p.roles.map((r) => ({ ...r, title: t.get(r.role) || null })), sources: p.sources, keysDetail: p.keys, connection: conn.rows[0] || null, environment: env.get(p.project_id) || null,
    becomes: becomes.rows.map((b) => ({ id: b.id, member: b.member, email: b.email, project: b.project_id, risk: b.risk, via: b.sources.filter((s) => s.member === p.member).map((s) => ({ via: s.via, role: s.role, at: s.at })) })),
    aws: { into: links.awsToGcp.filter((l) => l.gcpPrincipal === p.id), out: links.gcpToAws.filter((l) => l.gcpPrincipal === p.id) },
  });
}));

/** A whole permission list, on request (owner roles carry thousands). */
gcp.get('/gcp/roles/permissions', requirePerm('view'), unscoped, wrap(async (req, res) => {
  const name = z.string().max(300).parse(req.query.name);
  const r = (await query('SELECT name, title, permissions FROM gcp_role_defs WHERE name=$1', [name])).rows[0]; if (!r) throw NotFound();
  res.json(r);
}));

// ---------- Space: Google Cloud's field and the paths between the clouds ----------
export async function spaceGcp() {
  const [projects, principals, wif] = await Promise.all([
    gcpProjects(),
    query(`SELECT DISTINCT ON (member) id, member, kind, email, display_name, project_id, reach, permissions, risk, risk_score, risk_reasons, sources, origin, keys, managed_by FROM gcp_principals ORDER BY member, analyzed_at DESC`),
    query(`SELECT * FROM gcp_wif_providers`),
  ]);
  const byProject = new Map(projects.map((p) => [p.projectId, { ...p, accounts: [], risky: 0, keys: 0 }]));
  const outside = new Map();
  const out = (key, o) => { if (!outside.has(key)) outside.set(key, { key, ...o, targets: new Map(), worst: 'none' }); return outside.get(key); };
  const rank = { none: 0, low: 1, medium: 2, high: 3 };
  for (const p of principals.rows) {
    if (p.kind === 'serviceAccount' && byProject.has(p.project_id)) {
      const g = byProject.get(p.project_id);
      g.accounts.push({ id: p.id, email: p.email, name: p.display_name || p.email.split('@')[0], risk: p.risk, permissions: p.permissions, reach: p.reach.length, keys: p.keys.filter((k) => !k.disabled).length, managed: p.managed_by === 'google',
        sources: summarizeSources(p.sources), reasons: p.risk_reasons.filter((r) => r.severity !== 'info').slice(0, 3) });
      if (p.risk === 'High') g.risky++;
      g.keys += p.keys.filter((k) => !k.disabled).length;
    }
    // identities from outside the organization, and federated ones that are not from a connected AWS account
    const ext = p.risk_reasons.some((r) => ['external', 'public'].includes(r.id));
    if (ext || p.kind === 'public') {
      const o = out(p.member, { label: p.email || p.member, sub: p.kind === 'public' ? 'public' : `outside your domain · ${p.kind}`, group: p.kind === 'public' ? 'public' : 'external', principal: p.id });
      for (const pid of p.reach) o.targets.set(pid, { projectId: pid, principals: [p.id] });
      o.worst = p.risk === 'High' ? 'high' : 'medium';
    }
    for (const s of p.kind === 'federated' && p.origin ? [{ origin: p.origin, member: p.member }] : p.sources.filter((x) => x.via === 'wif' && x.origin)) {
      if (s.origin.cloud === 'aws') continue;                               // drawn as a path from the AWS field
      const o = out(`wif:${s.origin.pool}:${s.origin.label}`, { label: s.origin.label, sub: `federated · pool ${s.origin.pool}`, group: 'oidc' });
      const pid = p.kind === 'federated' ? p.reach[0] : p.project_id;
      if (pid) { const t = o.targets.get(pid) || { projectId: pid, principals: [] }; t.principals.push(p.id); o.targets.set(pid, t); }
      const sev = s.origin.broad ? 'high' : 'low';
      if (rank[sev] > rank[o.worst]) o.worst = sev;
    }
  }
  const links = await crossLinks();
  return {
    projects: [...byProject.values()].map((g) => ({ ...g, accounts: g.accounts.sort((a, b) => (a.risk === b.risk ? b.permissions - a.permissions : a.risk === 'High' ? -1 : b.risk === 'High' ? 1 : a.risk === 'Medium' ? -1 : 1)) })),
    outside: [...outside.values()].map((o) => ({ ...o, targets: [...o.targets.values()] })),
    providers: wif.rows.map((w) => ({ name: w.name, project: w.project_id, pool: w.pool_id, provider: w.provider_id, type: w.type, awsAccountId: w.aws_account_id, issuer: w.issuer, condition: w.attribute_condition, disabled: w.disabled })),
    links,
  };
}
gcp.get('/space/gcp', requirePerm('view'), wrap(async (req, res) => {
  if (req.user.scope_accounts) return res.json({ projects: [], outside: [], providers: [], links: { awsToGcp: [], gcpToAws: [] }, hidden: true });
  res.json(await cachedWarm(`space-gcp:${scopeKey(req.user)}`, () => spaceGcp()));
}));
