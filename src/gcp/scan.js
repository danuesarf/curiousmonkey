// One Google Cloud connection, read end to end: the hierarchy, every IAM policy, service accounts and their keys,
// workload identity providers, role definitions; then the analysis. The snapshot replaces the previous one in one
// transaction, so pages never see half a scan.
import { config } from '../config.js';
import { query, tx } from '../db.js';
import { analyzeGcp } from './analyze.js';
import { demoGcpGateway } from './demo.js';
import { realGcpGateway } from './real.js';

export const gcpGateway = (conn) => (config.awsMode === 'demo' ? demoGcpGateway(conn) : realGcpGateway(conn));
const PREDEFINED_TTL_DAYS = 7;

/** Projects in scope with their ancestry (nearest first, ending at the organization when it is visible). */
export async function hierarchy(conn, gw) {
  if (conn.scope_type === 'project') {
    const p = await gw.project(conn.scope_id);
    if (!p) throw Object.assign(new Error(`Project ${conn.scope_id} was not found, or the identity cannot see it.`), { retryable: false });
    const folders = await gw.folders().catch(() => []);
    return { org: null, folders, projects: [{ ...p, ancestors: ancestry(p.parent, folders) }] };
  }
  const folders = await gw.folders();
  const root = conn.scope_type === 'organization' ? `organizations/${conn.scope_id}` : `folders/${conn.scope_id}`;
  const all = (await gw.projects()).map((p) => ({ ...p, ancestors: ancestry(p.parent, folders) }));
  const inScope = all.filter((p) => p.ancestors.includes(root));
  return { folders: folders.filter((f) => ancestry(f.name, folders).includes(root)), projects: inScope };
}
function ancestry(parent, folders) {
  const by = new Map(folders.map((f) => [f.name, f]));
  const out = []; let at = parent, guard = 0;
  while (at && guard++ < 20) { out.push(at); at = by.get(at)?.parent; }
  return out;
}

const cachedFromDb = async (names) => new Map((await query(`SELECT name, permissions FROM gcp_role_defs WHERE name = ANY($1) AND fetched_at > now() - make_interval(days => $2)`, [names, PREDEFINED_TTL_DAYS])).rows.map((r) => [r.name, r.permissions]));

/** Read everything one connection can see and analyse it. No database writes. */
export async function collectGcp(conn, { gw = gcpGateway(conn), progress = async () => {}, log = () => {}, cachedRoles = cachedFromDb } = {}) {
  await progress({ stage: 'hierarchy' });
  const { folders, projects } = await hierarchy(conn, gw);
  const orgName = conn.scope_type === 'organization' ? `organizations/${conn.scope_id}` : projects[0]?.ancestors.find((a) => a.startsWith('organizations/')) || null;
  const org = orgName ? await gw.organization(orgName.split('/')[1]).catch(() => null) : null;

  // policies, from the top down; one we may not read is skipped and noted
  const bindings = [], skipped = [];
  const addPolicy = (resource, type, projectId, pol) => {
    for (const b of pol?.bindings || []) for (const member of b.members || []) bindings.push({ resource, resource_type: type, project_id: projectId, role: b.role, member, condition: b.condition || null });
  };
  const read = async (resource, type, projectId) => { const pol = await gw.iamPolicy(resource); if (!pol) skipped.push(resource); addPolicy(resource, type, projectId, pol); };
  await progress({ stage: 'policies', projects: projects.length });
  const above = new Set(projects.flatMap((p) => p.ancestors));
  if (orgName) above.add(orgName);
  await Promise.all([...above].map((r) => read(r, r.startsWith('organizations/') ? 'organization' : 'folder', null)));
  await Promise.all(projects.map((p) => read(`projects/${p.projectId}`, 'project', p.projectId)));

  // service accounts, keys, their own policies, custom roles, federation
  const serviceAccounts = [], providers = [], custom = [];
  let done = 0;
  await Promise.all(projects.map(async (p) => {
    const [sas, roles, wif] = await Promise.all([gw.serviceAccounts(p.projectId), gw.customRoles(`projects/${p.projectId}`), gw.wifProviders(p.projectId)]);
    custom.push(...roles);
    for (const w of wif) {
      const m = w.name.match(/projects\/(\d+)\/locations\/global\/workloadIdentityPools\/([^/]+)\/providers\/([^/]+)$/);
      providers.push({ name: w.name, project_id: p.projectId, project_number: m?.[1] || p.number, pool_id: m?.[2] || '', provider_id: m?.[3] || '', display_name: w.displayName || null,
        type: w.aws ? 'aws' : w.oidc ? 'oidc' : w.saml ? 'saml' : w.x509 ? 'x509' : 'other', aws_account_id: w.aws?.accountId || null, issuer: w.oidc?.issuerUri || null,
        allowed_audiences: w.oidc?.allowedAudiences || [], attribute_mapping: w.attributeMapping || {}, attribute_condition: w.attributeCondition || null, disabled: !!w.disabled });
    }
    await Promise.all(sas.map(async (sa) => {
      const [keys, pol] = await Promise.all([gw.serviceAccountKeys(sa.email), gw.serviceAccountPolicy(p.projectId, sa.email)]);
      serviceAccounts.push({ email: sa.email, project_id: p.projectId, unique_id: sa.uniqueId || null, display_name: sa.displayName || null, disabled: !!sa.disabled,
        keys: keys.filter((k) => !k.keyType || k.keyType === 'USER_MANAGED').map((k) => ({ id: k.name.split('/').pop(), created: k.validAfterTime, expires: k.validBeforeTime && !/^9999/.test(k.validBeforeTime) ? k.validBeforeTime : null, disabled: !!k.disabled })) });
      addPolicy(`projects/${p.projectId}/serviceAccounts/${sa.email}`, 'serviceAccount', p.projectId, pol);
    }));
    done++; if (done % 10 === 0) await progress({ stage: 'projects', done, projects: projects.length });
  }));
  if (orgName) custom.push(...await gw.customRoles(orgName).catch(() => []));

  // role definitions: custom ones from the listings, predefined ones cached for a week
  await progress({ stage: 'roles' });
  const roleDefs = new Map(custom.map((r) => [r.name, r.includedPermissions || []]));
  const wanted = [...new Set(bindings.map((b) => b.role))].filter((r) => !roleDefs.has(r));
  const cached = await cachedRoles(wanted);
  const fresh = [];
  await Promise.all(wanted.map(async (name) => {
    if (cached.has(name)) { roleDefs.set(name, cached.get(name)); return; }
    const r = await gw.role(name).catch(() => null);
    if (r) { roleDefs.set(name, r.includedPermissions || []); fresh.push({ name, title: r.title || null, permissions: r.includedPermissions || [], stage: r.stage || null }); }
    else log(`role ${name} could not be read; its permissions count as unknown`);
  }));
  for (const r of custom) fresh.push({ name: r.name, title: r.title || null, permissions: r.includedPermissions || [], stage: r.stage || null });

  await progress({ stage: 'analysis' });
  const snap = { org: { domain: org?.displayName || null }, projects: projects.map((p) => ({ project_id: p.projectId, ancestors: p.ancestors })), bindings, roleDefs, serviceAccounts, providers };
  const result = analyzeGcp(snap);
  return { org, folders, projects, bindings, serviceAccounts, providers, fresh, skipped, result };
}

export async function scanGcpConnection(conn, opts = {}) {
  const started = Date.now();
  const { org, folders, projects, bindings, serviceAccounts, providers, fresh, skipped, result } = await collectGcp(conn, opts);
  const log = opts.log || (() => {});
  await tx(async (c) => {
    const keep = new Map((await c.query('SELECT project_id, environment FROM gcp_projects WHERE connection_id=$1 AND environment IS NOT NULL', [conn.id])).rows.map((r) => [r.project_id, r.environment]));
    for (const t of ['gcp_projects', 'gcp_bindings', 'gcp_wif_providers', 'gcp_principals']) await c.query(`DELETE FROM ${t} WHERE connection_id=$1`, [conn.id]);
    for (const p of projects) {
      await c.query(`INSERT INTO gcp_projects(project_id, connection_id, number, name, parent, ancestors, labels, environment) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
        [p.projectId, conn.id, p.number, p.name, p.parent, p.ancestors, JSON.stringify(p.labels || {}), keep.get(p.projectId) || null]);
    }
    for (let i = 0; i < bindings.length; i += 500) {
      const chunk = bindings.slice(i, i + 500);
      await c.query(`INSERT INTO gcp_bindings(connection_id, resource, resource_type, project_id, role, member, condition)
                     SELECT $1, * FROM unnest($2::text[], $3::text[], $4::text[], $5::text[], $6::text[], $7::jsonb[])`,
      [conn.id, chunk.map((b) => b.resource), chunk.map((b) => b.resource_type), chunk.map((b) => b.project_id), chunk.map((b) => b.role), chunk.map((b) => b.member), chunk.map((b) => (b.condition ? JSON.stringify(b.condition) : null))]);
    }
    for (const w of providers) {
      await c.query(`INSERT INTO gcp_wif_providers(name, connection_id, project_id, project_number, pool_id, provider_id, display_name, type, aws_account_id, issuer, allowed_audiences, attribute_mapping, attribute_condition, disabled)
                     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`,
      [w.name, conn.id, w.project_id, w.project_number, w.pool_id, w.provider_id, w.display_name, w.type, w.aws_account_id, w.issuer, w.allowed_audiences, JSON.stringify(w.attribute_mapping), w.attribute_condition, w.disabled]);
    }
    for (const r of fresh) {
      await c.query(`INSERT INTO gcp_role_defs(name, title, permissions, stage, fetched_at) VALUES ($1,$2,$3,$4,now())
                     ON CONFLICT (name) DO UPDATE SET title=EXCLUDED.title, permissions=EXCLUDED.permissions, stage=EXCLUDED.stage, fetched_at=now()`, [r.name, r.title, r.permissions, r.stage]);
    }
    const saBy = new Map(serviceAccounts.map((s) => [`serviceAccount:${s.email}`, s]));
    for (const x of result.values()) {
      const sa = saBy.get(x.member);
      await c.query(`INSERT INTO gcp_principals(connection_id, member, kind, email, display_name, project_id, unique_id, disabled, managed_by, keys, roles, permissions, reach, sources, origin, risk, risk_score, risk_reasons, analyzed_at)
                     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18, now())`,
      [conn.id, x.member, x.kind, x.email || null, sa?.display_name || null, sa?.project_id || x.project || null, sa?.unique_id || null, !!sa?.disabled, x.managed ? 'google' : null,
        JSON.stringify(sa?.keys || []), JSON.stringify(x.roles), x.permissions, x.reach, JSON.stringify(x.sources), x.origin ? JSON.stringify(x.origin) : null, x.risk, x.risk_score, JSON.stringify(x.reasons)]);
    }
  });
  const summary = { projects: projects.length, folders: folders.length, serviceAccounts: serviceAccounts.length, principals: result.size, bindings: bindings.length, providers: providers.length,
    skipped, domain: org?.displayName || null, seconds: Math.round((Date.now() - started) / 1000) };
  log(`read ${summary.projects} projects, ${summary.serviceAccounts} service accounts, ${summary.bindings} bindings in ${summary.seconds}s`);
  return summary;
}

// ---------- the worker side: one connection at a time per worker, leased so two workers never read the same one ----------
const LEASE_MIN = 20;
export async function claimGcpConnection(workerId) {
  return (await query(`UPDATE gcp_connections SET lease_until = now() + make_interval(mins => $2), lease_by = $1, progress = '{"stage":"starting"}'
    WHERE id = (SELECT id FROM gcp_connections WHERE next_scan_at <= now() AND (lease_until IS NULL OR lease_until < now()) ORDER BY next_scan_at LIMIT 1 FOR UPDATE SKIP LOCKED)
    RETURNING *`, [workerId, LEASE_MIN])).rows[0] || null;
}

/** Scan one due connection, if any. Returns what happened, for the worker's log. */
export async function gcpTick(workerId, { gw } = {}) {
  const conn = await claimGcpConnection(workerId);
  if (!conn) return null;
  const progress = (p) => query(`UPDATE gcp_connections SET progress=$2, lease_until = now() + make_interval(mins => $3) WHERE id=$1`, [conn.id, JSON.stringify(p), LEASE_MIN]);
  try {
    const summary = await scanGcpConnection(conn, { gw: gw || gcpGateway(conn), progress });
    await query(`UPDATE gcp_connections SET status='connected', status_detail=$2, last_scan_at=now(), next_scan_at=now() + interval '24 hours', lease_until=NULL, lease_by=NULL, progress=NULL WHERE id=$1`,
      [conn.id, JSON.stringify(summary)]);
    return { id: conn.id, ok: true, summary };
  } catch (e) {
    await query(`UPDATE gcp_connections SET status='error', status_detail=$2, next_scan_at=now() + interval '1 hour', lease_until=NULL, lease_by=NULL, progress=NULL WHERE id=$1`,
      [conn.id, JSON.stringify({ message: String(e.message || e).slice(0, 600), at: new Date().toISOString() })]);
    return { id: conn.id, ok: false, error: e.message };
  }
}
