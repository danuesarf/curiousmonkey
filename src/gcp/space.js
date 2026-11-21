// Space for Google Cloud: the second field on the estate (a project is a ring, each service account a star) and one
// project (service accounts clustered by the service they call most, services as towers), in the same shapes as the
// AWS side (src/spaceApi.js), so Space draws both clouds the same way.
//
// Calls come from the audit-log usage reader (src/gcp/usage.js), when a connection has it on: per day for heights and
// services, per hour for the glow and the replay. Without it, heights are what a service account can do (permissions)
// and nothing is "never called": usage is unknown, not zero. Who can get in comes from the Trust page's ways in
// (src/gcp/trust.js) and from resource-level policies (resources and resource_findings), one node per outsider.
import { read as query } from '../db.js';
import { environmentOf } from '../environments.js';
import { crossLinks } from './links.js';
import { gcpWays } from './trust.js';
import { gcpProjects, summarizeSources } from './projects.js';
import { parseMember } from './analyze.js';

const num = (x) => Number(x || 0);
const RANK = { none: 0, low: 1, medium: 2, high: 3 };
const SEV = { high: 0, medium: 1, low: 2, info: 3, none: 4 };
const worse = (a, b) => (RANK[b] > RANK[a] ? b : a);
const OUTSIDE = new Set(['public', 'external', 'other-org', 'oidc']);   // AWS federation is a path between the fields instead
const RES_CONTROLS = ['res.public', 'res.external-account'];
const MAX_SOURCES = 14;
const LEVELS = new Set(['project', 'folder', 'organization']);
// a resource's service (the Resources page's names) as the first part of its permissions, so it sits by its tower
const TOWER = { gcs: 'storage', bigquery: 'bigquery', pubsub: 'pubsub', cloudkms: 'cloudkms', gsecret: 'secretmanager', cloudrun: 'run', cloudfunctions: 'cloudfunctions', artifactregistry: 'artifactregistry' };
const towerOf = (r) => ({ ...r, service: TOWER[r.service] || r.service, serviceKey: r.service });

// the same 24 one-hour buckets as the AWS side: bucket 23 is the hour in progress; ?day=N shows that day's 24 hours
async function hourStart(day = 0) { return new Date((await query(`SELECT date_trunc('hour', now()) - interval '23 hours' - make_interval(days => $1) AS t`, [day])).rows[0].t).getTime(); }
const bucketOf = (t, start) => Math.max(0, Math.min(23, Math.floor((new Date(t).getTime() - start) / 36e5)));
const svcOfPerm = (perm) => String(perm).split('.')[0];
// the service a role is about: roles/storage.objectAdmin → storage; basic roles reach everything
const svcOfRole = (role) => { const m = String(role).match(/^(?:projects\/[^/]+\/|organizations\/[^/]+\/)?roles\/([a-z0-9]+)\./i); return m ? m[1] : /roles\/(owner|editor|viewer)$/.test(role) ? 'every service' : 'custom'; };

/** How an outsider is named: the same words as the Trust page. */
function outsiderOf(member) {
  if (member === 'allUsers') return { label: 'Anyone on the internet (allUsers)', sub: 'public', group: 'public' };
  if (member === 'allAuthenticatedUsers') return { label: 'Any Google account (allAuthenticatedUsers)', sub: 'public', group: 'public' };
  const p = parseMember(member);
  if (p.kind === 'domain') return { label: `Everyone at ${p.email}`, sub: 'outside your domain · domain', group: 'external' };
  if (p.kind === 'serviceAccount') return { label: p.email, sub: 'service account outside the connection', group: 'external' };
  return { label: p.email || member, sub: `outside your domain · ${p.kind}`, group: 'external' };
}

/**
 * Usage: which projects have it (a connection reads their audit logs and has read some), and each caller's calls over
 * 7 days and 24 hours, by the hour in the window shown, whether it was ever seen, and (for one project's members) by
 * service. Callers are counted wherever they call, like an AWS role: a service account's calls in other projects count.
 */
async function usageOf(projectIds, start, { services = null } = {}) {
  const on = new Set((await query(
    `SELECT DISTINCT u.project_id FROM gcp_usage_projects u JOIN gcp_connections c ON c.id = u.connection_id AND c.usage_enabled
       JOIN gcp_log_cursors k ON k.project_ref = u.id AND k.hi_time IS NOT NULL WHERE u.project_id = ANY($1)`, [projectIds])).rows.map((r) => r.project_id));
  const [days, hours, ever, svc] = await Promise.all([
    query(`SELECT m.member, sum(d.count)::bigint AS c7, COALESCE(sum(d.count) FILTER (WHERE d.day >= current_date - 1), 0)::bigint AS c1, sum(d.denied)::bigint AS dn7
             FROM gcp_activity_daily d JOIN gcp_usage_members m ON m.id = d.member_id WHERE d.day >= current_date - 6 GROUP BY 1`),
    query(`SELECT m.member, h.hour, sum(h.count)::bigint AS n, sum(h.denied)::bigint AS dn FROM gcp_activity_hourly h JOIN gcp_usage_members m ON m.id = h.member_id
            WHERE h.hour >= to_timestamp($1) AND h.hour < to_timestamp($2) GROUP BY 1, 2`, [start / 1000, (start + 864e5) / 1000]),
    query(`SELECT DISTINCT m.member FROM gcp_usage_summary s JOIN gcp_usage_members m ON m.id = s.member_id WHERE s.count > 0`),
    services?.length ? query(`SELECT m.member, split_part(p.permission, '.', 1) AS svc, sum(d.count)::bigint AS n, sum(d.denied)::bigint AS dn
             FROM gcp_activity_daily d JOIN gcp_usage_members m ON m.id = d.member_id JOIN gcp_usage_perms p ON p.id = d.perm_id
            WHERE d.day >= current_date - 6 AND m.member = ANY($1) GROUP BY 1, 2`, [services]) : { rows: [] },
  ]);
  const by = new Map();
  const of = (member) => by.get(member) || by.set(member, { calls7: 0, calls24h: 0, denied7: 0, hourly: Array.from({ length: 24 }, () => ({ calls: 0, denied: 0 })), services: new Map() }).get(member);
  for (const r of days.rows) Object.assign(of(r.member), { calls7: num(r.c7), calls24h: num(r.c1), denied7: num(r.dn7) });
  for (const r of hours.rows) { const b = of(r.member).hourly[bucketOf(r.hour, start)]; b.calls += num(r.n); b.denied += num(r.dn); }
  for (const r of svc.rows) of(r.member).services.set(r.svc, { calls: num(r.n), denied: num(r.dn) });
  return { on, by, ever: new Set(ever.rows.map((r) => r.member)) };
}

/** Resources (resource-level IAM) open to anyone or outside: per project, and per outsider and project. */
async function resourceSide(projectIds) {
  const [exp, grants] = await Promise.all([
    query(`SELECT project_id, count(*) FILTER (WHERE exposure = 'public')::int AS public, count(*) FILTER (WHERE exposure = 'external')::int AS external,
                  min(CASE worst WHEN 'high' THEN 0 WHEN 'medium' THEN 1 WHEN 'low' THEN 2 END) AS w
             FROM resources WHERE cloud = 'gcp' AND deleted_at IS NULL AND project_id = ANY($1) AND exposure IN ('public', 'external') GROUP BY 1`, [projectIds]),
    query(`SELECT f.control, f.severity, f.principal, f.decision, f.title, r.id, r.name, r.service, r.project_id
             FROM resource_findings f JOIN resources r ON r.id = f.resource_id
            WHERE r.cloud = 'gcp' AND f.status = 'open' AND r.deleted_at IS NULL AND r.project_id = ANY($1) AND f.control = ANY($2) AND f.severity IN ('high', 'medium')`, [projectIds, RES_CONTROLS]),
  ]);
  return { exposure: new Map(exp.rows.map((x) => [x.project_id, { public: x.public, external: x.external, worst: ['high', 'medium', 'low'][x.w] || null }])), grants: grants.rows };
}

/**
 * Identities from outside the organisation, one node each, with what they reach per project: the service accounts
 * they can become (and the trust behind it), roles granted straight on the project, and resources.
 */
function outsidersOf(ways, grants, projects) {
  const by = new Map();
  const node = (key, base) => by.get(key) || by.set(key, { key, ...base, worst: 'none', trustWorst: 'none', findings: new Set(), targets: new Map(), resources: 0 }).get(key);
  const target = (o, pid) => o.targets.get(pid) || o.targets.set(pid, { projectId: pid, principals: new Set(), direct: [], edges: [], res: [], resCount: 0 }).get(pid);
  for (const w of ways) {
    const pid = w.target.project;
    if (!OUTSIDE.has(w.from) || !pid || !projects.has(pid)) continue;
    // trust is service accounts and roles on the project, folder or organisation; a role on one resource is drawn by
    // the resource layer (resource_findings), as AWS resource policies are
    if (w.target.kind !== 'serviceAccount' && !LEVELS.has(w.target.kind)) continue;
    const o = w.from === 'oidc'
      ? node(`wif:${w.origin?.pool}:${w.label}`, { label: w.label, sub: `federated · pool ${w.origin?.pool}`, group: 'oidc' })
      : node(w.member, { ...outsiderOf(w.member), principal: w.principalId || null });
    o.worst = worse(o.worst, w.worst); o.trustWorst = worse(o.trustWorst, w.worst);
    for (const f of w.findings) if (f.severity !== 'info') o.findings.add(f.title);
    const t = target(o, pid), findings = w.findings.filter((f) => f.severity !== 'info').map((f) => ({ title: f.title, severity: f.severity, detail: f.detail || null }));
    if (w.target.kind === 'serviceAccount') {
      t.principals.add(w.target.id);
      if (t.edges.length < 500) t.edges.push({ roleId: w.target.id, role: w.target.label, principal: w.member || w.label, actions: [w.role || w.via], conditions: w.conditional ? ['conditional binding'] : [], worst: w.worst, findings, sessions: 0, via: w.via });
    } else if (t.direct.length < 200) t.direct.push({ what: w.at?.label || w.target.label, role: w.role, worst: w.worst, findings });
  }
  for (const x of grants) {
    if (!projects.has(x.project_id)) continue;
    const o = node(x.principal, { ...outsiderOf(x.principal), principal: null });
    const sev = x.decision === 'expected' ? 'low' : x.severity;
    o.worst = worse(o.worst, sev);
    const t = target(o, x.project_id);
    if (t.res.some((r) => r.id === x.id)) continue;
    t.resCount++; o.resources++;
    if (t.res.length < 30) t.res.push({ id: x.id, name: x.name, service: TOWER[x.service] || x.service, serviceKey: x.service, severity: x.severity, expected: x.decision === 'expected', title: x.title });
  }
  const all = [...by.values()].sort((a, b) => RANK[b.worst] - RANK[a.worst] || b.targets.size - a.targets.size);
  return all.map((o) => ({ key: o.key, group: o.group, label: o.label, sub: o.sub, principal: o.principal || null, worst: o.worst, trustWorst: o.trustWorst, findings: [...o.findings].slice(0, 3), resources: o.resources,
    targets: [...o.targets.values()].map((t) => ({ projectId: t.projectId, principals: [...t.principals], direct: t.direct, edges: t.edges.sort((a, b) => SEV[a.worst] - SEV[b.worst]),
      resources: t.res.sort((a, b) => (a.expected - b.expected) || SEV[a.severity] - SEV[b.severity]), resourceCount: t.resCount })) }));
}

/**
 * Project to project: a service account that lives in one project and can act in another of the projects read (a role
 * granted on that project, a resource in it, or a service account there it can become), and the calls it was seen
 * making there (audit logs). The Google Cloud side of AWS's account-to-account paths. Roles granted on a folder or the
 * folder reaches the projects under it, and is drawn to each of them; one on the organization reaches every project, so
 * it is one decision on the identity's page, not a line to each.
 */
const BASIC = /^roles\/(owner|editor)$/;
const onLabel = (r) => r.resourceType === 'project' ? 'the project' : r.resourceType === 'serviceAccount' ? `becomes ${String(r.resource).split('/serviceAccounts/')[1]?.split('@')[0] || 'a service account'}`
  : `${r.resourceType} ${String(r.resource).replace(/^\/\/[^/]+\//, '').split('/').pop()}`;
export async function projectPairs(principals, has, start) {
  const [anc, days, hours] = await Promise.all([
    query(`SELECT DISTINCT project_id, ancestors FROM gcp_projects`).catch(() => ({ rows: [] })),
    query(`SELECT m.member, u.project_id, sum(d.count)::bigint AS n FROM gcp_activity_daily d JOIN gcp_usage_members m ON m.id = d.member_id JOIN gcp_usage_projects u ON u.id = d.project_ref
            WHERE d.day >= current_date - 6 AND m.member LIKE 'serviceAccount:%' GROUP BY 1, 2`).catch(() => ({ rows: [] })),
    query(`SELECT m.member, u.project_id, h.hour, sum(h.count)::bigint AS n FROM gcp_activity_hourly h JOIN gcp_usage_members m ON m.id = h.member_id JOIN gcp_usage_projects u ON u.id = h.project_ref
            WHERE h.hour >= to_timestamp($1) AND h.hour < to_timestamp($2) AND m.member LIKE 'serviceAccount:%' GROUP BY 1, 2, 3`, [start / 1000, (start + 864e5) / 1000]).catch(() => ({ rows: [] })),
  ]);
  const under = (folder) => [...new Set(anc.rows.filter((x) => (x.ancestors || []).includes(folder)).map((x) => x.project_id))];
  const calls = new Map(), hourly = new Map();
  for (const r of days.rows) calls.set(`${r.member}|${r.project_id}`, num(r.n));
  for (const r of hours.rows) { const k = `${r.member}|${r.project_id}`; if (!hourly.has(k)) hourly.set(k, Array(24).fill(0)); hourly.get(k)[bucketOf(r.hour, start)] += num(r.n); }
  const pairs = new Map();
  const pair = (a, b) => {
    const k = `${a}|${b}`;
    if (!pairs.has(k)) pairs.set(k, { from: `gcp:${a}`, to: `gcp:${b}`, fromProject: a, toProject: b, allowed: 0, calls7: 0, today: Array(24).fill(0), worst: 'none', grants: new Map() });
    return pairs.get(k);
  };
  const grantOf = (x, p, key, base) => x.grants.get(key) || x.grants.set(key, { caller: p.email, callerId: p.id, roles: [], calls7: 0, ...base }).get(key);
  for (const p of principals) {
    if (p.kind !== 'serviceAccount' || p.managed_by === 'google' || !has.has(p.project_id)) continue;
    const A = p.project_id, seen = new Set();
    for (const r of p.roles || []) {
      if (r.resourceType === 'organization') continue;
      const folder = r.resourceType === 'folder';
      for (const B of folder ? under(r.resource) : [r.project]) {
        if (!B || B === A || !has.has(B)) continue;
        const x = pair(A, B), on = folder ? `every project in ${r.resource}` : onLabel(r);
        const g = grantOf(x, p, `${p.id}|${on}`, { on, target: r.resourceType === 'serviceAccount' ? String(r.resource).split('/serviceAccounts/')[1] || null : null, folder });
        g.roles.push(r.role); x.allowed++;
        if (BASIC.test(r.role)) { x.worst = worse(x.worst, 'medium'); g.broad = true; }
        seen.add(B);
      }
    }
    // calls it made in other projects, allowed by a role here or not (a folder or organization role, say)
    for (const B of has) {
      if (B === A) continue;
      const n = calls.get(`${p.member}|${B}`) || 0, h = hourly.get(`${p.member}|${B}`);
      if (!n && !h) continue;
      const x = pair(A, B);
      const list = [...x.grants.values()].filter((g) => g.callerId === p.id);
      const g = list[0] || grantOf(x, p, `${p.id}|calls`, { on: seen.has(B) ? 'the project' : 'a role on the organization', target: null });
      g.calls7 += n; x.calls7 += n;
      if (h) h.forEach((v, i) => { x.today[i] += v; });
    }
  }
  return [...pairs.values()].map((x) => {
    const grants = [...x.grants.values()].sort((a, b) => b.calls7 - a.calls7 || (b.broad ? 1 : 0) - (a.broad ? 1 : 0));
    return { from: x.from, to: x.to, fromProject: x.fromProject, toProject: x.toProject, allowed: x.allowed, calls7: x.calls7, worst: x.worst,
      today: x.today.reduce((a, b) => a + b, 0), hours: x.today.map((n, b) => (n ? b : -1)).filter((b) => b >= 0),
      grants: grants.slice(0, 40).map((g) => ({ ...g, roles: [...new Set(g.roles)] })), moreGrants: Math.max(0, grants.length - 40) };
  }).sort((a, b) => b.calls7 - a.calls7 || b.allowed - a.allowed);
}

const principalsOf = () => query(`SELECT DISTINCT ON (member) id, member, kind, email, display_name, project_id, reach, permissions, roles, risk, risk_score, risk_reasons, sources, origin, keys, managed_by
                                    FROM gcp_principals ORDER BY member, analyzed_at DESC`);

// ---------------------------------------------------------------- the estate's second field
export async function spaceGcp(day = 0) {
  const start = await hourStart(day);
  const [projects, principals, wif, ways] = await Promise.all([gcpProjects(), principalsOf(), query(`SELECT * FROM gcp_wif_providers`), gcpWays()]);
  const ids = projects.map((p) => p.projectId), has = new Set(ids);
  const [use, res] = await Promise.all([usageOf(ids, start), resourceSide(ids)]);
  const byProject = new Map(projects.map((p) => [p.projectId, { ...p, accounts: [], risky: 0, keys: 0, usage: use.on.has(p.projectId), calls7: 0, calls24h: 0, cold: 0,
    hourly: Array.from({ length: 24 }, () => ({ sessions: 0, calls: 0, denied: 0 })), resources: res.exposure.get(p.projectId) || null }]));
  for (const p of principals.rows) {
    if (p.kind !== 'serviceAccount' || !byProject.has(p.project_id)) continue;
    const g = byProject.get(p.project_id), u = use.by.get(p.member), managed = p.managed_by === 'google';
    const used = g.usage ? use.ever.has(p.member) : null;
    g.accounts.push({ id: p.id, email: p.email, name: p.display_name || p.email.split('@')[0], risk: p.risk, permissions: p.permissions, reach: p.reach.length, keys: p.keys.filter((k) => !k.disabled).length, managed,
      sources: summarizeSources(p.sources), reasons: p.risk_reasons.filter((r) => r.severity !== 'info').slice(0, 3), calls7: u?.calls7 || 0, used });
    if (p.risk === 'High') g.risky++;
    g.keys += p.keys.filter((k) => !k.disabled).length;
    if (u && !managed) { g.calls7 += u.calls7; g.calls24h += u.calls24h; u.hourly.forEach((b, i) => { g.hourly[i].calls += b.calls; g.hourly[i].denied += b.denied; }); }
    if (used === false && !managed) g.cold++;
  }
  const outside = outsidersOf(ways, res.grants, has);
  return {
    hourStart: new Date(start).toISOString(),
    projects: [...byProject.values()].map((g) => ({ ...g, accounts: g.accounts.sort((a, b) => (g.usage ? b.calls7 - a.calls7 : 0) || (a.risk === b.risk ? b.permissions - a.permissions : a.risk === 'High' ? -1 : b.risk === 'High' ? 1 : a.risk === 'Medium' ? -1 : 1)) })),
    outside: outside.slice(0, MAX_SOURCES * 2), hidden: Math.max(0, outside.length - MAX_SOURCES * 2),
    providers: wif.rows.map((w) => ({ name: w.name, project: w.project_id, pool: w.pool_id, provider: w.provider_id, type: w.type, awsAccountId: w.aws_account_id, issuer: w.issuer, condition: w.attribute_condition, disabled: w.disabled })),
    links: await crossLinks(),
    // service accounts acting in another of your projects
    chains: await projectPairs(principals.rows, has, start),
  };
}

// ---------------------------------------------------------------- one project
/**
 * One project, in the shape of one AWS account (spaceApi.spaceAccount): service accounts are the roles, services
 * (the first part of a permission: storage, bigquery...) the towers, AWS accounts with federation in or out the
 * accounts past the edge, outsiders the gates. Null when the project is not read by any connection.
 */
export async function spaceGcpProject(projectId, day = 0) {
  const project = (await gcpProjects()).find((p) => p.projectId === projectId);
  if (!project) return null;
  const start = await hourStart(day);
  const [principals, ways, links, accounts] = await Promise.all([principalsOf(), gcpWays(), crossLinks(), query(`SELECT id, name, account_id, environment FROM cloud_accounts`)]);
  const sas = principals.rows.filter((p) => p.kind === 'serviceAccount' && p.project_id === projectId && p.managed_by !== 'google');
  const [use, res, exposed] = await Promise.all([
    usageOf([projectId], start, { services: sas.map((p) => p.member) }),
    resourceSide([projectId]),
    query(`SELECT id, name, service, exposure, worst FROM resources WHERE cloud = 'gcp' AND project_id = $1 AND deleted_at IS NULL AND exposure IN ('public', 'external')
            ORDER BY CASE worst WHEN 'high' THEN 0 WHEN 'medium' THEN 1 ELSE 2 END, name LIMIT 60`, [projectId]),
  ]);
  const usage = use.on.has(projectId);
  // each service account's services: what it called (usage on), else what its roles are about (how many grants)
  const out = sas.map((p) => {
    const u = use.by.get(p.member);
    let services;
    if (usage) services = [...(u?.services || new Map())].map(([name, v]) => ({ name, calls: v.calls, denied: v.denied })).sort((a, b) => b.calls - a.calls);
    else {
      const m = new Map();
      for (const r of p.roles || []) { const s = svcOfRole(r.role); m.set(s, (m.get(s) || 0) + 1); }
      services = [...m].map(([name, n]) => ({ name, calls: n, denied: 0 })).sort((a, b) => b.calls - a.calls);
    }
    return { id: p.id, name: p.email.split('@')[0], email: p.email, kind: 'serviceAccount', risk: p.risk, cold: usage ? !use.ever.has(p.member) : false,
      calls7: usage ? u?.calls7 || 0 : 0, denied7: usage ? u?.denied7 || 0 : 0, permissions: p.permissions, keys: p.keys.filter((k) => !k.disabled).length,
      services: services.slice(0, 6), hourly: (u?.hourly || []).map((b) => b.calls).concat(Array(24).fill(0)).slice(0, 24) };
  });
  const total = new Map();
  for (const r of out) for (const s of r.services) total.set(s.name, (total.get(s.name) || 0) + s.calls);
  const services = [...total].sort((m, n) => n[1] - m[1]).slice(0, 8).map(([name, calls]) => ({ name, calls }));
  const groups = new Map();
  const tail = usage ? 'quiet this week' : 'no roles';
  for (const r of out.filter((x) => !x.cold)) { const k = r.services[0]?.name || tail; if (!groups.has(k)) groups.set(k, []); groups.get(k).push(r); }
  // as in an AWS account: the five biggest keep a ring each, the rest share one, and those quiet this week (or with no
  // roles) keep their own ring, never counted under "Other services"
  const rest = groups.get(tail); groups.delete(tail);
  let clusters = [...groups].map(([key, rs]) => ({ key, roles: rs, calls: rs.reduce((t, r) => t + r.calls7, 0) })).sort((m, n) => n.roles.length - m.roles.length || n.calls - m.calls);
  if (clusters.length > 6) clusters = [...clusters.slice(0, 5), { key: 'other', roles: clusters.slice(5).flatMap((c) => c.roles) }];
  if (rest) clusters.push({ key: tail, roles: rest, calls: 0 });
  const order = usage ? (m, n) => n.calls7 - m.calls7 : (m, n) => n.permissions - m.permissions;

  // AWS accounts past the edge: federation into this project (in), AWS roles that trust a service account here (out)
  const acct = new Map(accounts.rows.map((a) => [a.id, a]));
  const here = new Set(out.map((r) => r.id));
  const nb = new Map();
  const line = (awsId, dir, roleId, other, worst) => {
    const a = acct.get(awsId); if (!a) return;
    if (!nb.has(awsId)) nb.set(awsId, { id: awsId, name: a.name, environment: environmentOf(a.environment), awsAccountId: a.account_id, sessions: 0, allowedIn: 0, allowedOut: 0, byLink: new Map() });
    const n = nb.get(awsId), k = `${dir}:${here.has(roleId) ? roleId : '*'}`;
    if (!n.byLink.has(k)) n.byLink.set(k, { dir, roleId: here.has(roleId) ? roleId : null, sessions: 0, allowed: 0, worst: 'none', others: new Set() });
    const l = n.byLink.get(k); l.allowed++; l.others.add(other); l.worst = worse(l.worst, worst);
    if (dir === 'in') n.allowedIn++; else n.allowedOut++;
  };
  for (const l of links.awsToGcp) if (l.gcpProject === projectId && l.awsAccount) line(l.awsAccount, 'in', l.gcpPrincipal, l.awsRole || 'any role', l.broad ? 'high' : 'none');
  for (const l of links.gcpToAws) if (l.gcpProject === projectId && l.awsAccount) line(l.awsAccount, 'out', l.gcpPrincipal, l.awsRole, 'none');
  const neighbours = [...nb.values()].map(({ byLink, ...n }) => ({ ...n, moreLinks: 0, links: [...byLink.values()].map((l) => {
    const o = [...l.others];
    return { dir: l.dir, roleId: l.roleId, sessions: 0, allowed: l.allowed, worst: l.worst, otherRole: o.length > 1 ? `${o[0]} +${o.length - 1} more` : o[0] || '' };
  }) }));
  // your other projects: service accounts here acting there (out), and service accounts there acting here (in). One
  // line per service account here and direction; "sessions" are its calls there in 7 days
  const projects = await gcpProjects();
  const pinfo = new Map(projects.map((p) => [p.projectId, p]));
  const byEmail = new Map(sas.map((p) => [p.email, p.id]));
  const gnb = new Map();
  for (const x of await projectPairs(principals.rows, new Set(pinfo.keys()), start)) {
    const dir = x.fromProject === projectId ? 'out' : x.toProject === projectId ? 'in' : null; if (!dir) continue;
    const other = dir === 'out' ? x.toProject : x.fromProject, info = pinfo.get(other);
    if (!gnb.has(other)) gnb.set(other, { id: `gcp:${other}`, cloud: 'gcp', name: other, environment: info?.environment || null, awsAccountId: info?.number || null, sessions: 0, allowedIn: 0, allowedOut: 0, byLink: new Map() });
    const n = gnb.get(other);
    for (const g of x.grants) {
      const hereId = dir === 'out' ? g.callerId : (g.target && byEmail.get(g.target)) || null;
      const k = `${dir}:${hereId || '*'}`;
      if (!n.byLink.has(k)) n.byLink.set(k, { dir, roleId: hereId, sessions: 0, allowed: 0, worst: 'none', others: [] });
      const l = n.byLink.get(k);
      l.sessions += g.calls7; l.allowed += g.roles.length; if (g.broad) l.worst = worse(l.worst, 'medium');
      l.others.push(dir === 'out' ? `${g.roles.join(', ') || 'calls'} on ${g.on}` : `${g.caller.split('@')[0]}${g.roles.length ? ` · ${g.roles.join(', ')}` : ''}`);
      n.sessions += g.calls7; if (dir === 'in') n.allowedIn += g.roles.length; else n.allowedOut += g.roles.length;
    }
  }
  const gWeight = (n) => n.sessions * 10 + n.allowedIn + n.allowedOut;
  neighbours.push(...[...gnb.values()].sort((m, k) => gWeight(k) - gWeight(m)).slice(0, 8).map(({ byLink, ...n }) => {
    const links = [...byLink.values()].sort((m, k) => k.sessions - m.sessions || k.allowed - m.allowed);
    return { ...n, moreLinks: Math.max(0, links.length - 40), links: links.slice(0, 40).map((l) => ({ dir: l.dir, roleId: l.roleId, sessions: l.sessions, allowed: l.allowed, worst: l.worst,
      otherRole: l.others.length > 1 ? `${l.others[0]} +${l.others.length - 1} more` : l.others[0] || '' })) };
  }));

  // outsiders: one gate each. A role granted straight on the project has no service account to fan to: it is listed on
  // the outsider's card, and its path still goes to the gate
  const all = outsidersOf(ways, res.grants, new Set([projectId]));
  const items = all.slice(0, MAX_SOURCES).map((o) => ({ ...o, sessions: 0, lastSeen: null,
    targets: o.targets.map((t) => ({ accountId: `gcp:${projectId}`, roles: t.principals.filter((id) => here.has(id)).concat(t.direct.length ? [`direct:${projectId}`] : []),
      sessions: 0, edges: t.edges, direct: t.direct, resources: t.resources, resourceCount: t.resourceCount })) }));
  return {
    cloud: 'gcp', usage, hourStart: new Date(start).toISOString(),
    account: { id: `gcp:${projectId}`, cloud: 'gcp', name: projectId, projectId, title: project.name, number: project.number, awsAccountId: project.number, environment: project.environment, ou: null, connection: project.connection, connectionName: project.connectionName },
    services, clusters: clusters.map((c) => ({ key: c.key, roles: c.roles.sort(order).slice(0, 40), more: Math.max(0, c.roles.length - 40) })),
    cold: out.filter((r) => r.cold).map((r) => ({ id: r.id, name: r.name })).slice(0, 80), coldCount: out.filter((r) => r.cold).length, roleCount: out.length,
    calledCount: usage ? out.filter((r) => r.calls7 > 0).length : 0,
    neighbours, outside: { items, hidden: Math.max(0, all.length - MAX_SOURCES) }, scanner: null, events: [],
    resources: exposed.rows.map(towerOf),
  };
}
