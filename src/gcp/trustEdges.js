// Google Cloud on the one Trust map: its ways in (src/gcp/trust.js) as Trust map edges, in the same shape as AWS's
// (src/trustmap.js edgesOf), so the map, grid, sources, ways in, filters, saved views, decisions, expected trust,
// change alerts and reports work for both clouds.
//
// A project is an "account" (id gcp:<project>, account_id <project>); what a way in reaches is the "role": a service
// account, every service account below a grant on a whole project, folder or organization (one edge per project, not
// one per service account), or the roles an identity holds on the project itself. Where it comes from is one of the
// Trust map's groups:
//   public            anyone (allUsers, allAuthenticatedUsers)
//   external-account  a domain outside yours, another company's project, an AWS account you do not connect, and your
//                     own project that no connection reads (marked yours, not onboarded)
//   connected-account another project you read, or an AWS account you connect: a line between your nodes
//   oidc              CI and identity providers through workload identity federation (GitHub…)
//   same-account      the project's own identities, its GKE workloads, and whoever holds a key
//   service           Google's own service agents
//   unknown           deleted identities
// Roles granted on one resource (a bucket, a topic…) are not ways in here, as AWS resource policies are not: they are
// on Resource access.
import { query } from '../db.js';
import { parseMember } from './analyze.js';
import { gcpWays, collapseWide } from './trust.js';
import { gcpProjects } from './projects.js';
import { BY_ID } from '../controlCatalog.js';

const LEVELS = new Set(['serviceAccount', 'scope', 'project', 'folder', 'organization']);
export const GCP_TYPES = { wif: 'gcp-federation', gke: 'gcp-gke', token: 'gcp-impersonate', actAs: 'gcp-actas', 'key-create': 'gcp-keycreate', key: 'gcp-key', direct: 'gcp-roles' };
// the permission each way in is used with, as the audit-log usage reader records it (Data Access for tokens)
const USE_PERM = { token: 'iam.serviceAccounts.getAccessToken', actAs: 'iam.serviceAccounts.actAs', 'key-create': 'iam.serviceAccountKeys.create' };
const ADMIN_PERMS = 3000;                  // Owner and Editor carry several thousand permissions
const pkindOf = (label) => (/github/i.test(label) ? 'github' : /gitlab/i.test(label) ? 'gitlab' : /bitbucket/i.test(label) ? 'bitbucket' : /terraform/i.test(label) ? 'terraform' : /circleci/i.test(label) ? 'circleci' : /azure|microsoft/i.test(label) ? 'azure' : null);

/** The Trust map group, the source and the account it comes from, for one way in. `ctx`: connected AWS accounts. */
export function originOf(w, ctx) {
  const p = w.member ? parseMember(w.member) : {};
  switch (w.from) {
    case 'public': return { group: 'public', source: w.label };
    case 'external': return { group: 'external-account', source: w.label, principalAccount: p.email || w.member, principalAccountName: w.label };
    case 'other-org': { const proj = p.project || p.projectNumber; return { group: 'external-account', source: w.label, principalAccount: proj || w.member, principalAccountName: proj ? `project ${proj}` : w.label }; }
    case 'own': { const proj = p.project || p.projectNumber; return { group: 'external-account', source: w.label, principalAccount: proj, principalAccountName: `project ${proj}`, inOrg: { name: proj, status: 'not read' } }; }
    case 'aws': {
      const acct = w.origin?.awsAccountId || w.origin?.awsAccountIds?.[0] || null;
      return { group: acct && ctx.awsConnected.has(acct) ? 'connected-account' : 'external-account', source: w.origin?.label || w.label, principalAccount: acct, principalAccountName: ctx.awsConnected.get(acct) || null, pkind: 'aws' };
    }
    case 'oidc': return { group: 'oidc', source: w.origin?.label || w.label, provider: w.origin?.issuer || w.origin?.pool || null, pkind: pkindOf(w.origin?.label || '') };
    case 'gke': return { group: 'same-account', source: w.label, pkind: 'gke' };
    case 'key': return { group: 'same-account', source: 'Key holders' };
    case 'deleted': return { group: 'unknown', source: w.label };
    default: {                                                           // your organisation
      if (p.kind === 'serviceAccount' && p.managed) return { group: 'service', source: w.label };
      const proj = p.kind === 'serviceAccount' ? ctx.own?.idOf(p.project || p.projectNumber) || p.project : null;
      if (proj && proj !== w.target.project) return { group: 'connected-account', source: w.label, principalAccount: proj, principalAccountName: proj };
      return { group: 'same-account', source: w.label };
    }
  }
}

const sameKind = (w) => (w.from === 'org' ? (parseMember(w.member || '').kind === 'serviceAccount' ? 'gcp-sa' : `gcp-${w.memberKind || 'user'}`) : null);

/** Edges and accounts (projects) for the Trust map. */
export async function gcpTrustEdges() {
  const [ways, projects, aws, perms, usage] = await Promise.all([
    gcpWays(),
    gcpProjects(),
    query('SELECT account_id, name FROM cloud_accounts').then((r) => r.rows),
    query(`SELECT DISTINCT ON (member) member, permissions FROM gcp_principals ORDER BY member, analyzed_at DESC`).then((r) => new Map(r.rows.map((x) => [x.member, x.permissions]))),
    usageOf(),
  ]);
  const { loadOwnership } = await import('./ownership.js');
  const ctx = { awsConnected: new Map(aws.map((a) => [a.account_id, a.name])), own: await loadOwnership() };
  const seenRows = (await query(`SELECT key, first_seen, conditional, weakened_at FROM gcp_ways_seen`).catch(() => ({ rows: [] }))).rows;
  const seen = new Map(seenRows.map((x) => [x.key, x]));
  const envOf = new Map(projects.map((p) => [p.projectId, p.environment]));

  // a grant on a whole project, folder or organization: one edge per project it reaches, not one per service account
  const perProject = [];
  for (const w of ways) {
    if (w.target.kind !== 'serviceAccount' || !w.wide) { perProject.push(w); continue; }
    perProject.push({ ...w, connectionId: `${w.connectionId}|${w.target.project}` });   // collapseWide groups by connection: split it by project
  }
  const folded = collapseWide(perProject).map((w) => ({ ...w, connectionId: String(w.connectionId).split('|')[0] }));

  const edges = [];
  for (const w of folded) {
    const kind = w.target.kind;
    if (!LEVELS.has(kind)) continue;                                   // a role on one resource: Resource access
    const project = w.target.project || w.target.projects?.[0];
    if (!project) continue;
    const o = originOf(w, ctx);
    const roleId = kind === 'serviceAccount' ? `gcp:${w.target.member}` : kind === 'scope' ? `gcp:scope:${w.at.label}|${project}` : `gcp:project:${project}`;
    const role = kind === 'serviceAccount' ? w.target.label : kind === 'scope' ? `${w.target.members.length} service accounts (all in ${w.at.label})` : `Roles on project ${project}`;
    const sid = String(w.role || GCP_TYPES[w.via] || '').replace(/^roles\//, '');
    const conditions = [...(w.conditional ? ['IAM condition on the binding'] : []), ...((w.origin?.providers || []).map((x) => x.condition).filter(Boolean).map((x) => `attribute condition: ${x}`))];
    // used: a caller seen with the permission this way in is used with, in the project, while usage is read there
    const perm = USE_PERM[w.via], u = usage.on.has(project) && perm && w.member ? usage.by.get(`${project}|${w.member}|${perm}`) : null;
    const useKnown = usage.on.has(project) && !!perm && !!w.member;
    const key = `${w.connectionId}|${roleId}|${w.member || w.label}|${w.via}|${w.role || ''}|${w.at?.label || ''}`;
    const s = seen.get(key);
    const granted = kind === 'serviceAccount' ? perms.get(w.target.member) || 0 : kind === 'scope' ? Math.max(0, ...w.target.members.map((m) => perms.get(`serviceAccount:${m.label}`) || 0)) : 0;
    const e = {
      cloud: 'gcp', gcpKey: key, roleId, role, roleArn: kind === 'serviceAccount' ? w.target.member : roleId, gcpId: w.target.id || null, gcpMembers: w.target.members || null,
      accountId: `gcp:${project}`, account: project, awsAccountId: project, environment: envOf.get(project) || w.target.env || null, connection: w.connection,
      risk: w.target.risk || (kind === 'scope' && w.target.members.some((m) => m.risk === 'High') ? 'High' : null), granted, gcpAdmin: granted >= ADMIN_PERMS,
      statement: `${w.via}:${w.role || ''}:${w.at?.label || ''}`, sid, actions: w.role ? [w.role] : [GCP_TYPES[w.via]], principal: w.member || w.label, conditions,
      findings: w.findings.map((f) => ({ id: f.id, severity: f.severity, title: f.title, detail: f.detail, fix: BY_ID.get(`gcp.${f.id}`)?.fix || null })),
      seen: u ? [{ display: w.member, last_seen: u.last, sessions: u.count, kind: 'gcp' }] : [], type: sameKind(w) || GCP_TYPES[w.via], ...o,
      lastUsed: null, useUnknown: !useKnown, worst: w.worst, sessions: u?.count || 0, callerCount: u ? 1 : 0, lastSeen: u?.last || null, firstSeen: s?.first_seen && new Date(s.first_seen).getFullYear() > 1971 ? s.first_seen : null,
      callers: u ? [[w.member, u.count]] : [], via: w.via, grantedOn: w.at?.label || null, origin: w.origin ? { label: w.origin.label, pool: w.origin.pool, broad: !!w.origin.broad, awsRole: w.origin.awsRole || null, awsAccountId: w.origin.awsAccountId || null } : null,
    };
    // AWS role behind federation: the chain can go on from it (Where it leads next)
    if (w.origin?.awsAccountId && w.origin?.awsRole) e.awsSourceRoleArn = `arn:aws:iam::${w.origin.awsAccountId}:role/${w.origin.awsRole}`;
    if (s && new Date(s.first_seen).getFullYear() > 1971 && Date.now() - new Date(s.first_seen) <= 30 * 864e5) e.change = { kind: 'new', at: s.first_seen };
    if (s?.weakened_at && Date.now() - new Date(s.weakened_at) <= 30 * 864e5) e.change = { kind: 'weakened', at: s.weakened_at, guards: ['IAM condition'] };
    edges.push(e);
  }
  const accounts = projects.map((p) => ({ id: `gcp:${p.projectId}`, name: p.projectId, account_id: p.projectId, environment: p.environment, status: 'connected', cloud: 'gcp', title: p.name }));
  return { edges, accounts };
}

/** Callers seen per project, member and permission, over the usage lookback; and which projects have usage read. */
async function usageOf() {
  const on = new Set((await query(`SELECT DISTINCT u.project_id FROM gcp_usage_projects u JOIN gcp_connections c ON c.id = u.connection_id AND c.usage_enabled
                                     JOIN gcp_log_cursors k ON k.project_ref = u.id AND k.hi_time IS NOT NULL`).catch(() => ({ rows: [] }))).rows.map((r) => r.project_id));
  const by = new Map();
  if (on.size) for (const r of (await query(`SELECT u.project_id, m.member, p.permission, max(s.last_day) AS last, sum(s.count)::bigint AS n
       FROM gcp_usage_summary s JOIN gcp_usage_projects u ON u.id = s.project_ref JOIN gcp_usage_members m ON m.id = s.member_id JOIN gcp_usage_perms p ON p.id = s.perm_id
      WHERE p.permission = ANY($1) AND s.count > 0 GROUP BY 1, 2, 3`, [Object.values(USE_PERM)])).rows) by.set(`${r.project_id}|${r.member}|${r.permission}`, { last: r.last, count: Number(r.n) });
  return { on, by };
}

/**
 * Keep gcp_ways_seen in step with the ways in now: new keys get their first sighting (the first sync of a connection
 * records what is there as known, not new), a binding that lost its condition gets weakened_at, keys not seen for 30
 * days go. Called by the worker after the index is built; a change re-signs the index.
 */
export async function syncGcpWaysSeen(edges) {
  const gcp = edges.filter((e) => e.cloud === 'gcp');
  const known = new Set((await query(`SELECT DISTINCT split_part(key, '|', 1) AS c FROM gcp_ways_seen`)).rows.map((r) => r.c));
  const rows = gcp.map((e) => ({ key: e.gcpKey, baseline: !known.has(e.gcpKey.split('|')[0]), conditional: e.conditions.includes('IAM condition on the binding') }));
  if (rows.length) await query(
    `INSERT INTO gcp_ways_seen AS s (key, first_seen, last_seen, conditional)
     SELECT k, CASE WHEN b THEN 'epoch'::timestamptz ELSE now() END, now(), c FROM unnest($1::text[], $2::boolean[], $3::boolean[]) AS x(k, b, c)
     ON CONFLICT (key) DO UPDATE SET last_seen = now(), conditional = EXCLUDED.conditional,
       weakened_at = CASE WHEN s.conditional AND NOT EXCLUDED.conditional THEN now() ELSE s.weakened_at END
     WHERE s.conditional IS DISTINCT FROM EXCLUDED.conditional OR s.last_seen < now() - interval '1 hour'`,
    [rows.map((r) => r.key), rows.map((r) => r.baseline), rows.map((r) => r.conditional)]);
  await query(`DELETE FROM gcp_ways_seen WHERE last_seen < now() - interval '30 days'`);
  return rows.length;
}
