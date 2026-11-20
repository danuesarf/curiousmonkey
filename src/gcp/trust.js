// Google Cloud on the Trust map: who can get in. The AWS side reads role trust policies; Google Cloud has none, so a
// "way in" here is one of:
//   - into a service account: workload identity federation (AWS, GitHub…), a GKE workload, impersonation (Token
//     Creator and similar), actAs (deploy something that runs as it), minting a key, or a key someone already holds
//     (worked out by the IAM scan: gcp_principals.sources);
//   - straight into a project, folder or the organization, for an identity from outside: anyone (allUsers…), a user,
//     group or domain outside the organisation's domain, a federated identity granted roles with no service account in
//     between, or a service account from a project outside the connection.
// Each way in gets its own findings, from the controls on the Policy page (gcp.*). No I/O but the reads at the top.
import { query } from '../db.js';
import { loadPolicy } from '../controls.js';
import { severityOf } from '../controlCatalog.js';
import { config } from '../config.js';
import { parseMember } from './analyze.js';
import { toCsv as rowsToCsv } from '../csv.js';
import { TYPE_LABEL } from './resources.js';

export const FROM = {
  public: 'Anyone', external: 'Outside your domain', aws: 'AWS (federation)', oidc: 'CI and identity providers', gke: 'GKE workloads', key: 'Keys',
  org: 'Your organisation', 'other-org': 'Service account outside the connection', deleted: 'Deleted identities',
};
export const VIA = { wif: 'Federation', gke: 'GKE workload', token: 'Impersonation', actAs: 'Act as', 'key-create': 'Can mint keys', key: 'Key', direct: 'Roles granted directly' };
const SEV = { high: 0, medium: 1, low: 2, info: 3, none: 4 };
const worstOf = (list) => list.reduce((w, f) => (SEV[f.severity] < SEV[w] ? f.severity : w), 'none');

/** Which "from" group a way in belongs to. */
function groupOf(src, domain, projects) {
  if (src.via === 'key') return 'key';
  if (src.via === 'wif' || src.kind === 'federated') return src.origin?.cloud === 'aws' ? 'aws' : 'oidc';
  if (src.via === 'gke' || src.kind === 'gke') return 'gke';
  if (src.kind === 'public') return 'public';
  if (src.kind === 'deleted') return 'deleted';
  const email = String(src.member || '').split(':').slice(1).join(':');
  if (src.kind === 'serviceAccount') {
    const p = parseMember(src.member);
    if (p.project && !projects.has(p.project) && !p.managed) return 'other-org';
    return 'org';
  }
  const d = (src.kind === 'domain' ? email : email.split('@')[1] || '').toLowerCase();
  if (domain && d && d !== domain && !d.endsWith(`.${domain}`)) return 'external';
  return 'org';
}

/**
 * Findings for one way in. `policy` is the workspace's control policy: a control turned off makes none, one given
 * another severity gets it.
 */
export function wayFindings(w, { policy, keyRotateDays = 90, now = Date.now() } = {}) {
  const out = [];
  const f = (id, builtIn, title, detail) => { const severity = policy ? severityOf(policy, `gcp.${id}`, builtIn) : builtIn; if (severity) out.push({ id, severity, title, detail }); };
  const target = w.target.kind === 'serviceAccount' ? 'become this service account' : `use the roles it holds on ${w.target.label}`;
  if (w.from === 'public') f(w.target.kind === 'serviceAccount' ? 'public-impersonator' : 'public', w.blocked ? 'low' : 'high', w.target.kind === 'serviceAccount' ? 'Anyone can become it' : 'Granted to everyone',
    w.blocked ? `${w.label} is granted ${w.role}, but the bucket enforces public access prevention: refused today.` : `${w.label} can ${target}.`);
  if (w.from === 'external') f(w.target.kind === 'serviceAccount' ? 'external-impersonator' : 'external', w.target.kind === 'serviceAccount' ? 'high' : 'medium',
    w.target.kind === 'serviceAccount' ? 'Someone outside your domain can become it' : 'Outside your domain', `${w.label} is not in your organisation's domain and can ${target}.`);
  if (w.from === 'other-org') f('foreign-sa', w.target.kind === 'serviceAccount' ? 'high' : 'medium', 'A service account from outside the connection', `${w.label} lives in a project this connection does not read: whoever runs it there can ${target}.`);
  if ((w.from === 'aws' || w.from === 'oidc') && w.origin?.broad) f('wif-broad', 'high', 'Any identity from a federated source', `${w.origin.label}: nothing narrows which identity it accepts (no attribute condition, or the whole pool).`);
  if (w.memberKind === 'domain' && w.from === 'org' && w.target.kind === 'serviceAccount') f('domain-impersonator', 'medium', 'Everyone in a domain can become it', `${w.label}: every account in the domain can ${target}.`);
  // Owner and Editor carry actAs everywhere: that is their own finding on the identity (gcp.basic-owner, basic-editor)
  const basic = /^roles\/(owner|editor)$/.test(w.role || '');
  if (basic && w.wide) f('basic-role', 'info', `Through ${w.role} on ${w.at.label}`, 'Owner and Editor include actAs on every service account below where they are granted; flagged on the identity itself.');
  if (w.wide && !basic && ['token', 'actAs', 'key-create'].includes(w.via)) f('wide-impersonation', 'medium', `Granted on the whole ${w.at.type}`,
    `${w.role} on ${w.at.label} lets ${w.label} become every service account there, this one included. Grant it on the service account instead.`);
  if (w.via === 'key-create') f('key-create', 'medium', 'Can mint keys for it', `${w.label} can create a key for this service account and use it from anywhere.`);
  if (w.via === 'key') {
    const keys = w.keys || [];
    const age = (k) => Math.floor((now - new Date(k.created).getTime()) / 864e5);
    const oldest = keys.length ? Math.max(...keys.map(age)) : 0, forever = keys.some((k) => !k.expires);
    f('key', oldest > keyRotateDays ? 'medium' : 'low', `${keys.length} user-managed key${keys.length === 1 ? '' : 's'}`, `Oldest ${oldest} days${forever ? ', never expires' : ''}. Whoever holds it can be this service account from anywhere.`);
  }
  if (w.conditional) f('conditional', 'info', 'Granted with a condition', 'Conditions are shown but not evaluated.');
  if (w.from === 'aws' && w.origin?.awsRole) f('cross-cloud', 'info', 'From AWS', `${w.origin.label}. The AWS role's own trust decides who reaches this.`);
  return out.sort((a, b) => SEV[a.severity] - SEV[b.severity]);
}

/** Every way in, one row each, from the stored scan. */
export async function gcpWays() {
  const [rows, conns, projs, awsRoles, papRows] = await Promise.all([
    // an organization and a project inside it may both be connected: the first copy of each member counts
    query(`SELECT DISTINCT ON (member) id, connection_id, member, kind, email, display_name, project_id, risk, roles, sources, origin, keys FROM gcp_principals ORDER BY member, analyzed_at DESC`),
    query(`SELECT id, name, status_detail->>'domain' AS domain FROM gcp_connections`),
    query(`SELECT connection_id, project_id, name, coalesce(environment, labels->>'env') AS env FROM gcp_projects`),
    query(`SELECT r.id, r.name, a.account_id FROM roles r JOIN cloud_accounts a ON a.id = r.account_id WHERE r.deleted_at IS NULL`),
    // buckets whose public access prevention refuses allUsers and allAuthenticatedUsers whatever IAM says
    query(`SELECT arn FROM resources WHERE cloud = 'gcp' AND deleted_at IS NULL AND extra->>'publicAccessPrevention' = 'enforced'`).catch(() => ({ rows: [] })),
  ]);
  const blocked = new Set(papRows.rows.map((x) => x.arn));
  const domainOf = new Map(conns.rows.map((c) => [c.id, String(c.domain || '').toLowerCase()]));
  const connName = new Map(conns.rows.map((c) => [c.id, c.name]));
  const projectsOf = new Map();
  for (const p of projs.rows) { if (!projectsOf.has(p.connection_id)) projectsOf.set(p.connection_id, new Set()); projectsOf.get(p.connection_id).add(p.project_id); }
  const envOf = new Map(projs.rows.map((p) => [p.project_id, p.env]));
  const awsRole = new Map(awsRoles.rows.map((r) => [`${r.account_id}:${r.name}`, r.id]));
  const where = (type, resource, project) => ({ type, label: type === 'organization' ? 'the organization' : type === 'folder' ? `folder ${resource.split('/')[1]}` : type === 'project' ? `project ${project || resource.split('/')[1]}` : type === 'serviceAccount' ? 'the service account itself'
    : TYPE_LABEL[type] ? `${TYPE_LABEL[type]} ${String(resource).replace(/^\/\/[^/]+\//, '').split('/').pop()}` : resource });

  const ways = [];
  const push = (w) => {
    if (w.origin?.cloud === 'aws' && w.origin.awsAccountId && w.origin.awsRole) w.awsRoleId = awsRole.get(`${w.origin.awsAccountId}:${w.origin.awsRole}`) || null;
    ways.push(w);
  };
  for (const p of rows.rows) {
    const domain = domainOf.get(p.connection_id) || '', projects = projectsOf.get(p.connection_id) || new Set();
    const base = { connectionId: p.connection_id, connection: connName.get(p.connection_id) || null };
    // into a service account
    if (p.kind === 'serviceAccount') {
      const target = { kind: 'serviceAccount', id: p.id, member: p.member, label: p.email, project: p.project_id, risk: p.risk, env: envOf.get(p.project_id) || null };
      for (const s of p.sources || []) {
        const from = groupOf(s, domain, projects);
        push({ ...base, key: `${p.member}|${s.via}|${s.member || 'key'}|${s.role || ''}|${s.at || ''}`, target, from, via: s.via, member: s.member || null, memberKind: s.kind,
          label: s.origin?.label || s.label || s.member, role: s.role || null, at: s.at ? where(s.atType, s.at, s.at.split('/')[1]) : null, wide: !!s.wide, conditional: !!s.conditional,
          origin: s.origin || null, keys: s.keys || null, namespace: s.namespace || null });
      }
      // a service account from a project outside the connection is also an identity from outside: its roles below
      const own = parseMember(p.member);
      if (!(own.project && !projects.has(own.project) && !own.managed)) continue;
    }
    // straight in, for identities from outside: their roles are the way in
    const pm = parseMember(p.member);
    const src = { kind: p.kind, member: p.member, via: p.kind === 'federated' ? 'wif' : 'direct', origin: p.origin };
    const from = groupOf(src, domain, projects);
    if (!['public', 'external', 'aws', 'oidc', 'other-org'].includes(from)) continue;
    for (const r of p.roles || []) {
      if (r.resourceType === 'serviceAccount') continue;            // counted above, as a way into that service account
      const at = where(r.resourceType, r.resource, r.project);
      push({ ...base, key: `${p.member}|direct|${r.role}|${r.resource}`, target: { kind: r.resourceType, id: null, member: null, label: at.label, project: r.project || null, env: envOf.get(r.project) || null, resource: r.resource },
        from, via: 'direct', member: p.member, memberKind: p.kind, principalId: p.id, label: p.origin?.label || pm.label, role: r.role, at, wide: false, conditional: !!r.condition, origin: p.origin || null,
        blocked: from === 'public' && blocked.has(r.resource) });
    }
  }
  const policy = await loadPolicy();
  for (const w of ways) { w.findings = wayFindings(w, { policy, keyRotateDays: config.risk.keyRotateDays }); w.worst = worstOf(w.findings.filter((x) => x.severity !== 'info')); }
  return ways;
}

const lc = (s) => String(s ?? '').toLowerCase();
/** The Trust page's Google Cloud view: the ways in that match, counts, and the outside sources rolled up. */
export async function gcpTrust(q = {}) {
  const all = await gcpWays();
  const list = (v) => (v ? String(v).split(',').filter(Boolean) : []);
  const from = list(q.from), sev = list(q.severity), via = list(q.via), conns = list(q.connection), projs = list(q.project);
  const text = lc(q.q).trim();
  const keep = (w, skip) => (skip === 'from' || !from.length || from.includes(w.from)) && (skip === 'severity' || !sev.length || sev.includes(w.worst))
    && (!via.length || via.includes(w.via)) && (!conns.length || conns.includes(w.connectionId)) && (!projs.length || projs.includes(w.target.project))
    && (!q.attention || ['high', 'medium'].includes(w.worst))
    && (!text || [w.label, w.member, w.target.label, w.role, w.origin?.label, ...w.findings.map((f) => f.title)].some((x) => lc(x).includes(text)));
  const ways = all.filter((w) => keep(w));
  const order = q.sort === 'target' ? (a, b) => a.target.label.localeCompare(b.target.label) : q.sort === 'source' ? (a, b) => lc(a.label).localeCompare(lc(b.label))
    : (a, b) => SEV[a.worst] - SEV[b.worst] || a.target.label.localeCompare(b.target.label);
  ways.sort(order);
  const count = (skip, key) => all.filter((w) => keep(w, skip)).reduce((m, w) => { m[w[key]] = (m[w[key]] || 0) + 1; return m; }, {});
  // the outside sources: one row per identity that comes in, with everything it reaches
  const by = new Map();
  for (const w of ways) {
    if (w.from === 'org' || w.from === 'key' || w.from === 'deleted') continue;
    const k = w.member || w.label;
    if (!by.has(k)) by.set(k, { key: k, label: w.label, from: w.from, member: w.member, origin: w.origin, awsRoleId: w.awsRoleId || null, worst: 'none', targets: new Set(), serviceAccounts: new Set(), projects: new Set(), vias: new Set() });
    const s = by.get(k);
    if (SEV[w.worst] < SEV[s.worst]) s.worst = w.worst;
    s.targets.add(w.target.label); s.vias.add(w.via);
    if (w.target.kind === 'serviceAccount') s.serviceAccounts.add(w.target.label); else s.projects.add(w.target.label);
  }
  const sources = [...by.values()].map((s) => ({ ...s, targets: s.targets.size, serviceAccounts: [...s.serviceAccounts], projects: [...s.projects], vias: [...s.vias] }))
    .sort((a, b) => SEV[a.worst] - SEV[b.worst] || b.targets - a.targets);
  const size = Math.min(200, Math.max(1, Number(q.size) || 50)), page = Math.max(0, Number(q.page) || 0);
  const items = q.all ? ways : ways.slice(page * size, (page + 1) * size);
  const [connections, projects] = await Promise.all([
    query(`SELECT id, name, last_scan_at FROM gcp_connections ORDER BY name`).then((r) => r.rows),
    query(`SELECT DISTINCT project_id, name FROM gcp_projects ORDER BY project_id`).then((r) => r.rows),
  ]);
  return {
    total: ways.length, page, size, items, sources,
    counts: { from: count('from', 'from'), severity: count('severity', 'worst'), attention: all.filter((w) => ['high', 'medium'].includes(w.worst)).length, all: all.length,
      serviceAccounts: new Set(all.filter((w) => w.target.kind === 'serviceAccount').map((w) => w.target.member)).size },
    labels: { from: FROM, via: VIA }, connections, projects,
  };
}

export async function gcpTrustCsv(q) {
  const all = (await gcpTrust({ ...q, all: true })).items;
  const cols = [['Severity', (w) => (w.worst === 'none' ? '' : w.worst)], ['Way in to', (w) => w.target.label], ['Target kind', (w) => w.target.kind], ['Project', (w) => w.target.project],
    ['From', (w) => FROM[w.from]], ['Identity', (w) => w.label], ['Member', (w) => w.member], ['How', (w) => VIA[w.via] || w.via], ['Role', (w) => w.role], ['Granted on', (w) => w.at?.label],
    ['Findings', (w) => w.findings.filter((f) => f.severity !== 'info').map((f) => f.title).join('; ')], ['Connection', (w) => w.connection]];
  return rowsToCsv(cols, all);
}
