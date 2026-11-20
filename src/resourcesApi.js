// Resource access: the list of resources with resource-based policies, one resource with who it lets in, and the
// reviewer's call on each finding (expected, or investigate). What is stored comes from resourceSync.js.
import { z } from 'zod';
import { query } from './db.js';
import { inScope, scopeSql } from './auth/rbac.js';
import { SERVICES, EXPOSURE, REACH } from './analyzer/resourcePolicy.js';
import { toCsv } from './csv.js';
import { GCP_SERVICES } from './gcp/resources.js';

// every type of resource, both clouds
const ALL_SERVICES = { ...Object.fromEntries(Object.entries(SERVICES).map(([k, v]) => [k, { ...v, cloud: 'aws' }])), ...GCP_SERVICES };

const uuid = z.string().uuid();
const list = (v) => (v ? String(v).split(',').map((x) => x.trim()).filter(Boolean) : []);
const SEVERITIES = ['high', 'medium', 'low'];
// what "shared" means on the page: anything beyond the resource's own account
export const SHARED = ['public', 'external', 'cross-account', 'service'];
const SEV_ORDER = "CASE r.worst WHEN 'high' THEN 0 WHEN 'medium' THEN 1 WHEN 'low' THEN 2 ELSE 3 END";
const EXP_ORDER = "CASE r.exposure WHEN 'public' THEN 0 WHEN 'external' THEN 1 WHEN 'cross-account' THEN 2 WHEN 'service' THEN 3 WHEN 'private' THEN 4 ELSE 5 END";
const SORTS = {
  risk: `${SEV_ORDER}, ${EXP_ORDER}, r.name`,
  name: 'lower(r.name), a.name',
  account: `a.name, ${SEV_ORDER}, lower(r.name)`,
  changed: `r.policy_changed_at DESC NULLS LAST, ${SEV_ORDER}, lower(r.name)`,
};
// open findings a reviewer has not called "expected": what needs attention
const ATTENTION = `EXISTS (SELECT 1 FROM resource_findings f WHERE f.resource_id = r.id AND f.status = 'open' AND f.severity IN ('high','medium') AND f.decision IS DISTINCT FROM 'expected')`;

/**
 * WHERE for the list. `skip` leaves one filter out so its facet counts what picking it would show.
 * Filters: q, accounts, service, exposure (default: shared beyond the account; `all` for every resource), severity,
 * control, state (attention | open | expected | all).
 */
function whereFor(user, q, params, skip = null) {
  const where = ['r.deleted_at IS NULL', scopeSql(user, 'r.account_id', params)];
  const add = (sql, v) => { params.push(v); where.push(sql.replaceAll('?', `$${params.length}`)); };
  const accts = list(q.accounts).filter((x) => uuid.safeParse(x).success);
  if (accts.length) add('r.account_id = ANY(?::uuid[])', accts);
  const svc = list(q.service).filter((s) => ALL_SERVICES[s]);
  if (q.cloud === 'aws' || q.cloud === 'gcp') add('r.cloud = ?', q.cloud);
  const conns = list(q.connections).filter((x) => uuid.safeParse(x).success);
  if (conns.length) add('r.gcp_connection_id = ANY(?::uuid[])', conns);
  if (skip !== 'service' && svc.length) add('r.service = ANY(?)', svc);
  const exp = q.exposure === 'all' ? [] : list(q.exposure || SHARED.join(',')).filter((e) => EXPOSURE[e]);
  if (skip !== 'exposure' && exp.length) add('r.exposure = ANY(?)', exp);
  const sev = list(q.severity).filter((s) => SEVERITIES.includes(s));
  if (skip !== 'severity' && sev.length) add('r.worst = ANY(?)', sev);
  const ctl = list(q.control).filter((x) => /^res\.[a-z-]{3,60}$/.test(x));
  if (ctl.length) add(`EXISTS (SELECT 1 FROM resource_findings f WHERE f.resource_id = r.id AND f.status = 'open' AND f.control = ANY(?))`, ctl);
  if (q.state === 'attention') where.push(ATTENTION);
  if (q.state === 'open') where.push(`r.worst IS NOT NULL`);
  if (q.state === 'expected') where.push(`EXISTS (SELECT 1 FROM resource_findings f WHERE f.resource_id = r.id AND f.status = 'open' AND f.decision = 'expected')`);
  if (q.q) {
    const like = `%${String(q.q).slice(0, 100).replace(/[\\%_]/g, (c) => `\\${c}`)}%`;
    add(`(r.name ILIKE ? OR r.arn ILIKE ? OR a.name ILIKE ? OR a.account_id ILIKE ? OR g.name ILIKE ? OR r.project_id ILIKE ?
          OR EXISTS (SELECT 1 FROM resource_findings f WHERE f.resource_id = r.id AND f.status = 'open' AND (f.principal ILIKE ? OR f.title ILIKE ?)))`, like);
  }
  return where.join(' AND ');
}
// a resource belongs to an AWS account, or to a Google Cloud connection (and a project in it)
const FROM = 'resources r LEFT JOIN cloud_accounts a ON a.id = r.account_id LEFT JOIN gcp_connections g ON g.id = r.gcp_connection_id';
const OWNER = `coalesce(a.name, g.name) AS account_name, coalesce(a.account_id, r.project_id) AS aws_account_id, coalesce(a.environment, NULL) AS environment`;

/** One page of resources, with counts by exposure, service and severity under the other filters. */
export async function listResources(user, q = {}) {
  const limit = Math.min(200, Math.max(1, Number(q.limit) || 50));
  const page = Math.max(1, Number(q.page) || 1);
  const sort = SORTS[q.sort] ? q.sort : 'risk';
  const p = [], ep = [], sp = [], vp = [], ap = [];
  const [rows, byExp, bySvc, bySev, att] = await Promise.all([
    query(`SELECT r.id, r.service, r.arn, r.name, r.region, r.exposure, r.worst, r.policy_changed_at, r.seen_at, r.extra ? 'unreadable' AS unreadable,
                  r.cloud, r.project_id, r.gcp_connection_id, a.id AS account_id, ${OWNER},
                  (SELECT count(*)::int FROM resource_findings f WHERE f.resource_id = r.id AND f.status = 'open') AS open,
                  (SELECT count(*)::int FROM resource_findings f WHERE f.resource_id = r.id AND f.status = 'open' AND f.decision = 'expected') AS expected,
                  (SELECT array_agg(DISTINCT f.control) FROM resource_findings f WHERE f.resource_id = r.id AND f.status = 'open') AS controls,
                  (SELECT count(*)::int FROM jsonb_array_elements(r.grants) g WHERE g->>'reach' <> 'same') AS outside,
                  count(*) OVER()::int AS total
             FROM ${FROM} WHERE ${whereFor(user, q, p)} ORDER BY ${SORTS[sort]} LIMIT ${limit} OFFSET ${(page - 1) * limit}`, p),
    query(`SELECT r.exposure AS k, count(*)::int n FROM ${FROM} WHERE ${whereFor(user, q, ep, 'exposure')} GROUP BY 1`, ep),
    query(`SELECT r.service AS k, count(*)::int n FROM ${FROM} WHERE ${whereFor(user, q, sp, 'service')} GROUP BY 1 ORDER BY 2 DESC`, sp),
    query(`SELECT r.worst AS k, count(*)::int n FROM ${FROM} WHERE ${whereFor(user, q, vp, 'severity')} AND r.worst IS NOT NULL GROUP BY 1`, vp),
    query(`SELECT count(*)::int n FROM ${FROM} WHERE r.deleted_at IS NULL AND ${scopeSql(user, 'r.account_id', ap)} AND ${ATTENTION}`, ap),
  ]);
  const count = (r) => Object.fromEntries(r.rows.map((x) => [x.k, x.n]));
  return {
    items: rows.rows.map(({ total, ...x }) => ({ ...x, controls: x.controls || [] })), total: rows.rows[0]?.total ?? 0, page, limit,
    exposure: count(byExp), services: count(bySvc), severity: count(bySev), attention: att.rows[0].n,
    labels: { exposure: EXPOSURE, services: Object.fromEntries(Object.entries(ALL_SERVICES).map(([k, v]) => [k, v.label])), clouds: { aws: 'AWS', gcp: 'Google Cloud' } },
    gcp: (await query(`SELECT count(*)::int n FROM resources WHERE cloud = 'gcp'`)).rows[0].n > 0,
  };
}

const NotFound = () => Object.assign(new Error('Not found'), { status: 404 });

/** One resource: its policy, who each statement lets in, its findings (open, and the last resolved ones). */
export async function resourceDetail(user, id) {
  const r = (await query(`SELECT r.*, ${OWNER} FROM ${FROM} WHERE r.id = $1`, [uuid.parse(id)])).rows[0];
  // Google Cloud is not visible to members limited to some AWS accounts
  if (!r || (r.cloud === 'gcp' ? !!user.scope_accounts : !inScope(user, r.account_id))) throw NotFound();
  const f = (await query(`SELECT f.*, u.name AS decided_by_name FROM resource_findings f LEFT JOIN users u ON u.id = f.decided_by
                           WHERE f.resource_id = $1 AND (f.status = 'open' OR f.resolved_at > now() - interval '30 days')
                           ORDER BY f.status, CASE f.severity WHEN 'high' THEN 0 WHEN 'medium' THEN 1 ELSE 2 END, f.statement`, [r.id])).rows;
  const { extra, ...rest } = r;
  return { ...rest, extra, label: ALL_SERVICES[r.service]?.label || r.service, exposureLabel: EXPOSURE[r.exposure], reachOrder: REACH,
    findings: f.map((x) => ({ ...x, decided_by: x.decided_by_name || null, decided_by_name: undefined })) };
}

export class DecisionError extends Error { constructor(status, message) { super(message); this.status = status; } }
export const DecisionIn = z.object({ decision: z.enum(['expected', 'investigate']), note: z.string().trim().max(1000).optional() })
  .refine((b) => b.decision !== 'expected' || (b.note && b.note.length >= 3), { message: 'Say why it is expected (a note of a few words), so the next reviewer knows.', path: ['note'] });

async function findingFor(user, id) {
  const f = (await query(`SELECT f.id, f.title, f.control, f.status, r.id AS resource_id, r.name AS resource_name, r.account_id, r.cloud
                            FROM resource_findings f JOIN resources r ON r.id = f.resource_id WHERE f.id = $1`, [uuid.parse(id)])).rows[0];
  if (!f || (f.cloud === 'gcp' ? !!user.scope_accounts : !inScope(user, f.account_id))) throw NotFound();
  return f;
}
export async function decide(user, id, body) {
  const b = DecisionIn.parse(body);
  const f = await findingFor(user, id);
  if (f.status !== 'open') throw new DecisionError(409, 'This finding is resolved: the policy no longer grants it.');
  await query(`UPDATE resource_findings SET decision = $2, note = $3, decided_by = $4, decided_at = now() WHERE id = $1`, [f.id, b.decision, b.note || null, user.id]);
  return { finding: f, decision: b.decision, note: b.note || null };
}
export async function undecide(user, id) {
  const f = await findingFor(user, id);
  await query(`UPDATE resource_findings SET decision = NULL, note = NULL, decided_by = NULL, decided_at = NULL WHERE id = $1`, [f.id]);
  return { finding: f };
}

/** Every open finding on the resources the filters show, one row each (a resource with none gets one row). */
export async function resourcesCsv(user, q) {
  const p = [];
  const rows = (await query(
    `SELECT r.service, r.name, r.arn, r.region, r.exposure, r.cloud, ${OWNER}, r.policy_changed_at,
            f.severity, f.control, f.title, f.principal, f.principal_account, f.actions, f.conditions, f.decision, f.note
       FROM ${FROM} LEFT JOIN resource_findings f ON f.resource_id = r.id AND f.status = 'open'
      WHERE ${whereFor(user, q, p)} ORDER BY ${SORTS.risk}, CASE f.severity WHEN 'high' THEN 0 WHEN 'medium' THEN 1 ELSE 2 END LIMIT 50000`, p)).rows;
  return toCsv([
    ['Cloud', (x) => (x.cloud === 'gcp' ? 'Google Cloud' : 'AWS')], ['Account', (x) => x.account_name], ['Account ID', (x) => x.aws_account_id], ['Environment', (x) => x.environment],
    ['Type', (x) => ALL_SERVICES[x.service]?.label || x.service], ['Name', (x) => x.name], ['ARN', (x) => x.arn], ['Region', (x) => x.region],
    ['Exposure', (x) => EXPOSURE[x.exposure]], ['Severity', (x) => x.severity], ['Finding', (x) => x.title], ['Control', (x) => x.control],
    ['Principal', (x) => x.principal], ['Principal account', (x) => x.principal_account], ['Actions', (x) => x.actions], ['Conditions', (x) => x.conditions],
    ['Decision', (x) => x.decision], ['Note', (x) => x.note], ['Policy changed', (x) => x.policy_changed_at],
  ], rows);
}
