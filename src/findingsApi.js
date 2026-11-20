// The Findings inbox: every open finding across the roles and IAM users a member can see, and Google Cloud ways in
// (Trust map findings with a gcp_subject instead of a role; shown to members not limited to some AWS accounts), in one list,
// and decisions on many of them at once. Findings are the `flags` rows the analyzer writes; a decision is a
// `review_decisions` row, the same one the role page writes.
import { z } from 'zod';
import { query, tx } from './db.js';
import { inScope, scopeSql } from './auth/rbac.js';

/** Findings about one action or service take keep/remove decisions; the rest (wildcards, trust, idle roles) accept/investigate. */
export const ACTION_CATS = new Set(['data-event', 'authorization-only', 'not-logged', 'before-window', 'service-unknown', 'unmapped-event']);
export const DECISIONS = ['keep_scoped', 'keep', 'remove', 'accept', 'investigate'];
export const allowedFor = (category) => (ACTION_CATS.has(category) ? ['keep_scoped', 'keep', 'remove'] : ['accept', 'investigate']);

const SEVERITIES = ['high', 'medium', 'low'];
const uuid = z.string().uuid();
const list = (v) => (v ? String(v).split(',').map((x) => x.trim()).filter(Boolean) : []);

/**
 * WHERE clauses for the inbox. `skip` leaves one filter out, so a facet can count what that filter would show.
 * Filters: severity, category, accounts, who (roles|users), state (open|decided|all), mine, q.
 */
function whereFor(user, q, params, skip = null) {
  const where = ["f.status = 'open'", LIVE, scopeSql(user, 'r.account_id', params)];
  const add = (sql, v) => { params.push(v); where.push(sql.replaceAll('?', `$${params.length}`)); };
  const sev = list(q.severity).filter((s) => SEVERITIES.includes(s));
  if (skip !== 'severity' && sev.length) add('f.severity = ANY(?)', sev);
  const cats = list(q.category);
  if (skip !== 'category' && cats.length) add('f.category = ANY(?)', cats);
  const ctl = list(q.control).filter((x) => /^[a-z0-9.-]{3,80}$/.test(x));
  if (ctl.length) add('f.control = ANY(?)', ctl);
  const accts = list(q.accounts).filter((x) => uuid.safeParse(x).success), projs = list(q.accounts).filter((x) => /^gcp:[a-z0-9-]+$/.test(x)).map((x) => x.slice(4));
  if (accts.length && projs.length) { params.push(accts); params.push(projs); where.push(`(r.account_id = ANY($${params.length - 1}::uuid[]) OR f.gcp_project = ANY($${params.length}))`); }
  else if (accts.length) add('r.account_id = ANY(?::uuid[])', accts);
  else if (projs.length) add('f.gcp_project = ANY(?)', projs);
  if (q.cloud === 'aws') where.push('f.role_id IS NOT NULL');
  if (q.cloud === 'gcp') where.push('f.gcp_subject IS NOT NULL');
  if (q.who === 'roles') where.push("(f.gcp_subject IS NOT NULL OR r.kind <> 'iam-user')");
  if (q.who === 'users') where.push("r.kind = 'iam-user'");
  const state = ['decided', 'all'].includes(q.state) ? q.state : 'open';
  if (state === 'open') where.push('d.id IS NULL');
  if (state === 'decided') where.push('d.id IS NOT NULL');
  // "Mine": what the member's review team signs off, including roles both teams must review
  if (q.mine === '1' && user.team) add('(r.reviewer_team = ? OR r.requires_both)', user.team);
  if (q.q) {
    const like = `%${String(q.q).slice(0, 100).replace(/[\\%_]/g, (c) => `\\${c}`)}%`;
    add('(r.name ILIKE ? OR r.arn ILIKE ? OR f.title ILIKE ? OR a.name ILIKE ? OR a.account_id ILIKE ? OR f.gcp_label ILIKE ? OR f.gcp_project ILIKE ?)', like);
  }
  return where.join(' AND ');
}
const FROM = 'flags f LEFT JOIN roles r ON r.id = f.role_id LEFT JOIN cloud_accounts a ON a.id = r.account_id LEFT JOIN review_decisions d ON d.flag_id = f.id';
// a finding about an AWS role that is not deleted, or about Google Cloud
const LIVE = '(f.gcp_subject IS NOT NULL OR (r.id IS NOT NULL AND r.deleted_at IS NULL))';
const SEV_ORDER = "CASE f.severity WHEN 'high' THEN 0 WHEN 'medium' THEN 1 ELSE 2 END";
const SORTS = {
  severity: `${SEV_ORDER}, r.risk_score DESC NULLS LAST, r.name, f.category, f.key`,
  role: `coalesce(r.name, f.gcp_label), coalesce(a.name, f.gcp_project), ${SEV_ORDER}, f.category, f.key`,
  newest: `f.created_at DESC, ${SEV_ORDER}, coalesce(r.name, f.gcp_label)`,
};

/** One page of findings, plus counts by severity and by category under the other filters. */
export async function listFindings(user, q) {
  const p = [];
  const where = whereFor(user, q, p);
  const limit = Math.min(Math.max(Number(q.limit) || 50, 1), 200), page = Math.max(Number(q.page) || 1, 1);
  const order = SORTS[q.sort] || SORTS.severity;
  const sp = [], cp = [], tp = [];
  const [rows, bySev, byCat, totals] = await Promise.all([
    query(`
      SELECT f.id, f.category, f.key, f.control, f.title, f.severity, f.reason, f.evidence, f.suggestion, f.created_at,
             f.actions[1:41] AS actions, cardinality(f.actions)::int AS action_count,
             f.resources[1:5] AS resources, cardinality(f.resources)::int AS resource_count, f.suggested_resources,
             r.id AS role_id, coalesce(r.name, f.gcp_label) AS role_name, coalesce(r.kind, 'gcp') AS role_kind, coalesce(r.risk, gp.risk) AS role_risk, r.reviewer_team, r.requires_both,
             coalesce(a.id::text, 'gcp:' || f.gcp_project) AS account_id, coalesce(a.name, f.gcp_project) AS account_name, coalesce(a.account_id, f.gcp_project) AS aws_account_id,
             coalesce(a.environment, gp.environment) AS environment, CASE WHEN f.gcp_subject IS NULL THEN 'aws' ELSE 'gcp' END AS cloud, f.gcp_subject, gp.id AS gcp_principal_id,
             d.decision, d.note, d.resources AS decided_resources, d.decided_at, d.team AS decided_team, u.name AS decided_by,
             count(*) OVER()::int AS total
        FROM ${FROM} LEFT JOIN users u ON u.id = d.decided_by
        -- the Google Cloud identity a finding is about, for its link (ids change at each scan; the member does not)
        LEFT JOIN LATERAL (SELECT p.id, p.risk, coalesce(pr.environment, pr.labels->>'env') AS environment FROM gcp_principals p LEFT JOIN gcp_projects pr ON pr.project_id = f.gcp_project
                            WHERE f.gcp_subject LIKE 'gcp:serviceAccount:%' AND p.member = substring(f.gcp_subject from 5) LIMIT 1) gp ON true
       WHERE ${where} ORDER BY ${order} LIMIT ${limit} OFFSET ${(page - 1) * limit}`, p),
    query(`SELECT f.severity AS k, count(*)::int n FROM ${FROM} WHERE ${whereFor(user, q, sp, 'severity')} GROUP BY 1`, sp),
    query(`SELECT f.category AS k, count(*)::int n FROM ${FROM} WHERE ${whereFor(user, q, cp, 'category')} GROUP BY 1 ORDER BY 2 DESC`, cp),
    // the same scope with no filters: what the page title says is waiting overall
    query(`SELECT count(*) FILTER (WHERE d.id IS NULL)::int open, count(*) FILTER (WHERE d.id IS NULL AND f.severity = 'high')::int high
             FROM ${FROM} WHERE f.status = 'open' AND ${LIVE} AND ${scopeSql(user, 'r.account_id', tp)}`, tp),
  ]);
  return {
    items: rows.rows.map(({ total, ...x }) => ({ ...x, allowed: allowedFor(x.category) })),
    total: rows.rows[0]?.total ?? 0, page, limit,
    severity: Object.fromEntries(SEVERITIES.map((s) => [s, bySev.rows.find((x) => x.k === s)?.n ?? 0])),
    categories: byCat.rows.map((x) => ({ category: x.k, n: x.n })),
    waiting: totals.rows[0],
  };
}

/** Open findings with no decision yet, in the member's scope: the count on the rail. */
export async function waitingCount(user) {
  const p = [];
  const r = await query(`SELECT count(*)::int n FROM ${FROM} WHERE f.status = 'open' AND d.id IS NULL AND ${LIVE} AND ${scopeSql(user, 'r.account_id', p)}`, p);
  return r.rows[0].n;
}

export const BulkIn = z.object({
  ids: z.array(uuid).min(1).max(200),
  decision: z.enum(DECISIONS),
  note: z.string().trim().max(1000).optional(),
  resources: z.array(z.string().min(1).max(500)).max(50).optional(),
});

export class DecisionError extends Error { constructor(status, code, message) { super(message); this.status = status; this.code = code; } }

/**
 * One decision on many findings, all or nothing. Every finding must be open, on a role the member can see, and of a
 * kind that takes this decision; otherwise nothing is written and the error says which part failed.
 * Returns the findings decided (with their roles), for the audit log.
 */
export async function decideMany(user, body) {
  const b = BulkIn.parse(body);
  const ids = [...new Set(b.ids)];
  if (b.resources?.length && b.decision !== 'keep_scoped') throw new DecisionError(400, 'invalid', 'Resources narrow a "Keep, scoped" decision only.');
  return tx(async (c) => {
    const found = (await c.query(`SELECT f.id, f.category, f.key, f.status, r.id AS role_id, coalesce(r.name, f.gcp_label) AS role_name, r.account_id, r.deleted_at, f.gcp_subject
                                    FROM flags f LEFT JOIN roles r ON r.id = f.role_id WHERE f.id = ANY($1::uuid[]) FOR UPDATE OF f`, [ids])).rows;
    // a finding outside the member's accounts is reported as missing, as everywhere else (existence is not revealed);
    // Google Cloud is for members not limited to some AWS accounts
    const visible = (f) => (f.gcp_subject ? !user.scope_accounts : !!f.role_id && inScope(user, f.account_id) && !f.deleted_at);
    const seen = found.filter(visible);
    if (seen.length !== ids.length) throw new DecisionError(404, 'not_found', `${ids.length - seen.length} of the selected findings no longer exist. Reload the list and try again.`);
    const closed = seen.filter((f) => f.status !== 'open');
    if (closed.length) throw new DecisionError(409, 'resolved', `${closed.length} of the selected findings were resolved by a newer scan. Reload the list and try again.`);
    const wrong = seen.filter((f) => !allowedFor(f.category).includes(b.decision));
    if (wrong.length) {
      const fits = ACTION_CATS.has(wrong[0].category) ? 'Keep, scoped / Keep / Remove' : 'Accept / Investigate';
      throw new DecisionError(400, 'bad_decision', `${wrong.length} of the selected findings cannot take this decision (they take ${fits}). Select findings of one kind, or decide them separately.`);
    }
    await c.query(
      `INSERT INTO review_decisions(flag_id, role_id, decision, resources, note, decided_by, team, decided_at)
       SELECT x.flag_id, x.role_id, $3, $4, $5, $6, $7, now() FROM unnest($1::uuid[], $2::uuid[]) AS x(flag_id, role_id)
       ON CONFLICT (flag_id) DO UPDATE SET decision=EXCLUDED.decision, resources=EXCLUDED.resources, note=EXCLUDED.note,
         decided_by=EXCLUDED.decided_by, team=EXCLUDED.team, decided_at=now()`,
      [seen.map((f) => f.id), seen.map((f) => f.role_id), b.decision, b.resources?.length ? b.resources : null, b.note || null, user.id, user.team ?? null]);
    return { decision: b.decision, flags: seen };
  });
}

/** Clears the decisions on many findings, so they wait again. Same scope rules as deciding. */
export async function undecideMany(user, body) {
  const { ids } = z.object({ ids: z.array(uuid).min(1).max(200) }).parse(body);
  const found = (await query(`SELECT f.id, f.category, f.key, coalesce(r.name, f.gcp_label) AS role_name, r.account_id, r.deleted_at, f.gcp_subject FROM flags f LEFT JOIN roles r ON r.id = f.role_id WHERE f.id = ANY($1::uuid[])`, [[...new Set(ids)]])).rows
    .filter((f) => (f.gcp_subject ? !user.scope_accounts : inScope(user, f.account_id) && !f.deleted_at));
  if (found.length !== new Set(ids).size) throw new DecisionError(404, 'not_found', 'Some of the selected findings no longer exist. Reload the list and try again.');
  await query('DELETE FROM review_decisions WHERE flag_id = ANY($1::uuid[])', [found.map((f) => f.id)]);
  return found;
}
