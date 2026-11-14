import { keyRules } from '../config.js';
import { query, tx, pool } from '../db.js';
import { analyze } from '../analyzer/analyze.js';
import { matchTrust } from '../analyzer/trust.js';
import { loadMappings, translate, applyBuiltins } from '../analyzer/mappings.js';
import { COMPANIONS } from '../analyzer/actionNames.js';
import { snapshotAndDiff } from '../radarHistory.js';
import { accountComplete } from '../history.js';
import { userFindings, withUserRisk } from '../analyzer/users.js';

const DAY = 864e5;

export async function analyzeRole(role, windowStart, now = new Date(), maps = null) {
  maps = maps || await loadMappings();
  const [pol, act, prin, pass, adv, boundary] = await Promise.all([
    query('SELECT name, kind, document FROM role_policies WHERE role_id=$1', [role.id]),
    query('SELECT action, sum(count)::int AS count, max(day) AS last FROM activity_daily WHERE role_id=$1 GROUP BY action HAVING sum(count) > 0', [role.id]),
    query('SELECT key, kind, display, via, caller FROM principals WHERE role_id=$1', [role.id]),
    query('SELECT passed_role_arn AS arn, service, count FROM passrole_observed WHERE role_id=$1', [role.id]),
    query('SELECT service_namespace AS service, last_authenticated AS "lastAuthenticated" FROM advisor_services WHERE role_id=$1', [role.id]),
    role.boundary_arn ? query('SELECT document FROM managed_policy_cache WHERE arn=$1 ORDER BY fetched_at DESC LIMIT 1', [role.boundary_arn]) : { rows: [] },
  ]);
  const principals = prin.rows.map((p) => ({ ...p, trust: p.caller?.trust || matchTrust(role.trust_policy, p.caller || {}, p.via) }));
  const actions = new Map(), unmappedServices = new Map();
  for (const r of act.rows) {
    const t = translate(r.action, maps);
    if (t.none) continue;
    if (t.unmapped) { const u = unmappedServices.get(t.unmapped) || []; u.push(r.action); unmappedServices.set(t.unmapped, u); continue; }
    for (const a of [t.action, ...(COMPANIONS[t.action] || [])]) {
      const prev = actions.get(a);
      actions.set(a, prev ? { count: prev.count + r.count, lastSeen: prev.lastSeen > r.last ? prev.lastSeen : r.last } : { count: r.count, lastSeen: r.last });
    }
  }
  const out = analyze({
    role, policies: pol.rows, boundaryDoc: boundary.rows[0]?.document || null, windowStart, now,
    activity: { actions, unmappedServices, passroles: pass.rows, principals },
    advisor: adv.rows,
  });
  if (role.kind !== 'iam-user') return out;
  // an IAM user's credentials count as much as its permissions
  const [d, k] = await Promise.all([query('SELECT * FROM iam_user_details WHERE role_id=$1', [role.id]), query('SELECT * FROM iam_access_keys WHERE role_id=$1', [role.id])]);
  return withUserRisk(out, userFindings({ details: d.rows[0], keys: k.rows, now: now.getTime(), rules: keyRules() }));
}

/** Stores one analysis. With `recordRisk`, a change of risk level from the last analysis goes to the identity's history. */
export async function persistAnalysis(roleId, r, { recordRisk = false } = {}) {
  await tx(async (c) => {
    // a role's first analysis has no previous level (the column's default is not one)
    const before = recordRisk ? (await c.query('SELECT risk FROM roles WHERE id=$1 AND analyzed_at IS NOT NULL', [roleId])).rows[0]?.risk : null;
    await c.query('DELETE FROM role_actions WHERE role_id=$1', [roleId]);
    const A = r.actions;
    const CH = 5000;
    for (let i = 0; i < A.length; i += CH) {
      const s = A.slice(i, i + CH);
      await c.query(
        `INSERT INTO role_actions(role_id, action, status, reason, access_level, event_count, last_seen)
         SELECT $1, a, st, rs, lv, n, ls::date FROM unnest($2::text[], $3::text[], $4::text[], $5::text[], $6::int[], $7::text[]) AS t(a, st, rs, lv, n, ls)`,
        [roleId, s.map((x) => x.action), s.map((x) => x.status), s.map((x) => x.reason), s.map((x) => x.level), s.map((x) => x.count), s.map((x) => x.lastSeen ? String(x.lastSeen).slice(0, 10) : null)]);
    }
    const keep = [];
    for (const f of r.flags) {
      const row = (await c.query(
        `INSERT INTO flags(role_id, category, key, title, actions, resources, reason, evidence, suggestion, suggested_resources, severity, status, updated_at)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,'open',now())
         ON CONFLICT (role_id, category, key) DO UPDATE SET title=EXCLUDED.title, actions=EXCLUDED.actions, resources=EXCLUDED.resources, reason=EXCLUDED.reason,
           evidence=EXCLUDED.evidence, suggestion=EXCLUDED.suggestion, severity=EXCLUDED.severity, status='open', updated_at=now()
         RETURNING id`,
        [roleId, f.category, f.key, f.title, f.actions, f.resources, f.reason, f.evidence, f.suggestion, f.suggestedResources, f.severity])).rows[0];
      keep.push(row.id);
    }
    await c.query(`UPDATE flags SET status='resolved', updated_at=now() WHERE role_id=$1 AND status='open' AND NOT (id = ANY($2))`, [roleId, keep]);
    await c.query(
      `UPDATE roles SET granted_count=$2, used_count=$3, unused_count=$4, unconfirmed_count=$5, risk=$6, risk_score=$7, risk_reasons=$8,
              reviewer_team=$9, requires_both=$10, analysis_hash=$11, analyzed_at=now(),
              last_activity_at=(SELECT max(day) FROM activity_daily WHERE role_id=$1 AND count>0)
        WHERE id=$1`,
      [roleId, r.counts.granted, r.counts.used, r.counts.unused, r.counts.unconfirmed, r.risk, r.riskScore, JSON.stringify(r.riskReasons), r.reviewerTeam, r.requiresBoth, r.analysisHash]);
    if (before && before !== r.risk) {
      const RANK = { Low: 0, Medium: 1, High: 2 };
      await c.query(`INSERT INTO identity_events(role_id, kind, title, detail) VALUES ($1,'risk',$2,$3)`,
        [roleId, `Risk ${RANK[r.risk] > RANK[before] ? 'rose' : 'fell'}: ${before} → ${r.risk}`, JSON.stringify({ from: before, to: r.risk, reasons: r.riskReasons.slice(0, 5) })]);
    }
  });
}

/** Analyze every role of an account from what is stored now. Used by the final stage and, provisionally, while reading. */
export async function analyzeAccount(accountId, { alive = () => {}, progress = async () => {} } = {}) {
  const roles = (await query('SELECT * FROM roles WHERE account_id=$1 AND deleted_at IS NULL', [accountId])).rows;
  // The oldest event we hold is the edge of what "unused" can honestly mean.
  const cp = (await query('SELECT min(first_event_time) AS t FROM scan_checkpoints WHERE account_id=$1', [accountId])).rows[0];
  const windowStart = cp.t ? new Date(cp.t) : new Date(Date.now() - 90 * DAY);
  await applyBuiltins();                 // names learned by a newer version settle before history is credited
  const maps = await loadMappings();
  // while history is still being read, results are provisional and the risk level can swing: only record it once complete
  const recordRisk = await accountComplete(accountId);
  let done = 0;
  for (const role of roles) {
    alive();
    await persistAnalysis(role.id, await analyzeRole(role, windowStart, new Date(), maps), { recordRisk });
    await progress({ phase: 'analyze', done: ++done, total: roles.length });
  }
  return { roles: roles.length };
}

export async function runAnalyze(ctx) {
  // a catch-up read that found nothing new has nothing to recompute
  const run = (await query(`SELECT r.trigger, (SELECT coalesce(sum((j.progress->>'events')::int), 0) FROM scan_jobs j WHERE j.run_id = r.id AND j.kind = 'events')::int AS events
                              FROM scan_runs r WHERE r.id = $1`, [ctx.job.run_id])).rows[0];
  if (run?.trigger === 'tail' && !run.events) return { skipped: 'no new events' };
  const out = await analyzeAccount(ctx.job.account_id, { alive: ctx.alive, progress: ctx.progress });
  // the final analysis of a fully read account: record what changed since the last one, and where things stand today
  if (run?.trigger !== 'tail' && await accountComplete(ctx.job.account_id)) out.changes = await snapshotAndDiff(ctx.job.account_id);
  return out;
}

/**
 * While history is still being read, refresh results now and then so the portal shows what is known so far.
 * One at a time per account (the regions of an account read in parallel); skipped if another is running.
 */
export async function provisionalAnalyze(accountId, log = () => {}) {
  const c = await pool.connect();
  try {
    const got = (await c.query('SELECT pg_try_advisory_lock(727200, hashtext($1)) AS ok', [accountId])).rows[0].ok;
    if (!got) return false;
    try { await analyzeAccount(accountId); log('provisional results refreshed'); return true; }
    finally { await c.query('SELECT pg_advisory_unlock(727200, hashtext($1))', [accountId]); }
  } finally { c.release(); }
}
