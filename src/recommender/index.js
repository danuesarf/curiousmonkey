import { config } from '../config.js';
import { query, tx } from '../db.js';
import { computeGrants } from '../analyzer/grants.js';
import { rulesDraft } from './rules.js';
import { aiDraft, bedrockLlm } from './ai.js';
import { runChecks, hardFailures, awsValidate } from './checks.js';
import { draftStatements } from './checks.js';
import { expandAction, hasService } from '../analyzer/catalog.js';
import { hasWildcard } from '../analyzer/wildcard.js';

export class Refusal extends Error { constructor(msg, code = 400) { super(msg); this.status = code; } }

export async function loadRoleContext(roleId) {
  const role = (await query('SELECT r.*, a.name AS account_name, a.account_id AS aws_account_id FROM roles r JOIN cloud_accounts a ON a.id=r.account_id WHERE r.id=$1', [roleId])).rows[0];
  if (!role) throw new Refusal('role not found', 404);
  const [pol, acts, res, dec] = await Promise.all([
    query('SELECT name, kind, aws_managed, arn, document FROM role_policies WHERE role_id=$1 ORDER BY kind, name', [roleId]),
    query('SELECT action, status, reason, access_level AS level, event_count, last_seen FROM role_actions WHERE role_id=$1', [roleId]),
    query('SELECT action, resource FROM activity_resources WHERE role_id=$1', [roleId]),
    query(`SELECT f.actions, d.decision, d.resources FROM review_decisions d JOIN flags f ON f.id=d.flag_id WHERE d.role_id=$1 AND f.status='open'`, [roleId]),
  ]);
  const observed = new Map();
  for (const r of res.rows) { if (!observed.has(r.action)) observed.set(r.action, []); observed.get(r.action).push(r.resource); }
  const decisions = new Map();
  for (const d of dec.rows) for (const a of d.actions) decisions.set(a, { decision: d.decision, resources: d.resources });
  const boundary = role.boundary_arn ? (await query('SELECT document FROM managed_policy_cache WHERE arn=$1 ORDER BY fetched_at DESC LIMIT 1', [role.boundary_arn])).rows[0]?.document : null;
  return { role, policies: pol.rows, grants: computeGrants(pol.rows, { permissionsBoundary: boundary }), actions: acts.rows, observed, decisions, boundaryDoc: boundary };
}

function buildDiff(ctx, policies) {
  const kept = new Map();
  for (const st of draftStatements(policies)) {
    const resources = st.resources.length ? st.resources : ['*'];
    for (const a of st.actions.flatMap((x) => (hasWildcard(x) ? expandAction(x) : [x]))) kept.set(a, resources);
  }
  const removed = [], narrowed = [];
  for (const [a, g] of ctx.grants) {
    if (!kept.has(a)) { removed.push(a); continue; }
    const before = [...g.resources].sort().join('|'), after = [...kept.get(a)].sort().join('|');
    if (before !== after) narrowed.push({ action: a, from: [...g.resources], to: kept.get(a) });
  }
  const byService = {};
  for (const a of removed) { const s = a.split(':')[0]; byService[s] = (byService[s] || 0) + 1; }
  return { granted: ctx.grants.size, kept: kept.size, removedCount: removed.length, removedByService: byService,
    removedSample: removed.slice(0, 200), narrowed: narrowed.slice(0, 200), narrowedCount: narrowed.length };
}

const policyBase = (role) => `cm-${role.name.replace(/[^\w+=,.@-]/g, '-').slice(0, 40)}-least-privilege`;

export async function recommend(roleId, { instruction = null, userId = null, llm = undefined, validateFn = undefined } = {}) {
  const ctx = await loadRoleContext(roleId);
  if (ctx.role.kind === 'service-linked') throw new Refusal('Service-linked roles are managed by AWS and cannot be edited. They are reported only.', 409);
  if (!ctx.role.analyzed_at) throw new Refusal('This role has not been analysed yet', 409);
  const base = policyBase(ctx.role);
  const origin = { originalPolicies: ctx.policies, boundaryDoc: ctx.boundaryDoc, actions: ctx.actions, observed: ctx.observed, decisions: ctx.decisions };

  let draft = null, model = null, note = null;
  const useAi = llm !== null && (llm || config.ai.enabled);
  if (useAi) {
    const fn = llm || await bedrockLlm();
    const r = await aiDraft({ llm: fn, ctx, instruction, baseName: base, originalPolicies: ctx.policies, boundaryDoc: ctx.boundaryDoc });
    if (r.draft) { draft = r.draft; model = config.ai.modelId; }
    else note = `AI draft could not meet the safety checks after ${r.attempts} attempts (${r.error}); showing the rules-based draft instead.`;
  }
  if (!draft) { draft = rulesDraft(ctx, base); if (useAi) draft.source = 'rules-fallback'; }

  const checks = runChecks({ draftPolicies: draft.policies, ...origin });
  checks.push(await awsValidate(config.validateWithAws ? validateFn : null, draft.policies));
  const diff = buildDiff(ctx, draft.policies);
  const summary = [draft.summary, note].filter(Boolean).join(' ') || null;

  return tx(async (c) => {
    await c.query(`UPDATE recommendations SET status='superseded' WHERE role_id=$1 AND status='draft'`, [roleId]);
    const row = (await c.query(
      `INSERT INTO recommendations(role_id, source, model, policies, statements, diff, checks, summary, instruction, analysis_hash, created_by)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) RETURNING *`,
      [roleId, draft.source, model, JSON.stringify(draft.policies), JSON.stringify(draft.statements), JSON.stringify(diff), JSON.stringify(checks),
       summary, instruction, ctx.role.analysis_hash, userId])).rows[0];
    return row;
  });
}

export async function latestRecommendation(roleId) {
  const rec = (await query(`SELECT * FROM recommendations WHERE role_id=$1 AND status<>'superseded' ORDER BY created_at DESC LIMIT 1`, [roleId])).rows[0];
  if (!rec) return null;
  const role = (await query('SELECT analysis_hash, requires_both, reviewer_team FROM roles WHERE id=$1', [roleId])).rows[0];
  const approvals = (await query(`SELECT a.team, a.approved_at, u.name FROM recommendation_approvals a LEFT JOIN users u ON u.id=a.user_id WHERE recommendation_id=$1`, [rec.id])).rows;
  const required = role.requires_both ? ['infrasec', 'infosec'] : [role.reviewer_team];
  return { ...rec, stale: rec.analysis_hash !== role.analysis_hash, approvals, requiredTeams: required };
}

export async function approve(recId, user) {
  const rec = (await query('SELECT * FROM recommendations WHERE id=$1', [recId])).rows[0];
  if (!rec) throw new Refusal('recommendation not found', 404);
  const role = (await query('SELECT * FROM roles WHERE id=$1', [rec.role_id])).rows[0];
  if (rec.status !== 'draft') throw new Refusal(`This recommendation is ${rec.status}`, 409);
  if (rec.analysis_hash !== role.analysis_hash) throw new Refusal('The role changed after this draft was made. Regenerate it before approving.', 409);
  if (rec.checks.some((c) => c.status === 'fail')) throw new Refusal('This draft fails safety checks and cannot be approved. Regenerate or adjust it.', 409);
  if (!user.team) throw new Refusal('Only members of Infrastructure Security or Information Security can approve', 403);
  const required = role.requires_both ? ['infrasec', 'infosec'] : [role.reviewer_team];
  if (!required.includes(user.team)) throw new Refusal(`This role is reviewed by ${required.join(' and ')}; you are on ${user.team}`, 403);
  return tx(async (c) => {
    await c.query(`INSERT INTO recommendation_approvals(recommendation_id, user_id, team) VALUES ($1,$2,$3) ON CONFLICT (recommendation_id, team) DO NOTHING`, [recId, user.id, user.team]);
    const got = (await c.query('SELECT team FROM recommendation_approvals WHERE recommendation_id=$1', [recId])).rows.map((r) => r.team);
    const done = required.every((t) => got.includes(t));
    if (done) await c.query(`UPDATE recommendations SET status='approved' WHERE id=$1`, [recId]);
    return { approved: done, waitingFor: required.filter((t) => !got.includes(t)) };
  });
}

export async function notifyApproved(recId) {
  if (!config.approvalWebhookUrl) return;
  const rec = (await query(`SELECT r.id, r.policies, ro.arn, ro.name FROM recommendations r JOIN roles ro ON ro.id=r.role_id WHERE r.id=$1`, [recId])).rows[0];
  await fetch(config.approvalWebhookUrl, { method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ event: 'recommendation.approved', recommendationId: rec.id, role: { arn: rec.arn, name: rec.name }, policies: rec.policies }) })
    .catch((e) => console.error(JSON.stringify({ level: 'warn', msg: 'approval webhook failed', error: e.message })));
}

export function toTerraform(role, rec) {
  const id = (s) => s.replace(/[^A-Za-z0-9_]/g, '_');
  const out = [`# Curious Monkey least-privilege recommendation for ${role.name}`, `# Generated ${new Date().toISOString().slice(0, 10)}. Review before applying.`, ''];
  rec.policies.forEach((p, i) => {
    out.push(`resource "aws_iam_policy" "${id(p.name)}" {`, `  name   = "${p.name}"`, `  policy = jsonencode(${JSON.stringify(p.document, null, 2).replace(/\n/g, '\n  ')})`, '}', '');
    if (role.kind === 'identity-center') {
      if (i === 0) out.push(`# Identity Center: apply this in permission set "${role.permission_set}", not on the generated role.`, `# resource "aws_ssoadmin_permission_set_inline_policy" "${id(role.permission_set || role.name)}" { ... }`, '');
    } else {
      out.push(`resource "aws_iam_role_policy_attachment" "${id(p.name)}" {`, `  role       = "${role.name}"`, `  policy_arn = aws_iam_policy.${id(p.name)}.arn`, '}', '');
    }
  });
  out.push('# After applying, remove these existing policies from the role:');
  return out.join('\n');
}
export { hasService, hardFailures };
