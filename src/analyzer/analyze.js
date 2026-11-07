// The heart of the tool. Pure function: role + policies + observed activity in, verdicts out.
import crypto from 'node:crypto';
import { computeGrants } from './grants.js';
import { actionInfo } from './catalog.js';
import { unloggableReason, dataEventResource } from './unloggable.js';
import { trustFindings } from './trust.js';
import { normalizeStatements } from './policy.js';
import { isMatchAll } from './wildcard.js';

const SEV_BY_LEVEL = { Permissions: 'high', Write: 'high', Tagging: 'medium', Read: 'medium', List: 'low' };
const RANK = { high: 3, medium: 2, low: 1 };
const DATA_SERVICES = new Set(['s3', 'dynamodb', 'rds', 'rds-data', 'secretsmanager', 'kms', 'redshift', 'redshift-data', 'athena', 'ssm', 'elasticfilesystem', 'kinesis']);

const TITLES = {
  'data-event': (s) => `${s} data-plane actions can't be confirmed from event history`,
  'authorization-only': () => `Checked by AWS but never logged by CloudTrail`,
  'not-logged': (s) => `${s} actions CloudTrail cannot record`,
  'before-window': (s) => `${s} was used before the stored history starts`,
  'service-unknown': (s) => `${s} was used but the actions aren't visible`,
};
const REASONS = {
  'data-event': (s, r) => `Object/item level ${s} calls are data events. Event History only holds management events, so unused is not provable. ${r ? `Enable data events for ${r} to verify.` : ''}`.trim(),
  'authorization-only': () => 'AWS evaluates these during another call but writes no event of their own. Evidence comes from the roles seen in other calls, when there is any.',
  'not-logged': (s) => `CloudTrail has no data-event type for ${s} message calls, so no setting can confirm them.`,
  'before-window': (s) => `IAM Access Advisor says ${s} was last used before the oldest event we can read. Which action it was is unknown.`,
  'service-unknown': (s) => `IAM Access Advisor says ${s} was used recently but no matching event was found for these actions.`,
};

export function analyze({ role, policies, boundaryDoc = null, activity, advisor = [], windowStart, now = new Date() }) {
  const grants = computeGrants(policies, { permissionsBoundary: boundaryDoc });
  const observed = activity.actions;                       // Map(action -> {count, lastSeen})
  const passed = activity.passroles || [];
  const advisorBy = new Map(advisor.map((a) => [a.service.toLowerCase(), a.lastAuthenticated ? new Date(a.lastAuthenticated) : null]));

  const observedServices = new Set([...observed.keys()].filter((a) => observed.get(a).count > 0).map((a) => a.split(':')[0].toLowerCase()));
  const rows = [];
  const unconfirmed = new Map();                           // `${category}|${service}` -> [{action, level}]

  for (const [action, g] of grants) {
    const info = actionInfo(action);
    const level = info?.level ?? null;
    const svc = action.split(':')[0].toLowerCase();
    const obs = observed.get(action);
    let status, reason = null, count = 0, lastSeen = null;

    if (obs && obs.count > 0) { status = 'used'; count = obs.count; lastSeen = obs.lastSeen; }
    else if (action === 'iam:PassRole' && passed.length) { status = 'used'; reason = 'inferred'; count = passed.reduce((n, p) => n + p.count, 0); }
    else if ((reason = unloggableReason(action))) status = 'unconfirmed';
    else {
      const last = advisorBy.get(svc);
      if (last && last < windowStart) { status = 'unconfirmed'; reason = 'before-window'; }
      else if (last && !observedServices.has(svc)) { status = 'unconfirmed'; reason = 'service-unknown'; }
      else status = 'unused';
    }
    rows.push({ action, status, reason: status === 'unused' ? null : reason, level, count, lastSeen });
    if (status === 'unconfirmed') {
      const k = `${reason}|${svc}`;
      if (!unconfirmed.has(k)) unconfirmed.set(k, []);
      unconfirmed.get(k).push({ action, level, resources: [...g.resources] });
    }
  }

  const flags = [];
  for (const [k, list] of unconfirmed) {
    const [cat, svc] = k.split('|');
    const key = cat === 'authorization-only' ? list.map((x) => x.action).sort()[0] : svc;
    const sev = list.reduce((m, x) => (RANK[SEV_BY_LEVEL[x.level] || 'medium'] > RANK[m] ? (SEV_BY_LEVEL[x.level] || 'medium') : m), 'low');
    const resources = [...new Set(list.flatMap((x) => x.resources))].sort();
    const res = dataEventResource(list[0].action);
    flags.push({
      category: cat, key, title: TITLES[cat](svc), actions: list.map((x) => x.action).sort(), resources,
      reason: REASONS[cat](svc, res), evidence: evidenceFor(cat, svc, advisorBy, activity), severity: sev,
      suggestion: cat === 'data-event' ? 'Keep, scoped to the resources the workload needs, until data events prove otherwise.' : 'Reviewer decides: keep scoped or remove.',
      suggestedResources: [], decisionKind: 'action',
    });
  }

  // wildcard grants
  for (const pol of policies) for (const st of normalizeStatements(pol.document)) {
    if (st.effect !== 'Allow') continue;
    for (const a of st.actions) {
      if (!/\*/.test(a)) continue;
      const wide = st.resources.some(isMatchAll) || !st.resources.length;
      if (!wide) continue;
      flags.push({ category: 'wildcard', key: a, title: `Wildcard grant ${a} on every resource`, actions: [], resources: ['*'],
        reason: `${pol.name} grants ${a} on Resource "*".`, evidence: `${grants.size} actions are granted in total.`,
        suggestion: 'Replace with the actions listed under Used.', suggestedResources: [], severity: a === '*' || a === '*:*' ? 'high' : 'medium', decisionKind: 'other' });
    }
  }

  // who is allowed in
  for (const f of trustFindings(role.trust_policy || {})) {
    flags.push({ category: 'trust-wildcard', key: f.key, title: 'Broad trust policy', actions: [], resources: [], reason: f.reason, evidence: null,
      suggestion: 'Restrict the trust policy to the specific principals that use this role.', suggestedResources: [], severity: f.severity, decisionKind: 'other' });
  }
  for (const p of activity.principals || []) {
    if (p.trust && !p.trust.matched && p.kind !== 'service') {
      flags.push({ category: 'external-principal', key: p.key, title: `Unexpected principal ${p.display}`, actions: [], resources: [],
        reason: 'This principal assumed the role but no trust statement names it directly.', evidence: p.via,
        suggestion: 'Confirm with the owner, then add it to the trust policy explicitly or block it.', suggestedResources: [], severity: 'medium', decisionKind: 'other' });
    }
  }

  const idle = !role.last_used_at || new Date(role.last_used_at) < windowStart;
  if (idle) flags.push({ category: 'role-idle', key: 'idle', title: 'Role not used in the window', actions: [], resources: [],
    reason: `No successful use in the last ${Math.round((now - windowStart) / 864e5)} days.`, evidence: role.last_used_at ? `Last used ${new Date(role.last_used_at).toISOString().slice(0, 10)}.` : 'IAM has never recorded a use.',
    suggestion: 'Delete the role if nothing depends on it.', suggestedResources: [], severity: 'medium', decisionKind: 'other' });

  const counts = { granted: rows.length, used: 0, unused: 0, unconfirmed: 0 };
  for (const r of rows) counts[r.status]++;

  const { risk, score, reasons } = scoreRisk({ rows, flags, role, counts });
  const { team, both } = reviewer({ role, rows, risk });

  const hash = crypto.createHash('sha256');
  hash.update(JSON.stringify(rows.map((r) => `${r.action}:${r.status}`).sort()));
  hash.update(JSON.stringify(flags.map((f) => `${f.category}:${f.key}`).sort()));
  hash.update(JSON.stringify(policies.map((p) => `${p.kind}:${p.name}`).sort()));
  return { actions: rows, flags, counts, risk, riskScore: score, riskReasons: reasons, reviewerTeam: team, requiresBoth: both,
    analysisHash: hash.digest('hex').slice(0, 32) };
}

function evidenceFor(cat, svc, advisorBy, activity) {
  if (cat === 'before-window' || cat === 'service-unknown') {
    const d = advisorBy.get(svc);
    return d ? `Access Advisor: ${svc} last authenticated ${d.toISOString().slice(0, 10)}.` : null;
  }
  if (cat === 'authorization-only' && activity.passroles?.length) return `${activity.passroles.length} role(s) were passed to services in the window.`;
  return null;
}

export function scoreRisk({ rows, flags, role, counts }) {
  let s = 0; const reasons = [];
  const add = (n, why) => { s += n; reasons.push(why); };
  if (counts.granted > 20000) add(40, 'Grants effectively every AWS action');
  const unusedLevel = (lv) => rows.filter((r) => r.status === 'unused' && r.level === lv).length;
  const up = unusedLevel('Permissions'), uw = unusedLevel('Write');
  if (up) add(Math.min(20, up), `${up} unused permission-management actions`);
  if (uw) add(Math.min(15, Math.ceil(uw / 10)), `${uw} unused write actions`);
  const wild = flags.filter((f) => f.category === 'wildcard').length;
  if (wild) add(Math.min(20, wild * 10), `${wild} wildcard grant(s) on all resources`);
  const tw = flags.filter((f) => f.category === 'trust-wildcard');
  if (tw.some((f) => f.severity === 'high')) add(30, 'Anyone can assume this role');
  else if (tw.length) add(10, 'Broad trust policy');
  if (flags.some((f) => f.category === 'external-principal')) add(20, 'Unexpected principal used the role');
  const uc = rows.filter((r) => r.status === 'unconfirmed' && (r.level === 'Write' || r.level === 'Permissions')).length;
  if (uc) add(Math.min(10, Math.ceil(uc / 5)), `${uc} write/permission actions can't be verified`);
  if (flags.some((f) => f.category === 'role-idle')) add(10, 'Role looks idle');
  return { risk: s >= 50 ? 'High' : s >= 25 ? 'Medium' : 'Low', score: s, reasons };
}

export function reviewer({ role, rows, risk }) {
  let team = 'infrasec';
  if (role.kind === 'identity-center') team = 'infosec';
  else if (role.kind !== 'service-linked') {
    const touchesData = rows.some((r) => r.level === 'Read' && DATA_SERVICES.has(r.action.split(':')[0].toLowerCase()) && (r.status === 'used' || r.status === 'unconfirmed'));
    if (touchesData) team = 'infosec';
  }
  return { team, both: risk === 'High' };
}
