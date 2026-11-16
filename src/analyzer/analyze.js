// The heart of the tool. Pure function: role + policies + observed activity in, verdicts out.
import crypto from 'node:crypto';
import { computeGrants } from './grants.js';
import { actionInfo, expandAction } from './catalog.js';
import { privilegeTier, isPrivilege, isDataRead } from './sensitive.js';
import { unloggableReason, dataEventResource } from './unloggable.js';
import { trustFindings } from './trust.js';
import { normalizeStatements } from './policy.js';
import { isMatchAll } from './wildcard.js';
import { controlOfFlag, severityOf, DEFAULT_POLICY } from '../controlCatalog.js';

const WIDE = (resources) => !resources.length || resources.some(isMatchAll);

/**
 * How serious an evidence gap is. None of these says something is wrong: they say use could not be proven, so they
 * are never high. Medium is kept for what a reviewer should really look at: privilege-changing actions that cannot be
 * verified, writes to every resource, and event names the tool could have mapped. The rest is low.
 */
export function gapSeverity(cat, list) {
  const priv = list.some((x) => isPrivilege(x.action, x.level));
  const write = list.some((x) => x.level === 'Write' || x.level === 'Permissions');
  const wide = list.some((x) => WIDE(x.resources || []));
  switch (cat) {
    case 'not-logged': return 'low';                                  // no setting can ever confirm these: nothing to act on
    case 'data-event': return write && wide ? 'medium' : 'low';      // writing or deleting data in every bucket or table, unseen
    case 'authorization-only': return priv && wide ? 'medium' : 'low';   // iam:PassRole on every role: a way to more privilege
    case 'before-window': return priv ? 'medium' : 'low';            // not used since before the history: likely removable
    case 'service-unknown': return priv ? 'medium' : 'low';          // usually a service calling on the role's behalf (KMS through S3)
    case 'unmapped-event': return priv || write ? 'medium' : 'low';  // fixable: map the event names
    default: return 'low';
  }
}

/**
 * A wildcard on every resource, rated by what it expands to: everything, or the identity plane (iam:*, iam:Put*), is
 * high; anything that can write is medium; read-only wildcards are low unless they read the data itself (s3:Get*).
 * A service-linked role's policy is AWS's own and cannot be edited: low, for the record.
 */
export function wildcardSeverity(pattern, role = {}) {
  if (role.kind === 'service-linked') return 'low';
  if (pattern === '*' || pattern === '*:*') return 'high';
  const all = expandAction(pattern);
  if (!all.length) return 'medium';                                   // a service the catalog does not know: assume it can write
  let write = false, data = false;
  for (const a of all) {
    const level = actionInfo(a)?.level;
    if (privilegeTier(a, level) === 'identity') return 'high';
    if (level === 'Write' || level === 'Permissions') write = true;
    else if (isDataRead(a)) data = true;
  }
  return write || data ? 'medium' : 'low';
}
const DATA_SERVICES = new Set(['s3', 'dynamodb', 'rds', 'rds-data', 'secretsmanager', 'kms', 'redshift', 'redshift-data', 'athena', 'ssm', 'elasticfilesystem', 'kinesis']);

const TITLES = {
  'data-event': (s) => `${s} data-plane actions can't be confirmed from event history`,
  'authorization-only': () => `Checked by AWS but never logged by CloudTrail`,
  'not-logged': (s) => `${s} actions CloudTrail cannot record`,
  'before-window': (s) => `${s} was used before the stored history starts`,
  'service-unknown': (s) => `${s} was used but the actions aren't visible`,
  'unmapped-event': (s) => `${s} calls were seen that could not be matched to IAM actions`,
};
const REASONS = {
  'data-event': (s, r) => `Object/item level ${s} calls are data events. Event History only holds management events, so unused is not provable. ${r ? `Enable data events for ${r} to verify.` : ''}`.trim(),
  'authorization-only': () => 'AWS evaluates these during another call but writes no event of their own. Evidence comes from the roles seen in other calls, when there is any.',
  'not-logged': (s) => `CloudTrail has no data-event type for ${s} message calls, so no setting can confirm them.`,
  'before-window': (s) => `IAM Access Advisor says ${s} was last used before the oldest event we can read. Which action it was is unknown.`,
  'service-unknown': (s) => `IAM Access Advisor says ${s} was used recently but no matching event was found for these actions.`,
  'unmapped-event': (s) => `This role made ${s} calls whose CloudTrail event names are not IAM action names, so any of these could be the permission they needed. Map the event names on the account's Event coverage page, then re-analyze.`,
};

export function analyze({ role, policies, boundaryDoc = null, activity, advisor = [], windowStart, now = new Date(), policy = DEFAULT_POLICY }) {
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
    else if (activity.unmappedServices?.has(svc)) { status = 'unconfirmed'; reason = 'unmapped-event'; }
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

  let flags = [];
  for (const [k, list] of unconfirmed) {
    const [cat, svc] = k.split('|');
    const key = cat === 'authorization-only' ? list.map((x) => x.action).sort()[0] : svc;
    const sev = gapSeverity(cat, list);
    const resources = [...new Set(list.flatMap((x) => x.resources))].sort();
    const res = dataEventResource(list[0].action);
    flags.push({
      category: cat, key, title: TITLES[cat](svc), actions: list.map((x) => x.action).sort(), resources,
      reason: REASONS[cat](svc, res), evidence: evidenceFor(cat, svc, advisorBy, activity), severity: sev,
      suggestion: cat === 'data-event' ? 'Keep, scoped to the resources the workload needs, until data events prove otherwise.'
        : cat === 'unmapped-event' ? 'Map the event names first; the actions that are really used then show as used.' : 'Reviewer decides: keep scoped or remove.',
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
        suggestion: role.kind === 'service-linked' ? 'Nothing to do: AWS owns a service-linked role\'s policy.' : 'Replace with the actions listed under Used.', suggestedResources: [], severity: wildcardSeverity(a, role), decisionKind: 'other' });
    }
    // Allow + NotAction on every resource: everything except a list, and every action AWS adds later
    if (st.notActions.length && (st.resources.some(isMatchAll) || !st.resources.length) && role.kind !== 'service-linked') {
      const keepsIam = !st.notActions.some((x) => /^(\*|iam:\*)$/i.test(x));
      flags.push({ category: 'wildcard', key: `NotAction:${st.notActions.slice().sort().join(',')}`.slice(0, 200), title: 'Grants every action except a list (NotAction) on every resource', actions: [], resources: ['*'],
        reason: `${pol.name} allows everything except ${st.notActions.slice(0, 6).join(', ')}${st.notActions.length > 6 ? '…' : ''}, including actions AWS adds in future.`, evidence: `${grants.size} actions are granted in total.`,
        suggestion: 'Replace with the actions listed under Used.', suggestedResources: [], severity: keepsIam ? 'high' : 'medium', decisionKind: 'other' });
    }
  }

  // who is allowed in: it counts toward the role's risk here; the findings themselves are the Trust map's (one rule set,
  // filed as category 'trust' by trustSync.js, which knows the whole estate: connected accounts, Identity Center…)
  const trust = trustFindings(role.trust_policy || {});
  // an IAM user has no trust policy: what calls as it is its own keys or console, never an unexpected principal
  for (const p of role.kind === 'iam-user' ? [] : activity.principals || []) {
    if (p.trust && !p.trust.matched && p.kind !== 'service') {
      flags.push({ category: 'external-principal', key: p.key, title: `Unexpected principal ${p.display}`, actions: [], resources: [],
        reason: 'This principal assumed the role but no trust statement names it directly.', evidence: p.via,
        suggestion: 'Confirm with the owner, then add it to the trust policy explicitly or block it.', suggestedResources: [], severity: 'medium', decisionKind: 'other' });
    }
  }

  // idle: not used in the window. A role created in the last 14 days has not had the time to be used.
  const young = role.created_in_aws && now - new Date(role.created_in_aws) < 14 * 864e5;
  const idle = !young && (!role.last_used_at || new Date(role.last_used_at) < windowStart);
  // what an unused role is worth to whoever finds a way in: any write medium, read-only low. The high case (an unused
  // administrator role) is the rule control "Administrator access not used in 90 days", so it is not raised twice.
  const idleSev = role.kind === 'service-linked' ? 'low' : rows.some((r) => r.level === 'Write' || r.level === 'Permissions') ? 'medium' : 'low';
  if (idle) flags.push({ category: 'role-idle', key: 'idle', title: 'Role not used in the window', actions: [], resources: [],
    reason: `No successful use in the last ${Math.round((now - windowStart) / 864e5)} days.`, evidence: role.last_used_at ? `Last used ${new Date(role.last_used_at).toISOString().slice(0, 10)}.` : 'IAM has never recorded a use.',
    suggestion: role.kind === 'service-linked' ? 'Delete it from its service if the service is no longer used.' : 'Delete the role if nothing depends on it.', suggestedResources: [], severity: idleSev, decisionKind: 'other' });

  // the workspace's policy: each finding names its control; one turned off is not made, one given a severity gets it
  flags = flags.flatMap((f) => {
    const control = controlOfFlag(f.category, f.key);
    const severity = control ? severityOf(policy, control, f.severity) : f.severity;
    return severity ? [{ ...f, control, severity }] : [];
  });

  const counts = { granted: rows.length, used: 0, unused: 0, unconfirmed: 0 };
  for (const r of rows) counts[r.status]++;

  const { risk, score, reasons } = scoreRisk({ rows, flags, role, counts, trust });
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
  if (cat === 'unmapped-event') return `Unmapped event names: ${(activity.unmappedServices?.get(svc) || []).slice(0, 5).join(', ')}.`;
  if (cat === 'authorization-only' && activity.passroles?.length) return `${activity.passroles.length} role(s) were passed to services in the window.`;
  return null;
}

export function scoreRisk({ rows, flags, role, counts, trust = [] }) {
  let s = 0; const reasons = [];
  const add = (n, why) => { s += n; reasons.push(why); };
  if (counts.granted > 20000) add(40, 'Grants effectively every AWS action');
  const unusedLevel = (lv) => rows.filter((r) => r.status === 'unused' && r.level === lv).length;
  const up = unusedLevel('Permissions'), uw = unusedLevel('Write');
  if (up) add(Math.min(20, up), `${up} unused permission-management actions`);
  if (uw) add(Math.min(15, Math.ceil(uw / 10)), `${uw} unused write actions`);
  // wildcards count by what they open: identity-plane or everything 20, writes 10, read-only nothing
  const wild = flags.filter((f) => f.category === 'wildcard' && f.severity !== 'low');
  if (wild.length) add(Math.min(30, wild.reduce((n, f) => n + (f.severity === 'high' ? 20 : 10), 0)), `${wild.length} wildcard grant(s) on all resources`);
  const tw = trust;
  if (tw.some((f) => f.severity === 'high')) add(50, 'Anyone can assume this role');          // High on its own, whatever it grants
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
