// The safety net. Whatever drafted the policy (rules, an AI model, a human edit), it must pass these before approval.
import { computeGrants } from '../analyzer/grants.js';
import { expandAction, actionInfo, hasService } from '../analyzer/catalog.js';
import { normalizeStatements, policySize, arr } from '../analyzer/policy.js';
import { isSubsetGlob, hasWildcard, globMatch, isMatchAll } from '../analyzer/wildcard.js';
import { MANAGED_LIMIT } from './rules.js';

const ok = (id, label, detail = null) => ({ id, label, status: 'pass', detail });
const bad = (id, label, detail) => ({ id, label, status: 'fail', detail });
const warn = (id, label, detail) => ({ id, label, status: 'warn', detail });

export function draftStatements(policies) {
  return policies.flatMap((p) => normalizeStatements(p.document)).filter((s) => s.effect === 'Allow');
}

/** Every concrete action a draft statement allows. */
const concrete = (st) => (st.notActions.length ? [] : st.actions.flatMap((a) => (hasWildcard(a) ? expandAction(a) : [actionInfo(a)?.action ?? a])));

export function runChecks({ draftPolicies, originalPolicies, boundaryDoc = null, actions, observed, decisions = new Map() }) {
  const results = [];
  const stmts = draftStatements(draftPolicies);
  const grants = computeGrants(originalPolicies, { permissionsBoundary: boundaryDoc });

  // 1. nothing the role did not already have
  const widened = [], lostCondition = [];
  for (const st of stmts) {
    if (st.notActions.length) { widened.push('NotAction is not allowed in a least-privilege draft'); continue; }
    const resources = st.resources.length ? st.resources : ['*'];
    for (const a of concrete(st)) {
      const g = grants.get(a);
      if (!g) { widened.push(`${a} is not granted today`); continue; }
      const orig = [...g.resources].filter((r) => !r.startsWith('NotResource:'));
      for (const r of resources) {
        if (!orig.some((o) => isSubsetGlob(r, o, { ci: false })) && !g.resources.size) widened.push(`${a} on ${r}`);
        else if (!orig.some((o) => isSubsetGlob(r, o, { ci: false }))) widened.push(`${a} on ${r} (today: ${orig.join(', ') || 'NotResource'})`);
      }
      if (g.conditions.length && !st.conditions) lostCondition.push(a);
    }
  }
  results.push(widened.length ? bad('no-new-access', 'Grants nothing the role did not already have', `${[...new Set(widened)].slice(0, 8).join('; ')}`) : ok('no-new-access', 'Grants nothing the role did not already have'));
  results.push(lostCondition.length ? bad('conditions', 'Keeps the conditions on existing grants', `Condition dropped for ${[...new Set(lostCondition)].slice(0, 6).join(', ')}`) : ok('conditions', 'Keeps the conditions on existing grants'));

  // 2. no bazooka
  const bazookas = [], loose = [];
  for (const st of stmts) for (const a of st.actions) {
    if (a === '*' || /^[\w-]+:\*$/.test(a)) bazookas.push(a); else if (hasWildcard(a)) loose.push(a);
  }
  results.push(bazookas.length ? bad('no-bazooka', 'No service-wide or global wildcards', `Found ${[...new Set(bazookas)].join(', ')}`)
    : loose.length ? warn('no-bazooka', 'No service-wide or global wildcards', `Partial wildcards left: ${[...new Set(loose)].slice(0, 5).join(', ')}`) : ok('no-bazooka', 'No service-wide or global wildcards'));

  // 3. evidence: each action is used, or unverifiable and not marked for removal
  const status = new Map(actions.map((a) => [a.action, a]));
  const unproven = [];
  for (const st of stmts) for (const a of concrete(st)) {
    const s = status.get(a);
    if (!s || s.status === 'unused' || (s.status === 'unconfirmed' && decisions.get(a)?.decision === 'remove')) unproven.push(a);
  }
  results.push(unproven.length ? bad('evidence', 'Every action is backed by evidence', `No evidence of use for ${[...new Set(unproven)].slice(0, 8).join(', ')}`) : ok('evidence', 'Every action is backed by evidence'));

  // 4. grammar, known actions, size
  const problems = [];
  for (const p of draftPolicies) {
    if (p.document?.Version !== '2012-10-17') problems.push(`${p.name}: Version must be 2012-10-17`);
    if (!Array.isArray(p.document?.Statement) || !p.document.Statement.length) problems.push(`${p.name}: no statements`);
    if (policySize(p.document) > MANAGED_LIMIT) problems.push(`${p.name}: ${policySize(p.document)} characters, limit ${MANAGED_LIMIT}`);
  }
  for (const st of stmts) for (const a of st.actions) {
    if (a === '*') continue;
    const [svc] = a.split(':');
    if (!hasService(svc)) problems.push(`unknown service in ${a}`);
    else if (!hasWildcard(a) && !actionInfo(a)) problems.push(`unknown action ${a}`);
  }
  results.push(problems.length ? bad('valid', 'Valid policy grammar, known actions, within size limits', problems.slice(0, 6).join('; ')) : ok('valid', 'Valid policy grammar, known actions, within size limits'));

  // 5. replay: would anything the role really did stop working?
  const broken = [];
  for (const a of actions.filter((x) => x.status === 'used')) {
    const obsRes = observed.get(a.action) || [];
    const covering = stmts.filter((st) => concrete(st).includes(a.action));
    if (!covering.length) { broken.push(a.action); continue; }
    for (const r of obsRes) {
      const covered = covering.some((st) => (st.resources.length ? st.resources : ['*']).some((p) => isMatchAll(p) || globMatch(p, r)));
      if (!covered) broken.push(`${a.action} on ${r}`);
    }
  }
  results.push(broken.length ? bad('replay', 'Replays everything seen in the window', `Would break: ${[...new Set(broken)].slice(0, 6).join('; ')}`) : ok('replay', 'Replays everything seen in the window'));
  return results;
}

export const checksPass = (results) => results.every((c) => c.status !== 'fail');
export const hardFailures = (results) => results.filter((c) => c.status === 'fail');

/** Optional second opinion from AWS itself. Skipped unless enabled and a client is supplied. */
export async function awsValidate(validateFn, policies) {
  if (!validateFn) return { id: 'aws-validate', label: 'IAM Access Analyzer policy validation', status: 'skipped', detail: 'Not enabled' };
  const findings = [];
  for (const p of policies) for (const f of await validateFn(p.document)) findings.push(f);
  const errs = findings.filter((f) => f.findingType === 'ERROR' || f.findingType === 'SECURITY_WARNING');
  return errs.length ? { id: 'aws-validate', label: 'IAM Access Analyzer policy validation', status: 'fail', detail: errs.slice(0, 4).map((f) => f.issueCode).join(', ') }
    : { id: 'aws-validate', label: 'IAM Access Analyzer policy validation', status: findings.length ? 'warn' : 'pass', detail: findings.length ? `${findings.length} suggestion(s)` : null };
}
export { arr };
