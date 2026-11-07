// Deterministic least-privilege draft. It can only keep or narrow what the role already has, never widen.
import { isSubsetGlob, isMatchAll } from '../analyzer/wildcard.js';
import { actionInfo } from '../analyzer/catalog.js';
import { policySize } from '../analyzer/policy.js';

export const MANAGED_LIMIT = 6144;

/**
 * ctx: { grants: Map, actions: [{action,status,reason}], decisions: Map(action -> {decision, resources}), observed: Map(action -> [arn]) }
 * Returns rows [{ action, resources[], condition, group: 'observed'|'unverified' }]
 */
/**
 * Should an action the event history cannot verify stay in the draft?
 * Named explicitly in a policy: yes, the author meant it. Granted only because a wildcard happened to
 * include it: no, unless a reviewer decides to keep it. Removing is always the reviewer's call to overrule.
 */
export function keepUnconfirmed(ctx, action, reason = null) {
  const d = ctx.decisions.get(action);
  if (d?.decision === 'remove') return false;
  if (d?.decision === 'keep' || d?.decision === 'keep_scoped') return true;
  // calls under an unidentified event name were made in this service: any of these could be the one needed
  if (reason === 'unmapped-event') return true;
  return !ctx.grants.get(action)?.wildcardGrant;
}

export function ruleRows(ctx) {
  const rows = [];
  for (const a of ctx.actions) {
    const g = ctx.grants.get(a.action);
    if (!g) continue;
    const d = ctx.decisions.get(a.action);
    if (a.status === 'unused') continue;
    if (a.status === 'unconfirmed' && !keepUnconfirmed(ctx, a.action, a.reason)) continue;
    const group = a.status === 'used' ? 'observed' : 'unverified';
    let resources = [...g.resources].filter((r) => !r.startsWith('NotResource:'));
    if (!resources.length) resources = ['*'];
    // reviewer narrowed it: accept only when every new resource sits inside what was already granted
    if (d?.resources?.length && d.resources.every((r) => resources.some((o) => isSubsetGlob(r, o, { ci: false })))) resources = d.resources;
    else if (resources.some(isMatchAll) && a.status === 'used') {
      const obs = ctx.observed.get(a.action) || [];
      const info = actionInfo(a.action);
      // only when every call named its resource; otherwise unseen targets would break
      if (obs.length && info?.hasResource && !info.wildcardOnly && !ctx.incomplete?.has(a.action)) resources = [...new Set(obs)].sort();
    }
    const cond = g.conditions.length === 1 ? g.conditions[0].condition : g.conditions.length > 1 ? g.conditions[0].condition : null;
    rows.push({ action: a.action, resources: resources.sort(), condition: cond, group });
  }
  return rows;
}

export function rowsToStatements(rows) {
  const by = new Map();
  for (const r of rows) {
    const k = `${r.group}|${JSON.stringify(r.resources)}|${JSON.stringify(r.condition)}`;
    if (!by.has(k)) by.set(k, { group: r.group, resources: r.resources, condition: r.condition, actions: [] });
    by.get(k).actions.push(r.action);
  }
  const counters = { observed: 0, unverified: 0 };
  return [...by.values()].sort((a, b) => a.group.localeCompare(b.group) || a.actions[0].localeCompare(b.actions[0])).map((g) => {
    const st = {
      Sid: `${g.group === 'observed' ? 'Observed' : 'Unverified'}${++counters[g.group]}`,
      Effect: 'Allow', Action: g.actions.sort(), Resource: g.resources.length === 1 ? g.resources[0] : g.resources,
    };
    if (g.condition) st.Condition = g.condition;
    return st;
  });
}

/** Managed policies are limited to 6,144 non-whitespace characters, so split big drafts into several documents. */
export function packPolicies(statements, baseName) {
  const docs = [];
  let cur = [];
  const doc = (s) => ({ Version: '2012-10-17', Statement: s });
  for (const st of statements) {
    if (policySize(doc([...cur, st])) > MANAGED_LIMIT - 40 && cur.length) { docs.push(cur); cur = []; }
    if (policySize(doc([st])) > MANAGED_LIMIT - 40) {                          // one statement too large: split its actions
      const half = Math.ceil(st.Action.length / 2);
      const parts = [{ ...st, Action: st.Action.slice(0, half) }, { ...st, Action: st.Action.slice(half) }];
      for (const p of parts) { if (policySize(doc([...cur, p])) > MANAGED_LIMIT - 40 && cur.length) { docs.push(cur); cur = []; } cur.push(p); }
      continue;
    }
    cur.push(st);
  }
  if (cur.length) docs.push(cur);
  return docs.map((s, i) => ({ name: docs.length === 1 ? baseName : `${baseName}-${i + 1}`, document: doc(s), size: policySize(doc(s)) }));
}

export function rulesDraft(ctx, baseName) {
  const rows = ruleRows(ctx);
  const statements = rowsToStatements(rows);
  return { source: 'rules', statements, policies: packPolicies(statements, baseName), summary: null };
}
