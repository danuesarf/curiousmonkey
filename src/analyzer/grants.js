// Turn a role's policies into the set of concrete actions it can be granted, with where each came from.
import { normalizeStatements, arr } from './policy.js';
import { expandAction, serviceActions, actionInfo } from './catalog.js';
import { globMatch, hasWildcard, isMatchAll } from './wildcard.js';

/**
 * policies: [{ name, kind: 'inline'|'managed', document }]
 * Returns Map(action -> { resources:Set, conditions:[], sources:Set, wildcardGrant:bool })
 * Only unconditional, resource-wide Deny statements remove an action; anything narrower is ignored
 * (we would rather over-report a grant than hide one).
 */
export function computeGrants(policies, { permissionsBoundary = null } = {}) {
  const grants = new Map();
  const denied = [];  // patterns fully denied on every resource

  const expandStmt = (st) => {
    if (st.notActions.length) {
      const excluded = st.notActions;
      const all = expandAction('*');
      return all.filter((a) => !excluded.some((p) => globMatch(p, a, { ci: true })));
    }
    const out = new Set();
    for (const p of st.actions) {
      if (!hasWildcard(p)) { out.add(actionInfo(p)?.action ?? p); continue; }   // keeps actions the catalog does not know yet
      for (const a of expandAction(p)) out.add(a);
    }
    return [...out];
  };

  for (const pol of policies) {
    for (const st of normalizeStatements(pol.document)) {
      if (st.effect === 'Deny') {
        const fullResource = st.resources.some(isMatchAll) && !st.conditions && !st.notResources.length;
        if (fullResource) denied.push(...(st.notActions.length ? [] : st.actions));
        continue;
      }
      const wildcardGrant = st.actions.some((a) => hasWildcard(a)) || st.notActions.length > 0;
      const resources = st.notResources.length ? ['NotResource:' + st.notResources.join(',')] : (st.resources.length ? st.resources : ['*']);
      for (const a of expandStmt(st)) {
        let g = grants.get(a);
        if (!g) { g = { resources: new Set(), conditions: [], sources: new Set(), wildcardGrant: false }; grants.set(a, g); }
        resources.forEach((r) => g.resources.add(r));
        if (st.conditions) g.conditions.push({ source: pol.name, condition: st.conditions });
        g.sources.add(pol.name);
        g.wildcardGrant ||= wildcardGrant;
      }
    }
  }
  for (const p of denied) {
    for (const a of [...grants.keys()]) if (globMatch(p, a, { ci: true })) grants.delete(a);
  }
  if (permissionsBoundary) {
    const allowed = computeGrants([{ name: 'boundary', document: permissionsBoundary }]);
    for (const a of [...grants.keys()]) if (!allowed.has(a)) grants.delete(a);
  }
  return grants;
}

export const grantedServices = (grants) => [...new Set([...grants.keys()].map((a) => a.split(':')[0]))];
export { serviceActions };
