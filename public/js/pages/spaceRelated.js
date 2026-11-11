// What is connected to the selection in Space, so everything else can fade. No DOM: the tests import it in Node.

export const FADE = 0.14;   // how far things not connected to the selection fade

/**
 * Everything connected to the selection: the paths that touch it and what is at their other end. A role also brings
 * its cluster, the services it calls and every outside identity that can enter it; an outside identity brings its gate
 * and every role it can enter; a path brings both ends.
 */
export function related(M, sel) {
  const rel = new Set([sel]);
  const role = M.byRole?.get(sel);
  const link = M.links.find((l) => l.id === sel);
  if (link) rel.add(link.from).add(link.to);
  if (role) rel.add(role.cluster.id);
  // an outside identity in one account: its gate, then the fan from the gate to the roles it can enter
  const gates = (M.gates || []).filter((g) => g.src === sel || (role && g.roles.includes(role.id)));
  for (const g of gates) { rel.add(g.id); if (role) rel.add(g.src); }
  for (const l of M.links) {
    const touches = l.from === sel || l.to === sel || l.id === sel || (role && l.owner === role.id)
      || (l.kind === 'fan' && (l.src === sel || (role && l.to === role.id))) || (/^ext/.test(l.kind) && gates.some((g) => g.id === l.to));
    if (!touches) continue;
    rel.add(l.id).add(l.from).add(l.to);
  }
  // a selected service lights the clusters whose roles call it
  for (const r of M.roles || []) if (rel.has(r.id) && !role) rel.add(r.cluster.id);
  return rel;
}
