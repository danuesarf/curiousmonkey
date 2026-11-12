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

// Paths that come in: an outside identity to its gate, the gate to a role, the scanner, another account chaining in
const IN_KINDS = new Set(['ext', 'extWarn', 'extHigh', 'fan', 'scan', 'in']);
const OUT_KINDS = new Set(['out']);

/**
 * Which paths and outside identities to draw for a direction: 'both', 'in' (who can get in) or 'out' (where it can
 * go). In one account it is relative to that account; paths inside it (roles to services) always stay. On the estate
 * it is relative to the account picked: In is what enters it, Out is what it enters, nothing else. With no account
 * picked, In is everything from outside your org and the scanner, Out the paths between your accounts.
 */
export function dirFilter(dir, M, sel) {
  if (dir !== 'in' && dir !== 'out') return { inside: true, link: () => true, source: () => true };
  const want = (inbound) => (dir === 'in') === inbound;
  if (M.view === 'account') {
    return { inside: dir === 'in', source: () => dir === 'in',
      link: (l) => (IN_KINDS.has(l.kind) ? want(true) : OUT_KINDS.has(l.kind) ? want(false) : true) };
  }
  const A = M.by?.has(sel) ? sel : null;
  if (A) {
    const link = (l) => (l.to === A ? want(true) : l.from === A ? want(false) : false);
    return { inside: dir === 'in', link, source: (id) => dir === 'in' && M.links.some((l) => l.from === id && l.to === A) };
  }
  const inbound = (l) => /^ext/.test(l.kind) || l.kind === 'scan';
  return { inside: dir === 'in', source: () => dir === 'in', link: (l) => (inbound(l) ? want(true) : want(false)) };
}
