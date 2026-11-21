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
  // a resource (one account) is like a role: the gates of whoever can use it, and those outsiders
  const res = String(sel).startsWith('res:');
  const gates = (M.gates || []).filter((g) => g.src === sel || (role && g.roles.includes(role.id)) || (res && g.res?.includes(sel)));
  for (const g of gates) { rel.add(g.id); if (role || res) rel.add(g.src); }
  for (const l of M.links) {
    const touches = l.from === sel || l.to === sel || l.id === sel || (role && l.owner === role.id)
      || (l.kind === 'fan' && (l.src === sel || (role && l.to === role.id))) || (l.kind === 'resfan' && (l.src === sel || l.to === sel))
      || (/^ext/.test(l.kind) && gates.some((g) => g.id === l.to));
    if (!touches) continue;
    rel.add(l.id).add(l.from).add(l.to);
  }
  // a selected service lights the clusters whose roles call it
  for (const r of M.roles || []) if (rel.has(r.id) && !role) rel.add(r.cluster.id);
  return rel;
}

// Paths that come in: an outside identity to its gate, the gate to a role or a resource, the scanner, another account
// chaining in, an outside identity using resources
const IN_KINDS = new Set(['ext', 'extWarn', 'extHigh', 'fan', 'scan', 'in', 'res', 'resWarn', 'resHigh', 'resfan']);
const OUT_KINDS = new Set(['out']);

/**
 * Which paths and outside identities to draw for a direction: 'both', 'in' (who can get in) or 'out' (where it can
 * go). In one account it is relative to that account; paths inside it (roles to services) always stay. On the estate
 * it is relative to the account picked: In is what enters it, Out is what it enters, nothing else. With no account
 * picked, In is everything from outside your org and the scanner, Out the paths between your accounts.
 */
// paths that count as a way in or out of an account or project (not the scanner, not paths inside one)
const WAY_KINDS = /^(ext|extWarn|extHigh|res|resWarn|resHigh|chain|new|gchain|xcloud|xcloudHigh)$/;

/**
 * The In / Out numbers for a picked account or project on the estate, or for the one account or project shown: who is at the other end (an outside identity,
 * another account or project), whatever the path (trust, resource policies, chaining, federation between the clouds).
 * The scanner is left out. Null when nothing is picked.
 */
export function wayEnds(M, sel, dir) {
  if (M.view === 'account') {
    // one account or project: outsiders come in through their gate, other accounts in and out at the edge
    const f = dirFilter(dir, M, null), ends = new Set();
    for (const l of M.links) if (ACCOUNT_WAY_KINDS.test(l.kind) && f.link(l)) ends.add(dir === 'out' ? l.to : l.from);
    return ends.size;
  }
  if (!M.by?.has(sel)) return null;
  const f = dirFilter(dir, M, sel), ends = new Set();
  for (const l of M.links) if (WAY_KINDS.test(l.kind) && f.link(l)) ends.add(l.to === sel ? l.from : l.to);
  return ends.size;
}
const ACCOUNT_WAY_KINDS = /^(ext|extWarn|extHigh|res|resWarn|resHigh|in|out)$/;

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
  const inbound = (l) => /^(ext|res)/.test(l.kind) || l.kind === 'scan';
  return { inside: dir === 'in', source: () => dir === 'in', link: (l) => (inbound(l) ? want(true) : want(false)) };
}

/**
 * What a wheel event is: 'pinch' (a trackpad pinch, or Ctrl+wheel: the browser sends Ctrl with it), 'zoom' (a mouse
 * wheel, or ⌘+wheel) or 'pan' (a two-finger swipe on a trackpad, or Shift+wheel). Browsers do not say which device
 * sent it: a mouse wheel scrolls by lines or pages (Firefox), or in notches of 120 (`wheelDelta`), with nothing
 * sideways; a trackpad sends small pixel steps, often on both axes. `mem` keeps the last answer: a swipe stays a swipe
 * until the fingers rest (150 ms), so a fast swipe whose step happens to look like a notch does not zoom.
 */
export function wheelKind(ev, mem = {}, now = Date.now()) {
  let kind;
  if (ev.ctrlKey) kind = 'pinch';
  else if (ev.metaKey) kind = 'zoom';
  else if (ev.shiftKey || ev.deltaX) kind = 'pan';
  else if (mem.kind === 'pan' && now - mem.at < 150) kind = 'pan';
  else if (ev.deltaMode && ev.deltaMode !== 0) kind = 'zoom';
  else if (ev.wheelDeltaY && Math.abs(ev.wheelDeltaY) % 120 === 0 && Math.abs(ev.wheelDeltaY) >= 120) kind = 'zoom';
  else if (Number.isInteger(ev.deltaY) && Math.abs(ev.deltaY) >= 100) kind = 'zoom';
  else kind = 'pan';
  mem.kind = kind; mem.at = now;
  return kind;
}
