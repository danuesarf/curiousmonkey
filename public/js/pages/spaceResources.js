// Resource access in Space: resources whose policy lets in anyone, or an account outside the estate. The outside
// identity is the same node as for trust (one outsider, every way it has into you); a resource grant is a dashed path
// beside the trust path. In one account each exposed resource is a small box beside its service's tower, fanned to
// from the gate of whoever can use it. No DOM: the tests import it in Node.

export const RES_KINDS = new Set(['res', 'resWarn', 'resHigh', 'resfan']);
const SEV = { high: 0, medium: 1, low: 2, none: 3 };
/** The worst of a target's resources; a grant a reviewer marked expected counts as low. */
export const worstRes = (list) => list.reduce((w, r) => { const s = r.expected ? 'low' : r.severity; return SEV[s] < SEV[w] ? s : w; }, 'none');
export const resKind = (worst) => (worst === 'high' ? 'resHigh' : worst === 'medium' ? 'resWarn' : 'res');

/**
 * The layer off: what Space draws without resource access. Outside identities that only reach resources go, the
 * rest keep their trust; the account badges and the account's resource boxes go.
 */
export function stripResources(d) {
  if (!d) return d;
  const items = (d.outside?.items || []).map((s) => ({ ...s, resources: 0, worst: s.trustWorst ?? s.worst, targets: s.targets.filter((t) => t.roles.length).map((t) => ({ ...t, resources: [], resourceCount: 0 })) }))
    .filter((s) => s.targets.length);
  return { ...d, outside: { ...d.outside, items }, accounts: d.accounts?.map((a) => ({ ...a, resources: null })), resources: d.resources ? [] : d.resources };
}

/** Estate: one dashed path per outside identity and account where it can use resources. */
export function estateResourceLinks(sources, has) {
  const out = [];
  for (const s of sources) for (const t of s.targets) {
    if (!t.resources?.length || !has(t.accountId)) continue;
    out.push({ from: s.id, to: t.accountId, kind: resKind(worstRes(t.resources)), vol: 1, at: null, resources: t.resources, resourceCount: t.resourceCount || t.resources.length });
  }
  return out;
}

/**
 * One account: where each exposed resource sits (beside its service's tower, or on an inner ring when the service has
 * none this week), and the fan from each gate to the resources its outsider can use.
 */
export function accountResources(list, towers, gates, sources) {
  const tower = new Map(towers.map((t) => [t.name, t]));
  const seen = new Map();
  const loose = (list || []).filter((r) => !tower.has(r.service));
  const marks = (list || []).map((r) => {
    const t = tower.get(r.service);
    let x, y;
    if (t) {
      const k = seen.get(r.service) || 0; seen.set(r.service, k + 1);
      const a = Math.atan2(t.y, t.x) + (k - 1.5) * 0.55 + Math.floor(k / 6) * 0.27, rad = 26 + 9 * Math.floor(k / 6);
      x = t.x + Math.cos(a) * rad; y = t.y + Math.sin(a) * rad * 0.8;
    } else {
      const i = loose.indexOf(r), a = -Math.PI / 2 + (i / Math.max(1, loose.length)) * Math.PI * 2;
      x = Math.cos(a) * 215; y = Math.sin(a) * 165;
    }
    return { ...r, id: `res:${r.id}`, rid: r.id, x, y, risk: r.worst || 'low', from: [] };
  });
  const byId = new Map(marks.map((m) => [m.rid, m]));
  const links = [];
  for (const g of gates) {
    const s = sources.find((x) => x.id === g.src);
    g.res = [];
    for (const t of s?.targets || []) for (const r of t.resources || []) {
      const m = byId.get(r.id); if (!m) continue;
      g.res.push(m.id); m.from.push(s.id);
      links.push({ from: g.id, to: m.id, kind: 'resfan', src: s.id, risk: r.expected ? 'low' : r.severity, vol: 1 });
    }
  }
  return { marks, links };
}
