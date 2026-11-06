// Normalising IAM policy documents. AWS lets almost every field be a string or an array.
import crypto from 'node:crypto';

export const arr = (v) => (v === undefined || v === null ? [] : Array.isArray(v) ? v : [v]);

export function normalizeStatements(doc) {
  const d = typeof doc === 'string' ? JSON.parse(doc) : doc;
  return arr(d?.Statement).map((s, i) => ({
    index: i,
    sid: s.Sid || null,
    effect: s.Effect === 'Deny' ? 'Deny' : 'Allow',
    actions: arr(s.Action),
    notActions: arr(s.NotAction),
    resources: arr(s.Resource),
    notResources: arr(s.NotResource),
    conditions: s.Condition || null,
    principal: s.Principal ?? null,
    notPrincipal: s.NotPrincipal ?? null,
  }));
}

/** Stable hash of a document so we only store a new version when it really changed. */
export function docHash(doc) {
  const canon = (v) => Array.isArray(v) ? v.map(canon)
    : v && typeof v === 'object' ? Object.fromEntries(Object.keys(v).sort().map((k) => [k, canon(v[k])])) : v;
  return crypto.createHash('sha256').update(JSON.stringify(canon(doc))).digest('hex').slice(0, 32);
}

/** Non-whitespace size, which is what IAM measures against the 6,144-character managed policy limit. */
export const policySize = (doc) => JSON.stringify(doc).replace(/\s+/g, '').length;

export const conditionToText = (c) => {
  if (!c) return [];
  const out = [];
  for (const [op, kv] of Object.entries(c)) {
    for (const [key, val] of Object.entries(kv)) out.push(`${key} ${op} ${arr(val).join(' | ')}`);
  }
  return out;
};
