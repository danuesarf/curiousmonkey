// IAM Identity Center, as seen from the accounts it signs people in to.
//
// Identity Center creates a SAML provider named AWSSSO_<id>_DO_NOT_DELETE in every account it is given; the <id> is
// different in every account. What is the same is the issuer in the provider's metadata:
//   https://portal.sso.<region>.amazonaws.com/saml/assertion/<base64 of "<account>_ins-<instance>">
// so the issuer says which instance it is, and which account it is managed from. One organisation has one
// organisation instance, so an account that trusts two, or a different one from the rest, deserves a look: an
// "account instance" can be turned on inside a member account, and another organisation's instance could be added.

export const IDC_PROVIDER = /^AWSSSO_[0-9a-f]+_DO_NOT_DELETE$/i;
const ISSUER = /^https:\/\/portal\.sso\.([a-z0-9-]+)\.amazonaws\.com(?:\.cn)?\/saml\/assertion\/([A-Za-z0-9_=+/-]+)$/;

/** The entityID of a SAML metadata document, or null. */
export function samlIssuer(xml) {
  return String(xml || '').match(/<(?:\w+:)?EntityDescriptor\b[^>]*\bentityID\s*=\s*"([^"]+)"/)?.[1] || null;
}

/** Which Identity Center instance an issuer belongs to: { region, id, instance, homeAccount }, or null. */
export function instanceOf(issuer) {
  const m = String(issuer || '').match(ISSUER);
  if (!m) return null;
  let decoded = '';
  try { decoded = Buffer.from(m[2].replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8'); } catch { /* not base64 */ }
  const parts = decoded.match(/^(\d{12})_(ins-[0-9a-z]+)$/);
  return { region: m[1], id: m[2], instance: parts?.[2] || null, homeAccount: parts?.[1] || null };
}

/** Is this SAML provider one Identity Center made? By its name, or by its issuer when the name was changed. */
export const isIdentityCenter = (p) => IDC_PROVIDER.test(p?.name || '') || !!instanceOf(p?.issuer);

/** The key every account's provider for the same instance shares; 'unknown' when the metadata could not be read. */
export const instanceKey = (issuer) => { const i = instanceOf(issuer); return i ? `${i.region}/${i.instance || i.id}` : 'unknown'; };

/** How an instance is labelled on the maps: the same text for the same instance, so they are drawn as one source. */
export function instanceLabel(issuer) {
  const i = instanceOf(issuer);
  if (!i) return 'IAM Identity Center';
  return `IAM Identity Center · ${i.instance || i.id.slice(0, 10)}`;
}

/**
 * Across the estate: which instance each account trusts, and the organisation's own one (the instance most accounts
 * trust, when there is a clear winner). `providers` are rows of saml_providers.
 */
export function identityCenters(providers) {
  const byAccount = new Map(), accountsOf = new Map(), issuers = new Map();
  for (const p of providers) {
    if (!isIdentityCenter(p)) continue;
    const k = instanceKey(p.issuer);
    if (!byAccount.has(p.account_id)) byAccount.set(p.account_id, new Map());
    byAccount.get(p.account_id).set(k, p.issuer || null);
    if (k !== 'unknown') { if (!accountsOf.has(k)) accountsOf.set(k, new Set()); accountsOf.get(k).add(p.account_id); issuers.set(k, p.issuer); }
  }
  const ranked = [...accountsOf].map(([k, s]) => [k, s.size]).sort((a, b) => b[1] - a[1]);
  const primary = ranked.length && (ranked.length === 1 || ranked[0][1] > ranked[1][1]) ? ranked[0][0] : null;
  return { byAccount, primary, issuers, instances: ranked.length };
}
