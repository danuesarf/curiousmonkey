// Match a caller against a role's trust policy, so the portal can show the conditions the caller had to meet.
import { normalizeStatements, arr, conditionToText } from './policy.js';

const accountOf = (arn) => arn?.match(/^arn:aws[a-z-]*:(?:iam|sts)::(\d{12}):/)?.[1] || null;
const assumedToRole = (arn) => {   // arn:aws:sts::123:assumed-role/Name/session -> arn:aws:iam::123:role/Name (no path known)
  const m = arn?.match(/^arn:(aws[a-z-]*):sts::(\d{12}):assumed-role\/([^/]+)\//);
  return m ? { account: m[2], name: m[3] } : null;
};

function principalMatches(p, caller) {
  if (p === '*') return { how: 'any principal' };
  const callerAcct = caller.accountId || accountOf(caller.arn);
  if (/^\d{12}$/.test(p)) return callerAcct === p ? { how: `account ${p}` } : null;
  if (p.endsWith(':root')) return accountOf(p) === callerAcct ? { how: `account ${accountOf(p)}` } : null;
  if (caller.arn && p === caller.arn) return { how: 'exact ARN' };
  const a = assumedToRole(caller.arn);
  if (a && p.includes(`:role/`) && p.endsWith(`/${a.name}`) && accountOf(p) === a.account) return { how: 'role session' };
  if (caller.invokedBy && p === caller.invokedBy) return { how: 'AWS service' };
  return null;
}

/**
 * Which trust statement admitted this caller? Success of the AssumeRole call already proves any
 * conditions were satisfied, so we report them as "had to satisfy", not as something we evaluated.
 */
export function matchTrust(trustPolicy, caller, viaAction = 'sts:AssumeRole') {
  for (const st of normalizeStatements(trustPolicy)) {
    if (st.effect !== 'Allow') continue;
    if (!st.actions.some((a) => a === '*' || a.toLowerCase() === viaAction.toLowerCase() || /^sts:\*$/i.test(a))) continue;
    const pr = st.principal || {};
    const candidates = typeof pr === 'string' ? [pr] : [...arr(pr.AWS), ...arr(pr.Service), ...arr(pr.Federated)];
    for (const c of candidates) {
      const m = principalMatches(c, caller);
      if (m) return { matched: true, statement: st.index, principal: c, how: m.how, conditions: conditionToText(st.conditions) };
    }
    if (caller.type === 'WebIdentityUser' || caller.type === 'SAMLUser') {
      const fed = arr(pr.Federated);
      if (fed.length) return { matched: true, statement: st.index, principal: fed[0], how: 'federated', conditions: conditionToText(st.conditions) };
    }
  }
  return { matched: false, conditions: [] };
}

export function trustFindings(trustPolicy) {
  const out = [];
  for (const st of normalizeStatements(trustPolicy)) {
    if (st.effect !== 'Allow') continue;
    const pr = st.principal || {};
    const all = typeof pr === 'string' ? [pr] : [...arr(pr.AWS), ...arr(pr.Service), ...arr(pr.Federated)];
    if (all.includes('*') && !st.conditions) out.push({ key: `stmt${st.index}`, reason: 'Anyone can assume this role: the trust policy allows principal "*" with no condition.', severity: 'high' });
    else if (all.includes('*')) out.push({ key: `stmt${st.index}`, reason: 'Trust policy allows principal "*" and relies on conditions alone to restrict it.', severity: 'medium' });
    for (const p of all) {
      const acct = p.match(/^arn:aws[a-z-]*:iam::(\d{12}):root$/)?.[1];
      if (acct && !st.conditions) out.push({ key: `root${acct}`, reason: `Every identity in account ${acct} that has sts:AssumeRole can assume this role (no condition).`, severity: 'low', external: acct });
    }
  }
  return out;
}
