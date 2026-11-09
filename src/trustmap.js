// Trust map: who can reach each role from outside it, read from the trust policies.
// Every (statement × principal) of every role becomes one edge: where it comes from (an AWS account, an OIDC provider
// such as GitHub Actions or Bitbucket Pipelines, SAML, Google, an AWS service, or anyone), the conditions on the way
// in, what has actually been seen using it, and what is wrong with it. Edges can be filtered with a small query
// language: `finding:account-root from:123456789012 provider:github -source:service text`.
import { query } from './db.js';
import { scopeSql } from './auth/rbac.js';
import { normalizeStatements, arr } from './analyzer/policy.js';

const SEV_ORDER = { high: 0, medium: 1, low: 2, info: 3, none: 4 };   // 'none' must be ranked, or nothing ever beats it
export const FINDINGS = {
  public: 'Anyone can assume it (principal "*")',
  'not-principal': 'Allow with NotPrincipal: everyone except a list',
  'account-root': 'Trusts a whole AWS account (:root), not a specific role',
  'external-no-externalid': 'Account outside your estate, no sts:ExternalId',
  'oidc-no-sub': 'OIDC trust without a subject (sub) condition',
  'oidc-broad-sub': 'OIDC subject condition is a broad wildcard',
  'oidc-no-aud': 'OIDC trust without an audience (aud) condition',
  'saml-no-aud': 'SAML trust without SAML:aud',
  'iam-user': 'Trusts an IAM user directly (long-lived keys)',
  'deleted-principal': 'Points at a deleted identity (unique ID instead of ARN)',
  'broad-action': 'Allows sts:* or * in a trust policy',
  'never-used': 'Not used in the CloudTrail history read',
  'used-unnamed': 'Used from that account, but which identity is not known yet',
  'used-unattributed': 'Something from another account came in before callers were recorded by account',
};
const ORG_KEYS = /^aws:(principalorgid|principalorgpaths|principalaccount|principalarn|sourceaccount|sourcearn|sourceorgid|principaltag\/)/i;

/** Who an OIDC / SAML / web identity provider is, from the Federated principal. */
export function providerOf(fed) {
  const saml = fed.match(/:saml-provider\/(.+)$/);
  if (saml) return { kind: 'saml', host: null, label: `SAML · ${saml[1]}` };
  const host = (fed.match(/:oidc-provider\/(.+)$/)?.[1] || fed).replace(/^https?:\/\//, '');
  const known = [
    [/^token\.actions\.githubusercontent\.com/, () => 'GitHub Actions', 'high'],
    [/^api\.bitbucket\.org\/2\.0\/workspaces\/([^/]+)\/pipelines-config\/identity\/oidc/, (m) => `Bitbucket Pipelines · ${m[1]}`, 'medium'],
    [/^gitlab\.com/, () => 'GitLab.com', 'high'],
    [/gitlab/, () => `GitLab · ${host.split('/')[0]}`, 'medium'],
    [/^oidc\.eks\.([a-z0-9-]+)\.amazonaws\.com\/id\/([A-Z0-9]+)/, (m) => `EKS · ${m[1]} · ${m[2].slice(0, 8)}`, 'medium'],
    [/^app\.terraform\.io/, () => 'Terraform Cloud', 'high'],
    [/^oidc\.circleci\.com\/org\/([^/]+)/, (m) => `CircleCI · ${m[1].slice(0, 8)}`, 'medium'],
    [/^sts\.windows\.net\/([^/]+)/, (m) => `Azure AD · ${m[1].slice(0, 8)}`, 'medium'],
    [/^agent\.buildkite\.com/, () => 'Buildkite', 'high'],
    [/^accounts\.google\.com$/, () => 'Google', 'high'],
    [/^cognito-identity\.amazonaws\.com$/, () => 'Cognito identity pool', 'medium'],
    [/^graph\.facebook\.com$/, () => 'Facebook', 'high'],
    [/^www\.amazon\.com$/, () => 'Login with Amazon', 'high'],
  ];
  for (const [re, label, noSub] of known) { const m = host.match(re); if (m) return { kind: 'oidc', host, label: label(m), noSubSeverity: noSub }; }
  return { kind: 'oidc', host, label: host.split('/')[0], noSubSeverity: 'high' };
}

const condList = (c) => {
  const out = [];
  for (const [op, kv] of Object.entries(c || {})) for (const [key, val] of Object.entries(kv || {})) out.push({ op, key, values: arr(val).map(String) });
  return out;
};

/** All edges of one role. `ctx` knows which AWS accounts are connected, and what was seen entering the role. */
export function edgesOf(role, ctx) {
  const own = role.aws_account_id;
  const edges = [];
  for (const st of normalizeStatements(role.trust_policy || {})) {
    if (st.effect !== 'Allow') continue;
    const actions = st.actions.length ? st.actions : ['(NotAction)'];
    const conds = condList(st.conditions);
    const condText = conds.map((c) => `${c.key} ${c.op} ${c.values.join(' | ')}`);
    const has = (re) => conds.some((c) => re.test(c.key));
    const pr = st.principal;
    const list = [];
    if (st.notPrincipal) list.push({ type: 'not-principal', raw: JSON.stringify(st.notPrincipal) });
    if (pr === '*') list.push({ type: 'public', raw: '*' });
    else if (pr && typeof pr === 'object') {
      for (const p of arr(pr.AWS)) list.push({ type: 'aws', raw: String(p) });
      for (const p of arr(pr.Service)) list.push({ type: 'service', raw: String(p) });
      for (const p of arr(pr.Federated)) list.push({ type: 'federated', raw: String(p) });
      for (const p of arr(pr.CanonicalUser)) list.push({ type: 'aws', raw: `canonical:${p}` });
    }
    for (const p of list) {
      const e = { roleId: role.id, role: role.name, roleArn: role.arn, accountId: role.account_id, account: role.account_name, awsAccountId: own, environment: role.environment,
        risk: role.risk, granted: role.granted_count, statement: st.index, sid: st.sid, actions, principal: p.raw, conditions: condText, findings: [], seen: [] };
      const f = (id, severity, detail) => e.findings.push({ id, severity, title: FINDINGS[id], detail });
      if (p.type === 'public' || p.raw === '*') {
        Object.assign(e, { type: 'public', group: 'public', source: 'Anyone (principal "*")' });
        f('public', has(ORG_KEYS) ? 'medium' : 'high', has(ORG_KEYS) ? `Relies on conditions alone: ${condText.join('; ')}` : 'No condition narrows it: any AWS identity in any account can assume this role.');
      } else if (p.type === 'not-principal') {
        Object.assign(e, { type: 'public', group: 'public', source: 'Everyone except a list (NotPrincipal)' });
        f('not-principal', 'high', 'AWS recommends never using NotPrincipal with Allow.');
      } else if (p.type === 'service') {
        Object.assign(e, { type: 'service', group: 'service', source: p.raw, provider: p.raw });
      } else if (p.type === 'federated') {
        const pv = providerOf(p.raw);
        const isSaml = pv.kind === 'saml' || st.actions.some((a) => /AssumeRoleWithSAML/i.test(a));
        Object.assign(e, { type: isSaml ? 'saml' : 'oidc', group: isSaml ? 'saml' : 'oidc', source: pv.label, provider: pv.host || p.raw });
        if (isSaml) { if (!has(/^SAML:aud$/i)) f('saml-no-aud', 'low', 'Add SAML:aud = https://signin.aws.amazon.com/saml so assertions meant for other apps are refused.'); }
        else {
          const subs = conds.filter((c) => /:sub$/i.test(c.key) || /^accounts\.google\.com:(sub|oaud)$/i.test(c.key));
          if (!subs.length) f('oidc-no-sub', pv.noSubSeverity || 'high', pv.label === 'GitHub Actions' ? 'Any GitHub repository in the world can get a token for this role. Pin token.actions.githubusercontent.com:sub to your repo and branch.'
            : `Any workload that ${pv.label} issues a token for can assume this role. Add a :sub condition.`);
          for (const c of subs) for (const v of c.values) {
            if (/like/i.test(c.op) && v.includes('*')) {
              const veryBroad = /^\*$|^repo:\*|^repo:[^/:]+\/\*$|^\{[^}]*\}:\*$/.test(v) || v.replace(/[^*]/g, '').length > 1;
              f('oidc-broad-sub', veryBroad ? 'high' : 'medium', `${c.key} ${c.op} ${v}`);
            }
          }
          if (!has(/:aud$/i) && !has(/^accounts\.google\.com:oaud$/i) && pv.label !== 'Google') f('oidc-no-aud', 'low', 'Add an :aud condition (sts.amazonaws.com for most providers).');
        }
      } else {
        // AWS principals: an account (bare or :root), a role, a user, an assumed-role session, or a unique ID
        const raw = p.raw;
        const acct = /^\d{12}$/.test(raw) ? raw : raw.match(/^arn:aws[a-z-]*:(?:iam|sts)::(\d{12}):/)?.[1] || null;
        const kind = /^\d{12}$/.test(raw) || /:root$/.test(raw) ? 'aws-root' : /:role\//.test(raw) ? 'aws-role' : /:user\//.test(raw) ? 'aws-user'
          : /:assumed-role\//.test(raw) ? 'aws-assumed' : /^A[IR]OA[A-Z0-9]{12,}$/.test(raw) ? 'deleted' : 'aws-other';
        const origin = !acct ? 'unknown' : acct === own ? 'same-account' : ctx.connected.has(acct) ? 'connected-account' : 'external-account';
        const acctName = acct === own ? role.account_name : ctx.connected.get(acct);
        Object.assign(e, { type: kind, group: kind === 'deleted' ? 'unknown' : origin, principalAccount: acct, principalAccountName: acctName || null,
          source: kind === 'aws-root' ? `AWS account ${acct}${acctName ? ` (${acctName})` : ''} · whole account` : kind === 'deleted' ? `Deleted identity ${raw}` : raw.replace(/^arn:aws[a-z-]*:(iam|sts)::/, '') });
        if (kind === 'aws-root') {
          const narrowed = has(/^aws:PrincipalArn$/i) || has(/^aws:PrincipalTag\//i);
          // a vendor account's :root with sts:ExternalId is the pattern AWS documents for third parties: lower, not gone
          const vendor = origin === 'external-account' && has(/^sts:ExternalId$/i);
          f('account-root', narrowed ? 'info' : vendor ? 'low' : origin === 'external-account' ? 'high' : 'medium',
            narrowed ? `Narrowed by ${conds.filter((c) => /^aws:Principal(Arn|Tag)/i.test(c.key)).map((c) => `${c.key} ${c.values.join(' | ')}`).join('; ')}`
              : vendor ? `The usual third-party pattern (account root plus sts:ExternalId). Confirm ${acct} is a vendor you still use.`
              : `Any identity in ${acct}${acctName ? ` (${acctName})` : ''} that holds sts:AssumeRole can come in.`);
        }
        if (kind === 'aws-user') f('iam-user', 'low', 'An IAM user means access keys that do not expire. Prefer a role.');
        if (kind === 'deleted') f('deleted-principal', 'medium', 'The identity this statement named was deleted. Recreating one with the same name will not restore access. Remove the statement.');
        if (origin === 'external-account' && !has(/^sts:ExternalId$/i) && !has(/^aws:Principal(OrgID|OrgPaths)$/i)) {
          f('external-no-externalid', kind === 'aws-root' ? 'high' : 'medium', `Account ${acct} is not one of your connected accounts. If it is a third party, require sts:ExternalId to stop the confused-deputy problem.`);
        }
      }
      if (st.actions.some((a) => a === '*' || /^sts:\*$/i.test(a))) f('broad-action', 'low', `Actions: ${st.actions.join(', ')}`);

      // what has been seen coming in through this edge
      const seen = ctx.seen.get(role.id) || [];
      e.seen = seen.filter((s) => matchesSeen(e, s)).map((s) => ({ display: s.display, kind: s.kind, lastSeen: s.last_seen, sessions: s.sessions_count }));
      // Usage is read from THIS account's CloudTrail: an AssumeRole into it is logged here whoever calls, so the caller's
      // account does not need to be onboarded to know a statement was used. Two cases can't be pinned to the statement:
      const fromElsewhere = e.principalAccount && e.principalAccount !== own;
      if (!e.seen.length && fromElsewhere) {
        // 1. the caller's account is known but CloudTrail gave only a unique ID (AROA.../AIDA...), not the role or user name
        const unnamed = seen.filter((s) => (s.key || '').startsWith(`acct:${e.principalAccount}:`));
        // 2. calls recorded before callers were kept by account: one merged "other:AWSAccount" entry, account unknown
        const merged = seen.filter((s) => s.key === 'other:AWSAccount');
        const srcName = e.principalAccountName, srcState = ctx.accountState?.get(e.principalAccount);
        if (unnamed.length) {
          e.seen = unnamed.map((s) => ({ display: `an identity in ${e.principalAccount} (not named yet)`, kind: 'account', lastSeen: s.last_seen, sessions: s.sessions_count, unnamed: true }));
          f('used-unnamed', 'info', srcState === 'connected'
            ? `CloudTrail here names the caller only by its unique ID. Rescan ${srcName || e.principalAccount} so its role IDs are stored, and the next sign-ins are matched to ${e.principal.split('/').pop()}.`
            : `CloudTrail here names the caller only by its unique ID. ${e.principalAccount}${srcState === 'planned' ? ` (${srcName}, planned)` : ''} is not scanned, so the ID cannot be turned into a role name. Onboard it to tell which identity it was.`);
        } else if (merged.length) {
          e.seen = merged.map((s) => ({ display: 'another AWS account (before callers were recorded by account)', kind: 'other', lastSeen: s.last_seen, sessions: s.sessions_count, merged: true }));
          f('used-unattributed', 'info', 'Older scans kept no caller account for cross-account calls, so this may or may not be the statement they came through. New sign-ins are attributed by account; check again after the next scans.');
        }
      }
      if (!e.seen.length && e.type !== 'service' && ctx.complete.has(role.account_id)) {
        const days = ctx.windowDays?.get(role.account_id);
        f('never-used', 'info', `Nothing came in through this statement in ${days ? `the ${days} days of CloudTrail read for ${role.account_name}` : 'the stored history'}. This is read from ${role.account_name}'s own trail, so it holds whether or not the caller's account is onboarded. If nobody needs it, remove it.`);
      }
      e.worst = e.findings.reduce((w, x) => (SEV_ORDER[x.severity] < SEV_ORDER[w] ? x.severity : w), 'none');
      edges.push(e);
    }
  }
  return edges;
}

function matchesSeen(e, s) {
  const key = s.key || '';
  if (e.type === 'public') return s.kind !== 'service';
  if (e.type === 'service') return key === `svc:${e.principal}` || s.display === e.principal;
  // web identity sessions carry the provider host in their principal ID; SAML ones carry the provider name, no host
  if (e.type === 'oidc') return s.kind === 'federated' && key.includes((e.provider || '').split('/')[0] || '#');
  if (e.type === 'saml') return s.kind === 'federated' && !/\.[a-z]{2,}[/:]/i.test(key);
  if (e.type === 'aws-root') return !!e.principalAccount && key.includes(e.principalAccount);
  if (e.type === 'aws-role') { const n = e.principal.split('/').pop(); return key === `role:${e.principalAccount}:${n}`; }
  if (e.type === 'aws-user' || e.type === 'aws-assumed') return key.includes(e.principal) || key.includes(e.principal.split('/').pop());
  return false;
}

// ---------------------------------------------------------------- query language
const KEYS = ['account', 'from', 'source', 'type', 'provider', 'finding', 'severity', 'role', 'cond', 'has', 'no', 'used', 'env'];
export function parseQuery(q) {
  const terms = [];
  const re = /(-?)(\w+):("([^"]*)"|\S+)|"([^"]*)"|(\S+)/g; let m;
  while ((m = re.exec(q || ''))) {
    if (m[2] && KEYS.includes(m[2].toLowerCase())) terms.push({ neg: !!m[1], key: m[2].toLowerCase(), value: (m[4] ?? m[3]).toLowerCase() });
    else terms.push({ neg: false, key: 'text', value: (m[5] ?? m[0]).toLowerCase() });
  }
  return terms;
}
const lc = (s) => String(s ?? '').toLowerCase();
function termMatches(e, t) {
  const v = t.value;
  switch (t.key) {
    case 'account': return lc(e.account).includes(v) || e.awsAccountId === v;
    case 'from': return e.principalAccount === v || lc(e.principalAccountName).includes(v) || lc(e.source).includes(v);
    case 'source': return lc(e.group).startsWith(v) || (v === 'aws' && /account/.test(e.group)) || (v === 'external' && e.group === 'external-account') || (v === 'connected' && e.group === 'connected-account') || (v === 'same' && e.group === 'same-account');
    case 'type': return lc(e.type).replace(/^aws-/, '') === v.replace(/^aws-/, '') || lc(e.type) === v;
    case 'provider': return lc(e.source).includes(v) || lc(e.provider).includes(v);
    case 'finding': return e.findings.some((f) => f.id === v || f.id.startsWith(v));
    case 'severity': return e.findings.some((f) => f.severity === v);
    case 'role': return lc(e.role).includes(v);
    case 'cond': return e.conditions.some((c) => lc(c).includes(v));
    case 'env': return lc(e.environment).startsWith(v);
    case 'has': return v === 'findings' ? e.findings.some((f) => f.severity !== 'info') : v === 'conditions' ? e.conditions.length > 0 : v === 'seen' ? e.seen.length > 0 : false;
    case 'no': return v === 'conditions' ? e.conditions.length === 0 : v === 'findings' ? !e.findings.some((f) => f.severity !== 'info') : v === 'seen' ? e.seen.length === 0 : false;
    case 'used': return v === 'yes' || v === 'true' ? e.seen.length > 0 : e.seen.length === 0;
    default: return [e.role, e.account, e.principal, e.source, ...e.conditions, ...e.findings.map((f) => f.title)].some((s) => lc(s).includes(v));
  }
}
export const matchesQuery = (e, terms) => terms.every((t) => termMatches(e, t) !== t.neg);

// ---------------------------------------------------------------- the whole map, for one viewer
export async function trustMap(user, q = '', { limit = 500 } = {}) {
  const p = [];
  const roles = (await query(
    `SELECT r.id, r.name, r.arn, r.account_id, r.trust_policy, r.risk, r.granted_count, a.name AS account_name, a.account_id AS aws_account_id, a.environment
       FROM roles r JOIN cloud_accounts a ON a.id=r.account_id
      WHERE r.deleted_at IS NULL AND ${scopeSql(user, 'r.account_id', p)}`, p)).rows;
  const connected = new Map((await query('SELECT account_id, name FROM cloud_accounts')).rows.map((a) => [a.account_id, a.name]));
  const seenRows = roles.length ? (await query(
    `SELECT role_id, key, kind, display, last_seen, sessions_count FROM principals WHERE role_id = ANY($1) AND kind <> 'session'`, [roles.map((r) => r.id)])).rows : [];
  const seen = new Map(); for (const s of seenRows) { if (!seen.has(s.role_id)) seen.set(s.role_id, []); seen.get(s.role_id).push(s); }
  const { historyFor } = await import('./history.js');
  const accts = (await query('SELECT * FROM cloud_accounts WHERE id = ANY($1)', [[...new Set(roles.map((r) => r.account_id))]])).rows;
  const hist = await historyFor(accts);
  const complete = new Set([...hist].filter(([, v]) => v.complete).map(([k]) => k));
  const states = (await query('SELECT account_id, status FROM cloud_accounts')).rows;
  const windowDays = new Map([...hist].filter(([, v]) => v.backTo).map(([k, v]) => [k, Math.max(1, Math.round((Date.now() - new Date(v.backTo)) / 864e5))]));
  const ctx = { connected, seen, complete, windowDays, accountState: new Map(states.map((a) => [a.account_id, a.status])) };
  const all = roles.flatMap((r) => edgesOf(r, ctx));
  const terms = parseQuery(q);
  const rows = all.filter((e) => matchesQuery(e, terms))
    .sort((a, b) => (SEV_ORDER[a.worst] ?? 9) - (SEV_ORDER[b.worst] ?? 9) || a.account.localeCompare(b.account) || a.role.localeCompare(b.role));

  // where things come from, grouped, over the rows that matched
  const groups = new Map();
  for (const e of rows) {
    const gk = e.group; if (!groups.has(gk)) groups.set(gk, new Map());
    // the role's own account is one source per kind of principal, not one per account
    const same = e.group === 'same-account';
    const SAME = { 'aws-root': 'Its own account · whole account (:root)', 'aws-role': 'Roles in its own account', 'aws-user': 'IAM users in its own account', 'aws-assumed': 'Role sessions in its own account' };
    const sk = same ? e.type : /account/.test(e.group) ? (e.principalAccount || e.source) : e.source;
    const g = groups.get(gk);
    if (!g.has(sk)) g.set(sk, { key: sk, label: same ? SAME[e.type] || 'Its own account' : e.group.endsWith('account') ? `${e.principalAccount}${e.principalAccountName ? ` · ${e.principalAccountName}` : ''}` : e.source,
      roles: new Set(), accounts: new Set(), edges: 0, findings: 0, worst: 'none', query: queryFor(e) });
    const s = g.get(sk); s.roles.add(e.roleId); s.accounts.add(e.accountId); s.edges++;
    const nf = e.findings.filter((f) => f.severity !== 'info').length; s.findings += nf;
    if ((SEV_ORDER[e.worst] ?? 9) < (SEV_ORDER[s.worst] ?? 9)) s.worst = e.worst;
  }
  const GROUP_ORDER = ['public', 'external-account', 'oidc', 'saml', 'connected-account', 'same-account', 'service', 'unknown'];
  const summary = GROUP_ORDER.filter((g) => groups.has(g)).map((g) => ({ group: g, sources: [...groups.get(g).values()]
    .map((s) => ({ ...s, roles: s.roles.size, accounts: s.accounts.size })).sort((a, b) => (SEV_ORDER[a.worst] ?? 9) - (SEV_ORDER[b.worst] ?? 9) || b.roles - a.roles) }));
  const findingCounts = {};
  for (const e of rows) for (const f of e.findings) findingCounts[f.id] = (findingCounts[f.id] || 0) + 1;
  const ap = [];
  const scoped = (await query(`SELECT id, name, account_id, environment, status FROM cloud_accounts a WHERE ${scopeSql(user, 'a.id', ap)}`, ap)).rows;
  const allAccts = (await query('SELECT id, name, account_id, environment, status FROM cloud_accounts')).rows;
  return { total: rows.length, totalEdges: all.length, roles: new Set(rows.map((e) => e.roleId)).size, rows: rows.slice(0, limit), truncated: rows.length > limit, summary, findingCounts,
    findings: FINDINGS, terms, map: mapOf(rows, scoped, allAccts) };
}

/**
 * The map: who can get into which account. One line per (where it comes from -> account), however many roles and
 * statements are behind it, coloured by the worst finding. Your own connected accounts are nodes, so trust between
 * them is account -> account. Trust from inside the account itself and from AWS services is counted on the account.
 */
const worse = (a, b) => ((SEV_ORDER[a] ?? 9) <= (SEV_ORDER[b] ?? 9) ? a : b);
export function mapOf(rows, scoped, allAccts) {
  const byAws = new Map(allAccts.map((a) => [a.account_id, a]));
  const accounts = new Map(scoped.filter((a) => a.status !== 'planned').map((a) => [a.id, { id: a.id, name: a.name, aws: a.account_id, env: a.environment, planned: false, inScope: true }]));
  const node = (a, inScope) => { if (!accounts.has(a.id)) accounts.set(a.id, { id: a.id, name: a.name, aws: a.account_id, env: a.environment, planned: a.status === 'planned', inScope }); return accounts.get(a.id); };
  for (const a of accounts.values()) Object.assign(a, { inbound: { roles: new Set(), worst: 'none', findings: 0 }, own: new Set(), services: new Set() });
  const ensureCounts = (a) => { if (!a.inbound) Object.assign(a, { inbound: { roles: new Set(), worst: 'none', findings: 0 }, own: new Set(), services: new Set() }); return a; };
  const sources = new Map(), links = new Map();
  for (const e of rows) {
    const to = ensureCounts(accounts.get(e.accountId) || node({ id: e.accountId, name: e.account, account_id: e.awsAccountId, environment: e.environment, status: 'connected' }, true));
    if (e.group === 'same-account') { to.own.add(e.roleId); continue; }
    if (e.group === 'service') { to.services.add(e.roleId); continue; }
    let from;
    const src = e.group === 'connected-account' && byAws.get(e.principalAccount);
    if (src) from = ensureCounts(node(src, false)).id;
    else {
      const key = e.group === 'external-account' ? `acct:${e.principalAccount}` : e.group === 'unknown' ? 'deleted' : `${e.group}:${e.source}`;
      if (!sources.has(key)) sources.set(key, { id: `src:${key}`, group: e.group,
        label: e.group === 'external-account' ? e.principalAccount : e.group === 'unknown' ? 'Deleted identities' : e.source,
        query: queryFor(e), roles: new Set(), accounts: new Set(), worst: 'none', findings: 0, vendor: true, seen: 0 });
      const s = sources.get(key);
      s.roles.add(e.roleId); s.accounts.add(e.accountId); s.worst = worse(s.worst, e.worst);
      s.findings += e.findings.filter((f) => f.severity !== 'info').length;
      if (e.group === 'external-account' && !e.conditions.some((c) => /^sts:ExternalId /i.test(c))) s.vendor = false;
      s.seen += e.seen.reduce((n, x) => n + Number(x.sessions || 0), 0);
      from = s.id;
    }
    const id = `${from}>${e.accountId}`;
    if (!links.has(id)) links.set(id, { id, from, to: e.accountId, kind: from.startsWith('src:') ? 'outside' : 'account', worst: 'none', ways: 0, findings: 0, sessions: 0, roles: new Map(),
      query: `${src ? `from:${e.principalAccount}` : queryFor(e)} account:${e.awsAccountId}` });
    const l = links.get(id);
    l.ways++; l.worst = worse(l.worst, e.worst);
    const nf = e.findings.filter((f) => f.severity !== 'info');
    l.findings += nf.length;
    const sess = e.seen.reduce((n, x) => n + Number(x.sessions || 0), 0);
    l.sessions += sess;
    const r = l.roles.get(e.roleId) || { roleId: e.roleId, role: e.role, worst: 'none', findings: new Map(), conditions: 0, sessions: 0, lastSeen: null, principals: new Set() };
    r.worst = worse(r.worst, e.worst); r.conditions += e.conditions.length; r.sessions += sess; r.principals.add(e.principal);
    for (const f of e.findings) r.findings.set(f.id, { id: f.id, severity: f.severity, title: f.title });
    for (const x of e.seen) if (x.lastSeen && (!r.lastSeen || new Date(x.lastSeen) > new Date(r.lastSeen))) r.lastSeen = x.lastSeen;
    l.roles.set(e.roleId, r);
    to.inbound.roles.add(e.roleId); to.inbound.worst = worse(to.inbound.worst, e.worst); to.inbound.findings += nf.length;
  }
  const ORDER = ['public', 'external-account', 'oidc', 'saml', 'unknown'];
  return {
    accounts: [...accounts.values()].map((a) => ensureCounts(a)).map((a) => ({ ...a, inbound: { roles: a.inbound.roles.size, worst: a.inbound.worst, findings: a.inbound.findings }, own: a.own.size, services: a.services.size })),
    sources: [...sources.values()].map((s) => ({ ...s, roles: s.roles.size, accounts: s.accounts.size, vendor: s.group === 'external-account' && s.vendor }))
      .sort((a, b) => ORDER.indexOf(a.group) - ORDER.indexOf(b.group) || (SEV_ORDER[a.worst] ?? 9) - (SEV_ORDER[b.worst] ?? 9) || b.roles - a.roles),
    links: [...links.values()].map((l) => ({ ...l, roles: [...l.roles.values()]
      .map((r) => ({ ...r, findings: [...r.findings.values()].sort((a, b) => (SEV_ORDER[a.severity] ?? 9) - (SEV_ORDER[b.severity] ?? 9)), principals: [...r.principals].slice(0, 5) }))
      .sort((a, b) => (SEV_ORDER[a.worst] ?? 9) - (SEV_ORDER[b.worst] ?? 9) || a.role.localeCompare(b.role)) })),
  };
}

function queryFor(e) {
  if (e.group === 'same-account') return `source:same type:${e.type.replace(/^aws-/, '')}`;
  if (/account/.test(e.group) && e.principalAccount) return `from:${e.principalAccount}`;
  if (e.group === 'oidc' || e.group === 'saml') return `provider:"${e.source}"`;
  if (e.group === 'service') return `provider:${e.source}`;
  return `source:${e.group}`;
}

export function toCsv(rows) {
  const esc = (v) => `"${String(v ?? '').replace(/"/g, '""')}"`;
  const head = ['account', 'aws_account_id', 'role', 'role_arn', 'statement', 'source_group', 'type', 'source', 'principal', 'conditions', 'findings', 'worst', 'seen'];
  return [head.join(','), ...rows.map((e) => [e.account, e.awsAccountId, e.role, e.roleArn, e.statement, e.group, e.type, e.source, e.principal, e.conditions.join('; '),
    e.findings.map((f) => `${f.severity}:${f.id}`).join('; '), e.worst, e.seen.map((s) => s.display).join('; ')].map(esc).join(','))].join('\n');
}
