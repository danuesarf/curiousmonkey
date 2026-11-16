// Trust map: who can reach each role from outside it, read from the trust policies.
// Every (statement × principal) of every role becomes one edge: where it comes from (an AWS account, an OIDC provider
// such as GitHub Actions or Bitbucket Pipelines, SAML, Google, an AWS service, or anyone), the conditions on the way
// in, what has actually been seen using it, and what is wrong with it. Edges can be filtered with a small query
// language: `finding:account-root from:123456789012 provider:github -source:service text`.
import { loadPolicy, severityOf } from './controls.js';
import { parseRule, leaves, evaluate } from './ruleLang.js';
import fs from 'node:fs';
import { query } from './db.js';
import { normalizeStatements, arr } from './analyzer/policy.js';
import { isIdentityCenter, instanceKey, instanceLabel, instanceOf, identityCenters } from './identityCenter.js';
import { toCsv as toCsvRows } from './csv.js';

const SEV_ORDER = { high: 0, medium: 1, low: 2, info: 3, none: 4 };   // 'none' must be ranked, or nothing ever beats it
export const FINDINGS = {
  public: 'Anyone can assume it (principal "*")',
  'not-principal': 'Allow with NotPrincipal: everyone except a list',
  'account-root': 'Trusts a whole AWS account (:root), not a specific role',
  'external-no-externalid': 'Account outside your estate, no sts:ExternalId',
  'oidc-no-sub': 'OIDC trust without a subject (sub) condition',
  'oidc-broad-sub': 'OIDC subject condition is a broad wildcard',
  'oidc-no-aud': 'OIDC trust without an audience (aud) condition',
  'cognito-no-aud': 'Cognito trust without an identity pool (aud) condition',
  'cognito-guest': 'Cognito guests (unauthenticated identities) can assume it',
  'cognito-no-amr': 'Cognito trust without an amr condition: guests and signed-in users alike',
  'saml-no-aud': 'SAML trust without SAML:aud',
  'idc-multiple': 'Account trusts more than one IAM Identity Center',
  'idc-other': 'IAM Identity Center that is not your organisation\'s',
  'idc-unknown': 'IAM Identity Center instance not known yet',
  'iam-user': 'Trusts an IAM user directly (long-lived keys)',
  'deleted-principal': 'Points at a deleted identity (unique ID instead of ARN)',
  'broad-action': 'Allows sts:* or * in a trust policy',
  'never-used': 'Not used in the CloudTrail history read',
  'used-unnamed': 'Used from that account, but which identity is not known yet',
  'used-unattributed': 'Something from another account came in before callers were recorded by account',
  'used-per-iam': 'IAM says the role is used, but no sign-in was tied to this statement',
};
const ORG_KEYS = /^aws:(principalorgid|principalorgpaths|principalaccount|principalarn|sourceaccount|sourcearn|sourceorgid|principaltag\/)/i;

/** Who an OIDC / SAML / web identity provider is, from the Federated principal. */
export function providerOf(fed) {
  const saml = fed.match(/:saml-provider\/(.+)$/);
  if (saml) return { kind: 'saml', host: null, label: `SAML · ${saml[1]}`, pkind: 'saml' };
  const host = (fed.match(/:oidc-provider\/(.+)$/)?.[1] || fed).replace(/^https?:\/\//, '');
  // [pattern, label, severity when there is no :sub condition, what kind of provider (for source:<kind> filters)]
  const known = [
    [/^token\.actions\.githubusercontent\.com/, () => 'GitHub Actions', 'high', 'github'],
    [/^api\.bitbucket\.org\/2\.0\/workspaces\/([^/]+)\/pipelines-config\/identity\/oidc/, (m) => `Bitbucket Pipelines · ${m[1]}`, 'medium', 'bitbucket'],
    [/^gitlab\.com/, () => 'GitLab.com', 'high', 'gitlab'],
    [/gitlab/, () => `GitLab · ${host.split('/')[0]}`, 'medium', 'gitlab'],
    [/^oidc\.eks\.([a-z0-9-]+)\.amazonaws\.com\/id\/([A-Z0-9]+)/, (m) => `EKS · ${m[1]} · ${m[2].slice(0, 8)}`, 'medium', 'eks'],
    [/^app\.terraform\.io/, () => 'Terraform Cloud', 'high', 'terraform'],
    [/^oidc\.circleci\.com\/org\/([^/]+)/, (m) => `CircleCI · ${m[1].slice(0, 8)}`, 'medium', 'circleci'],
    [/^sts\.windows\.net\/([^/]+)/, (m) => `Azure AD · ${m[1].slice(0, 8)}`, 'medium', 'azure'],
    [/^agent\.buildkite\.com/, () => 'Buildkite', 'high', 'buildkite'],
    [/^accounts\.google\.com$/, () => 'Google', 'high', 'google'],
    [/^cognito-identity\.amazonaws\.com$/, () => 'Cognito identity pool', 'medium', 'cognito'],
    [/^graph\.facebook\.com$/, () => 'Facebook', 'high', 'facebook'],
    [/^www\.amazon\.com$/, () => 'Login with Amazon', 'high', 'amazon'],
  ];
  for (const [re, label, noSub, pkind] of known) { const m = host.match(re); if (m) return { kind: 'oidc', host, label: label(m), noSubSeverity: noSub, pkind }; }
  return { kind: 'oidc', host, label: host.split('/')[0], noSubSeverity: 'high', pkind: 'oidc' };
}

const condList = (c) => {
  const out = [];
  for (const [op, kv] of Object.entries(c || {})) for (const [key, val] of Object.entries(kv || {})) out.push({ op, key, values: arr(val).map(String) });
  return out;
};

/**
 * IAM Identity Center: every account's AWSSSO_..._DO_NOT_DELETE provider for one instance gets the same source, so the
 * maps draw the instance once. An account that trusts two instances, or not the one most of your accounts trust,
 * is flagged: another Identity Center can sign people in to these roles without yours ever seeing it.
 */
function identityCenterEdge(e, f, arn, role, ctx) {
  const stored = ctx.saml?.get(`${role.account_id}|${arn}`) || null;
  if (!isIdentityCenter({ name: arn.split('/').pop(), issuer: stored?.issuer })) return;
  const issuer = stored?.issuer || null, key = instanceKey(issuer), inst = instanceOf(issuer);
  Object.assign(e, { source: instanceLabel(issuer), identityCenter: { key, region: inst?.region || null, instance: inst?.instance || null, managedFrom: inst?.homeAccount || null } });
  const idc = ctx.idc;
  if (!issuer) { f('idc-unknown', 'info', 'Give the scanner role iam:ListSAMLProviders and iam:GetSAMLProvider, then scan again, to tell which Identity Center this is.'); return; }
  const mine = [...(idc?.byAccount.get(role.account_id)?.keys() || [])].filter((k) => k !== 'unknown');
  const name = (k) => `${instanceLabel(idc.issuers.get(k))}${instanceOf(idc.issuers.get(k))?.homeAccount ? ` (managed from ${instanceOf(idc.issuers.get(k)).homeAccount})` : ''}`;
  if (mine.length > 1) f('idc-multiple', 'high', `This account trusts ${mine.length} IAM Identity Center instances: ${mine.map(name).join(', ')}. An organisation has one; check who runs the others and remove their AWSSSO provider if it is not yours.`);
  if (idc?.primary && key !== idc.primary) f('idc-other', 'high', `Most of your accounts trust ${name(idc.primary)}; this is ${name(key)}. It may be an account instance turned on inside this account, or another organisation's.`);
}

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
        Object.assign(e, { type: isSaml ? 'saml' : 'oidc', group: isSaml ? 'saml' : 'oidc', source: pv.label, provider: pv.host || p.raw, pkind: isSaml ? 'saml' : pv.pkind });
        if (isSaml) {
          if (!has(/^SAML:aud$/i)) f('saml-no-aud', 'low', 'Add SAML:aud = https://signin.aws.amazon.com/saml so assertions meant for other apps are refused.');
          identityCenterEdge(e, f, p.raw, role, ctx);
          if (e.identityCenter) e.pkind = 'identity-center';
        }
        else if (pv.pkind === 'cognito') {
          // an identity pool is pinned by its ID (aud), and guests are told apart from signed-in users by amr; it has no
          // meaningful subject to pin
          const aud = conds.filter((c) => /^cognito-identity\.amazonaws\.com:aud$/i.test(c.key)).flatMap((c) => c.values);
          const amr = conds.filter((c) => /^cognito-identity\.amazonaws\.com:amr$/i.test(c.key)).flatMap((c) => c.values.map((v) => v.toLowerCase()));
          if (!aud.length) f('cognito-no-aud', 'high', 'Any identity pool, in any account, could hand out credentials for this role. Add cognito-identity.amazonaws.com:aud with your pool ID.');
          if (amr.some((v) => v === 'unauthenticated' || v === '*')) f('cognito-guest', 'medium', 'Anyone using the app without signing in gets these permissions. Keep them to what a guest needs.');
          else if (!amr.length) f('cognito-no-amr', 'low', 'Add cognito-identity.amazonaws.com:amr = authenticated so guests cannot use this role.');
        }
        else {
          if (pv.label === 'Google') {
            // a Google service account named by its unique ID: if it is one Curious Monkey reads, say which
            const ids = conds.filter((c) => /^accounts\.google\.com:(sub|aud|oaud)$/i.test(c.key)).flatMap((c) => c.values).filter((v) => /^\d{15,25}$/.test(v));
            const sa = ids.map((id) => ctx.gcp?.get(id)).find(Boolean);
            if (sa) Object.assign(e, { source: `Google Cloud · ${sa.email}`, gcp: { id: sa.id, email: sa.email, project: sa.project_id, uniqueId: sa.unique_id } });
            else if (ids.length) e.source = `Google · service account ${ids[0]}`;
          }
          const subs = conds.filter((c) => /:sub$/i.test(c.key) || /^accounts\.google\.com:(sub|oaud)$/i.test(c.key));
          if (!subs.length) f('oidc-no-sub', pv.noSubSeverity || 'high', pv.label === 'GitHub Actions' ? 'Any GitHub repository in the world can get a token for this role. Pin token.actions.githubusercontent.com:sub to your repo and branch.'
            : `Any workload that ${pv.label} issues a token for can assume this role. Add a :sub condition.`);
          for (const c of subs) for (const v of c.values) {
            if (!/like/i.test(c.op) || !v.includes('*')) continue;
            if (pv.pkind === 'bitbucket') {
              // Bitbucket's subject is {repository}:{step} or {repository}:{environment}:{step}, and the step changes on
              // every run, so a wildcard after the repository (and environment) is how a role is pinned: not broad
              if (/^\{[^}*]+\}:\{[^}*]+\}:\*$/.test(v)) continue;
              if (/^\{[^}*]+\}:\*$/.test(v)) {
                f('oidc-broad-sub', 'low', `${c.key} ${c.op} ${v}: pinned to one repository, any of its deployment environments. To keep it to one, use {repository}:{environment}:*.`);
                continue;
              }
            }
            const veryBroad = /^\*$|^repo:\*|^repo:[^/:]+\/\*$|^\{[^}]*\}:\*$/.test(v) || v.replace(/[^*]/g, '').length > 1;
            f('oidc-broad-sub', veryBroad ? 'high' : 'medium', `${c.key} ${c.op} ${v}`);
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
          // your own account's root with MFA required (a break-glass role): a person with MFA, not any workload
          const mfa = origin !== 'external-account' && conds.some((c) => /^aws:MultiFactorAuth(Present|Age)$/i.test(c.key) && !c.values.includes('false'));
          // the role's own account: IAM's default delegation, where that account's policies decide who may assume it. Low,
          // unless the role it opens is High risk (an admin role anyone holding sts:AssumeRole can step into): medium.
          // Another of your accounts: every identity there that holds sts:AssumeRole can cross over: medium. Outside: high.
          f('account-root', narrowed ? 'info' : vendor || mfa || (origin === 'same-account' && role.risk !== 'High') ? 'low' : origin === 'external-account' ? 'high' : 'medium',
            narrowed ? `Narrowed by ${conds.filter((c) => /^aws:Principal(Arn|Tag)/i.test(c.key)).map((c) => `${c.key} ${c.values.join(' | ')}`).join('; ')}`
              : vendor ? `The usual third-party pattern (account root plus sts:ExternalId). Confirm ${acct} is a vendor you still use.`
              : mfa ? `Any identity in ${acct}${acctName ? ` (${acctName})` : ''} that holds sts:AssumeRole can come in, but only with MFA. Fine for break-glass; name the roles allowed (aws:PrincipalArn) if you can.`
              : `Any identity in ${acct}${acctName ? ` (${acctName})` : ''} that holds sts:AssumeRole can come in.`);
        }
        if (kind === 'aws-user') f('iam-user', 'low', 'An IAM user means access keys that do not expire. Prefer a role.');
        // nobody can come in through it: clutter to remove, not exposure
        if (kind === 'deleted') f('deleted-principal', 'low', 'The identity this statement named was deleted. Recreating one with the same name will not restore access. Remove the statement.');
        if (origin === 'external-account' && !has(/^sts:ExternalId$/i) && !has(/^aws:Principal(OrgID|OrgPaths)$/i)) {
          f('external-no-externalid', kind === 'aws-root' ? 'high' : 'medium', `Account ${acct} is not one of your connected accounts. If it is a third party, require sts:ExternalId to stop the confused-deputy problem.`);
        }
      }
      if (st.actions.some((a) => a === '*' || /^sts:\*$/i.test(a))) f('broad-action', 'low', `Actions: ${st.actions.join(', ')}`);

      // what has been seen coming in through this edge
      const seen = ctx.seen.get(role.id) || [];
      const subs = e.type === 'oidc' ? conds.filter((c) => /:sub$/i.test(c.key)) : [];
      e.seen = seen.filter((s) => matchesSeen(e, s, subs)).map((s) => ({ key: s.key, display: s.display, kind: s.kind, firstSeen: s.first_seen, lastSeen: s.last_seen, sessions: s.sessions_count }));
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
          e.seen = unnamed.map((s) => ({ key: s.key, display: `an identity in ${e.principalAccount} (not named yet)`, kind: 'account', lastSeen: s.last_seen, sessions: s.sessions_count, unnamed: true }));
          f('used-unnamed', 'info', srcState === 'connected'
            ? `CloudTrail here names the caller only by its unique ID. Rescan ${srcName || e.principalAccount} so its role IDs are stored, and the next sign-ins are matched to ${e.principal.split('/').pop()}.`
            : `CloudTrail here names the caller only by its unique ID. ${e.principalAccount}${srcState === 'planned' ? ` (${srcName}, planned)` : ''} is not scanned, so the ID cannot be turned into a role name. Onboard it to tell which identity it was.`);
        } else if (merged.length) {
          e.seen = merged.map((s) => ({ key: s.key, display: 'another AWS account (before callers were recorded by account)', kind: 'other', lastSeen: s.last_seen, sessions: s.sessions_count, merged: true }));
          f('used-unattributed', 'info', 'Older scans kept no caller account for cross-account calls, so this may or may not be the statement they came through. New sign-ins are attributed by account; check again after the next scans.');
        }
      }
      // IAM's own record (RoleLastUsed, kept ~400 days) is the ground truth for "is this role used at all". When it says
      // yes but CloudTrail tied no sign-in to this statement, say exactly that instead of "never used".
      const lastUsed = role.last_used_at ? new Date(role.last_used_at) : null;
      if (!e.seen.length && e.type !== 'service' && lastUsed) {
        const days = ctx.windowDays?.get(role.account_id);
        const inWindow = !days || Date.now() - lastUsed < days * 864e5;
        e.lastUsed = { at: lastUsed, region: role.last_used_region || null };
        f('used-per-iam', 'info', `IAM last used ${lastUsed.toISOString().slice(0, 10)}${role.last_used_region ? ` in ${role.last_used_region}` : ''}. `
          + (inWindow ? 'No sign-in in the CloudTrail read matched this statement: it may have come through another statement of this role, or been recorded before callers were kept by account. The next scans attribute new sign-ins.'
            : `That is before the ${days} days of CloudTrail read for ${role.account_name}, so which statement it came through is not known. Read further back to find out.`));
      }
      if (!e.seen.length && !e.lastUsed && e.type !== 'service' && ctx.complete.has(role.account_id)) {
        const days = ctx.windowDays?.get(role.account_id);
        f('never-used', 'info', `Nothing came in through this statement in ${days ? `the ${days} days of CloudTrail read for ${role.account_name}` : 'the stored history'}, and IAM has no record of the role being used. This is read from ${role.account_name} itself, so it holds whether or not the caller's account is onboarded. If nobody needs it, remove it.`);
      }
      e.worst = e.findings.reduce((w, x) => (SEV_ORDER[x.severity] < SEV_ORDER[w] ? x.severity : w), 'none');
      // what was seen, summed; the answer carries only the latest few callers (a CI role can have thousands, one per
      // pipeline step). Every caller is kept off the JSON, so lines and sources count each one once per role.
      const all = e.seen;
      e.sessions = all.reduce((n, s) => n + Number(s.sessions || 0), 0);
      e.callerCount = all.length;
      e.lastSeen = all.map((s) => s.lastSeen).filter(Boolean).sort((a, b) => new Date(b) - new Date(a))[0] || null;
      e.firstSeen = all.map((s) => s.firstSeen).filter(Boolean).sort((a, b) => new Date(a) - new Date(b))[0] || null;
      Object.defineProperty(e, 'callers', { value: all.map((s) => [s.key || s.display, Number(s.sessions || 0), s.lastSeen || null]), enumerable: false });
      e.seen = [...all].sort((a, b) => new Date(b.lastSeen || 0) - new Date(a.lastSeen || 0)).slice(0, 3);
      edges.push(e);
    }
  }
  return edges;
}

const globRe = (v) => new RegExp(`^${v.replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*').replace(/\?/g, '.')}$`, 'i');
/**
 * A web identity sign-in is recorded with a principal ID of `<provider ARN>:<audience>:<subject>`. It came through this
 * statement when the provider is the statement's (its whole path: one EKS cluster, one Bitbucket workspace) and the
 * subject passes the statement's :sub conditions, so one repository's sign-ins don't vouch for another's statement.
 */
function oidcSeen(e, key, subs) {
  const path = e.provider || '';
  const at = path ? key.indexOf(path) : -1;
  if (at < 0) return false;
  const rest = key.slice(at + path.length);
  if (rest && rest[0] !== ':') return false;                  // a longer provider path that starts the same way
  for (const c of subs) {
    const like = /like/i.test(c.op), not = /^StringNot/i.test(c.op);
    const hit = c.values.some((v) => (like ? globRe(`*:${v}`).test(rest) : rest.endsWith(`:${v}`)));
    if (hit === not) return false;
  }
  return true;
}

function matchesSeen(e, s, subs = []) {
  const key = s.key || '';
  if (e.type === 'public') return s.kind !== 'service';
  if (e.type === 'service') return key === `svc:${e.principal}` || s.display === e.principal;
  // web identity sessions carry the provider path in their principal ID; SAML ones carry the provider name, no host
  if (e.type === 'oidc') return s.kind === 'federated' && oidcSeen(e, key, subs);
  if (e.type === 'saml') return s.kind === 'federated' && !/\.[a-z]{2,}[/:]/i.test(key);
  if (e.type === 'aws-root') return !!e.principalAccount && key.includes(e.principalAccount);
  if (e.type === 'aws-role') { const n = e.principal.split('/').pop(); return key === `role:${e.principalAccount}:${n}`; }
  if (e.type === 'aws-user' || e.type === 'aws-assumed') return key.includes(e.principal) || key.includes(e.principal.split('/').pop());
  return false;
}

// ---------------------------------------------------------------- query language
// key:value terms, all of which must match; a comma inside a value means either (finding:public,account-root), a
// leading - excludes, quotes keep spaces, anything else is free text
export const KEYS = ['account', 'from', 'source', 'type', 'provider', 'finding', 'severity', 'role', 'roleid', 'cond', 'has', 'no', 'used', 'env', 'attention', 'expected', 'decided', 'new', 'fromenv'];
// source: also takes the kind of identity provider
export const PROVIDER_KINDS = ['github', 'bitbucket', 'gitlab', 'eks', 'terraform', 'circleci', 'azure', 'buildkite', 'google', 'cognito', 'facebook', 'amazon', 'identity-center'];
export function parseQuery(q) {
  const terms = [];
  const re = /(-?)(\w+):("([^"]*)"|\S+)|"([^"]*)"|(\S+)/g; let m;
  while ((m = re.exec(q || ''))) {
    if (m[2] && KEYS.includes(m[2].toLowerCase())) {
      const value = (m[4] ?? m[3]).toLowerCase();
      terms.push({ neg: !!m[1], key: m[2].toLowerCase(), value, values: value.split(',').map((x) => x.trim()).filter(Boolean) });
    } else terms.push({ neg: false, key: 'text', value: (m[5] ?? m[0]).toLowerCase(), values: [(m[5] ?? m[0]).toLowerCase()] });
  }
  return terms;
}
const lc = (s) => String(s ?? '').toLowerCase();
const yes = (v) => !['no', 'false', '0'].includes(v);
function valueMatches(e, key, v) {
  switch (key) {
    case 'account': return lc(e.account).includes(v) || e.awsAccountId === v || e.accountId === v;
    case 'from': return e.principalAccount === v || lc(e.principalAccountName).includes(v) || lc(e.source).includes(v) || lc(e.named?.name).includes(v);
    case 'source': return PROVIDER_KINDS.includes(v) ? e.pkind === v
      : lc(e.group).startsWith(v) || (v === 'aws' && /account/.test(e.group)) || (v === 'external' && e.group === 'external-account') || (v === 'connected' && e.group === 'connected-account') || (v === 'same' && e.group === 'same-account');
    case 'type': return lc(e.type).replace(/^aws-/, '') === v.replace(/^aws-/, '') || lc(e.type) === v;
    case 'provider': return lc(e.source).includes(v) || lc(e.provider).includes(v);
    case 'finding': return e.findings.some((f) => f.id === v || f.id.startsWith(v));
    case 'severity': return e.findings.some((f) => f.severity === v);
    case 'role': return lc(e.role).includes(v);
    case 'roleid': return String(e.roleId) === v; // one role exactly, for links from its page
    case 'cond': return e.conditions.some((c) => lc(c).includes(v));
    case 'env': return lc(e.environment).startsWith(v);
    // the environment of the account it comes from, when that is one of yours
    case 'fromenv': return !!e.fromEnv && lc(e.fromEnv).startsWith(v);
    case 'has': if (v === 'admin') return !!e.admin; if (v === 'name') return !!e.named; if (v === 'org') return !!e.inOrg;
      return v === 'findings' ? e.findings.some((f) => f.severity !== 'info') : v === 'conditions' ? e.conditions.length > 0 : v === 'seen' ? e.seen.length > 0 : false;
    case 'no': if (v === 'admin') return !e.admin; if (v === 'name') return !e.named;
      return v === 'conditions' ? e.conditions.length === 0 : v === 'findings' ? !e.findings.some((f) => f.severity !== 'info') : v === 'seen' ? e.seen.length === 0 : false;
    // yes: a sign-in came through it · iam: none did, but IAM says the role is used · no: neither
    case 'used': return v === 'yes' || v === 'true' ? e.seen.length > 0 : v === 'iam' ? !e.seen.length && !!e.lastUsed : !e.seen.length && !e.lastUsed;
    // review state: needs attention (an open high or medium finding), expected, every finding decided
    case 'attention': return yes(v) === !!e.attention;
    case 'expected': return v === 'due' ? !!e.expectedDue : yes(v) === !!e.expected;
    case 'decided': return v === 'accepted' ? !!e.accepted : yes(v) === !!e.decided;
    // new:7 (or new:yes): a way in that appeared, or lost a guard, in that many days; new:weakened only the latter
    case 'new': {
      if (!e.change) return false;
      if (v === 'weakened' || v === 'guard') return e.change.kind === 'weakened';
      const days = /^\d+$/.test(v) ? Number(v) : 7;
      return Date.now() - new Date(e.change.at) <= days * 864e5;
    }
    default: return [e.role, e.account, e.principal, e.source, e.named?.name, e.named?.owner, ...e.conditions, ...e.findings.map((f) => f.title)].some((s) => lc(s).includes(v));
  }
}
// ---------------------------------------------------------------- rules about ways in (Manage policy)
// keys that describe the review, not the trust: a control may not use them
export const WAYIN_REVIEW_KEYS = ['attention', 'expected', 'decided', 'severity', 'finding', 'roleid'];
const WAYIN_ALIAS = { environment: 'env' };
/**
 * A rule about ways in: the keys of the Trust map's filter, joined with AND, OR, NOT and brackets, with = and !=.
 * Returns { errors, test }: test(e) says whether a way in matches.
 */
export function compileWayIn(rule) {
  const { ast, errors } = parseRule(rule);
  if (errors.length) return { errors, test: () => false };
  if (!ast) return { errors: ['Write at least one term: an empty rule would match every way in.'], test: () => false };
  const terms = [];
  for (const l of leaves(ast)) {
    if (l.t === 'text') { l.values = [l.value.toLowerCase()]; l.k = 'text'; continue; }
    l.k = WAYIN_ALIAS[l.key] || l.key;
    if (WAYIN_REVIEW_KEYS.includes(l.k)) { errors.push(`${l.key} describes the review, not the trust, so a control cannot use it.`); continue; }
    if (!KEYS.includes(l.k)) { errors.push(`No key called "${l.key}" for ways in. The keys: ${KEYS.filter((k) => !WAYIN_REVIEW_KEYS.includes(k)).join(', ')}.`); continue; }
    if (l.op !== '=' && l.op !== '!=') { errors.push(`${l.key} takes = or !=, not ${l.op}.`); continue; }
    l.values = l.values.map((v) => v.toLowerCase());
    terms.push({ key: l.k, value: l.values[0], values: l.values, neg: false });
  }
  errors.push(...queryWarnings(terms));
  if (errors.length) return { errors: [...new Set(errors)], test: () => false };
  return { errors: [], test: (e) => evaluate(ast, (l) => l.values.some((v) => valueMatches(e, l.k, v)) !== (l.op === '!=')) };
}

const termMatches = (e, t) => (t.values?.length ? t.values : [t.value]).some((v) => valueMatches(e, t.key, v));
export const matchesQuery = (e, terms) => terms.every((t) => termMatches(e, t) !== t.neg);

const distance = (a, b) => {
  const d = Array.from({ length: a.length + 1 }, (_, i) => [i, ...Array(b.length).fill(0)]);
  for (let j = 1; j <= b.length; j++) d[0][j] = j;
  for (let i = 1; i <= a.length; i++) for (let j = 1; j <= b.length; j++) d[i][j] = Math.min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
  return d[a.length][b.length];
};
const closest = (word, list) => { const best = list.map((x) => [x, distance(word, x)]).sort((a, b) => a[1] - b[1])[0]; return best && best[1] <= Math.max(2, Math.floor(word.length / 4)) ? best[0] : null; };
/** What in a query was not understood, in words: an unknown key (searched as text instead) or an unknown finding. */
export function queryWarnings(terms) {
  const out = [];
  for (const t of terms) {
    const m = t.key === 'text' && t.value.match(/^-?(\w+):(.+)$/);
    if (m && !KEYS.includes(m[1])) {
      const near = closest(m[1], KEYS);
      out.push(near ? `No filter called "${m[1]}", so it was searched as text. Did you mean ${near}:${m[2]}?` : `No filter called "${m[1]}", so "${t.value}" was searched as text.`);
    }
    if (t.key === 'finding') for (const v of t.values) {
      if (v.startsWith('custom') || v.startsWith('rule.')) continue;   // a control that is a rule, by its id
      if (Object.keys(FINDINGS).some((id) => id === v || id.startsWith(v))) continue;
      const near = closest(v, Object.keys(FINDINGS));
      out.push(near ? `No finding called "${v}". Did you mean ${near}?` : `No finding called "${v}".`);
    }
    if (t.key === 'used') for (const v of t.values) if (!['yes', 'true', 'iam', 'no', 'false'].includes(v)) out.push(`used: takes yes, iam or no, not "${v}".`);
    if (['attention', 'expected', 'decided'].includes(t.key)) for (const v of t.values) if (!['yes', 'no', 'true', 'false', 'due', 'accepted'].includes(v)) out.push(`${t.key}: takes yes or no, not "${v}".`);
  }
  return out;
}

// ---------------------------------------------------------------- review: what changed, what is expected, what was decided
const GUARDS = [[/^sts:ExternalId$/i, 'ExternalId'], [/:sub$/i, 'subject'], [/:aud$/i, 'audience'], [/:amr$/i, 'amr'], [/^aws:MultiFactorAuth(Present|Age)$/i, 'MFA'],
  [/^aws:Principal(OrgID|OrgPaths)$/i, 'organisation'], [/^aws:PrincipalArn$/i, 'principal ARN'], [/^aws:PrincipalTag\//i, 'principal tag'], [/^aws:SourceIp$/i, 'source IP'],
  [/^SAML:aud$/i, 'SAML audience']];
const guardOf = (key) => GUARDS.find(([re]) => re.test(key))?.[1] || null;
/** Every principal a trust policy lets in (as the edges name them), with the guards its statements put on it. */
export function principalsOf(doc) {
  const out = new Map();
  for (const st of normalizeStatements(doc || {})) {
    if (st.effect !== 'Allow') continue;
    const pr = st.principal, list = [];
    if (pr === '*') list.push('*');
    else if (pr && typeof pr === 'object') for (const k of ['AWS', 'Service', 'Federated', 'CanonicalUser']) for (const p of arr(pr[k])) list.push(k === 'CanonicalUser' ? `canonical:${p}` : String(p));
    if (st.notPrincipal) list.push(JSON.stringify(st.notPrincipal));
    const guards = new Set(condList(st.conditions).map((c) => guardOf(c.key)).filter(Boolean));
    for (const p of list) { const g = out.get(p) || new Set(); for (const x of guards) g.add(x); out.set(p, g); }
  }
  return out;
}
/** What a trust policy change did to its ways in: principals let in that were not before, and guards taken off. */
export function trustChanges(before, after) {
  const b = principalsOf(before), a = principalsOf(after), out = new Map();
  for (const [p, g] of a) {
    if (!b.has(p)) out.set(p, { kind: 'new' });
    else { const lost = [...b.get(p)].filter((x) => !g.has(x)); if (lost.length) out.set(p, { kind: 'weakened', guards: lost }); }
  }
  return out;
}
/** The id a way in comes from, for every way in (also those the map counts on the account instead of drawing). */
export const sourceKeyOf = (e, byAws) => fromOf(e, byAws) || (e.group === 'service' ? `svc:${e.principal}` : e.group === 'same-account' ? `same:${e.type}` : `src:${e.group}:${e.source}`);
/** A trust finding is filed once per role, statement, principal and kind of finding. */
export const flagKey = (e, findingId) => `${e.statement}|${e.principal}|${findingId}`.slice(0, 900);
const ACCEPT = new Set(['accept']);
const globMatch = (pattern, v) => (!pattern || pattern === '*' ? true : globRe(pattern).test(v));
/** Does an expected-trust rule cover this way in? Only with the findings it was accepted with, and before its review date. */
export function coveredBy(rule, e, key, today = new Date()) {
  if (rule.source !== key || !globMatch(rule.roles, e.role)) return null;
  if (rule.accounts?.length && !rule.accounts.includes(e.awsAccountId)) return null;
  const extra = e.findings.filter((f) => f.severity !== 'info' && !rule.findings.includes(f.id));
  if (extra.length) return null;
  const due = rule.review_by && new Date(rule.review_by) < new Date(today.toISOString().slice(0, 10));
  return due ? 'due' : 'yes';
}

// known vendors' AWS account IDs (fwdcloudsec/known_aws_accounts, Apache-2.0; see THIRD_PARTY_NOTICES.md)
let vendors = null;
export function knownVendor(accountId) {
  if (!vendors) {
    try { vendors = JSON.parse(fs.readFileSync(new URL('./data/known-aws-accounts.json', import.meta.url), 'utf8')).accounts || {}; } catch { vendors = {}; }
  }
  return vendors[accountId] || null;
}
/** A role that can do this many things is treated as an administrator, as Radar does. */
export const ADMIN_AT = 15000;

const worstOf = (findings) => findings.reduce((w, x) => (SEV_ORDER[x.severity] < SEV_ORDER[w] ? x.severity : w), 'none');

async function annotate(edges, roles, byAws, custom = []) {
  // names the workspace gave to where trust comes from, and known vendors
  const names = new Map((await query(`SELECT s.*, u.name AS updated_by_name FROM trust_sources s LEFT JOIN users u ON u.id = s.updated_by`).catch(() => ({ rows: [] }))).rows.map((x) => [x.source, x]));
  // what the scanner read around the trust policies: EKS cluster names, the organisation's accounts, Identity Center
  const clusters = new Map((await query(`SELECT name, region, oidc_issuer FROM eks_clusters WHERE oidc_issuer IS NOT NULL`).catch(() => ({ rows: [] }))).rows
    .map((x) => [x.oidc_issuer.replace(/^https:\/\//, ''), x]));
  const org = new Map((await query(`SELECT account_id, name, status FROM org_accounts`).catch(() => ({ rows: [] }))).rows.map((x) => [x.account_id, x]));
  const idc = new Map();
  for (const x of (await query(`SELECT account_id, permission_set, principal_type, principal_name, principal_id FROM idc_assignments ORDER BY principal_type, principal_name`).catch(() => ({ rows: [] }))).rows) {
    const k = `${x.account_id}|${x.permission_set}`;
    if (!idc.has(k)) idc.set(k, []);
    idc.get(k).push({ type: x.principal_type === 'GROUP' ? 'group' : 'user', name: x.principal_name || x.principal_id });
  }
  const DAY = 864e5, now = Date.now();
  // what changed in the last 30 days: from the trust policy before and after each change, and roles created since
  const changes = new Map();                              // roleId -> principal -> { kind, at, guards }
  const ev = (await query(`SELECT role_id, at, detail FROM identity_events WHERE kind = 'trust-changed' AND at >= now() - interval '30 days' ORDER BY at`).catch(() => ({ rows: [] }))).rows;
  for (const x of ev) {
    const m = changes.get(x.role_id) || new Map();
    for (const [p, c] of trustChanges(x.detail?.before, x.detail?.after)) m.set(p, { ...c, at: x.at });
    changes.set(x.role_id, m);
  }
  for (const r of roles) {
    if (!r.created_in_aws || now - new Date(r.created_in_aws) > 30 * DAY) continue;
    const m = changes.get(r.id) || new Map();
    for (const p of principalsOf(r.trust_policy).keys()) if (!m.has(p)) m.set(p, { kind: 'new', at: r.created_in_aws, roleCreated: true });
    changes.set(r.id, m);
  }
  const rules = (await query(`SELECT e.*, u.name AS created_by_name FROM trust_expected e LEFT JOIN users u ON u.id = e.created_by`).catch(() => ({ rows: [] }))).rows;
  const flags = new Map((await query(`SELECT f.id, f.role_id, f.key, f.status, d.decision, d.note, d.decided_at, u.name AS decided_by
      FROM flags f LEFT JOIN review_decisions d ON d.flag_id = f.id LEFT JOIN users u ON u.id = d.decided_by WHERE f.category = 'trust'`).catch(() => ({ rows: [] }))).rows
    .map((f) => [`${f.role_id}|${f.key}`, f]));
  for (const e of edges) {
    const c = changes.get(e.roleId)?.get(e.principal);
    if (c) e.change = c;
    const key = sourceKeyOf(e, byAws);
    e.sourceKey = key;
    const n = names.get(key), vendor = e.group === 'external-account' ? knownVendor(e.principalAccount) : null;
    const mine = e.group === 'external-account' ? org.get(e.principalAccount) : null;
    if (mine) e.inOrg = { name: mine.name, status: mine.status };
    if (n || vendor || mine) e.named = { name: n?.name || mine?.name || vendor, owner: n?.owner || null, purpose: n?.purpose || null, reviewBy: n?.review_by || null, vendor, inOrg: !!mine, custom: !!n, by: n?.updated_by_name || null };
    if (e.pkind === 'eks') {
      const cl = clusters.get(e.provider);
      if (cl) { e.cluster = cl.name; e.source = `EKS · ${cl.name}`; }
    }
    if (e.pkind === 'identity-center') {
      const ps = /^AWSReservedSSO_(.+)_[0-9a-f]+$/.exec(e.role)?.[1];
      const who = ps ? idc.get(`${e.awsAccountId}|${ps}`) : null;
      if (who) e.idc = { permissionSet: ps, count: who.length, who: who.slice(0, 12) };
    }
    e.admin = Number(e.granted || 0) >= ADMIN_AT;
    e.fromEnv = byAws.get(e.principalAccount)?.environment || null;
    for (const cc of custom) {
      if (e.group === 'service' || !cc.test(e)) continue;
      e.findings.push({ id: cc.id, severity: cc.severity, title: cc.name, detail: cc.description || `Matches the rule: ${cc.rule}`, fix: cc.remediation || null, rule: true });
    }
    if (custom.length) e.worst = worstOf(e.findings);
    for (const r of rules) {
      const hit = coveredBy(r, e, key);
      if (!hit) continue;
      if (hit === 'due') { e.expectedDue = { id: r.id, note: r.note, reviewBy: r.review_by }; continue; }
      e.expected = { id: r.id, note: r.note, by: r.created_by_name || null, at: r.created_at, reviewBy: r.review_by };
      break;
    }
    e.flags = e.findings.filter((f) => f.severity === 'high' || f.severity === 'medium').map((f) => {
      const x = flags.get(`${e.roleId}|${flagKey(e, f.id)}`);
      return x ? { id: x.id, finding: f.id, status: x.status, decision: x.decision || null, note: x.note || null, by: x.decided_by || null, at: x.decided_at || null } : { id: null, finding: f.id };
    });
    e.decided = e.flags.length > 0 && e.flags.every((f) => f.decision);
    e.accepted = e.decided && e.flags.every((f) => ACCEPT.has(f.decision));
    // needs attention: a high or medium finding nobody has accepted or marked as expected
    e.attention = (e.worst === 'high' || e.worst === 'medium') && !e.expected && !e.accepted;
  }
}

// ---------------------------------------------------------------- every way in, kept between requests
// Working out the ways in reads every role's trust policy and every caller recorded, so it is done once and kept. A
// signature of what it is read from (roles, callers, accounts, SAML providers, Google service accounts, history read)
// is checked on each request, a few milliseconds; when it changes the ways in are worked out again, once, however many
// requests arrive meanwhile. The hour is part of it: "not used in N days" moves with the clock.
const SIGNATURE = `SELECT concat_ws('|',
    (SELECT count(*) || ':' || coalesce(sum(hashtext(id::text || name || coalesce(trust_policy::text, '') || coalesce(last_used_at::text, '') || coalesce(deleted_at::text, '') || coalesce(created_in_aws::text, '')
                                                || coalesce(risk, '') || coalesce(granted_count::text, ''))::bigint), 0) FROM roles),
    (SELECT count(*) || ':' || coalesce(sum(sessions_count), 0) || ':' || coalesce(max(last_seen)::text, '') FROM principals WHERE kind <> 'session'),
    (SELECT string_agg(id::text || account_id || name || status || coalesce(environment, '') || array_to_string(regions, ','), ';' ORDER BY id) FROM cloud_accounts),
    (SELECT count(*) || ':' || coalesce(sum(hashtext(account_id::text || arn || coalesce(issuer, ''))::bigint), 0) FROM saml_providers),
    (SELECT count(*) || ':' || coalesce(max(last_event_time)::text, '') || coalesce(max(caught_up_at)::text, '') || coalesce(min(first_event_time)::text, '') FROM scan_checkpoints),
    (SELECT count(*) || ':' || coalesce(sum(hashtext(unique_id || coalesce(email, '') || coalesce(project_id, ''))::bigint), 0) FROM gcp_principals WHERE unique_id IS NOT NULL),
    (SELECT count(*) || ':' || coalesce(max(updated_at)::text, '') FROM flags WHERE category = 'trust'),
    (SELECT count(*) || ':' || coalesce(max(decided_at)::text, '') FROM review_decisions),
    (SELECT count(*) || ':' || coalesce(sum(hashtext(id::text || roles || array_to_string(accounts, ',') || array_to_string(findings, ',') || note || coalesce(review_by::text, '')))::bigint, 0) FROM trust_expected),
    (SELECT coalesce(max(id), 0) FROM identity_events),
    (SELECT count(*) || ':' || coalesce(max(updated_at)::text, '') FROM trust_sources),
    (SELECT count(*) || ':' || coalesce(max(seen_at)::text, '') FROM eks_clusters),
    (SELECT count(*) || ':' || coalesce(max(seen_at)::text, '') FROM org_accounts),
    (SELECT count(*) || ':' || coalesce(max(seen_at)::text, '') FROM idc_assignments),
    (SELECT count(*) || ':' || coalesce(max(updated_at)::text, '') || ':' || coalesce(sum(hashtext(control_id || coalesce(severity, '') || enabled::text))::bigint, 0) FROM control_overrides),
    (SELECT count(*) || ':' || coalesce(max(updated_at)::text, '') FROM custom_controls),
    to_char(now(), 'YYYY-MM-DD HH24')) AS sig`;
let index = null, pending = null;

async function buildIndex(sig) {
  const roles = (await query(
    `SELECT r.id, r.name, r.arn, r.account_id, r.trust_policy, r.risk, r.granted_count, r.last_used_at, r.last_used_region, r.created_in_aws, a.name AS account_name, a.account_id AS aws_account_id, a.environment
       FROM roles r JOIN cloud_accounts a ON a.id=r.account_id WHERE r.deleted_at IS NULL AND r.kind <> 'iam-user'`)).rows;
  const accounts = (await query('SELECT * FROM cloud_accounts')).rows;
  const seenRows = roles.length ? (await query(
    `SELECT role_id, key, kind, display, first_seen, last_seen, sessions_count FROM principals WHERE role_id = ANY($1) AND kind <> 'session'`, [roles.map((r) => r.id)])).rows : [];
  const seen = new Map(); for (const s of seenRows) { if (!seen.has(s.role_id)) seen.set(s.role_id, []); seen.get(s.role_id).push(s); }
  const { historyFor } = await import('./history.js');
  const hist = await historyFor(accounts.filter((a) => roles.some((r) => r.account_id === a.id)));
  const complete = new Set([...hist].filter(([, v]) => v.complete).map(([k]) => k));
  const windowDays = new Map([...hist].filter(([, v]) => v.backTo).map(([k, v]) => [k, Math.max(1, Math.round((Date.now() - new Date(v.backTo)) / 864e5))]));
  // SAML providers of every account: which Identity Center is the organisation's is decided across the estate
  const samlRows = (await query('SELECT account_id, arn, name, issuer FROM saml_providers')).rows;
  // Google service accounts by unique ID, so a role that trusts one names it (hidden again from scoped members on read)
  const gcpRows = (await query(`SELECT DISTINCT ON (unique_id) id, unique_id, email, project_id FROM gcp_principals WHERE unique_id IS NOT NULL`).catch(() => ({ rows: [] }))).rows;
  const ctx = { connected: new Map(accounts.map((a) => [a.account_id, a.name])), seen, complete, windowDays, accountState: new Map(accounts.map((a) => [a.account_id, a.status])),
    saml: new Map(samlRows.map((x) => [`${x.account_id}|${x.arn}`, x])), idc: identityCenters(samlRows), gcp: new Map(gcpRows.map((x) => [x.unique_id, x])) };
  const edges = roles.flatMap((r) => edgesOf(r, ctx));
  // the workspace's policy (Manage policy): a control turned off is not a finding; one given a severity gets it
  const policy = await loadPolicy();
  if (policy.over.size) for (const e of edges) {
    e.findings = e.findings.flatMap((f) => { const severity = severityOf(policy, `trust.${f.id}`, f.severity); return severity ? [{ ...f, severity }] : []; });
    e.worst = worstOf(e.findings);
  }
  const byAws = new Map(accounts.map((a) => [a.account_id, a]));
  // custom controls about ways in: the Trust map's own query language, each match a finding
  const custom = policy.rules.filter((x) => x.target === 'way-in').map((x) => ({ ...x, ...compileWayIn(x.rule) })).filter((x) => !x.errors.length);
  await annotate(edges, roles, byAws, custom);
  edges.sort((a, b) => (SEV_ORDER[a.worst] ?? 9) - (SEV_ORDER[b.worst] ?? 9) || a.account.localeCompare(b.account) || a.role.localeCompare(b.role));
  return { sig, at: new Date(), edges, customTitles: Object.fromEntries(custom.map((x) => [x.id, x.name])), accounts: accounts.map((a) => ({ id: a.id, name: a.name, account_id: a.account_id, environment: a.environment, status: a.status })) };
}

// while the Trust map is in use, look for changes every minute, so a rebuild rarely waits for a request
let lastAsked = 0, warmer = null;
const WARM_MS = 60_000, WARM_FOR_MS = 15 * 60_000;
function keepWarm() {
  lastAsked = Date.now();
  if (warmer || process.env.CACHE_FRESH_MS === '0') return;
  warmer = setInterval(() => {
    if (Date.now() - lastAsked > WARM_FOR_MS) { clearInterval(warmer); warmer = null; return; }
    check().catch(() => {});
  }, WARM_MS).unref();
}

/** Every way in across the estate, worst first, and the accounts; worked out again only when the data behind it changed. */
export async function trustIndex() {
  keepWarm();
  return check();
}
async function check() {
  const { sig } = (await query(SIGNATURE)).rows[0];
  if (index?.sig === sig) return index;
  if (pending?.sig === sig) return pending.p;
  const p = buildIndex(sig).then((x) => { if (!index || x.at >= index.at) index = x; return x; }).finally(() => { if (pending?.p === p) pending = null; });
  pending = { sig, p };
  return p;
}
export const clearTrustIndex = () => { index = null; pending = null; };

/** Expected trust, with how many ways in each rule covers now (and how many it would, but its review date passed). */
export async function expectedRules(user) {
  const ix = await trustIndex();
  const scope = user?.scope_accounts ? new Set(user.scope_accounts) : null;
  const awsIn = scope ? new Set(ix.accounts.filter((a) => scope.has(a.id)).map((a) => a.account_id)) : null;
  const covers = new Map(), due = new Map();
  for (const e of ix.edges) {
    if (scope && !scope.has(e.accountId)) continue;
    if (e.expected) covers.set(e.expected.id, (covers.get(e.expected.id) || 0) + 1);
    if (e.expectedDue) due.set(e.expectedDue.id, (due.get(e.expectedDue.id) || 0) + 1);
  }
  const rows = (await query(`SELECT e.*, u.name AS created_by_name FROM trust_expected e LEFT JOIN users u ON u.id = e.created_by ORDER BY e.created_at DESC`)).rows;
  return rows.filter((r) => !awsIn || (r.accounts.length && r.accounts.every((a) => awsIn.has(a))) || covers.has(r.id))
    .map((r) => ({ id: r.id, source: r.source, sourceLabel: r.source_label, roles: r.roles, accounts: r.accounts, findings: r.findings, note: r.note,
      reviewBy: r.review_by, createdBy: r.created_by_name, createdAt: r.created_at, covers: covers.get(r.id) || 0, due: due.get(r.id) || 0 }));
}

// Google Cloud is shown to unscoped members only: for the others a trusted service account keeps its ID, not its name
export function forViewer(e, user) {
  if (!user?.scope_accounts || !e.gcp) return e;
  const out = { ...e, source: `Google · service account ${e.gcp.uniqueId}` };
  delete out.gcp;
  Object.defineProperty(out, 'callers', { value: e.callers, enumerable: false });
  return out;
}

/**
 * Where the line a way in is drawn on comes from: one of your accounts (its id), an outside source (src:...), or
 * nothing, for trust from inside the account itself, AWS services and the account's own EKS clusters, which are
 * counted on the account instead.
 */
export function fromOf(e, byAws) {
  if (e.group === 'same-account' || e.group === 'service' || e.pkind === 'eks') return null;
  if (e.group === 'connected-account') { const a = byAws.get(e.principalAccount); if (a) return a.id; }
  const key = /account/.test(e.group) ? `acct:${e.principalAccount}` : e.group === 'unknown' ? 'deleted' : `${e.group}:${e.source}`;
  return `src:${key}`;
}
/** Does a way in belong to what is picked on the map: a line (from>to), an account, or a source? */
function inSelection(e, sel, byAws, accountIds) {
  if (sel.includes('>')) { const [from, to] = sel.split('>'); return e.accountId === to && fromOf(e, byAws) === from; }
  if (accountIds.has(sel)) return e.accountId === sel || fromOf(e, byAws) === sel;
  return fromOf(e, byAws) === sel;
}

const RISK = { High: 0, Medium: 1, Low: 2 };
const SORTS = {
  worst: () => 0,                                   // the index is already worst first, then account and role
  account: (a, b) => a.account.localeCompare(b.account) || a.role.localeCompare(b.role),
  role: (a, b) => a.role.localeCompare(b.role) || a.account.localeCompare(b.account),
  source: (a, b) => a.source.localeCompare(b.source),
  used: (a, b) => new Date(b.lastSeen || b.lastUsed?.at || 0) - new Date(a.lastSeen || a.lastUsed?.at || 0),
  sessions: (a, b) => b.sessions - a.sessions,
  risk: (a, b) => (RISK[a.risk] ?? 3) - (RISK[b.risk] ?? 3),
  // how loose the trust is and what it reaches, together: a medium finding into an administrator before a high one into read-only
  reach: (a, b) => reachScore(b) - reachScore(a),
};
const SEV_WEIGHT = { high: 9, medium: 4, low: 1, info: 0, none: 0 };
const reachScore = (e) => (SEV_WEIGHT[e.attention || e.worst === 'low' ? e.worst : 'none'] || 0) * (e.admin ? 3 : e.risk === 'High' ? 2 : 1) + (e.admin ? 0.5 : 0);

async function select(user, q, { mentions = null, sel = null } = {}) {
  const ix = await trustIndex();
  const scope = user?.scope_accounts ? new Set(user.scope_accounts) : null;
  let all = scope ? ix.edges.filter((e) => scope.has(e.accountId)) : ix.edges;
  // `mentions`: only roles whose trust policy names that AWS account ID somewhere (a whole account, a role or user in
  // it, a condition): what that account's identities can get into
  if (mentions && /^\d{12}$/.test(mentions)) {
    const roles = new Set(all.filter((e) => e.principal.includes(mentions) || e.conditions.some((c) => c.includes(mentions))).map((e) => e.roleId));
    all = all.filter((e) => roles.has(e.roleId));
  }
  if (scope) all = all.map((e) => forViewer(e, user));
  const terms = parseQuery(q);
  const matched = all.filter((e) => matchesQuery(e, terms));
  const byAws = new Map(ix.accounts.map((a) => [a.account_id, a]));
  const accountIds = new Set(ix.accounts.map((a) => a.id));
  const rows = sel ? matched.filter((e) => inSelection(e, sel, byAws, accountIds)) : matched;
  return { ix, all, matched, rows, terms, byAws };
}

/** The ways in matching a query (and a pick on the map), one page at a time, sorted. */
export async function trustWays(user, q = '', { sel = null, sort = 'worst', dir = 'asc', page = 0, size = 50 } = {}) {
  const { rows, ix } = await select(user, q, { sel });
  const by = SORTS[sort] || SORTS.worst;
  const sorted = sort === 'worst' ? rows : [...rows].sort((a, b) => by(a, b) || (SEV_ORDER[a.worst] ?? 9) - (SEV_ORDER[b.worst] ?? 9));
  if (dir === 'desc') sorted.reverse();
  const n = Math.min(Math.max(1, size), 500), p = Math.max(0, page);
  return { total: rows.length, page: p, size: n, rows: sorted.slice(p * n, p * n + n), builtAt: ix.at };
}

/**
 * The same trust, grouped: one row per role name, where it comes from, and its findings, with the accounts it is in.
 * A vendor's role in 100 accounts is one row; open it for the accounts. Decisions apply to the whole group.
 */
export async function trustGroups(user, q = '', { sel = null, page = 0, size = 50 } = {}) {
  const { rows, ix } = await select(user, q, { sel });
  const by = new Map();
  for (const e of rows) {
    const nf = e.findings.filter((f) => f.severity !== 'info').map((f) => f.id).sort();
    const key = `${e.role}|${e.sourceKey}|${nf.join(',')}`;
    let g = by.get(key);
    if (!g) by.set(key, g = { key, role: e.role, source: e.named?.name || e.source, sourceKey: e.sourceKey, group: e.group, pkind: e.pkind || null, named: e.named || null,
      principal: e.principal, conditions: e.conditions, findings: e.findings.filter((f) => f.severity !== 'info'), worst: e.worst,
      ways: 0, accounts: new Set(), attention: 0, expected: 0, accepted: 0, admin: 0, sessions: 0, lastSeen: null, undecided: [], members: [] });
    g.ways++; g.accounts.add(e.accountId);
    if (e.attention) g.attention++;
    if (e.expected) g.expected++;
    if (e.accepted) g.accepted++;
    if (e.admin) g.admin++;
    g.sessions += e.sessions;
    if (e.lastSeen && (!g.lastSeen || e.lastSeen > g.lastSeen)) g.lastSeen = e.lastSeen;
    for (const f of e.flags || []) if (f.id && !f.decision && f.status === 'open') g.undecided.push(f.id);
    if (g.members.length < 200) g.members.push({ roleId: e.roleId, account: e.account, awsAccountId: e.awsAccountId, env: e.environment, statement: e.statement, sid: e.sid,
      worst: e.worst, attention: !!e.attention, expected: !!e.expected, accepted: !!e.accepted, sessions: e.sessions, lastSeen: e.lastSeen, admin: !!e.admin, risk: e.risk });
  }
  const groups = [...by.values()].map((g) => ({ ...g, accounts: g.accounts.size, undecided: g.undecided.slice(0, 500) }))
    .sort((a, b) => (b.attention > 0) - (a.attention > 0) || (SEV_ORDER[a.worst] ?? 9) - (SEV_ORDER[b.worst] ?? 9) || b.accounts - a.accounts || a.role.localeCompare(b.role));
  const n = Math.min(Math.max(1, size), 200), p = Math.max(0, page);
  return { total: groups.length, ways: rows.length, page: p, size: n, groups: groups.slice(p * n, p * n + n), builtAt: ix.at };
}

/**
 * Where a source leads next: the roles it can get into, then the roles those can get into (a role named in another
 * role's trust policy), up to four steps. A role whose whole account is trusted could go on to any role its
 * permissions allow: such steps are counted as possible, not certain.
 */
export async function trustChain(user, sel, { depth = 4 } = {}) {
  const ix = await trustIndex();
  const scope = user?.scope_accounts ? new Set(user.scope_accounts) : null;
  const byAws = new Map(ix.accounts.map((a) => [a.account_id, a]));
  const edges = scope ? ix.edges.filter((e) => scope.has(e.accountId)) : ix.edges;
  const byRoleArn = new Map(), byRootAcct = new Map();
  for (const e of edges) {
    if (e.type === 'aws-role') { if (!byRoleArn.has(e.principal)) byRoleArn.set(e.principal, []); byRoleArn.get(e.principal).push(e); }
    if (e.type === 'aws-root' && e.principalAccount && e.principalAccount !== e.awsAccountId) { if (!byRootAcct.has(e.principalAccount)) byRootAcct.set(e.principalAccount, []); byRootAcct.get(e.principalAccount).push(e); }
  }
  const start = edges.filter((e) => fromOf(e, byAws) === sel || e.sourceKey === sel);
  const seen = new Set(), levels = [];
  let frontier = [...new Map(start.map((e) => [e.roleId, { e, via: 'trust', sure: true }])).values()];
  for (const x of frontier) seen.add(x.e.roleId);
  for (let d = 0; d < depth && frontier.length; d++) {
    levels.push({ depth: d + 1, roles: frontier.map(({ e, via, sure, from }) => ({ roleId: e.roleId, role: e.role, account: e.account, awsAccountId: e.awsAccountId, accountId: e.accountId,
      risk: e.risk, admin: !!e.admin, via, sure, from: from || null })).sort((a, b) => (b.admin - a.admin) || a.account.localeCompare(b.account) || a.role.localeCompare(b.role)) });
    const next = new Map();
    for (const { e, sure } of frontier) {
      for (const n of byRoleArn.get(e.roleArn) || []) if (!seen.has(n.roleId) && !next.has(n.roleId)) next.set(n.roleId, { e: n, via: 'role', sure, from: e.role });
      for (const n of byRootAcct.get(e.awsAccountId) || []) if (!seen.has(n.roleId) && !next.has(n.roleId)) next.set(n.roleId, { e: n, via: 'account', sure: false, from: e.role });
    }
    for (const id of next.keys()) seen.add(id);
    frontier = [...next.values()];
  }
  const accounts = new Set(levels.flatMap((l) => l.roles.map((r) => r.accountId)));
  const first = new Set((levels[0]?.roles || []).map((r) => r.accountId));
  return { sel, levels: levels.map((l) => ({ ...l, roles: l.roles.slice(0, 200), total: l.roles.length })), roles: seen.size, accounts: accounts.size, moreAccounts: [...accounts].filter((a) => !first.has(a)).length,
    admin: levels.reduce((n, l) => n + l.roles.filter((r) => r.admin).length, 0), truncated: !!frontier.length };
}

/**
 * A tighter trust policy for a role, from what was seen coming in: principals nobody used are removed, a whole
 * account becomes the roles that came in from it, a web identity gets the subjects and audience it was used with,
 * an outside account gets an ExternalId to fill in. Nothing is changed in AWS: the policy is to review and apply.
 */
export async function suggestTrust(user, roleId) {
  const role = (await query(`SELECT r.id, r.name, r.account_id, r.trust_policy FROM roles r WHERE r.id = $1 AND r.deleted_at IS NULL`, [roleId])).rows[0];
  if (!role || (user?.scope_accounts && !user.scope_accounts.includes(role.account_id))) return null;
  const ix = await trustIndex();
  const edges = ix.edges.filter((e) => e.roleId === roleId);
  const before = role.trust_policy || {};
  const after = JSON.parse(JSON.stringify(before));
  const list = Array.isArray(after.Statement) ? after.Statement : after.Statement ? [after.Statement] : [];
  const changes = [];
  const sts = normalizeStatements(before);
  for (const st of sts) {
    const doc = list[st.index];
    if (!doc || st.effect !== 'Allow') continue;
    const mine = edges.filter((e) => e.statement === st.index);
    const used = (e) => e.callers.length > 0 || !!e.lastUsed;
    const never = (e) => e.findings.some((f) => f.id === 'never-used');
    const label = st.sid ? `statement ${st.sid}` : `statement ${st.index + 1}`;
    // principals nobody came in through, where the whole history was read
    const drop = mine.filter((e) => never(e) && e.type !== 'service');
    for (const e of drop) {
      removePrincipal(doc, e.principal);
      changes.push({ statement: label, kind: 'remove', text: `Remove ${e.principal}: nothing came in through it in the history read.` });
    }
    for (const e of mine.filter((x) => !drop.includes(x) && used(x))) {
      const keys = e.callers.map(([k]) => String(k));
      if ((e.type === 'aws-root' || e.type === 'public') && keys.length && keys.every((k) => /^role:\d{12}:/.test(k))) {
        const arns = [...new Set(keys.map((k) => { const [, acct, name] = k.split(':'); return `arn:aws:iam::${acct}:role/${name}`; }))].sort();
        if (arns.length <= 20) {
          removePrincipal(doc, e.principal); addPrincipal(doc, 'AWS', arns);
          changes.push({ statement: label, kind: 'narrow', text: `Replace ${e.principal === '*' ? 'anyone' : 'the whole account'} with the ${arns.length === 1 ? 'role' : `${arns.length} roles`} that came in: ${arns.map((a) => a.split('/').pop()).join(', ')}.` });
        }
      }
      if (e.type === 'oidc') {
        const host = e.provider;
        const subs = new Set(), auds = new Set();
        for (const k of keys) {
          const at = k.indexOf(host); if (at < 0) continue;
          const rest = k.slice(at + host.length + 1);
          const aud = /^ari:cloud:[^{]*\{[^}]+\}/.exec(rest)?.[0] || rest.split(':')[0];
          auds.add(aud); const sub = rest.slice(aud.length + 1); if (sub) subs.add(sub);
        }
        const need = (id) => e.findings.some((f) => f.id === id);
        if ((need('oidc-no-sub') || need('oidc-broad-sub')) && subs.size && subs.size <= 30 && e.pkind !== 'cognito') {
          setCondition(doc, 'StringLike', `${host}:sub`, [...subs].sort());
          changes.push({ statement: label, kind: 'condition', text: `Pin ${host}:sub to the ${subs.size === 1 ? 'subject' : `${subs.size} subjects`} seen: ${[...subs].slice(0, 3).join(', ')}${subs.size > 3 ? '…' : ''}.` });
        }
        if (need('oidc-no-aud') && auds.size === 1) {
          setCondition(doc, 'StringEquals', `${host}:aud`, [...auds][0]);
          changes.push({ statement: label, kind: 'condition', text: `Require ${host}:aud = ${[...auds][0]}, the audience seen.` });
        }
      }
    }
    for (const e of mine) {
      if (e.findings.some((f) => f.id === 'external-no-externalid') && !drop.includes(e)) {
        setCondition(doc, 'StringEquals', 'sts:ExternalId', 'ASK-THE-VENDOR-FOR-ITS-EXTERNAL-ID');
        changes.push({ statement: label, kind: 'condition', text: `Require sts:ExternalId for ${e.principalAccount}: ask the third party for the value they send.`, placeholder: true });
      }
    }
  }
  // statements left with no principal go
  const kept = list.filter((d) => !d.Principal || Object.values(d.Principal === '*' ? { x: '*' } : d.Principal).some((v) => (Array.isArray(v) ? v.length : v)));
  if (kept.length !== list.length) changes.push({ statement: '', kind: 'remove', text: `Remove ${list.length - kept.length === 1 ? 'a statement' : `${list.length - kept.length} statements`} left with nobody in it.` });
  after.Statement = kept;
  return { roleId, role: role.name, before, after, changes, empty: !kept.length };
}
function removePrincipal(doc, principal) {
  if (doc.Principal === '*' && principal === '*') { doc.Principal = {}; return; }
  for (const k of Object.keys(doc.Principal || {})) {
    const v = doc.Principal[k];
    const left = (Array.isArray(v) ? v : [v]).filter((x) => x !== principal && `canonical:${x}` !== principal);
    if (!left.length) delete doc.Principal[k]; else doc.Principal[k] = left.length === 1 ? left[0] : left;
  }
}
function addPrincipal(doc, kind, values) {
  if (!doc.Principal || doc.Principal === '*') doc.Principal = {};
  const cur = doc.Principal[kind] ? (Array.isArray(doc.Principal[kind]) ? doc.Principal[kind] : [doc.Principal[kind]]) : [];
  const all = [...new Set([...cur, ...values])];
  doc.Principal[kind] = all.length === 1 ? all[0] : all;
}
function setCondition(doc, op, key, value) {
  doc.Condition = doc.Condition || {};
  for (const o of Object.keys(doc.Condition)) if (doc.Condition[o][key] !== undefined && o !== op) { delete doc.Condition[o][key]; if (!Object.keys(doc.Condition[o]).length) delete doc.Condition[o]; }
  doc.Condition[op] = { ...(doc.Condition[op] || {}), [key]: value };
}

/** Third-party access: one row per source outside your estate (outside accounts, anyone, CI and identity providers). */
const OUTSIDE = new Set(['external-account', 'public', 'oidc', 'saml', 'unknown']);
export async function thirdParties(user, q = '') {
  const m = await trustMap(user, q, { limit: 0 });
  return m.summary.filter((g) => OUTSIDE.has(g.group)).flatMap((g) => g.sources.filter((s) => !s.named?.inOrg).map((s) => ({ ...s, group: g.group })));
}
export function thirdPartyCsv(rows) {
  const KIND = { 'external-account': 'Outside AWS account', public: 'Anyone', oidc: 'CI or web identity', saml: 'SAML / Identity Center', unknown: 'Deleted identity' };
  const day = (v) => (v ? String(v instanceof Date ? v.toISOString() : v).slice(0, 10) : '');
  return toCsvRows([
    ['name', (s) => s.named?.name || (s.group === 'external-account' ? '' : s.label)], ['aws_account', (s) => s.aws || ''], ['kind', (s) => KIND[s.group] || s.group],
    ['known_vendor', (s) => s.named?.vendor || ''], ['owner', (s) => s.named?.owner || ''], ['purpose', (s) => s.named?.purpose || ''], ['review_by', (s) => day(s.named?.reviewBy)],
    ['accounts', (s) => s.accounts], ['roles', (s) => s.roles], ['ways_in', (s) => s.edges], ['high_risk_roles', (s) => s.highRiskRoles], ['admin_accounts', (s) => s.adminAccounts],
    ['externalid_on', (s) => (s.group === 'external-account' ? `${s.guarded} of ${s.edges}` : '')], ['worst_finding', (s) => s.worst], ['needs_attention', (s) => s.attention],
    ['expected', (s) => s.expected], ['sessions', (s) => s.sessions], ['first_seen', (s) => day(s.firstSeen)], ['last_seen', (s) => day(s.lastSeen)],
  ], rows);
}

/** The whole map for one viewer: counts, sources, map, and the first ways in. */
const answers = new Map();                          // the last few answers, for the index they were worked out from
export async function trustMap(user, q = '', { limit = 500, mentions = null, sel = null } = {}) {
  const ix = await trustIndex();
  const key = JSON.stringify([user?.scope_accounts ? [...user.scope_accounts].sort() : '*', q, limit, mentions, sel]);
  const hit = answers.get(key);
  if (hit?.ix === ix) return hit.value;
  const value = await workOut(user, q, { limit, mentions, sel });
  if (answers.size >= 50) answers.delete(answers.keys().next().value);
  answers.set(key, { ix, value });
  return value;
}
async function workOut(user, q, { limit, mentions, sel }) {
  const { ix, all, matched, rows, terms, byAws } = await select(user, q, { mentions, sel });

  // where things come from, grouped, over the ways in that matched; sign-ins counted once per role and caller
  const groups = new Map();
  for (const e of matched) {
    const gk = e.group; if (!groups.has(gk)) groups.set(gk, new Map());
    // the role's own account is one source per kind of principal, not one per account
    const same = e.group === 'same-account';
    const SAME = { 'aws-root': 'Its own account · whole account (:root)', 'aws-role': 'Roles in its own account', 'aws-user': 'IAM users in its own account', 'aws-assumed': 'Role sessions in its own account' };
    const sk = same ? e.type : /account/.test(e.group) ? (e.principalAccount || e.source) : e.source;
    const g = groups.get(gk);
    if (!g.has(sk)) g.set(sk, { key: sk, label: same ? SAME[e.type] || 'Its own account' : e.group.endsWith('account') ? `${e.principalAccount}${e.principalAccountName ? ` · ${e.principalAccountName}` : e.named ? ` · ${e.named.name}` : ''}` : e.named?.name || e.source,
      sourceKey: e.sourceKey, named: e.named || null, aws: e.group.endsWith('account') ? e.principalAccount : null,
      pkind: e.pkind || null, node: fromOf(e, byAws), roles: new Set(), accounts: new Set(), edges: 0, findings: 0, worst: 'none', open: 'none', attention: 0, expected: 0, guarded: 0,
      query: queryFor(e), sessions: 0, lastSeen: null, firstSeen: null, byRole: new Map(), highRisk: new Set(), adminAccounts: new Set() });
    const s = g.get(sk); s.roles.add(e.roleId); s.accounts.add(e.accountId); s.edges++;
    s.findings += e.findings.filter((f) => f.severity !== 'info').length;
    if ((SEV_ORDER[e.worst] ?? 9) < (SEV_ORDER[s.worst] ?? 9)) s.worst = e.worst;
    if (!e.expected && !e.accepted) s.open = worse(s.open, e.worst);
    if (e.attention) s.attention++;
    if (e.expected) s.expected++;
    if (e.conditions.some((c) => /^sts:ExternalId /i.test(c))) s.guarded++;
    if (e.risk === 'High') s.highRisk.add(e.roleId);
    if (e.admin) s.adminAccounts.add(e.accountId);
    if (e.firstSeen && (!s.firstSeen || e.firstSeen < s.firstSeen)) s.firstSeen = e.firstSeen;
    addSeen(s, e);
  }
  const GROUP_ORDER = ['public', 'external-account', 'oidc', 'saml', 'connected-account', 'same-account', 'service', 'unknown'];
  const summary = GROUP_ORDER.filter((g) => groups.has(g)).map((g) => ({ group: g, sources: [...groups.get(g).values()]
    .map(({ byRole, highRisk, adminAccounts, ...s }) => ({ ...s, roles: s.roles.size, accounts: s.accounts.size, highRiskRoles: highRisk.size, adminAccounts: adminAccounts.size }))
    .sort((a, b) => (SEV_ORDER[a.worst] ?? 9) - (SEV_ORDER[b.worst] ?? 9) || b.roles - a.roles) }));
  const findingCounts = {};
  for (const e of matched) for (const f of e.findings) findingCounts[f.id] = (findingCounts[f.id] || 0) + 1;
  // the same, as if no finding: filter were set, so a menu of findings can list every one with its count
  const others = terms.filter((t) => t.key !== 'finding');
  const findingCountsAll = {};
  for (const e of (others.length === terms.length ? matched : all.filter((e) => matchesQuery(e, others)))) for (const f of e.findings) findingCountsAll[f.id] = (findingCountsAll[f.id] || 0) + 1;
  // ways in by their worst finding, and by use (services left out: AWS uses them, nobody signs in)
  const worstCounts = { high: 0, medium: 0, low: 0, info: 0, none: 0 }, usage = { yes: 0, iam: 0, no: 0 };
  const review = { attentionHigh: 0, attentionMedium: 0, expected: 0, expectedDue: 0, decided: 0, accepted: 0, undecided: 0, changed7: 0, weakened7: 0 };
  for (const e of matched) {
    worstCounts[e.worst] = (worstCounts[e.worst] || 0) + 1;
    if (e.attention) review[e.worst === 'high' ? 'attentionHigh' : 'attentionMedium']++;
    if (e.expected) review.expected++;
    if (e.expectedDue) review.expectedDue++;
    if (e.flags?.length) { if (e.decided) review.decided++; else review.undecided++; }
    if (e.accepted) review.accepted++;
    if (e.change && e.group !== 'service' && Date.now() - new Date(e.change.at) <= 7 * 864e5) { review.changed7++; if (e.change.kind === 'weakened') review.weakened7++; }
    if (e.group !== 'service') usage[e.seen.length ? 'yes' : e.lastUsed ? 'iam' : 'no']++;
  }
  // each finding at the worst severity it has anywhere the viewer can see, so a menu can order them
  const severities = {};
  for (const e of all) for (const f of e.findings) if (!severities[f.id] || (SEV_ORDER[f.severity] ?? 9) < (SEV_ORDER[severities[f.id]] ?? 9)) severities[f.id] = f.severity;
  const scope = user?.scope_accounts ? new Set(user.scope_accounts) : null;
  const scoped = ix.accounts.filter((a) => !scope || scope.has(a.id));
  return { total: matched.length, totalEdges: all.length, roles: new Set(matched.map((e) => e.roleId)).size, rows: rows.slice(0, limit), rowsTotal: rows.length, truncated: rows.length > limit,
    summary, findingCounts, findingCountsAll, worstCounts, usage, review, findings: { ...FINDINGS, ...(ix.customTitles || {}) }, severities, terms, warnings: queryWarnings(terms), builtAt: ix.at, map: mapOf(matched, scoped, ix.accounts) };
}

/**
 * Adds a way in's sign-ins to a total, each caller once per role however many statements it matched. Most roles have
 * one way in per line or source, so the callers are compared only when a second one of the same role arrives.
 */
function addSeen(t, e) {
  const prev = t.byRole.get(e.roleId);
  if (!prev) { t.byRole.set(e.roleId, [e]); t.sessions += e.sessions; }
  else {
    const keys = new Set(prev.flatMap((x) => (x.callers || []).map((c) => c[0])));
    for (const [key, sessions] of e.callers || []) if (!keys.has(key)) t.sessions += sessions;
    prev.push(e);
  }
  if (e.lastSeen && (!t.lastSeen || new Date(e.lastSeen) > new Date(t.lastSeen))) t.lastSeen = e.lastSeen;
}

/**
 * The map: who can get into which account. One line per (where it comes from -> account), however many roles and
 * statements are behind it, coloured by the worst finding. Your own connected accounts are nodes, so trust between
 * them is account -> account. Trust from inside the account itself, from AWS services and from the account's own EKS
 * clusters is counted on the account. The roles behind a line are asked for when it is picked (trustWays with sel).
 */
const worse = (a, b) => ((SEV_ORDER[a] ?? 9) <= (SEV_ORDER[b] ?? 9) ? a : b);
export function mapOf(rows, scoped, allAccts) {
  const byAws = new Map(allAccts.map((a) => [a.account_id, a]));
  const blank = () => ({ inbound: { roles: new Set(), worst: 'none', findings: 0, high: 0, medium: 0, expected: 0 }, own: new Set(), services: new Set(), clusters: new Set(), clusterSources: new Set() });
  const accounts = new Map(scoped.filter((a) => a.status !== 'planned').map((a) => [a.id, { id: a.id, name: a.name, aws: a.account_id, env: a.environment, planned: false, inScope: true, ...blank() }]));
  const node = (a, inScope) => { if (!accounts.has(a.id)) accounts.set(a.id, { id: a.id, name: a.name, aws: a.account_id, env: a.environment, planned: a.status === 'planned', inScope, ...blank() }); return accounts.get(a.id); };
  const sources = new Map(), links = new Map();
  for (const e of rows) {
    const to = accounts.get(e.accountId) || node({ id: e.accountId, name: e.account, account_id: e.awsAccountId, environment: e.environment, status: 'connected' }, true);
    if (e.group === 'same-account') { to.own.add(e.roleId); continue; }
    if (e.group === 'service') { to.services.add(e.roleId); continue; }
    to.inbound.roles.add(e.roleId); if (!e.expected && !e.accepted) to.inbound.worst = worse(to.inbound.worst, e.worst);
    const nf = e.findings.filter((f) => f.severity !== 'info');
    to.inbound.findings += nf.length;
    if (e.attention) { if (e.worst === 'high') to.inbound.high++; else to.inbound.medium++; }
    if (e.expected) to.inbound.expected++;
    if (e.pkind === 'eks') { to.clusters.add(e.roleId); to.clusterSources.add(e.source); continue; }
    const from = fromOf(e, byAws);
    if (!from.startsWith('src:')) node(byAws.get(e.principalAccount), false);
    else {
      if (!sources.has(from)) sources.set(from, { id: from, group: e.group, pkind: e.pkind || null,
        label: e.named?.name || (e.group === 'external-account' ? e.principalAccount : e.group === 'unknown' ? 'Deleted identities' : e.source),
        aws: e.group === 'external-account' ? e.principalAccount : null, named: e.named || null,
        query: queryFor(e), roles: new Set(), accounts: new Set(), worst: 'none', open: 'none', attention: 0, expected: 0, findings: 0, vendor: true, sessions: 0, lastSeen: null, firstSeen: null, byRole: new Map(), highRisk: new Set(), adminAccounts: new Set() });
      const s = sources.get(from);
      s.roles.add(e.roleId); s.accounts.add(e.accountId); s.worst = worse(s.worst, e.worst); s.findings += nf.length;
      if (!e.expected && !e.accepted) s.open = worse(s.open, e.worst);
      if (e.attention) s.attention++;
      if (e.expected) s.expected++;
      if (e.group === 'external-account' && !e.conditions.some((c) => /^sts:ExternalId /i.test(c))) s.vendor = false;
      if (e.risk === 'High') s.highRisk.add(e.roleId);
      if (e.admin) s.adminAccounts.add(e.accountId);
      if (e.firstSeen && (!s.firstSeen || e.firstSeen < s.firstSeen)) s.firstSeen = e.firstSeen;
      addSeen(s, e);
    }
    const id = `${from}>${e.accountId}`;
    if (!links.has(id)) links.set(id, { id, from, to: e.accountId, kind: from.startsWith('src:') ? 'outside' : 'account', worst: 'none', open: 'none', attention: 0, expected: 0, changed: null, ways: 0, findings: 0, sessions: 0, lastSeen: null,
      roles: new Set(), highRisk: new Set(), admin: 0, iamUsed: false, byRole: new Map(), query: `${from.startsWith('src:') ? queryFor(e) : `from:${e.principalAccount}`} account:${e.awsAccountId}` });
    const l = links.get(id);
    l.ways++; l.worst = worse(l.worst, e.worst); l.findings += nf.length; l.roles.add(e.roleId);
    // the colour that counts: the worst finding nobody has accepted or marked as expected
    if (!e.expected && !e.accepted) l.open = worse(l.open, e.worst);
    if (e.attention) l.attention++;
    if (e.expected) l.expected++;
    if (e.admin) l.admin++;
    if (e.change && (!l.changed || new Date(e.change.at) > new Date(l.changed))) l.changed = e.change.at;
    if (e.risk === 'High') l.highRisk.add(e.roleId);
    if (e.lastUsed && !e.sessions) l.iamUsed = true;
    addSeen(l, e);
  }
  const ORDER = ['public', 'external-account', 'oidc', 'saml', 'unknown'];
  return {
    accounts: [...accounts.values()].map((a) => ({ ...a, inbound: { ...a.inbound, roles: a.inbound.roles.size }, own: a.own.size, services: a.services.size, clusters: a.clusters.size, clusterSources: a.clusterSources.size })),
    sources: [...sources.values()].map(({ byRole, highRisk, adminAccounts, ...s }) => ({ ...s, roles: s.roles.size, accounts: s.accounts.size, highRiskRoles: highRisk.size, adminAccounts: adminAccounts.size, vendor: s.group === 'external-account' && s.vendor }))
      .sort((a, b) => ORDER.indexOf(a.group) - ORDER.indexOf(b.group) || (SEV_ORDER[a.worst] ?? 9) - (SEV_ORDER[b.worst] ?? 9) || b.roles - a.roles),
    links: [...links.values()].map(({ byRole, highRisk, ...l }) => ({ ...l, roles: l.roles.size, highRiskRoles: highRisk.size })),
  };
}

function queryFor(e) {
  if (e.group === 'same-account') return `source:same type:${e.type.replace(/^aws-/, '')}`;
  if (/account/.test(e.group) && e.principalAccount) return `from:${e.principalAccount}`;
  if (e.group === 'oidc' || e.group === 'saml') return `provider:"${e.source}"`;
  if (e.group === 'service') return `provider:${e.source}`;
  return `source:${e.group}`;
}

const COLUMNS = [
  ['account', (e) => e.account], ['aws_account_id', (e) => e.awsAccountId], ['environment', (e) => e.environment], ['role', (e) => e.role], ['role_arn', (e) => e.roleArn],
  ['role_risk', (e) => e.risk], ['statement', (e) => (e.sid || e.statement + 1)], ['source_group', (e) => e.group], ['type', (e) => e.type], ['source', (e) => e.source], ['principal', (e) => e.principal],
  ['conditions', (e) => e.conditions], ['worst', (e) => e.worst], ['findings', (e) => e.findings.map((f) => `${f.severity}:${f.id}`)],
  ['finding_text', (e) => e.findings.filter((f) => f.severity !== 'info').map((f) => f.title)], ['sessions', (e) => e.sessions], ['callers', (e) => e.callerCount],
  ['last_seen', (e) => e.lastSeen && new Date(e.lastSeen)], ['latest_callers', (e) => e.seen.map((s) => s.display)], ['iam_last_used', (e) => e.lastUsed?.at && new Date(e.lastUsed.at)],
];
/** The ways in as CSV: one row per statement and principal, the callers as a count and the latest few. */
export const toCsv = (rows) => toCsvRows(COLUMNS, rows);
/** Where things come from as CSV: one row per source (an outside account, a provider, your own accounts...). */
export const sourcesCsv = (summary) => toCsvRows([['group', (s) => s.group], ['source', (s) => s.label], ['worst', (s) => s.worst], ['roles', (s) => s.roles], ['accounts', (s) => s.accounts],
  ['high_risk_roles', (s) => s.highRiskRoles], ['findings', (s) => s.findings], ['sessions', (s) => s.sessions], ['last_seen', (s) => s.lastSeen && new Date(s.lastSeen)], ['query', (s) => s.query]],
  summary.flatMap((g) => g.sources.map((s) => ({ ...s, group: g.group }))));
