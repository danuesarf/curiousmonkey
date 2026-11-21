// Resource access: who a resource-based policy lets in. S3 bucket policies, KMS key policies, DynamoDB, SQS, SNS,
// Secrets Manager, Lambda and ECR policies all speak the same language, so one reading serves them all.
// Every (Allow statement × principal) becomes one grant: who it names, how far that really reaches once the conditions
// are counted (anyone, an account outside your estate, another of your accounts, the resource's own account, an AWS
// service), and what it lets them do (administer, use the data, or only read metadata). Deny statements that guard the
// whole policy ("deny everyone outside my organisation") narrow every grant the way AWS would.
// No I/O: the scanner and the re-analysis pass give it the estate (which accounts are yours) and the workspace policy.
import { normalizeStatements, arr } from './policy.js';
import { accessLevel, expandAction } from './catalog.js';
import { isPrivilege, isDataRead } from './sensitive.js';
import { globMatch } from './wildcard.js';
import { severityOf, DEFAULT_POLICY } from '../controlCatalog.js';

export const SERVICES = {
  s3: { label: 'S3 bucket', noun: 'S3 bucket', short: 'S3' },
  kms: { label: 'KMS key', noun: 'KMS key', short: 'KMS' },
  dynamodb: { label: 'DynamoDB table', noun: 'DynamoDB table', short: 'DynamoDB' },
  sqs: { label: 'SQS queue', noun: 'SQS queue', short: 'SQS' },
  sns: { label: 'SNS topic', noun: 'SNS topic', short: 'SNS' },
  secretsmanager: { label: 'Secret', noun: 'secret', short: 'Secrets Manager' },
  lambda: { label: 'Lambda function', noun: 'Lambda function', short: 'Lambda' },
  ecr: { label: 'ECR repository', noun: 'ECR repository', short: 'ECR' },
};

// how far a grant reaches, widest first
export const REACH = ['public', 'external', 'org', 'connected', 'same'];
const WIDTH = Object.fromEntries(REACH.map((r, i) => [r, i]));
const widest = (list) => list.reduce((w, r) => (WIDTH[r] < WIDTH[w] ? r : w), 'same');
const narrowest = (a, b) => (WIDTH[a] >= WIDTH[b] ? a : b);
/** The resource as a whole: the widest grant. 'service' when only AWS services get in from outside the account. */
export const EXPOSURE = { public: 'Public', external: 'Outside accounts', 'cross-account': 'Your other accounts', service: 'AWS services', private: 'This account only', none: 'No resource policy' };

// the things that narrow WHO gets in
const ORG_KEYS = /^aws:(PrincipalOrgID|PrincipalOrgPaths|SourceOrgID|SourceOrgPaths|ResourceOrgID)$/i;
const ACCOUNT_KEYS = /^(aws:PrincipalAccount|aws:SourceAccount|aws:SourceOwner|kms:CallerAccount)$/i;
const ARN_KEYS = /^aws:(PrincipalArn|SourceArn)$/i;
const SOURCE_KEYS = /^(aws:SourceAccount|aws:SourceArn|aws:SourceOrgID|aws:SourceOrgPaths|aws:SourceOwner|kms:CallerAccount)$/i;
// …and WHERE from: these keep the internet out, not other AWS accounts
const NETWORK_KEYS = /^aws:(SourceVpce|SourceVpc|SourceIp|VpcSourceIp)$/i;
const POSITIVE = /^(ForAnyValue:|ForAllValues:)?(StringEquals|StringEqualsIgnoreCase|StringLike|ArnEquals|ArnLike|IpAddress)(IfExists)?$/i;
const NEGATIVE = /^(ForAnyValue:|ForAllValues:)?(StringNotEquals|StringNotEqualsIgnoreCase|StringNotLike|ArnNotEquals|ArnNotLike|NotIpAddress)(IfExists)?$/i;
// reading or changing the data a resource holds (on top of the catalogue's Write level)
const DATA = ['kms:Decrypt', 'kms:ReEncrypt*', 'kms:GenerateDataKey*', 'sqs:ReceiveMessage', 'lambda:InvokeFunction', 'lambda:InvokeFunctionUrl',
  'ecr:BatchGetImage', 'ecr:GetDownloadUrlForLayer', 'sns:Subscribe', 'dynamodb:GetRecords', 'secretsmanager:GetSecretValue'];

const condList = (c) => {
  const out = [];
  for (const [op, kv] of Object.entries(c || {})) for (const [key, val] of Object.entries(kv || {})) out.push({ op, key, values: arr(val).map(String) });
  return out;
};
const acctOf = (v) => (/^\d{12}$/.test(v) ? v : String(v).match(/^arn:aws[a-z-]*:[a-z0-9-]*:[a-z0-9-]*:(\d{12}):/)?.[1] || null);
const matchesAll = (v) => /^\*+$/.test(v);

/** What the actions let someone do: 'admin' (everything, or changes access), 'data' (reads or writes the data), 'read' (metadata). */
export function accessOf(actions, notActions = []) {
  if (notActions.length) return 'admin';
  let data = false;
  for (const a of actions) {
    if (a === '*' || /^[a-z0-9-]+:\*$/i.test(a)) return 'admin';
    const list = /[*?]/.test(a) ? expandAction(a) : [a];
    for (const x of list.length ? list : [a]) {
      const level = accessLevel(x);
      if (isPrivilege(x, level === 'Permissions management' ? 'Permissions' : level)) return 'admin';
      if (isDataRead(x) || DATA.some((p) => globMatch(p, x, { ci: true })) || level === 'Write') data = true;
    }
  }
  return data ? 'data' : 'read';
}
export const ACCESS = { admin: 'administer it or change who has access', data: 'read or change what it holds', read: 'read its settings only' };
/** The same, worded by what the actions really are: a grant of s3:PutObject alone can only write into it, not read it. */
export function accessText(actions, access) {
  if (access !== 'data' || !actions.length || actions.some((a) => a.startsWith('NOT '))) return ACCESS[access];
  let reads = false, writes = false;
  for (const a of actions) {
    const list = /[*?]/.test(a) ? expandAction(a) : [a];
    for (const x of list.length ? list : [a]) {
      const level = accessLevel(x);
      if (isDataRead(x) || level === 'Read' || DATA.some((p) => globMatch(p, x, { ci: true }))) reads = true;
      else if (level === 'Write') writes = true;
    }
  }
  return writes && !reads ? 'write into it, not read it' : ACCESS[access];
}
/** Accounts AWS itself runs to deliver a service (ELB and Redshift log delivery, CloudTrail, GuardDuty…), named "… (AWS)". */
export const isAwsOwned = (name) => /\(AWS\)$/.test(String(name || ''));

/**
 * Narrowing from one statement's conditions (positive operators) or from the policy's Deny guards (negative ones, as
 * "deny everyone who is not…"). Returns { org: [ids] | null, accounts: [ids] | null, network: [text] }.
 */
function narrowing(conds, negated) {
  const out = { org: null, accounts: null, network: [], source: false, text: [] };
  const add = (k, vs) => { out[k] = out[k] ? out[k].filter((x) => vs.includes(x)) : [...vs]; };
  for (const c of conds) {
    const fits = negated ? NEGATIVE.test(c.op) : POSITIVE.test(c.op);
    if (!fits || !c.values.length || c.values.some(matchesAll)) continue;
    if (ORG_KEYS.test(c.key)) { add('org', c.values); out.text.push(`${c.key} ${c.values.join(' | ')}`); }
    else if (ACCOUNT_KEYS.test(c.key)) { add('accounts', c.values.filter((v) => /^\d{12}$/.test(v))); out.text.push(`${c.key} ${c.values.join(' | ')}`); }
    else if (ARN_KEYS.test(c.key)) {
      const accts = c.values.map(acctOf);
      if (accts.every(Boolean)) { add('accounts', accts); out.text.push(`${c.key} ${c.values.join(' | ')}`); }
    } else if (NETWORK_KEYS.test(c.key)) out.network.push(`${c.key} ${c.values.join(' | ')}`);
    if (SOURCE_KEYS.test(c.key) || ORG_KEYS.test(c.key)) out.source = true;
  }
  return out;
}

/**
 * The policy-wide guards: Deny statements that apply to everyone and every action of the service, with one negated
 * condition ("deny unless aws:PrincipalOrgID is mine"). Deny conditions are ANDed, so a statement with two of them only
 * denies when both miss: it is not counted, to stay on the safe side. aws:PrincipalIsAWSService false exempts services
 * (the usual way to keep CloudTrail and Config writing): the guard then does not apply to service principals.
 */
function denyGuards(statements, service) {
  const all = [], people = [];
  for (const st of statements) {
    if (st.effect !== 'Deny' || st.notActions.length) continue;
    const everyone = st.principal === '*' || arr(st.principal?.AWS).includes('*');
    const everything = st.actions.some((a) => a === '*' || a.toLowerCase() === `${service}:*`);
    if (!everyone || !everything) continue;
    const conds = condList(st.conditions);
    const exempt = conds.filter((c) => /^aws:PrincipalIsAWSService$/i.test(c.key) && /^Bool$/i.test(c.op) && c.values.every((v) => v === 'false'));
    const rest = conds.filter((c) => !exempt.includes(c));
    if (rest.length !== 1) continue;
    (exempt.length ? people : all).push(...rest);
  }
  return { all: narrowing(all, true), people: narrowing([...all, ...people], true) };
}

/**
 * Who the policy lets in, and what is wrong with it.
 * resource: { service, arn, name, accountId (12 digits, the owner), policy, extra }
 * estate:   { connected: Map(id -> name), org: Map(id -> name), orgIds: Set, vendor: (id) => name | null }
 * policy:   the workspace's control policy (severity overrides; controls turned off make no findings)
 */
export function analyzeResource(resource, estate = {}, policy = DEFAULT_POLICY) {
  const own = resource.accountId;
  const connected = estate.connected || new Map(), org = estate.org || new Map(), orgIds = estate.orgIds || new Set();
  const classify = (acct) => (!acct ? 'public' : acct === own ? 'same' : connected.has(acct) ? 'connected' : org.has(acct) ? 'org' : 'external');
  const nameOf = (acct) => (acct === own ? null : connected.get(acct) || org.get(acct) || estate.vendor?.(acct) || null);
  const awsOwned = (acct) => !!acct && acct !== own && !connected.has(acct) && !org.has(acct) && isAwsOwned(estate.vendor?.(acct));
  const doc = resource.policy;
  if (!doc) return { exposure: 'none', grants: [], findings: [] };
  const statements = normalizeStatements(doc);
  const guards = denyGuards(statements, resource.service);
  const bpa = resource.extra?.restrictPublic ? resource.extra.restrictPublicFrom || 'Block Public Access' : null;
  const grants = [], findings = [];

  for (const st of statements) {
    if (st.effect !== 'Allow') continue;
    const conds = condList(st.conditions);
    const nw = narrowing(conds, false);
    const condText = conds.map((c) => `${c.key} ${c.op} ${c.values.join(' | ')}`);
    const access = accessOf(st.actions, st.notActions);
    const actions = st.notActions.length ? st.notActions.map((a) => `NOT ${a}`) : st.actions;
    const list = [];
    if (st.notPrincipal) list.push({ kind: 'not-principal', raw: JSON.stringify(st.notPrincipal) });
    if (st.principal === '*') list.push({ kind: 'public', raw: '*' });
    else if (st.principal && typeof st.principal === 'object') {
      for (const p of arr(st.principal.AWS)) list.push({ kind: 'aws', raw: String(p) });
      for (const p of arr(st.principal.Service)) list.push({ kind: 'service', raw: String(p) });
      for (const p of arr(st.principal.Federated)) list.push({ kind: 'federated', raw: String(p) });
      for (const p of arr(st.principal.CanonicalUser)) list.push({ kind: 'canonical', raw: String(p) });
    }

    for (const p of list) {
      const g = { statement: st.index, sid: st.sid, principal: p.raw, kind: p.kind, account: null, accountName: null, actions, access, accessText: accessText(actions, access), conditions: condText, narrowedBy: [], findings: [] };
      let reach;
      if (p.kind === 'public' || p.kind === 'not-principal' || p.raw === '*') { g.kind = p.kind === 'not-principal' ? 'not-principal' : 'public'; reach = 'public'; }
      else if (p.kind === 'service' || /^arn:aws[a-z-]*:iam::cloudfront:user\//.test(p.raw)) { g.kind = 'service'; reach = 'service'; }
      else if (p.kind === 'federated') reach = 'external';
      else if (p.kind === 'canonical') reach = 'external';
      else {
        g.account = acctOf(p.raw);
        g.kind = /^\d{12}$/.test(p.raw) || /:root$/.test(p.raw) ? 'account' : /:role\//.test(p.raw) ? 'role' : /:user\//.test(p.raw) ? 'user'
          : /:assumed-role\//.test(p.raw) ? 'session' : /^A[IR]OA[A-Z0-9]{12,}$/.test(p.raw) ? 'deleted' : 'other';
        reach = g.kind === 'deleted' ? 'same' : classify(g.account);   // a deleted identity lets nobody in
        g.accountName = g.account ? nameOf(g.account) : null;
        // an account AWS runs for a service (ELB access logs, say) is the service delivering, not a third party
        if (g.kind !== 'deleted' && awsOwned(g.account)) { g.kind = 'service'; g.awsOwned = true; reach = 'service'; }
      }

      // what the conditions (and the policy's Deny guards) leave of it
      const guard = g.kind === 'service' ? guards.all : guards.people;
      const narrowTo = [];
      for (const n of [nw, guard]) {
        if (n.org) {
          const ours = n.org.every((o) => orgIds.has(o) || orgIds.has(String(o).split('/')[0]));
          narrowTo.push(orgIds.size && !ours ? 'external' : 'org');
          g.narrowedBy.push(n === guard ? `Deny guard: ${n.text.join('; ')}` : `organisation ${n.org.join(', ')}`);
        }
        if (n.accounts) {
          narrowTo.push(n.accounts.length ? widest(n.accounts.map(classify)) : 'same');
          g.narrowedBy.push(n === guard ? `Deny guard: ${n.text.join('; ')}` : `account ${n.accounts.join(', ') || '(none of the values is an account)'}`);
        }
      }
      const sourced = nw.source || guard.source;
      g.sourceAccounts = [...new Set([...(nw.accounts || []), ...(guard.accounts || [])])];
      if (reach === 'service') {
        // a log-delivery account writing under this account's own prefix (…/AWSLogs/<account>/*) cannot write for anyone else
        const ownPath = g.awsOwned && st.resources.length > 0 && st.resources.every((r) => String(r).includes(`/${own}/`) || String(r).includes(`/${own}*`));
        g.serviceScoped = sourced || ownPath;
        reach = narrowTo.length ? narrowTo.reduce(narrowest) : 'service';
      } else if (narrowTo.length) reach = narrowTo.reduce(narrowest, reach);
      g.network = [...nw.network, ...guard.network];
      g.reach = reach;

      // ----- findings
      const f = (control, builtIn, title, detail, suggestion) => {
        const severity = severityOf(policy, control, builtIn);
        if (!severity) return;
        const finding = { key: `${control}|${st.sid || st.index}|${p.raw}`.slice(0, 500), control, severity, title, detail, suggestion,
          principal: p.raw, principalAccount: g.account, statement: st.index, sid: st.sid, actions, conditions: condText };
        g.findings.push(control); findings.push(finding);
      };
      const what = `${accessText(actions, access)}${actions.length ? ` (${actions.slice(0, 6).join(', ')}${actions.length > 6 ? ', …' : ''})` : ''}`;
      const svcLabel = SERVICES[resource.service]?.noun || 'resource';
      if (reach === 'public' && g.kind === 'not-principal') {
        f('res.not-principal', 'high', 'Allow with NotPrincipal: everyone except a list',
          `Every AWS identity except the ones named can ${what}.`, 'Replace NotPrincipal with the principals that need it.');
      } else if (reach === 'public') {
        const net = g.network.length;
        const sev = bpa ? 'low' : net ? 'medium' : access === 'read' ? 'medium' : 'high';
        f('res.public', sev, `Anyone can ${access === 'admin' ? 'administer' : access === 'data' ? 'use' : 'read the settings of'} this ${svcLabel}`,
          bpa ? `The policy lets principal "*" ${what}, but ${bpa} restricts public policies: today only this account and AWS services get through. Turning it off would open it.`
            : net ? `Principal "*" can ${what} from ${g.network.join('; ')}. Only the network condition keeps other AWS accounts out.`
            : `Principal "*" with no condition that limits who: any AWS identity, in any account, can ${what}.`,
          resource.service === 's3' ? 'Name the principals, or add aws:PrincipalOrgID; keep Block Public Access on.' : 'Name the principals, or add a condition such as aws:PrincipalOrgID or aws:SourceAccount.');
      } else if (reach === 'external') {
        const ext = g.account && classify(g.account) === 'external' ? g.account : null;
        const who = g.kind === 'service' ? `${p.raw}, acting for ${g.sourceAccounts.filter((a) => classify(a) === 'external').join(', ') || 'an account outside your estate'},` : ext ? `account ${ext}${g.accountName ? ` (${g.accountName})` : ''}`
          : g.kind === 'federated' ? `federated identities of ${p.raw}` : g.kind === 'canonical' ? `S3 canonical user ${p.raw.slice(0, 16)}…` : 'another organisation';
        f('res.external-account', access === 'read' ? 'medium' : 'high', `Shared outside your estate: ${ext ? g.accountName || ext : g.kind === 'service' ? p.raw : 'outside identity'}`,
          `${g.kind === 'service' ? who : who[0].toUpperCase() + who.slice(1)} is not one of your accounts and can ${what}.${g.kind === 'account' ? ' Every identity there that its own IAM allows gets in.' : ''}`,
          'Confirm the third party still needs it. Name the role, not the whole account, and keep the actions to what it uses.');
      } else if (reach === 'service' && !g.serviceScoped && g.awsOwned) {
        f('res.service-no-source', access === 'read' ? 'low' : 'medium', `${g.accountName} account ${g.account} not limited to this account's logs`,
          `${g.accountName.replace(/ \(AWS\)$/, '')} is an account AWS runs to deliver logs, not a third party. It can ${what}, and nothing limits it to this account: another account's ${/ELB/i.test(g.accountName) ? 'load balancers' : 'resources'} could deliver into this ${svcLabel} too.`,
          resource.service === 's3' ? `Limit the Resource to this account's prefix, e.g. arn:aws:s3:::${resource.name || '<bucket>'}/<prefix>/AWSLogs/${own}/*${/ELB/i.test(g.accountName) ? ', or use the logdelivery.elasticloadbalancing.amazonaws.com service principal with aws:SourceAccount' : ''}.` : 'Add aws:SourceAccount (or aws:SourceArn) with this account.');
      } else if (reach === 'service' && !g.serviceScoped) {
        f('res.service-no-source', access === 'read' ? 'low' : 'medium', `${p.raw} with no aws:SourceAccount or aws:SourceArn`,
          `Any use of ${p.raw}, from any AWS account, could act on this ${svcLabel}: a confused deputy. It can ${what}.`,
          'Add aws:SourceAccount (or aws:SourceArn) with the account or resource that uses the service.');
      } else if ((reach === 'connected' || reach === 'org') && g.kind !== 'service') {
        f('res.cross-account', 'low', `Shared with ${g.accountName || g.account || 'your organisation'}`,
          `${reach === 'org' && !g.account ? 'Identities in your organisation' : `Account ${g.account}${g.accountName ? ` (${g.accountName})` : ''}, ${reach === 'connected' ? 'one of your connected accounts' : 'in your organisation'},`} can ${what}.`,
          'Fine when intended. Name the role that needs it rather than the whole account.');
      }
      if (g.kind === 'deleted') f('res.deleted-principal', 'low', 'Points at a deleted identity', `Statement ${st.sid || st.index + 1} names ${p.raw}, a unique ID left behind when the identity was deleted.`, 'Remove the statement.');
      if (access === 'admin' && reach !== 'same' && reach !== 'service' && st.actions.some((a) => a === '*' || /^[a-z0-9-]+:\*$/i.test(a)))
        f('res.broad-actions', 'low', `Every ${SERVICES[resource.service]?.short || ''} action granted outside the account`.replace('  ', ' '),
          `Statement ${st.sid || st.index + 1} allows ${st.actions.join(', ')} to ${p.raw}.`, 'Grant the actions it uses, not the whole service.');
      grants.push(g);
    }
  }
  const outside = grants.filter((g) => g.kind !== 'deleted');
  const exposure = outside.some((g) => g.reach === 'public') ? 'public'
    : outside.some((g) => g.reach === 'external') ? 'external'
    : outside.some((g) => g.reach === 'connected' || g.reach === 'org') ? 'cross-account'
    : outside.some((g) => g.reach === 'service') ? 'service' : 'private';
  return { exposure, grants, findings };
}

const SEV = { high: 0, medium: 1, low: 2 };
export const worstOf = (findings) => findings.reduce((w, f) => (w == null || SEV[f.severity] < SEV[w] ? f.severity : w), null);
