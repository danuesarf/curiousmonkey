// Rules about identities, for Manage policy. An identity is a role or IAM user in AWS, or a principal in Google Cloud
// (a user, group, service account, federated identity…); another cloud is another entry in CLOUDS below.
// One rule (ruleLang.js) is worked out per cloud: for AWS it becomes one parameterised SQL query over roles; for Google
// Cloud a test run over the stored principals. A rule applies to a cloud when every key it uses exists there, so
// `risk = high AND keyage > 365` covers both and `policy = AdministratorAccess` covers AWS only.
//
// Security. A rule is user input that ends up in a SQL statement, so:
//  - a value is never part of the SQL text: every one is a bound parameter ($1, $2…), also inside LIKE and ANY();
//  - a key picks a fragment from the fixed table below and an operator from a fixed list; anything else is an error;
//  - the statement runs in a read-only transaction with a time limit (db.js guardedRead);
//  - the rule's size is capped (ruleLang.js LIMITS), and previews only ever see the accounts the person may see.
import { query, guardedRead } from './db.js';
import { scopeSql } from './auth/rbac.js';
import { canonicalAction, expandAction } from './analyzer/catalog.js';
import { parseRule, leaves, evaluate, globTest, closest } from './ruleLang.js';

const ALIASES = { environment: 'env', project: 'account', type: 'kind', tags: 'tag', findings: 'finding', provider: 'cloud', users: 'callers' };
const keyOf = (k) => ALIASES[k] || k;
const NEVER = 1000000;                                      // "never" as a number of days
const SQL_OP = { '=': '=', '!=': '<>', '>': '>', '>=': '>=', '<': '<', '<=': '<=' };
const likeOf = (v, contains) => {
  const esc = v.replace(/[\\%_]/g, (ch) => `\\${ch}`);
  return /[*?]/.test(v) ? esc.replace(/\*/g, '%').replace(/\?/g, '_') : contains ? `%${esc}%` : esc;
};
const fail = (message) => { throw Object.assign(new Error(message), { rule: true }); };
const anyOf = (op, key, ors) => {
  if (op !== '=' && op !== '!=') fail(`${key} takes = or !=, not ${op}.`);
  return `${op === '!=' ? 'NOT ' : ''}(${ors.join(' OR ')})`;
};
const number = (key, v) => {
  if (v.toLowerCase() === 'never') return NEVER;
  if (!/^\d+(\.\d+)?$/.test(v)) fail(`${key} takes a number (${key} > 90), not "${v}".`);
  return Number(v);
};
const yes = (key, v) => {
  const x = v.toLowerCase();
  if (!['yes', 'no', 'true', 'false'].includes(x)) fail(`${key} takes yes or no, not "${v}".`);
  return x === 'yes' || x === 'true';
};

// ---------------------------------------------------------------- AWS: a term as SQL over `roles r JOIN cloud_accounts a`
const days = (col) => `EXTRACT(EPOCH FROM now() - ${col}) / 86400`;
const ACTIVE_KEYS = "iam_access_keys k WHERE k.role_id = r.id AND k.status = 'Active' AND k.deleted_at IS NULL";
const glob = (make, contains = true) => (op, values, P, key) => anyOf(op, key, values.map((v) => make(P(likeOf(v, contains)))));
const eq = (expr) => (op, values, P, key) => anyOf(op, key, values.map((v) => `${expr} = ${P(v.toLowerCase())}`));
const num = (expr) => (op, values, P, key) => `(${values.map((v) => `${expr} ${SQL_OP[op]} ${P(number(key, v))}`).join(op === '!=' ? ' AND ' : ' OR ')})`;
const yesno = (yesSql, noSql) => (op, values, P, key) => anyOf(op, key, values.map((v) => (yes(key, v) ? yesSql : noSql)));
// Actions are looked up through the index on (action, status, role): a name in full as it is, a wildcard as the
// actions it stands for in the IAM catalogue (s3:Get* is some forty names). Only a pattern the catalogue cannot
// expand (or one that stands for thousands of actions) is matched as text.
const action = (status) => (op, values, P, key) => {
  const names = [], patterns = [];
  for (const v of values) {
    if (!/[*?]/.test(v)) { names.push(canonicalAction(v)); continue; }
    const all = /^[\w-]+:/.test(v) ? expandAction(v) : [];
    if (all.length && all.length <= 3000) names.push(...all); else patterns.push(v);
  }
  const st = status ? ` AND x.status = '${status}'` : '';
  const ors = [];
  // worked out once per query (a materialised CTE), then each identity is looked up in the result
  if (names.length) ors.push(`r.id IN (SELECT role_id FROM ${P.cte(`SELECT DISTINCT x.role_id FROM role_actions x WHERE x.action = ANY(${P([...new Set(names)])}::text[])${st}`)})`);
  for (const v of patterns) ors.push(`EXISTS (SELECT 1 FROM role_actions x WHERE x.role_id = r.id AND x.action ILIKE ${P(likeOf(v, false))}${st})`);
  return anyOf(op, key, ors);
};
const HAS_MFA = "EXISTS (SELECT 1 FROM iam_user_details d WHERE d.role_id = r.id AND jsonb_array_length(coalesce(to_jsonb(d.mfa), '[]'::jsonb)) > 0)";
const HAS_CONSOLE = 'EXISTS (SELECT 1 FROM iam_user_details d WHERE d.role_id = r.id AND d.password_enabled)';
const AWS = {
  cloud: (op, values, P, key) => anyOf(op, key, values.map((v) => (v.toLowerCase() === 'aws' ? 'TRUE' : 'FALSE'))),
  name: glob((p) => `r.name ILIKE ${p}`),
  arn: glob((p) => `r.arn ILIKE ${p}`),
  path: glob((p) => `r.path ILIKE ${p}`),
  kind: (op, values, P, key) => anyOf(op, key, values.map((v) => { const x = v.toLowerCase(); return x === 'role' ? "r.kind <> 'iam-user'" : `r.kind = ${P(x === 'user' ? 'iam-user' : x)}`; })),
  account: (op, values, P, key) => anyOf(op, key, values.map((v) => (/^\d{12}$/.test(v) ? `a.account_id = ${P(v)}` : `a.name ILIKE ${P(likeOf(v, true))}`))),
  env: eq('lower(a.environment)'),
  risk: eq('lower(r.risk)'),
  team: eq('lower(r.reviewer_team)'),
  grants: action(null), uses: action('used'), unused: action('unused'), unverified: action('unconfirmed'),
  policy: glob((p) => `EXISTS (SELECT 1 FROM role_policies p WHERE p.role_id = r.id AND p.name ILIKE ${p})`),
  boundary: yesno('r.boundary_arn IS NOT NULL', 'r.boundary_arn IS NULL'),
  tag: (op, values, P, key) => anyOf(op, key, values.map((v) => { const [k, ...rest] = v.split('=');
    return rest.length ? `r.tags ->> ${P(k)} ILIKE ${P(likeOf(rest.join('='), false))}` : `jsonb_exists(coalesce(r.tags, '{}'::jsonb), ${P(k)})`; })),
  finding: (op, values, P, key) => anyOf(op, key, values.map((v) => { const p = P(v.toLowerCase());
    return `EXISTS (SELECT 1 FROM flags f WHERE f.role_id = r.id AND f.status = 'open' AND (f.category = ${p} OR f.control = ${p} OR substring(f.control from position('.' in f.control) + 1) = ${p}))`; })),
  caller: glob((p) => `EXISTS (SELECT 1 FROM principals p WHERE p.role_id = r.id AND p.kind <> 'session' AND p.display ILIKE ${p})`),
  permissions: num('r.granted_count'),
  unusedcount: num('r.unused_count'),
  unusedpct: num('(CASE WHEN r.granted_count > 0 THEN 100.0 * r.unused_count / r.granted_count ELSE 0 END)'),
  score: num('r.risk_score'),
  callers: num("(SELECT count(*) FROM principals p WHERE p.role_id = r.id AND p.kind <> 'session')"),
  idle: num(`coalesce(${days('r.last_used_at')}, ${NEVER})`),
  age: num(days('r.created_in_aws')),
  mfa: yesno(`(r.kind = 'iam-user' AND ${HAS_MFA})`, `(r.kind = 'iam-user' AND NOT ${HAS_MFA})`),
  console: yesno(`(r.kind = 'iam-user' AND ${HAS_CONSOLE})`, `(r.kind = 'iam-user' AND NOT ${HAS_CONSOLE})`),
  keys: num(`(SELECT count(*) FROM ${ACTIVE_KEYS})`),
  keyage: num(`(SELECT max(${days('k.created_at')}) FROM ${ACTIVE_KEYS})`),
  keyidle: num(`(SELECT max(coalesce(${days('greatest(k.last_used_at, k.trail_last_seen)')}, ${NEVER})) FROM ${ACTIVE_KEYS})`),
};

// ---------------------------------------------------------------- Google Cloud: a term as a test on a stored principal
const CMP = { '=': (a, b) => a === b, '!=': (a, b) => a !== b, '>': (a, b) => a > b, '>=': (a, b) => a >= b, '<': (a, b) => a < b, '<=': (a, b) => a <= b };
const gAny = (op, key, tests) => { if (op !== '=' && op !== '!=') fail(`${key} takes = or !=, not ${op}.`); return op === '!=' ? (p) => !tests.some((t) => t(p)) : (p) => tests.some((t) => t(p)); };
const gNum = (get) => (op, values, key) => { const ns = values.map((v) => number(key, v));
  return (p) => { const x = get(p); if (x == null) return false; return op === '!=' ? ns.every((n) => x !== n) : ns.some((n) => CMP[op](x, n)); }; };
const GKIND = { sa: 'serviceaccount', 'service-account': 'serviceaccount', serviceaccount: 'serviceaccount' };
const GCP = {
  cloud: (op, values, key) => gAny(op, key, values.map((v) => () => ['gcp', 'google', 'google-cloud'].includes(v.toLowerCase()))),
  name: (op, values, key) => gAny(op, key, values.map((v) => { const t = globTest(v); return (p) => t(p.member) || t(p.email) || t(p.display_name); })),
  kind: (op, values, key) => gAny(op, key, values.map((v) => { const k = GKIND[v.toLowerCase()] || v.toLowerCase(); return (p) => String(p.kind).toLowerCase() === k; })),
  account: (op, values, key) => gAny(op, key, values.map((v) => { const t = globTest(v); return (p) => t(p.project_id) || (p.reach || []).some(t); })),
  risk: (op, values, key) => gAny(op, key, values.map((v) => (p) => String(p.risk).toLowerCase() === v.toLowerCase())),
  finding: (op, values, key) => gAny(op, key, values.map((v) => { const id = v.toLowerCase().replace(/^gcp\./, ''); return (p) => p.reasons.some((r) => !r.rule && r.severity !== 'info' && (r.id === id || r.id === v.toLowerCase())); })),
  disabled: (op, values, key) => gAny(op, key, values.map((v) => { const want = yes(key, v); return (p) => !!p.disabled === want; })),
  permissions: gNum((p) => p.permissions),
  score: gNum((p) => p.risk_score),
  reach: gNum((p) => (p.reach || []).length),
  keys: gNum((p) => p.activeKeys.length),
  keyage: gNum((p) => (p.activeKeys.length ? Math.max(...p.activeKeys.map((k) => (Date.now() - new Date(k.created).getTime()) / 864e5)) : null)),
};

export const CLOUDS = { aws: 'AWS', gcp: 'Google Cloud' };
const HELP = {
  cloud: 'aws or gcp', name: 'its name; * is a wildcard (name = *-admin)', arn: 'its ARN', path: 'its IAM path',
  kind: 'AWS: role, user, or a kind of role (custom, service-linked, identity-center). Google Cloud: user, group, serviceaccount, federated, public',
  account: 'the AWS account (name or 12-digit ID) or Google Cloud project it is in or reaches', env: 'the account\'s environment: production, staging…',
  risk: 'high, medium or low', team: 'the review team', grants: 'an action it is allowed (grants = iam:PassRole, grants = s3:*)', uses: 'an action it was seen using',
  unused: 'an action it is allowed and did not use', unverified: 'an action whose use cannot be verified', policy: 'a policy attached to it or inline, by name',
  boundary: 'yes or no: has a permissions boundary', tag: 'a tag key, or key=value (tag = team=platform)', finding: 'an open finding, by kind or control (finding = wildcard, finding = key)',
  caller: 'who was seen using it', permissions: 'how many actions it is allowed', unusedcount: 'how many of them it did not use', unusedpct: 'the share it did not use, in percent',
  score: 'its risk score', callers: 'how many callers were seen', idle: 'days since it was last used; "never" for never used (idle > 90)', age: 'days since it was created',
  mfa: 'IAM users: yes or no, has an MFA device', console: 'IAM users: yes or no, has a console password', keys: 'how many active keys it has',
  keyage: 'days since its oldest active key was made', keyidle: 'IAM users: days since an active key was last used', disabled: 'Google Cloud: yes or no, the service account is disabled',
  reach: 'Google Cloud: how many projects it reaches',
};
/** Every key, what it means, and the clouds it exists on (for the editor's help). */
export const IDENTITY_KEYS = Object.fromEntries(Object.keys(HELP).map((k) => [k, { help: HELP[k], clouds: [AWS[k] && 'aws', GCP[k] && 'gcp'].filter(Boolean) }]));
const ALL_KEYS = Object.keys(HELP);

/**
 * Read a rule about identities. Returns { errors, clouds, aws, gcp }: `aws` is { with, where, params } for
 * `roles r JOIN cloud_accounts a`, `gcp` a test on a principal; each is null where the rule does not apply.
 */
export function compileIdentityRule(rule, params = []) {
  const { ast, errors } = parseRule(rule);
  if (errors.length) return { errors, clouds: [], aws: null, gcp: null };
  if (!ast) return { errors: ['Write at least one term: an empty rule would match every identity.'], clouds: [], aws: null, gcp: null };
  const terms = leaves(ast).filter((l) => l.t === 'term');
  for (const t of terms) {
    const k = keyOf(t.key);
    if (!HELP[k]) { const near = closest(t.key, [...ALL_KEYS, ...Object.keys(ALIASES)]); errors.push(near ? `No key called "${t.key}". Did you mean ${near}?` : `No key called "${t.key}".`); }
  }
  if (errors.length) return { errors: [...new Set(errors)], clouds: [], aws: null, gcp: null };
  const keys = [...new Set(terms.map((t) => keyOf(t.key)))];
  const onAws = keys.every((k) => AWS[k]), onGcp = keys.every((k) => GCP[k]);
  if (!onAws && !onGcp) {
    return { errors: [`This rule mixes keys that exist only on AWS (${keys.filter((k) => !GCP[k]).join(', ')}) with keys that exist only on Google Cloud (${keys.filter((k) => !AWS[k]).join(', ')}), so it can match nothing. Write one rule per cloud.`], clouds: [], aws: null, gcp: null };
  }
  const out = { errors: [], clouds: [], aws: null, gcp: null };
  try {
    if (onAws) {
      const ctes = [];
      const P = (v) => { params.push(v); return `$${params.length}`; };
      P.cte = (sql) => { ctes.push(sql); return `rule_set_${ctes.length}`; };
      const sql = (n) => {
        if (n.t === 'and' || n.t === 'or') return `(${n.kids.map(sql).join(n.t === 'and' ? ' AND ' : ' OR ')})`;
        if (n.t === 'not') return `NOT ${sql(n.kid)}`;
        if (n.t === 'text') { const v = P(likeOf(n.value, true)); return `(r.name ILIKE ${v} OR r.arn ILIKE ${v})`; }
        return AWS[keyOf(n.key)](n.op, n.values, P, n.key);
      };
      const where = sql(ast);
      out.aws = { where, params, with: ctes.length ? `WITH ${ctes.map((c, i) => `rule_set_${i + 1} AS MATERIALIZED (${c})`).join(', ')} ` : '' };
      out.clouds.push('aws');
    }
    if (onGcp) {
      const test = (n) => {
        if (n.t === 'text') { const t = globTest(n.value); return (p) => t(p.member) || t(p.email) || t(p.display_name); }
        return GCP[keyOf(n.key)](n.op, n.values, n.key);
      };
      const made = new Map(leaves(ast).map((l) => [l, test(l)]));
      out.gcp = (p) => evaluate(ast, (l) => made.get(l)(p));
      out.clouds.push('gcp');
    }
  } catch (e) { if (!e.rule) throw e; return { errors: [e.message], clouds: [], aws: null, gcp: null }; }
  return out;
}

const FROM = "roles r JOIN cloud_accounts a ON a.id = r.account_id WHERE r.deleted_at IS NULL AND a.status <> 'planned'";
/** Google Cloud principals as the rules see them. */
export async function loadGcpPrincipals() {
  const rows = (await query(`SELECT id, member, kind, email, display_name, project_id, disabled, keys, permissions, reach, risk, risk_score, risk_reasons FROM gcp_principals`).catch((e) => { if (e.code === '42P01') return { rows: [] }; throw e; })).rows;
  const now = Date.now();
  return rows.map((p) => ({ ...p, reasons: p.risk_reasons || [],
    activeKeys: (p.keys || []).filter((k) => !k.disabled && (!k.expires || new Date(k.expires).getTime() > now)) }));
}

/** The identities a rule matches now, for the person asking: how many, of how many, and the first few. */
export async function previewIdentityRule(user, rule, limit = 25) {
  const params = [];
  const scope = scopeSql(user, 'r.account_id', params);
  const c = compileIdentityRule(rule, params);
  if (c.errors.length) return { errors: c.errors, total: 0, of: null, items: [], clouds: [] };
  try { return await run(); } catch (e) { if (!e.rule) throw e; return { errors: [e.message], total: 0, of: null, items: [], clouds: [] }; }
  async function run() {
  const n = Math.min(100, Math.max(1, limit));
  // Google Cloud is the workspace's, not an account's: only for those who see every account
  const seeGcp = !user?.scope_accounts;
  const ap = [];
  const [rows, all, gcp] = await Promise.all([
    c.aws ? guardedRead(`${c.aws.with}SELECT r.id, r.name, r.kind, r.risk, a.name AS account, a.environment, count(*) OVER()::int AS total
                     FROM ${FROM} AND ${scope} AND ${c.aws.where} ORDER BY r.risk_score DESC NULLS LAST, r.name LIMIT ${n}`, params, 5000) : { rows: [] },
    query(`SELECT count(*)::int n FROM ${FROM} AND ${scopeSql(user, 'r.account_id', ap)}`, ap),
    seeGcp ? loadGcpPrincipals() : [],
  ]);
  const hits = c.gcp ? gcp.filter(c.gcp) : [];
  const awsTotal = rows.rows[0]?.total ?? 0;
  const items = [...rows.rows.map(({ total, ...x }) => ({ ...x, cloud: 'aws' })),
    ...hits.slice(0, Math.max(0, n - rows.rows.length)).map((p) => ({ id: p.id, name: p.email || p.display_name || p.member, kind: p.kind, risk: p.risk, account: p.project_id || 'Google Cloud', cloud: 'gcp' }))];
  return { errors: [], total: awsTotal + hits.length, of: all.rows[0].n + gcp.length, items, clouds: c.clouds, byCloud: { aws: awsTotal, gcp: hits.length } };
  }
}

/** Everything a rule matches, estate-wide: AWS identity ids and Google Cloud principal ids. */
export async function matchIdentityRule(rule, gcpPrincipals = null) {
  const c = compileIdentityRule(rule);
  if (c.errors.length) return { errors: c.errors, aws: [], gcp: [], clouds: [] };
  let aws = [];
  try { aws = c.aws ? (await guardedRead(`${c.aws.with}SELECT r.id FROM ${FROM} AND ${c.aws.where}`, c.aws.params, 30000)).rows.map((x) => x.id) : []; }
  catch (e) { if (!e.rule) throw e; return { errors: [e.message], aws: [], gcp: [], clouds: [] }; }
  const gcp = c.gcp ? (gcpPrincipals || await loadGcpPrincipals()).filter(c.gcp).map((p) => p.id) : [];
  return { errors: [], aws, gcp, clouds: c.clouds };
}
