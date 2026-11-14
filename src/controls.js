// Manage policy. Every rule the tool checks is a control: the built-in ones are listed here (the catalogue), and a
// workspace can give one another severity or turn it off (control_overrides), and write its own (custom_controls).
// The places that make findings ask this module what applies: the analyser, the IAM user checks, the Trust map, the
// Google Cloud analysis, and the worker job that files custom controls (policySync.js).
import { z } from 'zod';
import { query } from './db.js';
import { scopeSql } from './auth/rbac.js';
import { toCsv } from './csv.js';

import { BUILTIN, BY_ID, DOMAINS, SEVERITIES, INBOX, TRUST } from './controlCatalog.js';

export * from './controlCatalog.js';

// ---------------------------------------------------------------- what applies now
/** The workspace's policy: overrides of built-in controls and its enabled custom controls. Read before each analysis. */
export async function loadPolicy() {
  let o = [], cu = [];
  try {
    [o, cu] = await Promise.all([
      query('SELECT control_id, severity, enabled, updated_at FROM control_overrides').then((r) => r.rows),
      query('SELECT id, name, description, target, rule, severity, remediation, enabled, updated_at FROM custom_controls ORDER BY created_at').then((r) => r.rows),
    ]);
  } catch (e) { if (e.code !== '42P01') throw e; }          // before migrations
  const over = new Map(o.filter((x) => BY_ID.has(x.control_id)).map((x) => [x.control_id, { severity: x.severity, enabled: x.enabled }]));
  const sig = [...o.map((x) => `${x.control_id}:${x.severity}:${x.enabled}`).sort(), ...cu.map((x) => `${x.id}:${new Date(x.updated_at).getTime()}`)].join('|');
  return { over, custom: cu.filter((x) => x.enabled), sig };
}

// ---------------------------------------------------------------- rules for identities (roles and IAM users), as SQL
const num = (expr) => ({ type: 'num', expr });
const glob = (make, { contains = true } = {}) => ({ type: 'glob', make, contains });
const yesno = (yesSql, noSql) => ({ type: 'yesno', yesSql, noSql });
const action = (status) => glob((p) => `EXISTS (SELECT 1 FROM role_actions x WHERE x.role_id = r.id AND x.action ILIKE ${p}${status ? ` AND x.status = '${status}'` : ''})`, { contains: false });
const days = (col) => `EXTRACT(EPOCH FROM now() - ${col}) / 86400`;
const ACTIVE_KEYS = "iam_access_keys k WHERE k.role_id = r.id AND k.status = 'Active' AND k.deleted_at IS NULL";
export const IDENTITY_KEYS = {
  name: [glob((p) => `r.name ILIKE ${p}`), 'the role or user name; * is a wildcard (name:*-admin)'],
  arn: [glob((p) => `r.arn ILIKE ${p}`), 'its ARN'],
  path: [glob((p) => `r.path ILIKE ${p}`), 'its IAM path'],
  kind: [{ type: 'kind' }, 'role, user, or a kind of role: custom, service-linked, identity-center…'],
  account: [{ type: 'account' }, 'an account by name or 12-digit ID'],
  env: [{ type: 'eq', expr: 'lower(a.environment)' }, 'the account\'s environment: production, staging…'],
  risk: [{ type: 'eq', expr: 'lower(r.risk)' }, 'high, medium or low'],
  team: [{ type: 'eq', expr: 'lower(r.reviewer_team)' }, 'the review team'],
  grants: [action(null), 'an action it is allowed (grants:iam:PassRole, grants:s3:*)'],
  uses: [action('used'), 'an action it was seen using'],
  unused: [action('unused'), 'an action it is allowed and did not use'],
  unverified: [action('unconfirmed'), 'an action whose use cannot be verified'],
  policy: [glob((p) => `EXISTS (SELECT 1 FROM role_policies p WHERE p.role_id = r.id AND p.name ILIKE ${p})`), 'a policy attached to it or inline, by name (policy:AdministratorAccess)'],
  boundary: [yesno('r.boundary_arn IS NOT NULL', 'r.boundary_arn IS NULL'), 'yes or no: has a permissions boundary'],
  tag: [{ type: 'tag' }, 'a tag key, or key=value (tag:team=platform)'],
  finding: [{ type: 'finding' }, 'an open finding, by kind or control (finding:wildcard, finding:trust.public)'],
  caller: [glob((p) => `EXISTS (SELECT 1 FROM principals p WHERE p.role_id = r.id AND p.kind <> 'session' AND p.display ILIKE ${p})`), 'who was seen using it'],
  permissions: [num('r.granted_count'), 'how many actions it is allowed (permissions:>1000)'],
  unusedcount: [num('r.unused_count'), 'how many of them it did not use'],
  unusedpct: [num('(CASE WHEN r.granted_count > 0 THEN 100.0 * r.unused_count / r.granted_count ELSE 0 END)'), 'the share it did not use, in percent'],
  score: [num('r.risk_score'), 'its risk score'],
  callers: [num("(SELECT count(*) FROM principals p WHERE p.role_id = r.id AND p.kind <> 'session')"), 'how many callers were seen'],
  idle: [num(`coalesce(${days('r.last_used_at')}, 1000000)`), 'days since IAM last saw it used; never used counts as longest (idle:>90)'],
  age: [num(days('r.created_in_aws')), 'days since it was created'],
  mfa: [yesno("r.kind = 'iam-user' AND EXISTS (SELECT 1 FROM iam_user_details d WHERE d.role_id = r.id AND jsonb_array_length(coalesce(to_jsonb(d.mfa), '[]'::jsonb)) > 0)",
    "r.kind = 'iam-user' AND NOT EXISTS (SELECT 1 FROM iam_user_details d WHERE d.role_id = r.id AND jsonb_array_length(coalesce(to_jsonb(d.mfa), '[]'::jsonb)) > 0)"), 'IAM users: yes or no, has an MFA device'],
  console: [yesno("r.kind = 'iam-user' AND EXISTS (SELECT 1 FROM iam_user_details d WHERE d.role_id = r.id AND d.password_enabled)",
    "r.kind = 'iam-user' AND NOT EXISTS (SELECT 1 FROM iam_user_details d WHERE d.role_id = r.id AND d.password_enabled)"), 'IAM users: yes or no, has a console password'],
  keys: [num(`(SELECT count(*) FROM ${ACTIVE_KEYS})`), 'IAM users: how many active access keys'],
  keyage: [num(`(SELECT max(${days('k.created_at')}) FROM ${ACTIVE_KEYS})`), 'IAM users: days since its oldest active key was made'],
  keyidle: [num(`(SELECT max(coalesce(${days('greatest(k.last_used_at, k.trail_last_seen)')}, 1000000)) FROM ${ACTIVE_KEYS})`), 'IAM users: days since an active key was last used; never used counts as longest'],
};
const ID_KEY_NAMES = Object.keys(IDENTITY_KEYS);
// keys of the Trust map's query language a custom way-in control may not use: they describe the review, not the trust
export const WAYIN_REVIEW_KEYS = ['attention', 'expected', 'decided', 'severity', 'finding'];

function closest(word, list) {
  const d = (a, b) => { const m = Array.from({ length: a.length + 1 }, (_, i) => [i]); for (let j = 1; j <= b.length; j++) m[0][j] = j;
    for (let i = 1; i <= a.length; i++) for (let j = 1; j <= b.length; j++) m[i][j] = Math.min(m[i - 1][j] + 1, m[i][j - 1] + 1, m[i - 1][j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
    return m[a.length][b.length]; };
  const best = list.map((k) => [k, d(word, k)]).sort((x, y) => x[1] - y[1])[0];
  return best && best[1] <= 2 ? best[0] : null;
}
const likeOf = (v, contains) => {
  const esc = v.replace(/[\\%_]/g, (ch) => `\\${ch}`);
  return /[*?]/.test(v) ? esc.replace(/\*/g, '%').replace(/\?/g, '_') : contains ? `%${esc}%` : esc;
};

/**
 * A rule about roles and IAM users, as a WHERE clause over `roles r JOIN cloud_accounts a`.
 * Terms are key:value; a space between terms means and, a comma inside a value means or, a leading - means not.
 * Returns { where, params, errors }: errors is empty when the rule can run.
 */
export function compileIdentityRule(rule, params = []) {
  const errors = [], parts = [];
  const P = (v) => { params.push(v); return `$${params.length}`; };
  const re = /(-?)(\w+):("([^"]*)"|\S+)|"([^"]*)"|(\S+)/g; let m;
  while ((m = re.exec(String(rule || '')))) {
    if (!m[2]) {                                             // a bare word: the name or ARN contains it
      const v = likeOf(m[5] ?? m[6], true);
      parts.push(`(r.name ILIKE ${P(v)} OR r.arn ILIKE ${P(v)})`);
      continue;
    }
    const key = m[2].toLowerCase(), raw = m[4] ?? m[3];
    const def = IDENTITY_KEYS[key]?.[0];
    if (!def) { const near = closest(key, ID_KEY_NAMES); errors.push(near ? `No key called "${key}". Did you mean ${near}:${raw}?` : `No key called "${key}".`); continue; }
    const ors = [];
    for (const v0 of raw.split(',').map((x) => x.trim()).filter(Boolean)) {
      const v = v0.toLowerCase();
      if (def.type === 'glob') ors.push(def.make(P(likeOf(v0, def.contains))));
      else if (def.type === 'eq') ors.push(`${def.expr} = ${P(v)}`);
      else if (def.type === 'kind') ors.push(v === 'role' ? "r.kind <> 'iam-user'" : `r.kind = ${P(v === 'user' ? 'iam-user' : v)}`);
      else if (def.type === 'account') ors.push(/^\d{12}$/.test(v) ? `a.account_id = ${P(v)}` : `a.name ILIKE ${P(likeOf(v0, true))}`);
      else if (def.type === 'yesno') {
        if (!['yes', 'no', 'true', 'false'].includes(v)) errors.push(`${key}: takes yes or no, not "${v0}".`);
        else ors.push(v === 'yes' || v === 'true' ? def.yesSql : def.noSql);
      } else if (def.type === 'tag') {
        const [k, ...rest] = v0.split('=');
        ors.push(rest.length ? `r.tags ->> ${P(k)} ILIKE ${P(likeOf(rest.join('='), false))}` : `jsonb_exists(coalesce(r.tags, '{}'::jsonb), ${P(k)})`);
      } else if (def.type === 'finding') {
        const p = P(v);
        ors.push(`EXISTS (SELECT 1 FROM flags f WHERE f.role_id = r.id AND f.status = 'open' AND (f.category = ${p} OR f.control = ${p} OR f.control LIKE '%.' || ${p}))`);
      } else if (def.type === 'num') {
        const n = /^(>=|<=|>|<|=)?\s*(\d+(?:\.\d+)?)$/.exec(v);
        if (!n) errors.push(`${key}: takes a number, with >, >=, < or <= before it (${key}:>90), not "${v0}".`);
        else ors.push(`${def.expr} ${n[1] || '='} ${P(Number(n[2]))}`);
      }
    }
    if (ors.length) parts.push(`${m[1] ? 'NOT ' : ''}(${ors.join(' OR ')})`);
  }
  if (!parts.length && !errors.length) errors.push('Write at least one term: an empty rule would match every identity.');
  return { where: parts.join(' AND '), params, errors };
}
const FROM = "roles r JOIN cloud_accounts a ON a.id = r.account_id WHERE r.deleted_at IS NULL AND a.status <> 'planned'";

/** The identities a rule matches now, for the person asking: how many, and the first few. */
export async function previewIdentityRule(user, rule, limit = 25) {
  const params = [];
  const scope = scopeSql(user, 'r.account_id', params);
  const { where, errors } = compileIdentityRule(rule, params);
  if (errors.length) return { errors, total: 0, of: 0, items: [] };
  const [rows, all] = await Promise.all([
    query(`SELECT r.id, r.name, r.kind, r.risk, a.name AS account, a.environment, count(*) OVER()::int AS total
             FROM ${FROM} AND ${scope} AND (${where}) ORDER BY r.risk_score DESC NULLS LAST, r.name LIMIT ${Math.min(100, Math.max(1, limit))}`, params),
    (() => { const ap = []; return query(`SELECT count(*)::int n FROM ${FROM} AND ${scopeSql(user, 'r.account_id', ap)}`, ap); })(),
  ]);
  return { errors: [], total: rows.rows[0]?.total ?? 0, of: all.rows[0]?.n ?? null, items: rows.rows.map(({ total, ...x }) => x) };
}

/** Every identity a custom control matches, estate-wide (the worker files a finding on each). */
export async function matchIdentityRule(rule) {
  const { where, params, errors } = compileIdentityRule(rule);
  if (errors.length) return { errors, ids: [] };
  return { errors: [], ids: (await query(`SELECT r.id FROM ${FROM} AND (${where})`, params)).rows.map((x) => x.id) };
}

// ---------------------------------------------------------------- the catalogue, with the workspace's changes
export class ControlError extends Error { constructor(status, message, field) { super(message); this.status = status; this.field = field; } }

/**
 * Every control: built-in and custom, with its severity now, whether the workspace changed it, and its open findings.
 * `q` filters: words (name, description, id, rule), and domain:, severity:, source:builtin|custom, state:on|off|changed.
 */
export async function listControls(user, q = '') {
  const sp = [];
  const [over, custom, counts] = await Promise.all([
    query('SELECT o.*, u.name AS by FROM control_overrides o LEFT JOIN users u ON u.id = o.updated_by'),
    query('SELECT c.*, u.name AS by FROM custom_controls c LEFT JOIN users u ON u.id = c.updated_by ORDER BY lower(c.name)'),
    query(`SELECT f.control, count(*)::int n, count(*) FILTER (WHERE d.id IS NULL)::int undecided
             FROM flags f JOIN roles r ON r.id = f.role_id LEFT JOIN review_decisions d ON d.flag_id = f.id
            WHERE f.status = 'open' AND f.control IS NOT NULL AND r.deleted_at IS NULL AND ${scopeSql(user, 'r.account_id', sp)} GROUP BY 1`, sp),
  ]);
  const ov = new Map(over.rows.map((x) => [x.control_id, x])), n = new Map(counts.rows.map((x) => [x.control, x]));
  const filed = (id, where) => (where === INBOX || where === TRUST || id.startsWith('custom.') ? { open: n.get(id)?.n ?? 0, undecided: n.get(id)?.undecided ?? 0 } : { open: null, undecided: null });
  const items = [
    ...BUILTIN.map((b) => {
      const o = ov.get(b.id);
      const changed = !!o && (!o.enabled || !!o.severity);
      return { id: b.id, source: 'builtin', domain: b.domain, name: b.name, what: b.what, fix: b.fix, where: b.where,
        defaultSeverity: b.severity, varies: b.varies, severity: o?.severity || b.severity, enabled: o ? o.enabled : true, changed,
        note: changed ? o.note : null, updatedBy: changed ? o.by : null, updatedAt: changed ? o.updated_at : null, ...filed(b.id, b.where) };
    }),
    ...custom.rows.map((x) => ({ id: `custom.${x.id}`, source: 'custom', domain: 'custom', name: x.name, what: x.description, fix: x.remediation,
      where: x.target === 'way-in' ? TRUST : INBOX, target: x.target, rule: x.rule, defaultSeverity: x.severity, varies: null, severity: x.severity, enabled: x.enabled, changed: false,
      note: null, updatedBy: x.by, updatedAt: x.updated_at, ...filed(`custom.${x.id}`) })),
  ];
  const terms = [...String(q || '').matchAll(/(\w+):(\S+)|"([^"]*)"|(\S+)/g)].map((m) => (m[1] ? [m[1].toLowerCase(), m[2].toLowerCase()] : ['text', (m[3] ?? m[4]).toLowerCase()]));
  const hit = (x, [k, v]) => {
    const vs = v.split(',');
    if (k === 'domain') return vs.includes(x.domain);
    if (k === 'severity') return vs.includes(x.severity || 'varies');
    if (k === 'source') return vs.includes(x.source);
    if (k === 'state') return vs.some((s) => (s === 'on' ? x.enabled : s === 'off' ? !x.enabled : s === 'changed' ? x.changed || x.source === 'custom' : false));
    if (k === 'findings') return vs.some((s) => (s === 'yes' ? x.open > 0 : s === 'no' ? !x.open : false));
    return [x.id, x.name, x.what, x.rule, x.fix].some((t) => String(t || '').toLowerCase().includes(k === 'text' ? v : `${k}:${v}`));
  };
  const shown = items.filter((x) => terms.every((t) => hit(x, t)));
  return { items: shown, total: items.length, domains: DOMAINS,
    summary: { builtin: BUILTIN.length, custom: custom.rows.length, changed: items.filter((x) => x.changed).length, off: items.filter((x) => !x.enabled).length } };
}

export function controlsCsv(items) {
  return toCsv([
    ['ID', (x) => x.id], ['Domain', (x) => DOMAINS[x.domain]], ['Control', (x) => x.name], ['What it checks', (x) => x.what], ['Source', (x) => x.source],
    ['Severity', (x) => x.severity || 'varies'], ['Built-in severity', (x) => (x.source === 'custom' ? '' : x.defaultSeverity || `varies: ${x.varies}`)], ['On', (x) => (x.enabled ? 'yes' : 'no')],
    ['Changed here', (x) => (x.changed ? 'yes' : 'no')], ['Why', (x) => x.note], ['Applies to', (x) => (x.target === 'way-in' ? 'ways in' : x.target === 'identity' ? 'roles and IAM users' : '')],
    ['Rule', (x) => x.rule], ['Open findings', (x) => x.open], ['Shows in', (x) => x.where], ['How to fix', (x) => x.fix], ['Changed by', (x) => x.updatedBy], ['Changed at', (x) => x.updatedAt],
  ], items);
}

export const OverrideIn = z.object({
  severity: z.enum(SEVERITIES).nullable().optional(),       // null: back to the built-in severity
  enabled: z.boolean().optional(),
  note: z.string().trim().max(500).nullable().optional(),
});
/** Change a built-in control. Open findings follow at once where that is one statement; the rest on the next analysis. */
export async function setOverride(user, id, body) {
  const b = BY_ID.get(id);
  if (!b) throw new ControlError(404, 'No such control.');
  const patch = OverrideIn.parse(body);
  const cur = (await query('SELECT * FROM control_overrides WHERE control_id = $1', [id])).rows[0];
  const next = { severity: patch.severity !== undefined ? patch.severity : cur?.severity ?? null, enabled: patch.enabled ?? cur?.enabled ?? true, note: patch.note !== undefined ? patch.note : cur?.note ?? null };
  const before = { severity: cur?.severity ?? null, enabled: cur?.enabled ?? true };
  if (next.enabled && !next.severity) await query('DELETE FROM control_overrides WHERE control_id = $1', [id]);
  else await query(`INSERT INTO control_overrides(control_id, severity, enabled, note, updated_by, updated_at) VALUES ($1,$2,$3,$4,$5, now())
    ON CONFLICT (control_id) DO UPDATE SET severity = EXCLUDED.severity, enabled = EXCLUDED.enabled, note = EXCLUDED.note, updated_by = EXCLUDED.updated_by, updated_at = now()`,
  [id, next.severity, next.enabled, next.note, user.id]);
  // open findings follow now; a severity that goes back to "varies", and a control turned on again, need the next analysis
  let touched = 0;
  if (!next.enabled) touched = (await query(`UPDATE flags SET status = 'resolved', updated_at = now() WHERE control = $1 AND status = 'open'`, [id])).rowCount;
  else if (next.severity || b.severity) touched = (await query(`UPDATE flags SET severity = $2, updated_at = now() WHERE control = $1 AND status = 'open' AND severity <> $2`, [id, next.severity || b.severity])).rowCount;
  return { id, before, after: { severity: next.severity, enabled: next.enabled }, findingsChanged: touched };
}

export const CustomIn = z.object({
  name: z.string().trim().min(3).max(120),
  description: z.string().trim().max(1000).nullable().optional(),
  target: z.enum(['identity', 'way-in']),
  rule: z.string().trim().min(1).max(2000),
  severity: z.enum(SEVERITIES),
  remediation: z.string().trim().max(1000).nullable().optional(),
  enabled: z.boolean().default(true),
});
const customId = (id) => { const u = z.string().uuid().safeParse(String(id).replace(/^custom\./, '')); if (!u.success) throw new ControlError(404, 'No such control.'); return u.data; };

/** Create or change a custom control. `checkRule(target, rule)` returns the rule's errors (the routes pass it in). */
export async function saveCustom(user, id, body, checkRule) {
  const b = CustomIn.parse(body);
  const errors = await checkRule(b.target, b.rule);
  if (errors.length) throw new ControlError(400, errors[0], 'rule');
  try {
    if (!id) {
      const n = (await query('SELECT count(*)::int n FROM custom_controls')).rows[0].n;
      if (n >= 200) throw new ControlError(400, 'There are 200 custom controls; remove one first.');
      const r = (await query(`INSERT INTO custom_controls(name, description, target, rule, severity, remediation, enabled, created_by, updated_by)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$8) RETURNING id`, [b.name, b.description || null, b.target, b.rule, b.severity, b.remediation || null, b.enabled, user.id])).rows[0];
      return { id: `custom.${r.id}`, created: true, ...b };
    }
    const uid = customId(id);
    const old = (await query('SELECT target FROM custom_controls WHERE id = $1', [uid])).rows[0];
    if (!old) throw new ControlError(404, 'No such control.');
    if (old.target !== b.target) throw new ControlError(400, 'What a control applies to cannot change; make a new one.', 'target');
    await query(`UPDATE custom_controls SET name=$2, description=$3, rule=$4, severity=$5, remediation=$6, enabled=$7, updated_by=$8, updated_at=now() WHERE id=$1`,
      [uid, b.name, b.description || null, b.rule, b.severity, b.remediation || null, b.enabled, user.id]);
    return { id: `custom.${uid}`, created: false, ...b };
  } catch (e) {
    if (e.code === '23505') throw new ControlError(409, 'A custom control already has that name.', 'name');
    throw e;
  }
}
export async function deleteCustom(id) {
  const uid = customId(id);
  const r = (await query('DELETE FROM custom_controls WHERE id = $1 RETURNING name', [uid])).rows[0];
  if (!r) throw new ControlError(404, 'No such control.');
  const f = await query(`UPDATE flags SET status = 'resolved', updated_at = now() WHERE control = $1 AND status = 'open'`, [`custom.${uid}`]);
  return { name: r.name, findingsResolved: f.rowCount };
}
