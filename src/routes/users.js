// IAM users: their access keys (ID, status, age, last use), console password and MFA, groups, and what they did.
// A user is stored as a role of kind 'iam-user', so its permission analysis and calls are on the role page too.
import { keyRules } from '../config.js';
import { Router } from 'express';
import { z } from 'zod';
import { query } from '../db.js';
import { requireUser, requirePerm } from '../auth/sessions.js';
import { scopeSql, inScope } from '../auth/rbac.js';


export const users = Router();
users.use(requireUser);
const wrap = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);
const DAY = 864e5;
const days = (d, now = Date.now()) => (d ? Math.floor((now - new Date(d).getTime()) / DAY) : null);
const latest = (...ds) => ds.filter(Boolean).map((d) => new Date(d)).sort((a, b) => b - a)[0] || null;

/** One key as the page shows it: when it was last used by either source, and what is wrong with it. */
export function keyView(k, now = Date.now(), { rotateDays, staleDays } = keyRules()) {
  const used = latest(k.last_used_at, k.trail_last_seen);
  const age = days(k.created_at, now), idle = used ? days(used, now) : null;
  const active = k.status === 'Active' && !k.deleted_at;
  return { id: k.key_id, status: k.deleted_at ? 'Deleted' : k.status || 'Unknown', created: k.created_at, ageDays: age, lastUsed: used, idleDays: idle,
    lastService: k.last_used_service, lastRegion: k.last_used_region, trailCalls: Number(k.trail_calls || 0), trailFirst: k.trail_first_seen, trailLast: k.trail_last_seen,
    sourceIps: k.source_ips || [], deletedAt: k.deleted_at,
    old: active && age != null && age > rotateDays, unused: active && (used ? idle > staleDays : (age ?? 0) > 14), neverUsed: !used };
}

async function loadUsers(user, { id = null } = {}) {
  const p = [];
  const rows = (await query(
    `SELECT r.id, r.name, r.arn, r.path, r.account_id, r.risk, r.risk_score, r.risk_reasons, r.created_in_aws, r.last_used_at, r.last_activity_at, r.granted_count, r.used_count,
            r.unused_count, r.unconfirmed_count, r.tags, r.aws_id, a.name AS account_name, a.account_id AS aws_account_id, a.environment,
            d.password_enabled, d.password_created, d.password_last_used, d.mfa, d.groups,
            coalesce((SELECT sum(x.count) FROM activity_daily x WHERE x.role_id = r.id AND x.day >= current_date - 6), 0)::bigint AS calls7,
            coalesce((SELECT sum(x.error_count) FROM activity_daily x WHERE x.role_id = r.id AND x.day >= current_date - 6), 0)::bigint AS denied7
       FROM roles r JOIN cloud_accounts a ON a.id = r.account_id LEFT JOIN iam_user_details d ON d.role_id = r.id
      WHERE r.kind = 'iam-user' AND r.deleted_at IS NULL AND ${scopeSql(user, 'r.account_id', p)}${id ? ` AND r.id = $${p.push(id)}` : ''}`, p)).rows;
  const keys = rows.length ? (await query('SELECT * FROM iam_access_keys WHERE role_id = ANY($1) ORDER BY created_at DESC NULLS LAST', [rows.map((r) => r.id)])).rows : [];
  const by = new Map(); for (const k of keys) { if (!by.has(k.role_id)) by.set(k.role_id, []); by.get(k.role_id).push(k); }
  const now = Date.now();
  return rows.map((r) => {
    const ks = (by.get(r.id) || []).map((k) => keyView(k, now));
    const active = ks.filter((k) => k.status === 'Active');
    const mfa = r.mfa || [];
    const lastSeen = latest(r.last_used_at, r.last_activity_at, ...ks.map((k) => k.lastUsed));
    const flags = {
      oldKey: active.some((k) => k.old), unusedKey: active.some((k) => k.unused), twoKeys: active.length > 1,
      console: !!r.password_enabled, noMfa: !!r.password_enabled && !mfa.length, hasKeys: active.length > 0,
      inactive: !lastSeen || days(lastSeen, now) > keyRules().staleDays,
    };
    return {
      id: r.id, name: r.name, arn: r.arn, userId: r.aws_id, account: { id: r.account_id, name: r.account_name, awsAccountId: r.aws_account_id, environment: r.environment },
      risk: r.risk, riskScore: r.risk_score, reasons: r.risk_reasons, created: r.created_in_aws, ageDays: days(r.created_in_aws, now), lastSeen, idleDays: lastSeen ? days(lastSeen, now) : null,
      permissions: { granted: r.granted_count, used: r.used_count, unused: r.unused_count, unconfirmed: r.unconfirmed_count },
      console: { password: !!r.password_enabled, created: r.password_created, lastUsed: r.password_last_used, mfa: mfa.map((m) => ({ type: m.type, serial: m.serial, enabled: m.enabled })) },
      groups: r.groups || [], tags: r.tags || {}, keys: ks, activeKeys: active.length, oldestKeyDays: active.length ? Math.max(...active.map((k) => k.ageDays ?? 0)) : null,
      calls7: Number(r.calls7), denied7: Number(r.denied7), flags,
    };
  });
}

const FLAGS = ['oldKey', 'unusedKey', 'twoKeys', 'console', 'noMfa', 'hasKeys', 'inactive'];
users.get('/iam-users', requirePerm('view'), wrap(async (req, res) => {
  const q = z.object({ q: z.string().max(200).optional(), accounts: z.string().max(4000).optional(), risk: z.enum(['High', 'Medium', 'Low']).optional(),
    flag: z.enum(FLAGS).optional(), sort: z.enum(['risk', 'keyAge', 'lastSeen', 'name', 'calls']).default('risk'),
    limit: z.coerce.number().int().min(1).max(200).default(50), offset: z.coerce.number().int().min(0).default(0) }).parse(req.query);
  const all = await loadUsers(req.user);
  const accts = (q.accounts || '').split(',').filter(Boolean);
  const needle = (q.q || '').toLowerCase();
  const list = all.filter((u) => (!accts.length || accts.includes(u.account.id)) && (!q.risk || u.risk === q.risk) && (!q.flag || u.flags[q.flag])
    && (!needle || `${u.name} ${u.arn} ${u.account.name} ${u.keys.map((k) => k.id).join(' ')}`.toLowerCase().includes(needle)));
  const rank = { High: 0, Medium: 1, Low: 2 };
  const sorters = {
    risk: (a, b) => rank[a.risk] - rank[b.risk] || b.riskScore - a.riskScore || a.name.localeCompare(b.name),
    keyAge: (a, b) => (b.oldestKeyDays ?? -1) - (a.oldestKeyDays ?? -1),
    lastSeen: (a, b) => (b.idleDays ?? 1e9) - (a.idleDays ?? 1e9),
    name: (a, b) => a.name.localeCompare(b.name) || a.account.name.localeCompare(b.account.name),
    calls: (a, b) => b.calls7 - a.calls7,
  };
  list.sort(sorters[q.sort]);
  const scope = accts.length ? all.filter((u) => accts.includes(u.account.id)) : all;
  const keys = scope.flatMap((u) => u.keys.filter((k) => k.status === 'Active'));
  res.json({
    items: list.slice(q.offset, q.offset + q.limit), total: list.length,
    totals: { users: scope.length, high: scope.filter((u) => u.risk === 'High').length, activeKeys: keys.length, oldKeys: keys.filter((k) => k.old).length,
      unusedKeys: keys.filter((k) => k.unused).length, consoleNoMfa: scope.filter((u) => u.flags.noMfa).length, console: scope.filter((u) => u.flags.console).length,
      inactive: scope.filter((u) => u.flags.inactive).length },
    counts: Object.fromEntries(FLAGS.map((f) => [f, scope.filter((u) => u.flags[f]).length])),
    rules: keyRules(),
  });
}));

users.get('/iam-users/:id', requirePerm('view'), wrap(async (req, res) => {
  const id = z.string().uuid().parse(req.params.id);
  const [u] = await loadUsers(req.user, { id });
  if (!u || !inScope(req.user, u.account.id)) return res.status(404).json({ error: 'not_found' });
  // roles this user assumed: it is the caller there. Values are $n parameters; scopeSql only adds parameterised account filters
  const rp = [`user:${u.arn}`]; const where = ['p.key = $1', 'r.deleted_at IS NULL', scopeSql(req.user, 'r.account_id', rp)];
  // nosemgrep: tainted-sql-string -- fixed clauses joined; every value is a $n parameter
  const assumedSql = `SELECT r.id, r.name, a.name AS account_name, p.sessions_count, p.last_seen FROM principals p JOIN roles r ON r.id = p.role_id JOIN cloud_accounts a ON a.id = r.account_id WHERE ${where.join(' AND ')} ORDER BY p.last_seen DESC NULLS LAST LIMIT 50`;
  const [pol, who, roles] = await Promise.all([
    query(`SELECT kind, name, arn, aws_managed FROM role_policies WHERE role_id=$1 ORDER BY kind, name`, [id]),
    // per key (and the console): calls in the last 30 days, last seen
    query(`SELECT p.key, p.kind, p.display, p.first_seen, p.last_seen, coalesce(sum(d.count) FILTER (WHERE d.day >= current_date - 29), 0)::bigint AS calls30,
                  coalesce(sum(d.error_count) FILTER (WHERE d.day >= current_date - 29), 0)::bigint AS denied30
             FROM principals p LEFT JOIN activity_daily d ON d.principal_id = p.id WHERE p.role_id=$1 GROUP BY p.id ORDER BY p.last_seen DESC NULLS LAST`, [id]),
    query(assumedSql, rp),
  ]);
  res.json({ ...u, policies: pol.rows, callers: who.rows.map((x) => ({ ...x, calls30: Number(x.calls30), denied30: Number(x.denied30) })), assumes: roles.rows });
}));
