// Data for radar v3: the estate (accounts as contacts), one account (roles as contacts), the change feed, and blast radius.
import { query } from './db.js';
import { scopeSql, inScope } from './auth/rbac.js';
import { historyFor } from './history.js';

const ADMIN = 15000;
const MAX_HOPS = 4;
const num = (x) => Number(x || 0);
const share = (unused, granted) => (num(granted) ? num(unused) / num(granted) : null);

/** Unused/granted per account at the latest snapshot on or before N days ago. */
async function pastShares(daysAgo, accountIds) {
  if (!accountIds.length) return new Map();
  const rows = (await query(
    `WITH d AS (SELECT account_id, max(day) AS day FROM role_snapshots WHERE day <= current_date - $1::int AND account_id = ANY($2) GROUP BY account_id)
     SELECT s.account_id, sum(s.granted) AS g, sum(s.used) AS u, sum(s.unused) AS un FROM role_snapshots s JOIN d USING (account_id, day) GROUP BY s.account_id`,
    [daysAgo, accountIds])).rows;
  return new Map(rows.map((r) => [r.account_id, { never: share(r.un, r.g), excess: num(r.g) - num(r.u) }]));
}

export async function estate(user) {
  const p = [];
  const accts = (await query(
    `SELECT a.*, count(r.id)::int AS roles, coalesce(sum(r.granted_count),0)::bigint AS granted, coalesce(sum(r.used_count),0)::bigint AS used,
            coalesce(sum(r.unused_count),0)::bigint AS unused, count(r.id) FILTER (WHERE r.risk='High')::int AS high,
            count(r.id) FILTER (WHERE EXISTS (SELECT 1 FROM flags f WHERE f.role_id=r.id AND f.category='unmapped-event' AND f.status='open'))::int AS unidentified
       FROM cloud_accounts a LEFT JOIN roles r ON r.account_id=a.id AND r.deleted_at IS NULL
      WHERE ${scopeSql(user, 'a.id', p)} GROUP BY a.id ORDER BY a.name`, p)).rows;
  const ids = accts.map((a) => a.id);
  const [act, d7, d30, pings, hist] = await Promise.all([
    ids.length ? query(`SELECT r.account_id, sum(d.count)::bigint AS n FROM activity_daily d JOIN roles r ON r.id=d.role_id WHERE d.day >= current_date - 1 AND r.account_id = ANY($1) GROUP BY 1`, [ids]) : { rows: [] },
    pastShares(7, ids), pastShares(30, ids),
    ids.length ? query(`SELECT account_id, count(*)::int AS n, min(CASE severity WHEN 'high' THEN 0 WHEN 'warn' THEN 1 WHEN 'info' THEN 2 ELSE 3 END) AS worst
                          FROM changes WHERE at > now() - interval '7 days' AND account_id = ANY($1) GROUP BY 1`, [ids]) : { rows: [] },
    historyFor(accts),
  ]);
  const actBy = new Map(act.rows.map((r) => [r.account_id, num(r.n)]));
  const pingBy = new Map(pings.rows.map((r) => [r.account_id, r]));
  const sev = ['high', 'warn', 'info', 'good'];
  const out = accts.map((a) => {
    const h = hist.get(a.id);
    return {
      id: a.id, name: a.name, awsAccountId: a.account_id, environment: a.environment, ou: a.ou || null,
      roles: a.roles, granted: num(a.granted), used: num(a.used), unused: num(a.unused), excess: num(a.granted) - num(a.used),
      never: share(a.unused, a.granted), never7: d7.get(a.id)?.never ?? null, never30: d30.get(a.id)?.never ?? null, excess30: d30.get(a.id)?.excess ?? null,
      high: a.high, unidentified: a.unidentified, calls24h: actBy.get(a.id) || 0,
      pings: pingBy.get(a.id)?.n || 0, pingSeverity: pingBy.has(a.id) ? sev[pingBy.get(a.id).worst] : null,
      isNew: Date.now() - new Date(a.created_at).getTime() < 7 * 864e5,
      complete: !!h?.complete, progress: h?.progress ?? 0,
    };
  });
  const withPast = out.filter((a) => a.excess30 != null);
  return {
    accounts: out,
    totals: {
      accounts: out.length, roles: out.reduce((t, a) => t + a.roles, 0), excess: out.reduce((t, a) => t + a.excess, 0),
      // the trend compares like with like: only accounts that have a snapshot from 30 days ago
      excessNowComparable: withPast.reduce((t, a) => t + a.excess, 0), excess30: withPast.length ? withPast.reduce((t, a) => t + a.excess30, 0) : null,
      trendAccounts: withPast.length,
    },
  };
}

export async function accountRadar(user, accountId) {
  if (!inScope(user, accountId)) return null;
  const a = (await query('SELECT * FROM cloud_accounts WHERE id=$1', [accountId])).rows[0];
  if (!a) return null;
  const roles = (await query(
    `SELECT r.id, r.name, r.kind, r.risk, r.granted_count AS granted, r.used_count AS used, r.unused_count AS unused, r.unconfirmed_count AS unconfirmed,
            coalesce(t.calls,0)::bigint AS calls, coalesce(t.denied,0)::bigint AS denied, coalesce(t.c24,0)::bigint AS calls24h,
            s30.granted AS g30, s30.unused AS u30, s7.granted AS g7, s7.unused AS u7, fs.first AS first_snapshot,
            EXISTS (SELECT 1 FROM flags f WHERE f.role_id=r.id AND f.category='unmapped-event' AND f.status='open') AS unidentified
       FROM roles r
       LEFT JOIN (SELECT role_id, sum(count) calls, sum(error_count) denied, sum(count) FILTER (WHERE day >= current_date - 1) c24 FROM activity_daily GROUP BY role_id) t ON t.role_id=r.id
       LEFT JOIN LATERAL (SELECT granted, unused FROM role_snapshots s WHERE s.role_id=r.id AND s.day <= current_date - 30 ORDER BY day DESC LIMIT 1) s30 ON true
       LEFT JOIN LATERAL (SELECT granted, unused FROM role_snapshots s WHERE s.role_id=r.id AND s.day <= current_date - 7 ORDER BY day DESC LIMIT 1) s7 ON true
       LEFT JOIN (SELECT role_id, min(day) AS first FROM role_snapshots GROUP BY role_id) fs ON fs.role_id=r.id
      WHERE r.account_id=$1 AND r.deleted_at IS NULL`, [accountId])).rows;
  const firstDay = (await query('SELECT min(day) AS d FROM role_snapshots WHERE account_id=$1', [accountId])).rows[0].d;
  const pings = (await query(`SELECT role_id, kind, severity FROM changes WHERE account_id=$1 AND role_id IS NOT NULL AND at > now() - interval '7 days' ORDER BY at DESC`, [accountId])).rows;
  const pingBy = new Map(); for (const pg of pings) if (!pingBy.has(pg.role_id)) pingBy.set(pg.role_id, pg);
  const hist = (await historyFor([a])).get(a.id);
  const weekAgo = Date.now() - 7 * 864e5;
  return {
    account: { id: a.id, name: a.name, awsAccountId: a.account_id, environment: a.environment, ou: a.ou, complete: !!hist?.complete, progress: hist?.progress ?? 0 },
    roles: roles.map((r) => ({
      id: r.id, name: r.name, kind: r.kind, risk: r.risk, granted: r.granted, used: r.used, unused: r.unused, unconfirmed: r.unconfirmed,
      calls: num(r.calls), denied: num(r.denied), calls24h: num(r.calls24h), dead: num(r.calls) === 0, excess: r.granted - r.used,
      never: share(r.unused, r.granted) ?? 0, never30: share(r.u30, r.g30), never7: share(r.u7, r.g7),
      // new = first snapshotted after the account's first snapshot, within the last week
      isNew: !!(firstDay && r.first_snapshot && new Date(r.first_snapshot) > new Date(firstDay) && new Date(r.first_snapshot).getTime() > weekAgo),
      unidentified: r.unidentified, ping: pingBy.get(r.id) || null,
    })),
  };
}

export async function changeFeed(user, { accountId = null, days = 7, limit = 60 } = {}) {
  const p = []; const where = [scopeSql(user, 'c.account_id', p), `c.at > now() - make_interval(days => ${Math.max(1, Math.min(90, Number(days) || 7))})`];
  if (accountId) { p.push(accountId); where.push(`c.account_id = $${p.length}`); }
  p.push(Math.min(200, limit));
  const rows = (await query(
    `SELECT c.id, c.kind, c.severity, c.title, c.detail, c.at, c.account_id, a.name AS account_name, c.role_id, r.name AS role_name
       FROM changes c JOIN cloud_accounts a ON a.id=c.account_id LEFT JOIN roles r ON r.id=c.role_id
      WHERE ${where.join(' AND ')} ORDER BY c.at DESC LIMIT $${p.length}`, p)).rows;
  return { items: rows, seenAt: user.radar_seen_at || null };
}

export async function markSeen(user) {
  await query('UPDATE users SET radar_seen_at=now() WHERE id=$1', [user.id]);
}

/** Identities that enter roles, by how much they can reach directly. */
export async function identities(user, q = '') {
  // AWS services (ecs-tasks, lambda…) are not identities anyone can steal; their "reach" is every role that trusts them
  const p = []; const where = [scopeSql(user, 'r.account_id', p), `p.kind NOT IN ('session','service')`];
  if (q) { p.push(`%${q}%`); where.push(`p.display ILIKE $${p.length}`); }
  return (await query(
    `SELECT p.key, max(p.display) AS display, max(p.kind) AS kind, max(p.via) AS via, count(DISTINCT p.role_id)::int AS roles,
            count(DISTINCT r.account_id)::int AS accounts, sum(r.granted_count)::bigint AS perms, max(p.last_seen) AS last_seen,
            bool_or(r.granted_count >= ${ADMIN}) AS reaches_admin
       FROM principals p JOIN roles r ON r.id=p.role_id AND r.deleted_at IS NULL
      WHERE ${where.join(' AND ')} GROUP BY p.key ORDER BY sum(r.granted_count) DESC, max(p.display) LIMIT 80`, p)).rows
    .map((x) => ({ ...x, perms: num(x.perms) }));
}

const arnOfKey = (key) => {
  if (key.startsWith('user:')) return key.slice(5);
  const m = key.match(/^role:(\d{12}):(.+)$/); if (m) return `arn:aws:iam::${m[1]}:role/${m[2]}`;
  return null;
};

/**
 * Everything one identity can reach: roles it has been seen entering, roles whose trust policy names it,
 * then the same again from each role reached (role chaining), up to MAX_HOPS. Roles outside the viewer's
 * scope are counted, not shown, and not walked through.
 */
export async function blastRadius(user, key) {
  const ident = (await query(`SELECT key, max(display) AS display, max(kind) AS kind, max(via) AS via, (array_agg(caller))[1] AS caller FROM principals WHERE key=$1 GROUP BY key`, [key])).rows[0]
    || { key, display: key.replace(/^\w+:/, ''), kind: 'other', via: null, caller: {} };
  const nodes = new Map(); let hidden = 0;
  let frontier = [{ key, arn: arnOfKey(key), parent: null }];
  for (let hop = 1; hop <= MAX_HOPS && frontier.length; hop++) {
    const keys = frontier.map((f) => f.key), arns = frontier.map((f) => f.arn).filter(Boolean);
    const [obs, trust] = await Promise.all([
      query(`SELECT p.key AS via_key, r.id, r.name, r.arn, r.kind, r.risk, r.granted_count, r.account_id, a.name AS account_name, a.account_id AS aws, a.environment
               FROM principals p JOIN roles r ON r.id=p.role_id AND r.deleted_at IS NULL JOIN cloud_accounts a ON a.id=r.account_id WHERE p.key = ANY($1)`, [keys]),
      arns.length ? query(`SELECT t.arn AS via_arn, r.id, r.name, r.arn, r.kind, r.risk, r.granted_count, r.account_id, a.name AS account_name, a.account_id AS aws, a.environment
               FROM roles r JOIN cloud_accounts a ON a.id=r.account_id, unnest($1::text[]) AS t(arn)
              WHERE r.deleted_at IS NULL AND r.trust_policy::text LIKE '%"' || t.arn || '"%'`, [arns]) : { rows: [] },
    ]);
    const next = [];
    const add = (r, from, edge) => {
      if (nodes.has(r.id)) { if (edge === 'observed') nodes.get(r.id).edge = 'observed'; return; }
      if (!inScope(user, r.account_id)) { hidden++; nodes.set(r.id, null); return; }
      const n = { id: r.id, name: r.name, kind: r.kind, risk: r.risk, perms: r.granted_count, admin: r.granted_count >= ADMIN, accountId: r.account_id,
        account: r.account_name, awsAccountId: r.aws, environment: r.environment, hop, parent: from?.parent ?? null, edge };
      nodes.set(r.id, n);
      next.push({ key: `role:${r.aws}:${r.name}`, arn: r.arn, parent: r.id });
    };
    for (const r of obs.rows) add(r, frontier.find((f) => f.key === r.via_key), 'observed');
    for (const r of trust.rows) add(r, frontier.find((f) => f.arn === r.via_arn), 'trust');
    frontier = next;
  }
  const list = [...nodes.values()].filter(Boolean);
  const t = ident.caller?.trust;
  return {
    identity: { key: ident.key, display: ident.display, kind: ident.kind, via: ident.via, conditions: t?.matched ? (t.conditions || []) : null },
    nodes: list, hidden,
    totals: { roles: list.length, accounts: new Set(list.map((n) => n.accountId)).size, perms: list.reduce((s, n) => s + n.perms, 0),
      admin: list.filter((n) => n.admin).length, production: list.filter((n) => n.environment === 'production').length },
  };
}
