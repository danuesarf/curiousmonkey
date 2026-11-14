// Data for the radar: the estate (accounts as contacts), one account (roles as contacts), and the change feed.
import { query } from './db.js';
import { scopeSql, inScope } from './auth/rbac.js';
import { historyFor } from './history.js';

const num = (x) => Number(x || 0);
const share = (unused, granted) => (num(granted) ? num(unused) / num(granted) : null);

/** Unused/granted per account at the latest snapshot on or before N days ago. */
async function pastShares(daysAgo, accountIds) {
  if (!accountIds.length) return new Map();
  const rows = (await query(
    `WITH d AS (SELECT x.account_id, (SELECT max(day) FROM role_snapshots s WHERE s.account_id = x.account_id AND s.day <= current_date - $1::int) AS day
                 FROM unnest($2::uuid[]) AS x(account_id))
     SELECT s.account_id, sum(s.granted) AS g, sum(s.used) AS u, sum(s.unused) AS un,
            percentile_cont(0.5) WITHIN GROUP (ORDER BY s.unused::float8 / s.granted) FILTER (WHERE s.granted > 0) AS med
       FROM role_snapshots s JOIN d USING (account_id, day) GROUP BY s.account_id`,
    [daysAgo, accountIds])).rows;
  return new Map(rows.map((r) => [r.account_id, { never: r.med == null ? null : Number(r.med), pooled: share(r.un, r.g), excess: num(r.g) - num(r.u) }]));
}

/** Which identities: everything (default), roles only, or IAM users only. */
export const whoSql = (who, col = 'r.kind') => (who === 'roles' ? `${col} <> 'iam-user'` : who === 'users' ? `${col} = 'iam-user'` : 'TRUE');

export async function estate(user, who = 'all') {
  const p = [];
  const accts = (await query(
    `SELECT a.*, count(r.id)::int AS roles, coalesce(sum(r.granted_count),0)::bigint AS granted, coalesce(sum(r.used_count),0)::bigint AS used,
            coalesce(sum(r.unused_count),0)::bigint AS unused, count(r.id) FILTER (WHERE r.risk='High')::int AS high,
            -- the typical role: one admin-size role decides the pooled share, so distance on the radar is the median role's
            percentile_cont(0.5) WITHIN GROUP (ORDER BY r.unused_count::float8 / r.granted_count) FILTER (WHERE r.granted_count > 0) AS med,
            count(r.id) FILTER (WHERE EXISTS (SELECT 1 FROM flags f WHERE f.role_id=r.id AND f.category='unmapped-event' AND f.status='open'))::int AS unidentified
       FROM cloud_accounts a LEFT JOIN roles r ON r.account_id=a.id AND r.deleted_at IS NULL AND ${whoSql(who)}
      WHERE ${scopeSql(user, 'a.id', p)} AND a.status <> 'planned' GROUP BY a.id ORDER BY a.name`, p)).rows;
  const ids = accts.map((a) => a.id);
  const [act, d7, d30, pings, hist] = await Promise.all([
    ids.length ? query(`SELECT r.account_id, sum(d.count)::bigint AS n FROM activity_daily d JOIN roles r ON r.id=d.role_id WHERE d.day >= current_date - 1 AND r.account_id = ANY($1) AND ${whoSql(who)} GROUP BY 1`, [ids]) : { rows: [] },
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
      never: a.med == null ? null : Number(a.med), pooled: share(a.unused, a.granted), never7: d7.get(a.id)?.never ?? null, never30: d30.get(a.id)?.never ?? null, excess30: d30.get(a.id)?.excess ?? null,
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

export async function accountRadar(user, accountId, who = 'all') {
  if (!inScope(user, accountId)) return null;
  const a = (await query('SELECT * FROM cloud_accounts WHERE id=$1', [accountId])).rows[0];
  if (!a) return null;
  const roles = (await query(
    `SELECT r.id, r.name, r.kind, r.risk, r.granted_count AS granted, r.used_count AS used, r.unused_count AS unused, r.unconfirmed_count AS unconfirmed,
            coalesce(t.calls,0)::bigint AS calls, coalesce(t.denied,0)::bigint AS denied, coalesce(t.c24,0)::bigint AS calls24h,
            s30.granted AS g30, s30.unused AS u30, s7.granted AS g7, s7.unused AS u7, fs.first AS first_snapshot,
            EXISTS (SELECT 1 FROM flags f WHERE f.role_id=r.id AND f.category='unmapped-event' AND f.status='open') AS unidentified
       FROM roles r
       -- grouped over this account's roles only: grouping whole tables would read the estate's history for one account
       LEFT JOIN (SELECT role_id, sum(count) calls, sum(error_count) denied, sum(count) FILTER (WHERE day >= current_date - 1) c24
                    FROM activity_daily WHERE role_id IN (SELECT id FROM roles WHERE account_id=$1) GROUP BY role_id) t ON t.role_id=r.id
       LEFT JOIN LATERAL (SELECT granted, unused FROM role_snapshots s WHERE s.role_id=r.id AND s.day <= current_date - 30 ORDER BY day DESC LIMIT 1) s30 ON true
       LEFT JOIN LATERAL (SELECT granted, unused FROM role_snapshots s WHERE s.role_id=r.id AND s.day <= current_date - 7 ORDER BY day DESC LIMIT 1) s7 ON true
       LEFT JOIN (SELECT role_id, min(day) AS first FROM role_snapshots WHERE account_id=$1 GROUP BY role_id) fs ON fs.role_id=r.id
      WHERE r.account_id=$1 AND r.deleted_at IS NULL AND ${whoSql(who)}`, [accountId])).rows;
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

/** Daily never-called share for the card's heading line: an account's median role, or one role. */
export async function trail(user, { accountId = null, roleId = null, days = 30 }) {
  const d = Math.max(7, Math.min(180, Number(days) || 30));
  if (roleId) {
    const r = (await query('SELECT account_id FROM roles WHERE id=$1', [roleId])).rows[0];
    if (!r || !inScope(user, r.account_id)) return null;
    const rows = (await query(`SELECT day, CASE WHEN granted > 0 THEN unused::float8 / granted END AS v FROM role_snapshots
                                WHERE role_id=$1 AND day > current_date - $2::int ORDER BY day`, [roleId, d])).rows;
    return { days: d, points: rows.map((x) => ({ day: x.day, v: x.v == null ? null : Number(x.v) })) };
  }
  if (!accountId || !inScope(user, accountId)) return null;
  const rows = (await query(`SELECT day, percentile_cont(0.5) WITHIN GROUP (ORDER BY unused::float8 / granted) FILTER (WHERE granted > 0) AS v
                               FROM role_snapshots WHERE account_id=$1 AND day > current_date - $2::int GROUP BY day ORDER BY day`, [accountId, d])).rows;
  return { days: d, points: rows.map((x) => ({ day: x.day, v: x.v == null ? null : Number(x.v) })) };
}

export const FEED_DAYS = [1, 7, 30, 90];
// what counts as new when someone has never looked: the last week, so a new member is not met by months of pings
const UNSEEN_WINDOW = "c.at > now() - interval '30 days'";
const unseenSql = (user, p) => { p.push(user.changes_seen_id ?? null); return `(c.id > coalesce($${p.length}::bigint, 0) AND ${UNSEEN_WINDOW}${user.changes_seen_id == null ? " AND c.at > now() - interval '7 days'" : ''})`; };

/**
 * The change feed: what changed that matters, newest first, in the member's accounts. Radar shows it for a time range
 * (and an account); the bell shows the part this person has not seen. Each item says whether it is new to them.
 */
export async function changeFeed(user, { accountId = null, days = 7, limit = 60 } = {}) {
  const d = FEED_DAYS.includes(Number(days)) ? Number(days) : 7;
  const p = []; const where = [scopeSql(user, 'c.account_id', p), `c.at > now() - make_interval(days => ${d})`];
  if (accountId) { p.push(accountId); where.push(`c.account_id = $${p.length}`); }
  const unread = unseenSql(user, p);
  p.push(Math.min(200, limit));
  const rows = (await query(
    `SELECT c.id, c.kind, c.severity, c.title, c.detail, c.at, c.account_id, a.name AS account_name, c.role_id, r.name AS role_name, ${unread} AS unread, count(*) OVER ()::int AS total
       FROM changes c JOIN cloud_accounts a ON a.id=c.account_id LEFT JOIN roles r ON r.id=c.role_id
      WHERE ${where.join(' AND ')} ORDER BY c.at DESC, c.id DESC LIMIT $${p.length}`, p)).rows;
  return { items: rows.map(({ total, ...x }) => x), total: rows[0]?.total ?? 0, days: d, seenAt: user.radar_seen_at || null };
}

/** What this person has not seen yet, for the bell: how many, the worst severity, and the newest few. */
export async function unreadChanges(user, { limit = 40 } = {}) {
  const p = []; const where = [scopeSql(user, 'c.account_id', p)];
  where.push(unseenSql(user, p));
  const [rows, n] = await Promise.all([
    query(`SELECT c.id, c.kind, c.severity, c.title, c.detail, c.at, c.account_id, a.name AS account_name, c.role_id, r.name AS role_name, true AS unread
             FROM changes c JOIN cloud_accounts a ON a.id=c.account_id LEFT JOIN roles r ON r.id=c.role_id
            WHERE ${where.join(' AND ')} ORDER BY c.at DESC, c.id DESC LIMIT ${Math.min(100, limit)}`, p),
    query(`SELECT count(*)::int n, count(*) FILTER (WHERE c.severity='high')::int high, count(*) FILTER (WHERE c.severity='warn')::int warn FROM changes c WHERE ${where.join(' AND ')}`, p),
  ]);
  const t = n.rows[0];
  return { count: t.n, worst: t.high ? 'high' : t.warn ? 'warn' : t.n ? 'info' : 'none', items: rows.rows };
}

/** Everything recorded so far counts as seen by this person. */
export async function markSeen(user) {
  await query('UPDATE users SET radar_seen_at=now(), changes_seen_id=(SELECT max(id) FROM changes) WHERE id=$1', [user.id]);
}
