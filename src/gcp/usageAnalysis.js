// What each Google Cloud identity actually used, against what its roles grant. Reads gcp_usage_summary (one row
// per project, caller and permission), never the daily table, so it stays fast however long the history is.
//
//   used         granted, and checked (granted) within the lookback
//   unused       granted, a kind of call Admin Activity logs, and never seen: safe to propose removing
//   unconfirmed  granted, a read (get, list...) that only Data Access logs record, and those are not read: unknown
//
// Permissions are compared across every connection that reads role usage, like the identity's roles (which are joined
// across connections, see merge.js): a permission used in any project read counts as used.
import { query } from '../db.js';

// Reads appear only in Data Access logs (ADMIN_READ, DATA_READ); everything else is in Admin Activity.
const READ_VERB = /^(get|list|search|query|read|lookup|view|watch|aggregated|test|check|fetch|select|access|download|subscribe|receive|connect|use)/i;
export const isReadPermission = (p) => READ_VERB.test(String(p).split('.').pop());

/** Pure: counts for one identity. `used` is a Set of permissions seen granted within the lookback. */
export function classify(granted, used, { readsKnown }) {
  let u = 0, unused = 0, unconfirmed = 0;
  for (const p of granted) {
    if (used.has(p)) u++;
    else if (!readsKnown && isReadPermission(p)) unconfirmed++;
    else unused++;
  }
  return { used: u, unused, unconfirmed };
}

// usage projects of connections that read role usage now (what a connection read before it was turned off stays, unused)
const READ_PROJECTS = `gcp_usage_projects u ON u.id = s.project_ref JOIN gcp_connections uc ON uc.id = u.connection_id AND uc.usage_enabled`;

/** Every connection's identities again: after their roles were joined across connections (a scan, a removal). */
export async function refreshUsage({ now = Date.now() } = {}) {
  for (const { id } of (await query('SELECT id FROM gcp_connections ORDER BY name')).rows) await analyzeUsage(id, { now });
}

/** Recompute used / unused / unconfirmed for every identity of one connection. */
export async function analyzeUsage(connectionId, { now = Date.now() } = {}) {
  const conn = (await query('SELECT id, usage_enabled, usage_lookback_days, usage_data_access FROM gcp_connections WHERE id=$1', [connectionId])).rows[0];
  if (!conn) return null;
  if (!conn.usage_enabled) {
    await query(`UPDATE gcp_principals SET used_count=NULL, unused_count=NULL, unconfirmed_count=NULL, last_activity_at=NULL WHERE connection_id=$1`, [connectionId]);
    return { off: true };
  }
  const cutoff = new Date(now - conn.usage_lookback_days * 864e5).toISOString().slice(0, 10);
  const [principals, used, last, reads] = await Promise.all([
    query('SELECT id, member, roles FROM gcp_principals WHERE connection_id=$1', [connectionId]),
    // its identities' calls in any project read with usage on, not only this connection's
    query(`SELECT m.member, array_agg(DISTINCT pr.permission) AS perms
             FROM gcp_usage_summary s JOIN ${READ_PROJECTS} JOIN gcp_usage_members m ON m.id = s.member_id JOIN gcp_usage_perms pr ON pr.id = s.perm_id
            WHERE m.member IN (SELECT member FROM gcp_principals WHERE connection_id = $1) AND s.last_day >= $2 AND s.count > 0 GROUP BY m.member`, [connectionId, cutoff]),
    query(`SELECT m.member, max(s.last_day) AS last FROM gcp_usage_summary s JOIN ${READ_PROJECTS} JOIN gcp_usage_members m ON m.id = s.member_id
            WHERE m.member IN (SELECT member FROM gcp_principals WHERE connection_id = $1) GROUP BY m.member`, [connectionId]),
    // Data Access counts as read only when it is turned on and at least one entry came back from it
    query(`SELECT COALESCE(sum(k.entries_read), 0)::bigint AS n FROM gcp_log_cursors k JOIN gcp_usage_projects u ON u.id = k.project_ref
            WHERE u.connection_id = $1 AND k.log = 'data_access'`, [connectionId]),
  ]);
  const readsKnown = conn.usage_data_access && reads.rows[0].n > 0;
  const roleNames = [...new Set(principals.rows.flatMap((p) => p.roles.map((r) => r.role)))];
  const defs = new Map((await query('SELECT name, permissions FROM gcp_role_defs WHERE name = ANY($1)', [roleNames])).rows.map((r) => [r.name, r.permissions]));
  const usedBy = new Map(used.rows.map((r) => [r.member, new Set(r.perms)]));
  const lastBy = new Map(last.rows.map((r) => [r.member, r.last]));
  const empty = new Set();
  const ids = [], uc = [], nc = [], cc = [], la = [];
  for (const p of principals.rows) {
    const granted = new Set();
    for (const r of p.roles) for (const x of defs.get(r.role) || []) granted.add(x);
    const c = classify(granted, usedBy.get(p.member) || empty, { readsKnown });
    ids.push(p.id); uc.push(c.used); nc.push(c.unused); cc.push(c.unconfirmed); la.push(lastBy.get(p.member) || null);
  }
  if (ids.length) {
    await query(`UPDATE gcp_principals g SET used_count = x.u, unused_count = x.n, unconfirmed_count = x.c, last_activity_at = x.l
                   FROM unnest($1::uuid[], $2::int[], $3::int[], $4::int[], $5::date[]) AS x(id, u, n, c, l) WHERE g.id = x.id`, [ids, uc, nc, cc, la]);
  }
  await query('UPDATE gcp_connections SET usage_analyzed_at = now() WHERE id=$1', [connectionId]);
  return { principals: ids.length, readsKnown, callers: usedBy.size };
}

/** One identity's permissions with what was seen: for its page. Granted ones first, then any it used through a group. */
export async function principalUsage(p, { now = Date.now() } = {}) {
  const conn = (await query('SELECT usage_enabled, usage_lookback_days, usage_data_access FROM gcp_connections WHERE id=$1', [p.connection_id])).rows[0];
  if (!conn?.usage_enabled) return { enabled: false };
  const cutoff = new Date(now - conn.usage_lookback_days * 864e5).toISOString().slice(0, 10);
  const [seen, daily, defs, reads] = await Promise.all([
    query(`SELECT pr.permission, u.project_id, s.first_day, s.last_day, s.count, s.denied
             FROM gcp_usage_members m JOIN gcp_usage_summary s ON s.member_id = m.id JOIN ${READ_PROJECTS}
             JOIN gcp_usage_perms pr ON pr.id = s.perm_id WHERE m.member = $1`, [p.member]),
    // only the projects this identity was seen in (from the small summary), each read as one primary-key range
    query(`WITH m AS (SELECT id FROM gcp_usage_members WHERE member = $1),
                pr AS (SELECT DISTINCT s.project_ref FROM gcp_usage_summary s JOIN ${READ_PROJECTS}
                        WHERE s.member_id = (SELECT id FROM m) AND s.last_day >= $2)
           SELECT d.day, sum(d.count)::bigint AS n, sum(d.denied)::bigint AS denied FROM pr CROSS JOIN LATERAL (
             SELECT day, count, denied FROM gcp_activity_daily WHERE project_ref = pr.project_ref AND day >= $2 AND member_id = (SELECT id FROM m)) d
           GROUP BY d.day ORDER BY d.day`, [p.member, cutoff]),
    query('SELECT name, permissions FROM gcp_role_defs WHERE name = ANY($1)', [p.roles.map((r) => r.role)]),
    query(`SELECT COALESCE(sum(k.entries_read), 0)::bigint AS n FROM gcp_log_cursors k JOIN gcp_usage_projects u ON u.id = k.project_ref WHERE u.connection_id = $1 AND k.log = 'data_access'`, [p.connection_id]),
  ]);
  const readsKnown = conn.usage_data_access && reads.rows[0].n > 0;
  const fromRoles = new Map();
  for (const d of defs.rows) for (const x of d.permissions) (fromRoles.get(x) || fromRoles.set(x, []).get(x)).push(d.name);
  const by = new Map();
  for (const r of seen.rows) {
    const x = by.get(r.permission) || by.set(r.permission, { permission: r.permission, projects: [], count: 0, denied: 0, first: r.first_day, last: r.last_day }).get(r.permission);
    x.projects.push(r.project_id); x.count += r.count; x.denied += r.denied;
    if (r.first_day < x.first) x.first = r.first_day; if (r.last_day > x.last) x.last = r.last_day;
  }
  const list = [];
  for (const [perm, roles] of fromRoles) {
    const s = by.get(perm);
    const status = s && s.count > 0 && s.last >= cutoff ? 'used' : !readsKnown && isReadPermission(perm) ? 'unconfirmed' : 'unused';
    list.push({ permission: perm, roles, status, ...(s ? { count: s.count, denied: s.denied, first: s.first, last: s.last, projects: s.projects } : {}) });
  }
  // seen but not granted by its own roles: through a group, a domain, or a role granted elsewhere
  for (const [perm, s] of by) if (!fromRoles.has(perm)) list.push({ permission: perm, roles: [], status: s.count > 0 ? 'used-elsewhere' : 'denied', ...s });
  const rank = { used: 0, 'used-elsewhere': 1, denied: 2, unused: 3, unconfirmed: 4 };
  list.sort((a, b) => rank[a.status] - rank[b.status] || (b.count || 0) - (a.count || 0) || a.permission.localeCompare(b.permission));
  return { enabled: true, lookbackDays: conn.usage_lookback_days, readsKnown, permissions: list, daily: daily.rows.map((r) => ({ day: r.day, count: r.n, denied: r.denied })) };
}
