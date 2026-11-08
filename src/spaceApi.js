// Data for Space: the estate as a tilted plane (accounts as clouds of role stars, identities outside the org off its
// edge, paths between them above it), and one account (roles clustered by the service they call most, services as
// towers). Everything replays the last 24 hours, hour by hour.
//
// Sources: roles + activity_daily (calls per role per day, so heights cover 7 days), track_sessions (when sessions
// started and how many calls they made, so the replay has hours; parent_key_id gives role chaining across accounts),
// the trust map (who outside the org can enter, and how worrying that trust is), and changes (what needs a look).
import { query } from './db.js';
import { scopeSql, inScope } from './auth/rbac.js';
import { trustMap } from './trustmap.js';

const num = (x) => Number(x || 0);
const ENVS = ['production', 'shared', 'staging', 'development', 'sandbox'];
const OUTSIDE = new Set(['public', 'external-account', 'oidc', 'saml']);
const SEV = { high: 0, medium: 1, low: 2, info: 3, none: 4 };   // the trust map's severities
const MAX_STARS = 2400;            // across the estate; each account gets a share
const MAX_SOURCES = 14;            // identities outside the org drawn off the plane

// 24 one-hour buckets ending with the current hour. Bucket 23 is the hour in progress.
const BUCKETS = `date_trunc('hour', now()) - interval '23 hours'`;
const bucketOf = (t, start) => Math.max(0, Math.min(23, Math.floor((new Date(t).getTime() - start) / 36e5)));

async function hourStart() { return new Date((await query(`SELECT ${BUCKETS} AS t`)).rows[0].t).getTime(); }

/** Identities outside the org that can enter roles in these accounts, grouped by source, worst trust first. */
async function outsiders(user, accountIds, roleIds = null) {
  const m = await trustMap(user, '', { limit: 1e6 });
  const by = new Map();
  for (const e of m.rows) {
    if (!OUTSIDE.has(e.group) || !accountIds.has(e.accountId) || (roleIds && !roleIds.has(e.roleId))) continue;
    const key = /account/.test(e.group) ? `acct:${e.principalAccount || e.source}` : `${e.group}:${e.source}`;
    if (!by.has(key)) by.set(key, { key, group: e.group, label: /account/.test(e.group) ? `Account ${e.principalAccount || e.source}` : e.source,
      sub: e.group === 'public' ? 'anyone · Principal "*"' : e.group === 'external-account' ? (e.principalAccountName || 'not in your org') : e.group.toUpperCase(),
      worst: 'none', findings: new Set(), targets: new Map(), sessions: 0, lastSeen: null });
    const s = by.get(key);
    if ((SEV[e.worst] ?? 4) < (SEV[s.worst] ?? 4)) s.worst = e.worst;
    for (const f of e.findings) if (f.severity !== 'info') s.findings.add(f.title);
    const t = s.targets.get(e.accountId) || { roles: new Set(), sessions: 0, edges: [] };
    t.roles.add(e.roleId); s.targets.set(e.accountId, t);
    // what the trust statement says, so a click on the path can explain the warning
    if (t.edges.length < 12) t.edges.push({ roleId: e.roleId, role: e.role, principal: e.principal, actions: e.actions, conditions: e.conditions, worst: e.worst, sid: e.sid || null,
      findings: e.findings.filter((x) => x.severity !== 'info').map((x) => ({ title: x.title, severity: x.severity, detail: x.detail || null })),
      sessions: e.seen.reduce((n, x) => n + num(x.sessions), 0), lastSeen: e.seen.map((x) => x.lastSeen).filter(Boolean).sort().pop() || null });
    for (const seen of e.seen) { t.sessions += num(seen.sessions); s.sessions += num(seen.sessions); if (seen.lastSeen && (!s.lastSeen || new Date(seen.lastSeen) > new Date(s.lastSeen))) s.lastSeen = seen.lastSeen; }
  }
  const all = [...by.values()].sort((a, b) => (SEV[a.worst] ?? 4) - (SEV[b.worst] ?? 4) || b.targets.size - a.targets.size || b.sessions - a.sessions);
  return {
    hidden: Math.max(0, all.length - MAX_SOURCES),
    items: all.slice(0, MAX_SOURCES).map((s) => ({ key: s.key, group: s.group, label: s.label, sub: s.sub, worst: s.worst, findings: [...s.findings].slice(0, 3), sessions: s.sessions, lastSeen: s.lastSeen,
      targets: [...s.targets].map(([accountId, t]) => ({ accountId, roles: [...t.roles], sessions: t.sessions,
        edges: t.edges.sort((a, b) => (SEV[a.worst] ?? 4) - (SEV[b.worst] ?? 4)) })) })),
  };
}

/** Changes in the last 24 h, as replay events. */
async function events(where, p, start) {
  const rows = (await query(
    `SELECT c.id, c.account_id, c.role_id, c.kind, c.severity, c.title, c.detail, c.at, r.name AS role_name
       FROM changes c LEFT JOIN roles r ON r.id=c.role_id
      WHERE c.at >= ${BUCKETS} AND ${where} ORDER BY c.at DESC LIMIT 40`, p)).rows;
  return rows.map((c) => ({ id: `c${c.id}`, kind: c.kind, severity: c.severity, title: c.title, detail: c.detail, at: c.at, hour: bucketOf(c.at, start), accountId: c.account_id, roleId: c.role_id, roleName: c.role_name }));
}

export async function spaceEstate(user) {
  const p = [];
  const accts = (await query(`SELECT a.id, a.name, a.account_id, a.environment, a.ou, a.status, a.note FROM cloud_accounts a WHERE ${scopeSql(user, 'a.id', p)} ORDER BY a.environment, a.ou NULLS LAST, a.name`, p)).rows;
  const ids = accts.map((a) => a.id);
  const start = await hourStart();
  if (!ids.length) return { accounts: [], chains: [], outside: { items: [], hidden: 0 }, events: [], hourStart: new Date(start).toISOString() };

  const [roles, hourly, chains, ev] = await Promise.all([
    query(`SELECT r.id, r.account_id, r.name, r.kind, r.risk, coalesce(t.c7,0)::bigint AS calls7, coalesce(t.c1,0)::bigint AS calls24h, coalesce(t.all_calls,0)::bigint AS calls_all
             FROM roles r
             LEFT JOIN (SELECT role_id, sum(count) all_calls, sum(count) FILTER (WHERE day >= current_date - 6) c7, sum(count) FILTER (WHERE day >= current_date - 1) c1
                          FROM activity_daily GROUP BY role_id) t ON t.role_id=r.id
            WHERE r.account_id = ANY($1) AND r.deleted_at IS NULL`, [ids]),
    query(`SELECT account_id, date_trunc('hour', started_at) AS h, count(*)::int AS sessions, sum(calls)::bigint AS calls, sum(denied)::bigint AS denied
             FROM track_sessions WHERE account_id = ANY($1) AND started_at >= ${BUCKETS} GROUP BY 1, 2`, [ids]),
    // role chaining across accounts: a session whose parent session lives in another connected account
    query(`SELECT p.account_id AS src, s.account_id AS dst, count(*) FILTER (WHERE s.started_at >= ${BUCKETS})::int AS today, count(*)::int AS month,
                  min(s.started_at) AS first, array_agg(DISTINCT date_trunc('hour', s.started_at)) FILTER (WHERE s.started_at >= ${BUCKETS}) AS hours,
                  sum(s.denied)::bigint AS denied
             FROM track_sessions s JOIN track_sessions p ON p.access_key_id = s.parent_key_id
            WHERE s.account_id = ANY($1) AND p.account_id = ANY($1) AND p.account_id <> s.account_id AND s.started_at >= now() - interval '30 days'
            GROUP BY 1, 2`, [ids]),
    events('c.account_id = ANY($1)', [ids], start),
  ]);

  const byAcct = new Map(accts.map((a) => [a.id, { roles: [], hourly: Array.from({ length: 24 }, () => ({ sessions: 0, calls: 0, denied: 0 })) }]));
  for (const r of roles.rows) byAcct.get(r.account_id).roles.push(r);
  for (const hRow of hourly.rows) { const b = byAcct.get(hRow.account_id).hourly[bucketOf(hRow.h, start)]; b.sessions += hRow.sessions; b.calls += num(hRow.calls); b.denied += num(hRow.denied); }
  const per = Math.max(10, Math.floor(MAX_STARS / accts.length));

  const outside = await outsiders(user, new Set(ids));
  return {
    hourStart: new Date(start).toISOString(),
    accounts: accts.map((a) => {
      const x = byAcct.get(a.id);
      const active = x.roles.filter((r) => num(r.calls_all) > 0).sort((m, n) => num(n.calls7) - num(m.calls7) || num(n.calls_all) - num(m.calls_all));
      const cold = x.roles.length - active.length;
      return {
        id: a.id, name: a.name, awsAccountId: a.account_id, environment: ENVS.includes(a.environment) ? a.environment : 'production', ou: a.ou || null,
        planned: a.status === 'planned', note: a.status === 'planned' ? a.note : null,
        roles: x.roles.length, active: active.length, cold, high: x.roles.filter((r) => r.risk === 'High').length,
        calls7: x.roles.reduce((s, r) => s + num(r.calls7), 0), calls24h: x.roles.reduce((s, r) => s + num(r.calls24h), 0),
        // the busiest roles are drawn one by one; the rest of the active ones are counted
        stars: active.slice(0, per).map((r) => ({ id: r.id, name: r.name, calls7: num(r.calls7), risk: r.risk })),
        hourly: x.hourly,
      };
    }),
    chains: chains.rows.filter((c) => c.today > 0).map((c) => ({ from: c.src, to: c.dst, sessions: c.today, denied: num(c.denied),
      isNew: new Date(c.first).getTime() >= start, hours: (c.hours || []).map((t) => bucketOf(t, start)).sort((m, n) => m - n) })),
    outside,
    events: ev,
  };
}

const svcOf = (action) => String(action).split(':')[0];

export async function spaceAccount(user, accountId) {
  if (!inScope(user, accountId)) return null;
  const a = (await query('SELECT id, name, account_id, environment, ou FROM cloud_accounts WHERE id=$1', [accountId])).rows[0];
  if (!a) return null;
  const start = await hourStart();
  const [roles, acts, hourly, chains, ev] = await Promise.all([
    query(`SELECT r.id, r.name, r.kind, r.risk, coalesce(t.calls_all,0)::bigint AS calls_all FROM roles r
             LEFT JOIN (SELECT role_id, sum(count) calls_all FROM activity_daily GROUP BY role_id) t ON t.role_id=r.id
            WHERE r.account_id=$1 AND r.deleted_at IS NULL`, [accountId]),
    // calls per role per action over 7 days, so each role has its services
    query(`SELECT d.role_id, d.action, sum(d.count)::bigint AS n, sum(d.error_count)::bigint AS denied FROM activity_daily d JOIN roles r ON r.id=d.role_id
            WHERE r.account_id=$1 AND d.day >= current_date - 6 GROUP BY 1, 2`, [accountId]),
    query(`SELECT role_id, date_trunc('hour', started_at) AS h, sum(calls)::bigint AS calls, sum(denied)::bigint AS denied
             FROM track_sessions WHERE account_id=$1 AND started_at >= ${BUCKETS} GROUP BY 1, 2`, [accountId]),
    query(`SELECT p.account_id AS src, s.account_id AS dst, pr.name AS src_role, sr.name AS dst_role, s.role_id AS dst_role_id, p.role_id AS src_role_id, count(*)::int AS n
             FROM track_sessions s JOIN track_sessions p ON p.access_key_id = s.parent_key_id
             JOIN roles pr ON pr.id=p.role_id JOIN roles sr ON sr.id=s.role_id
            WHERE (s.account_id=$1 OR p.account_id=$1) AND p.account_id <> s.account_id AND s.started_at >= now() - interval '7 days'
            GROUP BY 1, 2, 3, 4, 5, 6`, [accountId]),
    events('c.account_id = $1', [accountId], start),
  ]);

  // each role's services, busiest first
  const svc = new Map();
  for (const x of acts.rows) {
    if (!svc.has(x.role_id)) svc.set(x.role_id, new Map());
    const m = svc.get(x.role_id), k = svcOf(x.action), v = m.get(k) || { calls: 0, denied: 0 };
    v.calls += num(x.n); v.denied += num(x.denied); m.set(k, v);
  }
  const roleHours = new Map();
  for (const hRow of hourly.rows) {
    if (!roleHours.has(hRow.role_id)) roleHours.set(hRow.role_id, Array(24).fill(0));
    roleHours.get(hRow.role_id)[bucketOf(hRow.h, start)] += num(hRow.calls);
  }
  const out = roles.rows.map((r) => {
    const s = [...(svc.get(r.id) || new Map())].map(([name, v]) => ({ name, calls: v.calls, denied: v.denied })).sort((m, n) => n.calls - m.calls);
    return { id: r.id, name: r.name, kind: r.kind, risk: r.risk, cold: num(r.calls_all) === 0, calls7: s.reduce((t, x) => t + x.calls, 0), denied7: s.reduce((t, x) => t + x.denied, 0),
      services: s.slice(0, 6), hourly: roleHours.get(r.id) || Array(24).fill(0) };
  });
  // services: the account's busiest eight. Clusters: roles grouped by the service they call most
  const total = new Map();
  for (const r of out) for (const s of r.services) total.set(s.name, (total.get(s.name) || 0) + s.calls);
  const services = [...total].sort((m, n) => n[1] - m[1]).slice(0, 8).map(([name, calls]) => ({ name, calls }));
  const groups = new Map();
  for (const r of out.filter((x) => !x.cold)) { const k = r.services[0]?.name || 'quiet this week'; if (!groups.has(k)) groups.set(k, []); groups.get(k).push(r); }
  let clusters = [...groups].map(([key, rs]) => ({ key, roles: rs, calls: rs.reduce((t, r) => t + r.calls7, 0) })).sort((m, n) => n.roles.length - m.roles.length || n.calls - m.calls);
  if (clusters.length > 6) clusters = [...clusters.slice(0, 5), { key: 'other', roles: clusters.slice(5).flatMap((c) => c.roles) }];

  const ids = new Set([a.id]);
  const outside = await outsiders(user, ids);
  const names = new Map((await query('SELECT id, name, environment FROM cloud_accounts WHERE id = ANY($1)', [[...new Set(chains.rows.flatMap((c) => [c.src, c.dst]))]])).rows.map((x) => [x.id, x]));
  const neighbours = new Map();
  for (const c of chains.rows) {
    const other = c.src === a.id ? c.dst : c.src, o = names.get(other); if (!o || !inScope(user, other)) continue;
    if (!neighbours.has(other)) neighbours.set(other, { id: other, name: o.name, environment: o.environment, links: [] });
    neighbours.get(other).links.push({ dir: c.src === a.id ? 'out' : 'in', roleId: c.src === a.id ? c.src_role_id : c.dst_role_id, otherRole: c.src === a.id ? c.dst_role : c.src_role, sessions: c.n });
  }
  return {
    hourStart: new Date(start).toISOString(),
    account: { id: a.id, name: a.name, awsAccountId: a.account_id, environment: ENVS.includes(a.environment) ? a.environment : 'production', ou: a.ou || null },
    services, clusters: clusters.map((c) => ({ key: c.key, roles: c.roles.sort((m, n) => n.calls7 - m.calls7).slice(0, 40), more: Math.max(0, c.roles.length - 40) })),
    cold: out.filter((r) => r.cold).map((r) => ({ id: r.id, name: r.name })).slice(0, 80), coldCount: out.filter((r) => r.cold).length, roleCount: out.length,
    neighbours: [...neighbours.values()].slice(0, 6), outside, events: ev,
  };
}
