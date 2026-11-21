import { whoSql } from './radarApi.js';
// Data for Space: the estate as a tilted plane (accounts as clouds of role stars, identities outside the org off its
// edge, paths between them above it), and one account (roles clustered by the service they call most, services as
// towers). Everything replays the last 24 hours, hour by hour.
//
// Sources: roles + activity_daily (calls per role per day, so heights cover 7 days), track_sessions (when sessions
// started and how many calls they made, so the replay has hours; parent_key_id gives role chaining across accounts),
// the trust map (who outside the org can enter, and how worrying that trust is), and changes (what needs a look).
import { read as query } from './db.js';
import { uncovered } from './rollups.js';
import { scopeSql, inScope } from './auth/rbac.js';
import { trustMap } from './trustmap.js';
import { environmentOf } from './environments.js';
import { config } from './config.js';
import { knownVendor } from './trustmap.js';

const num = (x) => Number(x || 0);
const OUTSIDE = new Set(['public', 'external-account', 'oidc', 'saml']);
const SEV = { high: 0, medium: 1, low: 2, info: 3, none: 4 };   // the trust map's severities
const MAX_STARS = 2400;            // across the estate; each account gets a share
const MAX_SOURCES = 14;            // identities outside the org drawn off the plane

// 24 one-hour buckets ending with the current hour. Bucket 23 is the hour in progress.
// A past day (1-29 days back) shows the same 24 hours of that day; the 7-day heights stay today's.
const BUCKETS = `date_trunc('hour', now()) - interval '23 hours'`;
// the window as literal timestamps (numbers only, computed here), so every query reads exactly the hours shown
const since = (start) => `to_timestamp(${Number(start) / 1000})`, until = (start) => `to_timestamp(${(Number(start) + 864e5) / 1000})`;
const bucketOf = (t, start) => Math.max(0, Math.min(23, Math.floor((new Date(t).getTime() - start) / 36e5)));

async function hourStart(day = 0) { return new Date((await query(`SELECT ${BUCKETS} - make_interval(days => $1) AS t`, [day])).rows[0].t).getTime(); }

// The last 24 hours, hour by hour. From the hourly rollups (calls counted in the hour they were made; sessions that
// made a call in it): a few thousand small rows. Only an account whose last day is still being counted (a few
// minutes after an upgrade) is added up from its sessions instead, by the hour they started; the others never wait
// for it.
async function split(ids, start) {
  const pending = await uncovered(ids, start);
  return [ids.filter((id) => !pending.has(id)), ids.filter((id) => pending.has(id))];
}
async function hourlyByAccount(ids, start) {
  const [ready, behind] = await split(ids, start);
  const [a, b] = await Promise.all([
    ready.length ? query(
      `SELECT c.account_id, c.hour AS h, COALESCE(s.sessions, 0)::int AS sessions, c.calls, c.denied
         FROM (SELECT account_id, hour, sum(n)::bigint AS calls, COALESCE(sum(n) FILTER (WHERE denied), 0)::bigint AS denied
                 FROM call_hourly WHERE account_id = ANY($1) AND hour >= ${since(start)} AND hour < ${until(start)} GROUP BY 1, 2) c
         LEFT JOIN (SELECT account_id, hour, count(DISTINCT session_id) AS sessions FROM session_hours WHERE account_id = ANY($1) AND hour >= ${since(start)} AND hour < ${until(start)} GROUP BY 1, 2) s
           ON s.account_id = c.account_id AND s.hour = c.hour`, [ready]) : { rows: [] },
    behind.length ? query(`SELECT account_id, date_trunc('hour', started_at) AS h, count(*)::int AS sessions, sum(calls)::bigint AS calls, sum(denied)::bigint AS denied
                             FROM track_sessions WHERE account_id = ANY($1) AND started_at >= ${since(start)} AND started_at < ${until(start)} GROUP BY 1, 2`, [behind]) : { rows: [] }]);
  return { rows: [...a.rows, ...b.rows] };
}
async function hourlyByRole(accountId, start) {
  const [ready] = await split([accountId], start);
  if (ready.length) return query(
    `SELECT role_id, hour AS h, sum(n)::bigint AS calls, COALESCE(sum(n) FILTER (WHERE denied), 0)::bigint AS denied
       FROM call_hourly WHERE account_id=$1 AND hour >= ${since(start)} AND hour < ${until(start)} GROUP BY 1, 2`, [accountId]);
  return query(`SELECT role_id, date_trunc('hour', started_at) AS h, sum(calls)::bigint AS calls, sum(denied)::bigint AS denied
                  FROM track_sessions WHERE account_id=$1 AND started_at >= ${since(start)} AND started_at < ${until(start)} GROUP BY 1, 2`, [accountId]);
}

/**
 * Resource access in Space: resources whose policy lets in anyone or an account outside the estate (open findings, high
 * or medium). Each row says who (as the outside identity's key in the trust layer, so one outsider is one node) and what.
 */
const RES_CONTROLS = ['res.public', 'res.not-principal', 'res.external-account'];
async function resourceGrants(accountIds) {
  if (!accountIds.length) return [];
  return (await query(
    `SELECT f.control, f.severity, f.principal, f.principal_account, f.decision, f.title, r.id, r.name, r.service, r.account_id
       FROM resource_findings f JOIN resources r ON r.id = f.resource_id
      WHERE f.status = 'open' AND r.deleted_at IS NULL AND r.account_id = ANY($1) AND f.control = ANY($2) AND f.severity IN ('high', 'medium')`,
    [accountIds, RES_CONTROLS]).catch((e) => { if (e.code === '42P01') return { rows: [] }; throw e; })).rows;
}
function resourceSource(x) {
  if (x.control === 'res.public') return { key: 'public:Anyone (principal "*")', group: 'public', label: 'Anyone (principal "*")', sub: 'anyone · Principal "*"' };
  if (x.control === 'res.not-principal') return { key: 'public:Everyone except a list (NotPrincipal)', group: 'public', label: 'Everyone except a list (NotPrincipal)', sub: 'anyone · NotPrincipal' };
  if (x.principal_account) return { key: `acct:${x.principal_account}`, group: 'external-account', label: `Account ${x.principal_account}`, sub: knownVendor(x.principal_account) || 'not in your org' };
  const short = String(x.principal).replace(/^arn:aws[a-z-]*:iam::/, '');
  return { key: `res:${x.principal}`, group: 'external-account', label: short.length > 40 ? `${short.slice(0, 39)}…` : short, sub: 'outside your estate' };
}

/**
 * Identities outside the org that can enter roles in these accounts (trust), or use resources there (resource
 * policies), grouped by source, worst first. An expected resource grant (a reviewer accepted it) counts as low.
 */
async function outsiders(user, accountIds, roleIds = null, { edgeCap = 12, rows = null, grants = [] } = {}) {
  const m = rows ? { rows } : await trustMap(user, '', { limit: 1e6 });
  const by = new Map();
  const node = (key, base) => {
    if (!by.has(key)) by.set(key, { key, ...base, worst: 'none', findings: new Set(), targets: new Map(), sessions: 0, lastSeen: null, resources: 0 });
    return by.get(key);
  };
  const target = (s, accountId) => { const t = s.targets.get(accountId) || { roles: new Set(), sessions: 0, edges: [], res: [], resCount: 0 }; s.targets.set(accountId, t); return t; };
  for (const e of m.rows) {
    if (!OUTSIDE.has(e.group) || !accountIds.has(e.accountId) || (roleIds && !roleIds.has(e.roleId))) continue;
    const key = /account/.test(e.group) ? `acct:${e.principalAccount || e.source}` : `${e.group}:${e.source}`;
    const s = node(key, { group: e.group, label: /account/.test(e.group) ? `Account ${e.principalAccount || e.source}` : e.source,
      sub: e.group === 'public' ? 'anyone · Principal "*"' : e.group === 'external-account' ? (e.principalAccountName || 'not in your org')
        : e.identityCenter ? `SAML · ${e.identityCenter.managedFrom ? `managed from ${e.identityCenter.managedFrom}` : e.identityCenter.key === 'unknown' ? 'instance not read yet' : e.identityCenter.region}` : e.group.toUpperCase() });
    if ((SEV[e.worst] ?? 4) < (SEV[s.worst] ?? 4)) s.worst = e.worst;
    if ((SEV[e.worst] ?? 4) < (SEV[s.trustWorst] ?? 4)) s.trustWorst = e.worst;
    for (const f of e.findings) if (f.severity !== 'info') s.findings.add(f.title);
    const t = target(s, e.accountId);
    t.roles.add(e.roleId);
    // what the trust statement says, so a click on the path can explain the warning
    if (t.edges.length < edgeCap) t.edges.push({ roleId: e.roleId, role: e.role, principal: e.principal, actions: e.actions, conditions: e.conditions, worst: e.worst, sid: e.sid || null,
      findings: e.findings.filter((x) => x.severity !== 'info').map((x) => ({ title: x.title, severity: x.severity, detail: x.detail || null })),
      sessions: num(e.sessions), lastSeen: e.lastSeen || null });
    t.sessions += num(e.sessions); s.sessions += num(e.sessions); if (e.lastSeen && (!s.lastSeen || new Date(e.lastSeen) > new Date(s.lastSeen))) s.lastSeen = e.lastSeen;
  }
  for (const x of grants) {
    if (!accountIds.has(x.account_id)) continue;
    const src = resourceSource(x), s = node(src.key, src);
    const sev = x.decision === 'expected' ? 'low' : x.severity;
    if ((SEV[sev] ?? 4) < (SEV[s.worst] ?? 4)) s.worst = sev;
    const t = target(s, x.account_id);
    if (t.res.some((r) => r.id === x.id)) continue;           // one resource once, however many statements let it in
    t.resCount++; s.resources++;
    if (t.res.length < Math.max(edgeCap, 30)) t.res.push({ id: x.id, name: x.name, service: x.service, severity: x.severity, expected: x.decision === 'expected', title: x.title });
  }
  const all = [...by.values()].sort((a, b) => (SEV[a.worst] ?? 4) - (SEV[b.worst] ?? 4) || b.targets.size - a.targets.size || b.sessions - a.sessions);
  return {
    hidden: Math.max(0, all.length - MAX_SOURCES),
    items: all.slice(0, MAX_SOURCES).map((s) => ({ key: s.key, group: s.group, label: s.label, sub: s.sub, worst: s.worst, findings: [...s.findings].slice(0, 3), sessions: s.sessions, lastSeen: s.lastSeen,
      resources: s.resources, trustWorst: s.trustWorst,
      targets: [...s.targets].map(([accountId, t]) => ({ accountId, roles: [...t.roles], sessions: t.sessions,
        edges: t.edges.sort((a, b) => (SEV[a.worst] ?? 4) - (SEV[b.worst] ?? 4)),
        resources: t.res.sort((a, b) => (a.expected - b.expected) || (SEV[a.severity] ?? 4) - (SEV[b.severity] ?? 4)), resourceCount: t.resCount })) })),
  };
}

/** Per account: how many resources are open to anyone or to accounts outside the estate, and the worst finding. */
async function resourceExposure(ids) {
  const r = await query(
    `SELECT account_id, count(*) FILTER (WHERE exposure = 'public')::int AS public, count(*) FILTER (WHERE exposure = 'external')::int AS external,
            min(CASE worst WHEN 'high' THEN 0 WHEN 'medium' THEN 1 WHEN 'low' THEN 2 END) AS w
       FROM resources WHERE deleted_at IS NULL AND account_id = ANY($1) AND exposure IN ('public', 'external') GROUP BY 1`, [ids])
    .catch((e) => { if (e.code === '42P01') return { rows: [] }; throw e; });
  return new Map(r.rows.map((x) => [x.account_id, { public: x.public, external: x.external, worst: ['high', 'medium', 'low'][x.w] || null }]));
}

/**
 * Curious Monkey itself: the identity the workers run as, and the scanner role it enters in each account.
 * Its sign-ins are drawn as their own labelled identity, not mixed into account-to-account paths.
 */
const SCANNER_SESSION = 'session:curious-monkey';
async function scannerOf(ids, start) {
  const idRows = (await query(`SELECT DISTINCT aws_identity->>'principal' AS principal, aws_identity->>'account' AS account FROM workers
                                 WHERE aws_identity ? 'principal' AND heartbeat_at >= now() - interval '30 days'`)).rows.filter((x) => x.principal);
  if (config.scanner.principalArn && !idRows.some((x) => x.principal === config.scanner.principalArn))
    idRows.push({ principal: config.scanner.principalArn, account: config.scanner.principalArn.match(/::(\d{12}):/)?.[1] || null });
  const keys = new Set([SCANNER_SESSION]), accts = new Set();
  for (const x of idRows) {
    const acct = x.account || x.principal.match(/::(\d{12}):/)?.[1];
    if (acct) accts.add(acct);
    if (/:user\//.test(x.principal)) keys.add(`user:${x.principal}`);
    const role = x.principal.match(/::(\d{12}):role\/(?:.*\/)?([^/]+)$/);
    if (role) keys.add(`role:${role[1]}:${role[2]}`);
  }
  const roles = (await query(`SELECT r.id, r.name, r.account_id, a.last_scan_at FROM roles r JOIN cloud_accounts a ON a.id = r.account_id AND r.arn = a.role_arn
                                WHERE r.account_id = ANY($1) AND r.deleted_at IS NULL`, [ids])).rows;
  if (!roles.length) return { item: null, principalIds: new Set() };
  const pr = (await query(`SELECT id, key, role_id, sessions_count, last_seen FROM principals WHERE role_id = ANY($1)`, [roles.map((r) => r.id)])).rows
    .filter((p) => keys.has(p.key) || [...accts].some((a) => p.key.startsWith(`acct:${a}:`)));
  const hours = new Map();
  if (pr.length) for (const x of (await query(`SELECT principal_id, date_trunc('hour', started_at) AS h FROM role_sessions WHERE started_at >= ${since(start)} AND started_at < ${until(start)} AND principal_id = ANY($1) GROUP BY 1, 2`,
    [pr.map((p) => p.id)])).rows) { if (!hours.has(x.principal_id)) hours.set(x.principal_id, new Set()); hours.get(x.principal_id).add(bucketOf(x.h, start)); }
  const home = idRows.length ? (await query(`SELECT id FROM cloud_accounts WHERE account_id = ANY($1) AND id = ANY($2) LIMIT 1`, [[...accts], ids])).rows[0]?.id || null : null;
  const targets = roles.map((r) => {
    const mine = pr.filter((p) => p.role_id === r.id), h = new Set(mine.flatMap((p) => [...(hours.get(p.id) || [])]));
    return { accountId: r.account_id, roleId: r.id, role: r.name, sessions: mine.reduce((n, p) => n + num(p.sessions_count), 0),
      lastSeen: mine.map((p) => p.last_seen).filter(Boolean).sort((a, b) => b - a)[0] || null, lastScan: r.last_scan_at, hours: [...h].sort((a, b) => a - b) };
  });
  return {
    principalIds: new Set(pr.map((p) => p.id)),
    item: { identities: idRows.map((x) => x.principal), homeAccountId: home, homeAws: [...accts][0] || null, targets },
  };
}

/** Changes in the last 24 h, as replay events. */
async function events(where, p, start) {
  const rows = (await query(
    `SELECT c.id, c.account_id, c.role_id, c.kind, c.severity, c.title, c.detail, c.at, r.name AS role_name
       FROM changes c LEFT JOIN roles r ON r.id=c.role_id
      WHERE c.at >= ${since(start)} AND c.at < ${until(start)} AND ${where} ORDER BY c.at DESC LIMIT 40`, p)).rows;
  return rows.map((c) => ({ id: `c${c.id}`, kind: c.kind, severity: c.severity, title: c.title, detail: c.detail, at: c.at, hour: bucketOf(c.at, start), accountId: c.account_id, roleId: c.role_id, roleName: c.role_name }));
}

export async function spaceEstate(user, who = 'all', day = 0) {
  const p = [];
  const accts = (await query(`SELECT a.id, a.name, a.account_id, a.environment, a.ou, a.status, a.note FROM cloud_accounts a WHERE ${scopeSql(user, 'a.id', p)} ORDER BY a.environment, a.ou NULLS LAST, a.name`, p)).rows;
  const ids = accts.map((a) => a.id);
  const start = await hourStart(day);
  if (!ids.length) return { accounts: [], chains: [], outside: { items: [], hidden: 0 }, scanner: null, events: [], hourStart: new Date(start).toISOString() };

  const [roles, hourly, entries, ev] = await Promise.all([
    // last 7 days from the day index; "ever used" is one probe per role instead of a sum over all history
    query(`SELECT r.id, r.account_id, r.name, r.kind, r.risk, r.last_activity_at, coalesce(t.c7,0)::bigint AS calls7, coalesce(t.c1,0)::bigint AS calls24h,
                  EXISTS (SELECT 1 FROM activity_daily d WHERE d.role_id = r.id AND d.count > 0) AS used
             FROM roles r
             LEFT JOIN (SELECT role_id, sum(count) c7, sum(count) FILTER (WHERE day >= current_date - 1) c1
                          FROM activity_daily WHERE day >= current_date - 6 GROUP BY role_id) t ON t.role_id=r.id
            WHERE r.account_id = ANY($1) AND r.deleted_at IS NULL AND ${whoSql(who)}`, [ids]),
    hourlyByAccount(ids, start),
    // account to account: every role or IAM user in one of your accounts that entered a role in another, over 90 days
    query(`SELECT p.id, p.key, p.kind, p.sessions_count, p.first_seen, p.last_seen, r.id AS role_id, r.name AS role_name, r.account_id AS dst
             FROM principals p JOIN roles r ON r.id = p.role_id AND r.deleted_at IS NULL
            WHERE r.account_id = ANY($1) AND p.kind IN ('role','user','account') AND p.last_seen >= now() - interval '90 days'`, [ids]),
    events('c.account_id = ANY($1)', [ids], start),
  ]);

  const byAcct = new Map(accts.map((a) => [a.id, { roles: [], hourly: Array.from({ length: 24 }, () => ({ sessions: 0, calls: 0, denied: 0 })) }]));
  for (const r of roles.rows) byAcct.get(r.account_id).roles.push(r);
  for (const hRow of hourly.rows) { const b = byAcct.get(hRow.account_id).hourly[bucketOf(hRow.h, start)]; b.sessions += hRow.sessions; b.calls += num(hRow.calls); b.denied += num(hRow.denied); }
  const per = Math.max(10, Math.floor(MAX_STARS / accts.length));

  const [grants, exposure] = await Promise.all([resourceGrants(ids), resourceExposure(ids)]);
  const outside = await outsiders(user, new Set(ids), null, { grants });
  // the caller's account comes from the principal key: role:<account>:<name> or user:arn:aws:iam::<account>:user/<name>
  const byAws = new Map((await query('SELECT id, account_id FROM cloud_accounts')).rows.map((x) => [x.account_id, x.id]));
  const inScope = new Set(ids);
  const callerOf = (e) => {
    const m = e.kind === 'role' ? e.key.match(/^role:(\d{12}):(.+)$/) : e.kind === 'account' ? e.key.match(/^acct:(\d{12}):(.+)$/) : e.key.match(/^user:arn:aws[\w-]*:iam::(\d{12}):user\/(.+)$/);
    if (!m) return null;
    return { aws: m[1], name: e.kind !== 'account' ? m[2] : /^AIDA/.test(m[2]) ? `IAM user ${m[2]}` : /^AROA/.test(m[2]) ? `role ${m[2]}` : m[2] };
  };
  const pairs = new Map(), todayOf = new Map();
  const scanner = await scannerOf(ids, start);
  // the roles and users filter: an entry made by an IAM user (by its ARN, or by an AIDA unique ID when CloudTrail gave no
  // ARN) shows with users, any other with roles
  const byUser = (e) => e.kind === 'user' || (e.kind === 'account' && /^acct:\d{12}:AIDA/.test(e.key));
  const keep = (e) => (who === 'users' ? byUser(e) : who === 'roles' ? !byUser(e) : true);
  const cross = entries.rows.map((e) => ({ e, c: callerOf(e) })).filter(({ e, c }) => c && keep(e) && !scanner.principalIds.has(e.id) && byAws.has(c.aws) && byAws.get(c.aws) !== e.dst && inScope.has(byAws.get(c.aws)));
  if (cross.length) {
    for (const x of (await query(`SELECT principal_id, date_trunc('hour', started_at) AS h, count(*)::int AS n FROM role_sessions WHERE started_at >= ${since(start)} AND started_at < ${until(start)} AND principal_id = ANY($1) GROUP BY 1, 2`,
      [cross.map(({ e }) => e.id)])).rows) { if (!todayOf.has(x.principal_id)) todayOf.set(x.principal_id, []); todayOf.get(x.principal_id).push([bucketOf(x.h, start), x.n]); }
  }
  for (const { e, c } of cross) {
    const from = byAws.get(c.aws), k = `${from}|${e.dst}`;
    if (!pairs.has(k)) pairs.set(k, { from, to: e.dst, sessions: 0, firstSeen: null, lastSeen: null, today: Array(24).fill(0), roles: [] });
    const pr = pairs.get(k);
    pr.sessions += num(e.sessions_count);
    if (e.first_seen && (!pr.firstSeen || e.first_seen < pr.firstSeen)) pr.firstSeen = e.first_seen;
    if (e.last_seen && (!pr.lastSeen || e.last_seen > pr.lastSeen)) pr.lastSeen = e.last_seen;
    for (const [b, n] of todayOf.get(e.id) || []) pr.today[b] += n;
    pr.roles.push({ caller: `${e.kind === 'user' ? 'user/' : ''}${c.name}`, callerKind: e.kind, roleId: e.role_id, role: e.role_name, sessions: num(e.sessions_count), lastSeen: e.last_seen });
  }
  return {
    hourStart: new Date(start).toISOString(),
    accounts: accts.map((a) => {
      const x = byAcct.get(a.id);
      const active = x.roles.filter((r) => r.used).sort((m, n) => num(n.calls7) - num(m.calls7) || (n.last_activity_at ? +new Date(n.last_activity_at) : 0) - (m.last_activity_at ? +new Date(m.last_activity_at) : 0));
      const cold = x.roles.length - active.length;
      return {
        id: a.id, name: a.name, awsAccountId: a.account_id, environment: environmentOf(a.environment), ou: a.ou || null,
        planned: a.status === 'planned', note: a.status === 'planned' ? a.note : null,
        roles: x.roles.length, active: active.length, cold, high: x.roles.filter((r) => r.risk === 'High').length,
        calls7: x.roles.reduce((s, r) => s + num(r.calls7), 0), calls24h: x.roles.reduce((s, r) => s + num(r.calls24h), 0),
        // the busiest roles are drawn one by one; the rest of the active ones are counted
        stars: active.slice(0, per).map((r) => ({ id: r.id, name: r.name, calls7: num(r.calls7), risk: r.risk, kind: r.kind })),
        hourly: x.hourly,
        // resource access: how many of its resources anyone, or an account outside the estate, can use
        resources: exposure.get(a.id) || null,
      };
    }),
    chains: [...pairs.values()].map((x) => ({ from: x.from, to: x.to, sessions: x.sessions, today: x.today.reduce((a, b) => a + b, 0),
      hours: x.today.map((n, b) => (n ? b : -1)).filter((b) => b >= 0), isNew: !!x.firstSeen && new Date(x.firstSeen).getTime() >= start,
      firstSeen: x.firstSeen, lastSeen: x.lastSeen, roles: x.roles.sort((m, n) => n.sessions - m.sessions).slice(0, 12), moreRoles: Math.max(0, x.roles.length - 12) })),
    outside,
    scanner: scanner.item,
    events: ev,
  };
}

const svcOf = (action) => String(action).split(':')[0];

export async function spaceAccount(user, accountId, who = 'all', day = 0) {
  if (!inScope(user, accountId)) return null;
  const a = (await query('SELECT id, name, account_id, environment, ou FROM cloud_accounts WHERE id=$1', [accountId])).rows[0];
  if (!a) return null;
  const start = await hourStart(day);
  const [roles, acts, hourly, chains, ev] = await Promise.all([
    // cold: no allowed call stored, ever. One index probe per role, not a sum over every role's history.
    query(`SELECT r.id, r.name, r.kind, r.risk, EXISTS (SELECT 1 FROM activity_daily d WHERE d.role_id = r.id AND d.count > 0) AS used
             FROM roles r WHERE r.account_id=$1 AND r.deleted_at IS NULL AND ${whoSql(who)}`, [accountId]),
    // calls per role per action over 7 days, so each role has its services
    query(`SELECT d.role_id, d.action, sum(d.count)::bigint AS n, sum(d.error_count)::bigint AS denied FROM activity_daily d JOIN roles r ON r.id=d.role_id
            WHERE r.account_id=$1 AND d.day >= current_date - 6 AND ${whoSql(who)} GROUP BY 1, 2`, [accountId]),
    hourlyByRole(accountId, start),
    // role chaining in and out over 7 days. Two halves so each uses an index: sessions here and their parents (by key),
    // and this account's sessions and their children (by parent key). A parent lives at most 36 h before its child.
    query(`WITH pairs AS (
             SELECT p.account_id AS src, s.account_id AS dst, p.role_id AS src_role_id, s.role_id AS dst_role_id
               FROM track_sessions s JOIN track_sessions p ON p.access_key_id = s.parent_key_id
              WHERE s.account_id = $1 AND s.started_at >= now() - interval '7 days' AND s.parent_key_id IS NOT NULL AND p.account_id <> $1
             UNION ALL
             SELECT p.account_id, s.account_id, p.role_id, s.role_id
               FROM track_sessions p JOIN track_sessions s ON s.parent_key_id = p.access_key_id
              WHERE p.account_id = $1 AND p.started_at >= now() - interval '7 days' - interval '36 hours'
                AND s.started_at >= now() - interval '7 days' AND s.account_id <> $1)
           SELECT x.src, x.dst, pr.name AS src_role, sr.name AS dst_role, x.dst_role_id, x.src_role_id, x.n
             FROM (SELECT src, dst, src_role_id, dst_role_id, count(*)::int AS n FROM pairs GROUP BY 1, 2, 3, 4) x
             JOIN roles pr ON pr.id = x.src_role_id JOIN roles sr ON sr.id = x.dst_role_id`, [accountId]),
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
    return { id: r.id, name: r.name, kind: r.kind, risk: r.risk, cold: !r.used, calls7: s.reduce((t, x) => t + x.calls, 0), denied7: s.reduce((t, x) => t + x.denied, 0),
      services: s.slice(0, 6), hourly: roleHours.get(r.id) || Array(24).fill(0) };
  });
  // services: the account's busiest eight. Clusters: roles grouped by the service they call most
  const total = new Map();
  for (const r of out) for (const s of r.services) total.set(s.name, (total.get(s.name) || 0) + s.calls);
  const services = [...total].sort((m, n) => n[1] - m[1]).slice(0, 8).map(([name, calls]) => ({ name, calls }));
  const groups = new Map();
  for (const r of out.filter((x) => !x.cold)) { const k = r.services[0]?.name || 'quiet this week'; if (!groups.has(k)) groups.set(k, []); groups.get(k).push(r); }
  // the busiest five services keep a ring each, the rest share one; roles used before but not this week keep their own
  // ring, so they are never counted under "Other services" as if they had called something
  const quiet = groups.get('quiet this week'); groups.delete('quiet this week');
  let clusters = [...groups].map(([key, rs]) => ({ key, roles: rs, calls: rs.reduce((t, r) => t + r.calls7, 0) })).sort((m, n) => n.roles.length - m.roles.length || n.calls - m.calls);
  if (clusters.length > 6) clusters = [...clusters.slice(0, 5), { key: 'other', roles: clusters.slice(5).flatMap((c) => c.roles) }];
  if (quiet) clusters.push({ key: 'quiet this week', roles: quiet, calls: 0 });

  const ids = new Set([a.id]);
  // Trust into this account's roles (for the outside identities and your accounts that may come in), and trust in
  // other accounts' roles that names this account (where its identities may go). The second only reads roles whose
  // trust policy mentions this account's ID.
  const [inTrust, outTrust] = await Promise.all([
    trustMap({ ...user, scope_accounts: [a.id] }, '', { limit: 1e6 }),
    trustMap(user, '', { limit: 1e6, mentions: a.account_id }),
  ]);
  const [grants, exposed] = await Promise.all([resourceGrants([a.id]),
    query(`SELECT id, name, service, exposure, worst FROM resources WHERE account_id = $1 AND deleted_at IS NULL AND exposure IN ('public', 'external')
            ORDER BY CASE worst WHEN 'high' THEN 0 WHEN 'medium' THEN 1 ELSE 2 END, name LIMIT 60`, [a.id]).catch((e) => { if (e.code === '42P01') return { rows: [] }; throw e; })]);
  const outside = await outsiders(user, ids, null, { edgeCap: 500, rows: inTrust.rows, grants });
  const byAws = new Map((await query('SELECT id, account_id, name, environment FROM cloud_accounts')).rows.map((x) => [x.account_id, x]));
  const byId = new Map([...byAws.values()].map((x) => [x.id, x]));
  // roles and IAM users here, by id, and by kind and name (a role and a user may share a name)
  const hereRows = (await query('SELECT id, name, kind FROM roles WHERE account_id=$1 AND deleted_at IS NULL', [a.id])).rows;
  const hereById = new Map(hereRows.map((r) => [r.id, r]));
  const roleHere = new Map(hereRows.map((r) => [`${r.kind === 'iam-user' ? 'user' : 'role'}|${r.name}`, r.id]));
  // which role or IAM user here a principal names (arn:aws:iam::<this>:role/path/name, …:user/path/name, or a session
  // of a role here), or null for the whole account. An IAM user named in a trust policy is that user, not the account.
  const hereRole = (principal) => {
    const s = String(principal), m = s.match(new RegExp(`^arn:aws[a-z-]*:iam::${a.account_id}:(role|user)/(?:.*/)?([^/]+)$`)) || s.match(new RegExp(`^arn:aws[a-z-]*:sts::${a.account_id}:(assumed-role)/([^/]+)/[^/]+$`));
    return m ? roleHere.get(`${m[1] === 'user' ? 'user' : 'role'}|${m[2]}`) || null : null;
  };
  // the roles and users filter: a line from a role or IAM user here is kept only while that kind is shown; a line from
  // the whole account always is (any role or user here may use it)
  const shown = (roleId) => { if (!roleId) return true; const k = hereById.get(roleId)?.kind; return who === 'users' ? k === 'iam-user' : who === 'roles' ? k !== 'iam-user' : true; };
  const SEVR = { high: 0, medium: 1, low: 2, info: 3, none: 4 };

  // one line per role here and direction, however many roles it pairs with on the other side; the busiest are drawn.
  // A line is used (sessions seen chaining), allowed (a trust policy lets it), or both.
  const neighbours = new Map();
  const link = (otherId, dir, roleId) => {
    const o = byId.get(otherId); if (!o || otherId === a.id || !inScope(user, otherId) || !shown(roleId)) return null;
    if (!neighbours.has(otherId)) neighbours.set(otherId, { id: otherId, name: o.name, environment: environmentOf(o.environment), awsAccountId: o.account_id, sessions: 0, allowedIn: 0, allowedOut: 0, byLink: new Map() });
    const n = neighbours.get(otherId), k = `${dir}:${roleId || '*'}`;
    if (!n.byLink.has(k)) n.byLink.set(k, { dir, roleId, sessions: 0, allowed: 0, worst: 'none', others: new Map() });
    return [n, n.byLink.get(k)];
  };
  for (const c of chains.rows) {
    const dir = c.src === a.id ? 'out' : 'in', x = link(dir === 'out' ? c.dst : c.src, dir, dir === 'out' ? c.src_role_id : c.dst_role_id); if (!x) continue;
    const [n, l] = x, other = dir === 'out' ? c.dst_role : c.src_role;
    l.sessions += c.n; n.sessions += c.n; l.others.set(other, (l.others.get(other) || 0) + c.n);
  }
  const allow = (n, l, other, e) => {
    l.allowed++; if ((SEVR[e.worst] ?? 4) < (SEVR[l.worst] ?? 4)) l.worst = e.worst;
    if (!l.others.has(other)) l.others.set(other, 0);
    if (l.dir === 'in') n.allowedIn++; else n.allowedOut++;
  };
  // in: a role here trusts another of your accounts (the whole account, or a role or user in it)
  for (const e of inTrust.rows) {
    if (e.group !== 'connected-account' || e.accountId !== a.id) continue;
    const from = byAws.get(e.principalAccount); if (!from) continue;
    const x = link(from.id, 'in', e.roleId); if (!x) continue;
    allow(x[0], x[1], e.type === 'aws-root' ? 'whole account' : e.principal.split('/').pop(), e);
  }
  // out: a role in another of your accounts trusts this account, or a role or IAM user here
  for (const e of outTrust.rows) {
    if (e.principalAccount !== a.account_id || e.accountId === a.id || !/^aws-/.test(e.type)) continue;
    const x = link(e.accountId, 'out', hereRole(e.principal)); if (!x) continue;
    allow(x[0], x[1], e.role, e);
  }
  const LINKS_PER_NEIGHBOUR = 40, NEIGHBOURS = 8;
  const weight = (n) => n.sessions * 10 + n.allowedIn + n.allowedOut;
  const nearest = [...neighbours.values()].sort((m, n) => weight(n) - weight(m)).slice(0, NEIGHBOURS).map(({ byLink, ...n }) => {
    const links = [...byLink.values()].sort((m, k) => k.sessions - m.sessions || k.allowed - m.allowed);
    return { ...n, moreLinks: Math.max(0, links.length - LINKS_PER_NEIGHBOUR), links: links.slice(0, LINKS_PER_NEIGHBOUR).map((l) => {
      const others = [...l.others].sort((m, k) => k[1] - m[1]);
      return { dir: l.dir, roleId: l.roleId, roleName: hereById.get(l.roleId)?.name || null, sessions: l.sessions, allowed: l.allowed, worst: l.worst,
        otherRole: others.length > 1 ? `${others[0][0]} +${others.length - 1} more` : others[0]?.[0] || '' };
    }) };
  });
  return {
    hourStart: new Date(start).toISOString(),
    account: { id: a.id, name: a.name, awsAccountId: a.account_id, environment: environmentOf(a.environment), ou: a.ou || null },
    services, clusters: clusters.map((c) => ({ key: c.key, roles: c.roles.sort((m, n) => n.calls7 - m.calls7).slice(0, 40), more: Math.max(0, c.roles.length - 40) })),
    cold: out.filter((r) => r.cold).map((r) => ({ id: r.id, name: r.name })).slice(0, 80), coldCount: out.filter((r) => r.cold).length, roleCount: out.length,
    // called this week: every one with a call in 7 days (the rings draw at most 40 a service)
    calledCount: out.filter((r) => r.calls7 > 0).length,
    neighbours: nearest, outside, scanner: (await scannerOf([a.id], start)).item, events: ev,
    // resources here that anyone, or an account outside the estate, can use (the worst 60)
    resources: exposed.rows,
  };
}
