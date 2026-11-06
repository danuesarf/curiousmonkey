import { config } from '../config.js';
import { query, tx } from '../db.js';
import { parseEvent } from '../analyzer/events.js';
import { matchTrust } from '../analyzer/trust.js';
import { loadContext } from './inventory.js';

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const HOUR = 3600e3, MIN = 60e3, DAY = 24 * HOUR;

/** Everything needed to resume lives in scan_checkpoints, so a retry never reads a finished slice again. */
export async function runEvents(ctx) {
  const { account, gw } = await loadContext(ctx.job.account_id);
  const region = ctx.job.region;
  const s = config.scanner;
  const now = Date.now();
  const end = now - s.deliveryLagMinutes * MIN;                // newest events may not be delivered yet
  const horizon = now - s.lookbackDays * DAY;                  // Event History keeps 90 days

  const cp = (await query(`SELECT * FROM scan_checkpoints WHERE account_id=$1 AND region=$2 AND source='event-history'`, [account.id, region])).rows[0];
  let start, gap = false;
  if (!cp) start = horizon;
  else {
    start = new Date(cp.last_event_time).getTime() - s.overlapMinutes * MIN;   // overlap catches late delivery; seen_events removes dupes
    if (start < horizon) { start = horizon; gap = true; }                       // the worker was down longer than the history lasts
  }
  if (start >= end) return { skipped: 'up to date' };

  const slices = [];
  for (let t = start; t < end; t += s.sliceHours * HOUR) slices.push([t, Math.min(t + s.sliceHours * HOUR, end)]);
  const roleIds = new Map((await query(`SELECT arn, id, trust_policy FROM roles WHERE account_id=$1 AND deleted_at IS NULL`, [account.id])).rows.map((r) => [r.arn, r]));

  let total = 0;
  for (let i = 0; i < slices.length; i++) {
    ctx.alive();
    const [a, b] = slices[i];
    const raw = [];
    let token = null;
    do {
      const page = await gw.lookupEventsPage({ region, start: new Date(a), end: new Date(b), token });
      raw.push(...page.events);
      token = page.nextToken;
      if (token && s.lookupDelayMs) await sleep(s.lookupDelayMs);               // LookupEvents: 2 requests/second
    } while (token);

    const n = await tx(async (c) => {
      const parsed = raw.map(parseEvent).filter((e) => e.type !== 'ignore');
      const ids = parsed.map((e) => e.id);
      const fresh = new Set((await c.query(
        `INSERT INTO seen_events(account_id, event_id, event_time) SELECT $3, x, to_timestamp($2) FROM unnest($1::text[]) x ON CONFLICT DO NOTHING RETURNING event_id`,
        [ids, b / 1000, account.id])).rows.map((r) => r.event_id));
      // assumptions first, so a session's calls can be attributed to who started it
      const evs = parsed.filter((e) => fresh.has(e.id)).sort((x, y) => (x.type === y.type ? x.time - y.time : x.type === 'assume' ? -1 : 1));
      await applyEvents(c, evs, roleIds);
      await c.query(
        `INSERT INTO scan_checkpoints(account_id, region, source, first_event_time, last_event_time, events_read, gap_detected, last_run_at)
         VALUES ($1,$2,'event-history',to_timestamp($3),to_timestamp($4),$5,$6,now())
         ON CONFLICT (account_id, region, source) DO UPDATE SET
           last_event_time=GREATEST(scan_checkpoints.last_event_time, EXCLUDED.last_event_time),
           first_event_time=COALESCE(scan_checkpoints.first_event_time, EXCLUDED.first_event_time),
           events_read=scan_checkpoints.events_read+EXCLUDED.events_read,
           gap_detected=scan_checkpoints.gap_detected OR EXCLUDED.gap_detected, last_run_at=now()`,
        [account.id, region, a / 1000, b / 1000, evs.length, gap]);
      return evs.length;
    });
    total += n;
    await ctx.progress({ phase: 'events', region, slice: new Date(b).toISOString(), done: i + 1, total: slices.length, events: total });
  }
  await query(`DELETE FROM seen_events WHERE event_time < now() - interval '3 days'`);
  await query(`DELETE FROM role_sessions WHERE started_at < now() - interval '2 days'`);   // credentials last at most 12h
  return { slices: slices.length, events: total, gap };
}

function principalFrom(e) {
  const c = e.caller;
  if (c.type === 'AWSService' || c.invokedBy) return { key: `svc:${c.invokedBy}`, kind: 'service', display: c.invokedBy };
  if (c.type === 'IAMUser') return { key: `user:${c.arn}`, kind: 'user', display: `${c.arn?.split(':').pop()} (${c.accountId})` };
  if (c.type === 'AssumedRole') { const m = c.arn?.match(/assumed-role\/([^/]+)\//); return { key: `role:${c.accountId}:${m?.[1]}`, kind: 'role', display: `role/${m?.[1]} (${c.accountId})` }; }
  if (c.type === 'SAMLUser' || c.type === 'WebIdentityUser') {
    const who = c.principalId?.split(':').slice(1).join(':') || e.sessionName;
    return { key: `fed:${c.principalId || e.sessionName}`, kind: 'federated', display: who };
  }
  return { key: `other:${c.arn || c.type}`, kind: 'other', display: c.arn || String(c.type) };
}

async function applyEvents(c, evs, roles) {
  const principalIds = new Map();                     // key -> id (this slice)
  const ensurePrincipal = async (role, p, e, extra = {}) => {
    const k = `${role.id}|${p.key}`;
    if (!principalIds.has(k)) {
      const r = await c.query(
        `INSERT INTO principals(role_id, key, kind, display, via, caller, first_seen, last_seen, sessions_count, source_ips, mfa, source_identity, session_tags)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$7,0,'{}',NULL,NULL,'{}')
         ON CONFLICT (role_id, key) DO UPDATE SET first_seen=LEAST(principals.first_seen, EXCLUDED.first_seen), last_seen=GREATEST(principals.last_seen, EXCLUDED.last_seen)
         RETURNING id`, [role.id, p.key, p.kind, p.display, extra.via || 'session', JSON.stringify(extra.caller || {}), e.time]);
      principalIds.set(k, r.rows[0].id);
    }
    return principalIds.get(k);
  };

  const daily = new Map(), resources = new Map(), passed = new Map();
  for (const e of evs) {
    const role = roles.get(e.roleArn);
    if (!role) continue;
    if (e.type === 'assume') {
      if (e.denied) continue;                          // a refused AssumeRole is not a use
      const p = principalFrom(e);
      const viaAction = `sts:${e.eventName}`;
      const trust = matchTrust(role.trust_policy, e.caller, viaAction);
      const id = await ensurePrincipal(role, p, e, { via: viaAction, caller: { ...e.caller, trust } });
      await c.query(
        `UPDATE principals SET sessions_count=sessions_count+1, caller=$2,
           source_ips = (SELECT ARRAY(SELECT DISTINCT unnest(source_ips || $3::text[]) LIMIT 20)),
           mfa = COALESCE($4, mfa) OR mfa, source_identity=COALESCE($5, source_identity),
           session_tags = (SELECT ARRAY(SELECT DISTINCT unnest(session_tags || $6::text[]) LIMIT 20)), via=$7
         WHERE id=$1`,
        [id, JSON.stringify({ ...e.caller, trust }), e.ip ? [e.ip] : [], e.mfa, e.sourceIdentity, e.sessionTags || [], viaAction]);
      if (e.accessKeyId) await c.query(
        `INSERT INTO role_sessions(access_key_id, role_id, principal_id, started_at) VALUES ($1,$2,$3,$4) ON CONFLICT (access_key_id) DO NOTHING`,
        [e.accessKeyId, role.id, id, e.time]);
      continue;
    }
    // an API call made with the role's credentials
    let principalId = null;
    if (e.accessKeyId) principalId = (await c.query('SELECT principal_id FROM role_sessions WHERE access_key_id=$1', [e.accessKeyId])).rows[0]?.principal_id ?? null;
    if (!principalId) principalId = await ensurePrincipal(role, { key: `session:${e.sessionName}`, kind: 'session', display: `session ${e.sessionName}` }, e, { via: 'unknown (started before the window)' });
    else await c.query('UPDATE principals SET last_seen=GREATEST(last_seen,$2), first_seen=LEAST(first_seen,$2) WHERE id=$1', [principalId, e.time]);
    if (!e.action) continue;
    const day = e.time.toISOString().slice(0, 10);
    const dk = `${role.id}|${principalId}|${e.action}|${day}`;
    const d = daily.get(dk) || { role: role.id, principal: principalId, action: e.action, day, ok: 0, err: 0 };
    e.denied ? d.err++ : d.ok++; daily.set(dk, d);
    if (e.denied) continue;                            // denied calls prove nothing was used
    for (const r of e.resources) {
      const rk = `${role.id}|${e.action}|${r}`;
      const x = resources.get(rk) || { role: role.id, action: e.action, resource: r, last: e.time, n: 0 };
      x.n++; if (e.time > x.last) x.last = e.time; resources.set(rk, x);
    }
    for (const arn of e.passedRoles) {
      const svc = e.eventSource.replace(/\.amazonaws\.com$/, '');
      const pk = `${role.id}|${arn}|${svc}`;
      const x = passed.get(pk) || { role: role.id, arn, svc, last: e.time, n: 0 };
      x.n++; if (e.time > x.last) x.last = e.time; passed.set(pk, x);
    }
  }
  for (const d of daily.values()) await c.query(
    `INSERT INTO activity_daily(role_id, principal_id, action, day, count, error_count) VALUES ($1,$2,$3,$4,$5,$6)
     ON CONFLICT (role_id, principal_id, action, day) DO UPDATE SET count=activity_daily.count+EXCLUDED.count, error_count=activity_daily.error_count+EXCLUDED.error_count`,
    [d.role, d.principal, d.action, d.day, d.ok, d.err]);
  for (const x of resources.values()) await c.query(
    `INSERT INTO activity_resources(role_id, action, resource, last_seen, count) VALUES ($1,$2,$3,$4,$5)
     ON CONFLICT (role_id, action, resource) DO UPDATE SET count=activity_resources.count+EXCLUDED.count, last_seen=GREATEST(activity_resources.last_seen, EXCLUDED.last_seen)`,
    [x.role, x.action, x.resource, x.last, x.n]);
  for (const x of passed.values()) await c.query(
    `INSERT INTO passrole_observed(role_id, passed_role_arn, service, last_seen, count) VALUES ($1,$2,$3,$4,$5)
     ON CONFLICT (role_id, passed_role_arn, service) DO UPDATE SET count=passrole_observed.count+EXCLUDED.count, last_seen=GREATEST(passrole_observed.last_seen, EXCLUDED.last_seen)`,
    [x.role, x.arn, x.svc, x.last, x.n]);
}
