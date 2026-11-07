import { config } from '../config.js';
import { query, tx } from '../db.js';
import { parseEvent } from '../analyzer/events.js';
import { matchTrust } from '../analyzer/trust.js';
import { loadContext } from './inventory.js';
import { provisionalAnalyze } from './analyzeJob.js';
import { recordNewCaller } from '../radarHistory.js';
import { accountComplete } from '../history.js';


const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const HOUR = 3600e3, MIN = 60e3, DAY = 24 * HOUR;

/** Days of history to keep reading. Event History stops at 90; an S3 trail goes as far back as its files. */
export const lookbackFor = (account) => (account.event_source === 's3' ? account.lookback_days : Math.min(account.lookback_days || 90, 90));

/**
 * Everything needed to resume lives in scan_checkpoints, so a retry never reads a finished slice again.
 * Forward slices continue from the newest stored event. If the window was widened (or the source switched to an
 * S3 trail with a longer lookback), the older range is backfilled newest-first so a crash resumes where it stopped.
 */
export async function runEvents(ctx) {
  const { account, gw } = await loadContext(ctx.job.account_id);
  const region = ctx.job.region;
  const s = config.scanner;
  const src = account.event_source === 's3' ? 's3' : 'event-history';
  const now = Date.now();
  const end = now - s.deliveryLagMinutes * MIN;                // newest events may not be delivered yet
  const horizon = now - lookbackFor(account) * DAY;
  const step = s.sliceHours * HOUR;

  const cp = (await query(`SELECT * FROM scan_checkpoints WHERE account_id=$1 AND region=$2`, [account.id, region])).rows[0];
  const slices = [];          // [start, end, kind]
  let gap = false;
  if (!cp) {
    for (let t = horizon; t < end; t += step) slices.push([t, Math.min(t + step, end), 'forward']);
  } else {
    const first = new Date(cp.first_event_time || cp.last_event_time).getTime();
    for (let t = first; t > horizon; t -= step) slices.push([Math.max(t - step, horizon), t, 'backfill']);
    let start = new Date(cp.last_event_time).getTime() - s.overlapMinutes * MIN;   // overlap catches late delivery; seen_events removes dupes
    if (start < horizon) { start = horizon; gap = true; }                           // the worker was down longer than the history lasts
    for (let t = start; t < end; t += step) slices.push([t, Math.min(t + step, end), 'forward']);
  }
  if (!slices.length) {
    await query('UPDATE scan_checkpoints SET caught_up_at=now() WHERE account_id=$1 AND region=$2', [account.id, region]);
    return { skipped: 'up to date' };
  }

  const roleRows = (await query(`SELECT arn, name, id, trust_policy FROM roles WHERE account_id=$1 AND deleted_at IS NULL`, [account.id])).rows;
  const roles = { byArn: new Map(roleRows.map((r) => [r.arn, r])), byName: new Map(roleRows.map((r) => [r.name, r])) };
  const listCache = new Map();
  const t0 = Date.now();
  let rate = null;                                             // seconds per slice, smoothed
  let lastProvisional = Date.now();
  let total = 0;
  const wasComplete = await accountComplete(account.id);     // pings for new callers only once the first full read is done
  for (let i = 0; i < slices.length; i++) {
    ctx.alive();
    const [a, b, kind] = slices[i];
    const sliceStart = Date.now();
    const raw = [];
    if (src === 's3') raw.push(...await gw.trailEventsForSlice({ region, start: new Date(a), end: new Date(b), listCache }));
    else {
      let token = null;
      do {
        const page = await gw.lookupEventsPage({ region, start: new Date(a), end: new Date(b), token });
        raw.push(...page.events);
        token = page.nextToken;
        if (token && s.lookupDelayMs) await sleep(s.lookupDelayMs);             // LookupEvents: 2 requests/second
      } while (token);
    }

    const n = await tx(async (c) => {
      // Regions of one account fetch in parallel but write one at a time: they update the same roles' rows,
      // and two transactions taking those row locks in different orders deadlock.
      await c.query('SELECT pg_advisory_xact_lock(727100, hashtext($1))', [account.id]);
      const all = raw.map(parseEvent).filter((e) => e.id);
      const fresh = new Set((await c.query(
        `INSERT INTO seen_events(account_id, event_id, event_time) SELECT $3, x, to_timestamp($2) FROM unnest($1::text[]) x ON CONFLICT DO NOTHING RETURNING event_id`,
        [all.map((e) => e.id), b / 1000, account.id])).rows.map((r) => r.event_id));
      const evs = all.filter((e) => fresh.has(e.id));
      const cov = coverage(evs, roles);
      // assumptions first, so a session's calls can be attributed to who started it
      const usable = evs.filter((e) => e.type !== 'ignore').sort((x, y) => (x.type === y.type ? x.time - y.time : x.type === 'assume' ? -1 : 1));
      await applyEvents(c, usable, roles, account.id, { recordNew: wasComplete && kind === 'forward' });
      await saveCoverage(c, account.id, region, new Date(a), cov);
      await c.query(
        `INSERT INTO scan_checkpoints(account_id, region, source, first_event_time, last_event_time, events_read, gap_detected, last_run_at)
         VALUES ($1,$2,$7,to_timestamp($3),to_timestamp($4),$5,$6,now())
         ON CONFLICT (account_id, region) DO UPDATE SET source=EXCLUDED.source,
           last_event_time=GREATEST(scan_checkpoints.last_event_time, EXCLUDED.last_event_time),
           first_event_time=LEAST(COALESCE(scan_checkpoints.first_event_time, EXCLUDED.first_event_time), EXCLUDED.first_event_time),
           events_read=scan_checkpoints.events_read+EXCLUDED.events_read,
           gap_detected=scan_checkpoints.gap_detected OR EXCLUDED.gap_detected, last_run_at=now()`,
        [account.id, region, a / 1000, kind === 'backfill' ? (cp?.last_event_time ? new Date(cp.last_event_time).getTime() / 1000 : b / 1000) : b / 1000, usable.length, gap, src]);
      return usable.length;
    });
    total += n;
    // show what is known so far: refresh results every few minutes during a long first read
    if (Date.now() - lastProvisional > s.provisionalEveryMs && i < slices.length - 1) {
      lastProvisional = Date.now();
      await provisionalAnalyze(account.id, (m) => ctx.log?.(m)).catch((e) => ctx.log?.(`provisional analysis skipped: ${e.message}`, null, 'warn'));
    }
    const took = (Date.now() - sliceStart) / 1000;
    rate = rate == null ? took : rate * 0.8 + took * 0.2;      // recent slices count more; busy and quiet days differ
    const elapsed = (Date.now() - t0) / 1000;
    await ctx.progress({ phase: 'events', source: src, region, slice: new Date(kind === 'backfill' ? a : b).toISOString(), direction: kind,
      done: i + 1, total: slices.length, events: total, elapsedSeconds: Math.round(elapsed),
      etaSeconds: Math.round(rate * (slices.length - i - 1)), eventsPerSecond: elapsed > 0 ? Math.round(total / elapsed) : null });
  }
  await query('UPDATE scan_checkpoints SET caught_up_at=now() WHERE account_id=$1 AND region=$2', [account.id, region]);   // reached the present
  await query(`DELETE FROM seen_events WHERE event_time < now() - interval '3 days'`);
  await query(`DELETE FROM role_sessions WHERE started_at < now() - interval '2 days'`);   // credentials last at most 12h
  await query(`DELETE FROM track_sessions WHERE account_id=$1 AND COALESCE(last_call_at, started_at) < now() - make_interval(days => $2)`, [account.id, config.scanner.sessionRetentionDays]);
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

/** The role an event belongs to: by ARN, or by name when the event had no sessionIssuer. */
export const roleOf = (e, roles) => (e.roleArn ? roles.byArn.get(e.roleArn) : e.roleName ? roles.byName.get(e.roleName) : null) || null;

/** Count what happens to every event, so nothing is dropped without a trace. */
export function coverage(evs, roles) {
  const k = { events: evs.length, assume_events: 0, role_calls: 0, recovered_role: 0, other_role: 0, not_role: 0, no_permission: 0, unmapped: 0, no_resources: 0 };
  const unmapped = new Map();
  for (const e of evs) {
    if (e.type === 'ignore') { k.not_role++; continue; }
    const role = roleOf(e, roles);
    if (!role) { k.other_role++; continue; }
    if (e.type === 'assume') { k.assume_events++; continue; }
    k.role_calls++;
    if (!e.roleArn) k.recovered_role++;
    if (e.noPermission) { k.no_permission++; continue; }
    if (!e.mapped && e.action) {
      k.unmapped++;
      const u = unmapped.get(e.action) || { raw: e.action, source: e.eventSource, name: e.eventName, n: 0, first: e.time, last: e.time, identity: e.identityType, keys: e.paramKeys };
      u.n++; if (e.time < u.first) u.first = e.time; if (e.time > u.last) u.last = e.time; unmapped.set(e.action, u);
    }
    if (!e.denied && !e.resources.length) k.no_resources++;
  }
  return { k, unmapped };
}
async function saveCoverage(c, accountId, region, day, { k, unmapped }) {
  const cols = Object.keys(k);
  await c.query(
    `INSERT INTO event_coverage(account_id, region, day, ${cols.join(',')}) VALUES ($1,$2,$3,${cols.map((_, i) => `$${i + 4}`).join(',')})
     ON CONFLICT (account_id, region, day) DO UPDATE SET ${cols.map((x) => `${x}=event_coverage.${x}+EXCLUDED.${x}`).join(', ')}`,
    [accountId, region, day.toISOString().slice(0, 10), ...Object.values(k)]);
  for (const u of unmapped.values()) await c.query(
    `INSERT INTO unmapped_events(account_id, raw_action, event_source, event_name, count, first_seen, last_seen, identity_type, param_keys)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
     ON CONFLICT (account_id, raw_action) DO UPDATE SET count=unmapped_events.count+EXCLUDED.count,
       first_seen=LEAST(unmapped_events.first_seen, EXCLUDED.first_seen), last_seen=GREATEST(unmapped_events.last_seen, EXCLUDED.last_seen),
       param_keys=(SELECT ARRAY(SELECT DISTINCT unnest(unmapped_events.param_keys || EXCLUDED.param_keys) LIMIT 30))`,
    [accountId, u.raw, u.source, u.name, u.n, u.first, u.last, u.identity, u.keys || []]);
}

export async function applyEvents(c, evs, roles, accountId, opts = {}) {
  const principalIds = new Map();                     // key -> id (this slice)
  const ensurePrincipal = async (role, p, e, extra = {}) => {
    const k = `${role.id}|${p.key}`;
    if (!principalIds.has(k)) {
      const r = await c.query(
        `INSERT INTO principals(role_id, key, kind, display, via, caller, first_seen, last_seen, sessions_count, source_ips, mfa, source_identity, session_tags)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$7,0,'{}',NULL,NULL,'{}')
         ON CONFLICT (role_id, key) DO UPDATE SET first_seen=LEAST(principals.first_seen, EXCLUDED.first_seen), last_seen=GREATEST(principals.last_seen, EXCLUDED.last_seen)
         RETURNING id, (xmax = 0) AS inserted`, [role.id, p.key, p.kind, p.display, extra.via || 'session', JSON.stringify(extra.caller || {}), e.time]);
      principalIds.set(k, r.rows[0].id);
      // a caller never seen before, in an account whose history was already complete: ping it
      if (r.rows[0].inserted && opts.recordNew && p.kind !== 'session' && new Date(e.time).getTime() > Date.now() - 3 * DAY) {
        await recordNewCaller(c, accountId, role, p, extra.via, e.time);
      }
    }
    return principalIds.get(k);
  };

  // ---- sessions (kept for replay within the retention window) ----
  const keepFrom = Date.now() - config.scanner.sessionRetentionDays * DAY;
  const sessionIds = new Map();                       // access key -> session id
  const sessionTally = new Map();                     // session id -> { n, denied, last }
  const sessionFor = async (key, role, e, principalId) => {
    if (!key) return null;
    if (sessionIds.has(key)) return sessionIds.get(key);
    let id = (await c.query('SELECT id FROM track_sessions WHERE access_key_id=$1', [key])).rows[0]?.id;
    if (!id) id = (await c.query(
      `INSERT INTO track_sessions(account_id, role_id, access_key_id, principal_id, via, session_name, source_ip, user_agent, start_known, started_at)
       VALUES ($1,$2,$3,$4,'started before stored history',$5,$6,$7,false,$8)
       ON CONFLICT (access_key_id) DO UPDATE SET started_at=LEAST(track_sessions.started_at, EXCLUDED.started_at) RETURNING id`,
      [accountId, role.id, key, principalId, e.sessionName || null, e.ip, e.userAgent, e.time])).rows[0].id;
    sessionIds.set(key, id);
    return id;
  };
  const recordCall = async (sessionId, e, action, extra = {}) => {
    if (!sessionId) return;
    const r = await c.query(
      `INSERT INTO track_calls(session_id, event_id, at, action, event_source, event_name, resources, denied, error_code, child_key_id)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) ON CONFLICT DO NOTHING`,
      [sessionId, e.id, e.time, action, e.eventSource || 'sts.amazonaws.com', e.eventName, extra.resources || e.resources || [], e.denied, e.errorCode, extra.childKey || null]);
    if (!r.rowCount) return;
    const t = sessionTally.get(sessionId) || { n: 0, denied: 0, last: e.time };
    t.n++; if (e.denied) t.denied++; if (e.time > t.last) t.last = e.time; sessionTally.set(sessionId, t);
  };

  const daily = new Map(), resources = new Map(), passed = new Map();

  /** An API call made with a role's credentials: counts as activity, and joins the session it belongs to. */
  const handleCall = async (role, e, { action = e.action, resources: res = e.resources, childKey = null } = {}) => {
    let principalId = null;
    if (e.accessKeyId) principalId = (await c.query('SELECT principal_id FROM role_sessions WHERE access_key_id=$1', [e.accessKeyId])).rows[0]?.principal_id ?? null;
    if (!principalId) principalId = await ensurePrincipal(role, { key: `session:${e.sessionName}`, kind: 'session', display: `session ${e.sessionName}` }, e, { via: 'unknown (started before the window)' });
    else await c.query('UPDATE principals SET last_seen=GREATEST(last_seen,$2), first_seen=LEAST(first_seen,$2) WHERE id=$1', [principalId, e.time]);
    if (e.time.getTime() >= keepFrom && e.accessKeyId) await recordCall(await sessionFor(e.accessKeyId, role, e, principalId), e, action, { resources: res, childKey });
    if (!action) return;                               // no IAM permission involved (console sign-in)
    const day = e.time.toISOString().slice(0, 10);
    const dk = `${role.id}|${principalId}|${action}|${day}`;
    const d = daily.get(dk) || { role: role.id, principal: principalId, action, day, ok: 0, err: 0, nores: 0 };
    e.denied ? d.err++ : d.ok++; daily.set(dk, d);
    if (!e.denied && !res.length) d.nores++;
    if (e.denied) return;                              // denied calls prove nothing was used
    for (const r of res) {
      const rk = `${role.id}|${action}|${r}`;
      const x = resources.get(rk) || { role: role.id, action, resource: r, last: e.time, n: 0 };
      x.n++; if (e.time > x.last) x.last = e.time; resources.set(rk, x);
    }
    for (const arn of e.passedRoles || []) {
      const svc = e.eventSource.replace(/\.amazonaws\.com$/, '');
      const pk = `${role.id}|${arn}|${svc}`;
      const x = passed.get(pk) || { role: role.id, arn, svc, last: e.time, n: 0 };
      x.n++; if (e.time > x.last) x.last = e.time; passed.set(pk, x);
    }
  };

  for (const e of evs) {
    if (e.type === 'assume') {
      // 1. role chaining: a role session in this account made the AssumeRole. That is a call of its own.
      const callerRole = e.callerRoleArn ? roles.byArn.get(e.callerRoleArn) : e.callerRoleName ? roles.byName.get(e.callerRoleName) : null;
      if (callerRole) {
        await handleCall(callerRole, { ...e, accessKeyId: e.callerKeyId, sessionName: e.callerSessionName, eventSource: 'sts.amazonaws.com', passedRoles: [] },
          { action: `sts:${e.eventName}`, resources: e.roleArn ? [e.roleArn] : [], childKey: e.denied ? null : e.accessKeyId });
      }
      // 2. the role being entered
      const role = roles.byArn.get(e.roleArn);
      if (!role || e.denied) continue;                 // a refused AssumeRole is not a use
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
      if (e.accessKeyId && e.time.getTime() >= keepFrom) {
        const sid = (await c.query(
          `INSERT INTO track_sessions(account_id, role_id, access_key_id, principal_id, parent_key_id, via, caller_type, caller_arn, session_name, source_ip, user_agent, mfa, source_identity, trust, start_known, started_at)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,true,$15)
           ON CONFLICT (access_key_id) DO UPDATE SET principal_id=EXCLUDED.principal_id, parent_key_id=EXCLUDED.parent_key_id, via=EXCLUDED.via,
             caller_type=EXCLUDED.caller_type, caller_arn=EXCLUDED.caller_arn, session_name=EXCLUDED.session_name, source_ip=EXCLUDED.source_ip,
             user_agent=EXCLUDED.user_agent, mfa=EXCLUDED.mfa, source_identity=EXCLUDED.source_identity, trust=EXCLUDED.trust, start_known=true,
             started_at=LEAST(track_sessions.started_at, EXCLUDED.started_at)
           RETURNING id`,
          [accountId, role.id, e.accessKeyId, id, e.caller?.type === 'AssumedRole' ? e.callerKeyId : null, viaAction, e.caller?.type || null, e.caller?.arn || null,
           e.sessionName, e.ip, e.userAgent, e.mfa ?? null, e.sourceIdentity || null, JSON.stringify(trust || null), e.time])).rows[0].id;
        sessionIds.set(e.accessKeyId, sid);
      }
      continue;
    }
    const role = roleOf(e, roles);
    if (!role) continue;
    await handleCall(role, e);
  }
  for (const [id, t] of sessionTally) await c.query(
    'UPDATE track_sessions SET calls=calls+$2, denied=denied+$3, last_call_at=GREATEST(COALESCE(last_call_at, $4), $4) WHERE id=$1', [id, t.n, t.denied, t.last]);
  for (const d of daily.values()) await c.query(
    `INSERT INTO activity_daily(role_id, principal_id, action, day, count, error_count, no_resource_count) VALUES ($1,$2,$3,$4,$5,$6,$7)
     ON CONFLICT (role_id, principal_id, action, day) DO UPDATE SET count=activity_daily.count+EXCLUDED.count, error_count=activity_daily.error_count+EXCLUDED.error_count,
       no_resource_count=activity_daily.no_resource_count+EXCLUDED.no_resource_count`,
    [d.role, d.principal, d.action, d.day, d.ok, d.err, d.nores]);
  for (const x of resources.values()) await c.query(
    `INSERT INTO activity_resources(role_id, action, resource, last_seen, count) VALUES ($1,$2,$3,$4,$5)
     ON CONFLICT (role_id, action, resource) DO UPDATE SET count=activity_resources.count+EXCLUDED.count, last_seen=GREATEST(activity_resources.last_seen, EXCLUDED.last_seen)`,
    [x.role, x.action, x.resource, x.last, x.n]);
  for (const x of passed.values()) await c.query(
    `INSERT INTO passrole_observed(role_id, passed_role_arn, service, last_seen, count) VALUES ($1,$2,$3,$4,$5)
     ON CONFLICT (role_id, passed_role_arn, service) DO UPDATE SET count=passrole_observed.count+EXCLUDED.count, last_seen=GREATEST(passrole_observed.last_seen, EXCLUDED.last_seen)`,
    [x.role, x.arn, x.svc, x.last, x.n]);
}
