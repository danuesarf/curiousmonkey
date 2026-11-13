import { pruneRollups } from '../rollups.js';
import { config } from '../config.js';
import { query, tx } from '../db.js';
import { parseEvent } from '../analyzer/events.js';
import { applyEvents, roleOf } from './applyEvents.js';
export { applyEvents, roleOf };
import { loadContext } from './inventory.js';
import { provisionalAnalyze } from './analyzeJob.js';
import { accountComplete } from '../history.js';
import { effectiveLookback } from '../settings.js';
import { bump } from '../telemetry.js';


const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const HOUR = 3600e3, MIN = 60e3, DAY = 24 * HOUR;

/** Days of history to keep reading. Event History stops at 90; an S3 trail goes as far back as its files. */
export const lookbackFor = (account) => effectiveLookback(account);

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
  // Slice size: the operator's choice for this job, else the default. If the last attempt's worker died
  // mid-run (usually out of memory on a busy slice), halve it so the same slice cannot kill the next one too.
  let hours = Number(ctx.job.options?.sliceHours) || s.sliceHours;
  if (ctx.job.attempts > 1 && /lease expired/.test(ctx.job.last_error || '') && hours > 0.25) {
    hours = Math.max(0.25, hours / 2);
    await query(`UPDATE scan_jobs SET options = options || jsonb_build_object('sliceHours', $2::numeric) WHERE id=$1`, [ctx.job.id, hours]);
    await ctx.log?.(`the last attempt's worker was lost; reading in smaller ${hours} h slices`, null, 'warn');
  }
  const step = hours * HOUR;

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

  const roleRows = (await query(`SELECT arn, name, id, kind, trust_policy FROM roles WHERE account_id=$1 AND deleted_at IS NULL`, [account.id])).rows;
  // IAM users are found by ARN only: a user and a role may share a name
  const roles = { byArn: new Map(roleRows.map((r) => [r.arn, r])), byName: new Map(roleRows.filter((r) => r.kind !== 'iam-user').map((r) => [r.name, r])) };
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
    // Records are parsed as they arrive, so a slice holds compact events rather than whole CloudTrail records
    // (a busy region's 6 hours can be 100k+ records). Never spread a big array into push: it overflows the stack.
    let parsed;
    if (src === 's3') parsed = await gw.trailEventsForSlice({ region, start: new Date(a), end: new Date(b), listCache, map: parseEvent });
    else {
      parsed = [];
      let token = null;
      do {
        const page = await gw.lookupEventsPage({ region, start: new Date(a), end: new Date(b), token });
        for (const e of page.events) parsed.push(parseEvent(e));
        token = page.nextToken;
        if (token && s.lookupDelayMs) await sleep(s.lookupDelayMs);             // LookupEvents: 2 requests/second
      } while (token);
    }

    const n = await tx(async (c) => {
      // Regions of one account fetch in parallel but write one at a time: they update the same roles' rows,
      // and two transactions taking those row locks in different orders deadlock.
      await c.query('SELECT pg_advisory_xact_lock(727100, hashtext($1))', [account.id]);
      const all = parsed.filter((e) => e.id);
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
    total += n; bump('events', n);
    // show what is known so far: refresh results every few minutes during a long first read
    if (Date.now() - lastProvisional > s.provisionalEveryMs && i < slices.length - 1) {
      lastProvisional = Date.now();
      await provisionalAnalyze(account.id, (m) => ctx.log?.(m)).catch((e) => ctx.log?.(`provisional analysis skipped: ${e.message}`, null, 'warn'));
    }
    const took = (Date.now() - sliceStart) / 1000;
    rate = rate == null ? took : rate * 0.8 + took * 0.2;      // recent slices count more; busy and quiet days differ
    const elapsed = (Date.now() - t0) / 1000;
    await ctx.progress({ phase: 'events', source: src, region, slice: new Date(kind === 'backfill' ? a : b).toISOString(), direction: kind, sliceHours: hours, at: new Date().toISOString(),
      done: i + 1, total: slices.length, events: total, elapsedSeconds: Math.round(elapsed),
      etaSeconds: Math.round(rate * (slices.length - i - 1)), eventsPerSecond: elapsed > 0 ? Math.round(total / elapsed) : null });
  }
  await query('UPDATE scan_checkpoints SET caught_up_at=now() WHERE account_id=$1 AND region=$2', [account.id, region]);   // reached the present
  // Pruned by when they were written, not by event time: another region may still be reading old history that needs them.
  await query(`DELETE FROM seen_events WHERE seen_at < now() - interval '3 days'`);
  await query(`DELETE FROM role_sessions WHERE seen_at < now() - interval '2 days' AND started_at < now() - interval '2 days'`);   // credentials last at most 12h
  await query(`DELETE FROM track_sessions WHERE account_id=$1 AND COALESCE(last_call_at, started_at) < now() - make_interval(days => $2)`, [account.id, config.scanner.sessionRetentionDays]);
  await pruneRollups(account.id);
  return { slices: slices.length, events: total, gap };
}

/** Count what happens to every event, so nothing is dropped without a trace. */
export function coverage(evs, roles) {
  const k = { events: evs.length, assume_events: 0, role_calls: 0, user_calls: 0, recovered_role: 0, other_role: 0, not_role: 0, no_permission: 0, unmapped: 0, no_resources: 0 };
  const unmapped = new Map();
  for (const e of evs) {
    if (e.type === 'ignore') { k.not_role++; continue; }
    const role = roleOf(e, roles);
    if (!role) { k.other_role++; continue; }
    if (e.type === 'assume') { k.assume_events++; continue; }
    if (e.userCall) k.user_calls++; else k.role_calls++;
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
export async function saveCoverage(c, accountId, region, day, { k, unmapped }) {
  const cols = Object.keys(k);
  await c.query(
    `INSERT INTO event_coverage(account_id, region, day, ${cols.join(',')}) VALUES ($1,$2,$3,${cols.map((_, i) => `$${i + 4}`).join(',')})
     ON CONFLICT (account_id, region, day) DO UPDATE SET ${cols.map((x) => `${x}=event_coverage.${x}+EXCLUDED.${x}`).join(', ')}`,
    [accountId, region, day.toISOString().slice(0, 10), ...Object.values(k)]);
  const U = [...unmapped.values()];
  if (U.length) await c.query(
    `INSERT INTO unmapped_events(account_id, raw_action, event_source, event_name, count, first_seen, last_seen, identity_type, param_keys)
     SELECT $1, r, s, n, c, f, l, it, ARRAY(SELECT jsonb_array_elements_text(pk::jsonb))
       FROM unnest($2::text[], $3::text[], $4::text[], $5::int[], $6::timestamptz[], $7::timestamptz[], $8::text[], $9::text[]) AS u(r, s, n, c, f, l, it, pk)
     ON CONFLICT (account_id, raw_action) DO UPDATE SET count=unmapped_events.count+EXCLUDED.count,
       first_seen=LEAST(unmapped_events.first_seen, EXCLUDED.first_seen), last_seen=GREATEST(unmapped_events.last_seen, EXCLUDED.last_seen),
       param_keys=(SELECT ARRAY(SELECT DISTINCT unnest(unmapped_events.param_keys || EXCLUDED.param_keys) LIMIT 30))`,
    [accountId, U.map((u) => u.raw), U.map((u) => u.source), U.map((u) => u.name), U.map((u) => u.n), U.map((u) => u.first), U.map((u) => u.last), U.map((u) => u.identity || null), U.map((u) => JSON.stringify(u.keys || []))]);
}

