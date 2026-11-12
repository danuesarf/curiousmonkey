// Reads an account's CloudTrail from its S3 trail, file by file.
//
// One reader per account covers every region that has log files (found in the bucket, not only the regions
// configured). Files from all regions are merged in delivery order, so an AssumeRole logged in one region
// (us-east-1 for the global STS endpoint, or IAM Identity Center) is applied before the calls its session makes
// elsewhere. Each region keeps a cursor: the last file read. A file is read exactly once, so nothing is lost to late
// delivery (a late record is in a later file) and nothing is read twice. The cursor moves in the same transaction
// as the counts.
//
// Downloads run ahead of the writer in parallel; how far ahead is bounded by file count and bytes, and a batch is
// written when it reaches a size, so memory stays flat whatever the account's volume.
import { pruneRollups } from '../rollups.js';
import { config } from '../config.js';
import { pool, query, tx } from '../db.js';
import { loadContext } from './inventory.js';
import { provisionalAnalyze } from './analyzeJob.js';
import { accountComplete } from '../history.js';
import { effectiveLookback } from '../settings.js';
import { bump } from '../telemetry.js';
import { applyEvents } from './applyEvents.js';
import { coverage, saveCoverage } from './events.js';
import { fileTimeFromKey } from '../aws/trailKeys.js';
import { decodeTrailFile } from './decode.js';

const MIN = 60e3, HOUR = 60 * MIN, DAY = 24 * HOUR;
export const SETTLE = 10 * MIN;          // files of the last few minutes may still be arriving
const FLOOR_WINDOW = HOUR;               // the per-slice reader read files up to 1 h past its last slice
const LOOKAHEAD = 15 * MIN;              // AssumeRoles this far past a batch are applied with it
const RECENT = 3 * DAY;                  // events newer than this are de-duplicated in the database
const T = (x) => (x == null ? null : new Date(x).getTime());

export const trailLimits = () => ({
  parallel: Math.max(1, Number(process.env.TRAIL_DOWNLOADS || 16)),
  aheadFiles: Math.max(4, Number(process.env.TRAIL_AHEAD_FILES || 96)),
  aheadBytes: Number(process.env.TRAIL_AHEAD_MB || 192) * 1024 * 1024,
  batchEvents: Math.max(1000, Number(process.env.TRAIL_BATCH_EVENTS || 50000)),
  batchFiles: Math.max(1, Number(process.env.TRAIL_BATCH_FILES || 400)),
});

/** Job handler: one reader per account at a time (a second job for the same account steps aside). */
export async function runTrailEvents(ctx) {
  const { account, gw } = await loadContext(ctx.job.account_id);
  const lock = await pool.connect();
  try {
    const ok = (await lock.query('SELECT pg_try_advisory_lock(727200, hashtext($1)) AS ok', [account.id])).rows[0].ok;
    if (!ok) { await ctx.log?.('another job is reading this account; nothing to do'); return { skipped: 'account already being read' }; }
    try { return await readTrail({ ctx, account, gw }); }
    finally { await lock.query('SELECT pg_advisory_unlock(727200, hashtext($1))', [account.id]).catch(() => {}); }
  } finally { lock.release(); }
}

/** The work itself; `gw` and `decode` are injectable for tests. */
export async function readTrail({ ctx, account, gw, decode = decodeTrailFile, now = Date.now(), limits = trailLimits() }) {
  const log = (m, d, l) => ctx.log?.(m, d, l);

  // ---- regions: every region the trail has files for ----
  let found = [];
  try { found = await gw.listTrailRegions(); } catch (e) { await log(`could not list the trail's regions (${e.name || e.message}); reading the configured ones`, null, 'warn'); }
  // regions someone removed on purpose stay out, even when the trail has files for them
  const excluded = new Set(account.excluded_regions || []);
  const skipped = found.filter((r) => excluded.has(r) && !account.regions.includes(r));
  if (skipped.length) await log(`skipping ${skipped.join(', ')}: removed from this account's regions`);
  const regions = [...new Set([...account.regions, ...found.filter((r) => !excluded.has(r))])].sort();
  const added = regions.filter((r) => !account.regions.includes(r));
  if (added.length) {
    await query('UPDATE cloud_accounts SET regions=$2 WHERE id=$1', [account.id, regions]);
    await log(`the trail has log files for ${added.join(', ')} too; reading ${added.length > 1 ? 'them' : 'it'} as well`);
    account.regions = regions;
  }

  const horizon = now - effectiveLookback(account) * DAY;
  const limit = now - SETTLE;
  const cur = await loadCursors(account, regions, horizon);
  for (const r of regions) if (cur.get(r).gap) await log(`${r}: stored history ended before the lookback window; continuing from ${new Date(horizon).toISOString().slice(0, 10)}`, null, 'warn');

  // ---- what to read: an older range first if the lookback was widened, then forward to the present ----
  const backRanges = regions.map((r) => cur.get(r)).filter((c) => c.backTo)
    .map((c) => ({ region: c.region, from: horizon, afterKey: c.backKey, to: T(c.backTo) }));
  const fwdRanges = regions.map((r) => cur.get(r))
    .map((c) => ({ region: c.region, from: c.lastKey ? fileTimeFromKey(c.lastKey) : T(c.afterTime) + 1, afterKey: c.lastKey, to: limit + 1 }));

  const wasComplete = await accountComplete(account.id);
  const roleRows = (await query(`SELECT arn, name, id, trust_policy FROM roles WHERE account_id=$1 AND deleted_at IS NULL`, [account.id])).rows;
  const roles = { byArn: new Map(roleRows.map((r) => [r.arn, r])), byName: new Map(roleRows.map((r) => [r.name, r])) };
  const st = { t0: Date.now(), events: 0, files: 0, bytes: 0, lastProvisional: Date.now(), preApplied: new Set(), oldSeen: new Set(), prevOldSeen: new Set() };

  if (backRanges.length) {
    await log(`reading older history for ${backRanges.map((r) => r.region).join(', ')} back to ${new Date(horizon).toISOString().slice(0, 10)}`);
    await readRanges({ ctx, account, gw, decode, roles, cur, ranges: backRanges, phase: 'backfill', wasComplete, st, limits, now, limit });
    await tx(async (c) => {
      for (const r of backRanges) {
        await c.query(`UPDATE trail_cursors SET lo_time=to_timestamp($3/1000.0), back_to=NULL, back_key=NULL, updated_at=now() WHERE account_id=$1 AND region=$2`, [account.id, r.region, horizon]);
        await c.query(`UPDATE scan_checkpoints SET first_event_time=LEAST(first_event_time, to_timestamp($3/1000.0)) WHERE account_id=$1 AND region=$2`, [account.id, r.region, horizon]);
      }
    });
  }
  await readRanges({ ctx, account, gw, decode, roles, cur, ranges: fwdRanges, phase: 'forward', wasComplete, st, limits, now, limit });

  // reached the present in every region: regions with no new files are read up to the limit too
  await tx(async (c) => {
    for (const r of regions) {
      const k = cur.get(r);
      if (!k.lastKey) await c.query(`UPDATE trail_cursors SET after_time=GREATEST(after_time, to_timestamp($3/1000.0)), updated_at=now() WHERE account_id=$1 AND region=$2`, [account.id, r, limit]);
      await c.query(
        `INSERT INTO scan_checkpoints(account_id, region, source, first_event_time, last_event_time, events_read, gap_detected, last_run_at, caught_up_at)
         VALUES ($1,$2,'s3',to_timestamp($3/1000.0),to_timestamp($4/1000.0),0,$5,now(),now())
         ON CONFLICT (account_id, region) DO UPDATE SET source='s3', last_event_time=GREATEST(scan_checkpoints.last_event_time, EXCLUDED.last_event_time),
           first_event_time=LEAST(COALESCE(scan_checkpoints.first_event_time, EXCLUDED.first_event_time), EXCLUDED.first_event_time),
           gap_detected=scan_checkpoints.gap_detected OR EXCLUDED.gap_detected, last_run_at=now(), caught_up_at=now()`,
        [account.id, r, T(k.loTime), limit, k.gap]);
    }
  });
  await query(`DELETE FROM seen_events WHERE seen_at < now() - interval '3 days'`);
  await query(`DELETE FROM role_sessions WHERE seen_at < now() - interval '2 days' AND started_at < now() - interval '2 days'`);
  await query(`DELETE FROM track_sessions WHERE account_id=$1 AND COALESCE(last_call_at, started_at) < now() - make_interval(days => $2)`, [account.id, config.scanner.sessionRetentionDays]);
  await pruneRollups(account.id);
  return { regions: regions.length, files: st.files, events: st.events, bytes: st.bytes };
}

// ---- cursors ----
async function loadCursors(account, regions, horizon) {
  const rows = new Map((await query(`SELECT * FROM trail_cursors WHERE account_id=$1`, [account.id])).rows.map((r) => [r.region, r]));
  const cps = new Map((await query(`SELECT * FROM scan_checkpoints WHERE account_id=$1`, [account.id])).rows.map((r) => [r.region, r]));
  const out = new Map();
  for (const region of regions) {
    let c = rows.get(region);
    if (!c) {
      const cp = cps.get(region);
      c = cp && cp.last_event_time
        // read before by the per-slice reader: files delivered after its last slice, minus what it already counted
        ? { last_key: null, after_time: new Date(T(cp.last_event_time) - 1), lo_time: cp.first_event_time || cp.last_event_time, floor_time: cp.last_event_time, back_to: null, back_key: null }
        : { last_key: null, after_time: new Date(horizon - 1), lo_time: new Date(horizon), floor_time: null, back_to: null, back_key: null };
      await query(`INSERT INTO trail_cursors(account_id, region, last_key, after_time, lo_time, floor_time) VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT DO NOTHING`,
        [account.id, region, c.last_key, c.after_time, c.lo_time, c.floor_time]);
    }
    const k = { region, lastKey: c.last_key, afterTime: c.after_time, loTime: c.lo_time, floorTime: c.floor_time, backTo: c.back_to, backKey: c.back_key, gap: false };
    const pos = k.lastKey ? fileTimeFromKey(k.lastKey) : T(k.afterTime);
    if (pos < horizon) {                                // the worker was off longer than the lookback (or the bucket expired files)
      k.gap = true; k.lastKey = null; k.afterTime = new Date(horizon - 1); k.loTime = new Date(horizon); k.backTo = null; k.backKey = null; k.floorTime = null;
      await query(`UPDATE trail_cursors SET last_key=NULL, after_time=$3, lo_time=$4, back_to=NULL, back_key=NULL, floor_time=NULL WHERE account_id=$1 AND region=$2`, [account.id, region, k.afterTime, k.loTime]);
    } else if (!k.backTo && T(k.loTime) - horizon > DAY) {   // lookback widened: read the older days first
      k.backTo = k.loTime; k.backKey = null;
      await query(`UPDATE trail_cursors SET back_to=$3, back_key=NULL WHERE account_id=$1 AND region=$2`, [account.id, region, k.backTo]);
    }
    out.set(region, k);
  }
  return out;
}

// ---- listing: files of every region in the ranges, merged in delivery order, a day at a time ----
function* daysBetween(from, to) { for (let d = Math.floor(from / DAY) * DAY; d < to; d += DAY) yield d; }
async function listDay(gw, ranges, day, parallel) {
  const active = ranges.filter((r) => r.from < day + DAY && r.to > day);
  const lists = await mapLimit(active, Math.min(parallel, 8), async (r) => (await gw.listTrailDay({ region: r.region, day: new Date(day) }))
    .filter((f) => f.time >= r.from && f.time < r.to && (!r.afterKey || f.key > r.afterKey)).map((f) => ({ ...f, region: r.region })));
  return lists.flat().sort((x, y) => x.time - y.time || (x.region < y.region ? -1 : x.region > y.region ? 1 : x.key < y.key ? -1 : 1));
}

async function readRanges({ ctx, account, gw, decode, roles, cur, ranges, phase, wasComplete, st, limits, now, limit }) {
  if (!ranges.length) return;
  const from = Math.min(...ranges.map((r) => r.from)), to = Math.min(Math.max(...ranges.map((r) => r.to)), limit + 1);
  const days = [...daysBetween(from, to)];
  const queue = [];                                     // { file, p, bytes } in delivery order
  let head = 0, started = 0, inFlight = 0, aheadBytes = 0, dayIdx = 0, listing = null;
  const listNext = () => { const d = days[dayIdx++]; const p = listDay(gw, ranges, d, limits.parallel); p.catch(() => {}); return p; };
  const pump = () => {
    while (started < queue.length && inFlight < limits.parallel && started - head < limits.aheadFiles && (aheadBytes < limits.aheadBytes || started === head)) {
      const it = queue[started++];
      inFlight++; aheadBytes += it.file.size;
      it.p = (async () => {
        const evs = await decode(await gw.getTrailFile(it.file.key), it.file.region);
        for (const e of evs) { e.fileRegion = it.file.region; e.fileTime = it.file.time; }
        return evs;
      })();
      it.p.catch(() => {}).finally(() => { inFlight--; pump(); });
    }
  };
  // keep listing ahead of the downloads, and the next day's listing running while this one downloads
  const fill = async () => {
    while (queue.length - head < limits.aheadFiles) {
      if (!listing) { if (dayIdx >= days.length) break; listing = listNext(); }
      const files = await listing; listing = null;
      for (const f of files) queue.push({ file: f, p: null });
      pump();
    }
    if (!listing && dayIdx < days.length) listing = listNext();
  };

  let batch = { files: [], events: [] };
  const flush = async (final) => {
    if (!batch.files.length) return;
    // AssumeRoles delivered just after the batch: apply them now, so the calls in this batch know who started them
    const last = batch.files[batch.files.length - 1].time;
    const extra = [];
    for (let i = head; i < queue.length && queue[i].file.time <= last + LOOKAHEAD; i++) {
      if (!queue[i].p) { pump(); if (!queue[i].p) break; }
      let evs; try { evs = await queue[i].p; } catch { break; }
      for (const e of evs) if (e.type === 'assume' && !st.preApplied.has(e.id)) { extra.push(e); }
    }
    await writeBatch({ ctx, account, roles, cur, phase, wasComplete, st, batch, extra, now });
    batch = { files: [], events: [] };
    ctx.alive?.();
    await progress(ctx, st, phase, ranges, days, final, cur);
    if (Date.now() - st.lastProvisional > config.scanner.provisionalEveryMs && !final) {
      st.lastProvisional = Date.now();
      await provisionalAnalyze(account.id, (m) => ctx.log?.(m)).catch((e) => ctx.log?.(`provisional analysis skipped: ${e.message}`, null, 'warn'));
    }
  };

  await fill();
  while (head < queue.length) {
    pump();
    const it = queue[head];
    const evs = await it.p;
    queue[head] = null; head++; aheadBytes -= it.file.size;
    if (head > 4096) { queue.splice(0, head); started -= head; head = 0; }
    batch.files.push(it.file);
    for (const e of evs) batch.events.push(e);
    st.files++; st.bytes += it.file.size;
    st.dayDone = Math.floor((Math.floor(it.file.time / DAY) * DAY - days[0]) / DAY);
    if (batch.events.length >= limits.batchEvents || batch.files.length >= limits.batchFiles) await flush(false);
    await fill();
  }
  await flush(true);
}

// ---- one batch: dedupe, coverage, counts and cursors in one transaction ----
async function writeBatch({ account, roles, cur, phase, wasComplete, st, batch, extra, now }) {
  const recentFrom = now - RECENT;
  // events counted by the per-slice reader before this account moved over
  const kept = [];
  for (const e of batch.events) {
    const k = cur.get(e.fileRegion);
    if (k?.floorTime && e.fileTime < T(k.floorTime) + FLOOR_WINDOW && e.time < k.floorTime) continue;
    if (st.preApplied.has(e.id)) { st.preApplied.delete(e.id); continue; }   // applied early with the batch before
    kept.push(e);
  }
  for (const e of extra) {
    const k = cur.get(e.fileRegion);
    if (k?.floorTime && e.fileTime < T(k.floorTime) + FLOOR_WINDOW && e.time < k.floorTime) continue;
    st.preApplied.add(e.id); kept.push(e);
  }

  await tx(async (c) => {
    await c.query('SELECT pg_advisory_xact_lock(727100, hashtext($1))', [account.id]);
    // duplicates: rare, and delivered close together. Recent events are checked against the database (they can
    // straddle two scans); older ones against the events of this batch and the one before.
    const withId = kept.filter((e) => e.id);
    const recent = withId.filter((e) => e.time.getTime() >= recentFrom);
    const fresh = new Set();
    if (recent.length) {
      const ids = [...new Set(recent.map((e) => e.id))];
      for (let i = 0; i < ids.length; i += 20000) {
        const r = await c.query(`INSERT INTO seen_events(account_id, event_id, event_time) SELECT $2, x, now() FROM unnest($1::text[]) x ON CONFLICT DO NOTHING RETURNING event_id`, [ids.slice(i, i + 20000), account.id]);
        for (const x of r.rows) fresh.add(x.event_id);
      }
    }
    const evs = [];
    const seenNow = new Set();
    for (const e of withId) {
      if (seenNow.has(e.id)) continue;
      seenNow.add(e.id);
      if (e.time.getTime() >= recentFrom) { if (fresh.has(e.id)) evs.push(e); }
      else if (!st.oldSeen.has(e.id) && !st.prevOldSeen.has(e.id)) { st.oldSeen.add(e.id); evs.push(e); }
    }
    // coverage by region and day
    const groups = new Map();
    for (const e of evs) {
      const g = `${e.fileRegion}|${e.time.toISOString().slice(0, 10)}`;
      if (!groups.has(g)) groups.set(g, []);
      groups.get(g).push(e);
    }
    for (const [g, list] of groups) { const [region, day] = g.split('|'); await saveCoverage(c, account.id, region, new Date(`${day}T00:00:00Z`), coverage(list, roles)); }
    const usable = evs.filter((e) => e.type !== 'ignore').sort((x, y) => (x.type === y.type ? x.time - y.time : x.type === 'assume' ? -1 : 1));
    await applyEvents(c, usable, roles, account.id, { recordNew: wasComplete && phase === 'forward' });

    // cursors and history checkpoints, per region
    const per = new Map();
    for (const f of batch.files) { const p = per.get(f.region) || { last: null, files: 0, bytes: 0, events: 0 }; p.last = f; p.files++; p.bytes += f.size; per.set(f.region, p); }
    for (const e of usable) { const p = per.get(e.fileRegion); if (p) p.events++; }
    for (const [region, p] of per) {
      const k = cur.get(region);
      if (phase === 'backfill') {
        k.backKey = p.last.key;
        await c.query(`UPDATE trail_cursors SET back_key=$3, files_read=files_read+$4, bytes_read=bytes_read+$5, updated_at=now() WHERE account_id=$1 AND region=$2`, [account.id, region, p.last.key, p.files, p.bytes]);
      } else {
        k.lastKey = p.last.key;
        if (k.floorTime && p.last.time >= T(k.floorTime) + FLOOR_WINDOW) k.floorTime = null;
        await c.query(`UPDATE trail_cursors SET last_key=$3, floor_time=$4, files_read=files_read+$5, bytes_read=bytes_read+$6, updated_at=now() WHERE account_id=$1 AND region=$2`,
          [account.id, region, p.last.key, k.floorTime, p.files, p.bytes]);
      }
      await c.query(
        `INSERT INTO scan_checkpoints(account_id, region, source, first_event_time, last_event_time, events_read, gap_detected, last_run_at)
         VALUES ($1,$2,'s3',to_timestamp($3/1000.0),to_timestamp($4/1000.0),$5,$6,now())
         ON CONFLICT (account_id, region) DO UPDATE SET source='s3',
           last_event_time=CASE WHEN $7 THEN GREATEST(scan_checkpoints.last_event_time, EXCLUDED.last_event_time) ELSE scan_checkpoints.last_event_time END,
           first_event_time=LEAST(COALESCE(scan_checkpoints.first_event_time, EXCLUDED.first_event_time), EXCLUDED.first_event_time),
           events_read=scan_checkpoints.events_read+EXCLUDED.events_read, gap_detected=scan_checkpoints.gap_detected OR EXCLUDED.gap_detected, last_run_at=now()`,
        [account.id, region, T(k.loTime), p.last.time, p.events, k.gap, phase === 'forward']);
    }
    st.events += usable.length; bump('events', usable.length);
  });
  st.prevOldSeen = st.oldSeen; st.oldSeen = new Set();
}

async function progress(ctx, st, phase, ranges, days, final, cur) {
  const elapsed = (Date.now() - st.t0) / 1000;
  const done = final ? days.length : Math.min(days.length - 1, Math.max(0, st.dayDone || 0));
  const rate = elapsed > 0 && done > 0 ? elapsed / done : null;
  const lastTimes = ranges.map((r) => { const k = cur.get(r.region); const key = phase === 'backfill' ? k.backKey : k.lastKey; return key ? fileTimeFromKey(key) : null; }).filter(Boolean);
  await ctx.progress?.({
    phase: 'events', source: 's3', unit: 'day', region: '*', regions: ranges.length, direction: phase,
    slice: lastTimes.length ? new Date(Math.min(...lastTimes)).toISOString() : null, at: new Date().toISOString(),
    done, total: days.length, events: st.events, files: st.files, mb: Math.round(st.bytes / 1048576),
    elapsedSeconds: Math.round(elapsed), etaSeconds: final ? 0 : Math.round(rate != null ? rate * (days.length - done) : 0),
    eventsPerSecond: elapsed > 0 ? Math.round(st.events / elapsed) : null,
  });
}

async function mapLimit(items, n, fn) {
  const out = new Array(items.length); let i = 0;
  await Promise.all(Array.from({ length: Math.min(n, items.length) }, async () => { while (i < items.length) { const k = i++; out[k] = await fn(items[k]); } }));
  return out;
}
