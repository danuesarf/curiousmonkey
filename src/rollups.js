// Hourly rollups (migration 023): call_hourly and session_hours are written as calls arrive. This module counts the
// calls stored before they existed, says how far back each account is covered, and prunes them with the calls.
import crypto from 'node:crypto';
import { query, tx, pool } from './db.js';
import { config } from './config.js';

const DAY = 864e5;

/** call_hourly's key for one kind of call. The backfill works out the same value in SQL. */
export function rollupKey(action, source, name, error, denied) {
  const x = crypto.createHash('md5').update([action, source, name, error, denied ? 'true' : 'false'].join('\u001f')).digest('hex');   // nosemgrep -- a short row key, not security
  return `${x.slice(0, 8)}-${x.slice(8, 12)}-${x.slice(12, 16)}-${x.slice(16, 20)}-${x.slice(20)}`;
}
// Old worker pods may still be writing uncounted calls for a moment after the migration; wait them out.
const SETTLE_MS = Number(process.env.ROLLUP_SETTLE_MS ?? 10 * 60e3);

/** Count one account-day of older calls into the rollups, and move the account's coverage back to that day. */
async function backfillDay(accountId, day) {
  const next = new Date(day.getTime() + DAY);
  return tx(async (c) => {
    await c.query(`SET LOCAL statement_timeout = 0`);
    // Sessions that can have calls on this day started at most 36 hours before it (the longest STS credentials).
    const r = await c.query(
      `WITH c AS (
         SELECT s.role_id, s.id AS sid, date_trunc('hour', c.at) AS h, COALESCE(c.action, '') AS a, c.event_source AS src, c.event_name AS nm, COALESCE(c.error_code, '') AS e, c.denied AS d
           FROM track_sessions s JOIN track_calls c ON c.session_id = s.id
          WHERE s.account_id = $1 AND s.started_at >= $2::timestamptz - interval '36 hours' AND s.started_at < $3
            AND c.at >= $2 AND c.at < $3 AND c.rolled IS NULL),
       kinds AS (
         INSERT INTO call_kinds(k, action, event_source, event_name, error_code, denied)
         SELECT DISTINCT md5(a || chr(31) || src || chr(31) || nm || chr(31) || e || chr(31) || d::text)::uuid, a, src, nm, e, d FROM c ORDER BY 1
         ON CONFLICT DO NOTHING),
       agg AS (
         INSERT INTO call_hourly(account_id, hour, role_id, k, denied, n)
         SELECT $1, h, role_id, md5(a || chr(31) || src || chr(31) || nm || chr(31) || e || chr(31) || d::text)::uuid, d, count(*)
           FROM c GROUP BY 2, 3, 4, 5 ORDER BY 2, 3, 4
         ON CONFLICT (account_id, hour, role_id, k) DO UPDATE SET n = call_hourly.n + EXCLUDED.n)
       INSERT INTO session_hours(account_id, hour, role_id, session_id)
       SELECT DISTINCT $1::uuid, h, role_id, sid FROM c ORDER BY 2, 3, 4 ON CONFLICT DO NOTHING`, [accountId, day, next]);
    const oldest = (await c.query(`SELECT min(started_at) AS t FROM track_sessions WHERE account_id=$1`, [accountId])).rows[0].t;
    const done = !oldest || day.getTime() <= new Date(oldest).getTime();
    // coverage only moves if it was this day's turn: a second worker doing the same day rolls back on the conflict below
    const moved = await c.query(`UPDATE rollup_backfill SET covered_from=$2, done=$3 WHERE account_id=$1 AND covered_from=$4 AND NOT done`, [accountId, day, done, next]);
    if (!moved.rowCount) throw Object.assign(new Error('another worker took this day'), { code: 'ROLLUP_RACE' });
    return { sessionHours: r.rowCount, done };
  });
}

/**
 * Work through accounts not yet covered, newest day first and the account furthest behind first, for up to
 * `budgetMs`. One worker at a time (advisory lock). Returns how many account-days were counted.
 */
export async function rollupBackfillTick({ budgetMs = 20_000, settleMs = SETTLE_MS, log = () => {} } = {}) {
  const client = await pool.connect();
  let days = 0;
  try {
    if (!(await client.query('SELECT pg_try_advisory_lock(727004) AS ok')).rows[0].ok) return 0;
    try {
      const until = Date.now() + budgetMs;
      while (Date.now() < until) {
        const row = (await client.query(
          `SELECT account_id, covered_from FROM rollup_backfill WHERE NOT done AND queued_at < now() - make_interval(secs => $1)
            ORDER BY covered_from DESC LIMIT 1`, [settleMs / 1000])).rows[0];
        if (!row) break;
        const day = new Date(new Date(row.covered_from).getTime() - DAY);
        try {
          const r = await backfillDay(row.account_id, day);
          days++;
          if (r.done) log('info', 'rollups cover all stored calls', { account: row.account_id });
        } catch (e) { if (e.code !== 'ROLLUP_RACE') throw e; }
      }
    } finally { await client.query('SELECT pg_advisory_unlock(727004)'); }
  } finally { client.release(); }
  return days;
}

/**
 * From when the rollups can be trusted for these accounts: the latest covered_from among those still being
 * backfilled, as ms; 0 when all of them are fully covered. Cached briefly: it only ever moves back.
 */
let cov = { at: 0, rows: [] };
export async function coveredFrom(accountIds) {
  if (Date.now() - cov.at > 15_000) cov = { at: Date.now(), rows: (await query(`SELECT account_id, covered_from FROM rollup_backfill WHERE NOT done`)).rows };
  if (!cov.rows.length) return 0;
  const want = accountIds ? new Set(accountIds) : null;
  let t = 0;
  for (const r of cov.rows) if (!want || want.has(r.account_id)) t = Math.max(t, new Date(r.covered_from).getTime());
  return t;
}
export const forgetCoverage = () => { cov = { at: 0, rows: [] }; };

/** Backfill progress for the health page. */
export async function rollupStatus() {
  const r = (await query(`SELECT count(*) FILTER (WHERE NOT done)::int AS pending, count(*)::int AS total, max(covered_from) FILTER (WHERE NOT done) AS behind FROM rollup_backfill`)).rows[0];
  return { pending: r.pending, total: r.total, coveredFrom: r.behind };
}

/** Drop rollup hours older than the calls kept (sessions go by their last call, so allow two days past retention). */
export async function pruneRollups(accountId) {
  const keep = config.scanner.sessionRetentionDays + 2;
  await query(`DELETE FROM call_hourly WHERE account_id=$1 AND hour < now() - make_interval(days => $2)`, [accountId, keep]);
  await query(`DELETE FROM session_hours WHERE account_id=$1 AND hour < now() - make_interval(days => $2)`, [accountId, keep]);
}
