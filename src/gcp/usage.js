// Google Cloud role usage: read the audit logs of every project with the Logging API (entries.list), the same way the
// AWS side reads CloudTrail, and keep per-day counts of who checked which permission. Optional, per connection.
//
// Each project has a cursor per log (Admin Activity always; Data Access when turned on). A cursor reads forward from
// where it stopped (new entries) and backward down to the lookback (the backfill), one window at a time:
//   forward  [hi_time, min(hi_time + 1 day, now - lag))
//   backward [max(start of the day before lo_time, lookback start), lo_time)
// A window's counts and the cursor's move commit in one transaction, so a worker dying mid-window re-reads that
// window from its start and nothing is counted twice. Forward goes first, so recent activity is never held up by a
// long backfill. Cursors are leased, so any number of workers share the projects.
//
// Reads are free (the _Required bucket costs nothing to store or read) but limited by the Logging API read quota.
// A token bucket per connection in Postgres keeps every worker together under GCP usage reads per minute.
import { config } from '../config.js';
import { query, tx } from '../db.js';

const DAY = 864e5;
export const LAG_MS = 10 * 60e3;                // audit entries can land a few minutes late: never read the last 10
export const MAX_LOOKBACK_DAYS = 400;           // _Required keeps Admin Activity for 400 days
const LEASE_SEC = 300;
const TICK_BUDGET_MS = 90_000;                  // one claim reads windows for up to this long, then lets others go
const LOGS = { activity: 'cloudaudit.googleapis.com%2Factivity', data_access: 'cloudaudit.googleapis.com%2Fdata_access' };

export const dayStart = (t) => Math.floor(t / DAY) * DAY;
const iso = (t) => new Date(t).toISOString();

// ---------------------------------------------------------------- reading one entry
/** The IAM member a log entry's caller is, as IAM policies write it. */
export function callerOf(auth = {}) {
  const email = auth.principalEmail;
  if (email) return /\.gserviceaccount\.com$/.test(email) ? `serviceAccount:${email}` : `user:${email}`;
  return auth.principalSubject || null;          // a federated identity with no service account: principal://iam.googleapis.com/...
}

/** The permission checks in one entry: [{ member, permission, granted }]. Entries with no caller or checks yield none. */
export function checksOf(entry) {
  const p = entry?.protoPayload;
  const member = callerOf(p?.authenticationInfo);
  if (!member) return [];
  const out = [];
  for (const a of p.authorizationInfo || []) if (a?.permission) out.push({ member, permission: a.permission, granted: a.granted !== false });
  return out;
}

/** Add one page of entries to a window's counts, keyed by day, caller and permission. */
export function addEntries(agg, entries) {
  let checks = 0;
  for (const e of entries) {
    const t = Date.parse(e.timestamp || e.receiveTimestamp || '');
    if (!Number.isFinite(t)) continue;
    const day = iso(t).slice(0, 10);
    for (const c of checksOf(e)) {
      const k = `${day}\u0000${c.member}\u0000${c.permission}`;
      const v = agg.get(k) || agg.set(k, { count: 0, denied: 0 }).get(k);
      if (c.granted) v.count++; else v.denied++;
      checks++;
    }
  }
  return checks;
}

// ---------------------------------------------------------------- which window next
/** The next window for a cursor, or null when it is caught up both ways. */
export function nextWindow(cur, { now = Date.now(), lookbackDays }) {
  const until = now - LAG_MS;
  const hi = cur.hi_time ? new Date(cur.hi_time).getTime() : null;
  const lo = cur.lo_time ? new Date(cur.lo_time).getTime() : null;
  if (hi == null || lo == null) return { kind: 'start', at: Math.floor(until / 60e3) * 60e3 };
  if (until - hi >= 60e3) return { kind: 'forward', from: hi, to: Math.min(hi + DAY, until) };
  const floor = dayStart(now - Math.min(lookbackDays, MAX_LOOKBACK_DAYS) * DAY);
  if (lo > floor) return { kind: 'back', from: Math.max(floor, dayStart(lo - 1)), to: lo };
  return null;
}

/** How much of the lookback a cursor has read, 0 to 1. */
export function coverage(cur, { now = Date.now(), lookbackDays }) {
  if (!cur.lo_time || !cur.hi_time) return 0;
  const floor = dayStart(now - Math.min(lookbackDays, MAX_LOOKBACK_DAYS) * DAY), lo = new Date(cur.lo_time).getTime(), hi = new Date(cur.hi_time).getTime();
  return Math.max(0, Math.min(1, (hi - Math.max(lo, floor)) / Math.max(1, hi - floor)));
}

// ---------------------------------------------------------------- cursors follow the projects
/** Make sure every project of every usage-enabled connection has its cursors; drop cursors nothing reads any more. Data stays. */
export async function syncCursors(connectionId = null) {
  const only = connectionId ? 'AND c.id = $1' : '';
  const args = connectionId ? [connectionId] : [];
  await query(`INSERT INTO gcp_usage_projects(connection_id, project_id)
               SELECT p.connection_id, p.project_id FROM gcp_projects p JOIN gcp_connections c ON c.id = p.connection_id WHERE c.usage_enabled ${only}
               ON CONFLICT DO NOTHING`, args);
  await query(`INSERT INTO gcp_log_cursors(project_ref, log)
               SELECT u.id, l.log FROM gcp_usage_projects u JOIN gcp_connections c ON c.id = u.connection_id
                 JOIN gcp_projects p ON p.connection_id = u.connection_id AND p.project_id = u.project_id
                 CROSS JOIN (VALUES ('activity'), ('data_access')) l(log)
                WHERE c.usage_enabled AND (l.log = 'activity' OR c.usage_data_access) ${only}
               ON CONFLICT DO NOTHING`, args);
  // turned off, Data Access turned off, or a project gone from the scope
  await query(`DELETE FROM gcp_log_cursors k USING gcp_usage_projects u, gcp_connections c
                WHERE u.id = k.project_ref AND c.id = u.connection_id ${only}
                  AND (NOT c.usage_enabled OR (k.log = 'data_access' AND NOT c.usage_data_access)
                       OR NOT EXISTS (SELECT 1 FROM gcp_projects p WHERE p.connection_id = u.connection_id AND p.project_id = u.project_id))`, args);
}

// ---------------------------------------------------------------- the read budget
/** Take one read from the connection's bucket. Returns ms to wait when it is empty. */
export async function takeRead(connectionId, perMinute = config.gcp.usageReadsPerMinute) {
  const rate = perMinute / 60, cap = Math.max(1, Math.min(perMinute, 10));     // small bursts only
  const r = await query(`INSERT INTO gcp_read_budget(connection_id, tokens, at) VALUES ($1, $3 - 1, now())
    ON CONFLICT (connection_id) DO UPDATE SET
      tokens = LEAST($3, gcp_read_budget.tokens + EXTRACT(EPOCH FROM now() - gcp_read_budget.at) * $2) - 1, at = now()
      WHERE LEAST($3, gcp_read_budget.tokens + EXTRACT(EPOCH FROM now() - gcp_read_budget.at) * $2) >= 1
    RETURNING tokens`, [connectionId, rate, cap]);
  if (r.rowCount) return 0;
  const t = (await query('SELECT tokens FROM gcp_read_budget WHERE connection_id=$1', [connectionId])).rows[0]?.tokens ?? 0;
  return Math.ceil(((1 - t) / rate) * 1000) + 50;
}

// ---------------------------------------------------------------- one window
const filterFor = (projectId, log, from, to) => `logName="projects/${projectId}/logs/${LOGS[log]}" AND timestamp>="${iso(from)}" AND timestamp<"${iso(to)}"`;

/** Read one window, every page, into counts. `beforePage` waits for the budget and keeps the lease. */
export async function readWindow(gw, { projectId, log, from, to }, { beforePage = async () => {} } = {}) {
  const agg = new Map();
  let token = '', pages = 0, entries = 0, checks = 0;
  do {
    await beforePage(pages);
    const r = await gw.logEntries({ projectId, filter: filterFor(projectId, log, from, to), pageToken: token });
    const list = r.entries || [];
    entries += list.length; checks += addEntries(agg, list); pages++;
    token = r.nextPageToken || '';
  } while (token);
  return { agg, pages, entries, checks };
}

/** Write a window's counts and move the cursor, together. Counts the rows each project adds, for storage tracking. */
export async function commitWindow(cur, w, read) {
  return tx(async (c) => {
    // the cursor must still be ours: a lease that ran out may have gone to another worker
    const mine = await c.query(`SELECT 1 FROM gcp_log_cursors WHERE project_ref=$1 AND log=$2 AND lease_by=$3 AND lease_until > now() FOR UPDATE`, [cur.project_ref, cur.log, cur.lease_by]);
    if (!mine.rowCount) return { lost: true };
    let addedDaily = 0, addedSummary = 0;
    if (read.agg.size) {
      const rows = [...read.agg].map(([k, v]) => { const [day, member, permission] = k.split('\u0000'); return { day, member, permission, ...v }; });
      const members = [...new Set(rows.map((r) => r.member))], perms = [...new Set(rows.map((r) => r.permission))];
      await c.query(`INSERT INTO gcp_usage_members(member) SELECT unnest($1::text[]) ORDER BY 1 ON CONFLICT DO NOTHING`, [members]);
      await c.query(`INSERT INTO gcp_usage_perms(permission) SELECT unnest($1::text[]) ORDER BY 1 ON CONFLICT DO NOTHING`, [perms]);
      const mid = new Map((await c.query(`SELECT id, member FROM gcp_usage_members WHERE member = ANY($1)`, [members])).rows.map((r) => [r.member, r.id]));
      const pid = new Map((await c.query(`SELECT id, permission FROM gcp_usage_perms WHERE permission = ANY($1)`, [perms])).rows.map((r) => [r.permission, r.id]));
      for (let i = 0; i < rows.length; i += 5000) {
        const ch = rows.slice(i, i + 5000);
        const args = [cur.project_ref, ch.map((r) => r.day), ch.map((r) => mid.get(r.member)), ch.map((r) => pid.get(r.permission)), ch.map((r) => r.count), ch.map((r) => r.denied)];
        // xmax = 0 on a returned row means it was inserted, not updated: that is what the storage counters count
        addedDaily += (await c.query(`INSERT INTO gcp_activity_daily AS d (project_ref, day, member_id, perm_id, count, denied)
            SELECT $1::int, * FROM unnest($2::date[], $3::int[], $4::int[], $5::int[], $6::int[]) ORDER BY 1, 2, 3
            ON CONFLICT (project_ref, day, member_id, perm_id) DO UPDATE SET count = d.count + EXCLUDED.count, denied = d.denied + EXCLUDED.denied
            RETURNING (xmax = 0) AS ins`, args)).rows.filter((r) => r.ins).length;
        addedSummary += (await c.query(`INSERT INTO gcp_usage_summary AS s (project_ref, member_id, perm_id, first_day, last_day, count, denied)
            SELECT $1::int, m, p, min(d), max(d), sum(n), sum(x) FROM unnest($2::date[], $3::int[], $4::int[], $5::int[], $6::int[]) AS t(d, m, p, n, x) GROUP BY m, p ORDER BY m, p
            ON CONFLICT (project_ref, member_id, perm_id) DO UPDATE SET first_day = LEAST(s.first_day, EXCLUDED.first_day), last_day = GREATEST(s.last_day, EXCLUDED.last_day),
              count = s.count + EXCLUDED.count, denied = s.denied + EXCLUDED.denied
            RETURNING (xmax = 0) AS ins`, args)).rows.filter((r) => r.ins).length;
      }
      if (addedDaily || addedSummary) await c.query(`UPDATE gcp_usage_projects SET daily_rows = daily_rows + $2, summary_rows = summary_rows + $3 WHERE id=$1`, [cur.project_ref, addedDaily, addedSummary]);
    }
    const edge = w.kind === 'forward' ? 'hi_time' : 'lo_time', to = w.kind === 'forward' ? w.to : w.from;
    await c.query(`UPDATE gcp_log_cursors SET ${edge} = $3, entries_read = entries_read + $4, pages_read = pages_read + $5, windows_read = windows_read + 1,
                   errors_in_row = 0, last_error = NULL, updated_at = now(), lease_until = now() + make_interval(secs => $6) WHERE project_ref=$1 AND log=$2`,
    [cur.project_ref, cur.log, iso(to), read.entries, read.pages, LEASE_SEC]);
    return { addedDaily, addedSummary };
  });
}

// ---------------------------------------------------------------- the worker side
export async function claimCursor(workerId) {
  return (await query(`UPDATE gcp_log_cursors k SET lease_until = now() + make_interval(secs => $2), lease_by = $1
    FROM gcp_usage_projects u, gcp_connections c
    WHERE u.id = k.project_ref AND c.id = u.connection_id
      AND (k.project_ref, k.log) = (SELECT x.project_ref, x.log FROM gcp_log_cursors x
             JOIN gcp_usage_projects ux ON ux.id = x.project_ref JOIN gcp_connections cx ON cx.id = ux.connection_id
            WHERE x.run_after <= now() AND (x.lease_until IS NULL OR x.lease_until < now()) AND cx.usage_enabled
            ORDER BY x.run_after LIMIT 1 FOR UPDATE OF x SKIP LOCKED)
    RETURNING k.*, u.project_id, u.connection_id, c.usage_lookback_days AS lookback_days`, [workerId, LEASE_SEC])).rows[0] || null;
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const release = (cur, runAfterSec, err = null) => query(`UPDATE gcp_log_cursors SET lease_until = NULL, lease_by = NULL, run_after = now() + make_interval(secs => $3),
    last_error = COALESCE($4, last_error), error_at = CASE WHEN $4 IS NULL THEN error_at ELSE now() END, errors_in_row = CASE WHEN $4 IS NULL THEN errors_in_row ELSE errors_in_row + 1 END, updated_at = now()
  WHERE project_ref=$1 AND log=$2 AND lease_by=$5`, [cur.project_ref, cur.log, runAfterSec, err, cur.lease_by]);

/**
 * Claim one due cursor and read windows for up to TICK_BUDGET_MS. Returns what happened, or null when nothing is due.
 * `gwFor(connection)` gives the gateway; `analyze(connectionId)` runs when a cursor catches up or every few minutes.
 */
export async function usageTick(workerId, { gwFor, analyze = async () => {}, now = () => Date.now(), budgetMs = TICK_BUDGET_MS, log = () => {} } = {}) {
  const cur = await claimCursor(workerId);
  if (!cur) return null;
  const conn = (await query('SELECT * FROM gcp_connections WHERE id=$1', [cur.connection_id])).rows[0];
  const gw = gwFor(conn);
  const started = now(), out = { project: cur.project_id, log: cur.log, windows: 0, entries: 0, added: 0 };
  const tail = Math.max(5, Number(config.scanner.tailEveryMinutes) || 30) * 60;
  try {
    for (;;) {
      const w = nextWindow(cur, { now: now(), lookbackDays: cur.lookback_days });
      if (!w) { await release(cur, tail); out.caughtUp = true; break; }
      if (w.kind === 'start') {
        await query(`UPDATE gcp_log_cursors SET hi_time = $3, lo_time = $3, updated_at = now() WHERE project_ref=$1 AND log=$2 AND lease_by=$4`, [cur.project_ref, cur.log, iso(w.at), cur.lease_by]);
        cur.hi_time = cur.lo_time = iso(w.at);
        continue;
      }
      if (now() - started > budgetMs) { await release(cur, 0); break; }      // more to read: due again at once, behind other projects
      const read = await readWindow(gw, { projectId: cur.project_id, log: cur.log, from: w.from, to: w.to }, {
        beforePage: async () => {
          for (let wait; (wait = await takeRead(conn.id)) > 0;) await sleep(Math.min(wait, 5000));
          await query(`UPDATE gcp_log_cursors SET lease_until = now() + make_interval(secs => $3) WHERE project_ref=$1 AND log=$2`, [cur.project_ref, cur.log, LEASE_SEC]);
        },
      });
      const r = await commitWindow(cur, w, read);
      if (r.lost) { out.lost = true; return out; }
      if (w.kind === 'forward') cur.hi_time = iso(w.to); else cur.lo_time = iso(w.from);
      out.windows++; out.entries += read.entries; out.added += r.addedDaily;
    }
  } catch (e) {
    const status = e.status;
    // over quota: wait a minute, not an error; refused or not found: the permission is missing, try hourly; else back off
    const wait = status === 429 ? 60 : status === 403 || status === 404 ? 3600 : Math.min(3600, 60 * 2 ** Math.min(6, Number(cur.errors_in_row) || 0));
    const msg = status === 403 ? `${e.message} (the reader needs logging.logEntries.list${cur.log === 'data_access' ? ' and logging.privateLogEntries.list' : ''} on this project)` : String(e.message || e);
    await release(cur, wait, status === 429 ? null : msg.slice(0, 600));
    out.error = msg; out.status = status;
    log(`gcp usage read ${cur.project_id}/${cur.log} failed: ${msg}`);
  }
  // fresh results: when a cursor catches up, and otherwise at most every 10 minutes while the backfill runs
  const stale = !conn.usage_analyzed_at || Date.now() - new Date(conn.usage_analyzed_at).getTime() > 10 * 60e3;
  if (out.windows && (out.caughtUp || stale)) await analyze(conn.id).catch((e) => log(`gcp usage analysis failed: ${e.message}`));
  return out;
}

// ---------------------------------------------------------------- storage
/**
 * Database space each project's usage data takes. Rows are counted as they are written; bytes come from each table's
 * measured size (heap, indexes and TOAST) divided by its rows, so the per-project split always adds up to the tables.
 * Cheap: two size lookups and one small table, never a scan of the activity rows.
 */
export async function usageStorage({ connectionId = null, save = false } = {}) {
  const [sizes, rows] = await Promise.all([
    query(`SELECT pg_total_relation_size('gcp_activity_daily')::bigint AS daily, pg_total_relation_size('gcp_usage_summary')::bigint AS summary,
                  (SELECT COALESCE(sum(daily_rows), 0) FROM gcp_usage_projects)::bigint AS daily_rows, (SELECT COALESCE(sum(summary_rows), 0) FROM gcp_usage_projects)::bigint AS summary_rows`),
    query(`SELECT u.id, u.connection_id, u.project_id, u.daily_rows, u.summary_rows, c.name AS connection_name
             FROM gcp_usage_projects u JOIN gcp_connections c ON c.id = u.connection_id ${connectionId ? 'WHERE u.connection_id = $1' : ''} ORDER BY u.daily_rows DESC`, connectionId ? [connectionId] : []),
  ]);
  const s = sizes.rows[0];
  const perDaily = s.daily_rows ? s.daily / s.daily_rows : 0, perSummary = s.summary_rows ? s.summary / s.summary_rows : 0;
  const items = rows.rows.map((r) => ({ ref: r.id, connection: r.connection_id, connectionName: r.connection_name, projectId: r.project_id, dailyRows: r.daily_rows, summaryRows: r.summary_rows,
    bytes: Math.round(r.daily_rows * perDaily + r.summary_rows * perSummary) }));
  if (save && items.length) {
    await query(`UPDATE gcp_usage_projects u SET bytes_est = x.b, bytes_at = now() FROM unnest($1::int[], $2::bigint[]) AS x(id, b) WHERE u.id = x.id`, [items.map((i) => i.ref), items.map((i) => i.bytes)]);
  }
  return { items, tables: { daily: s.daily, summary: s.summary }, bytesPerRow: { daily: Math.round(perDaily), summary: Math.round(perSummary) }, total: s.daily + s.summary };
}

/** Exact row counts for one project, to correct the counters if anything ever deleted rows behind their back. */
export async function recountProject(ref) {
  const r = (await query(`SELECT (SELECT count(*) FROM gcp_activity_daily WHERE project_ref=$1)::bigint AS d, (SELECT count(*) FROM gcp_usage_summary WHERE project_ref=$1)::bigint AS s`, [ref])).rows[0];
  await query('UPDATE gcp_usage_projects SET daily_rows=$2, summary_rows=$3 WHERE id=$1', [ref, r.d, r.s]);
  return { daily: r.d, summary: r.s };
}
