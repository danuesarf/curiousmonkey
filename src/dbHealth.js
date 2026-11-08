// Database health: how big Postgres is, how fast it grows, how much disk is left under it, and whether it is keeping
// up (connections, cache, vacuum, long transactions, transaction ID wraparound).
//
// Postgres cannot see free disk space. With Docker Compose the app container mounts the database volume read-only at
// DB_DATA_PATH (/pgdata), and statfs on it gives the free space of the disk the database actually writes to.
// The app samples sizes once an hour into db_samples, so growth and "days until full" come from real history.
import fs from 'node:fs/promises';
import { query } from './db.js';
import { config } from './config.js';

const DAY = 864e5;
const num = (x) => Number(x || 0);

async function disk() {
  const path = process.env.DB_DATA_PATH || '';
  if (!path) return { known: false, path: null };
  try {
    const s = await fs.statfs(path);
    const total = s.blocks * s.bsize, free = s.bavail * s.bsize;
    return { known: true, path, total, free, used: total - free };
  } catch (e) { return { known: false, path, error: e.code || e.message }; }
}

async function tables() {
  return (await query(
    `SELECT c.relname AS name, pg_total_relation_size(c.oid)::bigint AS total, pg_relation_size(c.oid)::bigint AS heap,
            pg_indexes_size(c.oid)::bigint AS indexes, s.n_live_tup::bigint AS live, s.n_dead_tup::bigint AS dead,
            GREATEST(s.last_autovacuum, s.last_vacuum) AS vacuumed, GREATEST(s.last_autoanalyze, s.last_analyze) AS analyzed
       FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace LEFT JOIN pg_stat_user_tables s ON s.relid = c.oid
      WHERE c.relkind = 'r' AND n.nspname = 'public' ORDER BY pg_total_relation_size(c.oid) DESC`)).rows
    .map((t) => ({ ...t, total: num(t.total), heap: num(t.heap), indexes: num(t.indexes), live: num(t.live), dead: num(t.dead) }));
}

/** Store one sample, at most once every 55 minutes. Keeps 90 days. */
export async function sampleDatabase() {
  const last = (await query(`SELECT max(taken_at) AS t FROM db_samples`)).rows[0].t;
  if (last && Date.now() - new Date(last).getTime() < 55 * 60e3) return false;
  const [size, d, t] = await Promise.all([query('SELECT pg_database_size(current_database())::bigint AS b'), disk(), tables()]);
  await query(`INSERT INTO db_samples(db_bytes, disk_free, disk_total, tables) VALUES ($1,$2,$3,$4)`,
    [num(size.rows[0].b), d.known ? d.free : null, d.known ? d.total : null, JSON.stringify(Object.fromEntries(t.slice(0, 20).map((x) => [x.name, x.total])))]);
  await query(`DELETE FROM db_samples WHERE taken_at < now() - interval '90 days'`);
  return true;
}

/** Bytes per day over the last 7 days of samples (least squares), or null with under a day of history. */
export function growthPerDay(samples, key = 'db_bytes') {
  const pts = samples.filter((s) => s[key] != null && Date.now() - new Date(s.taken_at).getTime() <= 7 * DAY).map((s) => [new Date(s.taken_at).getTime() / DAY, num(s[key])]);
  if (pts.length < 2 || pts.at(-1)[0] - pts[0][0] < 1) return null;
  const n = pts.length, mx = pts.reduce((a, p) => a + p[0], 0) / n, my = pts.reduce((a, p) => a + p[1], 0) / n;
  const sxx = pts.reduce((a, p) => a + (p[0] - mx) ** 2, 0), sxy = pts.reduce((a, p) => a + (p[0] - mx) * (p[1] - my), 0);
  return sxx ? sxy / sxx : null;
}

const GB = 1024 ** 3;
const fmt = (b) => (b >= GB ? `${(b / GB).toFixed(1)} GB` : `${Math.round(b / 1024 ** 2)} MB`);

export function databaseAdvice(h) {
  const out = [], add = (level, area, title, detail, fix) => out.push({ level, area, title, detail, fix });
  const { disk: d, growth: g, pg, tables: t } = h;
  if (!d.known) add('info', 'disk', 'Free disk space is not visible', d.path ? `Could not read ${d.path} (${d.error}).` : 'The app cannot see the disk the database writes to.',
    'In docker-compose.yml, give the app service the database volume read-only (pgdata:/pgdata:ro) and set DB_DATA_PATH=/pgdata. The compose file in this repository already does.');
  else {
    const used = d.used / d.total;
    if (used >= 0.9) add('critical', 'disk', `Disk ${Math.round(used * 100)}% full`, `${fmt(d.free)} left of ${fmt(d.total)}. Postgres stops accepting writes when the disk fills, and scans then fail.`, 'Grow the disk, or shorten SESSION_RETENTION_DAYS so less call history is kept.');
    else if (used >= 0.8) add('warning', 'disk', `Disk ${Math.round(used * 100)}% full`, `${fmt(d.free)} left of ${fmt(d.total)}.`, 'Plan to grow the disk, or shorten SESSION_RETENTION_DAYS.');
    if (g.daysUntilFull != null && g.daysUntilFull < 14) add('critical', 'disk', `Disk full in about ${Math.max(1, Math.round(g.daysUntilFull))} days`, `The database grows about ${fmt(g.perDay)} a day.`, 'Grow the disk now, or shorten SESSION_RETENTION_DAYS.');
    else if (g.daysUntilFull != null && g.daysUntilFull < 45) add('warning', 'disk', `Disk full in about ${Math.round(g.daysUntilFull)} days`, `The database grows about ${fmt(g.perDay)} a day.`, 'Plan more disk, or shorten SESSION_RETENTION_DAYS.');
  }
  if (pg.connections / pg.maxConnections >= 0.8) add('warning', 'database', `${pg.connections} of ${pg.maxConnections} connections in use`, 'New connections will be refused when the limit is reached.', 'Run fewer workers, or raise max_connections.');
  if (pg.cacheHit != null && pg.cacheHit < 0.95 && pg.blocksRead > 1e6) add('info', 'database', `Cache hit rate ${(pg.cacheHit * 100).toFixed(1)}%`, 'Postgres reads from disk more often than it should; pages load slower.', 'Give the postgres container more memory (and raise shared_buffers).');
  if (pg.xidAge >= 0.75) add('critical', 'database', `Transaction IDs ${Math.round(pg.xidAge * 100)}% used`, 'Postgres shuts down writes before they wrap around.', 'Run VACUUM FREEZE on the largest tables tonight.');
  else if (pg.xidAge >= 0.5) add('warning', 'database', `Transaction IDs ${Math.round(pg.xidAge * 100)}% used`, 'Autovacuum is not freezing old rows fast enough.', 'Check that autovacuum runs; VACUUM FREEZE the largest tables.');
  if (pg.longestQuerySec > 900) add('warning', 'database', `A query has run for ${Math.round(pg.longestQuerySec / 60)} minutes`, pg.longestQuery || '', 'If it is stuck, cancel it with pg_cancel_backend.');
  if (pg.oldestIdleTxSec > 900) add('warning', 'database', `A transaction has been open and idle for ${Math.round(pg.oldestIdleTxSec / 60)} minutes`, 'It holds back vacuum on every table.', 'Find it in pg_stat_activity and end it.');
  for (const x of t.filter((x) => x.dead > 2e5 && x.dead / Math.max(1, x.live + x.dead) > 0.2).slice(0, 3))
    add('warning', 'database', `Vacuum is behind on ${x.name}`, `${Math.round((100 * x.dead) / (x.live + x.dead))}% of its rows are dead (${x.dead.toLocaleString('en-US')}); last vacuumed ${x.vacuumed ? new Date(x.vacuumed).toISOString().slice(0, 16).replace('T', ' ') : 'never'}.`, `VACUUM (ANALYZE) ${x.name};`);
  const calls = t.filter((x) => x.name === 'track_calls' || x.name === 'track_sessions').reduce((a, x) => a + x.total, 0);
  if (d.known && d.used / d.total >= 0.8 && calls > 0.5 * pg.size) add('info', 'database', 'Most of the database is call history', `The session replay and event history (track_calls, track_sessions) take ${fmt(calls)} of ${fmt(pg.size)}.`, `SESSION_RETENTION_DAYS is ${config.scanner.sessionRetentionDays}; halving it roughly halves that.`);
  if (!out.some((a) => a.level !== 'info')) add('good', 'database', 'The database is fine', `${fmt(pg.size)}${d.known ? `, disk ${Math.round((d.used / d.total) * 100)}% full` : ''}. Nothing needs attention.`);
  return out;
}

export async function databaseHealth() {
  await sampleDatabase().catch(() => {});
  const [ver, size, conn, stat, act, xid, t, d, samples] = await Promise.all([
    query('SHOW server_version'),
    query('SELECT pg_database_size(current_database())::bigint AS b'),
    query(`SELECT count(*)::int AS n, count(*) FILTER (WHERE state = 'active')::int AS active, current_setting('max_connections')::int AS max FROM pg_stat_activity WHERE datname = current_database()`),
    query(`SELECT blks_hit::bigint, blks_read::bigint, deadlocks::bigint, temp_bytes::bigint, stats_reset FROM pg_stat_database WHERE datname = current_database()`),
    query(`SELECT max(EXTRACT(EPOCH FROM now() - query_start)) FILTER (WHERE state = 'active' AND pid <> pg_backend_pid())::int AS longest,
                  (array_agg(left(query, 200) ORDER BY query_start) FILTER (WHERE state = 'active' AND pid <> pg_backend_pid()))[1] AS longest_query,
                  max(EXTRACT(EPOCH FROM now() - xact_start)) FILTER (WHERE state = 'idle in transaction')::int AS idle_tx
             FROM pg_stat_activity WHERE datname = current_database()`),
    query(`SELECT age(datfrozenxid)::bigint AS age FROM pg_database WHERE datname = current_database()`),
    tables(), disk(),
    query(`SELECT taken_at, db_bytes, disk_free, disk_total FROM db_samples WHERE taken_at > now() - interval '30 days' ORDER BY taken_at`),
  ]);
  const s = stat.rows[0], hit = num(s.blks_hit), read = num(s.blks_read);
  const pg = {
    version: ver.rows[0].server_version, size: num(size.rows[0].b), connections: conn.rows[0].n, activeConnections: conn.rows[0].active, maxConnections: conn.rows[0].max,
    cacheHit: hit + read ? hit / (hit + read) : null, blocksRead: read, deadlocks: num(s.deadlocks), tempBytes: num(s.temp_bytes), statsSince: s.stats_reset,
    longestQuerySec: num(act.rows[0].longest), longestQuery: act.rows[0].longest_query, oldestIdleTxSec: num(act.rows[0].idle_tx),
    xidAge: num(xid.rows[0].age) / 2e9,
  };
  const rows = samples.rows.map((x) => ({ ...x, db_bytes: num(x.db_bytes), disk_free: x.disk_free == null ? null : num(x.disk_free), disk_total: x.disk_total == null ? null : num(x.disk_total) }));
  // disk filling counts everything on that disk, not only the database
  const perDay = growthPerDay(rows), diskPerDay = growthPerDay(rows.map((x) => ({ ...x, disk_used: x.disk_total == null ? null : x.disk_total - x.disk_free })), 'disk_used');
  const fill = d.known ? Math.max(perDay || 0, diskPerDay || 0) : 0;
  const growth = { perDay, diskPerDay, daysUntilFull: d.known && fill > 0 ? d.free / fill : null, days: rows.length ? (Date.now() - new Date(rows[0].taken_at).getTime()) / DAY : 0 };
  const h = { pg, disk: d, tables: t, growth, samples: rows.map((x) => ({ at: x.taken_at, db: x.db_bytes, diskUsed: x.disk_total == null ? null : x.disk_total - x.disk_free, diskTotal: x.disk_total })),
    retentionDays: config.scanner.sessionRetentionDays };
  return { ...h, tables: t.slice(0, 15), tableCount: t.length, advice: databaseAdvice(h) };
}
