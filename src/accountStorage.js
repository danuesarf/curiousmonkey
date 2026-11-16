// Database space per AWS account, estimated without touching the write paths.
//
// The tables come from the catalog: every table with a single-column foreign key to cloud_accounts (preferred), to
// roles, or to track_sessions, so a table added later is picked up on its own. Each table's rows are split by account:
//   up to SAMPLE_ROWS rows   exact count, grouped by the key
//   bigger                   TABLESAMPLE SYSTEM of about SAMPLE_ROWS rows (a few thousand random pages), scaled;
//                            the smallest accounts counted exactly through the key's index (up to 10% of the rows)
// and its measured size (pg_total_relation_size: heap, indexes, TOAST) is shared out in proportion. So the accounts
// add up to the tables they live in, and a 100-million-row table costs a sample, not a scan.
import { query, tx } from './db.js';

export const SAMPLE_ROWS = 200_000;
const VIA = { cloud_accounts: 0, roles: 1, track_sessions: 2 };       // preference when a table links more than one way

/** Tables holding account data, and how each one reaches an account. */
export async function accountTables() {
  const r = await query(`SELECT c.conrelid::regclass::text AS tbl, a.attname AS col, c.confrelid::regclass::text AS ref,
      greatest(cls.reltuples, 0)::bigint AS est, pg_total_relation_size(c.conrelid)::bigint AS bytes
    FROM pg_constraint c JOIN pg_attribute a ON a.attrelid = c.conrelid AND a.attnum = c.conkey[1] JOIN pg_class cls ON cls.oid = c.conrelid
    JOIN pg_namespace n ON n.oid = cls.relnamespace
    WHERE c.contype = 'f' AND cardinality(c.conkey) = 1 AND n.nspname = current_schema()
      AND c.confrelid::regclass::text IN ('cloud_accounts', 'roles', 'track_sessions') AND cls.relkind IN ('r', 'p')`);
  const best = new Map();
  for (const x of r.rows) {
    // a table's own account column beats any other link to cloud_accounts (org_accounts.seen_from is only where it was seen)
    const rank = VIA[x.ref] * 2 + (x.ref === 'cloud_accounts' && x.col !== 'account_id' ? 1 : 0);
    const cur = best.get(x.tbl);
    if (!cur || rank < cur.rank) best.set(x.tbl, { ...x, rank });
  }
  best.delete('cloud_accounts');
  return [...best.values()];
}

const ident = (s) => `"${String(s).replace(/"/g, '""')}"`;

/** Rows per account in one table: { counts: Map(account -> rows), total, sampled }. */
export async function splitTable(t, { sampleRows = SAMPLE_ROWS, exactShare = 0.1, exactMax = 25, exactMs = 2000 } = {}) {
  const sampled = t.est > sampleRows;
  const from = sampled ? `${ident(t.tbl)} TABLESAMPLE SYSTEM (${Math.max(0.01, Math.min(100, (sampleRows / t.est) * 100)).toFixed(4)})` : ident(t.tbl);
  const inner = `SELECT ${ident(t.col)} AS k, count(*)::bigint AS n FROM ${from} WHERE ${ident(t.col)} IS NOT NULL GROUP BY 1`;
  const sql = t.ref === 'cloud_accounts' ? `SELECT k AS account_id, n FROM (${inner}) x`
    : t.ref === 'roles' ? `SELECT r.account_id, sum(x.n)::bigint AS n FROM (${inner}) x JOIN roles r ON r.id = x.k GROUP BY 1`
      : `SELECT s.account_id, sum(x.n)::bigint AS n FROM (${inner}) x JOIN track_sessions s ON s.id = x.k GROUP BY 1`;
  const rows = (await query(sql)).rows;
  const seen = rows.reduce((a, r) => a + Number(r.n), 0);
  if (!sampled) return { counts: new Map(rows.map((r) => [r.account_id, Number(r.n)])), total: seen, sampled: false, seen };

  // A page sample is close for big accounts (within a few percent) but loose for small ones, which a few thousand
  // pages barely touch. So the smallest accounts are counted exactly through the key's index, smallest first, while
  // their rows stay under exactShare of the table; the rest of the table is shared out by the sample.
  const total = Math.max(seen, Number(t.est));
  const est = new Map(rows.map((r) => [r.account_id, (Number(r.n) / Math.max(1, seen)) * total]));
  const exact = new Map();
  if (await leadingIndex(t)) {
    const all = (await query('SELECT id FROM cloud_accounts')).rows.map((r) => r.id);
    const order = all.map((id) => [id, est.get(id) || 0]).sort((a, b) => a[1] - b[1]);
    const keyOf = t.ref === 'cloud_accounts' ? 'ARRAY[$1::uuid]' : t.ref === 'roles' ? 'ARRAY(SELECT id FROM roles WHERE account_id = $1)' : 'ARRAY(SELECT id FROM track_sessions WHERE account_id = $1)';
    let used = 0;
    const until = Date.now() + exactMs;
    for (const [id, guess] of order) {
      if (used + guess > exactShare * total || exact.size >= exactMax || Date.now() > until) break;
      const n = Number((await query(`SELECT count(*)::bigint AS n FROM ${ident(t.tbl)} WHERE ${ident(t.col)} = ANY(${keyOf})`, [id])).rows[0].n);
      exact.set(id, n); used += n;
      if (used > exactShare * total) break;
    }
  }
  const exactSum = [...exact.values()].reduce((a, n) => a + n, 0);
  const rest = [...est].filter(([id]) => !exact.has(id)), restEst = rest.reduce((a, [, n]) => a + n, 0);
  const counts = new Map(exact);
  for (const [id, n] of rest) counts.set(id, restEst ? (n / restEst) * Math.max(0, total - exactSum) : 0);
  return { counts, total: Math.max(total, exactSum), sampled: true, seen, exact: exact.size };
}

/** Is there an index starting with the key column, so one account's rows are a cheap range? */
async function leadingIndex(t) {
  return (await query(`SELECT 1 FROM pg_index i JOIN pg_attribute a ON a.attrelid = i.indrelid AND a.attnum = i.indkey[0]
    WHERE i.indrelid = $1::regclass AND a.attname = $2 LIMIT 1`, [t.tbl, t.col])).rowCount > 0;
}

/** Estimate every account's space. With save, store it as the latest and as an hourly point (kept 30 days). */
export async function accountStorage({ save = false, sampleRows = SAMPLE_ROWS } = {}) {
  const tables = await accountTables();
  const acc = new Map();
  let attributed = 0;
  for (const t of tables) {
    if (!t.bytes) continue;
    let s;
    try { s = await splitTable(t, { sampleRows }); } catch { continue; }       // a table being altered: next hour
    if (!s.total) continue;
    attributed += Number(t.bytes);
    for (const [id, n] of s.counts) {
      const b = (n / s.total) * Number(t.bytes);
      const x = acc.get(id) || acc.set(id, { bytes: 0, rows: 0, byTable: {}, sampled: false }).get(id);
      x.bytes += b; x.rows += n; x.byTable[t.tbl] = [Math.round(b), Math.round(n)]; if (s.sampled) x.sampled = true;
    }
  }
  const items = [...acc].map(([account, x]) => ({ account, bytes: Math.round(x.bytes), rows: Math.round(x.rows), byTable: x.byTable, sampled: x.sampled })).sort((a, b) => b.bytes - a.bytes);
  if (save) {
    await tx(async (c) => {
      const ids = items.map((i) => i.account);
      await c.query(`DELETE FROM account_storage WHERE NOT (account_id = ANY($1::uuid[]))`, [ids]);
      if (ids.length) {
        await c.query(`INSERT INTO account_storage(account_id, bytes, rows_est, by_table, sampled, at)
            SELECT * , now() FROM unnest($1::uuid[], $2::bigint[], $3::bigint[], $4::jsonb[], $5::bool[])
            ON CONFLICT (account_id) DO UPDATE SET bytes = EXCLUDED.bytes, rows_est = EXCLUDED.rows_est, by_table = EXCLUDED.by_table, sampled = EXCLUDED.sampled, at = now()`,
        [ids, items.map((i) => i.bytes), items.map((i) => i.rows), items.map((i) => JSON.stringify(i.byTable)), items.map((i) => i.sampled)]);
        await c.query(`INSERT INTO account_storage_samples(account_id, at, bytes) SELECT a, date_trunc('hour', now()), b FROM unnest($1::uuid[], $2::bigint[]) AS x(a, b)
            ON CONFLICT (account_id, at) DO UPDATE SET bytes = EXCLUDED.bytes`, [ids, items.map((i) => i.bytes)]);
      }
      await c.query(`DELETE FROM account_storage_samples WHERE at < now() - interval '30 days'`);
    });
  }
  return { items, attributed, tables: tables.length };
}

/**
 * The stored estimate. `bytes` is the average of the last 24 hourly estimates: each hour samples different pages, so
 * averaging them cancels most of the sampling noise. Growth compares it with the same average a week earlier.
 */
export async function storedAccountStorage() {
  return (await query(`SELECT s.account_id, a.name, a.account_id AS aws_account, a.environment, s.rows_est, s.by_table, s.sampled, s.at, s.bytes AS bytes_latest,
      COALESCE((SELECT avg(x.bytes) FROM account_storage_samples x WHERE x.account_id = s.account_id AND x.at > now() - interval '24 hours'), s.bytes)::bigint AS bytes,
      (SELECT avg(x.bytes) FROM account_storage_samples x WHERE x.account_id = s.account_id AND x.at > now() - interval '8 days' AND x.at <= now() - interval '7 days')::bigint AS bytes_7d_ago
    FROM account_storage s JOIN cloud_accounts a ON a.id = s.account_id ORDER BY bytes DESC`)).rows;
}
