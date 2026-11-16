// Database space per AWS account at scale, against a throwaway Postgres: how long the hourly estimate takes and how
// close the sampled split is to an exact count.
//   su postgres -s /bin/bash -c "node bench/account-storage.bench.mjs [accounts] [calls in millions] [activity rows in millions]"
// Defaults: 100 accounts, 20M track_calls (reached through sessions), 5M activity_daily (through roles).
import { startPg } from '../test/helpers/pg.js';

const ACCOUNTS = Number(process.argv[2] || 100), CALLS = Number(process.argv[3] || 20) * 1e6, ACTIVITY = Number(process.argv[4] || 5) * 1e6;
const pg = await startPg(54395);
const { query, closePool } = await import('../src/db.js');
await (await import('../src/migrate.js')).migrate(() => {});
const st = await import('../src/accountStorage.js');
const t0 = Date.now(), mb = (b) => `${(b / 1024 ** 2).toFixed(0)} MB`;

// accounts of very different sizes (Zipf-like), 50 roles each, 200 sessions per role
await query(`INSERT INTO cloud_accounts(account_id, name, regions) SELECT lpad(g::text, 12, '0'), 'acct-' || g, '{us-east-1}' FROM generate_series(1, $1) g`, [ACCOUNTS]);
await query(`INSERT INTO roles(account_id, arn, name, kind) SELECT a.id, 'arn:' || a.account_id || ':' || g, 'r' || g, 'custom' FROM cloud_accounts a, generate_series(1, 50) g`);
await query(`INSERT INTO principals(role_id, key, kind, display, via) SELECT id, 'k', 'aws', 'd', 'v' FROM roles`);
await query(`INSERT INTO track_sessions(account_id, role_id, access_key_id, started_at) SELECT r.account_id, r.id, 'ASIA' || md5(r.id::text || g), now() FROM roles r, generate_series(1, 200) g`);
// weight per account: account n gets about 1/n of the traffic
await query(`CREATE TEMP TABLE w AS SELECT a.id, (1.0 / row_number() OVER (ORDER BY a.account_id)) AS w FROM cloud_accounts a`);
await query(`CREATE TEMP TABLE sess AS SELECT s.id, s.account_id, row_number() OVER () AS n FROM track_sessions s`);
let t = Date.now();
// calls: each session gets a share of CALLS proportional to its account's weight
await query(`INSERT INTO track_calls(session_id, event_id, at, event_source, event_name)
  SELECT s.id, s.id::text || ':' || g, now() - (g || ' seconds')::interval, 'ec2.amazonaws.com', 'DescribeInstances'
    FROM sess s JOIN w ON w.id = s.account_id, LATERAL generate_series(1, greatest(1, round($1 * w.w / (SELECT sum(w) FROM w) / 10000)::int)) g`, [CALLS]);
await query(`INSERT INTO activity_daily(role_id, principal_id, action, day)
  SELECT r.id, p.id, 'svc:Act' || g, current_date - (g % 90) FROM roles r JOIN principals p ON p.role_id = r.id JOIN w ON w.id = r.account_id,
    LATERAL generate_series(1, greatest(1, round($1 * w.w / (SELECT sum(w) FROM w) / 50)::int)) g`, [ACTIVITY]);
await query('VACUUM ANALYZE');
const n = (await query(`SELECT (SELECT count(*) FROM track_calls)::bigint c, (SELECT count(*) FROM activity_daily)::bigint d, pg_database_size(current_database())::bigint b`)).rows[0];
console.log(`loaded ${Number(n.c).toLocaleString()} calls, ${Number(n.d).toLocaleString()} activity rows, database ${mb(n.b)} in ${Date.now() - t} ms`);
await query('SELECT pg_stat_reset()');

// the hourly estimate, cold and warm
const runs = [];
for (let i = 0; i < 3; i++) { const s = performance.now(); await st.accountStorage({ save: true }); runs.push(performance.now() - s); }
console.log(`accountStorage (save): ${runs.map((x) => `${x.toFixed(0)} ms`).join(', ')}`);
const io = (await query(`SELECT sum(heap_blks_read + heap_blks_hit)::bigint pages FROM pg_statio_user_tables WHERE relname IN ('track_calls','activity_daily')`)).rows[0];
const pages = (await query(`SELECT sum(relpages)::bigint p FROM pg_class WHERE relname IN ('track_calls','activity_daily')`)).rows[0];
console.log(`pages read by 3 runs from the two big tables: ${io.pages} of ${pages.p} (${((io.pages / 3 / pages.p) * 100).toFixed(2)}% a run)`);

// accuracy: sampled share vs an exact count, for the biggest, a middle and a small account
const exact = new Map((await query(`SELECT s.account_id, count(*)::bigint n FROM track_calls c JOIN track_sessions s ON s.id = c.session_id GROUP BY 1`)).rows.map((r) => [r.account_id, Number(r.n)]));
const est = await st.accountStorage();
const avg = new Map();
for (let i = 0; i < 24; i++) for (const x of (await st.accountStorage()).items) avg.set(x.account, (avg.get(x.account) || 0) + (x.byTable.track_calls?.[1] || 0) / 24);
const rank = [...exact].sort((a, b) => b[1] - a[1]);
console.log('\ntrack_calls rows: exact · one hourly estimate · average of 24 (what the pages show)');
const pc = (got, real) => `${(((got - real) / real) * 100).toFixed(1)}%`;
const errs1 = [], errs24 = [];
for (const [id, real] of rank) { const one = est.items.find((x) => x.account === id)?.byTable.track_calls?.[1] || 0; errs1.push(Math.abs(one - real) / real); errs24.push(Math.abs((avg.get(id) || 0) - real) / real); }
for (const i of [0, 1, 9, 49, ACCOUNTS - 1]) {
  const [id, real] = rank[i];
  const one = est.items.find((x) => x.account === id)?.byTable.track_calls?.[1] || 0;
  console.log(`  #${i + 1}: ${real.toLocaleString()} · ${Math.round(one).toLocaleString()} (${pc(one, real)}) · ${Math.round(avg.get(id)).toLocaleString()} (${pc(avg.get(id), real)})`);
}
const med = (a) => [...a].sort((x, y) => x - y)[Math.floor(a.length / 2)], p90 = (a) => [...a].sort((x, y) => x - y)[Math.floor(a.length * 0.9)];
console.log(`  all ${ACCOUNTS} accounts, error median / p90: one ${(med(errs1) * 100).toFixed(1)}% / ${(p90(errs1) * 100).toFixed(1)}% · average of 24 ${(med(errs24) * 100).toFixed(1)}% / ${(p90(errs24) * 100).toFixed(1)}%`);
const sum = est.items.reduce((s, i) => s + i.bytes, 0);
console.log(`\naccounts total ${mb(sum)}, attributed tables ${mb(est.attributed)}, ${est.tables} tables tied to accounts`);
const s = performance.now(); await st.storedAccountStorage(); console.log(`storedAccountStorage (page read): ${(performance.now() - s).toFixed(1)} ms`);
console.log(`total ${Date.now() - t0} ms`);
await closePool(); await pg.stop();
