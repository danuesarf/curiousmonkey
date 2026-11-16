// Google Cloud role usage at scale, against a throwaway Postgres: storage per row, and the time and plan of every
// query the reader, the analysis and the pages run.
//   su postgres -s /bin/bash -c "node bench/gcp-usage.bench.mjs [projects] [days] [callers] [pairs per project-day]"
// Defaults: 200 projects x 90 days x 250 (caller, permission) pairs a project-day = 4.5M day rows.
import { startPg } from '../test/helpers/pg.js';

const PROJECTS = Number(process.argv[2] || 200), DAYS = Number(process.argv[3] || 90), CALLERS = Number(process.argv[4] || 3000), PAIRS = Number(process.argv[5] || 250);
const PERMS = 4000, PRINCIPALS = 2500;
process.env.AWS_MODE = 'demo';
const pg = await startPg(54398);
const { query, closePool } = await import('../src/db.js');
await (await import('../src/migrate.js')).migrate(() => {});
await (await import('../src/settings.js')).refreshSettings();
const usage = await import('../src/gcp/usage.js'), ana = await import('../src/gcp/usageAnalysis.js');

const t0 = Date.now();
const ms = (t) => `${Date.now() - t} ms`;
const mb = (b) => `${(b / 1024 ** 2).toFixed(1)} MB`;
const conn = (await query(`INSERT INTO gcp_connections(name, scope_type, scope_id, auth_mode, usage_enabled, usage_lookback_days) VALUES ('bench','organization','1','key', true, 90) RETURNING id`)).rows[0].id;
await query(`INSERT INTO gcp_projects(project_id, connection_id) SELECT 'p-' || g, $1 FROM generate_series(1, $2) g`, [conn, PROJECTS]);
await usage.syncCursors(conn);
await query(`UPDATE gcp_log_cursors SET hi_time = now(), lo_time = now() - interval '${DAYS} days', run_after = now() + interval '1 hour'`);
await query(`INSERT INTO gcp_usage_members(member) SELECT 'serviceAccount:sa-' || g || '@p.iam.gserviceaccount.com' FROM generate_series(1, $1) g`, [CALLERS]);
await query(`INSERT INTO gcp_usage_perms(permission) SELECT 'svc' || (g % 80) || '.res.verb' || g FROM generate_series(1, $1) g`, [PERMS]);

// day rows: each project-day, PAIRS pairs drawn from that project's own few hundred callers (skewed, like real traffic)
let t = Date.now();
await query(`INSERT INTO gcp_activity_daily(project_ref, day, member_id, perm_id, count, denied)
  SELECT DISTINCT ON (u.id, d.day, m, p) u.id, d.day, m, p, 1 + (random() * 200)::int, (random() < 0.02)::int
    FROM gcp_usage_projects u CROSS JOIN generate_series(current_date - $1::int + 1, current_date, '1 day') AS d(day) CROSS JOIN generate_series(1, $2) k
    CROSS JOIN LATERAL (SELECT 1 + ((u.id * 37 + (power(random(), 3) * 300)::int) % $3) AS m, 1 + ((u.id * 13 + (power(random(), 2) * 40)::int + k % 7) % $4) AS p) x`, [DAYS, PAIRS, CALLERS, PERMS]);
await query(`INSERT INTO gcp_usage_summary(project_ref, member_id, perm_id, first_day, last_day, count, denied)
  SELECT project_ref, member_id, perm_id, min(day), max(day), sum(count), sum(denied) FROM gcp_activity_daily GROUP BY 1, 2, 3`);
await query(`UPDATE gcp_usage_projects u SET daily_rows = (SELECT count(*) FROM gcp_activity_daily d WHERE d.project_ref = u.id), summary_rows = (SELECT count(*) FROM gcp_usage_summary s WHERE s.project_ref = u.id)`);
await query('VACUUM ANALYZE gcp_activity_daily'); await query('VACUUM ANALYZE gcp_usage_summary');
const counts = (await query(`SELECT (SELECT count(*) FROM gcp_activity_daily)::bigint d, (SELECT count(*) FROM gcp_usage_summary)::bigint s`)).rows[0];
console.log(`loaded ${counts.d.toLocaleString()} day rows, ${counts.s.toLocaleString()} summary rows in ${ms(t)}`);

// principals with roles, so the analysis has real work: each holds 1 to 4 roles of 20 to 400 permissions
await query(`INSERT INTO gcp_role_defs(name, permissions) SELECT 'roles/r' || g, ARRAY(SELECT 'svc' || (g % 80) || '.res.verb' || ((g * 31 + k) % $1 + 1) FROM generate_series(1, 20 + (g * 7) % 380) k) FROM generate_series(1, 300) g`, [PERMS]);
await query(`INSERT INTO gcp_principals(connection_id, member, kind, roles)
  SELECT $1, 'serviceAccount:sa-' || g || '@p.iam.gserviceaccount.com', 'serviceAccount', (SELECT jsonb_agg(jsonb_build_object('role', 'roles/r' || (1 + (g * 7 + k * 13) % 300))) FROM generate_series(1, 1 + g % 4) k)
    FROM generate_series(1, $2) g`, [conn, PRINCIPALS]);

const sizes = (await query(`SELECT relname, pg_total_relation_size(oid)::bigint t, pg_relation_size(oid)::bigint heap, pg_indexes_size(oid)::bigint idx FROM pg_class WHERE relname IN ('gcp_activity_daily','gcp_usage_summary')`)).rows;
for (const s of sizes) { const n = s.relname === 'gcp_activity_daily' ? counts.d : counts.s; console.log(`  ${s.relname}: ${mb(s.t)} (heap ${mb(s.heap)}, indexes ${mb(s.idx)}) = ${Math.round(s.t / n)} bytes a row`); }

// ---- the queries, timed, with plans for the ones that touch big tables ----
const results = [];
async function bench(name, fn, n = 5) {
  await fn();                                          // warm
  const times = [];
  for (let i = 0; i < n; i++) { const s = performance.now(); await fn(); times.push(performance.now() - s); }
  times.sort((a, b) => a - b);
  results.push({ name, p50: times[Math.floor(n / 2)].toFixed(1), max: times.at(-1).toFixed(1) });
}
async function plan(name, sql, args) {
  const p = (await query(`EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) ${sql}`, args)).rows[0]['QUERY PLAN'][0];
  const nodes = []; const walk = (n) => { nodes.push(`${n['Node Type']}${n['Index Name'] ? ` ${n['Index Name']}` : n['Relation Name'] ? ` ${n['Relation Name']}` : ''}`); (n.Plans || []).forEach(walk); };
  walk(p.Plan);
  const seq = nodes.filter((x) => /Seq Scan (gcp_activity_daily|gcp_usage_summary)/.test(x));
  console.log(`  plan ${name}: ${p['Execution Time'].toFixed(1)} ms · ${[...new Set(nodes)].filter((x) => /Scan/.test(x)).join(', ')}${seq.length ? '  << SEQ SCAN ON A BIG TABLE' : ''}`);
}

const member = 'serviceAccount:sa-40@p.iam.gserviceaccount.com';
const p40 = (await query('SELECT id, member, roles, connection_id FROM gcp_principals WHERE member=$1', [member])).rows[0];
await bench('analyzeUsage (whole connection, 2,500 identities)', () => ana.analyzeUsage(conn), 3);
await bench('principalUsage (one identity page)', () => ana.principalUsage(p40));
await bench('usageStorage (all projects)', () => usage.usageStorage());
await bench('usageStorage, saved (hourly sample)', () => usage.usageStorage({ save: true }));
await query(`UPDATE gcp_log_cursors SET run_after = now() WHERE project_ref % 2 = 0`);
await bench('claimCursor (of 200 due)', async () => { const c = await usage.claimCursor('bench'); await query('UPDATE gcp_log_cursors SET lease_until=NULL, lease_by=NULL WHERE project_ref=$1 AND log=$2', [c.project_ref, c.log]); }, 20);

// a real window commit on top of millions of rows: one busy project-day, 100k entries folded into 3,000 pairs
const agg = new Map();
for (let i = 0; i < 3000; i++) agg.set(`${new Date().toISOString().slice(0, 10)}\u0000serviceAccount:sa-${1 + (i % 400)}@p.iam.gserviceaccount.com\u0000svc${i % 80}.res.verb${1 + (i * 17) % PERMS}`, { count: 30, denied: 0 });
await query(`UPDATE gcp_log_cursors SET lease_by='bench', lease_until = now() + interval '1 hour' WHERE project_ref = 1 AND log = 'activity'`);
const cur = (await query(`SELECT * FROM gcp_log_cursors WHERE project_ref = 1 AND log = 'activity'`)).rows[0];
await bench('commitWindow (3,000 pairs, one transaction)', async () => {
  const w = { kind: 'forward', from: Date.now() - 6e5, to: Date.now() };
  const r = await usage.commitWindow(cur, w, { agg, entries: 100000, pages: 100 });
  if (r.lost) throw new Error('lease lost');
});
const recount = await usage.recountProject(1);
const kept = (await query('SELECT daily_rows, summary_rows FROM gcp_usage_projects WHERE id=1')).rows[0];
console.log(`counters after commits: ${kept.daily_rows}/${kept.summary_rows}, recount ${recount.daily}/${recount.summary}`);

console.log('\ntimings (ms)');
console.table(results);

console.log('\nplans');
const cutoff = new Date(Date.now() - 90 * 864e5).toISOString().slice(0, 10);
await plan('analysis: used per caller', `SELECT m.member, array_agg(DISTINCT pr.permission) FROM gcp_usage_summary s JOIN gcp_usage_projects u ON u.id = s.project_ref
  JOIN gcp_usage_members m ON m.id = s.member_id JOIN gcp_usage_perms pr ON pr.id = s.perm_id WHERE u.connection_id = $1 AND s.last_day >= $2 AND s.count > 0 GROUP BY m.member`, [conn, cutoff]);
await plan('identity page: summary', `SELECT pr.permission, u.project_id, s.first_day, s.last_day, s.count FROM gcp_usage_members m JOIN gcp_usage_summary s ON s.member_id = m.id
  JOIN gcp_usage_projects u ON u.id = s.project_ref JOIN gcp_usage_perms pr ON pr.id = s.perm_id WHERE m.member = $1 AND u.connection_id = $2`, [member, conn]);
await plan('identity page: calls per day', `WITH m AS (SELECT id FROM gcp_usage_members WHERE member = $1),
    pr AS (SELECT DISTINCT s.project_ref FROM gcp_usage_summary s JOIN gcp_usage_projects u ON u.id = s.project_ref WHERE s.member_id = (SELECT id FROM m) AND u.connection_id = $2 AND s.last_day >= $3)
  SELECT d.day, sum(d.count) FROM pr CROSS JOIN LATERAL (SELECT day, count FROM gcp_activity_daily WHERE project_ref = pr.project_ref AND day >= $3 AND member_id = (SELECT id FROM m)) d GROUP BY d.day`, [member, conn, cutoff]);
await plan('storage recount (one project)', `SELECT count(*) FROM gcp_activity_daily WHERE project_ref = $1`, [7]);
await plan('cursor claim', `SELECT x.project_ref, x.log FROM gcp_log_cursors x JOIN gcp_usage_projects ux ON ux.id = x.project_ref JOIN gcp_connections cx ON cx.id = ux.connection_id
  WHERE x.run_after <= now() AND (x.lease_until IS NULL OR x.lease_until < now()) AND cx.usage_enabled ORDER BY x.run_after LIMIT 1`, []);

const st = await usage.usageStorage();
console.log(`\nstorage: ${mb(st.total)} total, ${st.bytesPerRow.daily} B/day row, ${st.bytesPerRow.summary} B/summary row; largest project ${st.items[0].projectId} ${mb(st.items[0].bytes)}, sum of projects ${mb(st.items.reduce((a, i) => a + i.bytes, 0))}`);
console.log(`total ${ms(t0)}`);
await closePool(); await pg.stop();
