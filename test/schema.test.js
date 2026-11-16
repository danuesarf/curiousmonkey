// Guards on the schema itself.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { startPg } from './helpers/pg.js';

let pg, db;
before(async () => { pg = await startPg(54369); db = await import('../src/db.js'); await (await import('../src/migrate.js')).migrate(() => {}); });
after(async () => { await db?.closePool(); await pg?.stop(); });

// Tables that grow with history. A foreign key on one of them with no index starting with its column makes every
// delete of a parent row read the whole table (Postgres 17 cannot use an index that starts with another column).
const BIG = ['activity_daily', 'activity_resources', 'role_sessions', 'track_sessions', 'track_calls', 'call_hourly', 'session_hours', 'seen_events',
  'identity_events', 'role_actions', 'role_snapshots', 'changes', 'flags', 'alert_hits', 'gcp_activity_daily', 'gcp_usage_summary'];
// (alert_deliveries is pruned and its parents, a rule or a destination, are deleted one at a time: one read each is fine)

test('every foreign key on a big table has an index that starts with it', async () => {
  const r = await db.query(`SELECT c.conrelid::regclass::text AS tbl, a.attname AS col, c.confrelid::regclass::text AS ref
      FROM pg_constraint c JOIN pg_attribute a ON a.attrelid = c.conrelid AND a.attnum = c.conkey[1]
     WHERE c.contype = 'f' AND cardinality(c.conkey) = 1 AND c.conrelid::regclass::text = ANY($1)
       AND NOT EXISTS (SELECT 1 FROM pg_index i WHERE i.indrelid = c.conrelid AND i.indkey[0] = c.conkey[1] AND i.indisvalid)`, [BIG]);
  assert.deepEqual(r.rows.map((x) => `${x.tbl}.${x.col} -> ${x.ref}`), []);
});

test('the concurrent index migration can run again over its own result', async () => {
  await db.query(`DELETE FROM schema_migrations WHERE name = '037_fk_indexes.sql'`);
  await (await import('../src/migrate.js')).migrate(() => {});
  const n = (await db.query(`SELECT count(*)::int n FROM pg_indexes WHERE indexname IN ('activity_daily_principal_idx','role_sessions_principal_idx','track_sessions_principal_idx','role_sessions_role_idx','alert_hits_delivery_idx','changes_role_idx')`)).rows[0].n;
  assert.equal(n, 6);
});
