import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { pool, closePool } from './db.js';

const dir = path.join(path.dirname(fileURLToPath(import.meta.url)), 'migrations');

export async function migrate(log = console.log) {
  const client = await pool.connect();
  try {
    // One migrator at a time, even when several pods start together.
    await client.query('SELECT pg_advisory_lock(727001)');
    await client.query(`CREATE TABLE IF NOT EXISTS schema_migrations (
      name text PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())`);
    const done = new Set((await client.query('SELECT name FROM schema_migrations')).rows.map((r) => r.name));
    const files = fs.readdirSync(dir).filter((f) => f.endsWith('.sql')).sort();
    let applied = 0;
    for (const f of files) {
      if (done.has(f)) continue;
      const sql = fs.readFileSync(path.join(dir, f), 'utf8');
      // "-- no-transaction" on the first line: for CREATE INDEX CONCURRENTLY, which builds without blocking writes to a
      // big table but cannot run in a transaction. Each statement runs on its own and must be safe to repeat.
      if (/^--\s*no-transaction\b/.test(sql)) {
        for (const stmt of sql.split(/;\s*$/m).map((x) => x.replace(/^\s*--.*$/gm, '').trim()).filter(Boolean)) await client.query(stmt);
        await client.query('INSERT INTO schema_migrations(name) VALUES ($1)', [f]);
        log(`migrated ${f}`);
        applied++;
        continue;
      }
      try {
        await client.query('BEGIN');
        await client.query(sql);
        await client.query('INSERT INTO schema_migrations(name) VALUES ($1)', [f]);
        await client.query('COMMIT');
        log(`migrated ${f}`);
        applied++;
      } catch (e) {
        await client.query('ROLLBACK');
        throw new Error(`migration ${f} failed: ${e.message}`);
      }
    }
    return applied;
  } finally {
    await client.query('SELECT pg_advisory_unlock(727001)').catch(() => {});
    client.release();
  }
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  migrate().then((n) => { console.log(`done, ${n} applied`); return closePool(); })
    .catch((e) => { console.error(e.message); process.exit(1); });
}
