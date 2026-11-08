// Database health: sizes, growth, days until full, and what to say about them.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { startPg } from './helpers/pg.js';

let pg, db, dh;
before(async () => {
  pg = await startPg(54353);
  db = await import('../src/db.js');
  await (await import('../src/migrate.js')).migrate(() => {});
  dh = await import('../src/dbHealth.js');
});
after(async () => { await db.closePool(); await pg.stop(); });

test('growth is a 7-day trend, and needs a day of samples', () => {
  const at = (d) => new Date(Date.now() - d * 864e5).toISOString();
  assert.equal(dh.growthPerDay([{ taken_at: at(0.5), db_bytes: 1 }, { taken_at: at(0), db_bytes: 2 }]), null);
  const g = dh.growthPerDay([0, 1, 2, 3].map((i) => ({ taken_at: at(3 - i), db_bytes: 1e9 + i * 2e8 })));
  assert.ok(Math.abs(g - 2e8) < 1e3);
});

test('the report: postgres numbers, tables, the disk when it can be seen, a sample stored once an hour', async () => {
  process.env.DB_DATA_PATH = fs.mkdtempSync('/tmp/cm-disk-');
  const h = await dh.databaseHealth();
  assert.ok(h.pg.size > 0 && h.pg.maxConnections > 0 && h.pg.connections >= 1);
  assert.ok(h.tableCount > 20 && h.tables.length === 15);
  assert.deepEqual(h.tables.map((t) => t.total), [...h.tables.map((t) => t.total)].sort((a, b) => b - a));
  assert.equal(h.disk.known, true); assert.ok(h.disk.free > 0 && h.disk.total >= h.disk.free);
  assert.equal(await dh.sampleDatabase(), false);                 // already sampled within the hour
  assert.equal((await db.query('SELECT count(*)::int n FROM db_samples')).rows[0].n, 1);
  delete process.env.DB_DATA_PATH;
  assert.equal((await dh.databaseHealth()).advice.find((a) => a.area === 'disk')?.title, 'Free disk space is not visible');
});

test('advice: a filling disk, a near date, vacuum behind, and all good', () => {
  const base = { pg: { size: 10e9, connections: 5, maxConnections: 100, cacheHit: 0.99, blocksRead: 0, xidAge: 0.01, longestQuerySec: 0, oldestIdleTxSec: 0 }, tables: [] };
  const full = dh.databaseAdvice({ ...base, disk: { known: true, total: 100e9, free: 5e9, used: 95e9 }, growth: { perDay: 1e9, daysUntilFull: 5 } });
  assert.deepEqual(full.map((a) => a.level), ['critical', 'critical']);
  assert.match(full[1].title, /full in about 5 days/);
  const vac = dh.databaseAdvice({ ...base, disk: { known: true, total: 100e9, free: 60e9, used: 40e9 }, growth: { perDay: null, daysUntilFull: null },
    tables: [{ name: 'track_calls', live: 1e6, dead: 5e5, total: 1e9, vacuumed: null }] });
  assert.match(vac[0].title, /Vacuum is behind on track_calls/);
  const ok = dh.databaseAdvice({ ...base, disk: { known: true, total: 100e9, free: 60e9, used: 40e9 }, growth: { perDay: 1e8, daysUntilFull: 600 } });
  assert.deepEqual(ok.map((a) => a.level), ['good']);
});
