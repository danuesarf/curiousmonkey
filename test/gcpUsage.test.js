// Google Cloud role usage from audit logs: windows, no double counting, backfill, opt-in, storage per project.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { startPg } from './helpers/pg.js';
import { demoLogEntries } from '../src/gcp/demo.js';

process.env.AWS_MODE = 'demo'; process.env.LOOKUP_DELAY_MS = '0'; process.env.DEMO_LOG_PAGE_SIZE = '7';   // small pages: pagination is exercised
const DAY = 864e5;
// src/gcp/usage.js reads the database URL when loaded: everything that touches config is imported after Postgres starts
let pg, db, q, server, base, totp, gcpScan, usage, ana, config;
let nextWindow, coverage, addEntries, callerOf, checksOf, LAG_MS, dayStart, classify, isReadPermission;
before(async () => {
  pg = await startPg(54367);
  db = await import('../src/db.js');
  await (await import('../src/migrate.js')).migrate(() => {});
  q = await import('../src/queue.js'); totp = await import('../src/auth/totp.js'); gcpScan = await import('../src/gcp/scan.js');
  usage = await import('../src/gcp/usage.js'); ana = await import('../src/gcp/usageAnalysis.js');
  ({ nextWindow, coverage, addEntries, callerOf, checksOf, LAG_MS, dayStart } = usage); ({ classify, isReadPermission } = ana);
  await (await import('../src/settings.js')).refreshSettings();
  config = (await import('../src/config.js')).config;
  config.gcp.usageReadsPerMinute = 600;
  const { createApp } = await import('../src/server.js');
  server = createApp().listen(0); base = `http://127.0.0.1:${server.address().port}`;
  await q.registerWorker();
});
after(async () => { server?.close(); await db?.closePool(); await pg?.stop(); });

// ---------------------------------------------------------------- pure parts
test('windows: start, forward first, then back one day at a time down to the lookback, then nothing', () => {
  const now = Date.parse('2026-11-17T12:34:56Z');
  const s = nextWindow({}, { now, lookbackDays: 3 });
  assert.equal(s.kind, 'start'); assert.equal(s.at, Math.floor((now - LAG_MS) / 60e3) * 60e3);
  const c = { hi_time: new Date(s.at).toISOString(), lo_time: new Date(s.at).toISOString() };
  // a minute later there is a forward window; it goes before any backfill
  const f = nextWindow(c, { now: now + 61e3, lookbackDays: 3 });
  assert.deepEqual([f.kind, f.from, f.to], ['forward', s.at, now + 61e3 - LAG_MS]);
  const seen = []; let lo = s.at;
  for (let w; (w = nextWindow({ hi_time: c.hi_time, lo_time: new Date(lo).toISOString() }, { now, lookbackDays: 3 }));) { seen.push(w); lo = w.from; }
  assert.ok(seen.every((w) => w.kind === 'back'));
  assert.equal(seen[0].from, dayStart(s.at)); assert.equal(seen[0].to, s.at);           // the rest of today first
  assert.ok(seen.slice(1).every((w) => w.to - w.from === DAY && w.from % DAY === 0));    // then whole UTC days
  assert.equal(seen.at(-1).from, dayStart(now - 3 * DAY));
  assert.equal(coverage({ hi_time: c.hi_time, lo_time: new Date(lo).toISOString() }, { now, lookbackDays: 3 }), 1);
  assert.equal(coverage({ hi_time: c.hi_time, lo_time: c.hi_time }, { now, lookbackDays: 3 }), 0);
  // a longer lookback later resumes the backfill from where it stopped
  assert.equal(nextWindow({ hi_time: c.hi_time, lo_time: new Date(lo).toISOString() }, { now, lookbackDays: 5 }).to, lo);
  // never past what the _Required bucket keeps
  assert.equal(nextWindow({ hi_time: c.hi_time, lo_time: new Date(dayStart(now - 400 * DAY)).toISOString() }, { now, lookbackDays: 400 }), null);
});

test('entries: the caller as IAM writes it, every permission check, denied ones apart', () => {
  assert.equal(callerOf({ principalEmail: 'a@p.iam.gserviceaccount.com' }), 'serviceAccount:a@p.iam.gserviceaccount.com');
  assert.equal(callerOf({ principalEmail: 'bob@acme.example' }), 'user:bob@acme.example');
  assert.match(callerOf({ principalSubject: 'principal://iam.googleapis.com/projects/1/locations/global/workloadIdentityPools/p/subject/x' }), /^principal:\/\//);
  assert.equal(callerOf({}), null);
  const e = { timestamp: '2026-11-01T10:00:00Z', protoPayload: { authenticationInfo: { principalEmail: 'bob@acme.example' }, authorizationInfo: [{ permission: 'a.b.create', granted: true }, { permission: 'a.b.delete', granted: false }] } };
  assert.equal(checksOf(e).length, 2);
  const agg = new Map();
  assert.equal(addEntries(agg, [e, e, { timestamp: 'x' }, { timestamp: '2026-11-01T11:00:00Z', protoPayload: {} }]), 4);
  assert.deepEqual(agg.get('2026-11-01\u0000user:bob@acme.example\u0000a.b.create'), { count: 2, denied: 0 });
  assert.deepEqual(agg.get('2026-11-01\u0000user:bob@acme.example\u0000a.b.delete'), { count: 0, denied: 2 });
});

test('the demo log returns the same entries however time is split into windows', () => {
  const from = Date.parse('2026-11-10T00:00:00Z'), to = from + 2 * DAY;
  const all = (a, b) => { const out = []; let tok = ''; do { const r = demoLogEntries({ projectId: 'acme-data-stg', filter: `logName="projects/acme-data-stg/logs/cloudaudit.googleapis.com%2Factivity" AND timestamp>="${new Date(a).toISOString()}" AND timestamp<"${new Date(b).toISOString()}"`, pageToken: tok }, 5); out.push(...r.entries); tok = r.nextPageToken || ''; } while (tok); return out; };
  const whole = all(from, to), split = [...all(from, from + 7 * 36e5 + 13 * 60e3), ...all(from + 7 * 36e5 + 13 * 60e3, to)];
  assert.ok(whole.length > 20);
  assert.deepEqual(split.map((e) => e.timestamp), whole.map((e) => e.timestamp));
});

test('classification: reads are unconfirmed until Data Access is read', () => {
  assert.ok(isReadPermission('storage.objects.get') && isReadPermission('bigquery.tables.list') && !isReadPermission('storage.objects.create'));
  const granted = new Set(['storage.objects.create', 'storage.objects.delete', 'storage.objects.get', 'storage.buckets.setIamPolicy']);
  assert.deepEqual(classify(granted, new Set(['storage.objects.create']), { readsKnown: false }), { used: 1, unused: 2, unconfirmed: 1 });
  assert.deepEqual(classify(granted, new Set(['storage.objects.create']), { readsKnown: true }), { used: 1, unused: 3, unconfirmed: 0 });
});

// ---------------------------------------------------------------- end to end, with the demo organization
class Client {
  constructor() { this.cookie = ''; this.csrf = ''; }
  async call(method, path, body) {
    const headers = { 'content-type': 'application/json' };
    if (this.cookie) headers.cookie = this.cookie;
    if (this.csrf) headers['x-csrf-token'] = this.csrf;
    const r = await fetch(base + path, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
    const sc = r.headers.get('set-cookie'); if (sc) this.cookie = sc.split(';')[0];
    const text = await r.text(); let json = null; try { json = JSON.parse(text); } catch { /* not json */ }
    if (json?.csrf) this.csrf = json.csrf;
    return { status: r.status, json, text };
  }
  get(p) { return this.call('GET', p); } post(p, b) { return this.call('POST', p, b ?? {}); } patch(p, b) { return this.call('PATCH', p, b); }
}
const PW = 'correct horse battery staple';
const owner = new Client();
let conn;
const tick = (opts = {}) => usage.usageTick('w1', { gwFor: gcpScan.gcpGateway, analyze: ana.analyzeUsage, ...opts });
async function drainUsage() { let n = 0; for (let r; (r = await tick());) { assert.ok(!r.error, r.error); n++; } return n; }
const one = async (sql, args) => (await db.query(sql, args)).rows[0];

test('setup: an owner and a Google Cloud organization, usage off by default', async () => {
  await owner.post('/api/auth/signup', { name: 'Owner', email: 'owner@acme.example', password: PW, workspaceName: 'Acme' });
  const s = await owner.post('/api/auth/mfa/start'); await owner.post('/api/auth/mfa/confirm', { code: totp.code(s.json.secret) });
  const wif = { projectNumber: '300000000003', poolId: 'curious-monkey', providerId: 'aws-scanner', serviceAccount: 'cm-reader@acme-shared-ci.iam.gserviceaccount.com' };
  const c = await owner.post('/api/gcp/connections', { name: 'acme.example', scopeType: 'organization', scopeId: '100000000001', authMode: 'wif', wif, environment: 'shared' });
  assert.equal(c.status, 201); conn = c.json.id;
  assert.equal(c.json.usage.enabled, false);
  assert.equal((await gcpScan.gcpTick('w1')).ok, true);
  assert.equal((await one('SELECT count(*)::int n FROM gcp_log_cursors')).n, 0);         // off: nothing to read
  assert.equal(await tick(), null);
  const p = (await owner.get('/api/gcp/principals?q=lake-sync')).json.items[0];
  assert.equal(p.usage, null);
});

test('onboarding adds only the log permissions asked for', async () => {
  const off = (await owner.get('/api/gcp/onboarding?scopeType=organization&scopeId=100000000001')).json;
  assert.doesNotMatch(off.steps.map((x) => x.code).join('\n'), /logging/);
  const on = (await owner.get('/api/gcp/onboarding?scopeType=organization&scopeId=100000000001&usage=1')).json.steps.map((x) => x.code).join('\n');
  assert.match(on, /logging\.logEntries\.list/); assert.doesNotMatch(on, /privateLogEntries/); assert.match(on, /logging\.googleapis\.com/);
  const folder = (await owner.get('/api/gcp/onboarding?scopeType=folder&scopeId=200000000001&usage=1&dataAccess=1')).json.steps.map((x) => x.code).join('\n');
  assert.match(folder, /roles\/logging\.viewer/); assert.match(folder, /roles\/logging\.privateLogViewer/);
});

test('turning it on: one cursor per project, the backfill reads every window once, counters match the rows', async () => {
  const r = await owner.patch(`/api/gcp/connections/${conn}`, { usage: { enabled: true, lookbackDays: 3, dataAccess: false } });
  assert.equal(r.status, 200, r.text); assert.equal(r.json.usage.enabled, true);
  assert.equal((await one(`SELECT count(*)::int n FROM gcp_log_cursors`)).n, 3);
  const ticks = await drainUsage();
  assert.ok(ticks >= 3);
  const cur = (await db.query('SELECT k.*, u.project_id FROM gcp_log_cursors k JOIN gcp_usage_projects u ON u.id = k.project_ref')).rows;
  assert.ok(cur.every((c) => c.lo_time && new Date(c.lo_time).getTime() === dayStart(Date.now() - 3 * DAY)));
  assert.ok(cur.every((c) => c.pages_read > c.windows_read));                                // several pages a window

  // exactly what the log holds over [lookback start, hi): every entry counted once
  for (const c of cur) {
    let want = 0, tok = '';
    const filter = `logName="projects/${c.project_id}/logs/cloudaudit.googleapis.com%2Factivity" AND timestamp>="${new Date(c.lo_time).toISOString()}" AND timestamp<"${new Date(c.hi_time).toISOString()}"`;
    do { const pg2 = demoLogEntries({ projectId: c.project_id, filter, pageToken: tok }, 1000); want += pg2.entries.length; tok = pg2.nextPageToken || ''; } while (tok);
    const got = await one(`SELECT COALESCE(sum(count + denied), 0)::int n FROM gcp_activity_daily WHERE project_ref = $1`, [c.project_ref]);
    assert.equal(got.n, want, c.project_id);
    assert.equal(Number(c.entries_read), want, c.project_id);
    const sum = await one(`SELECT COALESCE(sum(count + denied), 0)::int n FROM gcp_usage_summary WHERE project_ref = $1`, [c.project_ref]);
    assert.equal(sum.n, want, `${c.project_id} summary`);
  }
  // storage counters equal real row counts
  for (const u of (await db.query('SELECT * FROM gcp_usage_projects')).rows) {
    const real = await usage.recountProject(u.id);
    assert.deepEqual([u.daily_rows, u.summary_rows], [real.daily, real.summary]);
  }
  // nothing is due again until the next catch-up
  assert.equal(await tick(), null);
});

test('reading again later only adds the new minutes; a window whose lease was lost writes nothing', async () => {
  const before = await one('SELECT sum(count + denied)::int n FROM gcp_activity_daily');
  await db.query(`UPDATE gcp_log_cursors SET run_after = now()`);
  await drainUsage();
  const again = await one('SELECT sum(count + denied)::int n FROM gcp_activity_daily');
  assert.ok(again.n - before.n <= 3, `${again.n - before.n} added in a minute`);
  // a lease that ran out: the commit refuses and the cursor does not move
  await db.query(`UPDATE gcp_log_cursors SET run_after = now(), hi_time = hi_time - interval '2 hours'`);
  const cur = await usage.claimCursor('w1');
  await db.query(`UPDATE gcp_log_cursors SET lease_by = 'w2' WHERE project_ref = $1 AND log = $2`, [cur.project_ref, cur.log]);
  const w = usage.nextWindow(cur, { lookbackDays: 3 });
  const read = await usage.readWindow(gcpScan.gcpGateway({}), { projectId: cur.project_id, log: cur.log, from: w.from, to: w.to });
  assert.equal((await usage.commitWindow(cur, w, read)).lost, true);
  assert.equal((await one('SELECT sum(count + denied)::int n FROM gcp_activity_daily')).n, again.n);
  await db.query(`UPDATE gcp_log_cursors SET lease_until = NULL, lease_by = NULL, hi_time = hi_time + interval '2 hours'`);
});

test('identities: used, unused and unconfirmed; denied calls apart; usage through a group shows up', async () => {
  const lake = (await owner.get('/api/gcp/principals?q=lake-sync')).json.items[0];
  assert.ok(lake.usage.used >= 3 && lake.usage.unused > 0 && lake.usage.unconfirmed > 0, JSON.stringify(lake.usage));
  const u = (await owner.get(`/api/gcp/principals/${lake.id}/usage`)).json;
  assert.equal(u.enabled, true); assert.equal(u.readsKnown, false);
  const st = Object.fromEntries(u.permissions.map((x) => [x.permission, x.status]));
  assert.equal(st['storage.objects.create'], 'used'); assert.equal(st['storage.buckets.setIamPolicy'], 'unused'); assert.equal(st['storage.objects.get'], 'unconfirmed');
  assert.ok(u.daily.length >= 2 && u.daily.every((d) => d.count >= 0));
  assert.ok(u.progress.complete >= 3);
  const vendor = (await owner.get('/api/gcp/principals?q=vendor')).json.items[0];
  const v = (await owner.get(`/api/gcp/principals/${vendor.id}/usage`)).json;
  assert.ok(v.permissions.some((x) => x.permission === 'storage.buckets.delete' && x.status === 'denied' && x.denied > 0));
  // sorted by most unused
  const byUnused = (await owner.get('/api/gcp/principals?sort=unused&limit=3')).json.items;
  assert.ok(byUnused[0].usage.unused >= byUnused[1].usage.unused);
  // the owner role's thousands of permissions come back capped per status
  const alice = (await owner.get('/api/gcp/principals?q=alice')).json.items[0];
  const a = (await owner.get(`/api/gcp/principals/${alice.id}/usage`)).json;
  assert.equal(a.capped, true); assert.ok(a.counts.unused > 1000 && a.permissions.length <= 3000);
  assert.ok(a.permissions.some((x) => x.permission === 'iam.workloadIdentityPools.update' && x.status === 'used'));
});

test('Data Access turned on: reads become known, and a new cursor backfills just that log', async () => {
  await owner.patch(`/api/gcp/connections/${conn}`, { usage: { enabled: true, lookbackDays: 3, dataAccess: true } });
  assert.equal((await one(`SELECT count(*)::int n FROM gcp_log_cursors WHERE log = 'data_access'`)).n, 3);
  await drainUsage();
  const lake = (await owner.get('/api/gcp/principals?q=lake-sync')).json.items[0];
  const u = (await owner.get(`/api/gcp/principals/${lake.id}/usage`)).json;
  assert.equal(u.readsKnown, true);
  assert.equal(u.permissions.find((x) => x.permission === 'storage.objects.get').status, 'used');
  assert.equal(lake.usage.unconfirmed, 0);
});

test('storage per project: on the connection, on the Database page, adding up to the tables', async () => {
  const c = (await owner.get(`/api/gcp/connections/${conn}/usage`)).json;
  assert.equal(c.projects.length, 3);
  assert.ok(c.projects.every((p) => p.bytes > 0 && p.logs.length === 2 && p.logs.every((l) => l.coverage === 1 && !l.error)));
  const list = (await owner.get('/api/gcp/connections')).json.items[0];
  assert.equal(list.usageProgress.cursors, 6); assert.equal(list.usageProgress.complete, 6); assert.ok(list.usageProgress.bytes > 0);
  const d = (await owner.get('/api/ops/database')).json;
  assert.equal(d.gcpUsage.projects.length, 3);
  const sum = d.gcpUsage.projects.reduce((a, p) => a + p.bytes, 0);
  assert.ok(Math.abs(sum - d.gcpUsage.total) <= 3, `${sum} vs ${d.gcpUsage.total}`);
  await usage.usageStorage({ save: true });
  assert.ok((await one('SELECT min(bytes_est)::bigint b FROM gcp_usage_projects')).b > 0);
});

test('a missing permission is shown on the project and retried hourly, without failing the others', async () => {
  await db.query(`UPDATE gcp_log_cursors SET run_after = now(), hi_time = hi_time - interval '1 hour'`);
  const refusing = (c) => ({ ...gcpScan.gcpGateway(c), async logEntries() { throw Object.assign(new Error('PERMISSION_DENIED'), { status: 403 }); } });
  const r = await tick({ gwFor: refusing });
  assert.equal(r.status, 403); assert.match(r.error, /logging\.logEntries\.list/);
  const k = await one(`SELECT *, EXTRACT(EPOCH FROM run_after - now())::int AS wait FROM gcp_log_cursors WHERE last_error IS NOT NULL`);
  assert.ok(k.wait > 3000 && k.errors_in_row === 1);
  const c = (await owner.get(`/api/gcp/connections/${conn}/usage`)).json;
  assert.equal(c.projects.flatMap((p) => p.logs).filter((l) => l.error).length, 1);
  // the next good read clears it
  await db.query(`UPDATE gcp_log_cursors SET run_after = now()`);
  await drainUsage();
  assert.equal((await one(`SELECT count(*)::int n FROM gcp_log_cursors WHERE last_error IS NOT NULL OR errors_in_row > 0`)).n, 0);
});

test('a new IAM scan keeps the usage counts; turning it off stops reading but keeps the data', async () => {
  await db.query('UPDATE gcp_connections SET next_scan_at = now()');
  assert.equal((await gcpScan.gcpTick('w1')).ok, true);
  assert.ok((await owner.get('/api/gcp/principals?q=lake-sync')).json.items[0].usage.used >= 3);
  await owner.patch(`/api/gcp/connections/${conn}`, { usage: { enabled: false, lookbackDays: 3, dataAccess: true } });
  assert.equal((await one('SELECT count(*)::int n FROM gcp_log_cursors')).n, 0);
  assert.ok((await one('SELECT count(*)::int n FROM gcp_activity_daily')).n > 0);
  assert.equal((await owner.get('/api/gcp/principals?q=lake-sync')).json.items[0].usage, null);
  assert.equal((await owner.get(`/api/gcp/principals/${(await owner.get('/api/gcp/principals?q=lake-sync')).json.items[0].id}/usage`)).json.enabled, false);
  // back on: the data is still there, so only the gap is read
  await owner.patch(`/api/gcp/connections/${conn}`, { usage: { enabled: true, lookbackDays: 3, dataAccess: false } });
  assert.equal((await one('SELECT count(*)::int n FROM gcp_log_cursors')).n, 3);
});

test('the read budget is shared: an empty bucket says how long to wait', async () => {
  const id = conn;
  await db.query('DELETE FROM gcp_read_budget');
  let ok = 0, wait = 0;
  for (let i = 0; i < 15; i++) { const w = await usage.takeRead(id, 60); if (w === 0) ok++; else wait = w; }
  assert.equal(ok, 10);                                                                        // a burst of 10, then 1 a second
  assert.ok(wait > 0 && wait <= 1100, String(wait));
});
