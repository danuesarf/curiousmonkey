import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { gzipSync } from 'node:zlib';
import { startPg } from './helpers/pg.js';

process.env.AWS_MODE = 'demo';
let pg, db, tr;
before(async () => {
  pg = await startPg(54440);
  db = await import('../src/db.js');
  await (await import('../src/migrate.js')).migrate(() => {});
  tr = await import('../src/scanner/trailReader.js');
});
after(async () => { await db.closePool(); await pg.stop(); });

const ACCT = '111122223333';
const MIN = 60e3, DAY = 864e5;
const NOW = Date.UTC(2026, 10, 8, 12, 0);
const iso = (t) => new Date(t).toISOString();
const ROLE = `arn:aws:iam::${ACCT}:role/app-role`;

// ---- a fake bucket: files are { region, time, records }, listed and served like the real gateway ----
function bucket(files) {
  const key = (f, i) => `AWSLogs/${ACCT}/CloudTrail/${f.region}/${iso(f.time).slice(0, 10).replace(/-/g, '/')}/${ACCT}_CloudTrail_${f.region}_${iso(f.time).replace(/[-:]/g, '').slice(0, 13)}Z_F${String(i).padStart(5, '0')}.json.gz`;
  const all = files.map((f, i) => ({ ...f, key: key(f, i) }));
  const gets = [];
  return {
    gets, add(f) { all.push({ ...f, key: key(f, all.length) }); },
    async listTrailRegions() { return [...new Set(all.map((f) => f.region))]; },
    async listTrailDay({ region, day }) {
      const d0 = day.getTime();
      return all.filter((f) => f.region === region && f.time >= d0 && f.time < d0 + DAY)
        .map((f) => ({ key: f.key, size: 1000, time: f.time })).sort((a, b) => (a.key < b.key ? -1 : 1));
    },
    async getTrailFile(k) { gets.push(k); return gzipSync(Buffer.from(JSON.stringify({ Records: all.find((f) => f.key === k).records }))); },
  };
}
let n = 0;
const assume = (t, key, who = 'dhimas@kbi') => ({ eventID: `a-${n++}`, eventTime: iso(t), eventSource: 'sts.amazonaws.com', eventName: 'AssumeRoleWithSAML', awsRegion: 'us-east-1',
  userIdentity: { type: 'SAMLUser', principalId: `AROA:sso:${who}` }, requestParameters: { roleArn: ROLE, roleSessionName: who }, responseElements: { credentials: { accessKeyId: key } } });
const call = (t, key, region, name = 'DescribeInstances') => ({ eventID: `c-${n++}`, eventTime: iso(t), eventSource: 'ec2.amazonaws.com', eventName: name, awsRegion: region,
  userIdentity: { type: 'AssumedRole', accessKeyId: key, arn: `arn:aws:sts::${ACCT}:assumed-role/app-role/dhimas@kbi`, sessionContext: { sessionIssuer: { type: 'Role', arn: ROLE } } } });

async function account(regions, extra = {}) {
  const a = (await db.query(`INSERT INTO cloud_accounts(account_id, name, role_arn, regions, status, event_source, s3_bucket, lookback_days)
    VALUES ($1,'t','x',$2,'connected','s3','b',30) RETURNING *`, [extra.acct || ACCT, regions])).rows[0];
  await db.query(`INSERT INTO roles(account_id, arn, name, kind) VALUES ($1,$2,'app-role','custom')`, [a.id, ROLE]);
  return a;
}
const ctx = () => { const logs = []; return { logs, job: {}, log: async (m) => logs.push(m), progress: async () => {}, alive() {} }; };
const usage = async (a) => (await db.query(
  `SELECT p.key, sum(d.count)::int AS n FROM activity_daily d JOIN principals p ON p.id=d.principal_id JOIN roles r ON r.id=d.role_id WHERE r.account_id=$1 GROUP BY p.key ORDER BY p.key`, [a.id])).rows;
const small = { parallel: 4, aheadFiles: 8, aheadBytes: 1e9, batchEvents: 1000, batchFiles: 1 };   // every file its own batch

async function reset() { await db.query('TRUNCATE cloud_accounts CASCADE'); await db.query('TRUNCATE seen_events, role_sessions'); }

test('a session started in us-east-1 is attributed in another region, even across batch boundaries', async () => {
  await reset();
  const a = await account(['ap-southeast-1', 'us-east-1']);
  const t = NOW - 2 * DAY;
  // the AssumeRole's file (us-east-1) is delivered AFTER the file holding the session's first calls
  const gw = bucket([
    { region: 'ap-southeast-1', time: t + 6 * MIN, records: [call(t + 2 * MIN, 'ASIAKEY1', 'ap-southeast-1'), call(t + 3 * MIN, 'ASIAKEY1', 'ap-southeast-1')] },
    { region: 'us-east-1', time: t + 9 * MIN, records: [assume(t + 1 * MIN, 'ASIAKEY1')] },
    { region: 'ap-southeast-1', time: t + 30 * MIN, records: [call(t + 25 * MIN, 'ASIAKEY1', 'ap-southeast-1')] },
  ]);
  await tr.readTrail({ ctx: ctx(), account: a, gw, now: NOW, limits: small });
  assert.deepEqual(await usage(a), [{ key: 'fed:AROA:sso:dhimas@kbi', n: 3 }]);   // nobody "started before the window"
});

test('every file is read exactly once; late and newly delivered files are picked up by the next run', async () => {
  await reset();
  const a = await account(['ap-southeast-1']);
  const t = NOW - 3 * DAY;
  const gw = bucket([
    { region: 'ap-southeast-1', time: t + 10 * MIN, records: [assume(t, 'K2'), call(t + MIN, 'K2', 'ap-southeast-1')] },
    { region: 'ap-southeast-1', time: t + 3 * 60 * MIN, records: [call(t + 2 * MIN, 'K2', 'ap-southeast-1', 'DescribeVpcs')] },   // delivered 3 h late
  ]);
  await tr.readTrail({ ctx: ctx(), account: a, gw, now: NOW, limits: small });
  assert.equal((await usage(a))[0].n, 2);
  assert.equal(gw.gets.length, 2);
  // a second run reads nothing again; a file delivered since is read
  gw.add({ region: 'ap-southeast-1', time: NOW + 20 * MIN, records: [call(NOW + 5 * MIN, 'K2', 'ap-southeast-1', 'DescribeSubnets')] });
  await tr.readTrail({ ctx: ctx(), account: a, gw, now: NOW + 40 * MIN, limits: small });
  assert.equal(gw.gets.length, 3);
  assert.equal((await usage(a))[0].n, 3);
  await tr.readTrail({ ctx: ctx(), account: a, gw, now: NOW + 60 * MIN, limits: small });
  assert.equal(gw.gets.length, 3);
  const cp = (await db.query(`SELECT caught_up_at, last_event_time FROM scan_checkpoints WHERE account_id=$1 AND region='ap-southeast-1'`, [a.id])).rows[0];
  assert.ok(cp.caught_up_at && cp.last_event_time.getTime() === NOW + 60 * MIN - tr.SETTLE);
});

test('files still arriving (the last few minutes) wait for the next run', async () => {
  await reset();
  const a = await account(['ap-southeast-1']);
  const gw = bucket([{ region: 'ap-southeast-1', time: NOW - 4 * MIN, records: [assume(NOW - 6 * MIN, 'K3'), call(NOW - 5 * MIN, 'K3', 'ap-southeast-1')] }]);
  await tr.readTrail({ ctx: ctx(), account: a, gw, now: NOW, limits: small });
  assert.equal(gw.gets.length, 0);
  await tr.readTrail({ ctx: ctx(), account: a, gw, now: NOW + 15 * MIN, limits: small });
  assert.equal(gw.gets.length, 1);
  assert.equal((await usage(a))[0].n, 1);
});

test('regions with log files in the trail are read even when not configured', async () => {
  await reset();
  const a = await account(['ap-southeast-1']);
  const t = NOW - DAY;
  const gw = bucket([
    { region: 'ap-southeast-1', time: t + 5 * MIN, records: [assume(t, 'K4'), call(t + MIN, 'K4', 'ap-southeast-1')] },
    { region: 'eu-west-1', time: t + 9 * MIN, records: [call(t + 4 * MIN, 'K4', 'eu-west-1', 'RunInstances')] },
  ]);
  const c = ctx();
  await tr.readTrail({ ctx: c, account: a, gw, now: NOW, limits: small });
  assert.deepEqual((await db.query(`SELECT regions FROM cloud_accounts WHERE id=$1`, [a.id])).rows[0].regions, ['ap-southeast-1', 'eu-west-1']);
  assert.ok(c.logs.some((m) => /eu-west-1/.test(m)));
  const run = (await db.query(`SELECT d.action FROM activity_daily d JOIN roles r ON r.id=d.role_id WHERE r.account_id=$1 AND d.action='ec2:RunInstances'`, [a.id])).rows;
  assert.equal(run.length, 1);
});

test('a region someone removed stays out, even though the trail has files for it', async () => {
  await reset();
  const a = await account(['ap-southeast-1']);
  await db.query(`UPDATE cloud_accounts SET excluded_regions='{eu-west-1}' WHERE id=$1`, [a.id]);
  const acc = (await db.query('SELECT * FROM cloud_accounts WHERE id=$1', [a.id])).rows[0];
  const t = NOW - DAY;
  const gw = bucket([
    { region: 'ap-southeast-1', time: t + 5 * MIN, records: [assume(t, 'K5'), call(t + MIN, 'K5', 'ap-southeast-1')] },
    { region: 'eu-west-1', time: t + 9 * MIN, records: [call(t + 4 * MIN, 'K5', 'eu-west-1', 'RunInstances')] },
  ]);
  const c = ctx();
  await tr.readTrail({ ctx: c, account: acc, gw, now: NOW, limits: small });
  assert.deepEqual((await db.query(`SELECT regions FROM cloud_accounts WHERE id=$1`, [a.id])).rows[0].regions, ['ap-southeast-1']);
  assert.ok(c.logs.some((m) => /skipping eu-west-1/.test(m)));
  assert.equal((await db.query(`SELECT count(*)::int n FROM scan_checkpoints WHERE account_id=$1 AND region='eu-west-1'`, [a.id])).rows[0].n, 0);
  assert.ok(!gw.gets.some((k) => k.includes('/eu-west-1/')), 'its files are not downloaded');
});

test('moving over from the per-slice reader counts nothing twice', async () => {
  await reset();
  const a = await account(['ap-southeast-1']);
  const stop = NOW - 2 * DAY;                         // the old reader's last slice ended here
  await db.query(`INSERT INTO scan_checkpoints(account_id, region, source, first_event_time, last_event_time, events_read) VALUES ($1,'ap-southeast-1','s3',$2,$3,1)`,
    [a.id, new Date(NOW - 20 * DAY), new Date(stop)]);
  const gw = bucket([
    { region: 'ap-southeast-1', time: stop - 30 * MIN, records: [call(stop - 40 * MIN, 'K5', 'ap-southeast-1')] },                 // fully read before
    { region: 'ap-southeast-1', time: stop + 10 * MIN, records: [call(stop - 5 * MIN, 'K5', 'ap-southeast-1'), call(stop + 2 * MIN, 'K5', 'ap-southeast-1')] },   // half read
    { region: 'ap-southeast-1', time: stop + 2 * 60 * MIN, records: [call(stop - 50 * MIN, 'K5', 'ap-southeast-1')] },              // late, never read
  ]);
  await tr.readTrail({ ctx: ctx(), account: a, gw, now: NOW, limits: small });
  // counted now: the call after the stop, and the late one the old reader could not see
  assert.equal((await usage(a)).reduce((s, x) => s + x.n, 0), 2);
  assert.equal(gw.gets.length, 2);
});

test('memory stays bounded: downloads never run further ahead than allowed', async () => {
  await reset();
  const a = await account(['ap-southeast-1']);
  const files = [];
  for (let i = 0; i < 60; i++) files.push({ region: 'ap-southeast-1', time: NOW - DAY + i * 5 * MIN, records: [call(NOW - DAY + i * 5 * MIN - MIN, 'K6', 'ap-southeast-1')] });
  const gw = bucket(files);
  let inFlight = 0, peak = 0;
  const real = gw.getTrailFile.bind(gw);
  gw.getTrailFile = async (k) => { inFlight++; peak = Math.max(peak, inFlight); await new Promise((r) => setTimeout(r, 2)); try { return await real(k); } finally { inFlight--; } };
  await tr.readTrail({ ctx: ctx(), account: a, gw, now: NOW, limits: { parallel: 3, aheadFiles: 5, aheadBytes: 1e9, batchEvents: 10, batchFiles: 7 } });
  assert.ok(peak <= 3, `peak parallel downloads ${peak}`);
  assert.equal((await usage(a))[0].n, 60);
});
