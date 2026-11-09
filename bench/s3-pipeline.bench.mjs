// Where does an S3-trail backfill spend its time? Measures each stage of the current pipeline on synthetic,
// realistically shaped CloudTrail records, plus the cost of one database round trip against a batched write.
//   su postgres -s /bin/bash -c "node bench/s3-pipeline.bench.mjs [events]"
// Runs a throwaway Postgres with fsync off on localhost: real deployments (Docker network, fsync on) are slower,
// so the database figures here are an upper bound.
import crypto from 'node:crypto';
import { gzipSync } from 'node:zlib';
import { Readable } from 'node:stream';
import { startPg } from '../test/helpers/pg.js';

const N = Number(process.argv[2] || 20000);
const ACCT = '210987654321';
const uuid = () => crypto.randomUUID();
const pick = (a, r) => a[Math.floor(r() * a.length)];
let seed = 7; const rnd = () => ((seed = (seed * 1103515245 + 12345) % 2147483648) / 2147483648);

// ---- synthetic CloudTrail records: a busy account's mix ----
const ROLES = Array.from({ length: 390 }, (_, i) => `role-${i}-${i % 3 ? 'app' : 'AWSReservedSSO_Eng_f974d1ae'}`);
const ACTIVE = ROLES.slice(0, 60);
const CALLS = [['ec2', 'DescribeInstances'], ['ec2', 'DescribeSubnets'], ['ecs', 'DescribeServices'], ['ssm', 'UpdateInstanceInformation'], ['kms', 'Decrypt'],
  ['logs', 'DescribeLogGroups'], ['s3', 'GetBucketLocation'], ['secretsmanager', 'GetSecretValue'], ['elasticloadbalancing', 'DescribeTargetHealth'], ['iam', 'GetRole'],
  ['cloudwatch', 'GetMetricData'], ['autoscaling', 'DescribeAutoScalingGroups'], ['eks', 'DescribeCluster'], ['ec2', 'CreateTags'], ['lambda', 'GetFunction']];
const sessions = ACTIVE.map((r) => ({ role: r, key: 'ASIA' + crypto.randomBytes(8).toString('hex').toUpperCase(), left: 50 + Math.floor(rnd() * 150) }));
const t0 = Date.parse('2026-08-13T00:00:00Z');
function record(i) {
  const t = new Date(t0 + i * 1000).toISOString().replace('.000', '');
  const base = { eventVersion: '1.10', eventTime: t, awsRegion: 'ap-southeast-1', requestID: uuid(), eventID: uuid(), eventType: 'AwsApiCall', managementEvent: true,
    recipientAccountId: ACCT, eventCategory: 'Management', sourceIPAddress: `10.20.${i % 250}.${i % 200}`,
    userAgent: 'aws-sdk-go-v2/1.30.3 os/linux lang/go#1.22.5 md/GOOS#linux md/GOARCH#amd64 api/ec2#1.170.0 m/E,g',
    tlsDetails: { tlsVersion: 'TLSv1.3', cipherSuite: 'TLS_AES_128_GCM_SHA256', clientProvidedHostHeader: 'ec2.ap-southeast-1.amazonaws.com' } };
  const r = rnd();
  if (r < 0.15) {   // an AWS service acting on its own (KMS for S3, EC2 assuming instance roles): not a role's call
    return { ...base, userIdentity: { type: 'AWSService', invokedBy: 's3.amazonaws.com' }, eventSource: 'kms.amazonaws.com', eventName: 'Decrypt', readOnly: true,
      requestParameters: { encryptionContext: { 'aws:s3:arn': `arn:aws:s3:::bucket-${i % 40}/key/${i}` }, encryptionAlgorithm: 'SYMMETRIC_DEFAULT' }, responseElements: null,
      resources: [{ accountId: ACCT, type: 'AWS::KMS::Key', ARN: `arn:aws:kms:ap-southeast-1:${ACCT}:key/${uuid()}` }] };
  }
  if (r < 0.2) {    // a role being entered
    const s = pick(sessions, rnd); s.key = 'ASIA' + crypto.randomBytes(8).toString('hex').toUpperCase(); s.left = 50 + Math.floor(rnd() * 150);
    return { ...base, eventSource: 'sts.amazonaws.com', eventName: 'AssumeRole', readOnly: true,
      userIdentity: { type: 'AWSService', invokedBy: 'ec2.amazonaws.com' },
      requestParameters: { roleArn: `arn:aws:iam::${ACCT}:role/${s.role}`, roleSessionName: `i-${crypto.randomBytes(8).toString('hex')}`, durationSeconds: 3600 },
      responseElements: { credentials: { accessKeyId: s.key, sessionToken: 'IQoJb3JpZ2luX2VjE' + 'x'.repeat(600) /* synthetic, not a real token: gitleaks:allow */, expiration: 'Aug 13, 2026, 2:00:00 AM' },
        assumedRoleUser: { assumedRoleId: `AROA${i}:i-0`, arn: `arn:aws:sts::${ACCT}:assumed-role/${s.role}/i-0` } } };
  }
  const s = pick(sessions, rnd);
  const [svc, name] = pick(CALLS, rnd);
  const hasRes = svc === 'kms' || svc === 'secretsmanager' || svc === 'lambda';
  return { ...base, eventSource: `${svc}.amazonaws.com`, eventName: name, readOnly: !name.startsWith('Create'),
    userIdentity: { type: 'AssumedRole', principalId: `AROAEXAMPLE:${s.role}-session`, arn: `arn:aws:sts::${ACCT}:assumed-role/${s.role}/${s.role}-session`,
      accountId: ACCT, accessKeyId: s.key, sessionContext: { sessionIssuer: { type: 'Role', principalId: 'AROAEXAMPLE', arn: `arn:aws:iam::${ACCT}:role/${s.role}`, accountId: ACCT, userName: s.role },
        attributes: { creationDate: t, mfaAuthenticated: 'false' }, ec2RoleDelivery: '2.0' } },
    requestParameters: { filterSet: { items: [{ name: 'tag:Name', valueSet: { items: [{ value: `svc-${i % 30}` }] } }] }, maxResults: 1000, instancesSet: {} },
    responseElements: null,
    ...(hasRes ? { resources: [{ accountId: ACCT, type: 'AWS::KMS::Key', ARN: `arn:aws:kms:ap-southeast-1:${ACCT}:key/k-${i % 25}` }] } : {}) };
}

const ms = (a) => Number(process.hrtime.bigint() - a) / 1e6;
const rate = (n, t) => `${Math.round(n / (t / 1000)).toLocaleString('en-US')}/s`;

const records = Array.from({ length: N }, (_, i) => record(i));
const json = JSON.stringify({ Records: records });
const gz = gzipSync(Buffer.from(json));
console.log(`${N.toLocaleString('en-US')} records, ${(json.length / 1e6).toFixed(1)} MB JSON (${Math.round(json.length / N)} B/record), ${(gz.length / 1e6).toFixed(2)} MB gzipped\n`);

const { streamRecords } = await import('../src/aws/trailStream.js');
const { parseEvent } = await import('../src/analyzer/events.js');
const chunks = []; for (let i = 0; i < gz.length; i += 65536) chunks.push(gz.subarray(i, i + 65536));

// 1. CPU: unzip + split + JSON.parse, then parseEvent
let t = process.hrtime.bigint(); let n = 0;
await streamRecords(Readable.from(chunks), () => { n++; });
const tParse = ms(t);
t = process.hrtime.bigint(); const parsed = [];
await streamRecords(Readable.from(chunks), (r) => parsed.push(parseEvent(r)));
const tParseEv = ms(t);
console.log(`1. unzip + parse records          ${tParse.toFixed(0).padStart(6)} ms  ${rate(n, tParse)}`);
console.log(`   ... + parseEvent                ${tParseEv.toFixed(0).padStart(6)} ms  ${rate(n, tParseEv)}  (parseEvent alone ~${rate(n, tParseEv - tParse)})`);

// 2. Database: the current per-event write path
const pg = await startPg(54411);
const db = await import('../src/db.js');
await (await import('../src/migrate.js')).migrate(() => {});
const acc = (await db.query(`INSERT INTO cloud_accounts(account_id, name, role_arn, regions, status) VALUES ($1,'bench','x','{ap-southeast-1}','connected') RETURNING id`, [ACCT])).rows[0].id;
const roleRows = [];
for (const name of ROLES) roleRows.push((await db.query(`INSERT INTO roles(account_id, arn, name, kind) VALUES ($1,$2,$3,'custom') RETURNING id, arn, name, trust_policy`, [acc, `arn:aws:iam::${ACCT}:role/${name}`, name])).rows[0]);
const roles = { byArn: new Map(roleRows.map((r) => [r.arn, r])), byName: new Map(roleRows.map((r) => [r.name, r])) };
const { applyEvents } = await import('../src/scanner/events.js');
const { config } = await import('../src/config.js');

const usable = parsed.filter((e) => e.type !== 'ignore').sort((x, y) => (x.type === y.type ? x.time - y.time : x.type === 'assume' ? -1 : 1));
const pool = db.pool;
// counts queries by wrapping the client
async function timed(label, events, retentionDays) {
  config.scanner.sessionRetentionDays = retentionDays;   // old history: no session replay rows; recent: one row per call
  const c = await pool.connect(); let qn = 0; const real = c.query.bind(c); c.query = (...a) => { qn++; return real(...a); };
  const s = process.hrtime.bigint();
  await real('BEGIN'); await applyEvents(c, events, roles, acc, {}); await real('COMMIT');
  const tt = ms(s); c.query = real; c.release();
  console.log(`${label.padEnd(33)}${tt.toFixed(0).padStart(6)} ms  ${rate(events.length, tt)}  ${qn.toLocaleString('en-US')} queries (${(qn / events.length).toFixed(2)} per event, ${(tt * 1000 / qn).toFixed(0)} µs each)`);
  return tt;
}
console.log(`\n   ${usable.length.toLocaleString('en-US')} of ${N.toLocaleString('en-US')} records belong to roles and are written`);
// first pass: events older than session replay (backfill of last quarter); shift times so they are "old"
const old = usable.map((e) => ({ ...e, time: new Date(e.time.getTime() - 60 * 864e5) }));
await timed('2. write path, old history', old, 30);
const recent = usable.map((e) => ({ ...e, id: e.id + 'r', time: new Date(Date.now() - 2 * 864e5 + (e.time - t0)) }));
await timed('   write path, last 30 days', recent, 30);

// 3. one round trip per row vs one statement for all rows
await db.query(`CREATE TEMP TABLE IF NOT EXISTS x(a text, b timestamptz, c int)`).catch(() => {});
const c = await pool.connect();
await c.query(`CREATE TEMP TABLE bench_rows(a text, b timestamptz, c int)`);
const rows = usable.slice(0, 10000);
t = process.hrtime.bigint();
await c.query('BEGIN'); for (const e of rows) await c.query(`INSERT INTO bench_rows VALUES ($1,$2,$3)`, [e.id, e.time, 1]); await c.query('COMMIT');
const tRow = ms(t);
t = process.hrtime.bigint();
await c.query(`INSERT INTO bench_rows SELECT * FROM unnest($1::text[], $2::timestamptz[], $3::int[])`, [rows.map((e) => e.id), rows.map((e) => e.time), rows.map(() => 1)]);
const tBatch = ms(t);
c.release();
console.log(`\n3. 10,000 rows, one INSERT each    ${tRow.toFixed(0).padStart(6)} ms  ${rate(rows.length, tRow)}`);
console.log(`   10,000 rows, one INSERT total   ${tBatch.toFixed(0).padStart(6)} ms  ${rate(rows.length, tBatch)}  (${Math.round(tRow / tBatch)}x)`);

await db.closePool(); await pg.stop();
