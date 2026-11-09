// End to end: the S3 trail reader on an in-memory bucket of realistic files, against a throwaway Postgres.
//   su postgres -s /bin/bash -c "TRAIL_PARSERS=0 node bench/trail-reader.bench.mjs"     (parse on the main thread)
//   su postgres -s /bin/bash -c "node bench/trail-reader.bench.mjs [files] [records/file] [age days]"
//   age 20 = inside the 30-day session replay window (every call stored for the timeline); 60 = older history
import crypto from 'node:crypto';
import { gzipSync } from 'node:zlib';
import { startPg } from '../test/helpers/pg.js';

const FILES = Number(process.argv[2] || 120), PER = Number(process.argv[3] || 1000), AGE_DAYS = Number(process.argv[4] || 20);   // 20: within session replay; 60: older history
const ACCT = '210987654321', DAY = 864e5, MIN = 60e3;
const NOW = Date.now(), START = NOW - AGE_DAYS * DAY;
let seed = 11; const rnd = () => ((seed = (seed * 1103515245 + 12345) % 2147483648) / 2147483648);
const roles = Array.from({ length: 60 }, (_, i) => `role-${i}`);
const sessions = roles.map((r) => ({ r, k: 'ASIA' + crypto.randomBytes(8).toString('hex').toUpperCase() }));
const svcs = [['ec2', 'DescribeInstances'], ['ssm', 'UpdateInstanceInformation'], ['kms', 'Decrypt'], ['logs', 'DescribeLogGroups'], ['ecs', 'DescribeServices'], ['s3', 'GetBucketLocation']];
function record(t, region) {
  const base = { eventVersion: '1.10', eventID: crypto.randomUUID(), requestID: crypto.randomUUID(), eventTime: new Date(t).toISOString(), awsRegion: region, sourceIPAddress: '10.20.1.2',
    userAgent: 'aws-sdk-go-v2/1.30.3 os/linux lang/go#1.22.5 md/GOOS#linux md/GOARCH#amd64 api/ec2#1.170.0 m/E,g', recipientAccountId: ACCT, eventType: 'AwsApiCall', managementEvent: true,
    tlsDetails: { tlsVersion: 'TLSv1.3', cipherSuite: 'TLS_AES_128_GCM_SHA256', clientProvidedHostHeader: `ec2.${region}.amazonaws.com` } };
  const x = rnd();
  if (x < 0.15) return { ...base, eventSource: 'kms.amazonaws.com', eventName: 'Decrypt', userIdentity: { type: 'AWSService', invokedBy: 's3.amazonaws.com' }, requestParameters: { encryptionContext: { 'aws:s3:arn': 'arn:aws:s3:::b/k' } } };
  const s = sessions[Math.floor(rnd() * sessions.length)];
  if (x < 0.2) { s.k = 'ASIA' + crypto.randomBytes(8).toString('hex').toUpperCase();
    return { ...base, eventSource: 'sts.amazonaws.com', eventName: 'AssumeRole', userIdentity: { type: 'AWSService', invokedBy: 'ec2.amazonaws.com' },
      requestParameters: { roleArn: `arn:aws:iam::${ACCT}:role/${s.r}`, roleSessionName: 'i-0' }, responseElements: { credentials: { accessKeyId: s.k, sessionToken: 'x'.repeat(600) } } }; }
  const [svc, name] = svcs[Math.floor(rnd() * svcs.length)];
  return { ...base, eventSource: `${svc}.amazonaws.com`, eventName: name,
    userIdentity: { type: 'AssumedRole', accessKeyId: s.k, arn: `arn:aws:sts::${ACCT}:assumed-role/${s.r}/sess`, accountId: ACCT,
      sessionContext: { sessionIssuer: { type: 'Role', arn: `arn:aws:iam::${ACCT}:role/${s.r}`, userName: s.r }, attributes: { mfaAuthenticated: 'false' } } },
    requestParameters: { filterSet: { items: [{ name: 'tag:Name', valueSet: { items: [{ value: 'svc' }] } }] }, maxResults: 1000 }, responseElements: null,
    ...(svc === 'kms' ? { resources: [{ ARN: `arn:aws:kms:${region}:${ACCT}:key/k-1` }] } : {}) };
}
// files across 3 regions, 5 minutes apart, older history (beyond session replay)
const regions = ['ap-southeast-1', 'ap-southeast-3', 'us-east-1'];
const files = [];
for (let i = 0; i < FILES; i++) {
  const region = regions[i % 3], time = START + Math.floor(i / 3) * 5 * MIN;
  const recs = Array.from({ length: PER }, (_, j) => record(time - 5 * MIN + (j * 300000) / PER, region));
  const stamp = new Date(time).toISOString().replace(/[-:]/g, '').slice(0, 13) + 'Z';
  files.push({ region, time, key: `AWSLogs/${ACCT}/CloudTrail/${region}/${new Date(time).toISOString().slice(0, 10).replace(/-/g, '/')}/${ACCT}_CloudTrail_${region}_${stamp}_X${i}.json.gz`,
    gz: gzipSync(Buffer.from(JSON.stringify({ Records: recs }))) });
}
const mb = files.reduce((s, f) => s + f.gz.length, 0) / 1048576;
const gw = {
  async listTrailRegions() { return regions; },
  async listTrailDay({ region, day }) { const d = day.getTime(); return files.filter((f) => f.region === region && f.time >= d && f.time < d + DAY).map((f) => ({ key: f.key, size: f.gz.length, time: f.time })); },
  async getTrailFile(k) { return Buffer.from(files.find((f) => f.key === k).gz); },
};
const pg = await startPg(54450);
const db = await import('../src/db.js');
await (await import('../src/migrate.js')).migrate(() => {});
const a = (await db.query(`INSERT INTO cloud_accounts(account_id, name, role_arn, regions, status, event_source, s3_bucket, lookback_days) VALUES ($1,'b','x',$2,'connected','s3','b',90) RETURNING *`, [ACCT, regions])).rows[0];
for (const r of roles) await db.query(`INSERT INTO roles(account_id, arn, name, kind) VALUES ($1,$2,$3,'custom')`, [a.id, `arn:aws:iam::${ACCT}:role/${r}`, r]);
const { readTrail } = await import('../src/scanner/trailReader.js');
const { parserCount, closeDecoders } = await import('../src/scanner/decode.js');
const t0 = Date.now();
const r = await readTrail({ ctx: { job: {}, log: async () => {}, progress: async () => {}, alive() {} }, account: a, gw, now: NOW });
const ms = Date.now() - t0;
console.log(`${FILES} files (${mb.toFixed(1)} MB gz), ${(FILES * PER).toLocaleString('en-US')} records, ${r.events.toLocaleString('en-US')} written · ${parserCount()} parser thread(s) · ${(ms / 1000).toFixed(1)} s · ${Math.round((FILES * PER) / (ms / 1000)).toLocaleString('en-US')} records/s, ${Math.round(r.events / (ms / 1000)).toLocaleString('en-US')} events/s written`);
await closeDecoders(); await db.closePool(); await pg.stop();
