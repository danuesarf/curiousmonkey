// Deterministic fake AWS. Events are generated from a seeded function of (role, hour), so asking for the
// same time range twice returns the same events with the same IDs. That is what lets the checkpoint and
// de-duplication logic be tested honestly.
import crypto from 'node:crypto';
import { gzipSync } from 'node:zlib';
import { buildEstate, MANAGED } from './estate.js';
import { trailDayPrefix } from '../aws/trailKeys.js';

const h32 = (s) => parseInt(crypto.createHash('sha1').update(s).digest('hex').slice(0, 8), 16);
const uuid = (s) => { const x = crypto.createHash('sha1').update(s).digest('hex'); return `${x.slice(0, 8)}-${x.slice(8, 12)}-${x.slice(12, 16)}-${x.slice(16, 20)}-${x.slice(20, 32)}`; };
const HOUR = 3600e3, DAY = 24 * HOUR;
let calls = 0;
export const resetDemoCalls = () => { calls = 0; };
export const demoNow = () => new Date(process.env.DEMO_NOW || Date.now());

export function demoGateway(account) {
  const acct = account.account_id;
  const estate = buildEstate(acct);
  const region0 = account.regions[0];

  function eventsForHour(hourStart, region) {
    const out = [];
    if (region !== region0) return out;
    const day = new Date(hourStart).getUTCDay();
    for (const role of estate) {
      for (const pr of role.principals) {
        if (!pr.hours.includes(new Date(hourStart).getUTCHours())) continue;
        if (pr.days && !pr.days.includes(day)) continue;
        const dayKey = Math.floor(hourStart / DAY);
        const keyFor = (roleName, prKey) => 'ASIA' + crypto.createHash('sha1').update(`${acct}${roleName}${prKey}${dayKey}${new Date(hourStart).getUTCHours()}`).digest('hex').slice(0, 16).toUpperCase();
        const ak = keyFor(role.name, pr.key);
        const t0 = hourStart + 5000 + (pr.viaRole ? (pr.viaPr?.startsWith('role:') ? 40000 : 20000) : 0); // a chained session starts after its caller's
        const caller = pr.federated ? { type: pr.type, principalId: 'AROA:' + pr.key, accountId: acct }
          : pr.invokedBy ? { type: 'AWSService', invokedBy: pr.invokedBy }
          : pr.viaRole ? { type: 'AssumedRole', arn: pr.arn, accountId: acct, accessKeyId: keyFor(pr.viaRole, pr.viaPr), // role chaining: the caller's own session key
            sessionContext: { sessionIssuer: { type: 'Role', arn: `arn:aws:iam::${acct}:role/${pr.viaRole}`, userName: pr.viaRole } } }
          : { type: pr.type, arn: pr.arn, accountId: pr.accountId || acct, userName: pr.arn?.split('/').pop() };
        const assumeName = pr.federated ? (pr.type === 'WebIdentityUser' ? 'AssumeRoleWithWebIdentity' : 'AssumeRoleWithSAML') : 'AssumeRole';
        out.push({
          eventID: uuid(`${role.name}|${pr.key}|${hourStart}|assume`), eventTime: new Date(t0).toISOString(), eventSource: 'sts.amazonaws.com', eventName: assumeName,
          awsRegion: region0, sourceIPAddress: pr.invokedBy || (pr.key.startsWith('user:888') ? '203.0.113.77' : '10.20.0.15'), userAgent: 'demo',
          userIdentity: caller, requestParameters: { roleArn: role.arn, roleSessionName: pr.sessions + '-' + dayKey },
          responseElements: { credentials: { accessKeyId: ak } },
          additionalEventData: { MFAAuthenticated: pr.type === 'SAMLUser' || pr.type === 'IAMUser' ? 'true' : 'false' },
        });
        for (const u of role.usage.filter((x) => x.p === pr.key)) {
          for (let i = 0; i < u.perHour; i++) {
            const t = t0 + (i + 1) * 60000 + (h32(`${role.name}${u.name}${hourStart}${i}`) % 30000);
            const denied = u.deniedEvery && i % u.deniedEvery === 2;
            out.push({
              eventID: uuid(`${role.name}|${u.name}|${hourStart}|${i}`), eventTime: new Date(t).toISOString(), eventSource: u.src, eventName: u.name, awsRegion: region0,
              sourceIPAddress: '10.20.0.15', userAgent: 'demo', errorCode: denied ? 'AccessDenied' : undefined,
              userIdentity: { type: 'AssumedRole', accessKeyId: ak, arn: `arn:aws:sts::${acct}:assumed-role/${role.name}/${pr.sessions}-${dayKey}`,
                sessionContext: { sessionIssuer: { type: 'Role', arn: role.arn, userName: role.name } } },
              requestParameters: u.params || {}, resources: u.res ? [{ ARN: u.res }] : undefined,
            });
          }
        }
      }
    }
    return out;
  }

  const FIVE = 5 * 60e3;
  const dayCache = new Map();
  const deliveredAt = (e) => {
    const t = new Date(e.eventTime).getTime();
    const late = h32(`late${e.eventID}`) % 200 === 0;
    return t + (late ? (75 + (h32(e.eventID) % 45)) * 60e3 : (2 + (h32(e.eventID) % 7)) * 60e3);
  };
  // the files delivered on one UTC day in one region: Map key -> { key, time, records }
  function trailDay(region, day) {
    const d0 = Date.UTC(day.getUTCFullYear(), day.getUTCMonth(), day.getUTCDate());
    const ck = `${region}|${d0}`;
    if (dayCache.has(ck)) return dayCache.get(ck);
    const files = new Map();
    const now = demoNow().getTime();
    for (let h = d0 - 3 * HOUR; h < d0 + DAY; h += HOUR) {
      for (const e of eventsForHour(h, region)) {
        const ft = Math.ceil(deliveredAt(e) / FIVE) * FIVE;
        if (ft < d0 || ft >= d0 + DAY || ft > now) continue;
        const stamp = new Date(ft).toISOString().replace(/[-:]/g, '').slice(0, 13) + 'Z';
        const key = `${trailDayPrefix(account, region, new Date(ft))}${acct}_CloudTrail_${region}_${stamp}_${(h32(region + ft) >>> 0).toString(36).padStart(7, '0').slice(0, 7).toUpperCase()}DEMO.json.gz`;
        const f = files.get(key) || { key, time: ft, records: [] };
        f.records.push(e); files.set(key, f);
      }
    }
    if (d0 + DAY < now - 6 * HOUR) dayCache.set(ck, files);   // a finished day never changes
    return files;
  }

  return {
    mode: 'demo',
    async verify() { return { ok: true, accountId: acct, arn: account.role_arn }; },
    async listRoles() {
      return estate.map((r) => ({ arn: r.arn, name: r.name, path: r.path, createDate: new Date(demoNow() - 400 * DAY), trustPolicy: r.trust, boundaryArn: null }));
    },
    async getRoleDetail(name) {
      const r = estate.find((x) => x.name === name);
      const used = r.lastUsedDaysAgo != null ? new Date(demoNow() - r.lastUsedDaysAgo * DAY) : r.usage.length ? new Date(demoNow() - 2 * HOUR) : null;
      return { lastUsedAt: used, lastUsedRegion: used ? region0 : null, tags: r.kind === 'custom' ? { team: 'platform' } : {} };
    },
    async getRolePolicies(name) {
      const r = estate.find((x) => x.name === name);
      return { inline: r.inline, attached: r.attached.map((a) => ({ arn: a, name: a.split('/').pop(), awsManaged: a.startsWith('arn:aws:iam::aws:') })) };
    },
    async getManagedPolicy(arn) {
      if (!MANAGED[arn]) throw Object.assign(new Error('NoSuchEntity'), { retryable: false });
      return { versionId: 'v1', document: MANAGED[arn] };
    },
    async getAdvisor(roleArn) {
      const r = estate.find((x) => x.arn === roleArn);
      return Object.entries(r.advisor || {}).map(([service, d]) => ({ service, lastAuthenticated: d == null ? null : new Date(demoNow() - d * DAY) }));
    },
    async lookupEventsPage({ region, start, end, token }) {
      if (globalThis.__demoFailAt && ++calls === globalThis.__demoFailAt) {
        throw Object.assign(new Error('Rate exceeded'), { name: 'ThrottlingException' });   // test hook: simulate a throttle mid-scan
      }
      const all = [];
      for (let h = Math.floor(start.getTime() / HOUR) * HOUR; h < end.getTime(); h += HOUR) {
        for (const e of eventsForHour(h, region)) {
          const t = new Date(e.eventTime).getTime();
          if (t >= start.getTime() && t < end.getTime()) all.push(e);
        }
      }
      all.sort((a, b) => b.eventTime.localeCompare(a.eventTime));   // LookupEvents returns newest first
      const from = token ? Number(token) : 0;
      const next = from + 50;
      return { events: all.slice(from, next), nextToken: next < all.length ? String(next) : null };
    },
    // ---- S3 trail, simulated as files: each event is delivered a few minutes after it happens (1 in 200 over an
    // hour late), files are cut every 5 minutes and only exist once delivered. Deterministic, like the events.
    async listTrailRegions() { return [...account.regions]; },
    async listTrailDay({ region, day }) {
      return [...trailDay(region, day).values()].map((f) => ({ key: f.key, size: f.records.length * 900, time: f.time })).sort((x, y) => (x.key < y.key ? -1 : 1));
    },
    async getTrailFile(key) {
      const m = key.match(/CloudTrail\/([a-z0-9-]+)\/(\d{4})\/(\d{2})\/(\d{2})\//);
      const f = trailDay(m[1], new Date(Date.UTC(+m[2], +m[3] - 1, +m[4]))).get(key);
      if (!f) throw Object.assign(new Error(`NoSuchKey: ${key}`), { name: 'NoSuchKey' });
      return gzipSync(Buffer.from(JSON.stringify({ Records: f.records })));
    },
    async discoverDataEvents() {
      return [{ name: 'org-trail', bucket: 'kbi-org-cloudtrail', type: 'trail', resourceType: 'AWS::S3::Object', readWrite: 'All', arnPatterns: ['arn:aws:s3:::kbi-payments-docs/'] },
              { name: 'org-trail', bucket: 'kbi-org-cloudtrail', type: 'trail', resourceType: 'AWS::Lambda::Function', readWrite: 'WriteOnly', arnPatterns: ['arn:aws:lambda'] }];
    },
  };
}
