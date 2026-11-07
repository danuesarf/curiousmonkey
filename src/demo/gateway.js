// Deterministic fake AWS. Events are generated from a seeded function of (role, hour), so asking for the
// same time range twice returns the same events with the same IDs. That is what lets the checkpoint and
// de-duplication logic be tested honestly.
import crypto from 'node:crypto';
import { buildEstate, MANAGED } from './estate.js';

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
        const ak = 'ASIA' + crypto.createHash('sha1').update(`${role.name}${pr.key}${dayKey}${new Date(hourStart).getUTCHours()}`).digest('hex').slice(0, 16).toUpperCase();
        const t0 = hourStart + 5000;
        const caller = pr.federated ? { type: pr.type, principalId: 'AROA:' + pr.key, accountId: acct }
          : pr.invokedBy ? { type: 'AWSService', invokedBy: pr.invokedBy }
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
    async trailEventsForSlice({ region, start, end }) {
      const all = [];
      for (let h = Math.floor(start.getTime() / HOUR) * HOUR; h < end.getTime(); h += HOUR) {
        for (const e of eventsForHour(h, region)) { const t = new Date(e.eventTime).getTime(); if (t >= start.getTime() && t < end.getTime()) all.push(e); }
      }
      return all;
    },
    async discoverDataEvents() {
      return [{ name: 'org-trail', bucket: 'kbi-org-cloudtrail', type: 'trail', resourceType: 'AWS::S3::Object', readWrite: 'All', arnPatterns: ['arn:aws:s3:::kbi-payments-docs/'] },
              { name: 'org-trail', bucket: 'kbi-org-cloudtrail', type: 'trail', resourceType: 'AWS::Lambda::Function', readWrite: 'WriteOnly', arnPatterns: ['arn:aws:lambda'] }];
    },
  };
}
