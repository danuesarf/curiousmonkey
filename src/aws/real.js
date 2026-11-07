// Real AWS access through the read-only scanner role. NOT exercised against live AWS in this repo's tests;
// the demo gateway shares the same interface and drives the test suite.
import { STSClient, AssumeRoleCommand, GetCallerIdentityCommand } from '@aws-sdk/client-sts';
import { IAMClient, ListRolesCommand, GetRoleCommand, ListRolePoliciesCommand, GetRolePolicyCommand,
  ListAttachedRolePoliciesCommand, GetPolicyCommand, GetPolicyVersionCommand,
  GenerateServiceLastAccessedDetailsCommand, GetServiceLastAccessedDetailsCommand } from '@aws-sdk/client-iam';
import { S3Client, ListObjectsV2Command, GetObjectCommand } from '@aws-sdk/client-s3';
import { gunzipSync } from 'node:zlib';
import { baseCredentials } from './credentials.js';
import { trailDayPrefix, fileTimeFromKey } from './trailKeys.js';
import { CloudTrailClient, LookupEventsCommand, DescribeTrailsCommand, GetEventSelectorsCommand,
  ListEventDataStoresCommand } from '@aws-sdk/client-cloudtrail';

const decode = (d) => (typeof d === 'string' ? JSON.parse(decodeURIComponent(d)) : d);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

export async function realGateway(account, { externalId, sessionName = 'curious-monkey' }) {
  const base = baseCredentials(account);
  let credentials;
  if (account.auth_mode === 'access_key') credentials = base;
  else {
    const sts = new STSClient({ region: account.regions[0], credentials: base });
    const out = await sts.send(new AssumeRoleCommand({
      RoleArn: account.role_arn, RoleSessionName: sessionName, ExternalId: externalId, DurationSeconds: 3600 }));
    const c = out.Credentials;
    credentials = { accessKeyId: c.AccessKeyId, secretAccessKey: c.SecretAccessKey, sessionToken: c.SessionToken };
  }
  const iam = new IAMClient({ region: 'us-east-1', credentials });
  const trails = new Map();
  let s3c = null;
  const ct = (region) => trails.get(region) || trails.set(region, new CloudTrailClient({ region, credentials })).get(region);

  return {
    mode: 'aws',
    async verify() {
      const id = await new STSClient({ region: account.regions[0], credentials }).send(new GetCallerIdentityCommand({}));
      return { ok: true, accountId: id.Account, arn: id.Arn };
    },
    async listRoles() {
      const roles = []; let Marker;
      do {
        const r = await iam.send(new ListRolesCommand({ Marker, MaxItems: 200 }));
        for (const x of r.Roles) roles.push(x);
        Marker = r.IsTruncated ? r.Marker : undefined;
      } while (Marker);
      return roles.map((x) => ({ arn: x.Arn, name: x.RoleName, path: x.Path, createDate: x.CreateDate,
        trustPolicy: decode(x.AssumeRolePolicyDocument), boundaryArn: x.PermissionsBoundary?.PermissionsBoundaryArn || null }));
    },
    async getRoleDetail(name) {   // ListRoles omits last-used and tags
      const r = (await iam.send(new GetRoleCommand({ RoleName: name }))).Role;
      return { lastUsedAt: r.RoleLastUsed?.LastUsedDate || null, lastUsedRegion: r.RoleLastUsed?.Region || null,
        tags: Object.fromEntries((r.Tags || []).map((t) => [t.Key, t.Value])) };
    },
    async getRolePolicies(name) {
      const inline = [];
      const names = (await iam.send(new ListRolePoliciesCommand({ RoleName: name }))).PolicyNames;
      for (const p of names) {
        const d = await iam.send(new GetRolePolicyCommand({ RoleName: name, PolicyName: p }));
        inline.push({ name: p, document: decode(d.PolicyDocument) });
      }
      const attached = (await iam.send(new ListAttachedRolePoliciesCommand({ RoleName: name }))).AttachedPolicies
        .map((a) => ({ arn: a.PolicyArn, name: a.PolicyName, awsManaged: a.PolicyArn.startsWith('arn:aws:iam::aws:') }));
      return { inline, attached };
    },
    async getManagedPolicy(arn) {
      const p = (await iam.send(new GetPolicyCommand({ PolicyArn: arn }))).Policy;
      const v = (await iam.send(new GetPolicyVersionCommand({ PolicyArn: arn, VersionId: p.DefaultVersionId }))).PolicyVersion;
      return { versionId: p.DefaultVersionId, document: decode(v.Document) };
    },
    async getAdvisor(roleArn) {
      const { JobId } = await iam.send(new GenerateServiceLastAccessedDetailsCommand({ Arn: roleArn }));
      for (let i = 0; i < 30; i++) {
        const r = await iam.send(new GetServiceLastAccessedDetailsCommand({ JobId }));
        if (r.JobStatus === 'COMPLETED') {
          return (r.ServicesLastAccessed || []).map((s) => ({ service: s.ServiceNamespace, lastAuthenticated: s.LastAuthenticated || null }));
        }
        if (r.JobStatus === 'FAILED') throw Object.assign(new Error(r.Error?.Message || 'advisor job failed'), { retryable: true });
        await sleep(1500);
      }
      throw Object.assign(new Error('advisor job timed out'), { retryable: true });
    },
    /** One page of Event History. LookupEvents allows 2 requests per second per account and region. */
    async lookupEventsPage({ region, start, end, token }) {
      const r = await ct(region).send(new LookupEventsCommand({ StartTime: start, EndTime: end, NextToken: token, MaxResults: 50 }));
      return { events: (r.Events || []).map((e) => JSON.parse(e.CloudTrailEvent)), nextToken: r.NextToken || null };
    },
    /** All records of one time slice from the trail's S3 log files. No 2 TPS limit, and history can exceed 90 days. */
    async trailEventsForSlice({ region, start, end, listCache = new Map() }) {
      const s3 = s3c || (s3c = new S3Client({ region: account.s3_region || region, credentials }));
      const from = start.getTime(), to = end.getTime() + 60 * 60e3;          // a record is published up to ~1 h after it happens
      const keys = [];
      for (let d = Date.UTC(start.getUTCFullYear(), start.getUTCMonth(), start.getUTCDate()); d < to; d += 864e5) {
        const prefix = trailDayPrefix(account, region, new Date(d));
        if (!listCache.has(prefix)) {
          const all = []; let ContinuationToken;
          do {
            const r = await s3.send(new ListObjectsV2Command({ Bucket: account.s3_bucket, Prefix: prefix, ContinuationToken }));
            for (const o of r.Contents || []) all.push(o.Key);
            ContinuationToken = r.IsTruncated ? r.NextContinuationToken : undefined;
          } while (ContinuationToken);
          listCache.set(prefix, all);
        }
        for (const k of listCache.get(prefix)) { const t = fileTimeFromKey(k); if (t == null || (t >= from && t < to)) keys.push(k); }
      }
      const out = [];
      let i = 0;
      await Promise.all(Array.from({ length: Math.min(8, keys.length) }, async () => {
        while (i < keys.length) {
          const Key = keys[i++];
          const body = await (await s3.send(new GetObjectCommand({ Bucket: account.s3_bucket, Key }))).Body.transformToByteArray();
          for (const r of JSON.parse(gunzipSync(Buffer.from(body)).toString('utf8')).Records || []) {
            const t = new Date(r.eventTime).getTime();
            if (t >= from && t < end.getTime()) out.push(r);
          }
        }
      }));
      return out;
    },
    async discoverDataEvents() {
      const found = [];
      const region = account.regions[0];
      for (const t of (await ct(region).send(new DescribeTrailsCommand({}))).trailList || []) {
        const sel = await ct(region).send(new GetEventSelectorsCommand({ TrailName: t.TrailARN }));
        for (const a of sel.AdvancedEventSelectors || []) {
          const type = a.FieldSelectors.find((f) => f.Field === 'resources.type')?.Equals?.[0];
          if (!type) continue;
          found.push({ name: t.Name, bucket: t.S3BucketName, type: 'trail', resourceType: type, readWrite: a.FieldSelectors.find((f) => f.Field === 'readOnly')?.Equals?.[0] ?? 'All',
            arnPatterns: a.FieldSelectors.find((f) => f.Field === 'resources.ARN')?.StartsWith || a.FieldSelectors.find((f) => f.Field === 'resources.ARN')?.Equals || ['*'] });
        }
        for (const s of sel.EventSelectors || []) for (const d of s.DataResources || []) {
          found.push({ name: t.Name, bucket: t.S3BucketName, type: 'trail', resourceType: d.Type, readWrite: s.ReadWriteType, arnPatterns: d.Values });
        }
      }
      for (const s of (await ct(region).send(new ListEventDataStoresCommand({}))).EventDataStores || []) {
        found.push({ name: s.Name, type: 'event-data-store', resourceType: 'multiple', readWrite: 'All', arnPatterns: ['*'] });
      }
      return found;
    },
  };
}
