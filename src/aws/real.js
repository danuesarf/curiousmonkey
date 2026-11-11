// Real AWS access through the read-only scanner role. NOT exercised against live AWS in this repo's tests;
// the demo gateway shares the same interface and drives the test suite.
import { STSClient, AssumeRoleCommand, GetCallerIdentityCommand } from '@aws-sdk/client-sts';
import { IAMClient, ListRolesCommand, GetRoleCommand, ListRolePoliciesCommand, GetRolePolicyCommand,
  ListAttachedRolePoliciesCommand, GetPolicyCommand, GetPolicyVersionCommand,
  GenerateServiceLastAccessedDetailsCommand, GetServiceLastAccessedDetailsCommand, ListSAMLProvidersCommand, GetSAMLProviderCommand } from '@aws-sdk/client-iam';
import { samlIssuer } from '../identityCenter.js';
import { S3Client, ListObjectsV2Command, GetObjectCommand } from '@aws-sdk/client-s3';
import { bump } from '../telemetry.js';
import { baseCredentials, refreshingRoleCredentials } from './credentials.js';
import { trailDayPrefix, trailRegionsPrefix, fileTimeFromKey } from './trailKeys.js';
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
    credentials = refreshingRoleCredentials({
      assume: async () => {
        const c = (await sts.send(new AssumeRoleCommand({
          RoleArn: account.role_arn, RoleSessionName: sessionName, ExternalId: externalId, DurationSeconds: 3600 }))).Credentials;
        return { accessKeyId: c.AccessKeyId, secretAccessKey: c.SecretAccessKey, sessionToken: c.SessionToken, expiration: new Date(c.Expiration) };
      },
    });
    await credentials();                                      // fail fast: a wrong trust policy or ExternalId shows at once
  }
  const iam = new IAMClient({ region: 'us-east-1', credentials });
  const trails = new Map();
  let s3client = null;
  // the bucket's region if set, else the account's first region; followRegionRedirects copes with a wrong guess
  const s3c = () => s3client || (s3client = new S3Client({ region: account.s3_region || account.regions[0] || 'us-east-1', credentials, followRegionRedirects: true }));
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
      return roles.map((x) => ({ arn: x.Arn, awsId: x.RoleId || null, name: x.RoleName, path: x.Path, createDate: x.CreateDate,
        trustPolicy: decode(x.AssumeRolePolicyDocument), boundaryArn: x.PermissionsBoundary?.PermissionsBoundaryArn || null }));
    },
    async listSamlProviders() {   // the issuer in each provider's metadata says which IdP (or Identity Center instance) it is
      const list = (await iam.send(new ListSAMLProvidersCommand({}))).SAMLProviderList || [];
      const out = [];
      for (const p of list) {
        const d = await iam.send(new GetSAMLProviderCommand({ SAMLProviderArn: p.Arn }));
        out.push({ arn: p.Arn, name: p.Arn.split('/').pop(), issuer: samlIssuer(d.SAMLMetadataDocument), createdAt: p.CreateDate || d.CreateDate || null });
      }
      return out;
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
      bump('apiCalls');
      const r = await ct(region).send(new LookupEventsCommand({ StartTime: start, EndTime: end, NextToken: token, MaxResults: 50 }));
      return { events: (r.Events || []).map((e) => JSON.parse(e.CloudTrailEvent)), nextToken: r.NextToken || null };
    },
    /** Regions that have log files in the trail, from the folder names under <account>/CloudTrail/. */
    async listTrailRegions() {
      const base = trailRegionsPrefix(account);
      const out = []; let ContinuationToken;
      do {
        bump('apiCalls');
        const r = await s3c().send(new ListObjectsV2Command({ Bucket: account.s3_bucket, Prefix: base, Delimiter: '/', ContinuationToken }));
        for (const p of r.CommonPrefixes || []) { const reg = p.Prefix.slice(base.length).replace(/\/$/, ''); if (/^[a-z]{2}(-gov)?-[a-z]+-\d$/.test(reg)) out.push(reg); }
        ContinuationToken = r.IsTruncated ? r.NextContinuationToken : undefined;
      } while (ContinuationToken);
      return out;
    },
    /** Log files delivered on one UTC day in one region: [{ key, size, time }], in key order (= delivery order). */
    async listTrailDay({ region, day }) {
      const prefix = trailDayPrefix(account, region, day);
      const out = []; let ContinuationToken;
      do {
        bump('apiCalls');
        const r = await s3c().send(new ListObjectsV2Command({ Bucket: account.s3_bucket, Prefix: prefix, ContinuationToken }));
        for (const o of r.Contents || []) { if (!o.Key.endsWith('.json.gz')) continue; const t = fileTimeFromKey(o.Key); if (t != null) out.push({ key: o.Key, size: o.Size || 0, time: t }); }
        ContinuationToken = r.IsTruncated ? r.NextContinuationToken : undefined;
      } while (ContinuationToken);
      return out.sort((x, y) => (x.key < y.key ? -1 : 1));
    },
    /** One log file, still gzipped. Decoding happens elsewhere (on a parser thread). */
    async getTrailFile(key) {
      bump('apiCalls');
      const r = await s3c().send(new GetObjectCommand({ Bucket: account.s3_bucket, Key: key }));
      const buf = Buffer.from(await r.Body.transformToByteArray());
      bump('s3Files'); bump('s3Bytes', buf.length);
      return buf;
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
