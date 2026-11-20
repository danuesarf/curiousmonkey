// Reading resource-based policies, one service at a time, through the read-only scanner role. Only policies and the
// settings that decide access (S3 Block Public Access, who manages a KMS key) are read, never the data.
// A list call that is denied fails the whole service (the scanner skips it and keeps what is stored); a policy that
// cannot be read for one resource (a KMS key policy that does not let the scanner in) is kept with `unreadable`.
import { S3Client, ListBucketsCommand, GetBucketPolicyCommand, GetPublicAccessBlockCommand, GetBucketLocationCommand } from '@aws-sdk/client-s3';
import { S3ControlClient, GetPublicAccessBlockCommand as GetAccountPublicAccessBlockCommand } from '@aws-sdk/client-s3-control';
import { KMSClient, ListKeysCommand, DescribeKeyCommand, GetKeyPolicyCommand, ListAliasesCommand } from '@aws-sdk/client-kms';
import { DynamoDBClient, ListTablesCommand, GetResourcePolicyCommand as GetTablePolicyCommand } from '@aws-sdk/client-dynamodb';
import { SQSClient, ListQueuesCommand, GetQueueAttributesCommand } from '@aws-sdk/client-sqs';
import { SNSClient, ListTopicsCommand, GetTopicAttributesCommand } from '@aws-sdk/client-sns';
import { SecretsManagerClient, ListSecretsCommand, GetResourcePolicyCommand as GetSecretPolicyCommand } from '@aws-sdk/client-secrets-manager';
import { LambdaClient, ListFunctionsCommand, GetPolicyCommand as GetFunctionPolicyCommand } from '@aws-sdk/client-lambda';
import { ECRClient, DescribeRepositoriesCommand, GetRepositoryPolicyCommand } from '@aws-sdk/client-ecr';
import { OrganizationsClient, DescribeOrganizationCommand } from '@aws-sdk/client-organizations';
import { bump } from '../telemetry.js';

const parse = (s) => { if (!s) return null; if (typeof s !== 'string') return s; try { return JSON.parse(s); } catch { return JSON.parse(decodeURIComponent(s)); } };
const NOT_FOUND = /NoSuchBucketPolicy|NoSuchPublicAccessBlockConfiguration|PolicyNotFound|ResourceNotFound|RepositoryPolicyNotFound|NotFoundException|NoSuchEntity/;
const DENIED = /AccessDenied|not authorized|UnauthorizedOperation|AuthorizationError|don't have permissions/i;
const isMissing = (e) => NOT_FOUND.test(`${e.name} ${e.Code || ''} ${e.message}`);
export const isDenied = (e) => DENIED.test(`${e.name} ${e.message}`);

async function limited(items, n, fn) {
  const out = []; let i = 0;
  await Promise.all(Array.from({ length: Math.min(n, items.length) }, async () => { while (i < items.length) { const k = i++; out[k] = await fn(items[k], k); } }));
  return out;
}
/** A resource's policy: null when it has none, `unreadable` when the scanner may not read it (the rest still counts). */
async function policyOf(read) {
  bump('apiCalls');
  try { return { policy: parse(await read()) }; }
  catch (e) {
    if (isMissing(e)) return { policy: null };
    if (isDenied(e)) return { policy: null, unreadable: String(e.message).slice(0, 300) };
    throw e;
  }
}
const pages = async (fetch) => { const out = []; let token; do { bump('apiCalls'); const r = await fetch(token); out.push(...r.items); token = r.next; } while (token); return out; };

export function resourceReaders(account, credentials) {
  const regions = account.regions?.length ? account.regions : ['us-east-1'];
  const acct = account.account_id;
  const per = (Client) => { const m = new Map(); return (region) => m.get(region) || m.set(region, new Client({ region, credentials })).get(region); };
  const s3 = per(S3Client), kms = per(KMSClient), ddb = per(DynamoDBClient), sqs = per(SQSClient), sns = per(SNSClient), sm = per(SecretsManagerClient), lambda = per(LambdaClient), ecr = per(ECRClient);
  const s3any = new S3Client({ region: regions[0], credentials, followRegionRedirects: true });

  return {
    async organizationId() {
      const r = await new OrganizationsClient({ region: 'us-east-1', credentials }).send(new DescribeOrganizationCommand({}));
      return r.Organization?.Id || null;
    },

    // buckets are global; each is read in its own region. Block Public Access (bucket and account) decides whether a
    // public bucket policy takes effect.
    async s3() {
      const buckets = await pages(async (token) => {
        const r = await s3any.send(new ListBucketsCommand({ MaxBuckets: 1000, ContinuationToken: token }));
        return { items: r.Buckets || [], next: r.ContinuationToken };
      });
      let accountBlock = null;
      try { accountBlock = (await new S3ControlClient({ region: regions[0], credentials }).send(new GetAccountPublicAccessBlockCommand({ AccountId: acct }))).PublicAccessBlockConfiguration || null; }
      catch (e) { if (!isMissing(e) && !isDenied(e)) throw e; accountBlock = isDenied(e) ? { unknown: true } : null; }
      return limited(buckets, 8, async (b) => {
        let region = b.BucketRegion;
        if (!region) { bump('apiCalls'); region = (await s3any.send(new GetBucketLocationCommand({ Bucket: b.Name })).catch(() => ({}))).LocationConstraint || 'us-east-1'; }
        const c = s3(region);
        const pol = await policyOf(async () => (await c.send(new GetBucketPolicyCommand({ Bucket: b.Name }))).Policy);
        let bucketBlock = null;
        try { bump('apiCalls'); bucketBlock = (await c.send(new GetPublicAccessBlockCommand({ Bucket: b.Name }))).PublicAccessBlockConfiguration || null; }
        catch (e) { if (!isMissing(e) && !isDenied(e)) throw e; }
        const restrictPublic = !!(bucketBlock?.RestrictPublicBuckets || accountBlock?.RestrictPublicBuckets);
        return { service: 's3', arn: `arn:aws:s3:::${b.Name}`, name: b.Name, region, ...pol,
          extra: { bucketBlock, accountBlock, restrictPublic, restrictPublicFrom: bucketBlock?.RestrictPublicBuckets ? 'the bucket\'s Block Public Access' : accountBlock?.RestrictPublicBuckets ? 'the account\'s Block Public Access' : null } };
      });
    },

    // customer managed keys only: an AWS managed key's policy is AWS's, and only lets its own service in
    async kms() {
      const out = [];
      for (const region of regions) {
        const c = kms(region);
        const keys = await pages(async (token) => { const r = await c.send(new ListKeysCommand({ Marker: token, Limit: 1000 })); return { items: r.Keys || [], next: r.Truncated ? r.NextMarker : null }; });
        if (!keys.length) continue;
        const aliases = new Map();
        for (const a of await pages(async (token) => { const r = await c.send(new ListAliasesCommand({ Marker: token, Limit: 100 })); return { items: r.Aliases || [], next: r.Truncated ? r.NextMarker : null }; })) {
          if (a.TargetKeyId && !aliases.has(a.TargetKeyId)) aliases.set(a.TargetKeyId, a.AliasName.replace(/^alias\//, ''));
        }
        out.push(...(await limited(keys, 6, async (k) => {
          bump('apiCalls');
          const d = (await c.send(new DescribeKeyCommand({ KeyId: k.KeyId })).catch((e) => { if (isDenied(e)) return { KeyMetadata: null, denied: e }; throw e; }));
          const m = d.KeyMetadata;
          if (m && m.KeyManager === 'AWS') return null;
          const pol = await policyOf(async () => (await c.send(new GetKeyPolicyCommand({ KeyId: k.KeyId, PolicyName: 'default' }))).Policy);
          return { service: 'kms', arn: k.KeyArn, name: aliases.get(k.KeyId) || k.KeyId, region, ...pol,
            extra: { keyId: k.KeyId, state: m?.KeyState || null, usage: m?.KeyUsage || null, multiRegion: !!m?.MultiRegion, unreadableMeta: d.denied ? true : undefined } };
        })).filter(Boolean));
      }
      return out;
    },

    async dynamodb() {
      const out = [];
      for (const region of regions) {
        const c = ddb(region);
        const names = await pages(async (token) => { const r = await c.send(new ListTablesCommand({ ExclusiveStartTableName: token, Limit: 100 })); return { items: r.TableNames || [], next: r.LastEvaluatedTableName }; });
        out.push(...(await limited(names, 6, async (name) => {
          const arn = `arn:aws:dynamodb:${region}:${acct}:table/${name}`;
          return { service: 'dynamodb', arn, name, region, ...(await policyOf(async () => (await c.send(new GetTablePolicyCommand({ ResourceArn: arn }))).Policy)), extra: {} };
        })));
      }
      return out;
    },

    async sqs() {
      const out = [];
      for (const region of regions) {
        const c = sqs(region);
        const urls = await pages(async (token) => { const r = await c.send(new ListQueuesCommand({ NextToken: token, MaxResults: 1000 })); return { items: r.QueueUrls || [], next: r.NextToken }; });
        out.push(...(await limited(urls, 6, async (url) => {
          const name = url.split('/').pop();
          let arn = `arn:aws:sqs:${region}:${acct}:${name}`;
          const pol = await policyOf(async () => {
            const a = (await c.send(new GetQueueAttributesCommand({ QueueUrl: url, AttributeNames: ['Policy', 'QueueArn'] }))).Attributes || {};
            if (a.QueueArn) arn = a.QueueArn;
            return a.Policy || null;
          });
          return { service: 'sqs', arn, name, region, ...pol, extra: { url } };
        })));
      }
      return out;
    },

    async sns() {
      const out = [];
      for (const region of regions) {
        const c = sns(region);
        const topics = await pages(async (token) => { const r = await c.send(new ListTopicsCommand({ NextToken: token })); return { items: r.Topics || [], next: r.NextToken }; });
        out.push(...(await limited(topics, 6, async (t) => ({ service: 'sns', arn: t.TopicArn, name: t.TopicArn.split(':').pop(), region,
          ...(await policyOf(async () => (await c.send(new GetTopicAttributesCommand({ TopicArn: t.TopicArn }))).Attributes?.Policy || null)), extra: {} }))));
      }
      return out;
    },

    async secretsmanager() {
      const out = [];
      for (const region of regions) {
        const c = sm(region);
        const secrets = await pages(async (token) => { const r = await c.send(new ListSecretsCommand({ NextToken: token, MaxResults: 100 })); return { items: r.SecretList || [], next: r.NextToken }; });
        out.push(...(await limited(secrets, 6, async (s) => ({ service: 'secretsmanager', arn: s.ARN, name: s.Name, region,
          ...(await policyOf(async () => (await c.send(new GetSecretPolicyCommand({ SecretId: s.ARN }))).ResourcePolicy || null)), extra: {} }))));
      }
      return out;
    },

    async lambda() {
      const out = [];
      for (const region of regions) {
        const c = lambda(region);
        const fns = await pages(async (token) => { const r = await c.send(new ListFunctionsCommand({ Marker: token, MaxItems: 50 })); return { items: r.Functions || [], next: r.NextMarker }; });
        out.push(...(await limited(fns, 6, async (f) => ({ service: 'lambda', arn: f.FunctionArn, name: f.FunctionName, region,
          ...(await policyOf(async () => (await c.send(new GetFunctionPolicyCommand({ FunctionName: f.FunctionArn }))).Policy)), extra: {} }))));
      }
      return out;
    },

    async ecr() {
      const out = [];
      for (const region of regions) {
        const c = ecr(region);
        const repos = await pages(async (token) => { const r = await c.send(new DescribeRepositoriesCommand({ nextToken: token, maxResults: 1000 })); return { items: r.repositories || [], next: r.nextToken }; });
        out.push(...(await limited(repos, 6, async (x) => ({ service: 'ecr', arn: x.repositoryArn, name: x.repositoryName, region,
          ...(await policyOf(async () => (await c.send(new GetRepositoryPolicyCommand({ repositoryName: x.repositoryName }))).policyText)), extra: {} }))));
      }
      return out;
    },
  };
}
