// Reads Google Cloud IAM through the REST APIs: Resource Manager v3 and IAM v1. Read-only.
// Credentials: a service account key, or workload identity federation from this app's own AWS identity
// (the pod, task or instance role), so no Google secret has to be stored.
import { GoogleAuth, AwsClient } from 'google-auth-library';
import { defaultProvider } from '@aws-sdk/credential-provider-node';
import { decrypt } from '../auth/crypto.js';
import { ASSET_TYPES } from './resources.js';

const SCOPES = ['https://www.googleapis.com/auth/cloud-platform'];
const CRM = 'https://cloudresourcemanager.googleapis.com/v3';
const IAM = 'https://iam.googleapis.com/v1';
const LOGGING = 'https://logging.googleapis.com/v2';
const ASSET = 'https://cloudasset.googleapis.com/v1', STORAGE = 'https://storage.googleapis.com/storage/v1', BQ = 'https://bigquery.googleapis.com/bigquery/v2';
const COMPUTE = 'https://compute.googleapis.com/compute/v1';
const PUBSUB = 'https://pubsub.googleapis.com/v1', SECRETS = 'https://secretmanager.googleapis.com/v1', RUN = 'https://run.googleapis.com/v2', FUNCTIONS = 'https://cloudfunctions.googleapis.com/v2';
// Partial responses: the `fields` system parameter, which every Google REST API takes
// (https://cloud.google.com/apis/docs/system-parameters). The reader never falls back to whole entries. The first
// mask reaches inside protoPayload, a google.protobuf.Any; if that is refused, or the paths get dropped on the way
// (so pages come back with entries but no protoPayload), it steps down to the whole protoPayload, still without
// resource, labels, operation and the rest. If both fail, the read fails with a clear error and is retried later.
export const LOG_MASKS = [
  'nextPageToken,entries(timestamp,protoPayload/authenticationInfo,protoPayload/authorizationInfo)',
  'nextPageToken,entries(timestamp,protoPayload)',
];
let maskAt = 0;                                    // per process: once a mask fails, later reads start at the next one
export const logMaskInUse = () => (maskAt < LOG_MASKS.length ? LOG_MASKS[maskAt] : null);
/** Entries came back, but none carries a caller or a permission check: the mask lost the fields it asked for. */
export const maskDropped = (r) => (r.entries || []).length > 0 && !(r.entries || []).some((e) => e?.protoPayload?.authenticationInfo || e?.protoPayload?.authorizationInfo);

/** One entries.list page through the field masks, best first. `post(mask)` makes the request. Never reads whole entries. */
export async function readWithMasks(post) {
  for (; maskAt < LOG_MASKS.length; maskAt++) {
    let r;
    try { r = await post(LOG_MASKS[maskAt]); } catch (e) {
      if (e.status === 400 && /field|mask|path/i.test(e.message)) continue;          // this mask refused: try the next
      throw e;
    }
    if (maskDropped(r)) continue;                                                     // accepted but emptied: try the next
    return r;
  }
  maskAt = 0;                                                                         // the next retry starts from the best mask again
  throw Object.assign(new Error('The Logging API returned no caller or permission fields under any field mask, so nothing was counted; whole entries are never read. Retried later.'), { status: 422 });
}
export const resetLogMask = () => { maskAt = 0; };

export const wifAudience = (w) => `//iam.googleapis.com/projects/${w.projectNumber}/locations/global/workloadIdentityPools/${w.poolId}/providers/${w.providerId}`;

/** An authenticated client for one connection. */
export async function gcpClient(conn) {
  if (conn.auth_mode === 'key') {
    if (!conn.key_enc) throw Object.assign(new Error('No service account key is saved for this connection. Edit it and add one.'), { retryable: false });
    const credentials = JSON.parse(decrypt(conn.key_enc));
    return new GoogleAuth({ credentials, scopes: SCOPES }).getClient();
  }
  const w = conn.wif || {};
  if (!w.projectNumber || !w.poolId || !w.providerId) throw Object.assign(new Error('Workload identity federation is not set up: project number, pool and provider are needed.'), { retryable: false });
  const aws = defaultProvider();
  const region = process.env.AWS_REGION || process.env.AWS_DEFAULT_REGION || 'us-east-1';
  return new AwsClient({
    type: 'external_account',
    audience: wifAudience(w),
    subject_token_type: 'urn:ietf:params:aws:token-type:aws4_request',
    token_url: 'https://sts.googleapis.com/v1/token',
    ...(w.serviceAccount ? { service_account_impersonation_url: `https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/${w.serviceAccount}:generateAccessToken` } : {}),
    scopes: SCOPES,
    aws_security_credentials_supplier: {
      getAwsRegion: async () => region,
      getAwsSecurityCredentials: async () => { const c = await aws(); return { accessKeyId: c.accessKeyId, secretAccessKey: c.secretAccessKey, token: c.sessionToken }; },
    },
  });
}

/** Run at most `n` calls at once. */
function limiter(n) {
  let active = 0; const queue = [];
  const next = () => { if (active >= n || !queue.length) return; active++; const { fn, ok, ko } = queue.shift(); fn().then(ok, ko).finally(() => { active--; next(); }); };
  return (fn) => new Promise((ok, ko) => { queue.push({ fn, ok, ko }); next(); });
}

export function realGcpGateway(conn, { client: injected } = {}) {
  let clientP = injected ? Promise.resolve(injected) : null;
  const limit = limiter(8);
  const call = (method, url, data) => limit(async () => {
    clientP ||= gcpClient(conn);
    const client = await clientP;
    try {
      return (await client.request({ method, url, data, retry: true })).data;
    } catch (e) {
      const status = e.response?.status, msg = e.response?.data?.error?.message || e.message;
      const err = Object.assign(new Error(`${method} ${url.replace(/^https:\/\//, '')}: ${msg}`), { status });
      if (status === 401 || status === 403 || status === 400) err.retryable = false;
      throw err;
    }
  });
  const pages = async (url, key) => {
    const out = []; let token = '';
    do {
      const sep = url.includes('?') ? '&' : '?';
      const r = await call('GET', `${url}${token ? `${sep}pageToken=${encodeURIComponent(token)}` : ''}`);
      out.push(...(r[key] || [])); token = r.nextPageToken || '';
    } while (token);
    return out;
  };
  const optional = async (p, fallback, also = []) => { try { return await p; } catch (e) { if (e.status === 403 || e.status === 404 || also.includes(e.status)) return fallback; throw e; } };

  return {
    async organization(id) { return call('GET', `${CRM}/organizations/${id}`); },
    async folders() { return pages(`${CRM}/folders:search?pageSize=500`, 'folders'); },
    async projects() { return (await pages(`${CRM}/projects:search?pageSize=500`, 'projects')).filter((p) => p.state === 'ACTIVE')
      .map((p) => ({ projectId: p.projectId, number: p.name.split('/')[1], name: p.displayName, parent: p.parent, labels: p.labels || {}, state: p.state })); },
    async project(id) { const p = await call('GET', `${CRM}/projects/${id}`); return { projectId: p.projectId, number: p.name.split('/')[1], name: p.displayName, parent: p.parent, labels: p.labels || {}, state: p.state }; },
    async iamPolicy(resource) { return optional(call('POST', `${CRM}/${resource}:getIamPolicy`, { options: { requestedPolicyVersion: 3 } }), null); },
    async serviceAccounts(projectId) { return optional(pages(`${IAM}/projects/${projectId}/serviceAccounts?pageSize=100`, 'accounts'), []); },
    async serviceAccountKeys(email) { return optional(call('GET', `${IAM}/projects/-/serviceAccounts/${encodeURIComponent(email)}/keys?keyTypes=USER_MANAGED`).then((r) => r.keys || []), []); },
    async serviceAccountPolicy(projectId, email) { return optional(call('POST', `${IAM}/projects/${projectId}/serviceAccounts/${encodeURIComponent(email)}:getIamPolicy?options.requestedPolicyVersion=3`), null); },
    async customRoles(parent) { return optional(pages(`${IAM}/${parent}/roles?view=FULL&pageSize=300`, 'roles'), []); },
    async role(name) { return optional(call('GET', `${IAM}/${name}`), null); },
    async wifProviders(projectId) {
      const pools = await optional(pages(`${IAM}/projects/${projectId}/locations/global/workloadIdentityPools?pageSize=100`, 'workloadIdentityPools'), []);
      const out = [];
      // Google-managed pools hold no providers, and listing them is refused with a 400: the GKE workload identity pool
      // <project>.svc.id.goog that every GKE project gets, and trust-domain pools. GKE identities are read from IAM bindings.
      const managed = (p) => /\.svc\.id\.goog$/.test(p.name) || (p.mode && p.mode !== 'FEDERATION_ONLY');
      for (const pool of pools.filter((p) => p.state !== 'DELETED' && !managed(p))) {
        // any other pool that cannot list providers is skipped too: one pool never fails the whole scan
        const providers = await optional(pages(`${IAM}/${pool.name}/providers?pageSize=100`, 'workloadIdentityPoolProviders'), [], [400]);
        for (const pv of providers) {
          if (pv.state !== 'DELETED') out.push({ ...pv, disabled: pv.disabled || pool.disabled });
        }
      }
      return out;
    },
    // Audit log entries (Logging API v2 entries.list), 1,000 a page. Only the caller and the permission checks are
    // asked for, so a page is a few hundred KB instead of megabytes of request and response bodies.
    async logEntries({ projectId, filter, pageToken = '' }) {
      const body = { resourceNames: [`projects/${projectId}`], filter, orderBy: 'timestamp asc', pageSize: 1000, ...(pageToken ? { pageToken } : {}) };
      return readWithMasks((mask) => call('POST', `${LOGGING}/entries:list?fields=${encodeURIComponent(mask)}`, body));
    },
    /**
     * Resource-level IAM policies. Cloud Asset Inventory answers for every service at once (searchAllIamPolicies over
     * the connection's scope, cloudasset.assets.searchAllIamPolicies). When it is refused (the API is off, or the
     * permission is missing) the main services are read one by one; a service refused in a project is skipped.
     */
    async resourcePolicies({ scope, projects }) {
      try {
        const types = Object.keys(ASSET_TYPES).map((t) => `assetTypes=${encodeURIComponent(t)}`).join('&');
        return { source: 'asset', items: await pages(`${ASSET}/${scope}:searchAllIamPolicies?pageSize=500&${types}`, 'results'), skipped: [] };
      } catch (e) {
        if (![400, 403, 404].includes(e.status)) throw e;
        const items = [], skipped = new Set();
        const opt = (p, what) => p.catch((x) => { if ([400, 403, 404].includes(x.status)) { skipped.add(what); return null; } throw x; });
        const policyOf = (url, method = 'GET') => opt(call(method, url, method === 'POST' ? {} : undefined), 'getIamPolicy');
        await Promise.all(projects.map(async (p) => {
          const project = `projects/${p.number}`;
          const add = (assetType, resource, policy, extra = {}) => { if (policy?.bindings?.length) items.push({ assetType, resource, project, policy, ...extra }); };
          const [buckets, datasets, topics, secrets, services, functions] = await Promise.all([
            opt(pages(`${STORAGE}/b?project=${p.projectId}&fields=${encodeURIComponent('items(name,location,iamConfiguration/publicAccessPrevention),nextPageToken')}`, 'items'), 'storage'),
            opt(pages(`${BQ}/projects/${p.projectId}/datasets?all=true`, 'datasets'), 'bigquery'),
            opt(pages(`${PUBSUB}/projects/${p.projectId}/topics`, 'topics'), 'pubsub'),
            opt(pages(`${SECRETS}/projects/${p.projectId}/secrets`, 'secrets'), 'secretmanager'),
            opt(pages(`${RUN}/projects/${p.projectId}/locations/-/services`, 'services'), 'run'),
            opt(pages(`${FUNCTIONS}/projects/${p.projectId}/locations/-/functions`, 'functions'), 'cloudfunctions'),
          ]);
          await Promise.all([
            ...(buckets || []).map(async (b) => add('storage.googleapis.com/Bucket', `//storage.googleapis.com/${b.name}`, await policyOf(`${STORAGE}/b/${b.name}/iam?optionsRequestedPolicyVersion=3`),
              { location: b.location, extra: { publicAccessPrevention: b.iamConfiguration?.publicAccessPrevention || null } })),
            ...(datasets || []).map(async (d) => { const id = d.datasetReference?.datasetId; add('bigquery.googleapis.com/Dataset', `//bigquery.googleapis.com/projects/${p.projectId}/datasets/${id}`, await policyOf(`${BQ}/projects/${p.projectId}/datasets/${id}:getIamPolicy`, 'POST'), { location: d.location }); }),
            ...(topics || []).map(async (t) => add('pubsub.googleapis.com/Topic', `//pubsub.googleapis.com/${t.name}`, await policyOf(`${PUBSUB}/${t.name}:getIamPolicy`))),
            ...(secrets || []).map(async (x) => add('secretmanager.googleapis.com/Secret', `//secretmanager.googleapis.com/${x.name}`, await policyOf(`${SECRETS}/${x.name}:getIamPolicy`))),
            ...(services || []).map(async (x) => add('run.googleapis.com/Service', `//run.googleapis.com/${x.name}`, await policyOf(`${RUN}/${x.name}:getIamPolicy`))),
            ...(functions || []).map(async (x) => add('cloudfunctions.googleapis.com/CloudFunction', `//cloudfunctions.googleapis.com/${x.name}`, await policyOf(`${FUNCTIONS}/${x.name}:getIamPolicy`))),
          ]);
        }));
        return { source: 'per-service', items, skipped: [...skipped], assetError: e.message };
      }
    },
    /** A bucket's public access prevention ('enforced' refuses allUsers and allAuthenticatedUsers whatever IAM says). */
    /**
     * One project's networking (the Networking extension): every list at once. A list the reader may not make (403),
     * or a project without the Compute Engine API (403/404), is skipped and named.
     */
    async network(projectId) {
      const base = `${COMPUTE}/projects/${projectId}`, skipped = [];
      const agg = async (kind) => {
        const out = []; let token = '';
        do {
          const r = await call('GET', `${base}/aggregated/${kind}?maxResults=500&returnPartialSuccess=true${token ? `&pageToken=${encodeURIComponent(token)}` : ''}`);
          for (const v of Object.values(r.items || {})) out.push(...(v[kind] || []));
          token = r.nextPageToken || '';
        } while (token);
        return out;
      };
      const list = async (path) => pages(`${base}/${path}?maxResults=500`, 'items');
      const safe = async (kind, p) => { try { return await p; } catch (e) { if (e.status === 403 || e.status === 404 || e.status === 400) { skipped.push(kind); return []; } throw e; } };
      const [networks, subnetworks, firewalls, firewallPolicies, routers, routes, vpnGateways, targetVpnGateways, externalVpnGateways, vpnTunnels, interconnectAttachments, addresses, forwardingRules, globalForwardingRules, instances] = await Promise.all([
        safe('networks', list('global/networks')), safe('subnetworks', agg('subnetworks')), safe('firewalls', list('global/firewalls')), safe('firewallPolicies', list('global/firewallPolicies')),
        safe('routers', agg('routers')), safe('routes', list('global/routes')), safe('vpnGateways', agg('vpnGateways')), safe('targetVpnGateways', agg('targetVpnGateways')),
        safe('externalVpnGateways', list('global/externalVpnGateways')), safe('vpnTunnels', agg('vpnTunnels')), safe('interconnectAttachments', agg('interconnectAttachments')),
        safe('addresses', agg('addresses')), safe('forwardingRules', agg('forwardingRules')), safe('globalForwardingRules', list('global/forwardingRules')), safe('instances', agg('instances'))]);
      return { raw: { networks, subnetworks, firewalls, firewallPolicies, routers, routes, vpnGateways, targetVpnGateways, externalVpnGateways, vpnTunnels, interconnectAttachments, addresses,
        forwardingRules: [...forwardingRules, ...globalForwardingRules], instances }, skipped };
    },
    async bucketPublicAccess(name) {
      return optional(call('GET', `${STORAGE}/b/${encodeURIComponent(name)}?fields=iamConfiguration`).then((b) => b.iamConfiguration?.publicAccessPrevention || null), null);
    },
    async whoami() {
      clientP ||= gcpClient(conn);
      const client = await clientP;
      if (conn.auth_mode === 'key') return { email: client.email };
      return { email: conn.wif?.serviceAccount || `federated principal from ${wifAudience(conn.wif)}` };
    },
  };
}
