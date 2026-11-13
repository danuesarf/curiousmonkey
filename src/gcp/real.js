// Reads Google Cloud IAM through the REST APIs: Resource Manager v3 and IAM v1. Read-only.
// Credentials: a service account key, or workload identity federation from this app's own AWS identity
// (the pod, task or instance role), so no Google secret has to be stored.
import { GoogleAuth, AwsClient } from 'google-auth-library';
import { defaultProvider } from '@aws-sdk/credential-provider-node';
import { decrypt } from '../auth/crypto.js';

const SCOPES = ['https://www.googleapis.com/auth/cloud-platform'];
const CRM = 'https://cloudresourcemanager.googleapis.com/v3';
const IAM = 'https://iam.googleapis.com/v1';

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

export function realGcpGateway(conn) {
  let clientP;
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
  const optional = async (p, fallback) => { try { return await p; } catch (e) { if (e.status === 403 || e.status === 404) return fallback; throw e; } };

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
      for (const pool of pools.filter((p) => p.state !== 'DELETED')) {
        for (const pv of await optional(pages(`${IAM}/${pool.name}/providers?pageSize=100`, 'workloadIdentityPoolProviders'), [])) {
          if (pv.state !== 'DELETED') out.push({ ...pv, disabled: pv.disabled || pool.disabled });
        }
      }
      return out;
    },
    async whoami() {
      clientP ||= gcpClient(conn);
      const client = await clientP;
      if (conn.auth_mode === 'key') return { email: client.email };
      return { email: conn.wif?.serviceAccount || `federated principal from ${wifAudience(conn.wif)}` };
    },
  };
}
