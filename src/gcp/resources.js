// Google Cloud resource-level IAM: who a bucket, dataset, topic, key, secret, service, function or repository lets in.
// The same questions as for AWS resource policies (src/analyzer/resourcePolicy.js), the same answers: each binding
// member is a grant; how far it reaches (anyone, outside your organisation, another of your connections, this
// organisation); what the role allows (administer, use the data, read settings); and findings under the same res.*
// controls. No I/O.
import { parseMember, federatedOrigin } from './analyze.js';
import { severityOf, DEFAULT_POLICY } from '../controlCatalog.js';

/** Cloud Asset Inventory types read, and what the Resources page calls them. */
export const ASSET_TYPES = {
  'storage.googleapis.com/Bucket': { service: 'gcs', type: 'bucket', label: 'Cloud Storage bucket' },
  'bigquery.googleapis.com/Dataset': { service: 'bigquery', type: 'dataset', label: 'BigQuery dataset' },
  'bigquery.googleapis.com/Table': { service: 'bigquery', type: 'table', label: 'BigQuery table' },
  'pubsub.googleapis.com/Topic': { service: 'pubsub', type: 'topic', label: 'Pub/Sub topic' },
  'pubsub.googleapis.com/Subscription': { service: 'pubsub', type: 'subscription', label: 'Pub/Sub subscription' },
  'cloudkms.googleapis.com/CryptoKey': { service: 'cloudkms', type: 'cryptoKey', label: 'Cloud KMS key' },
  'cloudkms.googleapis.com/KeyRing': { service: 'cloudkms', type: 'keyRing', label: 'Cloud KMS key ring' },
  'secretmanager.googleapis.com/Secret': { service: 'gsecret', type: 'secret', label: 'Secret Manager secret' },
  'run.googleapis.com/Service': { service: 'cloudrun', type: 'runService', label: 'Cloud Run service' },
  'cloudfunctions.googleapis.com/CloudFunction': { service: 'cloudfunctions', type: 'function', label: 'Cloud Function' },
  'artifactregistry.googleapis.com/Repository': { service: 'artifactregistry', type: 'repository', label: 'Artifact Registry repository' },
};
export const TYPE_LABEL = Object.fromEntries(Object.values(ASSET_TYPES).map((t) => [t.type, t.label]));
export const GCP_SERVICES = {
  gcs: { label: 'Cloud Storage bucket', noun: 'bucket', short: 'GCS', cloud: 'gcp' },
  bigquery: { label: 'BigQuery dataset', noun: 'BigQuery dataset', short: 'BigQuery', cloud: 'gcp' },
  pubsub: { label: 'Pub/Sub topic', noun: 'Pub/Sub topic', short: 'Pub/Sub', cloud: 'gcp' },
  cloudkms: { label: 'Cloud KMS key', noun: 'Cloud KMS key', short: 'Cloud KMS', cloud: 'gcp' },
  gsecret: { label: 'Secret Manager secret', noun: 'secret', short: 'Secret Manager', cloud: 'gcp' },
  cloudrun: { label: 'Cloud Run service', noun: 'Cloud Run service', short: 'Cloud Run', cloud: 'gcp' },
  cloudfunctions: { label: 'Cloud Function', noun: 'function', short: 'Functions', cloud: 'gcp' },
  artifactregistry: { label: 'Artifact Registry repository', noun: 'repository', short: 'Artifact Registry', cloud: 'gcp' },
};

/**
 * One asset from Cloud Asset Inventory (or a per-service read) into a stored resource.
 * `numbers` maps project numbers to IDs (assets name projects by number).
 */
export function normalizeAsset(a, numbers = new Map()) {
  const t = ASSET_TYPES[a.assetType];
  if (!t) return null;
  const full = String(a.resource);
  const path = full.replace(/^\/\/[^/]+\//, '');
  const proj = a.project ? String(a.project).replace(/^projects\//, '') : path.match(/^projects\/([^/]+)/)?.[1] || null;
  const project = numbers.get(proj) || proj;
  const location = path.match(/\/locations\/([^/]+)/)?.[1] || a.location || null;
  const name = t.type === 'table' ? path.split('/datasets/')[1]?.replace('/tables/', '.') : path.split('/').pop();
  return { service: t.service, type: t.type, arn: full, name: name || full, project_id: project, region: location, policy: a.policy && (a.policy.bindings || []).length ? { bindings: a.policy.bindings } : null,
    extra: { assetType: a.assetType, ...(a.extra || {}) } };
}

/** The resource-level bindings, in the IAM scan's shape: they become part of each principal's roles. */
export function assetBindings(resources) {
  const out = [];
  for (const r of resources) for (const b of r.policy?.bindings || []) for (const member of b.members || []) {
    out.push({ resource: r.arn, resource_type: r.type, project_id: r.project_id, role: b.role, member, condition: b.condition || null });
  }
  return out;
}

// what a role allows, from its permissions (or its name when the definition was not read)
const DATA = /\.(get|list)Data$|\.objects\.(get|create|delete|update)$|\.tables\.(getData|updateData|export)$|versions\.access$|\.publish$|\.consume$|subscriptions\.consume|\.invoke$|routes\.invoke|useToDecrypt|useToEncrypt|useToSign|downloadArtifacts|uploadArtifacts|\.(create|update|delete)$/;
const ADMIN = /\.setIamPolicy$/;
export function roleAccess(role, perms) {
  const list = perms?.length ? perms : null;
  if (list) {
    if (list.some((p) => ADMIN.test(p))) return 'admin';
    if (list.some((p) => DATA.test(p))) return 'data';
    return 'read';
  }
  if (/^roles\/(owner|editor)$|admin$|Admin$|owner$/i.test(role)) return 'admin';
  if (/objectViewer|objectUser|objectCreator|objectAdmin|dataViewer|dataEditor|dataOwner|secretAccessor|invoker|subscriber|publisher|cryptoKey|reader|writer|legacyObject/i.test(role)) return 'data';
  return 'read';
}
const ACCESS = { admin: 'administer it or change who has access', data: 'read or change what it holds', read: 'read its settings only' };

/**
 * Who the policy lets in, and what is wrong with it.
 * resource: { service, type, arn, name, project_id, policy: { bindings }, extra: { publicAccessPrevention } }
 * estate:   { domain, projects: Set (this connection's), otherProjects: Set (other connections'), awsAccounts: Map,
 *             providers (workload identity providers), roleDefs: Map(role -> permissions) }
 */
export function analyzeGcpResource(resource, estate = {}, policy = DEFAULT_POLICY) {
  if (!resource.policy) return { exposure: 'none', grants: [], findings: [] };
  const domain = String(estate.domain || '').toLowerCase();
  const mine = estate.projects || new Set(), others = estate.otherProjects || new Set();
  const noun = GCP_SERVICES[resource.service]?.noun || 'resource';
  const pap = resource.extra?.publicAccessPrevention === 'enforced';
  const grants = [], findings = [];
  const inDomain = (email) => { const d = String(email || '').split('@')[1]?.toLowerCase() || String(email || '').toLowerCase(); return !!domain && (d === domain || d.endsWith(`.${domain}`)); };
  const projectReach = (p) => (!p ? 'external' : mine.has(p) ? 'same' : others.has(p) ? 'connected' : 'external');

  (resource.policy.bindings || []).forEach((b, i) => {
    const access = roleAccess(b.role, estate.roleDefs?.get(b.role));
    for (const member of b.members || []) {
      const p = parseMember(member);
      const g = { statement: i, sid: b.role, principal: member, kind: p.kind, account: null, accountName: null, actions: [b.role], access, conditions: b.condition ? [b.condition.title || b.condition.expression || 'condition'] : [], narrowedBy: [], network: [], findings: [] };
      let reach;
      const conv = member.match(/^project(Owner|Editor|Viewer):(.+)$/);       // legacy bucket convenience values
      if (p.kind === 'public') reach = 'public';
      else if (conv) { reach = projectReach(conv[2]); g.account = conv[2]; g.kind = 'project-role'; }
      else if (p.kind === 'deleted') reach = 'same';
      else if (p.kind === 'serviceAccount') reach = p.managed ? 'service' : p.project ? projectReach(p.project) : /gserviceaccount\.com$/.test(p.email) ? 'service' : 'external';
      else if (p.kind === 'gke') reach = projectReach(p.project);
      else if (p.kind === 'federated') {
        const o = federatedOrigin(p, estate.providers || []);
        g.origin = o; g.accountName = o.label;
        const acct = o.awsAccountId || o.awsAccountIds?.[0];
        reach = o.cloud === 'aws' ? (acct && estate.awsAccounts?.has(acct) ? 'connected' : 'external') : 'external';
        if (o.broad) g.narrowedBy.push('nothing narrows the federated identity');
      } else if (p.kind === 'user' || p.kind === 'group') reach = inDomain(p.email) ? 'same' : 'external';
      else if (p.kind === 'domain') reach = inDomain(p.email) ? 'same' : 'external';
      else reach = 'external';
      if (g.account == null && p.project) g.account = p.project;
      g.reach = reach;

      const f = (control, builtIn, title, detail, suggestion) => {
        const severity = severityOf(policy, control, builtIn);
        if (!severity) return;
        findings.push({ key: `${control}|${b.role}|${member}`.slice(0, 500), control, severity, title, detail, suggestion, principal: member, principalAccount: g.account, statement: i, sid: b.role, actions: [b.role], conditions: g.conditions });
        g.findings.push(control);
      };
      const what = `${ACCESS[access]} (${b.role})`;
      if (reach === 'public') {
        const who = member === 'allUsers' ? 'Anyone on the internet' : 'Any Google account, in any organisation';
        f('res.public', pap ? 'low' : access === 'read' ? 'medium' : 'high', `${member === 'allUsers' ? 'Anyone' : 'Any Google account'} can ${access === 'admin' ? 'administer' : access === 'data' ? 'use' : 'read the settings of'} this ${noun}`,
          pap ? `${who} is granted ${b.role}, but public access prevention is enforced on the bucket: it is refused today, and turning prevention off would open it.` : `${who} (${member}) can ${what}.`,
          'Remove the binding, or grant it to the identities that need it. For buckets, enforce public access prevention.');
      } else if (reach === 'external' && p.kind !== 'deleted') {
        const who = p.kind === 'serviceAccount' ? `service account ${p.email}, from a project outside your connections` : p.kind === 'domain' ? `everyone at ${p.email}` : p.kind === 'federated' ? `${g.accountName}` : conv ? `the ${conv[1].toLowerCase()}s of project ${conv[2]}` : `${p.email || member}`;
        f('res.external-account', access === 'read' ? 'medium' : 'high', `Shared outside your organisation: ${p.email || g.accountName || member}`,
          `${who[0].toUpperCase()}${who.slice(1)} is not in ${domain || 'your organisation'} and can ${what}.`, 'Confirm it is still needed; grant the narrowest role.');
      } else if (reach === 'connected') {
        f('res.cross-account', 'low', `Shared with ${g.accountName || g.account || 'another of your connections'}`, `${g.accountName || p.email || member}, outside this connection but known to Curious Monkey, can ${what}.`, 'Fine when intended.');
      }
      if (p.kind === 'deleted') f('res.deleted-principal', 'low', 'Bound to a deleted identity', `${member} was deleted; its binding (${b.role}) stays.`, 'Remove the binding.');
      if (reach !== 'same' && reach !== 'service' && /^roles\/(owner|editor)$|admin$/i.test(b.role))
        f('res.broad-actions', 'low', `${b.role} granted outside the organisation`, `${member} holds ${b.role} on this ${noun}.`, 'Grant a narrower role.');
      grants.push(g);
    }
  });
  const live = grants.filter((g) => g.kind !== 'deleted');
  const exposure = live.some((g) => g.reach === 'public') ? 'public' : live.some((g) => g.reach === 'external') ? 'external'
    : live.some((g) => g.reach === 'connected') ? 'cross-account' : live.some((g) => g.reach === 'service') ? 'service' : 'private';
  return { exposure, grants, findings };
}
