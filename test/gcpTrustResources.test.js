// Google Cloud on the Trust page (who can get in) and on the Resources page (resource-level IAM policies).
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { startPg } from './helpers/pg.js';
import { analyzeGcpResource, normalizeAsset, roleAccess, assetBindings } from '../src/gcp/resources.js';

process.env.AWS_MODE = 'demo';
process.env.DATABASE_URL = 'postgres://cm:cm@127.0.0.1:54387/cm';
const { wayFindings } = await import('../src/gcp/trust.js');

// ---------------------------------------------------------------- resource policies (no database)
const estate = { domain: 'acme.example', projects: new Set(['acme-data']), otherProjects: new Set(['acme-other']), awsAccounts: new Map([['222222222222', 'data-stg']]),
  providers: [{ pool_id: 'aws-estate', project_number: '3', type: 'aws', aws_account_id: '222222222222', attribute_condition: 'x' }],
  roleDefs: new Map([['roles/storage.objectViewer', ['storage.objects.get', 'storage.objects.list']], ['roles/storage.legacyBucketReader', ['storage.buckets.get']], ['roles/storage.admin', ['storage.buckets.setIamPolicy']]]) };
const bucket = (bindings, extra = {}) => ({ service: 'gcs', type: 'bucket', arn: '//storage.googleapis.com/b', name: 'b', project_id: 'acme-data', policy: { bindings }, extra });
const sev = (r) => r.findings.map((f) => `${f.control}:${f.severity}`).sort();

test('a bucket open to anyone: high when it reaches the objects, medium for settings, low when public access prevention refuses it', () => {
  assert.deepEqual(sev(analyzeGcpResource(bucket([{ role: 'roles/storage.objectViewer', members: ['allUsers'] }]), estate)), ['res.public:high']);
  assert.deepEqual(sev(analyzeGcpResource(bucket([{ role: 'roles/storage.legacyBucketReader', members: ['allAuthenticatedUsers'] }]), estate)), ['res.public:medium']);
  const pap = analyzeGcpResource(bucket([{ role: 'roles/storage.objectViewer', members: ['allUsers'] }], { publicAccessPrevention: 'enforced' }), estate);
  assert.deepEqual(sev(pap), ['res.public:low']); assert.match(pap.findings[0].detail, /public access prevention is enforced/);
});

test('who a member is: your domain, another domain, a service account from elsewhere, another connection, a Google agent, AWS through federation', () => {
  const one = (member, role = 'roles/storage.objectViewer') => analyzeGcpResource(bucket([{ role, members: [member] }]), estate);
  assert.equal(one('user:ana@acme.example').exposure, 'private');
  assert.equal(one('group:eng@team.acme.example').exposure, 'private');
  assert.deepEqual(sev(one('user:vendor@gmail.com')), ['res.external-account:high']);
  assert.deepEqual(sev(one('domain:partner.example')), ['res.external-account:high']);
  assert.equal(one('serviceAccount:svc@acme-data.iam.gserviceaccount.com').exposure, 'private');
  assert.deepEqual(sev(one('serviceAccount:svc@partner-1.iam.gserviceaccount.com')), ['res.external-account:high']);
  assert.deepEqual(sev(one('serviceAccount:svc@acme-other.iam.gserviceaccount.com')), ['res.cross-account:low']);
  assert.equal(one('serviceAccount:service-123@gcp-sa-pubsub.iam.gserviceaccount.com').exposure, 'service');
  assert.equal(one('projectViewer:acme-data', 'roles/storage.legacyBucketReader').exposure, 'private');
  assert.deepEqual(sev(one('principalSet://iam.googleapis.com/projects/3/locations/global/workloadIdentityPools/aws-estate/attribute.aws_role/arn:aws:sts::222222222222:assumed-role/etl')), ['res.cross-account:low']);
  assert.deepEqual(sev(one('deleted:user:old@acme.example?uid=1')), ['res.deleted-principal:low']);
  assert.deepEqual(sev(one('user:vendor@gmail.com', 'roles/storage.admin')), ['res.broad-actions:low', 'res.external-account:high']);
  // a control turned off makes no finding; the exposure stays a fact
  const off = analyzeGcpResource(bucket([{ role: 'roles/storage.objectViewer', members: ['allUsers'] }]), estate, { over: new Map([['res.public', { enabled: false, severity: null }]]), rules: [], sig: '' });
  assert.deepEqual(off.findings, []); assert.equal(off.exposure, 'public');
});

test('assets: names, projects by number, the bindings they add to principals; what a role allows without its definition', () => {
  const t = normalizeAsset({ assetType: 'bigquery.googleapis.com/Table', resource: '//bigquery.googleapis.com/projects/acme-data/datasets/sales/tables/orders', project: 'projects/42', policy: { bindings: [{ role: 'r', members: ['user:a@x'] }] } }, new Map([['42', 'acme-data']]));
  assert.deepEqual([t.service, t.type, t.name, t.project_id], ['bigquery', 'table', 'sales.orders', 'acme-data']);
  const k = normalizeAsset({ assetType: 'cloudkms.googleapis.com/CryptoKey', resource: '//cloudkms.googleapis.com/projects/p/locations/asia-southeast2/keyRings/r/cryptoKeys/k', policy: { bindings: [] } });
  assert.deepEqual([k.name, k.region, k.policy], ['k', 'asia-southeast2', null]);
  assert.equal(normalizeAsset({ assetType: 'compute.googleapis.com/Instance', resource: 'x' }), null);
  assert.deepEqual(assetBindings([t]).map((b) => [b.resource_type, b.member]), [['table', 'user:a@x']]);
  assert.equal(roleAccess('roles/storage.objectViewer'), 'data'); assert.equal(roleAccess('roles/pubsub.admin'), 'admin'); assert.equal(roleAccess('roles/browser'), 'read');
});

test('ways in: impersonation granted on a whole project is flagged, Owner and Editor are not (their own finding); keys by age', () => {
  const w = (o) => ({ target: { kind: 'serviceAccount', label: 'sa@p' }, from: 'org', label: 'x', at: { type: 'project', label: 'project p' }, ...o });
  assert.deepEqual(wayFindings(w({ via: 'actAs', role: 'roles/iam.serviceAccountUser', wide: true })).map((f) => f.id), ['wide-impersonation']);
  assert.deepEqual(wayFindings(w({ via: 'actAs', role: 'roles/owner', wide: true })).map((f) => `${f.id}:${f.severity}`), ['basic-role:info']);
  const key = (days) => wayFindings(w({ via: 'key', from: 'key', keys: [{ created: new Date(Date.now() - days * 864e5).toISOString(), expires: null }] }))[0].severity;
  assert.equal(key(400), 'medium'); assert.equal(key(10), 'low');
  assert.deepEqual(wayFindings(w({ from: 'public', via: 'direct', target: { kind: 'bucket', label: 'b' }, blocked: true, role: 'roles/storage.objectViewer' })).map((f) => f.severity), ['low']);
});

// ---------------------------------------------------------------- the scan, the pages
let pg, db, scan, conn, rs, api, trust;
before(async () => {
  pg = await startPg(54387);
  db = await import('../src/db.js');
  await (await import('../src/migrate.js')).migrate(() => {});
  scan = await import('../src/gcp/scan.js'); rs = await import('../src/resourceSync.js'); api = await import('../src/resourcesApi.js'); trust = await import('../src/gcp/trust.js');
  await db.query(`INSERT INTO workspace(name, slug, external_id) VALUES ('Acme','acme','x')`);
  conn = (await db.query(`INSERT INTO gcp_connections(name, scope_type, scope_id, auth_mode, wif, environment, status) VALUES ('acme.example','organization','100000000001','wif','{}','shared','connected') RETURNING *`)).rows[0];
});
after(async () => { delete process.env.DEMO_GCP_ASSET_DENIED; await db?.closePool(); await pg?.stop(); });

const owner = { id: null, scope_accounts: null };
// as the worker does (gcpTick): the scan's summary, with the organisation's domain, goes on the connection
const rescan = async () => { const s = await scan.scanGcpConnection(conn); await db.query('UPDATE gcp_connections SET status_detail = $2 WHERE id = $1', [conn.id, JSON.stringify(s)]); return s; };
const res = async (name) => (await db.query(`SELECT r.*, (SELECT array_agg(control || ':' || severity ORDER BY control) FROM resource_findings f WHERE f.resource_id = r.id AND f.status = 'open') AS f FROM resources r WHERE r.cloud = 'gcp' AND r.name = $1`, [name])).rows[0];

test('a scan reads resource-level policies: stored on the Resources page, and on the principals\' roles', async () => {
  const s = await rescan();
  assert.equal(s.resources.source, 'asset'); assert.equal(s.resources.stored, 10);
  assert.deepEqual((await res('acme-public-site')).f, ['res.public:high']);
  const exp = await res('acme-payments-exports');
  assert.equal(exp.extra.publicAccessPrevention, 'enforced'); assert.deepEqual(exp.f, ['res.public:low']);
  assert.equal((await res('finance')).exposure, 'external');
  assert.equal((await res('orders')).exposure, 'external');                // a partner's service account publishes to it
  assert.equal((await res('db-password')).exposure, 'private');
  assert.equal((await res('lake-key')).exposure, 'external');              // AWS 222222222222 is not connected here
  const vendor = (await db.query(`SELECT roles FROM gcp_principals WHERE member = 'user:vendor.dev@gmail.com'`)).rows[0];
  assert.ok(vendor.roles.some((r) => r.resourceType === 'bucket' && r.role === 'roles/storage.objectAdmin'));
  // a role on a bucket makes no one able to become a service account
  const deployer = (await db.query(`SELECT sources FROM gcp_principals WHERE member LIKE 'serviceAccount:payments-api@%'`)).rows[0];
  assert.ok(!deployer.sources.some((x) => /storage/.test(x.role || '')));
});

test('the Resources page lists both clouds; members limited to AWS accounts see no Google Cloud', async () => {
  const all = await api.listResources(owner, { cloud: 'gcp' });
  assert.ok(all.total >= 7 && all.items.every((x) => x.cloud === 'gcp'));
  assert.equal(all.items[0].worst, 'high'); assert.ok(all.labels.services.gcs);
  assert.deepEqual((await api.listResources(owner, { service: 'cloudrun' })).items.map((x) => x.name), ['status-page']);
  assert.deepEqual((await api.listResources(owner, { q: 'acme-payments-prod', exposure: 'all' })).items.map((x) => x.name).sort(), ['acme-payments-exports', 'db-password', 'finance', 'orders']);
  const d = await api.resourceDetail(owner, all.items[0].id);
  assert.equal(d.cloud, 'gcp'); assert.ok(d.project_id && d.grants.length && d.findings.length);
  const scoped = { id: null, scope_accounts: ['00000000-0000-0000-0000-000000000001'] };
  assert.equal((await api.listResources(scoped, { cloud: 'gcp' })).total, 0);
  await assert.rejects(api.resourceDetail(scoped, all.items[0].id), { status: 404 });
});

test('the Trust page for Google Cloud: ways in to service accounts and outside identities, with the outside sources rolled up', async () => {
  const t = await trust.gcpTrust({ all: true });
  const one = (pred) => t.items.find(pred);
  assert.equal(one((w) => /etl-runner/.test(w.target.label) && w.from === 'aws').worst, 'high');
  assert.equal(one((w) => w.via === 'gke').from, 'gke');
  assert.equal(one((w) => /acme-payments-exports/.test(w.target.label)).worst, 'low');   // public access prevention
  assert.equal(one((w) => /partner-prod-123/.test(w.member || '')).from, 'other-org');
  assert.ok(!t.items.some((w) => w.findings.some((f) => f.id === 'wide-impersonation') && /owner|editor/.test(w.role)));
  const vendor = t.sources.find((s) => s.label === 'vendor.dev@gmail.com');
  assert.deepEqual([vendor.from, vendor.targets], ['external', 2]);
  // filters and counts
  const pub = await trust.gcpTrust({ from: 'public' });
  assert.ok(pub.total >= 4 && pub.items.every((w) => w.from === 'public'));
  assert.ok(pub.counts.from.aws >= 3, 'the From counts ignore the From filter');
  assert.ok((await trust.gcpTrust({ attention: '1' })).items.every((w) => ['high', 'medium'].includes(w.worst)));
  assert.match((await trust.gcpTrustCsv({})).split('\n')[0], /^Severity,Way in to/);
});

test('Cloud Asset Inventory refused: the main services are read one by one; what is gone is closed; the AWS estate is followed', async () => {
  process.env.DEMO_GCP_ASSET_DENIED = '1';
  const s = await rescan();
  delete process.env.DEMO_GCP_ASSET_DENIED;
  assert.equal(s.resources.source, 'per-service'); assert.match(s.resources.assetError, /not enabled/); assert.deepEqual(s.resources.skipped, ['bigquery', 'pubsub']);
  const fin = await res('finance');
  assert.ok(fin.deleted_at); assert.equal(fin.f, null);
  await rescan();
  assert.equal((await res('finance')).deleted_at, null);
  // the AWS account behind the federated pool is onboarded: the key is shared with your own estate now
  await db.query(`INSERT INTO cloud_accounts(account_id, name, role_arn, regions, status) VALUES ('222222222222','data-stg','arn:x','{us-east-1}','connected')`);
  await rs.resourceTick();
  assert.equal((await res('lake-key')).exposure, 'cross-account');
});

test('Space for Google Cloud: calls from the audit logs by day and by hour, never-called service accounts, resources, one project shaped like an account', async () => {
  const usage = await import('../src/gcp/usage.js'), space = await import('../src/gcp/space.js');
  // without usage: heights are what a service account can do, nothing is called cold, towers count service accounts
  let e = await space.spaceGcp();
  const stg0 = e.projects.find((p) => p.projectId === 'acme-data-stg');
  assert.deepEqual([stg0.usage, stg0.calls7, stg0.cold], [false, 0, 0]);
  assert.ok(stg0.accounts.every((a) => a.used === null));
  const p0 = await space.spaceGcpProject('acme-data-stg');
  assert.equal(p0.usage, false); assert.equal(p0.coldCount, 0);
  assert.ok(p0.clusters.some((c) => c.key === 'storage'), 'placed by the service its roles reach');

  // read 3 days of audit logs: per day for heights, per hour for the replay
  await db.query(`UPDATE gcp_connections SET usage_enabled = true, usage_lookback_days = 3 WHERE id = $1`, [conn.id]);
  await usage.syncCursors();
  for (let i = 0; i < 100; i++) { const r = await usage.usageTick('t', { gwFor: (c) => scan.gcpGateway(c), budgetMs: 60000 }); if (!r) break; }
  const hourly = (await db.query(`SELECT sum(count)::int AS n FROM gcp_activity_hourly`)).rows[0].n;
  const daily = (await db.query(`SELECT sum(count)::int AS n FROM gcp_activity_daily`)).rows[0].n;
  assert.ok(hourly > 0 && hourly === daily, `the hours add up to the days (${hourly} vs ${daily})`);

  e = await space.spaceGcp();
  const stg = e.projects.find((p) => p.projectId === 'acme-data-stg');
  assert.equal(stg.usage, true);
  assert.ok(stg.calls7 > 0 && stg.hourly.reduce((n, b) => n + b.calls, 0) > 0);
  const analytics = stg.accounts.find((a) => a.email.startsWith('analytics@'));
  assert.equal(analytics.used, false); assert.equal(stg.cold, 1);
  assert.deepEqual(stg.resources, { public: 0, external: 1, worst: 'high' });
  // one outsider node for trust and resources; a role on one resource is not a trust path
  const vendor = e.outside.find((o) => o.key === 'user:vendor.dev@gmail.com');
  const vt = vendor.targets.find((t) => t.projectId === 'acme-data-stg');
  assert.equal(vt.resources[0].name, 'acme-lake-raw'); assert.equal(vt.resources[0].service, 'storage');
  assert.ok(!vt.direct.some((d) => /acme-lake-raw/.test(d.what)));
  const anyone = e.outside.find((o) => o.key === 'allUsers');
  assert.ok(anyone.targets.every((t) => !t.direct.length && !t.principals.length), 'allUsers only has resources');

  const p = await space.spaceGcpProject('acme-data-stg');
  assert.equal(p.account.id, 'gcp:acme-data-stg'); assert.equal(p.usage, true);
  assert.deepEqual(p.services.map((s) => s.name).sort(), ['bigquery', 'dataflow', 'storage']);
  assert.deepEqual(p.cold.map((c) => c.name), ['analytics']);
  assert.equal(p.clusters.find((c) => c.key === 'storage').roles[0].name, 'lake-sync');
  // AWS accounts past the edge (here only 222222222222 is connected): federation into a service account, and roles
  // held directly, which come in at a door on the edge
  const nb = Object.fromEntries(p.neighbours.map((x) => [x.name, x.links]));
  assert.deepEqual(Object.keys(nb), ['data-stg']);
  const lake = p.clusters.flatMap((c) => c.roles).find((r) => r.name === 'lake-sync');
  assert.ok(nb['data-stg'].some((l) => l.dir === 'in' && l.roleId === lake.id && l.otherRole === 'data-etl'));
  assert.ok(nb['data-stg'].some((l) => l.dir === 'in' && l.roleId === null));
  assert.equal(p.resources[0].service, 'storage');
  // project to project: the shared CI deployer holds roles on the payments folder, so a line to the project under it
  const ci = e.chains.find((c) => c.from === 'gcp:acme-shared-ci' && c.to === 'gcp:acme-payments-prod');
  assert.ok(ci, 'shared CI reaches payments');
  const dep = ci.grants.find((g) => g.caller.startsWith('deployer@'));
  assert.deepEqual(dep.roles.sort(), ['roles/iam.serviceAccountUser', 'roles/run.admin']);
  assert.equal(dep.on, 'every project in folders/200000000001'); assert.equal(dep.folder, true);
  assert.ok(!e.chains.some((c) => c.grants.some((g) => g.caller.startsWith('terraform@'))), 'an organization role draws no line');
  const pay = await space.spaceGcpProject('acme-payments-prod');
  const nci = pay.neighbours.find((n) => n.id === 'gcp:acme-shared-ci');
  assert.equal(nci.cloud, 'gcp'); assert.ok(nci.links.every((l) => l.dir === 'in') && nci.links.some((l) => /deployer/.test(l.otherRole)));
  const ciView = await space.spaceGcpProject('acme-shared-ci');
  const deployer = ciView.clusters.flatMap((c) => c.roles).find((r) => r.name === 'deployer');
  assert.ok(ciView.neighbours.find((n) => n.id === 'gcp:acme-payments-prod').links.some((l) => l.dir === 'out' && l.roleId === deployer.id));
  assert.equal(await space.spaceGcpProject('no-such-project'), null);
});
