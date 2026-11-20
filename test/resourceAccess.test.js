// Resource access: who resource-based policies let in, the findings, the scanner step and the re-analysis.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { startPg } from './helpers/pg.js';
import { analyzeResource, accessOf } from '../src/analyzer/resourcePolicy.js';

process.env.AWS_MODE = 'demo';
const OWN = '111111111111', STG = '222222222222', VENDOR = '464622532012', STRANGER = '888888888888';
const estate = { connected: new Map([[OWN, 'payments-prod'], [STG, 'data-stg']]), org: new Map([['555555555555', 'security-tools']]), orgIds: new Set(['o-curiousdemo1']),
  vendor: (a) => (a === VENDOR ? 'Datadog' : null) };
const run = (service, statements, extra = {}) => analyzeResource({ service, arn: 'arn:x', name: 'x', accountId: OWN, policy: { Statement: statements }, extra }, estate);
const one = (r) => r.findings.map((f) => `${f.control}:${f.severity}`).sort();

// ---------------------------------------------------------------- the analysis (no database)
test('anyone: high when it reaches the data, medium for metadata or behind a network condition, low behind S3 Block Public Access', () => {
  assert.deepEqual(one(run('s3', [{ Effect: 'Allow', Principal: '*', Action: 's3:GetObject', Resource: '*' }])), ['res.public:high']);
  assert.deepEqual(one(run('s3', [{ Effect: 'Allow', Principal: { AWS: '*' }, Action: 's3:GetBucketLocation', Resource: '*' }])), ['res.public:medium']);
  assert.deepEqual(one(run('sqs', [{ Effect: 'Allow', Principal: '*', Action: 'sqs:SendMessage', Condition: { StringEquals: { 'aws:SourceVpce': 'vpce-1' } } }])), ['res.public:medium']);
  const blocked = run('s3', [{ Effect: 'Allow', Principal: '*', Action: 's3:GetObject' }], { restrictPublic: true, restrictPublicFrom: 'the account\'s Block Public Access' });
  assert.deepEqual(one(blocked), ['res.public:low']); assert.match(blocked.findings[0].detail, /account's Block Public Access/);
  assert.equal(blocked.exposure, 'public');
  assert.deepEqual(one(run('s3', [{ Effect: 'Allow', NotPrincipal: { AWS: `arn:aws:iam::${OWN}:root` }, Action: 's3:GetObject' }])), ['res.not-principal:high']);
});

test('who an account is: yours (connected or in the organisation), a known vendor, or a stranger', () => {
  const v = run('s3', [{ Effect: 'Allow', Principal: { AWS: `arn:aws:iam::${VENDOR}:root` }, Action: ['s3:GetObject', 's3:ListBucket'] }]);
  assert.equal(v.exposure, 'external'); assert.deepEqual(one(v), ['res.external-account:high']); assert.match(v.findings[0].title, /Datadog/);
  assert.deepEqual(one(run('kms', [{ Effect: 'Allow', Principal: { AWS: `arn:aws:iam::${STRANGER}:role/etl` }, Action: 'kms:DescribeKey' }])), ['res.external-account:medium']);
  const stg = run('dynamodb', [{ Effect: 'Allow', Principal: { AWS: `arn:aws:iam::${STG}:role/app` }, Action: 'dynamodb:Query' }]);
  assert.equal(stg.exposure, 'cross-account'); assert.deepEqual(one(stg), ['res.cross-account:low']); assert.match(stg.findings[0].title, /data-stg/);
  assert.deepEqual(one(run('kms', [{ Effect: 'Allow', Principal: { AWS: 'arn:aws:iam::555555555555:root' }, Action: 'kms:Decrypt' }])), ['res.cross-account:low']);
  // the default key policy: its own account, every KMS action
  const own = run('kms', [{ Sid: 'EnableIAMPolicies', Effect: 'Allow', Principal: { AWS: `arn:aws:iam::${OWN}:root` }, Action: 'kms:*', Resource: '*' }]);
  assert.equal(own.exposure, 'private'); assert.deepEqual(own.findings, []);
  // every action of the service to someone outside the account
  assert.deepEqual(one(run('kms', [{ Effect: 'Allow', Principal: { AWS: `arn:aws:iam::${STRANGER}:root` }, Action: 'kms:*' }])), ['res.broad-actions:low', 'res.external-account:high']);
});

test('conditions narrow who: an organisation, an account, a source ARN; values that match anything do not', () => {
  assert.equal(run('s3', [{ Effect: 'Allow', Principal: '*', Action: 's3:GetObject', Condition: { StringEquals: { 'aws:PrincipalOrgID': 'o-curiousdemo1' } } }]).exposure, 'cross-account');
  // someone else's organisation is outside
  assert.deepEqual(one(run('s3', [{ Effect: 'Allow', Principal: '*', Action: 's3:GetObject', Condition: { StringEquals: { 'aws:PrincipalOrgID': 'o-someoneelse1' } } }])), ['res.external-account:high']);
  assert.equal(run('s3', [{ Effect: 'Allow', Principal: '*', Action: 's3:GetObject', Condition: { StringEquals: { 'aws:PrincipalAccount': OWN } } }]).exposure, 'private');
  assert.equal(run('sns', [{ Effect: 'Allow', Principal: { AWS: '*' }, Action: 'SNS:Publish', Condition: { StringEquals: { 'AWS:SourceOwner': OWN } } }]).exposure, 'private');
  assert.equal(run('s3', [{ Effect: 'Allow', Principal: '*', Action: 's3:GetObject', Condition: { ArnLike: { 'aws:PrincipalArn': `arn:aws:iam::${STG}:role/*` } } }]).exposure, 'cross-account');
  assert.equal(run('s3', [{ Effect: 'Allow', Principal: '*', Action: 's3:GetObject', Condition: { StringLike: { 'aws:PrincipalOrgID': '*' } } }]).exposure, 'public');
  // a negated operator in an Allow narrows nothing
  assert.equal(run('s3', [{ Effect: 'Allow', Principal: '*', Action: 's3:GetObject', Condition: { StringNotEquals: { 'aws:PrincipalAccount': STRANGER } } }]).exposure, 'public');
});

test('a Deny guard with one condition narrows every grant; one with two is not counted; services can be exempted', () => {
  const guard = (cond) => ({ Effect: 'Deny', Principal: '*', Action: 's3:*', Resource: '*', Condition: cond });
  const pub = { Effect: 'Allow', Principal: '*', Action: 's3:GetObject' };
  const g = run('s3', [pub, guard({ StringNotEquals: { 'aws:PrincipalOrgID': 'o-curiousdemo1' } })]);
  assert.equal(g.exposure, 'cross-account'); assert.match(g.grants[0].narrowedBy.join(), /Deny guard/);
  assert.equal(run('s3', [pub, guard({ StringNotEquals: { 'aws:PrincipalOrgID': 'o-curiousdemo1', 'aws:SourceVpce': 'vpce-1' } })]).exposure, 'public');
  const ct = { Effect: 'Allow', Principal: { Service: 'cloudtrail.amazonaws.com' }, Action: 's3:PutObject' };
  // services exempted from the guard: CloudTrail is still not scoped to a source
  assert.deepEqual(one(run('s3', [ct, guard({ StringNotEquals: { 'aws:PrincipalOrgID': 'o-curiousdemo1' }, Bool: { 'aws:PrincipalIsAWSService': 'false' } })])), ['res.service-no-source:medium']);
});

test('AWS services: without a source condition a confused deputy, with one as far as its account', () => {
  assert.deepEqual(one(run('sns', [{ Effect: 'Allow', Principal: { Service: 'events.amazonaws.com' }, Action: 'sns:Publish' }])), ['res.service-no-source:medium']);
  const scoped = run('lambda', [{ Effect: 'Allow', Principal: { Service: 's3.amazonaws.com' }, Action: 'lambda:InvokeFunction', Condition: { StringEquals: { 'AWS:SourceAccount': OWN } } }]);
  assert.equal(scoped.exposure, 'private'); assert.deepEqual(scoped.findings, []);
  // S3 ARNs carry no account: scoped, and left at "AWS services"
  assert.equal(run('sqs', [{ Effect: 'Allow', Principal: { Service: 's3.amazonaws.com' }, Action: 'sqs:SendMessage', Condition: { ArnLike: { 'aws:SourceArn': 'arn:aws:s3:::my-bucket' } } }]).exposure, 'service');
  assert.deepEqual(one(run('sqs', [{ Effect: 'Allow', Principal: { Service: 'sns.amazonaws.com' }, Action: 'sqs:SendMessage', Condition: { StringEquals: { 'aws:SourceAccount': STRANGER } } }])), ['res.external-account:high']);
});

test('what a grant allows, and the workspace policy: another severity, or a control turned off', () => {
  assert.equal(accessOf(['s3:GetBucketLocation']), 'read');
  assert.equal(accessOf(['s3:GetObject']), 'data');
  assert.equal(accessOf(['kms:Decrypt']), 'data');
  assert.equal(accessOf(['s3:PutBucketPolicy']), 'admin');
  assert.equal(accessOf(['s3:*']), 'admin');
  assert.equal(accessOf([], ['s3:DeleteBucket']), 'admin');
  const st = [{ Effect: 'Allow', Principal: { AWS: `arn:aws:iam::${STG}:role/app` }, Action: 'dynamodb:Query' }];
  const policy = (over) => ({ over: new Map(Object.entries(over)), rules: [], sig: '' });
  assert.deepEqual(one(analyzeResource({ service: 'dynamodb', arn: 'a', name: 'a', accountId: OWN, policy: { Statement: st } }, estate, policy({ 'res.cross-account': { severity: 'medium', enabled: true } }))), ['res.cross-account:medium']);
  const off = analyzeResource({ service: 'dynamodb', arn: 'a', name: 'a', accountId: OWN, policy: { Statement: st } }, estate, policy({ 'res.cross-account': { severity: null, enabled: false } }));
  assert.deepEqual(off.findings, []); assert.equal(off.exposure, 'cross-account');      // a fact stays a fact
  assert.equal(run('ecr', [{ Effect: 'Allow', Principal: { AWS: 'AROAEXAMPLEDELETED123' }, Action: 'ecr:*' }]).findings[0].control, 'res.deleted-principal');
});

// ---------------------------------------------------------------- the scanner step and the re-analysis
let pg, db, sync, A, B;
const logs = [];
const ctx = { log: (m, d, level) => logs.push([level, m]), progress: async () => {} };
before(async () => {
  pg = await startPg(54381);
  db = await import('../src/db.js');
  await (await import('../src/migrate.js')).migrate(() => {});
  sync = await import('../src/resourceSync.js');
  await db.query(`INSERT INTO workspace(name, slug, external_id) VALUES ('Acme','acme','ext-1')`);
  const acct = async (id, name) => (await db.query(`INSERT INTO cloud_accounts(account_id, name, environment, role_arn, regions, status) VALUES ($1,$2,'production','arn:x','{us-east-1}','connected') RETURNING *`, [id, name])).rows[0];
  A = await acct(OWN, 'payments-prod'); B = await acct(STG, 'data-stg');
});
after(async () => { await db?.closePool(); await pg?.stop(); });

const gwOf = async (account, patch = {}) => {
  const { demoGateway } = await import('../src/demo/gateway.js');
  const gw = demoGateway(account);
  return { ...gw, async listResources(svc) { if (patch[svc] instanceof Error) throw patch[svc]; return patch[svc] ? patch[svc](await gw.listResources(svc)) : gw.listResources(svc); } };
};
const findings = async (name) => (await db.query(
  `SELECT f.* FROM resource_findings f JOIN resources r ON r.id = f.resource_id WHERE r.account_id = $1 AND r.name = $2 ORDER BY f.control`, [A.id, name])).rows;

test('a scan stores every service\'s resources, the organisation, the exposure and the findings', async () => {
  const out = await sync.inventoryResources(ctx, A, await gwOf(A));
  assert.deepEqual(out.skipped, []);
  assert.equal(out.resources.s3, 6); assert.equal(out.resources.kms, 3);
  assert.equal((await db.query('SELECT aws_org_id FROM cloud_accounts WHERE id=$1', [A.id])).rows[0].aws_org_id, 'o-curiousdemo1');
  const by = new Map((await db.query('SELECT name, exposure, worst FROM resources WHERE account_id=$1', [A.id])).rows.map((x) => [x.name, x]));
  assert.equal(by.get('demo-111-public-assets').exposure, 'public'); assert.equal(by.get('demo-111-public-assets').worst, 'high');
  assert.equal(by.get('demo-111-private').exposure, 'none');
  assert.equal(by.get('vendor/api-key').exposure, 'external');
  assert.equal(by.get('shared-backups').exposure, 'cross-account');         // data-stg is connected
  assert.equal(by.get('demo-111-org-artifacts').exposure, 'cross-account'); // the organisation, now known
  assert.equal(by.get('payments-data').worst, null);
  // the first scan of an account reports nothing to the change feed: everything would be "new"
  assert.equal((await db.query(`SELECT count(*)::int n FROM changes WHERE kind LIKE 'resource-%'`)).rows[0].n, 0);
});

test('a policy that changes is a change: opened to anyone goes to the feed; a decision stays while its grant stays', async () => {
  const [ext] = (await findings('vendor/api-key')).filter((f) => f.control === 'res.external-account');
  await db.query(`UPDATE resource_findings SET decision='expected', note='vendor contract' WHERE id=$1`, [ext.id]);
  const openLedger = (list) => list.map((x) => (x.name === 'ledger' ? { ...x, policy: { Statement: [{ Effect: 'Allow', Principal: '*', Action: 'dynamodb:GetItem', Resource: '*' }] } } : x));
  await sync.inventoryResources(ctx, A, await gwOf(A, { dynamodb: openLedger }));
  const ch = (await db.query(`SELECT kind, severity, title FROM changes WHERE kind LIKE 'resource-%'`)).rows;
  assert.deepEqual(ch.map((x) => [x.kind, x.severity]), [['resource-public', 'high']]); assert.match(ch[0].title, /ledger opened to anyone/);
  assert.equal((await findings('vendor/api-key')).find((f) => f.id === ext.id).decision, 'expected');
  // the vendor gets more: the grant changed, the decision is cleared
  const wider = (list) => list.map((x) => (x.name === 'vendor/api-key' ? { ...x, policy: { Statement: [{ ...x.policy.Statement[0], Action: ['secretsmanager:GetSecretValue', 'secretsmanager:PutSecretValue'] }] } } : x));
  await sync.inventoryResources(ctx, A, await gwOf(A, { dynamodb: openLedger, secretsmanager: wider }));
  assert.equal((await findings('vendor/api-key')).find((f) => f.id === ext.id).decision, null);
  // fixed: the finding is resolved, the resource is private
  await sync.inventoryResources(ctx, A, await gwOf(A));
  assert.equal((await findings('ledger')).every((f) => f.status === 'resolved'), true);
  assert.equal((await db.query(`SELECT exposure FROM resources WHERE name='ledger'`)).rows[0].exposure, 'none');
});

test('a service the scanner role may not list is skipped, and what is stored for it stays; a deleted resource is closed', async () => {
  logs.length = 0;
  const denied = Object.assign(new Error('User is not authorized to perform: kms:ListKeys'), { name: 'AccessDeniedException' });
  const out = await sync.inventoryResources(ctx, A, await gwOf(A, { kms: denied, ecr: (l) => l.filter((x) => x.name !== 'old-app') }));
  assert.deepEqual(out.skipped, ['kms']);
  assert.ok(logs.some(([lv, m]) => lv === 'warn' && /KMS resource policies skipped.*kms:GetKeyPolicy/.test(m)));
  assert.equal((await db.query(`SELECT count(*)::int n FROM resources WHERE account_id=$1 AND service='kms' AND deleted_at IS NULL`, [A.id])).rows[0].n, 3);
  assert.ok((await db.query(`SELECT deleted_at FROM resources WHERE name='old-app'`)).rows[0].deleted_at);
  assert.ok((await findings('old-app')).every((f) => f.status === 'resolved'));
});

test('the re-analysis follows the estate and the policy: an account removed is outside; a control turned off closes its findings', async () => {
  await sync.resourceTick({ force: true });
  assert.equal(await sync.resourceTick(), null);                             // nothing changed since
  await db.query('DELETE FROM cloud_accounts WHERE id=$1', [B.id]);
  const r = await sync.resourceTick();
  assert.ok(r.opened >= 1);
  assert.equal((await db.query(`SELECT exposure FROM resources WHERE name='shared-backups'`)).rows[0].exposure, 'external');
  assert.deepEqual((await findings('shared-backups')).filter((f) => f.status === 'open').map((f) => `${f.control}:${f.severity}`), ['res.external-account:high']);
  await db.query(`INSERT INTO control_overrides(control_id, enabled) VALUES ('res.cross-account', false)`);
  await sync.resourceTick();
  assert.ok((await findings('demo-111-org-artifacts')).every((f) => f.status === 'resolved'));
  // the re-analysis never writes to the change feed
  assert.equal((await db.query(`SELECT count(*)::int n FROM changes WHERE kind = 'resource-shared'`)).rows[0].n, 0);
});

// ---------------------------------------------------------------- the API
test('the list: shared beyond the account by default, with facets, search, a control, and members\' account scope', async () => {
  const api = await import('../src/resourcesApi.js');
  const owner = { id: null, scope_accounts: null };
  const r = await api.listResources(owner, {});
  assert.ok(r.items.length > 0 && r.items.every((x) => api.SHARED.includes(x.exposure)));
  assert.equal(r.items[0].worst, 'high');                                     // most exposed first
  assert.ok(r.exposure.public >= 3 && r.exposure.external >= 2);
  assert.ok(r.attention >= 1);
  const all = await api.listResources(owner, { exposure: 'all' });
  assert.equal(all.total, Object.values(all.exposure).reduce((a, b) => a + b, 0));
  assert.ok(all.total > r.total && all.exposure.none >= 1 && all.exposure.private >= 1);
  assert.deepEqual((await api.listResources(owner, { q: 'Datadog' })).items.map((x) => x.name), ['demo-111-vendor-exports']);
  assert.ok((await api.listResources(owner, { control: 'res.service-no-source', exposure: 'all' })).items.every((x) => x.controls.includes('res.service-no-source')));
  assert.deepEqual((await api.listResources(owner, { service: 'lambda' })).items.map((x) => x.name), ['status-url']);
  // a member scoped to other accounts sees none of them, and cannot open one
  const scoped = { id: null, scope_accounts: ['00000000-0000-0000-0000-000000000001'] };
  assert.equal((await api.listResources(scoped, {})).total, 0);
  await assert.rejects(api.resourceDetail(scoped, r.items[0].id), { status: 404 });
  const d = await api.resourceDetail(owner, r.items[0].id);
  assert.ok(d.grants.length && d.findings.length && d.policy);
  const csv = await api.resourcesCsv(owner, {});
  assert.match(csv.split('\n')[0], /^Cloud,Account,Account ID/); assert.ok(csv.includes('demo-111-public-assets'));
});

test('decisions: expected needs a reason, and leaves "needs attention"; a resolved finding takes none', async () => {
  const api = await import('../src/resourcesApi.js');
  const user = (await db.query(`INSERT INTO users(email, name, role, password_hash) VALUES ('r@acme.example','Rina','reviewer','x') RETURNING *`)).rows[0];
  const [f] = (await findings('vendor/api-key')).filter((x) => x.status === 'open');
  const before = (await api.listResources({ scope_accounts: null }, { state: 'attention' })).items.map((x) => x.name);
  assert.ok(before.includes('vendor/api-key'));
  await assert.rejects(api.decide(user, f.id, { decision: 'expected' }), (e) => e.issues?.[0]?.path?.[0] === 'note');
  await api.decide(user, f.id, { decision: 'expected', note: 'vendor contract until 2027' });
  assert.ok(!(await api.listResources({ scope_accounts: null }, { state: 'attention' })).items.some((x) => x.name === 'vendor/api-key'));
  assert.equal((await api.resourceDetail(user, f.resource_id)).findings.find((x) => x.id === f.id).decided_by, 'Rina');
  await api.undecide(user, f.id);
  assert.equal((await findings('vendor/api-key')).find((x) => x.id === f.id).decision, null);
  const [gone] = (await findings('ledger')).filter((x) => x.status === 'resolved');
  await assert.rejects(api.decide(user, gone.id, { decision: 'investigate' }), { status: 409 });
});

test('the Policy page counts resource findings under their controls', async () => {
  const { listControls } = await import('../src/controls.js');
  const c = await listControls({ scope_accounts: null }, 'domain:resource');
  assert.equal(c.items.length, 7);
  assert.ok(c.items.find((x) => x.id === 'res.public').open >= 3);
});
