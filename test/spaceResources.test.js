// Resource access in Space: one outsider node for trust and resource grants, the account badges, the boxes beside
// the towers, and the layer switched off.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { startPg } from './helpers/pg.js';
import { stripResources, estateResourceLinks, accountResources, worstRes, resKind } from '../public/js/pages/spaceResources.js';
import { related, dirFilter } from '../public/js/pages/spaceRelated.js';

process.env.AWS_MODE = 'demo';
const OWN = '111111111111', BOTH = '999999999999';

// ---------------------------------------------------------------- the layer (no database)
const res = (id, severity, extra = {}) => ({ id, name: `r-${id}`, service: 's3', severity, expected: false, ...extra });
const src = (key, targets) => ({ key, id: `src:${key}`, group: key.startsWith('public') ? 'public' : 'external-account', worst: 'high', trustWorst: 'medium', targets });

test('a grant marked expected counts as low; the path takes the worst of the rest', () => {
  assert.equal(worstRes([res('a', 'high', { expected: true }), res('b', 'medium')]), 'medium');
  assert.equal(worstRes([res('a', 'high', { expected: true })]), 'low');
  assert.equal(resKind('high'), 'resHigh'); assert.equal(resKind('low'), 'res');
  const links = estateResourceLinks([src('acct:9', [{ accountId: 'A', roles: [], resources: [res('a', 'high')], resourceCount: 3 }, { accountId: 'X', roles: [], resources: [res('b', 'high')] }])], (id) => id === 'A');
  assert.deepEqual(links.map((l) => [l.to, l.kind, l.resourceCount]), [['A', 'resHigh', 3]]);   // an account not drawn gets no path
});

test('switched off: outsiders that only use resources go, trust stays with its own severity, badges and boxes go', () => {
  const d = { outside: { items: [
    src('acct:9', [{ accountId: 'A', roles: ['r1'], edges: [], resources: [res('a', 'high')], resourceCount: 1 }]),
    src('public:Anyone (principal "*")', [{ accountId: 'A', roles: [], resources: [res('b', 'high')], resourceCount: 1 }]),
  ], hidden: 0 }, accounts: [{ id: 'A', resources: { public: 1, external: 1, worst: 'high' } }], resources: [{ id: 'b' }] };
  const s = stripResources(d);
  assert.deepEqual(s.outside.items.map((x) => [x.key, x.worst, x.targets[0].resources.length]), [['acct:9', 'medium', 0]]);
  assert.equal(s.accounts[0].resources, null); assert.deepEqual(s.resources, []);
  assert.equal(d.outside.items.length, 2);                                     // the original (a cached answer) is untouched
});

test('one account: a box beside its tower, or on the inner ring; each gate fans to what its outsider can use', () => {
  const towers = [{ name: 's3', x: 132, y: 0 }], gates = [{ id: 'gate:acct:9', src: 'src:acct:9', roles: [] }];
  const sources = [src('acct:9', [{ accountId: 'A', roles: [], resources: [res('a', 'high'), res('k', 'medium', { service: 'kms' })] }])];
  const { marks, links } = accountResources([{ id: 'a', name: 'bucket', service: 's3', exposure: 'external', worst: 'high' }, { id: 'k', name: 'key', service: 'kms', exposure: 'external', worst: 'medium' }], towers, gates, sources);
  const a = marks.find((m) => m.id === 'res:a'), k = marks.find((m) => m.id === 'res:k');
  assert.ok(Math.hypot(a.x - 132, a.y) < 40, 'beside the S3 tower');
  assert.ok(Math.hypot(k.x, k.y) > 150, 'no KMS tower: on the inner ring');
  assert.deepEqual(gates[0].res, ['res:a', 'res:k']); assert.deepEqual(a.from, ['src:acct:9']);
  assert.deepEqual(links.map((l) => [l.from, l.to, l.kind, l.risk]), [['gate:acct:9', 'res:a', 'resfan', 'high'], ['gate:acct:9', 'res:k', 'resfan', 'medium']]);
  // picking the box lights its gate and its outsider; "In" keeps the resource paths
  const M = { view: 'account', gates, links: [{ id: 'link:0', from: 'src:acct:9', to: 'gate:acct:9', kind: 'resHigh' }, ...links.map((l, i) => ({ ...l, id: `link:${i + 1}` }))], roles: [], byRole: new Map() };
  const lit = related(M, 'res:a');
  assert.ok(lit.has('gate:acct:9') && lit.has('src:acct:9') && !lit.has('res:k'));
  assert.ok(M.links.every((l) => dirFilter('in', M, null).link(l)));
  assert.ok(!M.links.some((l) => dirFilter('out', M, null).link(l)));
});

// ---------------------------------------------------------------- what the API gives Space
let pg, db, space, A;
before(async () => {
  pg = await startPg(54383);
  db = await import('../src/db.js');
  await (await import('../src/migrate.js')).migrate(() => {});
  space = await import('../src/spaceApi.js');
  await db.query(`INSERT INTO workspace(name, slug, external_id) VALUES ('Acme','acme','ext-1')`);
  const acct = (await db.query(`INSERT INTO cloud_accounts(account_id, name, environment, role_arn, regions, status) VALUES ($1,'payments-prod','production','arn:x','{us-east-1}','connected') RETURNING *`, [OWN])).rows[0];
  A = acct.id;
  // an outside account that can both assume a role and read a bucket
  await db.query(`INSERT INTO roles(account_id, arn, name, kind, granted_count, trust_policy) VALUES ($1,$2,'vendor-audit','custom',10,$3)`,
    [A, `arn:aws:iam::${OWN}:role/vendor-audit`, JSON.stringify({ Statement: [{ Effect: 'Allow', Principal: { AWS: `arn:aws:iam::${BOTH}:root` }, Action: 'sts:AssumeRole' }] })]);
  const { demoGateway } = await import('../src/demo/gateway.js');
  const gw = demoGateway(acct);
  const shared = { service: 's3', arn: 'arn:aws:s3:::audit-exports', name: 'audit-exports', region: 'us-east-1', extra: {},
    policy: { Statement: [{ Effect: 'Allow', Principal: { AWS: `arn:aws:iam::${BOTH}:root` }, Action: 's3:GetObject', Resource: '*' }] } };
  await (await import('../src/resourceSync.js')).inventoryResources({ log() {}, async progress() {} }, acct,
    { ...gw, async listResources(svc) { const l = await gw.listResources(svc); return svc === 's3' ? [...l, shared] : l; } });
});
after(async () => { await db?.closePool(); await pg?.stop(); });

test('the estate: one node per outsider, with its roles and its resources; a badge per account', async () => {
  const e = await space.spaceEstate({ id: null, scope_accounts: null });
  const both = e.outside.items.find((x) => x.key === `acct:${BOTH}`);
  assert.ok(both, 'the outside account is one node');
  const t = both.targets.find((x) => x.accountId === A);
  assert.equal(t.roles.length, 1); assert.deepEqual(t.resources.map((r) => r.name), ['audit-exports']);
  assert.equal(both.trustWorst, 'high');                               // its trust (whole outside account, no ExternalId)
  const dd = e.outside.items.find((x) => x.key === 'acct:464622532012');
  assert.equal(dd.sub, 'Datadog'); assert.equal(dd.targets[0].roles.length, 0); assert.ok(dd.targets[0].resources.length);
  const pub = e.outside.items.find((x) => x.key === 'public:Anyone (principal "*")');
  assert.ok(pub.targets[0].resources.some((r) => r.name === 'demo-111-public-assets'));
  // org-wide, service and blocked grants are not drawn: only high or medium, anyone or outside the estate
  assert.ok(!e.outside.items.flatMap((x) => x.targets.flatMap((y) => y.resources)).some((r) => /org-artifacts|trail-logs|website-blocked/.test(r.name)));
  const acc = e.accounts.find((x) => x.id === A);
  assert.ok(acc.resources.public >= 3 && acc.resources.external >= 3); assert.equal(acc.resources.worst, 'high');
});

test('one account: its exposed resources, worst first, and the outsiders that use them', async () => {
  const d = await space.spaceAccount({ id: null, scope_accounts: null }, A);
  assert.ok(d.resources.length >= 6 && d.resources.every((r) => ['public', 'external'].includes(r.exposure)));
  assert.equal(d.resources[0].worst, 'high');
  assert.ok(d.outside.items.find((x) => x.key === `acct:${BOTH}`).targets[0].resources.length === 1);
  // a member who cannot see the account gets nothing
  assert.equal(await space.spaceAccount({ id: null, scope_accounts: ['00000000-0000-0000-0000-000000000001'] }, A), null);
});
