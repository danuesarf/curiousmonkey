// One Trust map for both clouds: Google Cloud ways in as edges (projects as accounts, what is reached as roles), with
// filters, findings filed in the inbox and decided there, changes fed, and chains across clouds. Made-up names only.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { startPg } from './helpers/pg.js';

process.env.AWS_MODE = 'demo';
process.env.DATABASE_URL = 'postgres://cm:cm@127.0.0.1:54388/cm';
process.env.CACHE_FRESH_MS = '0';

let pg, db, tm, sync, findings, radar, conn, owner;
const scoped = { id: null, scope_accounts: ['00000000-0000-0000-0000-000000000001'] };
const gcpOf = (ix) => ix.edges.filter((e) => e.cloud === 'gcp');

before(async () => {
  pg = await startPg(54388);
  db = await import('../src/db.js');
  await (await import('../src/migrate.js')).migrate(() => {});
  await db.query(`INSERT INTO workspace(name, slug, external_id) VALUES ('Acme','acme','x')`);
  owner = (await db.query(`INSERT INTO users(email, name, role, password_hash) VALUES ('dana@acme.example','Dana','owner','x') RETURNING id, role`)).rows[0];
  owner.scope_accounts = null;
  // one AWS account of the estate is connected: AWS federation from it into Google Cloud is a line between your accounts
  await db.query(`INSERT INTO cloud_accounts(account_id, name, role_arn, regions, status, environment) VALUES ('222222222222','data-stg','arn:x','{us-east-1}','connected','staging')`);
  conn = (await db.query(`INSERT INTO gcp_connections(name, scope_type, scope_id, auth_mode, wif, environment, status) VALUES ('acme.example','organization','100000000001','wif','{}','shared','connected') RETURNING *`)).rows[0];
  const scan = await import('../src/gcp/scan.js');
  const s = await scan.scanGcpConnection(conn);
  await db.query('UPDATE gcp_connections SET status_detail = $2 WHERE id = $1', [conn.id, JSON.stringify(s)]);
  tm = await import('../src/trustmap.js'); sync = await import('../src/trustSync.js'); findings = await import('../src/findingsApi.js'); radar = await import('../src/radarApi.js');
});
after(async () => { await db?.closePool(); await pg?.stop(); });

test('Google Cloud ways in are Trust map edges: projects as accounts, where they come from as the map\'s groups', async () => {
  const ix = await tm.trustIndex();
  assert.deepEqual(ix.accounts.filter((a) => a.cloud === 'gcp').map((a) => a.id).sort(), ['gcp:acme-data-stg', 'gcp:acme-payments-prod', 'gcp:acme-shared-ci']);
  const g = gcpOf(ix);
  const one = (pred, what) => { const e = g.find(pred); assert.ok(e, what); return e; };
  // AWS federation: from an AWS account you connect, a line between your accounts; from one you do not, an outsider
  const fromAws = one((e) => e.principalAccount === '222222222222' && /lake-sync/.test(e.role), 'data-etl into lake-sync');
  assert.equal(fromAws.group, 'connected-account');
  assert.equal(fromAws.awsSourceRoleArn, 'arn:aws:iam::222222222222:role/data-etl');
  const broad = one((e) => e.principalAccount === '111111111111', 'the pool open to any role in 111111111111');
  assert.deepEqual([broad.group, broad.worst, broad.findings.map((f) => f.id)], ['external-account', 'high', ['wif-broad']]);
  // an outside user with a role on the project: the user, not its IAM member string
  const vendor = one((e) => e.principalAccount === 'vendor.dev@gmail.com', 'the vendor');
  assert.deepEqual([vendor.group, vendor.role, vendor.findings[0].id], ['external-account', 'Roles on project acme-data-stg', 'external']);
  // GitHub through federation, a GKE workload, key holders
  assert.equal(one((e) => e.group === 'oidc', 'GitHub').pkind, 'github');
  assert.equal(one((e) => e.pkind === 'gke', 'GKE').group, 'same-account');
  assert.ok(g.some((e) => e.type === 'gcp-key' && e.source === 'Key holders'));
  // one grant on a whole folder or organization: one edge per project it reaches
  const wide = g.filter((e) => /service accounts \(all in/.test(e.role));
  assert.ok(wide.length >= 3 && wide.every((e) => e.gcpMembers.length > 1));
  // a role on one bucket or topic is resource access, not a way in on this map
  assert.ok(!g.some((e) => /acme-public-site|orders|finance/.test(e.role)));
  assert.ok(!g.some((e) => e.source.includes('partner-prod-123')), 'the partner only holds a role on one topic');
});

test('filters: cloud, role by subject, use not known without usage; the map has lines into projects from AWS and between projects', async () => {
  const gcp = await tm.trustMap(owner, 'cloud:gcp');
  assert.ok(gcp.total > 0 && gcp.rows.every((e) => e.cloud === 'gcp'));
  assert.deepEqual(gcp.clouds.sort(), ['aws', 'gcp']);
  const aws = await tm.trustMap(owner, 'cloud:aws');
  assert.ok(aws.rows.every((e) => e.cloud !== 'gcp'));
  const sub = gcp.rows.find((e) => e.roleId.startsWith('gcp:serviceAccount:'));
  assert.ok((await tm.trustWays(owner, `roleid:${sub.roleId}`)).rows.every((e) => e.roleId === sub.roleId), 'a subject with capitals still matches');
  assert.ok(gcp.usage.unknown > 0 && gcp.usage.no === 0, 'usage not read: not "never used"');
  const ids = gcp.map.links.map((l) => l.id);
  const awsNode = (await db.query(`SELECT id FROM cloud_accounts WHERE account_id = '222222222222'`)).rows[0].id;
  assert.ok(ids.includes(`${awsNode}>gcp:acme-data-stg`), 'AWS account → project');
  assert.ok(ids.some((x) => /^gcp:acme-shared-ci>gcp:/.test(x)), 'project → project');
  assert.equal(gcp.map.accounts.find((a) => a.id === 'gcp:acme-data-stg').cloud, 'gcp');
  // members limited to some AWS accounts see no Google Cloud on the map
  const s = await tm.trustMap(scoped, 'cloud:gcp');
  assert.equal(s.total, 0); assert.ok(!s.map.accounts.some((a) => a.cloud === 'gcp'));
});

test('findings are filed in the inbox, decided there and on the map, and resolved; members limited to AWS accounts do not see them', async () => {
  await sync.trustTick({ force: true });
  const list = await findings.listFindings(owner, { cloud: 'gcp', category: 'trust' });
  assert.ok(list.total > 0 && list.items.every((x) => x.cloud === 'gcp' && x.gcp_subject));
  const broad = list.items.find((x) => /federated source/.test(x.title));
  assert.equal(broad.severity, 'high'); assert.ok(broad.gcp_principal_id, 'links to the service account');
  assert.equal((await findings.listFindings(scoped, { cloud: 'gcp' })).total, 0);
  await assert.rejects(findings.decideMany(scoped, { ids: [broad.id], decision: 'accept' }), { status: 404 });
  const out = await findings.decideMany(owner, { ids: [broad.id], decision: 'accept', note: 'pool pinned next sprint' });
  assert.equal(out.flags.length, 1);
  // the map shows the decision on the way in
  const ix = await tm.trustIndex();
  const e = gcpOf(ix).find((x) => x.principalAccount === '111111111111');
  assert.equal(e.accepted, true); assert.equal(e.attention, false);
  // expected trust: its findings are no longer filed; the open one is resolved
  const vendor = list.items.find((x) => /Outside your domain/.test(x.title));
  await db.query(`INSERT INTO trust_expected(source, source_label, roles, accounts, findings, note) VALUES ($1, 'vendor', '*', '{acme-data-stg}', '{external}', 'contractor until March')`,
    [gcpOf(ix).find((x) => x.principalAccount === 'vendor.dev@gmail.com').sourceKey]);
  await sync.trustTick({ force: true });
  assert.equal((await db.query('SELECT status FROM flags WHERE id = $1', [vendor.id])).rows[0].status, 'resolved');
});

test('changes: the first read is known, not new; a way in that appears later is new on the map and in the feed', async () => {
  const before = await tm.trustMap(owner, 'cloud:gcp new:7');
  assert.equal(before.total, 0, 'nothing is new on the first read');
  // forget one way in, as if it had just appeared
  const key = (await db.query(`SELECT key FROM gcp_ways_seen WHERE key LIKE '%vendor.dev%' LIMIT 1`)).rows[0].key;
  await db.query('DELETE FROM gcp_ways_seen WHERE key = $1', [key]);
  await sync.trustTick({ force: true });                 // records it now
  const now = await tm.trustMap(owner, 'cloud:gcp new:7');
  assert.equal(now.total, 1); assert.equal(now.rows[0].change.kind, 'new');
  await sync.trustTick({ force: true });                 // feeds it
  const feed = await radar.changeFeed({ ...owner, radar_seen_at: null, changes_seen_id: 0 }, { days: 7 });
  const c = feed.items.find((x) => x.gcp_project === 'acme-data-stg');
  assert.ok(c && c.kind === 'new-trust' && /Google Cloud/.test(c.title));
  assert.equal((await radar.changeFeed({ ...scoped, radar_seen_at: null, changes_seen_id: 0 }, { days: 7 })).items.filter((x) => x.gcp_project).length, 0);
});

test('where it leads next crosses clouds: an AWS role into a Google service account, a service account into others', async () => {
  const ix = await tm.trustIndex();
  const deployer = gcpOf(ix).find((e) => /^serviceAccount:deployer@/.test(e.principal));
  const c = await tm.trustChain(owner, deployer.sourceKey);
  assert.ok(c.levels[0].roles.some((r) => r.cloud === 'gcp'));
});
