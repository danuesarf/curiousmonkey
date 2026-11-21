// Google Cloud connected one project at a time, with no connection on the folders or the organization: what each
// project's reader sees, the roles granted above it, and one identity across the connections.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { startPg } from './helpers/pg.js';

process.env.AWS_MODE = 'demo';
let pg, db, scan, space, demo, merge;
const PROJECTS = ['acme-payments-prod', 'acme-data-stg', 'acme-shared-ci'];
const conns = {};
const denied = () => Object.assign(new Error('The caller does not have permission'), { status: 403 });

before(async () => {
  pg = await startPg(54393);
  db = await import('../src/db.js');
  await (await import('../src/migrate.js')).migrate(() => {});
  scan = await import('../src/gcp/scan.js'); space = await import('../src/gcp/space.js'); demo = await import('../src/gcp/demo.js'); merge = await import('../src/gcp/merge.js');
  await db.query(`INSERT INTO workspace(name, slug, external_id) VALUES ('Acme','acme','x')`);
  for (const pid of PROJECTS) {
    conns[pid] = (await db.query(`INSERT INTO gcp_connections(name, scope_type, scope_id, auth_mode, wif, status) VALUES ($1,'project',$1,'wif','{}','connected') RETURNING *`, [pid])).rows[0];
  }
});
after(async () => { await db?.closePool(); await pg?.stop(); });

// a reader granted on one project only: it sees that project, its policy and its service accounts, and the project's
// ancestry; it cannot list folders, and (unless `above`) cannot read the folders' or the organization's policy
function projectReader(pid, { above = false, ancestry = true } = {}) {
  const base = demo.demoGcpGateway();
  const gw = { ...base,
    async folders() { throw denied(); },
    async organization() { throw denied(); },
    async projects() { return (await base.projects()).filter((p) => p.projectId === pid); },
    async iamPolicy(r) { return r === `projects/${pid}` || (above && /^(folders|organizations)\//.test(r)) ? base.iamPolicy(r) : null; },
    async serviceAccounts(p) { return p === pid ? base.serviceAccounts(p) : []; },
    async customRoles(parent) { return parent === `projects/${pid}` ? base.customRoles(parent) : []; },
  };
  if (!ancestry) delete gw.ancestry;
  return gw;
}
// as the worker does (gcpTick): the summary goes on the connection
const scanOne = async (pid, opts) => {
  const s = await scan.scanGcpConnection(conns[pid], { gw: projectReader(pid, opts) });
  await db.query(`UPDATE gcp_connections SET status_detail = $2, last_scan_at = now() WHERE id = $1`, [conns[pid].id, JSON.stringify(s)]);
  return s;
};
const deployer = 'serviceAccount:deployer@acme-shared-ci.iam.gserviceaccount.com';
// what every page sees of one identity: the latest copy
const shown = async (member) => (await db.query(`SELECT DISTINCT ON (member) * FROM gcp_principals WHERE member = $1 ORDER BY member, analyzed_at DESC`, [member])).rows[0];

test('a project reader learns every folder and the organization above its project, and says which policies it could not read', async () => {
  const s = await scanOne('acme-payments-prod');
  const [p] = (await db.query(`SELECT ancestors FROM gcp_projects WHERE connection_id = $1`, [conns['acme-payments-prod'].id])).rows;
  assert.deepEqual(p.ancestors, ['folders/200000000001', 'organizations/100000000001']);     // not only the parent folder
  assert.deepEqual(s.above, { read: [], refused: ['folders/200000000001', 'organizations/100000000001'] });
  // without the ancestry call (an older reader), the listing stops at the parent: the organization is never looked for
  const old = await scan.collectGcp(conns['acme-payments-prod'], { gw: projectReader('acme-payments-prod', { ancestry: false }), cachedRoles: async () => new Map() });
  assert.deepEqual(old.projects[0].ancestors, ['folders/200000000001']);
});

test('roles granted on a folder nobody can read are missing, and Space says so for the projects under it', async () => {
  for (const pid of PROJECTS) await scanOne(pid);
  const d = await shown(deployer);
  assert.ok(!d.roles.some((r) => r.resourceType === 'folder'), 'the folder policy was refused');
  const one = await space.spaceGcpProject('acme-payments-prod');
  assert.deepEqual(one.notRead, ['folders/200000000001', 'organizations/100000000001']);
  const est = await space.spaceGcp();
  assert.deepEqual(est.projects.find((x) => x.projectId === 'acme-shared-ci').notRead, ['folders/200000000003', 'organizations/100000000001']);
});

test('read from the project under it, a folder role belongs to the service account wherever it lives, whatever was read last', async () => {
  // the reader may now read the policies above: each project's connection reads its own folders and the organization
  for (const order of [PROJECTS, [...PROJECTS].reverse()]) {
    for (const pid of order) await scanOne(pid, { above: true });
    const d = await shown(deployer);
    const roles = d.roles.map((r) => `${r.role} on ${r.resource}`).sort();
    // its own project's role (read by acme-shared-ci) and the folder's (read by acme-payments-prod, under that folder)
    assert.ok(roles.includes('roles/artifactregistry.writer on projects/acme-shared-ci'), roles.join('\n'));
    assert.ok(roles.includes('roles/run.admin on folders/200000000001'), roles.join('\n'));
    assert.deepEqual(d.reach, ['acme-payments-prod', 'acme-shared-ci']);
    assert.equal(d.project_id, 'acme-shared-ci');
    // every copy says the same; a key is known however the copy was made
    const copies = (await db.query(`SELECT roles, reach, risk FROM gcp_principals WHERE member = $1`, [deployer])).rows;
    assert.ok(copies.length > 1 && copies.every((c) => JSON.stringify(c.roles) === JSON.stringify(d.roles) && c.risk === d.risk));
    const tf = await shown('serviceAccount:terraform@acme-shared-ci.iam.gserviceaccount.com');
    assert.equal(tf.keys.length, 2);
    assert.ok(tf.roles.some((r) => r.role === 'roles/owner' && r.resourceType === 'organization'));
  }
  // Space: the service account's own project and the folder's project are joined by a line, through the folder
  const est = await space.spaceGcp();
  const pair = est.chains.find((c) => c.fromProject === 'acme-shared-ci' && c.toProject === 'acme-payments-prod');
  assert.ok(pair?.grants.some((g) => g.caller === 'deployer@acme-shared-ci.iam.gserviceaccount.com' && g.folder && g.roles.includes('roles/run.admin')));
  assert.ok(est.projects.every((p) => !p.notRead.length), 'everything above is read now');
  // one project: the deployer is placed by what it can do there, with its folder roles counted
  const ci = await space.spaceGcpProject('acme-shared-ci');
  const dep = ci.clusters.flatMap((c) => c.roles).find((r) => r.name === 'deployer');
  assert.ok(dep.permissions > 0);
});

test('removing a connection takes what it read out of the others', async () => {
  await db.query('DELETE FROM gcp_connections WHERE id = $1', [conns['acme-payments-prod'].id]);
  await db.tx((c) => merge.mergeConnections(c, { force: true }));
  const d = await shown(deployer);
  assert.ok(!d.roles.some((r) => r.resource === 'folders/200000000001'), 'the folder above payments was read only by its connection');
  assert.ok(d.roles.some((r) => r.resource === 'projects/acme-shared-ci'));
});
