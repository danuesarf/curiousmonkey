// Trust review: the Trust map's findings filed in the Findings inbox, expected trust, decisions and what changed.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { startPg } from './helpers/pg.js';

process.env.AWS_MODE = 'demo';
process.env.CACHE_FRESH_MS = '0';
let pg, db, tm, sync;
let A, vendorRole, ciRole;
const owner = { id: null, scope_accounts: null };
const VENDOR = '999999999999';
const vendorTrust = (cond) => ({ Statement: [{ Effect: 'Allow', Principal: { AWS: `arn:aws:iam::${VENDOR}:root` }, Action: 'sts:AssumeRole', ...(cond ? { Condition: cond } : {}) }] });
const GH = 'arn:aws:iam::111111111111:oidc-provider/token.actions.githubusercontent.com';

before(async () => {
  pg = await startPg(54371);
  db = await import('../src/db.js');
  await (await import('../src/migrate.js')).migrate(() => {});
  tm = await import('../src/trustmap.js'); sync = await import('../src/trustSync.js');
  await db.query(`INSERT INTO workspace(name, slug, external_id) VALUES ('KBI','kbi','ext-1')`);
  A = (await db.query(`INSERT INTO cloud_accounts(account_id, name, environment, role_arn, regions, status) VALUES ('111111111111','payments-prod','production','arn:x','{us-east-1}','connected') RETURNING id`)).rows[0].id;
  const role = async (name, trust) => (await db.query(`INSERT INTO roles(account_id, arn, name, kind, granted_count, trust_policy) VALUES ($1,$2,$3,'custom',10,$4) RETURNING id`,
    [A, `arn:aws:iam::111111111111:role/${name}`, name, JSON.stringify(trust)])).rows[0].id;
  vendorRole = await role('vendor-audit', vendorTrust({ StringEquals: { 'sts:ExternalId': 'abc' } }));
  ciRole = await role('ci-deploy', { Statement: [{ Effect: 'Allow', Principal: { Federated: GH }, Action: 'sts:AssumeRoleWithWebIdentity' }] });
});
after(async () => { await db.closePool(); await pg.stop(); });

test('what a trust policy change did: principals let in, and guards taken off', () => {
  const { trustChanges } = tm;
  const before_ = vendorTrust({ StringEquals: { 'sts:ExternalId': 'abc' } });
  const after_ = { Statement: [...vendorTrust().Statement, { Effect: 'Allow', Principal: { AWS: 'arn:aws:iam::888888888888:role/x' }, Action: 'sts:AssumeRole' }] };
  const ch = trustChanges(before_, after_);
  assert.deepEqual(ch.get(`arn:aws:iam::${VENDOR}:root`), { kind: 'weakened', guards: ['ExternalId'] });
  assert.deepEqual(ch.get('arn:aws:iam::888888888888:role/x'), { kind: 'new' });
  assert.equal(trustChanges(after_, after_).size, 0);
});

test('an expected rule covers a way in only with the findings it was accepted with, and until its review date', () => {
  const { coveredBy } = tm;
  const e = { role: 'ci-deploy', awsAccountId: '111111111111', findings: [{ id: 'oidc-no-sub', severity: 'high' }, { id: 'never-used', severity: 'info' }] };
  const rule = { source: 'k', roles: 'ci-*', accounts: [], findings: ['oidc-no-sub'], review_by: null };
  assert.equal(coveredBy(rule, e, 'k'), 'yes');
  assert.equal(coveredBy({ ...rule, findings: [] }, e, 'k'), null);                  // a finding it was not accepted with
  assert.equal(coveredBy({ ...rule, roles: 'other' }, e, 'k'), null);
  assert.equal(coveredBy({ ...rule, accounts: ['222222222222'] }, e, 'k'), null);
  assert.equal(coveredBy({ ...rule, review_by: '2000-01-01' }, e, 'k'), 'due');
  assert.equal(coveredBy(rule, e, 'other-source'), null);
});

test('trust findings are filed once, with the Trust map\'s severity, and resolved when the policy is fixed', async () => {
  const r = await sync.trustTick({ force: true });
  assert.ok(r.opened >= 1);
  const f = (await db.query(`SELECT key, severity, status, suggestion FROM flags WHERE category='trust' AND role_id=$1`, [ciRole])).rows;
  assert.deepEqual(f.map((x) => [x.key.split('|').pop(), x.severity, x.status]).sort(), [['oidc-no-sub', 'high', 'open']]);
  assert.match(f.find((x) => x.key.endsWith('oidc-no-sub')).suggestion, /:sub condition/);
  // a vendor's whole account with ExternalId: a low finding, on the map only
  assert.equal((await db.query(`SELECT count(*)::int n FROM flags WHERE category='trust' AND role_id=$1`, [vendorRole])).rows[0].n, 0);
  const again = await sync.trustTick({ force: true });
  assert.equal(again.opened, 0); assert.equal(again.updated, 0);                  // unchanged: left alone

  // fixed: the sub and aud conditions added
  await db.query(`UPDATE roles SET trust_policy=$2 WHERE id=$1`, [ciRole, JSON.stringify({ Statement: [{ Effect: 'Allow', Principal: { Federated: GH }, Action: 'sts:AssumeRoleWithWebIdentity',
    Condition: { StringEquals: { 'token.actions.githubusercontent.com:sub': 'repo:krom/app:ref:refs/heads/main', 'token.actions.githubusercontent.com:aud': 'sts.amazonaws.com' } } }] })]);
  const fixed = await sync.trustTick({ force: true });
  assert.equal(fixed.resolved, 1);
});

test('a guard taken off goes to the change feed, once, and the way in is "new" on the map', async () => {
  const before_ = vendorTrust({ StringEquals: { 'sts:ExternalId': 'abc' } }), after_ = vendorTrust();
  await db.query(`UPDATE roles SET trust_policy=$2 WHERE id=$1`, [vendorRole, JSON.stringify(after_)]);
  await db.query(`INSERT INTO identity_events(role_id, kind, title, detail) VALUES ($1,'trust-changed','Trust policy changed',$2)`, [vendorRole, JSON.stringify({ name: 'trust', before: before_, after: after_ })]);
  const r = await sync.trustTick({ force: true });
  assert.equal(r.changes, 1);
  const ch = (await db.query(`SELECT kind, severity, title FROM changes WHERE role_id=$1`, [vendorRole])).rows;
  assert.deepEqual(ch.map((c) => [c.kind, c.severity]), [['trust-weakened', 'high']]);
  assert.match(ch[0].title, /ExternalId taken off vendor-audit/);
  assert.equal((await sync.trustTick({ force: true })).changes, 0);              // once
  const w = await tm.trustWays(owner, 'new:7 role:vendor-audit');
  assert.equal(w.total, 1); assert.equal(w.rows[0].change.kind, 'weakened');
  assert.equal((await tm.trustWays(owner, 'new:weakened')).total, 1);
  const m = await tm.trustMap(owner, '');
  assert.ok(m.review.changed7 >= 1 && m.review.weakened7 === 1);
  assert.equal(m.review.attentionHigh, 1);
});

test('expected trust: out of "needs attention", its findings not filed, until its review date passes', async () => {
  const w = (await tm.trustWays(owner, 'role:vendor-audit')).rows[0];
  assert.equal(w.attention, true);
  const ids = w.findings.filter((f) => f.severity !== 'info').map((f) => f.id);
  const rule = (await db.query(`INSERT INTO trust_expected(source, source_label, roles, findings, note) VALUES ($1,'vendor','vendor-*',$2,'Audit vendor, contract 2026') RETURNING id`, [w.sourceKey, ids])).rows[0].id;
  const after_ = (await tm.trustWays(owner, 'role:vendor-audit')).rows[0];
  assert.equal(after_.expected.id, rule); assert.equal(after_.attention, false);
  assert.equal((await tm.trustWays(owner, 'expected:yes')).total, 1);
  assert.equal((await tm.trustWays(owner, 'attention:yes')).total, 0);
  await sync.trustTick({ force: true });
  assert.equal((await db.query(`SELECT count(*)::int n FROM flags WHERE category='trust' AND role_id=$1 AND status='open'`, [vendorRole])).rows[0].n, 0);
  const rules = await tm.expectedRules(owner);
  assert.equal(rules[0].covers, 1);

  await db.query(`UPDATE trust_expected SET review_by = current_date - 1 WHERE id=$1`, [rule]);
  const due = (await tm.trustWays(owner, 'role:vendor-audit')).rows[0];
  assert.equal(due.expected, undefined); assert.equal(due.expectedDue.id, rule); assert.equal(due.attention, true);
  assert.equal((await tm.trustWays(owner, 'expected:due')).total, 1);
});

test('a decision on every finding of a way in takes it out of "needs attention" (accept), and shows on the way in', async () => {
  await db.query(`DELETE FROM trust_expected`);
  await sync.trustTick({ force: true });
  const flags = (await db.query(`SELECT id FROM flags WHERE category='trust' AND role_id=$1 AND status='open'`, [vendorRole])).rows;
  assert.ok(flags.length >= 1);
  for (const f of flags) await db.query(`INSERT INTO review_decisions(flag_id, role_id, decision, note, decided_at) VALUES ($1,$2,'accept','known vendor', now())`, [f.id, vendorRole]);
  const w = (await tm.trustWays(owner, 'role:vendor-audit')).rows[0];
  assert.equal(w.decided, true); assert.equal(w.accepted, true); assert.equal(w.attention, false);
  assert.ok(w.flags.every((f) => f.decision === 'accept' && f.id));
  assert.equal((await tm.trustWays(owner, 'decided:accepted')).total, 1);
});

test('Bitbucket callers: one per repository (and environment), not one per pipeline step; stored ones are merged', async () => {
  const { stableFederatedKey } = await import('../src/scanner/applyEvents.js');
  const P = 'arn:aws:iam::1:oidc-provider/api.bitbucket.org/2.0/workspaces/w/pipelines-config/identity/oidc:ari:cloud:bitbucket::workspace/{11111111-1111-1111-1111-111111111111}';
  const R = '{22222222-2222-2222-2222-222222222222}', S1 = '{33333333-3333-3333-3333-333333333333}', S2 = '{44444444-4444-4444-4444-444444444444}';
  assert.equal(stableFederatedKey(`${P}:${R}:${S1}`), `${P}:${R}:*`);
  assert.equal(stableFederatedKey(`${P}:${R}:production:${S1}`), `${P}:${R}:production:*`);
  assert.equal(stableFederatedKey(`${P}:${R}`), `${P}:${R}`, 'no step: unchanged');
  const gh = 'arn:aws:iam::1:oidc-provider/token.actions.githubusercontent.com:sts.amazonaws.com:repo:a/b:ref:refs/heads/main';
  assert.equal(stableFederatedKey(gh), gh);

  // two steps stored the old way, with daily counts: merged into one caller
  const add = async (k, n, first, last) => (await db.query(`INSERT INTO principals(role_id, key, kind, display, via, first_seen, last_seen, sessions_count) VALUES ($1,$2,'federated',$3,'sts:AssumeRoleWithWebIdentity',$4,$5,$6) RETURNING id`,
    [ciRole, `fed:${P}:${R}:${k}`, k, first, last, n])).rows[0].id;
  const a = await add(S1, 3, '2026-10-01', '2026-10-05'), b = await add(S2, 4, '2026-10-03', '2026-11-01');
  for (const id of [a, b]) await db.query(`INSERT INTO activity_daily(role_id, principal_id, action, day, count) VALUES ($1,$2,'s3:PutObject','2026-11-01',5)`, [ciRole, id]);
  const fs = await import('node:fs');
  const sql = fs.readFileSync(new URL('../src/migrations/033_caller_keys.sql', import.meta.url), 'utf8');
  const c = await db.pool.connect();
  try { await c.query('BEGIN'); await c.query(sql); await c.query('COMMIT'); } finally { c.release(); }
  const rows = (await db.query(`SELECT id, key, sessions_count, first_seen::date::text f, last_seen::date::text l FROM principals WHERE role_id=$1 AND key LIKE $2`, [ciRole, `fed:${P}%`])).rows;
  assert.equal(rows.length, 1);
  assert.deepEqual([rows[0].key, rows[0].sessions_count, rows[0].f, rows[0].l], [`fed:${P}:${R}:*`, 7, '2026-10-01', '2026-11-01']);
  assert.equal((await db.query(`SELECT sum(count)::int n FROM activity_daily WHERE principal_id=$1`, [rows[0].id])).rows[0].n, 10);
});

test('where a source leads next, a tighter trust policy, and what the scanner read around trust (EKS, organisation, Identity Center)', async () => {
  const mk = async (name, trust, acctAws = '111111111111') => (await db.query(`INSERT INTO roles(account_id, arn, name, kind, granted_count, trust_policy) VALUES ($1,$2,$3,'custom',$4,$5) RETURNING id`,
    [A, `arn:aws:iam::${acctAws}:role/${name}`, name, name.endsWith('admin') ? 20000 : 10, JSON.stringify(trust)])).rows[0].id;
  // 555555555555 → hop-1 → hop-2-admin (named), and the whole account trusted by hop-wide (possible)
  const hop1 = await mk('hop-1', { Statement: [{ Effect: 'Allow', Principal: { AWS: 'arn:aws:iam::555555555555:root' }, Action: 'sts:AssumeRole' }] });
  await mk('hop-2-admin', { Statement: [{ Effect: 'Allow', Principal: { AWS: 'arn:aws:iam::111111111111:role/hop-1' }, Action: 'sts:AssumeRole' }] });
  const c = await tm.trustChain(owner, 'src:acct:555555555555');
  assert.deepEqual(c.levels.map((l) => l.roles.map((r) => r.role)), [['hop-1'], ['hop-2-admin']]);
  assert.equal(c.admin, 1); assert.equal(c.levels[1].roles[0].from, 'hop-1');

  // tighter trust: the whole account becomes the role that came in; never-used principals go
  await db.query(`INSERT INTO principals(role_id, key, kind, display, via, first_seen, last_seen, sessions_count) VALUES ($1,'role:555555555555:deployer','role','role/deployer (555555555555)','sts:AssumeRole',now(),now(),3)`, [hop1]);
  const s = await tm.suggestTrust(owner, hop1);
  assert.deepEqual(s.after.Statement[0].Principal, { AWS: 'arn:aws:iam::555555555555:role/deployer' });
  assert.ok(s.changes.some((x) => x.kind === 'narrow'));
  assert.ok(s.changes.some((x) => /ExternalId/.test(x.text) && x.placeholder));
  const ci = await tm.suggestTrust(owner, ciRole);
  assert.ok(ci, 'a role with a fixed policy still answers');

  // the organisation's own account is not a third party; EKS clusters and Identity Center people get names
  await db.query(`INSERT INTO org_accounts(account_id, name) VALUES ('555555555555','shared-tools')`);
  const w = (await tm.trustWays(owner, 'role:hop-1')).rows[0];
  assert.equal(w.inOrg.name, 'shared-tools'); assert.equal(w.named.name, 'shared-tools');
  assert.ok(!(await tm.thirdParties(owner)).some((x) => x.aws === '555555555555'));
  assert.equal((await tm.trustWays(owner, 'has:org')).total, 1);

  const eksIssuer = 'oidc.eks.ap-southeast-3.amazonaws.com/id/ABCDEF0123456789';
  await mk('eks-app', { Statement: [{ Effect: 'Allow', Principal: { Federated: `arn:aws:iam::111111111111:oidc-provider/${eksIssuer}` }, Action: 'sts:AssumeRoleWithWebIdentity',
    Condition: { StringEquals: { [`${eksIssuer}:sub`]: 'system:serviceaccount:app:api', [`${eksIssuer}:aud`]: 'sts.amazonaws.com' } } }] });
  await db.query(`INSERT INTO eks_clusters(account_id, region, name, arn, oidc_issuer) VALUES ($1,'ap-southeast-3','payments','arn:aws:eks:ap-southeast-3:111111111111:cluster/payments',$2)`, [A, `https://${eksIssuer}`]);
  assert.equal((await tm.trustWays(owner, 'role:eks-app')).rows[0].source, 'EKS · payments');

  await mk('AWSReservedSSO_Admin_0123abcd', { Statement: [{ Effect: 'Allow', Principal: { Federated: 'arn:aws:iam::111111111111:saml-provider/AWSSSO_0123456789abcdef_DO_NOT_DELETE' }, Action: 'sts:AssumeRoleWithSAML' }] });
  await db.query(`INSERT INTO idc_assignments(instance_arn, account_id, permission_set, principal_type, principal_id, principal_name) VALUES ('i','111111111111','Admin','GROUP','g','admins')`);
  const idcWay = (await tm.trustWays(owner, 'role:AWSReservedSSO_Admin')).rows[0];
  assert.deepEqual(idcWay.idc, { permissionSet: 'Admin', count: 1, who: [{ type: 'group', name: 'admins' }] });
});
