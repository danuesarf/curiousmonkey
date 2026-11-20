// Specific trust: a whole-account principal narrowed to the identities seen coming in, checked, stored and approved.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { startPg } from './helpers/pg.js';

// the module also stores drafts: its database settings are read when it is first loaded, so point them at this test's
process.env.DATABASE_URL = 'postgres://cm:cm@127.0.0.1:54385/cm';
const { buildTrustDraft, allows, rootPrincipals } = await import('../src/recommender/trust.js');

const SHARED = '555555555555', OWN = '111111111111', VENDOR = '999999999999';
const recent = new Date().toISOString();
const role = (name, extra = {}) => ({ key: `role:${SHARED}:${name}`, kind: 'role', account: SHARED, name, arn: `arn:aws:iam::${SHARED}:role/${name}`, pathKnown: true, via: 'sts:AssumeRole', sessions: 5, lastSeen: recent, ...extra });
const trust = (stmts) => ({ Version: '2012-10-17', Statement: stmts });
const rootSt = (account = SHARED, extra = {}) => ({ Effect: 'Allow', Principal: { AWS: `arn:aws:iam::${account}:root` }, Action: 'sts:AssumeRole', ...extra });
const draft = (t, callers, o = {}) => buildTrustDraft({ role: { name: 'r', trust: t, lastUsedAt: o.lastUsedAt || null }, callers, complete: o.complete ?? true, windowDays: 90, exclude: o.exclude, style: o.style });
const check = (d, id) => d.checks.find((c) => c.id === id)?.status;

// ---------------------------------------------------------------- the draft (no database)
test('a whole account becomes the identities that came in: aws:PrincipalArn with real ARNs, paths included', () => {
  const sso = role('AWSReservedSSO_Admin_0a1b', { arn: `arn:aws:iam::${SHARED}:role/aws-reserved/sso.amazonaws.com/ap-southeast-3/AWSReservedSSO_Admin_0a1b` });
  const d = draft(trust([rootSt(SHARED, { Sid: 'Shared', Condition: { Bool: { 'aws:MultiFactorAuthPresent': 'true' } } })]), [role('deployer'), sso]);
  assert.equal(d.after.Statement.length, 1);
  const st = d.after.Statement[0];
  assert.equal(st.Principal.AWS, `arn:aws:iam::${SHARED}:root`);
  assert.deepEqual(st.Condition.ArnEquals['aws:PrincipalArn'], [sso.arn, `arn:aws:iam::${SHARED}:role/deployer`].sort());
  assert.deepEqual(st.Condition.Bool, { 'aws:MultiFactorAuthPresent': 'true' }, 'MFA stays');
  assert.equal(st.Sid, 'SharedNamed');
  assert.equal(check(d, 'callers-kept'), 'pass'); assert.equal(check(d, 'root-left'), 'pass');
  // somebody else in that account, not seen, is now refused
  assert.equal(allows(d.after, role('someone-else')), false);
  assert.equal(allows(d.after, role('deployer')), true);
});

test('named in Principal when asked; a role whose path is not known stays a condition (ArnLike, any path)', () => {
  const p = draft(trust([rootSt()]), [role('deployer')], { style: 'principal' });
  assert.deepEqual(p.after.Statement[0].Principal, { AWS: `arn:aws:iam::${SHARED}:role/deployer` }); assert.equal(p.after.Statement[0].Condition, undefined);
  const g = draft(trust([rootSt()]), [role('deployer', { pathKnown: false })], { style: 'principal' });
  assert.deepEqual(g.after.Statement[0].Condition.ArnLike['aws:PrincipalArn'], [`arn:aws:iam::${SHARED}:role/*/deployer`, `arn:aws:iam::${SHARED}:role/deployer`]);
  assert.equal(check(g, 'path'), 'warn');
  assert.ok(allows(g.after, { ...role('x'), arn: `arn:aws:iam::${SHARED}:role/team/deployer` }));
});

test('identities CloudTrail named only by unique ID get their own aws:userid statement; sts:* narrows to what was used', () => {
  const uid = { key: `acct:${SHARED}:AROAEXAMPLE000000001`, kind: 'unnamed', account: SHARED, uid: 'AROAEXAMPLE000000001', via: 'sts:AssumeRole', sessions: 2, lastSeen: recent };
  const user = { key: `acct:${SHARED}:AIDAEXAMPLE000000002`, kind: 'unnamed', account: SHARED, uid: 'AIDAEXAMPLE000000002', via: 'sts:AssumeRole', sessions: 1, lastSeen: recent };
  const d = draft(trust([rootSt(SHARED, { Action: 'sts:*' })]), [role('deployer', { tags: true }), uid, user]);
  assert.equal(d.after.Statement.length, 2);
  assert.deepEqual(d.after.Statement[1].Condition.StringLike['aws:userid'], ['AIDAEXAMPLE000000002', 'AROAEXAMPLE000000001:*']);
  assert.deepEqual(d.after.Statement[0].Action, ['sts:AssumeRole', 'sts:TagSession']);
  assert.equal(check(d, 'unnamed'), 'warn'); assert.equal(check(d, 'callers-kept'), 'pass');
});

test('left out, never used, not enough history, IAM says used before the window, already narrowed', () => {
  const left = draft(trust([rootSt(), rootSt(VENDOR)]), [role('deployer'), role('old-ci')], { exclude: [`role:${SHARED}:old-ci`] });
  assert.deepEqual(left.after.Statement.map((s) => s.Principal.AWS), [`arn:aws:iam::${SHARED}:root`]);   // the vendor nobody used: removed
  assert.equal(left.after.Statement[0].Condition.ArnEquals['aws:PrincipalArn'], `arn:aws:iam::${SHARED}:role/deployer`);
  assert.equal(check(left, 'left-out'), 'warn');
  assert.ok(left.changes.some((c) => c.kind === 'remove' && /999999999999/.test(c.text)));
  // history not read through: a principal nobody was seen through stays
  assert.equal(draft(trust([rootSt(VENDOR)]), [], { complete: false }).after.Statement[0].Principal.AWS, `arn:aws:iam::${VENDOR}:root`);
  assert.equal(draft(trust([rootSt(VENDOR)]), [], { lastUsedAt: '2025-01-01' }).accounts[0].outcome, 'kept');
  // removing the only statement leaves nothing: IAM refuses an empty trust policy
  assert.equal(check(draft(trust([rootSt(VENDOR)]), []), 'empty'), 'fail');
  const narrowed = trust([rootSt(SHARED, { Condition: { ArnLike: { 'aws:PrincipalArn': `arn:aws:iam::${SHARED}:role/ci-*` } } })]);
  assert.deepEqual(draft(narrowed, [role('ci-1')]).after, narrowed);
});

test('a bare account ID counts as the whole account; other principals in the statement stay where they are; size is checked', () => {
  const t = trust([{ Effect: 'Allow', Principal: { AWS: [SHARED, `arn:aws:iam::${OWN}:role/ci`] }, Action: 'sts:AssumeRole' }]);
  assert.deepEqual(rootPrincipals(t).map((r) => r.account), [SHARED]);
  const d = draft(t, [role('deployer')]);
  assert.equal(d.after.Statement[0].Principal.AWS, `arn:aws:iam::${OWN}:role/ci`);
  assert.equal(d.after.Statement[1].Principal.AWS, `arn:aws:iam::${SHARED}:root`);
  const many = Array.from({ length: 60 }, (_, i) => role(`a-very-long-role-name-for-pipeline-number-${i}`));
  assert.equal(check(draft(trust([rootSt()]), many), 'size'), 'fail');
});

// ---------------------------------------------------------------- stored, stale, approved
let pg, db, tr, A, R;
before(async () => {
  pg = await startPg(54385);
  db = await import('../src/db.js');
  await (await import('../src/migrate.js')).migrate(() => {});
  tr = await import('../src/recommender/trust.js');
  await db.query(`INSERT INTO workspace(name, slug, external_id) VALUES ('Acme','acme','x')`);
  const acct = async (id, name) => (await db.query(`INSERT INTO cloud_accounts(account_id, name, role_arn, regions, status) VALUES ($1,$2,'arn:x','{us-east-1}','connected') RETURNING id`, [id, name])).rows[0].id;
  A = await acct(OWN, 'prod');
  const S = await acct(SHARED, 'shared-tools');
  for (const a of [A, S]) await db.query(`INSERT INTO scan_checkpoints(account_id, region, source, first_event_time, last_event_time, caught_up_at) VALUES ($1,'us-east-1','event-history',now() - interval '91 days', now() - interval '20 minutes', now())`, [a]);
  // the shared account's roles, as the inventory read them: one under a path, one known by its unique ID
  await db.query(`INSERT INTO roles(account_id, arn, name, kind, path, aws_id) VALUES ($1,$2,'deployer','custom','/ci/','AROADEPLOYER00000001'), ($1,$3,'backup','custom','/','AROABACKUP0000000002')`,
    [S, `arn:aws:iam::${SHARED}:role/ci/deployer`, `arn:aws:iam::${SHARED}:role/backup`]);
  R = (await db.query(`INSERT INTO roles(account_id, arn, name, kind, reviewer_team, trust_policy) VALUES ($1,$2,'payments-admin','custom','infrasec',$3) RETURNING id`,
    [A, `arn:aws:iam::${OWN}:role/payments-admin`, JSON.stringify(trust([rootSt(SHARED, { Sid: 'Shared' })]))])).rows[0].id;
  const seen = (key, kind, n) => db.query(`INSERT INTO principals(role_id, key, kind, display, via, first_seen, last_seen, sessions_count) VALUES ($1,$2,$3,$2,'sts:AssumeRole',now() - interval '30 days',now(),$4)`, [R, key, kind, n]);
  await seen(`role:${SHARED}:deployer`, 'role', 12);
  await seen(`acct:${SHARED}:AROABACKUP0000000002`, 'account', 3);      // named from its ID
  await seen(`acct:${SHARED}:AROAUNKNOWN000000003`, 'account', 1);      // not known: by ID
});
after(async () => { await db?.closePool(); await pg?.stop(); });

test('callers are named from the inventory: the real path, and a unique ID turned into a role', async () => {
  const t = await tr.latestTrustDraft(R);
  const by = new Map(t.callers.map((c) => [c.key, c]));
  assert.equal(by.get(`role:${SHARED}:deployer`).arn, `arn:aws:iam::${SHARED}:role/ci/deployer`);
  assert.equal(by.get(`acct:${SHARED}:AROABACKUP0000000002`).name, 'backup');
  assert.equal(by.get(`acct:${SHARED}:AROAUNKNOWN000000003`).kind, 'unnamed');
  assert.equal(t.draft, null); assert.equal(t.complete, true);
});

test('a stored draft goes stale when someone new comes in or the trust changes, and is approved by the role\'s team', async () => {
  const d = await tr.draftTrust(R, {});
  assert.deepEqual(d.policy.Statement[0].Condition.ArnEquals['aws:PrincipalArn'], [`arn:aws:iam::${SHARED}:role/backup`, `arn:aws:iam::${SHARED}:role/ci/deployer`]);
  assert.deepEqual(d.policy.Statement[1].Condition.StringLike['aws:userid'], ['AROAUNKNOWN000000003:*']);
  assert.equal((await tr.latestTrustDraft(R)).draft.stale, false);
  await db.query(`INSERT INTO principals(role_id, key, kind, display, via, first_seen, last_seen, sessions_count) VALUES ($1,$2,'role',$2,'sts:AssumeRole',now(),now(),1)`, [R, `role:${SHARED}:newcomer`]);
  const s = (await tr.latestTrustDraft(R)).draft;
  assert.equal(s.stale, true); assert.equal(s.staleWhy, 'callers'); assert.deepEqual(s.newCallers.map((c) => c.name), ['newcomer']);
  const infra = { id: null, team: 'infrasec' };
  await assert.rejects(tr.approveTrust(d.id, infra), /Someone new came in/);
  // drafted again, leaving the newcomer out on purpose
  const d2 = await tr.draftTrust(R, { exclude: [`role:${SHARED}:newcomer`, 'role:not-a-caller'] });
  assert.deepEqual(d2.excluded, [`role:${SHARED}:newcomer`]);
  assert.equal((await db.query('SELECT status FROM trust_recommendations WHERE id=$1', [d.id])).rows[0].status, 'superseded');
  await assert.rejects(tr.approveTrust(d2.id, { id: null, team: 'infosec' }), /reviewed by infrasec/);
  assert.deepEqual(await tr.approveTrust(d2.id, infra), { approved: true, waitingFor: [] });
  // the trust policy changes in AWS: the draft no longer fits
  await db.query(`UPDATE roles SET trust_policy = $2 WHERE id = $1`, [R, JSON.stringify(trust([rootSt(SHARED, { Sid: 'Changed' })]))]);
  assert.equal((await tr.latestTrustDraft(R)).draft.staleWhy, 'trust');
  const cli = tr.trustExport({ name: 'payments-admin', arn: 'x' }, d2, 'cli');
  assert.match(cli, /aws iam update-assume-role-policy --role-name payments-admin/);
  await assert.rejects(tr.draftTrust((await db.query(`INSERT INTO roles(account_id, arn, name, kind, trust_policy) VALUES ($1,'arn:aws:iam::111111111111:role/ci','ci','custom',$2) RETURNING id`,
    [A, JSON.stringify(trust([{ Effect: 'Allow', Principal: { Service: 'ec2.amazonaws.com' }, Action: 'sts:AssumeRole' }]))])).rows[0].id), /trusts no whole account/);
});
