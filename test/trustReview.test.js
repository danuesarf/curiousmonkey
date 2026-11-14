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
