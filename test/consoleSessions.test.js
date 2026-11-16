// Console sessions: the console signs in with AssumeRoleWithSAML and then calls with keys that event never shows.
// Those calls are tied back to the sign-in (and the person) by the session's name and creation time.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { startPg } from './helpers/pg.js';

process.env.AWS_MODE = 'demo';
let pg, db, ev, sev, A, sso, deployer;
const ACCT = '111111111111';
const SSO_ARN = `arn:aws:iam::${ACCT}:role/aws-reserved/sso.amazonaws.com/ap-southeast-1/AWSReservedSSO_AWSAdministratorAccess_19523ac1c7ba27c6`;
const SSO_NAME = 'AWSReservedSSO_AWSAdministratorAccess_19523ac1c7ba27c6';
const DEP_ARN = `arn:aws:iam::${ACCT}:role/AWSReservedSSO_lookalike`;   // the name copied, not the path
const SAML = `arn:aws:iam::${ACCT}:saml-provider/AWSSSO_abc_DO_NOT_DELETE`;
const t0 = Date.now() - 6 * 3600e3;
const at = (min) => new Date(t0 + min * 60e3).toISOString();

before(async () => {
  pg = await startPg(54381);
  db = await import('../src/db.js');
  await (await import('../src/migrate.js')).migrate(() => {});
  ev = await import('../src/analyzer/events.js'); sev = await import('../src/scanner/events.js');
  A = (await db.query(`INSERT INTO cloud_accounts(account_id, name, role_arn, regions, status) VALUES ($1,'prod','x','{ap-southeast-1}','connected') RETURNING id`, [ACCT])).rows[0].id;
  const trust = { Statement: [{ Effect: 'Allow', Principal: { Federated: SAML }, Action: ['sts:AssumeRoleWithSAML', 'sts:TagSession'], Condition: { StringEquals: { 'SAML:aud': 'https://signin.aws.amazon.com/saml' } } }] };
  sso = (await db.query(`INSERT INTO roles(account_id, arn, name, kind, trust_policy) VALUES ($1,$2,$3,'identity-center',$4) RETURNING *`, [A, SSO_ARN, SSO_NAME, trust])).rows[0];
  deployer = (await db.query(`INSERT INTO roles(account_id, arn, name, kind, trust_policy) VALUES ($1,$2,'AWSReservedSSO_lookalike','custom',$3) RETURNING *`, [A, DEP_ARN, trust])).rows[0];
});
after(async () => { await db.closePool(); await pg.stop(); });

const rolesOf = (rows) => ({ byArn: new Map(rows.map((r) => [r.arn, r])), byName: new Map(rows.map((r) => [r.name, r])) });
const apply = (recs, rows = [sso, deployer]) => db.tx(async (c) => {
  const evs = recs.map(ev.parseEvent).sort((x, y) => (x.type === y.type ? x.time - y.time : x.type === 'assume' ? -1 : 1));
  await sev.applyEvents(c, evs, rolesOf(rows), A);
});
let n = 0;
const signIn = (who, key, min, roleArn = SSO_ARN) => ({
  eventID: `s${++n}`, eventTime: at(min), eventSource: 'sts.amazonaws.com', eventName: 'AssumeRoleWithSAML', sourceIPAddress: '52.74.86.12',
  userIdentity: { type: 'SAMLUser', principalId: `Zx9abc=:${who}`, userName: who, identityProvider: SAML },
  requestParameters: { roleArn, principalArn: SAML, roleSessionName: who }, responseElements: { credentials: { accessKeyId: key } } });
// a console call: a key the sign-in never showed, the session's creation time, the person's own IP
const call = (who, key, min, created, eventName = 'DescribeTargetHealth', roleArn = SSO_ARN, roleName = SSO_NAME) => ({
  eventID: `c${++n}`, eventTime: at(min), eventSource: 'elasticloadbalancing.amazonaws.com', eventName, sourceIPAddress: '103.10.20.30',
  userIdentity: { type: 'AssumedRole', principalId: `AROAX:${who}`, arn: `arn:aws:sts::${ACCT}:assumed-role/${roleName}/${who}`, accountId: ACCT, accessKeyId: key,
    sessionContext: { sessionIssuer: { type: 'Role', arn: roleArn }, attributes: { creationDate: at(created), mfaAuthenticated: 'false' } } },
  requestParameters: {} });
const callers = async (role) => (await db.query(`SELECT id, kind, display, sessions_count, call_ips FROM principals WHERE role_id=$1 ORDER BY kind, display`, [role.id])).rows;
const sessionsOf = async (pid) => (await db.query(`SELECT access_key_id, calls, start_known FROM track_sessions WHERE principal_id=$1 ORDER BY started_at`, [pid])).rows;

test('console calls in the same batch as the sign-in go to that person and that sign-in', async () => {
  await apply([signIn('bernard@krom.id', 'ASIASIGNIN000000001', 0),
    call('bernard@krom.id', 'ASIACONSOLE00000001', 1, 0), call('bernard@krom.id', 'ASIACONSOLE00000002', 20, 0)]);
  const p = await callers(sso);
  assert.deepEqual(p.map((x) => [x.kind, x.display]), [['federated', 'bernard@krom.id']]);    // no "session bernard@krom.id"
  assert.deepEqual(p[0].call_ips, ['103.10.20.30']);
  assert.deepEqual(await sessionsOf(p[0].id), [{ access_key_id: 'ASIASIGNIN000000001', calls: 2, start_known: true }]);
  const acts = (await db.query(`SELECT sum(count)::int n FROM activity_daily WHERE principal_id=$1`, [p[0].id])).rows[0].n;
  assert.equal(acts, 2);
});

test('console calls in a later batch than the sign-in still find it', async () => {
  await apply([signIn('michael@krom.id', 'ASIASIGNIN000000002', 30)]);
  await apply([call('michael@krom.id', 'ASIACONSOLE00000003', 31, 30)]);
  await apply([call('michael@krom.id', 'ASIACONSOLE00000004', 50, 30)]);     // a refreshed key, another batch
  const m = (await callers(sso)).filter((x) => x.display.includes('michael'));
  assert.deepEqual(m.map((x) => x.kind), ['federated']);
  assert.deepEqual(await sessionsOf(m[0].id), [{ access_key_id: 'ASIASIGNIN000000002', calls: 2, start_known: true }]);
});

test('on an Identity Center role, calls whose sign-in was not seen go to the person by name, one session per sign-in', async () => {
  // michael signs in again, but that sign-in is not in the history: his keys share one creation time
  await apply([call('michael@krom.id', 'ASIACONSOLE00000005', 121, 120)]);
  await apply([call('michael@krom.id', 'ASIACONSOLE00000006', 140, 120), call('michael@krom.id', 'ASIACONSOLE00000007', 141, 120)]);
  const m = (await callers(sso)).filter((x) => x.display.includes('michael'));
  assert.deepEqual(m.map((x) => x.kind), ['federated']);
  const s = await sessionsOf(m[0].id);
  assert.equal(s.length, 2);                                                // the seen sign-in, and this one
  assert.deepEqual(s[1], { access_key_id: 'ASIACONSOLE00000005', calls: 3, start_known: false });
});

test('on any other role, even one named like Identity Center, a session name proves nothing', async () => {
  await apply([signIn('bernard@krom.id', 'ASIASIGNIN000000003', 200, DEP_ARN)]);
  // someone else, much later, with the same session name and no sign-in seen
  await apply([call('bernard@krom.id', 'ASIACONSOLE00000008', 300, 299, 'DescribeTargetHealth', DEP_ARN, 'AWSReservedSSO_lookalike')]);
  const p = await callers(deployer);
  assert.deepEqual(p.map((x) => [x.kind, x.display]), [['federated', 'bernard@krom.id'], ['session', 'session bernard@krom.id']]);
  assert.deepEqual((await db.query(`SELECT via FROM principals WHERE role_id=$1 AND kind='session'`, [deployer.id])).rows[0].via, 'sign-in not seen');
});

test('the migration merges callers already stored apart, on Identity Center roles only', async () => {
  const fed = (await callers(sso)).find((x) => x.display === 'bernard@krom.id');
  const old = (await db.query(`INSERT INTO principals(role_id, key, kind, display, via, first_seen, last_seen) VALUES ($1,'session:bernard@krom.id','session','session bernard@krom.id','unknown (started before the window)', now() - interval '20 days', now()) RETURNING id`, [sso.id])).rows[0].id;
  await db.query(`INSERT INTO activity_daily(role_id, principal_id, action, day, count, error_count) VALUES ($1,$2,'notifications:ListManagedNotificationEvents', current_date, 1984, 0)`, [sso.id, old]);
  const dep = (await callers(deployer)).find((x) => x.kind === 'session');
  const sql = fs.readFileSync(new URL('../src/migrations/040_console_sessions_merge.sql', import.meta.url), 'utf8');
  await db.tx((c) => c.query(sql));
  const after = await callers(sso);
  assert.deepEqual(after.map((x) => x.kind), ['federated', 'federated']);                    // bernard and michael, nobody twice
  const n2 = (await db.query(`SELECT sum(count)::int n FROM activity_daily WHERE principal_id=$1 AND action='notifications:ListManagedNotificationEvents'`, [fed.id])).rows[0].n;
  assert.equal(n2, 1984);
  assert.ok((await callers(deployer)).some((x) => x.id === dep.id), 'not merged on a role anyone could name a session on');
});
