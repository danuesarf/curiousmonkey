// Sessions are stored for replay, and a role that assumes another role is followed across the jump,
// including into another connected account.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { startPg } from './helpers/pg.js';

process.env.AWS_MODE = 'demo';
let pg, db, ev, sev, ses;
let A, B, roleA, roleB;
const ARN_A = 'arn:aws:iam::111111111111:role/ci-deployer';
const ARN_B = 'arn:aws:iam::222222222222:role/payments-deployer';
const t0 = Date.now() - 3600e3;
const at = (min) => new Date(t0 + min * 60e3).toISOString();

before(async () => {
  pg = await startPg(54338);
  db = await import('../src/db.js');
  await (await import('../src/migrate.js')).migrate(() => {});
  ev = await import('../src/analyzer/events.js'); sev = await import('../src/scanner/events.js'); ses = await import('../src/sessions.js');
  A = (await db.query(`INSERT INTO cloud_accounts(account_id, name, role_arn, regions, status) VALUES ('111111111111','prod','x','{us-east-1}','connected') RETURNING id`)).rows[0].id;
  B = (await db.query(`INSERT INTO cloud_accounts(account_id, name, role_arn, regions, status) VALUES ('222222222222','stg','x','{us-east-1}','connected') RETURNING id`)).rows[0].id;
  roleA = (await db.query(`INSERT INTO roles(account_id, arn, name, kind, trust_policy) VALUES ($1,$2,'ci-deployer','custom',$3) RETURNING *`,
    [A, ARN_A, { Statement: [{ Effect: 'Allow', Principal: { Federated: 'arn:aws:iam::111111111111:oidc-provider/token.actions.githubusercontent.com' }, Action: 'sts:AssumeRoleWithWebIdentity' }] }])).rows[0];
  roleB = (await db.query(`INSERT INTO roles(account_id, arn, name, kind, trust_policy) VALUES ($1,$2,'payments-deployer','custom',$3) RETURNING *`,
    [B, ARN_B, { Statement: [{ Effect: 'Allow', Principal: { AWS: ARN_A }, Action: 'sts:AssumeRole' }] }])).rows[0];
});
after(async () => { await db.closePool(); await pg.stop(); });

const sessionA = { type: 'AssumedRole', arn: 'arn:aws:sts::111111111111:assumed-role/ci-deployer/GitHubActions-1', accountId: '111111111111', accessKeyId: 'ASIAAAAAAAAAAAAAAAA1',
  principalId: 'AROAA:GitHubActions-1', sessionContext: { sessionIssuer: { type: 'Role', arn: ARN_A } } };
const sessionB = { type: 'AssumedRole', arn: 'arn:aws:sts::222222222222:assumed-role/payments-deployer/deploy-1', accountId: '222222222222', accessKeyId: 'ASIABBBBBBBBBBBBBBB2',
  principalId: 'AROAB:deploy-1', sessionContext: { sessionIssuer: { type: 'Role', arn: ARN_B } } };
const oidc = { eventID: 'e1', eventTime: at(0), eventSource: 'sts.amazonaws.com', eventName: 'AssumeRoleWithWebIdentity', sourceIPAddress: '20.205.243.166',
  userIdentity: { type: 'WebIdentityUser', principalId: 'token.actions.githubusercontent.com:repo:krom-id/payments-api:ref:refs/heads/main', userName: 'repo:krom-id/payments-api:ref:refs/heads/main', identityProvider: 'token.actions.githubusercontent.com' },
  requestParameters: { roleArn: ARN_A, roleSessionName: 'GitHubActions-1' }, responseElements: { credentials: { accessKeyId: sessionA.accessKeyId } } };
const push = { eventID: 'e2', eventTime: at(1), eventSource: 'ecr.amazonaws.com', eventName: 'PutImage', userIdentity: sessionA, resources: [{ ARN: 'arn:aws:ecr:us-east-1:111111111111:repository/payments-api' }] };
// the jump: logged in both accounts' trails (same event, different eventID per recipient)
const jump = (id) => ({ eventID: id, eventTime: at(2), eventSource: 'sts.amazonaws.com', eventName: 'AssumeRole', userIdentity: sessionA,
  requestParameters: { roleArn: ARN_B, roleSessionName: 'deploy-1', externalId: 'x' }, responseElements: { credentials: { accessKeyId: sessionB.accessKeyId } } });
const update = { eventID: 'e5', eventTime: at(3), eventSource: 'ecs.amazonaws.com', eventName: 'UpdateService', userIdentity: sessionB, resources: [] };
const del = { eventID: 'e6', eventTime: at(4), eventSource: 'ecs.amazonaws.com', eventName: 'DeleteService', userIdentity: sessionB, errorCode: 'AccessDeniedException' };

const rolesOf = (rows) => ({ byArn: new Map(rows.map((r) => [r.arn, r])), byName: new Map(rows.map((r) => [r.name, r])) });
const apply = (recs, acct, rows) => db.tx(async (c) => {
  const evs = recs.map(ev.parseEvent).sort((x, y) => (x.type === y.type ? x.time - y.time : x.type === 'assume' ? -1 : 1));
  await sev.applyEvents(c, evs, rolesOf(rows), acct);
});

test('each account’s scan stores its own sessions; the jump links them by access key', async () => {
  await apply([oidc, push, jump('e3')], A, [roleA]);          // account 111's trail
  await apply([jump('e4'), update, del], B, [roleB]);         // account 222's trail
  const s = (await db.query('SELECT access_key_id, parent_key_id, via, calls, denied, start_known FROM track_sessions ORDER BY started_at')).rows;
  assert.equal(s.length, 2);
  assert.deepEqual(s.map((x) => [x.access_key_id, x.parent_key_id, x.via]), [
    [sessionA.accessKeyId, null, 'sts:AssumeRoleWithWebIdentity'], [sessionB.accessKeyId, sessionA.accessKeyId, 'sts:AssumeRole']]);
  assert.equal(s[0].calls, 2); assert.equal(s[1].calls, 2); assert.equal(s[1].denied, 1);
});

test('the AssumeRole a role makes counts as that role using sts:AssumeRole', async () => {
  const r = (await db.query(`SELECT action, sum(count)::int n FROM activity_daily WHERE role_id=$1 GROUP BY action ORDER BY action`, [roleA.id])).rows;
  assert.deepEqual(r, [{ action: 'ecr:PutImage', n: 1 }, { action: 'sts:AssumeRole', n: 1 }]);
  const res = (await db.query(`SELECT resource FROM activity_resources WHERE role_id=$1 AND action='sts:AssumeRole'`, [roleA.id])).rows;
  assert.deepEqual(res, [{ resource: ARN_B }]);
});

test('a track from either end shows the whole chain, calls in order, with the jump', async () => {
  const owner = { scope_accounts: null };
  const idB = (await db.query('SELECT id FROM track_sessions WHERE access_key_id=$1', [sessionB.accessKeyId])).rows[0].id;
  const idA = (await db.query('SELECT id FROM track_sessions WHERE access_key_id=$1', [sessionA.accessKeyId])).rows[0].id;
  for (const id of [idA, idB]) {
    const t = await ses.buildTrack(owner, id);
    assert.deepEqual(t.sessions.map((s) => [s.role, s.lane, s.parentLane]), [['ci-deployer', 0, null], ['payments-deployer', 1, 0]]);
    assert.deepEqual(t.calls.map((c) => [c.lane, c.action, c.jumpTo, c.denied]), [
      [0, 'ecr:PutImage', null, false], [0, 'sts:AssumeRole', 1, false], [1, 'ecs:UpdateService', null, false], [1, 'ecs:DeleteService', null, true]]);
    assert.match(t.origin.caller, /repo:krom-id\/payments-api/);
  }
  const list = await ses.listSessions(owner, {});
  assert.equal(list.find((s) => s.role === 'ci-deployer').hasJumps, true);
  assert.equal(list.find((s) => s.role === 'payments-deployer').isJump, true);
});

test('someone who can only see the second account sees their part and is told the rest is hidden', async () => {
  const idB = (await db.query('SELECT id FROM track_sessions WHERE access_key_id=$1', [sessionB.accessKeyId])).rows[0].id;
  const t = await ses.buildTrack({ scope_accounts: [B] }, idB);
  assert.equal(t.sessions.length, 1); assert.equal(t.hidden, 1);
  assert.equal(t.calls.length, 2); assert.equal(t.sessions[0].parentLane, null);
  assert.equal(await ses.buildTrack({ scope_accounts: [B] }, (await db.query('SELECT id FROM track_sessions WHERE access_key_id=$1', [sessionA.accessKeyId])).rows[0].id), null);
});

test('calls of a session whose start is older than stored history still group, marked as such', async () => {
  const orphan = { ...update, eventID: 'e9', userIdentity: { ...sessionB, accessKeyId: 'ASIACCCCCCCCCCCCCCC3', arn: 'arn:aws:sts::222222222222:assumed-role/payments-deployer/old' } };
  await apply([orphan], B, [roleB]);
  const s = (await db.query('SELECT start_known, via, calls FROM track_sessions WHERE access_key_id=$1', ['ASIACCCCCCCCCCCCCCC3'])).rows[0];
  assert.deepEqual(s, { start_known: false, via: 'started before stored history', calls: 1 });
});

// In the target account's trail a cross-account AssumeRole carries no ARN: { type: AWSAccount, accountId, principalId }.
test('a cross-account caller logged as AWSAccount keeps its account, and is named when that account is connected', async () => {
  await db.query(`UPDATE roles SET aws_id='AROAKNOWNCALLER00001' WHERE id=$1`, [roleA.id]);
  const asAccount = (id, acct, pid, key) => ({ eventID: id, eventTime: at(10), eventSource: 'sts.amazonaws.com', eventName: 'AssumeRole',
    userIdentity: { type: 'AWSAccount', accountId: acct, principalId: pid },
    requestParameters: { roleArn: ARN_B, roleSessionName: 'curious-monkey' }, responseElements: { credentials: { accessKeyId: key } } });
  await apply([asAccount('x1', '111111111111', 'AROAKNOWNCALLER00001:curious-monkey', 'ASIAXXXXXXXXXXXXXXX1'),
               asAccount('x2', '333333333333', 'AIDASTRANGERUSER0001', 'ASIAXXXXXXXXXXXXXXX2')], B, [roleB]);
  const p = (await db.query(`SELECT key, kind, display FROM principals WHERE role_id=$1 AND key NOT LIKE 'session:%' ORDER BY key`, [roleB.id])).rows;
  assert.ok(p.some((x) => x.key === 'role:111111111111:ci-deployer' && x.kind === 'role'), JSON.stringify(p));
  const stranger = p.find((x) => x.key.startsWith('acct:'));
  assert.equal(stranger.key, 'acct:333333333333:AIDASTRANGERUSER0001');
  assert.equal(stranger.kind, 'account');
  assert.match(stranger.display, /IAM user .* in 333333333333/);
  assert.ok(!p.some((x) => x.key.startsWith('other:')));
});
