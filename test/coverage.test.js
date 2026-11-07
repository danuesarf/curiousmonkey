// Every event is accounted for; unmapped event names never make a permission look unused; resources are only
// narrowed when every call named one; Bedrock suggestions apply only after a reviewer accepts them.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { startPg } from './helpers/pg.js';

process.env.AWS_MODE = 'demo';
process.env.LOOKUP_DELAY_MS = '0';
let pg, db, q, w, ev, sev, an, rec, em, checks;
let A;
before(async () => {
  pg = await startPg(54337);
  db = await import('../src/db.js');
  await (await import('../src/migrate.js')).migrate(() => {});
  q = await import('../src/queue.js'); w = await import('../src/worker.js');
  ev = await import('../src/analyzer/events.js'); sev = await import('../src/scanner/events.js'); an = await import('../src/scanner/analyzeJob.js');
  rec = await import('../src/recommender/index.js'); em = await import('../src/recommender/eventMap.js'); checks = await import('../src/recommender/checks.js');
  await q.registerWorker();
  await db.query(`INSERT INTO workspace(name, slug, external_id) VALUES ('KBI','kbi','ext-123')`);
  A = (await db.query(`INSERT INTO cloud_accounts(account_id, name, role_arn, regions, status) VALUES ('111111111111','prod','arn:aws:iam::111111111111:role/CuriousMonkeyScanner','{ap-southeast-3}','connected') RETURNING id`)).rows[0].id;
  await q.enqueueRun(A, { trigger: 'manual' });
  for (let j; (j = await q.claimJob());) { try { await w.runJob(j); } catch (e) { await q.failJob(j, e); } }
});
after(async () => { await db.closePool(); await pg.stop(); });

const role = async (name) => (await db.query(`SELECT * FROM roles WHERE account_id=$1 AND name=$2`, [A, name])).rows[0];
const actionRow = async (roleId, action) => (await db.query(`SELECT status, reason FROM role_actions WHERE role_id=$1 AND action=$2`, [roleId, action])).rows[0];
const reanalyze = async (r) => an.persistAnalysis(r.id, await an.analyzeRole(r, new Date(Date.now() - 90 * 864e5)));

test('an event without sessionIssuer is still tied to its role by name', () => {
  const e = ev.parseEvent({ eventID: '1', eventTime: '2026-11-01T00:00:00Z', eventSource: 'ec2.amazonaws.com', eventName: 'DescribeInstances',
    userIdentity: { type: 'AssumedRole', arn: 'arn:aws:sts::111111111111:assumed-role/data-etl/i-0abc' } });
  assert.equal(e.type, 'api'); assert.equal(e.roleArn, null); assert.equal(e.roleName, 'data-etl'); assert.equal(e.action, 'ec2:DescribeInstances');
  const roles = { byArn: new Map(), byName: new Map([['data-etl', { id: 'x' }]]) };
  const user = ev.parseEvent({ eventID: '2', eventTime: '2026-11-01T00:00:00Z', eventSource: 'iam.amazonaws.com', eventName: 'ListUsers', userIdentity: { type: 'IAMUser', arn: 'arn:aws:iam::1:user/bob' } });
  const odd = ev.parseEvent({ eventID: '3', eventTime: '2026-11-01T00:00:00Z', eventSource: 'newsvc.amazonaws.com', eventName: 'DoThing2031_01_01',
    userIdentity: { type: 'AssumedRole', arn: 'arn:aws:sts::111111111111:assumed-role/data-etl/s', sessionContext: { sessionIssuer: { arn: 'arn:aws:iam::111111111111:role/data-etl' } } },
    requestParameters: { secretThing: 'value-not-kept' } });
  const signin = ev.parseEvent({ eventID: '4', eventTime: '2026-11-01T00:00:00Z', eventSource: 'signin.amazonaws.com', eventName: 'ConsoleLogin',
    userIdentity: { type: 'AssumedRole', arn: 'arn:aws:sts::111111111111:assumed-role/data-etl/s' } });
  const cov = sev.coverage([e, user, odd, signin], { ...roles, byArn: new Map([['arn:aws:iam::111111111111:role/data-etl', { id: 'x' }]]) });
  assert.deepEqual({ ...cov.k }, { events: 4, assume_events: 0, role_calls: 3, recovered_role: 2, other_role: 0, not_role: 1, no_permission: 1, unmapped: 1, no_resources: 2 });
  const u = [...cov.unmapped.values()][0];
  assert.equal(u.raw, 'newsvc:DoThing2031_01_01'); assert.deepEqual(u.keys, ['secretThing']);   // parameter names only
  assert.doesNotMatch(JSON.stringify(u), /value-not-kept/);
});

test('a scan records coverage for what it read', async () => {
  const c = (await db.query(`SELECT sum(events)::int ev, sum(role_calls)::int rc, sum(assume_events)::int ae, sum(no_resources)::int nr FROM event_coverage WHERE account_id=$1`, [A])).rows[0];
  assert.ok(c.ev > 0 && c.rc > 0 && c.ae > 0, JSON.stringify(c));
  assert.ok(c.ev >= c.rc + c.ae);
});

test('calls with an unmapped event name make that service unconfirmed, never unused; accepting a mapping credits them', async () => {
  const r = await role('legacy-admin');                         // grants everything, so cloudfront:* is granted
  const p = (await db.query('SELECT id FROM principals WHERE role_id=$1 LIMIT 1', [r.id])).rows[0].id;
  const raw = 'cloudfront:GetDistributionConfigV9';
  await db.query(`INSERT INTO activity_daily(role_id, principal_id, action, day, count) VALUES ($1,$2,$3,current_date,4)`, [r.id, p, raw]);
  await db.query(`INSERT INTO unmapped_events(account_id, raw_action, event_source, event_name, count, first_seen, last_seen) VALUES ($1,$2,'cloudfront.amazonaws.com','GetDistributionConfigV9',4,now(),now())`, [A, raw]);
  await reanalyze(r);
  assert.deepEqual(await actionRow(r.id, 'cloudfront:GetDistributionConfig'), { status: 'unconfirmed', reason: 'unmapped-event' });
  assert.deepEqual(await actionRow(r.id, 'cloudfront:CreateDistribution'), { status: 'unconfirmed', reason: 'unmapped-event' });
  const flag = (await db.query(`SELECT evidence FROM flags WHERE role_id=$1 AND category='unmapped-event'`, [r.id])).rows[0];
  assert.match(flag.evidence, /GetDistributionConfigV9/);

  // a Bedrock suggestion alone changes nothing
  em.setEventMapLlm(async ({ user }) => {
    assert.match(user, /untrusted_data/);
    return JSON.stringify({ mappings: [
      { rawAction: raw, action: 'cloudfront:GetDistributionConfig', confidence: 0.9, reason: 'versioned name' },
      { rawAction: 'something-not-asked', action: 'iam:CreateUser', confidence: 1, reason: 'x' }] });
  });
  const items = (await db.query('SELECT * FROM unmapped_events WHERE account_id=$1', [A])).rows;
  const s = await em.suggestMappings(items);
  assert.equal(s.suggested.length, 1);
  await reanalyze(r);
  assert.equal((await actionRow(r.id, 'cloudfront:GetDistributionConfig')).status, 'unconfirmed');

  // the reviewer accepts it: the stored calls are credited without a rescan
  await em.decideMapping({ rawAction: raw, eventSource: 'cloudfront.amazonaws.com', eventName: 'GetDistributionConfigV9', action: 'cloudfront:GetDistributionConfig', userId: null });
  await reanalyze(r);
  assert.equal((await actionRow(r.id, 'cloudfront:GetDistributionConfig')).status, 'used');
  assert.equal((await actionRow(r.id, 'cloudfront:CreateDistribution')).status, 'unused');
  await assert.rejects(em.decideMapping({ rawAction: raw, eventSource: 'x', eventName: 'y', action: 'cloudfront:MadeUp', userId: null }), /not an IAM action/);
});

test('the model naming a non-existent action is rejected, not stored', async () => {
  em.setEventMapLlm(async () => '```json\n{"mappings":[{"rawAction":"newsvc:Thing","action":"newsvc:Thing","confidence":0.4,"reason":"guess"}]}\n```');
  const out = await em.suggestMappings([{ raw_action: 'newsvc:Thing', event_source: 'newsvc.amazonaws.com', event_name: 'Thing', param_keys: [] }]);
  assert.equal(out.suggested.length, 0); assert.equal(out.rejected[0].why, 'unknown service');
  assert.equal((await db.query(`SELECT count(*)::int n FROM event_action_map WHERE raw_action='newsvc:Thing'`)).rows[0].n, 0);
  em.setEventMapLlm(null);
});

test('resources are not narrowed when some calls named no resource, and a draft that narrows them fails replay', async () => {
  const r = await role('payments-api-prod');
  const narrow = await rec.recommend(r.id, { llm: null });
  const st = (x) => x.statements.find((s) => [].concat(s.Action).includes('ssm:GetParameter'));
  assert.notDeepEqual([].concat(st(narrow).Resource), ['*']);                       // every call named it: narrowed
  await db.query(`UPDATE activity_daily SET no_resource_count=1 WHERE role_id=$1 AND action='ssm:GetParameter'`, [r.id]);
  const kept = await rec.recommend(r.id, { llm: null });
  assert.ok([].concat(st(kept).Resource).some((x) => x.includes('*')), JSON.stringify(st(kept).Resource));
  const ctx = await rec.loadRoleContext(r.id);
  const res = checks.runChecks({ draftPolicies: [{ name: 'p', document: { Version: '2012-10-17', Statement: [{ Effect: 'Allow', Action: 'ssm:GetParameter', Resource: 'arn:aws:ssm:ap-southeast-3:111111111111:parameter/payments/db' }] } }],
    originalPolicies: ctx.policies, actions: ctx.actions.filter((a) => a.action === 'ssm:GetParameter'), observed: ctx.observed, incomplete: ctx.incomplete });
  assert.match(res.find((c) => c.id === 'replay').detail, /some calls named no resource/);
});
