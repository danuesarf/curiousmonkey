// Manage policy: the control catalogue, severities changed and controls turned off, custom controls and their rules.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { startPg } from './helpers/pg.js';

process.env.AWS_MODE = 'demo';
process.env.CACHE_FRESH_MS = '0';
let pg, db, ctl, sync, tm, tsync, job;
let A, wide, idle, user;
const owner = { id: null, scope_accounts: null };
const policyOf = (over, custom = []) => ({ over: new Map(Object.entries(over)), custom, sig: 'x' });

before(async () => {
  pg = await startPg(54373);
  db = await import('../src/db.js');
  await (await import('../src/migrate.js')).migrate(() => {});
  ctl = await import('../src/controls.js'); sync = await import('../src/policySync.js'); tm = await import('../src/trustmap.js');
  tsync = await import('../src/trustSync.js'); job = await import('../src/scanner/analyzeJob.js');
  await db.query(`INSERT INTO workspace(name, slug, external_id) VALUES ('KBI','kbi','ext-1')`);
  owner.id = (await db.query(`INSERT INTO users(email, name, role, password_hash) VALUES ('o@kbi.id','Owner','owner','x') RETURNING id`)).rows[0].id;
  A = (await db.query(`INSERT INTO cloud_accounts(account_id, name, environment, role_arn, regions, status) VALUES ('111111111111','payments-prod','production','arn:x','{us-east-1}','connected') RETURNING id`)).rows[0].id;
  const role = async (name, { kind = 'custom', trust = { Statement: [{ Effect: 'Allow', Principal: { Service: 'ec2.amazonaws.com' }, Action: 'sts:AssumeRole' }] }, used = 'now()', doc = null, tags = {} } = {}) => {
    const id = (await db.query(`INSERT INTO roles(account_id, arn, name, kind, trust_policy, last_used_at, tags) VALUES ($1,$2,$3,$4,$5,${used},$6) RETURNING id`,
      [A, `arn:aws:iam::111111111111:${kind === 'iam-user' ? 'user' : 'role'}/${name}`, name, kind, JSON.stringify(trust), JSON.stringify(tags)])).rows[0].id;
    if (doc) await db.query(`INSERT INTO role_policies(role_id, kind, name, document, doc_hash) VALUES ($1,'inline','main',$2,'h')`, [id, JSON.stringify(doc)]);
    return id;
  };
  wide = await role('wide-open', { doc: { Statement: [{ Effect: 'Allow', Action: ['s3:*', 'iam:PassRole'], Resource: '*' }] }, tags: { team: 'platform' },
    trust: { Statement: [{ Effect: 'Allow', Principal: { AWS: 'arn:aws:iam::999999999999:root' }, Action: 'sts:AssumeRole' }] } });
  idle = await role('idle-reader', { used: 'NULL', doc: { Statement: [{ Effect: 'Allow', Action: 's3:GetObject', Resource: 'arn:aws:s3:::b/*' }] } });
  user = await role('deploy-bot', { kind: 'iam-user', trust: {} });
  await db.query(`INSERT INTO iam_user_details(role_id, user_id, password_enabled, password_created, mfa) VALUES ($1,'AIDA1',true, now() - interval '5 days', '[]')`, [user]);
  await db.query(`INSERT INTO iam_access_keys(role_id, key_id, status, created_at, last_used_at) VALUES ($1,'AKIA1','Active', now() - interval '200 days', now())`, [user]);
  await job.analyzeAccount(A);
});
after(async () => { await db.closePool(); await pg.stop(); });

test('every built-in control has an id, a domain, a name and a way to fix it; ids are unique', () => {
  const ids = new Set();
  for (const b of ctl.BUILTIN) {
    assert.match(b.id, /^(perm|usage|evidence|trust|cred|gcp)\.[a-z-]+$/); assert.ok(ctl.DOMAINS[b.domain], b.id); assert.ok(b.name && b.what && b.fix && b.where, b.id);
    assert.ok(b.severity ? ctl.SEVERITIES.includes(b.severity) : b.varies, `${b.id}: a severity, or what it varies by`);
    assert.ok(!ids.has(b.id)); ids.add(b.id);
  }
  assert.equal(ctl.controlOfFlag('wildcard', '*'), 'perm.wildcard-all'); assert.equal(ctl.controlOfFlag('wildcard', 's3:*'), 'perm.wildcard-service');
  assert.equal(ctl.controlOfFlag('data-event', 's3'), 'evidence.data-event');
});

test('a severity: built-in, the workspace\'s, none when the control is off; a fact stays a fact', () => {
  const p = policyOf({ 'trust.public': { severity: 'low', enabled: true }, 'perm.wildcard-all': { severity: null, enabled: false } });
  assert.equal(ctl.severityOf(p, 'trust.public', 'high'), 'low');
  assert.equal(ctl.severityOf(p, 'trust.public', 'info'), 'info');
  assert.equal(ctl.severityOf(p, 'perm.wildcard-all', 'high'), null);
  assert.equal(ctl.severityOf(p, 'usage.role-idle', 'medium'), 'medium');
  assert.equal(ctl.severityOf(ctl.DEFAULT_POLICY, 'trust.public', 'high'), 'high');
});

test('identity rules compile to SQL with parameters, and say what is wrong', () => {
  const r = ctl.compileIdentityRule('kind:role env:production grants:iam:PassRole -policy:Admin* idle:>90 name:a*,c "x y"');
  assert.deepEqual(r.errors, []);
  assert.match(r.where, /^\(r\.kind <> 'iam-user'\) AND \(lower\(a\.environment\) = \$1\) AND \(EXISTS .*x\.action ILIKE \$2\)\) AND NOT \(EXISTS .*p\.name ILIKE \$3\)\) AND \(coalesce\(.*1000000\) > \$4\) AND \(r\.name ILIKE \$5 OR r\.name ILIKE \$6\) AND \(r\.name ILIKE \$7 OR r\.arn ILIKE \$8\)$/);
  assert.deepEqual(r.params, ['production', 'iam:PassRole', 'Admin%', 90, 'a%', '%c%', '%x y%', '%x y%']);
  assert.ok(!/DROP|;/.test(ctl.compileIdentityRule("name:x';DROP").where.replace(/\$\d/g, '')), 'values never reach the SQL text');
  assert.match(ctl.compileIdentityRule('knd:role').errors[0], /Did you mean kind:role/);
  assert.match(ctl.compileIdentityRule('idle:long').errors[0], /takes a number/);
  assert.match(ctl.compileIdentityRule('mfa:maybe').errors[0], /yes or no/);
  assert.match(ctl.compileIdentityRule('  ').errors[0], /empty rule/);
});

test('the analyser follows the policy: a control off makes no finding and no risk; a severity set is used', async () => {
  const flags = async (id) => (await db.query(`SELECT control, severity FROM flags WHERE role_id=$1 AND status='open' AND category <> 'trust' ORDER BY control`, [id])).rows.map((x) => `${x.control}:${x.severity}`);
  assert.ok((await flags(wide)).includes('perm.wildcard-service:medium'));
  assert.ok((await flags(idle)).includes('usage.role-idle:medium'));
  const before_ = (await db.query('SELECT risk_score FROM roles WHERE id=$1', [wide])).rows[0].risk_score;

  // severity set: open findings follow at once
  let r = await ctl.setOverride(owner, 'perm.wildcard-service', { severity: 'high', note: 'no wildcards here' });
  assert.equal(r.findingsChanged, 1);
  assert.ok((await flags(wide)).includes('perm.wildcard-service:high'));
  // …and stay so when the account is analysed again
  await job.analyzeAccount(A);
  assert.ok((await flags(wide)).includes('perm.wildcard-service:high'));

  // turned off: resolved now, not made again, and it no longer counts toward the risk
  r = await ctl.setOverride(owner, 'perm.wildcard-service', { enabled: false });
  assert.equal(r.findingsChanged, 1);
  await job.analyzeAccount(A);
  assert.ok(!(await flags(wide)).some((x) => x.startsWith('perm.wildcard')));
  assert.ok((await db.query('SELECT risk_score FROM roles WHERE id=$1', [wide])).rows[0].risk_score < before_);

  // back to built-in: the override row goes, and the worker analyses every account again
  await ctl.setOverride(owner, 'perm.wildcard-service', { enabled: true, severity: null });
  assert.equal((await db.query('SELECT count(*)::int n FROM control_overrides')).rows[0].n, 0);
  await db.query(`INSERT INTO app_settings(key, value) VALUES ('policy.applied', '{"over":"stale"}') ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value`);
  const t = await sync.policyTick({ force: true });
  assert.equal(t.reanalysed, 1);
  assert.ok((await flags(wide)).includes('perm.wildcard-service:medium'));
  assert.equal((await sync.policyTick({ force: true })).reanalysed, 0, 'nothing changed: not analysed again');
  await assert.rejects(ctl.setOverride(owner, 'perm.nope', { enabled: false }), /No such control/);
});

test('IAM user checks follow the policy: off adds nothing, a severity sets the weight', async () => {
  const { userFindings } = await import('../src/analyzer/users.js');
  const details = { password_enabled: true, password_created: new Date(), mfa: [] }, keys = [{ key_id: 'K', status: 'Active', created_at: new Date(Date.now() - 200 * 864e5), last_used_at: new Date() }];
  const pts = (p) => Object.fromEntries(userFindings({ details, keys, policy: p }).map((f) => [f.id, f.points]));
  assert.deepEqual(pts(null), { 'key-old': 15, 'console-no-mfa': 30, 'console-and-keys': 5 });
  assert.deepEqual(pts(policyOf({ 'cred.console-no-mfa': { severity: null, enabled: false }, 'cred.key-old': { severity: 'high', enabled: true } })), { 'key-old': 30, 'console-and-keys': 5 });
});

test('a custom control about identities: what the rule matches gets a finding; it closes when it no longer matches', async () => {
  const check = (t, r) => (t === 'identity' ? ctl.compileIdentityRule(r).errors : []);
  await assert.rejects(ctl.saveCustom(owner, null, { name: 'Bad', target: 'identity', rule: 'nokey:1', severity: 'high' }, check), /No key called/);
  const c = await ctl.saveCustom(owner, null, { name: 'Can pass roles, tagged platform', description: 'Platform roles must not pass roles.', target: 'identity', rule: 'grants:iam:PassRole tag:team=platform', severity: 'high', remediation: 'Remove iam:PassRole.' }, check);
  await assert.rejects(ctl.saveCustom(owner, null, { name: 'can pass roles, tagged PLATFORM', target: 'identity', rule: 'kind:role', severity: 'low' }, check), /already has that name/);
  let s = await sync.syncCustom();
  assert.equal(s.opened, 1);
  const f = (await db.query(`SELECT role_id, category, control, severity, title, suggestion, evidence FROM flags WHERE control=$1 AND status='open'`, [c.id])).rows;
  assert.deepEqual(f.map((x) => [x.role_id, x.category, x.severity, x.title, x.suggestion]), [[wide, 'custom', 'high', 'Can pass roles, tagged platform', 'Remove iam:PassRole.']]);
  assert.match(f[0].evidence, /^Rule: grants:iam:PassRole/);
  assert.deepEqual(await sync.syncCustom().then((x) => [x.opened, x.updated, x.resolved]), [0, 0, 0], 'unchanged: left alone');
  await job.analyzeAccount(A);
  assert.equal((await db.query(`SELECT status FROM flags WHERE control=$1`, [c.id])).rows[0].status, 'open', 'an analysis does not close custom findings');

  // more rules, through the preview
  for (const [rule, names] of [['kind:user console:yes mfa:no', ['deploy-bot']], ['keyage:>180', ['deploy-bot']], ['idle:>90 kind:role', ['idle-reader']], ['finding:wildcard', ['wide-open']],
    ['uses:s3:* ', []], ['permissions:>0 -name:wide*', ['idle-reader']], ['policy:main unverified:s3:GetObject', ['idle-reader', 'wide-open']], ['boundary:no kind:role account:111111111111', ['idle-reader', 'wide-open']]]) {
    const p = await ctl.previewIdentityRule(owner, rule);
    assert.deepEqual(p.errors, [], rule); assert.deepEqual(p.items.map((x) => x.name).sort(), names, rule);
  }
  assert.equal((await ctl.previewIdentityRule({ id: 'x', scope_accounts: [] }, 'kind:role')).total, 0, 'someone scoped to no accounts sees none');

  // the catalogue lists it with its open findings; it can be searched
  const cat = await ctl.listControls(owner, 'source:custom');
  assert.deepEqual(cat.items.map((x) => [x.name, x.open, x.severity, x.target]), [['Can pass roles, tagged platform', 1, 'high', 'identity']]);
  assert.equal((await ctl.listControls(owner, 'domain:trust severity:high')).items.every((x) => x.domain === 'trust' && x.severity === 'high'), true);
  assert.equal((await ctl.listControls(owner, 'passrole')).items.length, 1);
  assert.match(ctl.controlsCsv(cat.items), /custom\.[0-9a-f-]+,Custom,"Can pass roles, tagged platform"/);

  // the rule changes: the finding closes; deleting closes what is left
  await ctl.saveCustom(owner, c.id, { name: 'Can pass roles, tagged platform', target: 'identity', rule: 'grants:iam:PassRole tag:team=data', severity: 'high' }, check);
  s = await sync.syncCustom();
  assert.equal(s.resolved, 1);
  await ctl.deleteCustom(c.id);
  assert.equal((await ctl.listControls(owner, 'source:custom')).items.length, 0);
});

test('the Trust map follows the policy: built-in trust controls, and custom controls about ways in', async () => {
  let w = (await tm.trustWays(owner, 'role:wide-open')).rows[0];
  assert.deepEqual(w.findings.filter((f) => f.severity !== 'info').map((f) => [f.id, f.severity]).sort(), [['account-root', 'high'], ['external-no-externalid', 'high']]);
  await ctl.setOverride(owner, 'trust.external-no-externalid', { enabled: false });
  await ctl.setOverride(owner, 'trust.account-root', { severity: 'low' });
  w = (await tm.trustWays(owner, 'role:wide-open')).rows[0];
  assert.deepEqual(w.findings.filter((f) => f.severity !== 'info').map((f) => [f.id, f.severity]), [['account-root', 'low']]);
  assert.equal(w.worst, 'low'); assert.equal(w.attention, false);

  const check = (t, r) => tm.queryWarnings(tm.parseQuery(r));
  const c = await ctl.saveCustom(owner, null, { name: 'Outside account into production', target: 'way-in', rule: 'source:external env:production', severity: 'high', remediation: 'Move it behind the hub account.' }, check);
  w = (await tm.trustWays(owner, 'role:wide-open')).rows[0];
  const cf = w.findings.find((f) => f.id === c.id);
  assert.deepEqual([cf.severity, cf.title, cf.custom], ['high', 'Outside account into production', true]);
  assert.equal(w.worst, 'high'); assert.equal(w.attention, true);
  assert.equal((await tm.trustWays(owner, `finding:${c.id}`)).total, 1);
  assert.equal((await tm.trustMap(owner, '')).findings[c.id], 'Outside account into production');
  // filed in the inbox under the custom control, with its suggestion
  await tsync.trustTick({ force: true });
  const f = (await db.query(`SELECT category, control, severity, suggestion FROM flags WHERE role_id=$1 AND category='trust' AND status='open'`, [wide])).rows;
  assert.deepEqual(f.map((x) => [x.control, x.severity, x.suggestion]), [[c.id, 'high', 'Move it behind the hub account.']]);
  assert.equal((await ctl.listControls(owner, 'source:custom')).items[0].open, 1);
  await ctl.deleteCustom(c.id);
  assert.equal((await tm.trustWays(owner, 'role:wide-open')).rows[0].worst, 'low');
});
