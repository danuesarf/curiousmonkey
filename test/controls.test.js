// Manage policy: the control catalogue, severities changed and controls turned off, custom controls and their rules.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { startPg } from './helpers/pg.js';

process.env.AWS_MODE = 'demo';
process.env.CACHE_FRESH_MS = '0';
let pg, db, ctl, sync, tm, tsync, job, idr, lang;
let A, wide, idle, user;
const owner = { id: null, scope_accounts: null };
const policyOf = (over, rules = []) => ({ over: new Map(Object.entries(over)), rules, sig: 'x' });

before(async () => {
  pg = await startPg(54373);
  db = await import('../src/db.js');
  await (await import('../src/migrate.js')).migrate(() => {});
  ctl = await import('../src/controls.js'); sync = await import('../src/policySync.js'); tm = await import('../src/trustmap.js');
  tsync = await import('../src/trustSync.js'); job = await import('../src/scanner/analyzeJob.js');
  idr = await import('../src/identityRules.js'); lang = await import('../src/ruleLang.js');
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
  // Google Cloud: a service account with an old key that is Owner, and a person reaching twelve projects
  const conn = (await db.query(`INSERT INTO gcp_connections(name, scope_type, scope_id, auth_mode) VALUES ('org','organization','9','wif') RETURNING id`)).rows[0].id;
  const gp = (member, kind, extra = {}) => db.query(`INSERT INTO gcp_principals(connection_id, member, kind, email, project_id, keys, permissions, reach, risk, risk_score, risk_reasons) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
    [conn, member, kind, member.split(':')[1], extra.project || null, JSON.stringify(extra.keys || []), extra.permissions || 10, extra.reach || [], extra.risk || 'Low', extra.score || 0, JSON.stringify(extra.reasons || [])]);
  await gp('serviceAccount:etl@p1.iam.gserviceaccount.com', 'serviceAccount', { project: 'p1', keys: [{ id: 'k1', created: new Date(Date.now() - 500 * 864e5).toISOString(), expires: null }], risk: 'High', score: 60,
    reach: ['p1'], reasons: [{ id: 'basic-owner', severity: 'high', title: 'Owner' }] });
  await gp('user:ana@acme.io', 'user', { reach: Array.from({ length: 12 }, (_, i) => `p${i}`) });
  await job.analyzeAccount(A);
});
after(async () => { await db.closePool(); await pg.stop(); });

test('every built-in control has an id, a domain, a name and a way to fix it; ids are unique; every built-in rule can be read', () => {
  const ids = new Set();
  for (const b of ctl.BUILTIN) {
    assert.match(b.id, /^(perm|usage|evidence|trust|cred|gcp|rule)\.[a-z-]+$/); assert.ok(ctl.DOMAINS[b.domain], b.id); assert.ok(b.name && b.what && b.fix && b.where, b.id);
    assert.ok(b.severity ? ctl.SEVERITIES.includes(b.severity) : b.varies, `${b.id}: a severity, or what it varies by`);
    assert.ok(!ids.has(b.id)); ids.add(b.id);
    if (b.rule) assert.deepEqual(b.target === 'identity' ? idr.compileIdentityRule(b.rule).errors : tm.compileWayIn(b.rule).errors, [], b.id);
  }
  assert.ok(ctl.BUILTIN.length >= 60);
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

test('the rule language: AND, OR, NOT, brackets, = and !=, a key used twice, the older key:value form', () => {
  const shape = (n) => (!n ? null : n.t === 'term' ? `${n.key}${n.op}${n.values.join(',')}` : n.t === 'text' ? `"${n.value}"` : n.t === 'not' ? `!${shape(n.kid)}` : `${n.t}(${n.kids.map(shape).join(' ')})`);
  const p = (r) => { const x = lang.parseRule(r); return x.errors.length ? x.errors[0] : shape(x.ast); };
  assert.equal(p('environment=production OR environment=staging'), 'or(environment=production environment=staging)');
  assert.equal(p('a = 1 OR b = 2 AND c = 3'), 'or(a=1 and(b=2 c=3))', 'AND binds tighter than OR');
  assert.equal(p('(a = 1 OR b = 2) AND c != 3'), 'and(or(a=1 b=2) c!=3)');
  assert.equal(p('NOT (a=1 or b=2) c>=3 d<4'), 'and(!or(a=1 b=2) c>=3 d<4)');
  assert.equal(p('kind:role -policy:Admin* idle:>90 word'), 'and(kind=role !policy=Admin* idle>90 "word")', 'the older form still reads');
  assert.equal(p('name = "a b",c* tag = team=platform'), 'and(name=a b,c* tag=team=platform)');
  assert.equal(p('grants = iam:PassRole AND (grants = ec2:RunInstances OR grants = lambda:CreateFunction)'), 'and(grants=iam:PassRole or(grants=ec2:RunInstances grants=lambda:CreateFunction))');
  assert.match(p('(a = 1'), /bracket is not closed/); assert.match(p('a = 1 OR'), /OR needs a term/); assert.match(p('a ='), /needs a value/); assert.match(p('a = 1)'), /closing bracket/);
  assert.equal(lang.parseRule('  ').ast, null);
});

test('identity rules become parameterised SQL for AWS and a test for Google Cloud, and say what is wrong', () => {
  const r = idr.compileIdentityRule('(environment = production OR environment = staging) AND kind = role AND policy != Admin* AND idle > 90');
  assert.deepEqual(r.errors, []); assert.deepEqual(r.clouds, ['aws']);
  assert.match(r.aws.where, /^\(\(\(lower\(a\.environment\) = \$1\) OR \(lower\(a\.environment\) = \$2\)\) AND \(r\.kind <> 'iam-user'\) AND NOT \(EXISTS .*p\.name ILIKE \$3\)\) AND \(coalesce\(.*\) > \$4\)\)$/);
  assert.deepEqual(r.aws.params, ['production', 'staging', 'Admin%', 90]);
  const inj = idr.compileIdentityRule("name = x';DROP");
  assert.ok(!/DROP/.test(inj.aws.where) && inj.aws.params[0].includes('DROP'), 'values never reach the SQL text');
  // actions go through the index: a name as it is (in the catalogue's case), a wildcard as the names it stands for
  const g = idr.compileIdentityRule('grants = iam:passrole,s3:Get*');
  assert.match(g.aws.with, /^WITH rule_set_1 AS MATERIALIZED \(SELECT DISTINCT x\.role_id FROM role_actions x WHERE x\.action = ANY\(\$1::text\[\]\)\) $/);
  assert.ok(g.aws.params[0].includes('iam:PassRole') && g.aws.params[0].includes('s3:GetObject') && g.aws.params[0].length > 10);
  // which cloud a rule covers
  assert.deepEqual(idr.compileIdentityRule('risk = high AND keyage > 365').clouds, ['aws', 'gcp']);
  assert.deepEqual(idr.compileIdentityRule('cloud = gcp AND reach > 10').clouds, ['gcp']);
  assert.match(idr.compileIdentityRule('policy = Admin* AND reach > 3').errors[0], /only on AWS \(policy\).*only on Google Cloud \(reach\)/);
  assert.match(idr.compileIdentityRule('knd = role').errors[0], /Did you mean kind/);
  assert.match(idr.compileIdentityRule('idle > long').errors[0], /takes a number/);
  assert.match(idr.compileIdentityRule('mfa = maybe').errors[0], /yes or no/);
  assert.match(idr.compileIdentityRule('kind > role').errors[0], /takes = or !=/);
  assert.match(idr.compileIdentityRule('  ').errors[0], /empty rule/);
});

test('the analyser follows the policy: a control off makes no finding and no risk; a severity set is used', async () => {
  const flags = async (id) => (await db.query(`SELECT control, severity FROM flags WHERE role_id=$1 AND status='open' AND category NOT IN ('trust', 'rule', 'custom') ORDER BY control`, [id])).rows.map((x) => `${x.control}:${x.severity}`);
  assert.ok((await flags(wide)).includes('perm.wildcard-service:medium'));
  assert.ok((await flags(idle)).includes('usage.role-idle:medium'));
  const before_ = (await db.query('SELECT risk_score FROM roles WHERE id=$1', [wide])).rows[0].risk_score;

  let r = await ctl.setOverride(owner, 'perm.wildcard-service', { severity: 'high', note: 'no wildcards here' });
  assert.equal(r.findingsChanged, 1);
  assert.ok((await flags(wide)).includes('perm.wildcard-service:high'));
  await job.analyzeAccount(A);
  assert.ok((await flags(wide)).includes('perm.wildcard-service:high'), 'and stays so when the account is analysed again');

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

test('built-in rules are filed like any control, in AWS and Google Cloud; one that ships off stays off until turned on', async () => {
  const s = await sync.syncRules();
  assert.ok(s.rules >= 10);
  const open = async (control) => (await db.query(`SELECT r.name FROM flags f JOIN roles r ON r.id = f.role_id WHERE f.control=$1 AND f.status='open' ORDER BY 1`, [control])).rows.map((x) => x.name);
  assert.deepEqual(await open('rule.user-in-production'), ['deploy-bot']);
  assert.equal((await db.query(`SELECT category, key, severity FROM flags WHERE control='rule.user-in-production'`)).rows[0].category, 'rule');
  // Google Cloud: the match is added to what the principal's page lists, and kept apart from the scan's own findings
  const gcp = async (member) => (await db.query(`SELECT risk_reasons FROM gcp_principals WHERE member=$1`, [member])).rows[0].risk_reasons.map((x) => `${x.id}:${x.severity}${x.rule ? ':rule' : ''}`);
  assert.deepEqual(await gcp('serviceAccount:etl@p1.iam.gserviceaccount.com'), ['basic-owner:high', 'rule.key-over-a-year:high:rule', 'rule.gcp-key-on-powerful:high:rule']);
  assert.deepEqual(await gcp('user:ana@acme.io'), ['rule.gcp-person-many-projects:low:rule']);
  assert.equal((await sync.syncRules()).gcpChanged, 0, 'unchanged: nothing written');

  // off as shipped
  assert.deepEqual(await open('rule.no-owner-tag'), []);
  const row = (await ctl.listControls(owner, 'rule.no-owner-tag')).items[0];
  assert.deepEqual([row.enabled, row.defaultEnabled, row.changed, row.target, row.clouds], [false, false, false, 'identity', ['aws']]);
  await ctl.setOverride(owner, 'rule.no-owner-tag', { enabled: true });
  await sync.syncRules();
  assert.deepEqual(await open('rule.no-owner-tag'), ['idle-reader'], 'wide-open has a team tag');
  assert.equal((await ctl.listControls(owner, 'rule.no-owner-tag')).items[0].changed, true);
  await ctl.setOverride(owner, 'rule.no-owner-tag', { enabled: false });
  assert.equal((await db.query('SELECT count(*)::int n FROM control_overrides')).rows[0].n, 0, 'back to how it ships: no override kept');
  assert.deepEqual(await open('rule.no-owner-tag'), []);

  // a severity set on a rule, and a rule turned off
  await ctl.setOverride(owner, 'rule.gcp-person-many-projects', { severity: 'high' });
  await ctl.setOverride(owner, 'rule.user-in-production', { enabled: false });
  await sync.syncRules();
  assert.deepEqual(await gcp('user:ana@acme.io'), ['rule.gcp-person-many-projects:high:rule']);
  assert.deepEqual(await open('rule.user-in-production'), []);
  assert.equal((await sync.policyTick({ force: true })).reanalysed, 0, 'a rule changing needs no analysis of the accounts');
  await ctl.setOverride(owner, 'rule.gcp-person-many-projects', { severity: null }); await ctl.setOverride(owner, 'rule.user-in-production', { enabled: true });
});

test('a custom control about identities: what the rule matches gets a finding; it closes when it no longer matches', async () => {
  const check = (t, r) => (t === 'identity' ? idr.compileIdentityRule(r).errors : tm.compileWayIn(r).errors);
  await assert.rejects(ctl.saveCustom(owner, null, { name: 'Bad', target: 'identity', rule: 'nokey = 1', severity: 'high' }, check), /No key called/);
  const c = await ctl.saveCustom(owner, null, { name: 'Can pass roles, tagged platform', description: 'Platform roles must not pass roles.', target: 'identity', rule: 'grants = iam:PassRole AND tag = team=platform', severity: 'high', remediation: 'Remove iam:PassRole.' }, check);
  await assert.rejects(ctl.saveCustom(owner, null, { name: 'can pass roles, tagged PLATFORM', target: 'identity', rule: 'kind = role', severity: 'low' }, check), /already has that name/);
  let s = await sync.syncRules();
  assert.equal(s.opened, 1);
  const f = (await db.query(`SELECT role_id, category, key, control, severity, title, suggestion, evidence FROM flags WHERE control=$1 AND status='open'`, [c.id])).rows;
  assert.deepEqual(f.map((x) => [x.role_id, x.category, x.key, x.severity, x.title, x.suggestion]), [[wide, 'custom', c.id, 'high', 'Can pass roles, tagged platform', 'Remove iam:PassRole.']]);
  assert.match(f[0].evidence, /^Rule: grants = iam:PassRole/);
  assert.deepEqual(await sync.syncRules().then((x) => [x.opened, x.updated, x.resolved]), [0, 0, 0], 'unchanged: left alone');
  await job.analyzeAccount(A);
  assert.equal((await db.query(`SELECT status FROM flags WHERE control=$1`, [c.id])).rows[0].status, 'open', 'an analysis does not close rule findings');

  // rules through the preview: both clouds, OR and brackets, the same key twice, !=
  const names = async (rule, user = owner) => { const p = await idr.previewIdentityRule(user, rule); assert.deepEqual(p.errors, [], rule); return p.items.map((x) => x.name).sort(); };
  assert.deepEqual(await names('kind = user AND console = yes AND mfa = no'), ['deploy-bot']);
  assert.deepEqual(await names('keyage > 180'), ['deploy-bot', 'etl@p1.iam.gserviceaccount.com'], 'AWS access keys and Google Cloud service account keys');
  assert.deepEqual(await names('keyage > 180 AND cloud != gcp'), ['deploy-bot']);
  assert.deepEqual(await names('cloud = gcp AND (kind = user OR finding = basic-owner)'), ['ana@acme.io', 'etl@p1.iam.gserviceaccount.com']);
  assert.deepEqual(await names('name = idle* OR name = wide*'), ['idle-reader', 'wide-open']);
  assert.deepEqual(await names('(name = idle* OR name = wide*) AND tag != team'), ['idle-reader']);
  assert.deepEqual(await names('kind = role AND NOT (idle < 90 OR tag = team)'), ['idle-reader']);
  assert.deepEqual(await names('idle = never AND kind = role'), ['idle-reader']);
  assert.deepEqual(await names('finding = wildcard'), ['wide-open']);
  assert.deepEqual(await names('grants = s3:Put* AND grants != ec2:*'), ['wide-open']);
  assert.deepEqual(await names('policy = main AND unverified = s3:GetObject'), ['idle-reader', 'wide-open']);
  assert.deepEqual(await names('kind:role -name:wide* permissions:>0'), ['idle-reader'], 'the older form');
  const both = await idr.previewIdentityRule(owner, 'risk = high OR risk = low');
  assert.deepEqual(both.clouds, ['aws', 'gcp']); assert.equal(both.of, 5); assert.ok(both.byCloud.gcp === 2);
  const scoped = await idr.previewIdentityRule({ id: 'x', scope_accounts: [] }, 'keyage > 180');
  assert.equal(scoped.total, 0, 'someone scoped to no accounts sees none, and no Google Cloud');

  // the catalogue lists it with its open findings; it can be searched
  const cat = await ctl.listControls(owner, 'source:custom');
  assert.deepEqual(cat.items.map((x) => [x.name, x.open, x.severity, x.target, x.clouds]), [['Can pass roles, tagged platform', 1, 'high', 'identity', ['aws']]]);
  assert.equal((await ctl.listControls(owner, 'domain:trust severity:high')).items.every((x) => x.domain === 'trust' && x.severity === 'high'), true);
  assert.ok((await ctl.listControls(owner, 'target:rule cloud:gcp')).items.some((x) => x.id === 'rule.key-over-a-year'));
  assert.match(ctl.controlsCsv(cat.items), /custom\.[0-9a-f-]+,Custom,"Can pass roles, tagged platform"/);

  await ctl.saveCustom(owner, c.id, { name: 'Can pass roles, tagged platform', target: 'identity', rule: 'grants = iam:PassRole AND tag = team=data', severity: 'high' }, check);
  s = await sync.syncRules();
  assert.equal(s.resolved, 1);
  await ctl.deleteCustom(c.id);
  assert.equal((await ctl.listControls(owner, 'source:custom')).items.length, 0);
});

test('the Trust map follows the policy: built-in trust controls, and rules about ways in with OR, brackets and !=', async () => {
  const own = (w) => w.findings.filter((f) => f.severity !== 'info' && !f.rule).map((f) => [f.id, f.severity]).sort();
  let w = (await tm.trustWays(owner, 'role:wide-open')).rows[0];
  assert.deepEqual(own(w), [['account-root', 'high'], ['external-no-externalid', 'high']]);
  await ctl.setOverride(owner, 'trust.external-no-externalid', { enabled: false });
  await ctl.setOverride(owner, 'trust.account-root', { severity: 'low' });
  w = (await tm.trustWays(owner, 'role:wide-open')).rows[0];
  assert.deepEqual(own(w), [['account-root', 'low']]);
  assert.equal(w.worst, 'low'); assert.equal(w.attention, false);

  const t = (rule) => tm.compileWayIn(rule);
  assert.equal(t('(source = external OR source = public) AND env = production').test(w), true);
  assert.equal(t('source = external AND env != production').test(w), false);
  assert.equal(t('source = connected OR NOT has = admin').test(w), true);
  assert.equal(t('source = external AND fromenv != production').test(w), true, 'an outside account has no environment of yours');
  assert.equal(t('fromenv = production').test(w), false);
  assert.match(t('attention = yes').errors[0], /describes the review/);
  assert.match(t('sorce = external').errors[0], /No key called "sorce"/);
  assert.match(t('source > external').errors[0], /takes = or !=/);

  const check = (tg, r) => tm.compileWayIn(r).errors;
  const c = await ctl.saveCustom(owner, null, { name: 'Outside account into production', target: 'way-in', rule: '(source = external OR source = public) AND environment = production', severity: 'high', remediation: 'Move it behind the hub account.' }, check);
  w = (await tm.trustWays(owner, 'role:wide-open')).rows[0];
  const cf = w.findings.find((f) => f.id === c.id);
  assert.deepEqual([cf.severity, cf.title, cf.rule], ['high', 'Outside account into production', true]);
  assert.equal(w.worst, 'high'); assert.equal(w.attention, true);
  assert.equal((await tm.trustWays(owner, `finding:${c.id}`)).total, 1);
  assert.equal((await tm.trustMap(owner, '')).findings[c.id], 'Outside account into production');
  await tsync.trustTick({ force: true });
  const f = (await db.query(`SELECT category, control, severity, suggestion FROM flags WHERE role_id=$1 AND category='trust' AND status='open'`, [wide])).rows;
  assert.deepEqual(f.map((x) => [x.control, x.severity, x.suggestion]), [[c.id, 'high', 'Move it behind the hub account.']]);
  assert.equal((await ctl.listControls(owner, 'source:custom')).items[0].open, 1);
  await ctl.deleteCustom(c.id);
  assert.equal((await tm.trustWays(owner, 'role:wide-open')).rows[0].worst, 'low');
  await ctl.setOverride(owner, 'trust.external-no-externalid', { enabled: true }); await ctl.setOverride(owner, 'trust.account-root', { severity: null });
});

test('the policy as a file: exported, imported elsewhere, with a dry run first; what cannot be read is skipped', async () => {
  const check = (t, r) => (t === 'identity' ? idr.compileIdentityRule(r).errors : tm.compileWayIn(r).errors);
  await ctl.setOverride(owner, 'usage.role-idle', { severity: 'low', note: 'sandbox' });
  await ctl.saveCustom(owner, null, { name: 'Old keys', target: 'identity', rule: 'keyage > 180', severity: 'medium' }, check);
  const file = await ctl.exportPolicy();
  assert.deepEqual([file.kind, file.version], ['curious-monkey-policy', 1]);
  assert.deepEqual(file.overrides, [{ id: 'usage.role-idle', severity: 'low', enabled: true, note: 'sandbox' }]);
  assert.deepEqual(file.custom.map((x) => [x.name, x.rule, x.severity]), [['Old keys', 'keyage > 180', 'medium']]);

  // "elsewhere": the same workspace emptied
  await db.query('DELETE FROM custom_controls'); await db.query('DELETE FROM control_overrides');
  const doc = JSON.parse(JSON.stringify(file));
  doc.overrides.push({ id: 'trust.from-the-future', severity: 'high' });
  doc.custom.push({ name: 'Broken', target: 'identity', rule: '(kind = role', severity: 'low' }, { name: 'Ways', target: 'way-in', rule: 'source = external AND has = admin', severity: 'high' });
  const dry = await ctl.importPolicy(owner, doc, { dryRun: true }, check);
  assert.deepEqual([dry.dryRun, dry.overrides, dry.created, dry.updated], [true, 1, 2, 0]);
  assert.deepEqual(dry.skipped.map((x) => x.what), ['trust.from-the-future', 'Broken']);
  assert.equal((await db.query('SELECT count(*)::int n FROM custom_controls')).rows[0].n, 0, 'a dry run writes nothing');
  const done = await ctl.importPolicy(owner, doc, {}, check);
  assert.deepEqual([done.created, done.updated, done.overrides], [2, 0, 1]);
  assert.equal((await ctl.listControls(owner, 'usage.role-idle')).items[0].severity, 'low');
  // again: the same names are updated, not added twice; replace removes what the file does not hold
  await ctl.saveCustom(owner, null, { name: 'Local only', target: 'identity', rule: 'kind = user', severity: 'low' }, check);
  await ctl.setOverride(owner, 'trust.iam-user', { enabled: false });
  const again = await ctl.importPolicy(owner, file, { replace: true }, check);
  assert.deepEqual([again.created, again.updated, again.removed, again.reset], [0, 1, 2, 1]);
  assert.deepEqual((await ctl.listControls(owner, 'source:custom')).items.map((x) => x.name), ['Old keys']);
  assert.equal((await ctl.listControls(owner, 'trust.iam-user')).items[0].enabled, true);
  await assert.rejects(ctl.importPolicy(owner, { hello: 1 }, {}, check), /not a policy file/);
  await db.query('DELETE FROM custom_controls'); await db.query('DELETE FROM control_overrides');
});

test('rules are safe to run: values are only ever parameters, keys and operators come from fixed lists, size is capped, the query is read-only and timed', async () => {
  // nothing a value says reaches the statement
  const nasty = ["x' OR '1'='1", "x'; DROP TABLE roles; --", 'x") OR 1=1 --', '$1', '%', '\\', "team=' || (SELECT password_hash FROM users LIMIT 1) || '", '*/ SELECT pg_sleep(10) /*'];
  const SAFE = /^[\sA-Za-z0-9_.,:()'$<>=*/|[\]{}%+-]*$/;       // what the fixed fragments are made of
  for (const v of nasty) {
    for (const key of ['name', 'arn', 'account', 'env', 'kind', 'grants', 'uses', 'policy', 'tag', 'finding', 'caller', 'team', 'risk']) {
      const c = idr.compileIdentityRule(`${key} = "${v.replace(/"/g, '')}" OR ${key} != "${v.replace(/"/g, '')}"`);
      if (c.errors.length) continue;
      const sql = `${c.aws.with}${c.aws.where}`;
      assert.ok(!sql.includes(v.replace(/"/g, '')) || v === '$1' || v === '%', `${key}: the value is not in the SQL`);
      assert.ok(!/DROP|pg_sleep|password_hash|1=1/i.test(sql), `${key}: ${sql}`);
      assert.match(sql.replace(/role_set_\d+|rule_set_\d+/g, ''), SAFE);
      const p = await idr.previewIdentityRule(owner, `${key} = "${v.replace(/"/g, '')}"`);
      assert.deepEqual(p.errors, [], `${key} = ${v}`);         // runs, and matches as text
    }
  }
  assert.equal((await db.query('SELECT count(*)::int n FROM roles')).rows[0].n, 3, 'the table is still there');
  // a key or an operator that is not on the list is an error, never SQL
  for (const r of ['name;DROP = 1', 'r.id = 1', 'name || 1', 'name LIKE x', '1=1', 'name = x; SELECT 1', 'name == x']) {
    const c = idr.compileIdentityRule(r);
    assert.ok(c.errors.length || !/DROP|SELECT 1|\|\| 1/.test(`${c.aws?.with}${c.aws?.where}`), r);
  }
  // size
  assert.match(lang.parseRule('a = 1 '.repeat(500)).errors[0], /2000 characters at most/);
  assert.match(lang.parseRule(Array.from({ length: 61 }, (_, i) => `a=${i}`).join(' ')).errors[0], /60 terms at most/);
  assert.match(lang.parseRule(`${'('.repeat(13)}a=1${')'.repeat(13)}`).errors[0], /nested 12 deep/);
  assert.match(lang.parseRule('name = a*b*c*d*e*f*g*h').errors[0], /6 wildcards at most/);
  assert.match(lang.parseRule(`name = ${'x'.repeat(201)}`).errors[0], /200 characters at most/);
  assert.deepEqual(lang.parseRule(`${'NOT '.repeat(40)}a = 1`).errors, [], 'NOT NOT … is counted, not nested');

  // the transaction is read-only, and stopped when it takes too long
  const { guardedRead } = db;
  await assert.rejects(guardedRead(`UPDATE roles SET name = 'x'`), /read-only transaction/);
  await assert.rejects(guardedRead(`SELECT pg_sleep(2)`, [], 200), /took too long/);
  assert.equal((await guardedRead('SELECT 1 AS one')).rows[0].one, 1, 'the connection is given back clean');
  assert.equal((await db.query(`SHOW statement_timeout`)).rows[0].statement_timeout, '0', 'the time limit does not leak to other queries');
});
