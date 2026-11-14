// Trust map: each way into a role is classified, its findings raised, and the query language finds it.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { edgesOf, parseQuery, matchesQuery, providerOf } from '../src/trustmap.js';

const OWN = '111111111111', CONNECTED = '222222222222', THIRD = '999999999999';
const ctx = { connected: new Map([[OWN, 'payments-prod'], [CONNECTED, 'data-stg']]), seen: new Map(), complete: new Set(['acct']) };
const role = (name, statements) => ({ id: `r-${name}`, name, arn: `arn:aws:iam::${OWN}:role/${name}`, account_id: 'acct', account_name: 'payments-prod',
  aws_account_id: OWN, environment: 'production', risk: 'Low', granted_count: 10, trust_policy: { Version: '2012-10-17', Statement: statements } });
const ids = (e) => e.findings.map((f) => `${f.severity}:${f.id}`).sort();

test('whole-account trust is a finding; how bad depends on whose account and whether it is narrowed', () => {
  const [own, conn, ext, narrowed] = edgesOf(role('x', [
    { Effect: 'Allow', Principal: { AWS: `arn:aws:iam::${OWN}:root` }, Action: 'sts:AssumeRole' },
    { Effect: 'Allow', Principal: { AWS: CONNECTED }, Action: 'sts:AssumeRole' },
    { Effect: 'Allow', Principal: { AWS: `arn:aws:iam::${THIRD}:root` }, Action: 'sts:AssumeRole' },
    { Effect: 'Allow', Principal: { AWS: `arn:aws:iam::${CONNECTED}:root` }, Action: 'sts:AssumeRole', Condition: { ArnLike: { 'aws:PrincipalArn': `arn:aws:iam::${CONNECTED}:role/ci-*` } } },
  ]), ctx);
  assert.equal(own.group, 'same-account'); assert.equal(own.type, 'aws-root');
  assert.deepEqual(ids(own), ['info:never-used', 'medium:account-root']);
  assert.equal(conn.group, 'connected-account'); assert.equal(conn.principalAccountName, 'data-stg');
  assert.equal(ext.group, 'external-account');
  assert.deepEqual(ids(ext), ['high:account-root', 'high:external-no-externalid', 'info:never-used']);
  assert.ok(ids(narrowed).includes('info:account-root'));
});

test('a third party with ExternalId passes; a specific role in a connected account raises nothing', () => {
  const [third, specific] = edgesOf(role('y', [
    { Effect: 'Allow', Principal: { AWS: `arn:aws:iam::${THIRD}:role/vendor` }, Action: 'sts:AssumeRole', Condition: { StringEquals: { 'sts:ExternalId': 'abc' } } },
    { Effect: 'Allow', Principal: { AWS: `arn:aws:iam::${CONNECTED}:role/ci` }, Action: 'sts:AssumeRole' },
  ]), { ...ctx, complete: new Set() });
  assert.deepEqual(ids(third), []); assert.deepEqual(ids(specific), []);
});

test('OIDC: GitHub without sub is high, a broad sub is flagged, Bitbucket and EKS are recognised', () => {
  const gh = 'arn:aws:iam::111111111111:oidc-provider/token.actions.githubusercontent.com';
  const bb = 'arn:aws:iam::111111111111:oidc-provider/api.bitbucket.org/2.0/workspaces/krom/pipelines-config/identity/oidc';
  const [noSub, broad, pinned, bitb] = edgesOf(role('z', [
    { Effect: 'Allow', Principal: { Federated: gh }, Action: 'sts:AssumeRoleWithWebIdentity' },
    { Effect: 'Allow', Principal: { Federated: gh }, Action: 'sts:AssumeRoleWithWebIdentity', Condition: { StringLike: { 'token.actions.githubusercontent.com:sub': 'repo:krom-id/*' }, StringEquals: { 'token.actions.githubusercontent.com:aud': 'sts.amazonaws.com' } } },
    { Effect: 'Allow', Principal: { Federated: gh }, Action: 'sts:AssumeRoleWithWebIdentity', Condition: { StringEquals: { 'token.actions.githubusercontent.com:sub': 'repo:krom-id/payments:ref:refs/heads/main', 'token.actions.githubusercontent.com:aud': 'sts.amazonaws.com' } } },
    { Effect: 'Allow', Principal: { Federated: bb }, Action: 'sts:AssumeRoleWithWebIdentity' },
  ]), { ...ctx, complete: new Set() });
  assert.equal(noSub.source, 'GitHub Actions');
  assert.deepEqual(ids(noSub), ['high:oidc-no-sub', 'low:oidc-no-aud']);
  assert.deepEqual(ids(broad), ['high:oidc-broad-sub']);
  assert.deepEqual(ids(pinned), []);
  assert.equal(bitb.source, 'Bitbucket Pipelines · krom');
  assert.ok(ids(bitb).includes('medium:oidc-no-sub'));
  assert.match(providerOf('arn:aws:iam::1:oidc-provider/oidc.eks.ap-southeast-3.amazonaws.com/id/ABCDEF1234567890').label, /^EKS · ap-southeast-3/);
  assert.equal(providerOf('accounts.google.com').label, 'Google');
  assert.equal(providerOf('arn:aws:iam::1:saml-provider/Okta').kind, 'saml');
});

test('anyone, NotPrincipal, IAM users, deleted identities, services', () => {
  const es = edgesOf(role('w', [
    { Effect: 'Allow', Principal: '*', Action: 'sts:AssumeRole' },
    { Effect: 'Allow', Principal: { AWS: '*' }, Action: 'sts:AssumeRole', Condition: { StringEquals: { 'aws:PrincipalOrgID': 'o-abc' } } },
    { Effect: 'Allow', NotPrincipal: { AWS: `arn:aws:iam::${OWN}:role/x` }, Action: 'sts:AssumeRole' },
    { Effect: 'Allow', Principal: { AWS: `arn:aws:iam::${OWN}:user/legacy-bot` }, Action: 'sts:*' },
    { Effect: 'Allow', Principal: { AWS: 'AROAEXAMPLEEXAMPLE12' }, Action: 'sts:AssumeRole' },
    { Effect: 'Allow', Principal: { Service: 'ecs-tasks.amazonaws.com' }, Action: 'sts:AssumeRole' },
    { Effect: 'Deny', Principal: '*', Action: 'sts:AssumeRole' },
  ]), { ...ctx, complete: new Set() });
  assert.equal(es.length, 6);                                        // the Deny statement is not a way in
  assert.deepEqual(ids(es[0]), ['high:public']);
  assert.deepEqual(ids(es[1]), ['medium:public']);
  assert.deepEqual(ids(es[2]), ['high:not-principal']);
  assert.deepEqual(ids(es[3]), ['low:broad-action', 'low:iam-user']);
  assert.deepEqual(ids(es[4]), ['medium:deleted-principal']);
  assert.equal(es[5].group, 'service'); assert.deepEqual(ids(es[5]), []);
});

test('what was seen coming in is attached to the edge it came through', () => {
  const r = role('v', [{ Effect: 'Allow', Principal: { AWS: `arn:aws:iam::${CONNECTED}:root` }, Action: 'sts:AssumeRole' }]);
  const seen = new Map([[r.id, [{ key: `role:${CONNECTED}:ci-deployer`, kind: 'role', display: `role/ci-deployer (${CONNECTED})`, last_seen: new Date(), sessions_count: 4 }]]]);
  const [e] = edgesOf(r, { ...ctx, seen });
  assert.equal(e.seen.length, 1);
  assert.ok(!ids(e).includes('info:never-used'));
});

test('the query language: keys, negation, quotes, free text', () => {
  const es = edgesOf(role('deployer', [
    { Effect: 'Allow', Principal: { AWS: `arn:aws:iam::${THIRD}:root` }, Action: 'sts:AssumeRole' },
    { Effect: 'Allow', Principal: { Federated: 'arn:aws:iam::1:oidc-provider/api.bitbucket.org/2.0/workspaces/krom/pipelines-config/identity/oidc' }, Action: 'sts:AssumeRoleWithWebIdentity' },
    { Effect: 'Allow', Principal: { Service: 'lambda.amazonaws.com' }, Action: 'sts:AssumeRole' },
  ]), { ...ctx, complete: new Set() });
  const find = (q) => es.filter((e) => matchesQuery(e, parseQuery(q))).map((e) => e.type);
  assert.deepEqual(find(`finding:account-root from:${THIRD}`), ['aws-root']);
  assert.deepEqual(find('type:root'), ['aws-root']);
  assert.deepEqual(find('provider:"bitbucket pipelines · krom"'), ['oidc']);
  assert.deepEqual(find('-source:service role:deploy'), ['aws-root', 'oidc']);
  assert.deepEqual(find('source:external'), ['aws-root']);
  assert.deepEqual(find('no:conditions has:findings'), ['aws-root', 'oidc']);
  assert.deepEqual(find('lambda'), ['service']);
  assert.deepEqual(find('account:payments-prod severity:high'), ['aws-root']);
});

test('an edge reports its worst finding, not none', async () => {
  const { edgesOf } = await import('../src/trustmap.js');
  const role = { id: 'r', name: 'x', arn: 'arn:aws:iam::111111111111:role/x', account_id: 'a', account_name: 'acct', aws_account_id: '111111111111',
    trust_policy: { Statement: [{ Effect: 'Allow', Principal: { AWS: 'arn:aws:iam::999999999999:root' }, Action: 'sts:AssumeRole' }] } };
  const [e] = edgesOf(role, { connected: new Map(), seen: new Map(), complete: new Set() });
  assert.ok(e.findings.length);
  assert.equal(e.worst, 'high');
});

test('the map: one line per source and account, account to account between your own, inside trust counted', async () => {
  const { mapOf } = await import('../src/trustmap.js');
  const accts = [{ id: 'acct', name: 'payments-prod', account_id: OWN, environment: 'production', status: 'connected' },
    { id: 'stg', name: 'data-stg', account_id: CONNECTED, environment: 'staging', status: 'connected' }];
  const st = (Principal, Condition) => ({ Effect: 'Allow', Principal, Action: 'sts:AssumeRole', ...(Condition ? { Condition } : {}) });
  const rows = [
    ...edgesOf(role('vendor-a', [st({ AWS: `arn:aws:iam::${THIRD}:root` })]), ctx),                                       // high
    ...edgesOf(role('vendor-b', [st({ AWS: `arn:aws:iam::${THIRD}:root` }, { StringEquals: { 'sts:ExternalId': 'x' } })]), ctx),  // low
    ...edgesOf(role('from-stg', [st({ AWS: `arn:aws:iam::${CONNECTED}:role/release` })]), ctx),
    ...edgesOf(role('own', [st({ AWS: `arn:aws:iam::${OWN}:root` })]), ctx),
    ...edgesOf(role('svc', [st({ Service: 'ecs.amazonaws.com' })]), ctx),
  ];
  const m = mapOf(rows, accts, accts);
  const vendor = m.links.find((l) => l.from === `src:acct:${THIRD}`);
  assert.equal(m.links.filter((l) => l.from === `src:acct:${THIRD}`).length, 1, 'two roles, one line');
  assert.equal(vendor.roles, 2); assert.equal(vendor.worst, 'high'); assert.equal(vendor.kind, 'outside');
  const s = m.sources.find((x) => x.id === `src:acct:${THIRD}`);
  assert.equal(s.vendor, false, 'one statement lacks ExternalId');
  const between = m.links.find((l) => l.kind === 'account');
  assert.deepEqual([between.from, between.to, between.roles], ['stg', 'acct', 1]);
  const a = m.accounts.find((x) => x.id === 'acct');
  assert.equal(a.own, 1); assert.equal(a.services, 1); assert.equal(a.inbound.roles, 3); assert.equal(a.inbound.worst, 'high');
});

test('cross-account use: named, unnamed (only a unique ID), merged from older scans, or not used in the window read', () => {
  const st = (p) => [{ Effect: 'Allow', Principal: { AWS: p }, Action: 'sts:AssumeRole' }];
  const r = role('x', st(`arn:aws:iam::${THIRD}:role/vendor-app`));
  const at = (seen) => ({ ...ctx, complete: new Set(['acct']), windowDays: new Map([['acct', 30]]), accountState: new Map([[CONNECTED, 'connected']]), seen: new Map([['r-x', seen]]) });
  const row = (key, n = 3) => ({ key, kind: 'account', display: key, last_seen: new Date(), sessions_count: n });
  // the target's trail had only the caller's unique ID: used, but which identity is not known
  let [e] = edgesOf(r, at([row(`acct:${THIRD}:AROAVENDORAPP000001`)]));
  assert.equal(e.seen.length, 1); assert.ok(e.seen[0].unnamed);
  assert.deepEqual(ids(e).filter((x) => /used/.test(x)), ['info:used-unnamed']);
  assert.match(e.findings.find((f) => f.id === 'used-unnamed').detail, /not scanned.*Onboard it/);
  // a whole-account trust is matched by the account alone: named enough
  [e] = edgesOf(role('x', st(`arn:aws:iam::${THIRD}:root`)), at([row(`acct:${THIRD}:AIDASOMEUSER0000001`)]));
  assert.equal(e.seen.length, 1); assert.ok(!e.findings.some((f) => /used/.test(f.id)));
  // older scans: one merged entry with no account
  [e] = edgesOf(r, at([row('other:AWSAccount', 162)]));
  assert.ok(e.seen[0].merged); assert.ok(e.findings.some((f) => f.id === 'used-unattributed')); assert.ok(!e.findings.some((f) => f.id === 'never-used'));
  // nothing at all: not used in the 30 days read, which holds without onboarding the caller
  [e] = edgesOf(r, at([]));
  assert.match(e.findings.find((f) => f.id === 'never-used').detail, /30 days of CloudTrail read for payments-prod.*whether or not the caller's account is onboarded/);
});

test('IAM last used beats "never used": the role is used even when no sign-in was tied to the statement', () => {
  const r = { ...role('ssm-exec', [{ Effect: 'Allow', Principal: { AWS: `arn:aws:iam::${CONNECTED}:root` }, Action: 'sts:AssumeRole' }]), last_used_at: new Date(Date.now() - 3 * 864e5), last_used_region: 'ap-southeast-3' };
  const c = { ...ctx, complete: new Set(['acct']), windowDays: new Map([['acct', 30]]) };
  let [e] = edgesOf(r, c);
  assert.ok(e.lastUsed);
  assert.deepEqual(ids(e).filter((x) => /used/.test(x)), ['info:used-per-iam']);
  [e] = edgesOf({ ...r, last_used_at: new Date(Date.now() - 200 * 864e5) }, c);
  assert.match(e.findings.find((f) => f.id === 'used-per-iam').detail, /before the 30 days of CloudTrail read/);
  [e] = edgesOf({ ...r, last_used_at: null }, c);
  assert.match(e.findings.find((f) => f.id === 'never-used').detail, /IAM has no record/);
});

test('Bitbucket: a wildcard after the repository pins it (the step changes every run); after repository and environment it is fine', () => {
  const bb = 'api.bitbucket.org/2.0/workspaces/krom/pipelines-config/identity/oidc', arn = `arn:aws:iam::${OWN}:oidc-provider/${bb}`;
  const st = (sub) => ({ Effect: 'Allow', Principal: { Federated: arn }, Action: 'sts:AssumeRoleWithWebIdentity',
    Condition: { StringEquals: { [`${bb}:aud`]: 'ari:cloud:bitbucket::workspace/x' }, StringLike: { [`${bb}:sub`]: sub } } });
  const [repo, env, any] = edgesOf(role('deploy', [st('{7f91ae86-0388-45be-9a20-35cbc4fc5f75}:*'), st('{7f91ae86-0388-45be-9a20-35cbc4fc5f75}:{c84baa79-f46a-414f-ab4d-e05775a5af99}:*'), st('*')]), { ...ctx, complete: new Set() });
  assert.deepEqual(ids(repo), ['low:oidc-broad-sub']);
  assert.deepEqual(ids(env), []);
  assert.deepEqual(ids(any), ['high:oidc-broad-sub']);
  assert.equal(repo.pkind, 'bitbucket');
});

test('Cognito: judged by the pool (aud) and guests (amr), not by a subject', () => {
  const st = (cond) => ({ Effect: 'Allow', Principal: { Federated: 'cognito-identity.amazonaws.com' }, Action: 'sts:AssumeRoleWithWebIdentity', Condition: cond });
  const aud = { 'cognito-identity.amazonaws.com:aud': 'ap-southeast-3:12345678-abcd-abcd-abcd-123456790ab' };
  const [signedIn, guests, noAmr, noAud] = edgesOf(role('app', [
    st({ StringEquals: aud, 'ForAnyValue:StringLike': { 'cognito-identity.amazonaws.com:amr': 'authenticated' } }),
    st({ StringEquals: aud, 'ForAnyValue:StringLike': { 'cognito-identity.amazonaws.com:amr': 'unauthenticated' } }),
    st({ StringEquals: aud }),
    st({ 'ForAnyValue:StringLike': { 'cognito-identity.amazonaws.com:amr': 'authenticated' } }),
  ]), { ...ctx, complete: new Set() });
  assert.deepEqual(ids(signedIn), []);
  assert.deepEqual(ids(guests), ['medium:cognito-guest']);
  assert.deepEqual(ids(noAmr), ['low:cognito-no-amr']);
  assert.deepEqual(ids(noAud), ['high:cognito-no-aud']);
});

test('your own account with MFA required (break-glass) is low; without it medium', () => {
  const [mfa, plain] = edgesOf(role('break-glass', [
    { Effect: 'Allow', Principal: { AWS: `arn:aws:iam::${OWN}:root` }, Action: 'sts:AssumeRole', Condition: { Bool: { 'aws:MultiFactorAuthPresent': 'true' } } },
    { Effect: 'Allow', Principal: { AWS: `arn:aws:iam::${OWN}:root` }, Action: 'sts:AssumeRole' },
  ]), { ...ctx, complete: new Set() });
  assert.deepEqual(ids(mfa), ['low:account-root']);
  assert.deepEqual(ids(plain), ['medium:account-root']);
});

test('a web identity sign-in vouches only for the statement whose provider and subject it matches', () => {
  const gh = 'token.actions.githubusercontent.com', arn = `arn:aws:iam::${OWN}:oidc-provider/${gh}`;
  const st = (sub) => ({ Effect: 'Allow', Principal: { Federated: arn }, Action: 'sts:AssumeRoleWithWebIdentity', Condition: { StringEquals: { [`${gh}:aud`]: 'sts.amazonaws.com' }, StringLike: { [`${gh}:sub`]: sub } } });
  const r = role('ci', [st('repo:acme/app:*'), st('repo:acme/infra:*')]);
  const seen = new Map([[r.id, [{ key: `fed:${arn}:sts.amazonaws.com:repo:acme/app:ref:refs/heads/main`, kind: 'federated', display: 'repo:acme/app', last_seen: new Date(), sessions_count: 10 }]]]);
  const [app, infra] = edgesOf(r, { ...ctx, seen });
  assert.equal(app.sessions, 10); assert.equal(app.callerCount, 1);
  assert.equal(infra.sessions, 0, 'repository B is not used because repository A signed in');
  // another EKS cluster in the same region is another provider
  const eks = (id) => `oidc.eks.ap-southeast-3.amazonaws.com/id/${id}`;
  const r2 = role('irsa', [{ Effect: 'Allow', Principal: { Federated: `arn:aws:iam::${OWN}:oidc-provider/${eks('AAAA1111')}` }, Action: 'sts:AssumeRoleWithWebIdentity' }]);
  const [e] = edgesOf(r2, { ...ctx, seen: new Map([[r2.id, [{ key: `fed:arn:aws:iam::${OWN}:oidc-provider/${eks('BBBB2222')}:sts.amazonaws.com:system:serviceaccount:a:b`, kind: 'federated', display: 'x', last_seen: new Date(), sessions_count: 3 }]]]) });
  assert.equal(e.sessions, 0);
});

test('a line and a source count each sign-in once, however many statements it matched', async () => {
  const { mapOf } = await import('../src/trustmap.js');
  const accts = [{ id: 'acct', name: 'payments-prod', account_id: OWN, environment: 'production', status: 'connected' }];
  const r = role('vendor', [
    { Effect: 'Allow', Principal: { AWS: [`arn:aws:iam::${THIRD}:root`, `arn:aws:iam::${THIRD}:role/ci`] }, Action: 'sts:AssumeRole', Condition: { StringEquals: { 'sts:ExternalId': 'x' } } }]);
  const seen = new Map([[r.id, [{ key: `role:${THIRD}:ci`, kind: 'role', display: 'role/ci', last_seen: new Date(), sessions_count: 7 }]]]);
  const es = edgesOf(r, { ...ctx, seen });
  assert.equal(es.length, 2); assert.ok(es.every((e) => e.sessions === 7));
  const m = mapOf(es, accts, accts);
  assert.equal(m.links[0].sessions, 7); assert.equal(m.sources[0].sessions, 7);
  assert.equal(es[0].seen.length, 1);
  assert.equal(JSON.parse(JSON.stringify(es[0])).callers, undefined, 'every caller stays off the answer');
});

test('the query language: a comma means either, source: takes provider kinds, mistakes are named', async () => {
  const { queryWarnings } = await import('../src/trustmap.js');
  const es = edgesOf(role('deployer', [
    { Effect: 'Allow', Principal: { AWS: `arn:aws:iam::${THIRD}:root` }, Action: 'sts:AssumeRole' },
    { Effect: 'Allow', Principal: { Federated: 'arn:aws:iam::1:oidc-provider/oidc.eks.ap-southeast-3.amazonaws.com/id/ABCDEF12' }, Action: 'sts:AssumeRoleWithWebIdentity' },
    { Effect: 'Allow', Principal: { Service: 'eks.amazonaws.com' }, Action: 'sts:AssumeRole' },
  ]), { ...ctx, complete: new Set() });
  const find = (q) => es.filter((e) => matchesQuery(e, parseQuery(q))).map((e) => e.type);
  assert.deepEqual(find('source:eks'), ['oidc'], 'the EKS kind, not the AWS service named eks');
  assert.deepEqual(find('source:external,eks'), ['aws-root', 'oidc']);
  assert.deepEqual(find('finding:account-root,oidc-no-sub'), ['aws-root', 'oidc']);
  assert.deepEqual(find('used:no -source:service'), ['aws-root', 'oidc']);
  assert.deepEqual(queryWarnings(parseQuery('fnding:account-root')), ['No filter called "fnding", so it was searched as text. Did you mean finding:account-root?']);
  assert.deepEqual(queryWarnings(parseQuery('finding:acount-root')), ['No finding called "acount-root". Did you mean account-root?']);
  assert.deepEqual(queryWarnings(parseQuery('finding:account-root role:deploy')), []);
});
