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
  assert.equal(vendor.roles.length, 2); assert.equal(vendor.worst, 'high'); assert.equal(vendor.kind, 'outside');
  assert.equal(vendor.roles[0].role, 'vendor-a', 'the worst role first');
  const s = m.sources.find((x) => x.id === `src:acct:${THIRD}`);
  assert.equal(s.vendor, false, 'one statement lacks ExternalId');
  const between = m.links.find((l) => l.kind === 'account');
  assert.deepEqual([between.from, between.to, between.roles.map((r) => r.role)], ['stg', 'acct', ['from-stg']]);
  const a = m.accounts.find((x) => x.id === 'acct');
  assert.equal(a.own, 1); assert.equal(a.services, 1); assert.equal(a.inbound.roles, 3); assert.equal(a.inbound.worst, 'high');
});
