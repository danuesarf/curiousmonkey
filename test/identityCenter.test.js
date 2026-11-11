// IAM Identity Center: providers from one instance are one source; an account trusting another instance is flagged.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { samlIssuer, instanceOf, instanceKey, instanceLabel, identityCenters, isIdentityCenter } from '../src/identityCenter.js';
import { edgesOf } from '../src/trustmap.js';
import { samlProvidersOf, ssoProviderName } from '../src/demo/estate.js';

const issuer = (home, ins, region = 'ap-southeast-1') => `https://portal.sso.${region}.amazonaws.com/saml/assertion/${Buffer.from(`${home}_ins-${ins}`).toString('base64')}`;
const ORG = issuer('999900001111', 'a1b2c3d4e5f60718'), LOCAL = issuer('222222222222', '0f0f0f0f0f0f0f0f'), OTHER_ORG = issuer('555500006666', '1234567890abcdef');

test('the issuer is read from SAML metadata, and says which instance and which account manages it', () => {
  const xml = `<?xml version="1.0"?><md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="${ORG}" validUntil="2030-01-01T00:00:00Z"><md:IDPSSODescriptor/></md:EntityDescriptor>`;
  assert.equal(samlIssuer(xml), ORG);
  assert.equal(samlIssuer('<EntityDescriptor entityID="http://www.okta.com/exk1"/>'), 'http://www.okta.com/exk1');
  assert.equal(samlIssuer('not xml'), null);
  assert.deepEqual({ ...instanceOf(ORG), id: undefined }, { region: 'ap-southeast-1', id: undefined, instance: 'ins-a1b2c3d4e5f60718', homeAccount: '999900001111' });
  assert.equal(instanceOf('http://www.okta.com/exk1'), null);
  assert.equal(instanceLabel(ORG), 'IAM Identity Center · ins-a1b2c3d4e5f60718');
  assert.equal(instanceLabel(null), 'IAM Identity Center');
  assert.equal(instanceKey(null), 'unknown');
  // recognised by name even before the metadata could be read; an Okta provider is not Identity Center
  assert.ok(isIdentityCenter({ name: 'AWSSSO_893c66bbe512aa15_DO_NOT_DELETE' }));
  assert.ok(!isIdentityCenter({ name: 'Okta', issuer: 'http://www.okta.com/exk1' }));
});

test("the organisation's instance is the one most accounts trust; a tie decides nothing", () => {
  const rows = [
    { account_id: 'a', name: 'AWSSSO_1_DO_NOT_DELETE', issuer: ORG }, { account_id: 'b', name: 'AWSSSO_2_DO_NOT_DELETE', issuer: ORG },
    { account_id: 'c', name: 'AWSSSO_3_DO_NOT_DELETE', issuer: OTHER_ORG }, { account_id: 'b', name: 'AWSSSO_4_DO_NOT_DELETE', issuer: LOCAL },
    { account_id: 'a', name: 'Okta', issuer: 'http://www.okta.com/exk1' },
  ];
  const idc = identityCenters(rows);
  assert.equal(idc.primary, instanceKey(ORG));
  assert.equal(idc.byAccount.get('b').size, 2);
  assert.equal(idc.byAccount.get('a').size, 1);                    // Okta is not counted
  assert.equal(identityCenters(rows.filter((r) => r.account_id !== 'b')).primary, null);   // one each: no winner
});

const role = (acct, id, provider) => ({ id: `r-${acct}`, name: 'AWSReservedSSO_Admin_1', arn: `arn:aws:iam::${id}:role/AWSReservedSSO_Admin_1`, account_id: acct, account_name: acct,
  aws_account_id: id, environment: 'production', risk: 'Low', granted_count: 1,
  trust_policy: { Statement: [{ Effect: 'Allow', Action: ['sts:AssumeRoleWithSAML', 'sts:TagSession'], Principal: { Federated: `arn:aws:iam::${id}:saml-provider/${provider}` }, Condition: { StringEquals: { 'SAML:aud': 'https://signin.aws.amazon.com/saml' } } }] } });

test('every account trusting the same instance is one source; a second or foreign instance is a high finding', () => {
  const A = ['acct-a', '111111111111', 'AWSSSO_aaaaaaaaaaaaaaaa_DO_NOT_DELETE'], B = ['acct-b', '222222222222', 'AWSSSO_bbbbbbbbbbbbbbbb_DO_NOT_DELETE'];
  const C = ['acct-c', '333333333333', 'AWSSSO_cccccccccccccccc_DO_NOT_DELETE'], D = ['acct-d', '444444444444', 'AWSSSO_dddddddddddddddd_DO_NOT_DELETE'];
  const rows = [
    { account_id: A[0], arn: `arn:aws:iam::${A[1]}:saml-provider/${A[2]}`, name: A[2], issuer: ORG },
    { account_id: B[0], arn: `arn:aws:iam::${B[1]}:saml-provider/${B[2]}`, name: B[2], issuer: ORG },
    { account_id: B[0], arn: `arn:aws:iam::${B[1]}:saml-provider/AWSSSO_eeeeeeeeeeeeeeee_DO_NOT_DELETE`, name: 'AWSSSO_eeeeeeeeeeeeeeee_DO_NOT_DELETE', issuer: LOCAL },
    { account_id: C[0], arn: `arn:aws:iam::${C[1]}:saml-provider/${C[2]}`, name: C[2], issuer: OTHER_ORG },
  ];
  const ctx = { connected: new Map(), seen: new Map(), complete: new Set(), saml: new Map(rows.map((x) => [`${x.account_id}|${x.arn}`, x])), idc: identityCenters(rows) };
  const [a] = edgesOf(role(...A), ctx), [b] = edgesOf(role(...B), ctx), [c] = edgesOf(role(...C), ctx), [d] = edgesOf(role(...D), ctx);
  const ids = (e) => e.findings.filter((f) => f.severity !== 'info' || f.id.startsWith('idc')).map((f) => `${f.severity}:${f.id}`).sort();

  assert.equal(a.source, 'IAM Identity Center · ins-a1b2c3d4e5f60718');
  assert.equal(b.source, a.source);                                 // two accounts, two provider names, one source
  assert.equal(a.identityCenter.managedFrom, '999900001111');
  assert.deepEqual(ids(a), []);
  assert.deepEqual(ids(b), ['high:idc-multiple']);                  // b also trusts an instance of its own
  assert.match(b.findings.find((f) => f.id === 'idc-multiple').detail, /2 IAM Identity Center instances.*ins-0f0f0f0f0f0f0f0f \(managed from 222222222222\)/);
  assert.deepEqual(ids(c), ['high:idc-other']);                     // c trusts only someone else's
  assert.match(c.findings.find((f) => f.id === 'idc-other').detail, /Most of your accounts trust IAM Identity Center · ins-a1b2c3d4e5f60718 \(managed from 999900001111\); this is .*555500006666/);
  assert.equal(d.source, 'IAM Identity Center');                    // provider not read: grouped, and says why
  assert.deepEqual(ids(d), ['info:idc-unknown']);
});

test('the demo estate: one organisation instance everywhere, and the staging account has a second', () => {
  const prod = samlProvidersOf('111111111111'), stg = samlProvidersOf('222222222222');
  assert.equal(prod.length, 1); assert.equal(stg.length, 2);
  assert.equal(prod[0].issuer, stg[0].issuer);
  assert.notEqual(prod[0].name, stg[0].name);                       // a different provider name in every account
  assert.equal(prod[0].name, ssoProviderName('111111111111'));
  assert.notEqual(instanceKey(stg[1].issuer), instanceKey(stg[0].issuer));
});
