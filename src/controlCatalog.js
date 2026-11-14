// The control catalogue: every built-in rule the tool checks, as data, and what a workspace's policy does to a finding.
// No I/O here, so the pure analysers (analyzer/analyze.js, gcp/analyze.js) can use it; controls.js adds the database.
export const SEVERITIES = ['high', 'medium', 'low'];
export const DOMAINS = {
  permissions: 'Permissions',
  usage: 'Use of the role',
  evidence: 'What cannot be verified',
  trust: 'Trust: who can get in',
  credentials: 'IAM user credentials',
  gcp: 'Google Cloud',
  custom: 'Custom',
};
export const INBOX = 'Findings inbox', TRUST = 'Trust map; high and medium also in the Findings inbox';
const RISK = 'Risk score of the IAM user', GCP = 'Google Cloud page and its risk score';
const BY_LEVEL = 'By what the actions can do: high for write and permission management, medium for read and tagging, low for list.';

// id, domain, name, what it checks, severity (null = it varies, said in `varies`), where it shows, how to fix
const c = (id, domain, name, what, severity, where, fix, varies = null) => ({ id, domain, name, what, severity, varies, where, fix });
export const BUILTIN = [
  c('perm.wildcard-all', 'permissions', 'Every action on every resource', 'A policy allows "*" (or "*:*") on Resource "*".', 'high', INBOX, 'Replace with the actions listed under Used.'),
  c('perm.wildcard-service', 'permissions', 'Wildcard actions on every resource', 'A policy allows a wildcard such as s3:* or iam:Get* on Resource "*".', 'medium', INBOX, 'Replace with the actions listed under Used.'),
  c('usage.role-idle', 'usage', 'Role not used', 'No successful use in the history read.', 'medium', INBOX, 'Delete the role if nothing depends on it.'),
  c('usage.unexpected-principal', 'usage', 'Unexpected principal', 'Something assumed the role that no trust statement names directly.', 'medium', INBOX, 'Confirm with the owner, then name it in the trust policy or block it.'),
  c('evidence.data-event', 'evidence', 'Data-plane actions not verifiable', 'Object and item level calls are data events; without them "unused" cannot be proved.', null, INBOX, 'Keep, scoped to what the workload needs, or enable data events to verify.', BY_LEVEL),
  c('evidence.authorization-only', 'evidence', 'Checked by AWS, never logged', 'Actions AWS evaluates during another call and writes no event for.', null, INBOX, 'Reviewer decides: keep scoped or remove.', BY_LEVEL),
  c('evidence.not-logged', 'evidence', 'Actions CloudTrail cannot record', 'No data-event type exists for these calls, so no setting can confirm them.', null, INBOX, 'Reviewer decides: keep scoped or remove.', BY_LEVEL),
  c('evidence.before-window', 'evidence', 'Used before the stored history', 'IAM says the service was last used before the oldest event read.', null, INBOX, 'Reviewer decides: keep scoped or remove.', BY_LEVEL),
  c('evidence.service-unknown', 'evidence', 'Service used, actions not visible', 'IAM says the service was used recently but no matching event was found.', null, INBOX, 'Reviewer decides: keep scoped or remove.', BY_LEVEL),
  c('evidence.unmapped-event', 'evidence', 'Calls not matched to IAM actions', 'Event names seen that are not IAM action names.', null, INBOX, 'Map the event names on Event coverage, then re-analyse.', BY_LEVEL),

  c('trust.public', 'trust', 'Anyone can assume it', 'The trust policy allows principal "*".', null, TRUST, 'Name the principals that need the role, or add a condition such as aws:PrincipalOrgID.', 'High with no condition; medium when an organisation, account or ARN condition narrows it.'),
  c('trust.not-principal', 'trust', 'Allow with NotPrincipal', 'Everyone except a list is let in.', 'high', TRUST, 'Replace NotPrincipal with the principals that should get in.'),
  c('trust.account-root', 'trust', 'Trusts a whole AWS account', 'A whole account (:root) is trusted, not a specific role.', null, TRUST, 'Name the roles that come in (aws:PrincipalArn), or trust them directly.', 'High for an account outside your estate, medium for one of yours, low with ExternalId or MFA; not a finding when conditions name who comes in.'),
  c('trust.external-no-externalid', 'trust', 'Outside account without ExternalId', 'An account outside your estate is trusted with no sts:ExternalId.', null, TRUST, 'Ask the third party for its ExternalId and require it.', 'High when the whole account is trusted, medium for a named role.'),
  c('trust.oidc-no-sub', 'trust', 'OIDC trust without a subject', 'A web identity provider is trusted with no :sub condition.', null, TRUST, 'Add a :sub condition for the repository, branch or workload.', 'High for CI providers (GitHub, Bitbucket, GitLab…); lower where the provider has no shared tenants.'),
  c('trust.oidc-broad-sub', 'trust', 'OIDC subject is a broad wildcard', 'The :sub condition matches far more than one repository or workload.', null, TRUST, 'Narrow :sub to the repositories and branches that use the role.', 'High for "*", medium for a broad pattern, low for Bitbucket pinned to a repository.'),
  c('trust.oidc-no-aud', 'trust', 'OIDC trust without an audience', 'No :aud condition.', 'low', TRUST, 'Add an :aud condition (sts.amazonaws.com for most providers).'),
  c('trust.cognito-no-aud', 'trust', 'Cognito trust without an identity pool', 'No cognito-identity.amazonaws.com:aud condition: any pool in any account.', 'high', TRUST, 'Add the :aud condition with your identity pool ID.'),
  c('trust.cognito-guest', 'trust', 'Cognito guests can assume it', 'Unauthenticated identities of the pool get the role.', 'medium', TRUST, 'Keep the role to what a guest needs, or require amr = authenticated.'),
  c('trust.cognito-no-amr', 'trust', 'Cognito trust without amr', 'Guests and signed-in users alike.', 'low', TRUST, 'Add cognito-identity.amazonaws.com:amr = authenticated.'),
  c('trust.saml-no-aud', 'trust', 'SAML trust without SAML:aud', 'Assertions meant for other applications are not refused.', 'low', TRUST, 'Add SAML:aud = https://signin.aws.amazon.com/saml.'),
  c('trust.idc-multiple', 'trust', 'More than one IAM Identity Center', 'The account trusts several Identity Center instances.', 'high', TRUST, 'Check who runs the others and remove their AWSSSO provider if it is not yours.'),
  c('trust.idc-other', 'trust', 'Identity Center that is not your organisation\'s', 'Most of your accounts trust another instance.', 'high', TRUST, 'Check whose Identity Center this is; remove its provider if it is not yours.'),
  c('trust.iam-user', 'trust', 'Trusts an IAM user directly', 'A user with long-lived keys can assume the role.', 'low', TRUST, 'Trust a role instead of an IAM user.'),
  c('trust.deleted-principal', 'trust', 'Points at a deleted identity', 'The statement holds a unique ID where an ARN was.', 'medium', TRUST, 'Remove the statement.'),
  c('trust.broad-action', 'trust', 'sts:* or * in a trust policy', 'More than the sts: actions needed are allowed.', 'low', TRUST, 'Allow sts:AssumeRole and only the sts: actions needed.'),

  c('cred.console-no-mfa', 'credentials', 'Console password without MFA', 'An IAM user can sign in to the console with a password alone.', 'high', RISK, 'Add an MFA device, or remove the password.'),
  c('cred.key-old', 'credentials', 'Access key older than the rotation age', 'An active access key is older than the rotation age set in Configuration.', 'medium', RISK, 'Rotate it, or move the workload to a role.', 'Medium past the rotation age; weighs more past a year.'),
  c('cred.key-unused', 'credentials', 'Access key not used', 'An active key never used, or unused for longer than the age set in Configuration.', 'low', RISK, 'Deactivate it.'),
  c('cred.password-unused', 'credentials', 'Console password not used', 'A console password never used, or unused for longer than the age set in Configuration.', 'low', RISK, 'Remove it.'),
  c('cred.key-two', 'credentials', 'Two active access keys', 'Both key slots are active.', 'low', RISK, 'Retire one after rotation.'),
  c('cred.console-and-keys', 'credentials', 'Console password and access keys', 'One identity is both a person and a workload.', 'low', RISK, 'Split it: a person or a workload, not both.'),

  c('gcp.public', 'gcp', 'Granted to everyone', 'allUsers or allAuthenticatedUsers holds a role.', 'high', GCP, 'Remove the binding.'),
  c('gcp.public-impersonator', 'gcp', 'Anyone can become a service account', 'allUsers or allAuthenticatedUsers can impersonate it.', 'high', GCP, 'Remove the binding.'),
  c('gcp.external-impersonator', 'gcp', 'Someone outside your domain can become it', 'A user or group outside the organisation\'s domain can impersonate a service account.', 'high', GCP, 'Remove the binding or move the identity into your domain.'),
  c('gcp.basic-owner', 'gcp', 'Owner', 'The basic Owner role without a condition.', 'high', GCP, 'Replace with predefined roles.'),
  c('gcp.basic-editor', 'gcp', 'Editor', 'The basic Editor role without a condition.', null, GCP, 'Replace with predefined roles.', 'High on a default service account, medium otherwise.'),
  c('gcp.iam-admin', 'gcp', 'Can change who has access', 'Can set IAM policy on an organisation, folder or project.', 'high', GCP, 'Grant it on fewer resources, or to fewer identities.'),
  c('gcp.impersonate-many', 'gcp', 'Can become other service accounts', 'Token creator, actAs or key creation across a project, folder or organisation.', 'high', GCP, 'Grant it on the one service account needed.'),
  c('gcp.wif-broad', 'gcp', 'Any identity from a federated source', 'A workload identity pool or provider has no attribute condition.', 'high', GCP, 'Add an attribute condition.'),
  c('gcp.key', 'gcp', 'User-managed service account key', 'A service account has keys someone downloaded.', null, GCP, 'Prefer workload identity federation; delete or rotate the key.', 'High for a key that never expires on a powerful account, medium past the rotation age, low otherwise.'),
  c('gcp.external', 'gcp', 'Outside your domain', 'A user or group outside the organisation\'s domain holds a role.', 'medium', GCP, 'Confirm it is expected, or remove the binding.'),
  c('gcp.deleted', 'gcp', 'Bound to a deleted identity', 'The identity is gone but its bindings stay.', 'medium', GCP, 'Remove the bindings.'),
  c('gcp.disabled', 'gcp', 'Disabled but still granted roles', 'A disabled service account keeps its roles.', 'low', GCP, 'Remove the bindings or delete the service account.'),
];
export const BY_ID = new Map(BUILTIN.map((x) => [x.id, x]));
export const isBuiltin = (id) => BY_ID.has(id);

/** The control behind an analyser finding. */
const EVIDENCE = new Set(['data-event', 'authorization-only', 'not-logged', 'before-window', 'service-unknown', 'unmapped-event']);
export function controlOfFlag(category, key) {
  if (category === 'wildcard') return key === '*' || key === '*:*' ? 'perm.wildcard-all' : 'perm.wildcard-service';
  if (category === 'role-idle') return 'usage.role-idle';
  if (category === 'external-principal') return 'usage.unexpected-principal';
  if (EVIDENCE.has(category)) return `evidence.${category}`;
  return null;
}

// ---------------------------------------------------------------- what applies now
/** Nothing changed: every built-in control as shipped, no custom ones. */
export const DEFAULT_POLICY = { over: new Map(), custom: [], sig: '' };

/**
 * The severity a finding of this control gets: null when the control is off, the workspace's severity when it set one,
 * else the built-in one. An informational result (a fact, not a finding) stays informational.
 */
export function severityOf(policy, id, builtIn) {
  const o = policy?.over.get(id);
  if (!o) return builtIn;
  if (!o.enabled) return null;
  return builtIn === 'info' || !o.severity ? builtIn : o.severity;
}

