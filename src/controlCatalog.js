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
  resource: 'Resource access: who resource policies let in',
  network: 'Networking (extension)',
  custom: 'Custom',
};
export const INBOX = 'Findings inbox', TRUST = 'Trust map; high and medium also in the Findings inbox', RESOURCES = 'Resource access', NETWORK = 'Networking page (when the extension is on)';
const RISK = 'Risk score of the IAM user', GCP = 'Google Cloud page and its risk score';
const EVIDENCE_SEV = 'Low; medium when the actions that cannot be verified change access (IAM, resource policies, grants, logging), write to every bucket or table, or are iam:PassRole on every role. Never high: nothing was seen to be wrong.';

// id, domain, name, what it checks, severity (null = it varies, said in `varies`), where it shows, how to fix
const c = (id, domain, name, what, severity, where, fix, varies = null) => ({ id, domain, name, what, severity, varies, where, fix });
// a built-in control that is a rule: what it applies to (identities or ways in), the rule, and whether it starts off
const r = (id, domain, name, what, severity, where, fix, target, rule, { off = false } = {}) => ({ id, domain, name, what, severity, varies: null, where, fix, target, rule, off });
export const BUILTIN = [
  c('perm.wildcard-all', 'permissions', 'Every action on every resource', 'A policy allows "*" (or "*:*") on Resource "*".', 'high', INBOX, 'Replace with the actions listed under Used.'),
  c('perm.wildcard-service', 'permissions', 'Wildcard actions on every resource', 'A policy allows a wildcard such as s3:* or iam:Get* on Resource "*".', null, INBOX, 'Replace with the actions listed under Used.', 'By what the wildcard expands to: high for the identity plane (iam:*, iam:Put*, organizations:*), medium when it can write or read data (s3:*, s3:Get*), low when read-only (ec2:Describe*) or on a service-linked role.'),
  c('perm.not-action', 'permissions', 'Everything except a list (NotAction)', 'A policy allows every action except a list, on Resource "*", including actions AWS adds later.', null, INBOX, 'Replace with the actions listed under Used.', 'High; medium when IAM is among the exclusions.'),
  c('usage.role-idle', 'usage', 'Role not used', 'No successful use in the history read. Roles under 14 days old are not counted.', null, INBOX, 'Delete the role if nothing depends on it.', 'Medium when it can write, low when read-only or service-linked. An unused administrator role is also caught, as high, by "Administrator access not used in 90 days".'),
  c('usage.unexpected-principal', 'usage', 'Unexpected principal', 'Something assumed the role that no trust statement names directly.', 'medium', INBOX, 'Confirm with the owner, then name it in the trust policy or block it.'),
  c('evidence.data-event', 'evidence', 'Data-plane actions not verifiable', 'Object and item level calls are data events; without them "unused" cannot be proved.', null, INBOX, 'Keep, scoped to what the workload needs, or enable data events to verify.', EVIDENCE_SEV),
  c('evidence.authorization-only', 'evidence', 'Checked by AWS, never logged', 'Actions AWS evaluates during another call and writes no event for.', null, INBOX, 'Reviewer decides: keep scoped or remove.', EVIDENCE_SEV),
  c('evidence.not-logged', 'evidence', 'Actions CloudTrail cannot record', 'No data-event type exists for these calls, so no setting can confirm them.', null, INBOX, 'Reviewer decides: keep scoped or remove.', EVIDENCE_SEV),
  c('evidence.before-window', 'evidence', 'Used before the stored history', 'IAM says the service was last used before the oldest event read.', null, INBOX, 'Reviewer decides: keep scoped or remove.', EVIDENCE_SEV),
  c('evidence.service-unknown', 'evidence', 'Service used, actions not visible', 'IAM says the service was used recently but no matching event was found.', null, INBOX, 'Reviewer decides: keep scoped or remove.', EVIDENCE_SEV),
  c('evidence.unmapped-event', 'evidence', 'Calls not matched to IAM actions', 'Event names seen that are not IAM action names.', null, INBOX, 'Map the event names on Event coverage, then re-analyse.', EVIDENCE_SEV),

  c('trust.public', 'trust', 'Anyone can assume it', 'The trust policy allows principal "*".', null, TRUST, 'Name the principals that need the role, or add a condition such as aws:PrincipalOrgID.', 'High with no condition; medium when an organisation, account or ARN condition narrows it.'),
  c('trust.not-principal', 'trust', 'Allow with NotPrincipal', 'Everyone except a list is let in.', 'high', TRUST, 'Replace NotPrincipal with the principals that should get in.'),
  c('trust.account-root', 'trust', 'Trusts a whole AWS account', 'A whole account (:root) is trusted, not a specific role.', null, TRUST, 'Name the roles that come in (aws:PrincipalArn), or trust them directly.', 'High for an account outside your estate; medium for another of your accounts; low for the role\'s own account (medium when the role is High risk), with MFA, or with a vendor\'s ExternalId; informational when narrowed by aws:PrincipalArn or tags.'),
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
  c('trust.deleted-principal', 'trust', 'Points at a deleted identity', 'The statement holds a unique ID where an ARN was.', 'low', TRUST, 'Remove the statement.'),
  c('trust.broad-action', 'trust', 'sts:* or * in a trust policy', 'More than the sts: actions needed are allowed.', 'low', TRUST, 'Allow sts:AssumeRole and only the sts: actions needed.'),

  c('res.public', 'resource', 'Anyone can use a resource', 'A bucket, key, table, queue, topic, secret, function or repository policy allows principal "*" with no condition that limits who.', null, RESOURCES,
    'Name the principals, or add aws:PrincipalOrgID or aws:SourceAccount; keep S3 Block Public Access on.', 'High when it reaches the data or can change access; medium for metadata only, or when only a network condition (VPC endpoint, IP) keeps other accounts out; low when S3 Block Public Access already restricts the bucket.'),
  c('res.not-principal', 'resource', 'Resource policy Allow with NotPrincipal', 'Everyone except a list is let in.', 'high', RESOURCES, 'Replace NotPrincipal with the principals that need it.'),
  c('res.external-account', 'resource', 'Shared with an account outside your estate', 'A resource policy lets in an AWS account that is neither connected here nor in your organisation (or another organisation, or a service acting for one).', null, RESOURCES,
    'Confirm the third party still needs it; name its role, not the whole account, and keep the actions to what it uses.', 'High when it reaches the data or can change access; medium for metadata only.'),
  c('res.service-no-source', 'resource', 'AWS service let in without a source condition', 'A service principal (cloudtrail, sns, events…) is allowed with no aws:SourceAccount, aws:SourceArn or aws:SourceOrgID: any account\'s use of that service could reach it (confused deputy).', null, RESOURCES,
    'Add aws:SourceAccount or aws:SourceArn.', 'Medium; low when the service can only read settings.'),
  c('res.cross-account', 'resource', 'Shared with another of your accounts', 'Another connected account, an account of your organisation, or the whole organisation can use the resource.', 'low', RESOURCES, 'Fine when intended. Name the role that needs it rather than the whole account.'),
  c('res.broad-actions', 'resource', 'Every action of a service granted outside the account', 'A resource policy allows * or service:* to a principal outside the resource\'s account.', 'low', RESOURCES, 'Grant the actions it uses.'),
  c('res.deleted-principal', 'resource', 'Resource policy names a deleted identity', 'A statement holds a unique ID where an ARN was.', 'low', RESOURCES, 'Remove the statement.'),

  c('net.sg-admin-open', 'network', 'Admin port open to the internet (security group)', 'A security group allows 0.0.0.0/0 or ::/0 on SSH, RDP, Telnet, WinRM, VNC, the Docker API or the kubelet.', null, NETWORK, 'Allow only your own ranges, or use Session Manager or a VPN.', 'High when something with a public address uses it; medium when it is in use with no public address; low when nothing uses it.'),
  c('net.sg-data-open', 'network', 'Database port open to the internet (security group)', 'A security group allows 0.0.0.0/0 on a database or cache port (MySQL, PostgreSQL, SQL Server, Oracle, MongoDB, Redis, Elasticsearch…).', null, NETWORK, 'Allow only the application tier.', 'High when something with a public address uses it; medium when it is in use with no public address; low when nothing uses it.'),
  c('net.sg-all-open', 'network', 'Every port open to the internet (security group)', 'A security group allows all traffic from 0.0.0.0/0.', null, NETWORK, 'Open only the ports the service listens on, to the addresses that need them.', 'High when something with a public address uses it; medium when it is in use with no public address; low when nothing uses it.'),
  c('net.sg-wide-open', 'network', 'Wide port range open to the internet (security group)', 'More than 1,000 ports open to 0.0.0.0/0, none of them an admin or database port.', null, NETWORK, 'Open only the ports the service listens on.', 'Medium when something with a public address uses it, low otherwise.'),
  c('net.sg-unused', 'network', 'Security group not used', 'No network interface or load balancer uses it.', 'low', NETWORK, 'Delete it.'),
  c('net.default-sg-used', 'network', 'Default security group in use', 'Something uses the VPC\'s default security group.', 'low', NETWORK, 'Give it its own group; leave the default one empty (CIS 5.4).'),
  c('net.nacl-admin-open', 'network', 'Network ACL lets the internet reach admin ports', 'The ACL of a public subnet allows 0.0.0.0/0 to SSH or RDP before any deny.', 'low', NETWORK, 'Deny the admin ports from 0.0.0.0/0 in the ACL (CIS 5.1).'),
  c('net.default-vpc', 'network', 'Default VPC', 'A default VPC exists in a region read.', null, NETWORK, 'Delete it once nothing runs there.', 'Medium when something runs in it, low when empty.'),
  c('net.flow-logs-off', 'network', 'VPC without flow logs', 'A VPC (other than an empty default one) has no active flow log on it or on all its subnets.', 'medium', NETWORK, 'Turn on VPC flow logs (CIS 3.7).'),
  c('net.subnet-auto-public-ip', 'network', 'Public subnets that assign public IPs', 'Subnets routed to an internet gateway give every instance a public address on launch.', 'low', NETWORK, 'Turn off auto-assign public IPv4.'),
  c('net.peering-external', 'network', 'VPC peering outside your estate', 'An active peering connection with an account that is neither connected here nor in your organisation.', 'medium', NETWORK, 'Confirm it; route only what is needed.'),
  c('net.tgw-external', 'network', 'Transit gateway attachment outside your estate', 'A VPC of another account on your transit gateway, or yours on someone else\'s.', 'medium', NETWORK, 'Confirm it; give it its own route table.'),
  c('net.tgw-auto-accept', 'network', 'Transit gateway accepts shared attachments on its own', 'Auto accept shared attachments is on.', 'low', NETWORK, 'Turn it off.'),
  c('net.vpn-down', 'network', 'VPN tunnels down (AWS)', 'A site-to-site VPN with one or both tunnels down.', null, NETWORK, 'Bring the tunnel up, or delete the VPN.', 'Medium when every tunnel is down, low when one is.'),
  c('net.cidr-overlap', 'network', 'Connected networks with overlapping addresses', 'Two VPCs or networks connected by peering, a transit gateway or a VPN use overlapping ranges.', 'low', NETWORK, 'Renumber one side, or connect through NAT.'),
  c('net.dx-down', 'network', 'Direct Connect virtual interface down', 'A virtual interface is down, or BGP sessions on it are.', null, NETWORK, 'Check the connection and your router, or delete the interface.', 'Medium when nothing is up on it, low when one BGP session is down.'),
  c('net.dx-single', 'network', 'Gateway on one Direct Connect connection', 'Every virtual interface to a Direct Connect gateway or virtual private gateway uses the same connection.', 'low', NETWORK, 'Add a connection at another location, or a VPN as a backup.'),
  c('net.tgw-blackhole', 'network', 'Transit gateway blackhole routes', 'A transit gateway route table has routes whose attachment is gone.', 'low', NETWORK, 'Delete the routes.'),
  c('net.client-vpn-wide', 'network', 'Client VPN reaches everything for everyone', 'An authorization rule for all users covers the whole VPC or 0.0.0.0/0.', 'low', NETWORK, 'Authorize groups to the subnets they need.'),
  c('net.client-vpn-no-log', 'network', 'Client VPN without connection logs', 'Connection logging is off.', 'low', NETWORK, 'Turn on connection logging.'),
  c('net.privatelink-external', 'network', 'PrivateLink service used outside your estate', 'An endpoint in an account that is not yours is connected to a service you offer.', 'medium', NETWORK, 'Confirm the consumer; require acceptance; allow only the principals that need it.'),
  c('net.vpc-shared-external', 'network', 'VPC subnets shared outside your estate', 'A network account shares subnets (AWS RAM) with an account that is neither connected here nor in your organisation: it can run resources inside your VPC.', 'medium', NETWORK, 'Share only with accounts in your organisation; turn off sharing with external principals in RAM.'),
  c('net.gcp-psc-external', 'network', 'Private Service Connect service used by a project that is not yours', 'An accepted endpoint from a project no connection reads and that is not listed as yours.', 'medium', NETWORK, 'Use ACCEPT_MANUAL with an accept list.'),
  c('net.link-unused', 'network', 'Connection not used (flow logs)', 'Peering, a transit gateway attachment, a VPN, Direct Connect or PrivateLink with no accepted traffic in the VPC flow logs read, while flow logs covered it for at least 3 days.', 'low', NETWORK, 'Remove it if nothing needs it: an unused path is still a way in.'),
  c('net.open-port-unused', 'network', 'Port open to the internet that nobody uses (flow logs)', 'A port the internet can reach on a public address had no accepted connection in the VPC flow logs read (at least 3 days).', 'low', NETWORK, 'Close it.'),
  c('net.gcp-fw-admin-open', 'network', 'Admin port open to the internet (Google Cloud firewall)', 'A firewall rule or firewall policy rule allows 0.0.0.0/0 on SSH, RDP and other admin ports.', null, NETWORK, 'Allow only your ranges, or Identity-Aware Proxy (35.235.240.0/20).', 'High when it reaches an instance with an external address; medium when its targets have none; low when nothing it targets runs.'),
  c('net.gcp-fw-data-open', 'network', 'Database port open to the internet (Google Cloud firewall)', 'A firewall rule allows 0.0.0.0/0 on a database or cache port.', null, NETWORK, 'Allow only the application tier.', 'High when it reaches an instance with an external address; medium when its targets have none; low when nothing it targets runs.'),
  c('net.gcp-fw-all-open', 'network', 'Every port open to the internet (Google Cloud firewall)', 'A firewall rule allows every protocol from 0.0.0.0/0.', null, NETWORK, 'Open only the ports needed.', 'High when it reaches an instance with an external address; medium when its targets have none; low when nothing it targets runs.'),
  c('net.gcp-fw-wide-open', 'network', 'Wide port range open to the internet (Google Cloud firewall)', 'More than 1,000 ports open to 0.0.0.0/0.', null, NETWORK, 'Open only the ports needed.', 'Medium when it reaches an external address, low otherwise.'),
  c('net.gcp-default-network', 'network', 'Default or auto mode network', 'A project has the default network, or a network that creates a subnet in every region.', 'medium', NETWORK, 'Use a custom mode network (CIS 3.1).'),
  c('net.gcp-legacy-network', 'network', 'Legacy network', 'A network with no subnets.', 'medium', NETWORK, 'Move to a VPC network (CIS 3.2).'),
  c('net.gcp-flow-logs-off', 'network', 'Subnets without flow logs (Google Cloud)', 'Subnets with VPC flow logs off.', 'low', NETWORK, 'Turn on flow logs (CIS 3.8).'),
  c('net.gcp-peering-external', 'network', 'Network peering with a project that is not yours', 'An active peering to a network in a project no connection reads and that is not listed as yours.', 'medium', NETWORK, 'Confirm it; keep firewall rules for its ranges tight.'),
  c('net.gcp-vpn-down', 'network', 'VPN tunnel not up (Google Cloud)', 'A Cloud VPN tunnel whose status is not ESTABLISHED.', 'low', NETWORK, 'Check the peer, or delete the tunnel.'),

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
  c('gcp.deleted', 'gcp', 'Bound to a deleted identity', 'The identity is gone but its bindings stay.', 'low', GCP, 'Remove the bindings.'),
  c('gcp.foreign-sa', 'gcp', 'Service account from outside your organisation', 'A service account from a project that is not yours (no connection reads it, it is not under one of your organizations, it is not on your list of projects) can become a service account here, or holds roles here.', null, GCP, 'Confirm who owns that project; grant on the one service account it needs. If it is yours, add it under Configuration → Google Cloud: what is yours.', 'High when it can become a service account; medium for roles held directly.'),
  c('gcp.domain-impersonator', 'gcp', 'Everyone in a domain can become a service account', 'A domain: member holds Token Creator, Service Account User or similar on a service account.', 'medium', GCP, 'Grant it to a group or the people who need it.'),
  c('gcp.wide-impersonation', 'gcp', 'Impersonation granted on a whole project, folder or organisation', 'Token Creator, Service Account User or key creation granted above the service account reaches every service account below it.', 'medium', GCP, 'Grant it on the service account that is needed.'),
  c('gcp.key-create', 'gcp', 'Can mint keys for a service account', 'Holds iam.serviceAccountKeys.create on a service account.', 'medium', GCP, 'Remove it; use impersonation or federation instead of keys.'),
  c('gcp.disabled', 'gcp', 'Disabled but still granted roles', 'A disabled service account keeps its roles.', 'low', GCP, 'Remove the bindings or delete the service account.'),

  // ---- built-in controls that are rules: written in the rule language, so they can be read, copied and adapted
  r('rule.admin-unused', 'permissions', 'Administrator access not used in 90 days', 'A role that can do nearly everything and that nobody has used for three months.', 'high', INBOX, 'Delete it, or replace it with what its last users needed.',
    'identity', 'kind = role AND kind != service-linked AND (policy = AdministratorAccess OR permissions >= 15000) AND idle > 90'),
  r('rule.privesc-iam', 'permissions', 'Can give itself more permissions', 'Not an administrator, but allowed to attach or rewrite IAM policies or change who can assume a role.', 'high', INBOX, 'Remove the IAM write actions, or put a permissions boundary on what it can create.',
    'identity', 'kind != service-linked AND permissions < 15000 AND grants = iam:AttachRolePolicy,iam:PutRolePolicy,iam:AttachUserPolicy,iam:PutUserPolicy,iam:CreatePolicyVersion,iam:SetDefaultPolicyVersion,iam:UpdateAssumeRolePolicy'),
  r('rule.privesc-passrole', 'permissions', 'Can pass a role to compute it launches', 'iam:PassRole together with launching compute: it can run code as another, stronger role.', 'medium', INBOX, 'Limit iam:PassRole to the roles the workload needs (Resource), with iam:PassedToService.',
    'identity', 'kind != service-linked AND permissions < 15000 AND grants = iam:PassRole AND grants = ec2:RunInstances,lambda:CreateFunction,ecs:RunTask,glue:CreateJob,cloudformation:CreateStack,sagemaker:CreateTrainingJob'),
  r('rule.create-credentials', 'permissions', 'Can create credentials for other identities', 'Allowed to make access keys or console passwords for IAM users.', 'medium', INBOX, 'Remove the actions, or limit them to the identity itself (${aws:username}).',
    'identity', 'kind != service-linked AND permissions < 15000 AND grants = iam:CreateAccessKey,iam:CreateLoginProfile,iam:UpdateLoginProfile'),
  r('rule.disable-logging', 'permissions', 'Can turn off logging or detection', 'Allowed to stop CloudTrail, AWS Config, GuardDuty or Security Hub, without being an administrator.', 'medium', INBOX, 'Remove the actions; deny them with a service control policy.',
    'identity', 'kind != service-linked AND permissions < 15000 AND grants = cloudtrail:StopLogging,cloudtrail:DeleteTrail,config:StopConfigurationRecorder,config:DeleteConfigurationRecorder,guardduty:DeleteDetector,securityhub:DisableSecurityHub'),
  r('rule.kms-destroy', 'permissions', 'Can delete or take over encryption keys', 'Allowed to schedule KMS keys for deletion, disable them or rewrite their key policy.', 'medium', INBOX, 'Keep key administration to the roles that own the keys.',
    'identity', 'kind != service-linked AND permissions < 15000 AND grants = kms:ScheduleKeyDeletion,kms:DisableKey,kms:PutKeyPolicy'),
  r('rule.create-role-no-boundary', 'permissions', 'Can create roles, with no permissions boundary', 'It can create roles and nothing limits what those roles may do.', 'low', INBOX, 'Require a permissions boundary on the roles it creates (iam:PermissionsBoundary).',
    'identity', 'kind != service-linked AND permissions < 15000 AND grants = iam:CreateRole AND boundary = no'),
  r('rule.mostly-unused', 'usage', 'Uses less than a tenth of what it is allowed', 'In use, but nine in ten of its permissions were never needed.', 'low', INBOX, 'Apply the least-privilege recommendation.',
    'identity', 'kind != service-linked AND permissions >= 50 AND permissions < 15000 AND unusedpct >= 90 AND idle <= 90'),
  r('rule.no-owner-tag', 'usage', 'No owner or team tag', 'Nobody is named as responsible for the role.', 'low', INBOX, 'Tag it with owner or team.',
    'identity', 'kind = role AND kind != service-linked,identity-center AND tag != owner AND tag != team', { off: true }),
  r('rule.user-admin', 'credentials', 'IAM user with administrator access', 'Long-lived credentials that can do nearly everything.', 'high', INBOX, 'Move it to a role people or workloads assume; delete the user.',
    'identity', 'kind = user AND (policy = AdministratorAccess OR permissions >= 15000)'),
  r('rule.key-over-a-year', 'credentials', 'Key older than a year', 'An active access key (AWS) or service account key (Google Cloud) made more than a year ago.', 'high', `${INBOX}; Google Cloud page`, 'Rotate it, or replace it with a role or workload identity federation.',
    'identity', 'keyage > 365'),
  r('rule.user-no-credentials', 'credentials', 'IAM user with no way to sign in', 'No active access key and no console password: a leftover.', 'low', INBOX, 'Delete the user.',
    'identity', 'kind = user AND keys = 0 AND console = no'),
  r('rule.user-in-production', 'credentials', 'IAM user in a production account', 'Long-lived credentials where roles should be used.', 'low', INBOX, 'Replace it with a role: Identity Center for people, workload identity for services.',
    'identity', 'kind = user AND env = production'),
  r('rule.gcp-key-on-powerful', 'gcp', 'Key on a service account that controls access', 'A downloadable key for a service account that is Owner or can change IAM policy.', 'high', 'Google Cloud page', 'Delete the key; use workload identity federation or impersonation.',
    'identity', 'cloud = gcp AND keys > 0 AND finding = basic-owner,iam-admin'),
  r('rule.gcp-person-many-projects', 'gcp', 'A person with roles across more than ten projects', 'One user account reaches many projects directly, not through a group.', 'low', 'Google Cloud page', 'Grant the roles to a group, at the folder that fits.',
    'identity', 'cloud = gcp AND kind = user AND reach > 10'),
  r('rule.outside-into-admin', 'trust', 'Outside account into an administrator role', 'An AWS account that is not yours can assume a role that can do nearly everything.', 'high', TRUST, 'Give the third party a role with only what it needs.',
    'way-in', 'source = external AND has = admin'),
  r('rule.lower-env-into-production', 'trust', 'A non-production account can get into production', 'A role in production trusts one of your accounts from another environment.', 'high', TRUST, 'Go through a deployment or hub account instead.',
    'way-in', 'source = connected AND env = production AND fromenv != production'),
  r('rule.ci-into-admin', 'trust', 'A CI pipeline into an administrator role', 'A CI provider (GitHub, Bitbucket, GitLab, CircleCI, Buildkite, Terraform Cloud) can assume a role that can do nearly everything.', 'medium', TRUST, 'Give the pipeline a deploy role with what it deploys.',
    'way-in', 'source = github,bitbucket,gitlab,circleci,buildkite,terraform AND has = admin'),
  r('rule.outside-never-used', 'trust', 'Outside account trusted, never used', 'An AWS account that is not yours is trusted and nothing came in through it in the history read.', 'medium', TRUST, 'Remove the statement.',
    'way-in', 'source = external AND used = no'),
  r('rule.new-outside-trust', 'trust', 'New trust from outside this week', 'An outside account or anyone was let in, or lost a guard, in the last seven days.', 'medium', TRUST, 'Confirm it was intended; mark it as expected once reviewed.',
    'way-in', 'source = external,public AND new = 7'),
];
export const BY_ID = new Map(BUILTIN.map((x) => [x.id, x]));
export const isBuiltin = (id) => BY_ID.has(id);

/** The control behind an analyser finding. */
const EVIDENCE = new Set(['data-event', 'authorization-only', 'not-logged', 'before-window', 'service-unknown', 'unmapped-event']);
export function controlOfFlag(category, key) {
  if (category === 'wildcard') return key === '*' || key === '*:*' ? 'perm.wildcard-all' : String(key).startsWith('NotAction:') ? 'perm.not-action' : 'perm.wildcard-service';
  if (category === 'role-idle') return 'usage.role-idle';
  if (category === 'external-principal') return 'usage.unexpected-principal';
  if (EVIDENCE.has(category)) return `evidence.${category}`;
  return null;
}

// ---------------------------------------------------------------- what applies now
/** Nothing changed: every built-in control as shipped, no custom ones. */
export const DEFAULT_POLICY = { over: new Map(), rules: [], sig: '' };

/**
 * The severity a finding of this control gets: null when the control is off, the workspace's severity when it set one,
 * else the built-in one. An informational result (a fact, not a finding) stays informational.
 */
export function severityOf(policy, id, builtIn) {
  const o = policy?.over.get(id);
  if (!o) return BY_ID.get(id)?.off ? null : builtIn;
  if (!o.enabled) return null;
  return builtIn === 'info' || !o.severity ? builtIn : o.severity;
}

