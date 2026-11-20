# Built-in rules and their severity

These are the defaults. A workspace can change any built-in control's severity or turn it off, and add its own rules, on the Policy page (`control_overrides`, `custom_controls`); its choices win. The policy page's descriptions come from `src/controlCatalog.js`, which must match this page.

What each severity means:

- **High**: someone who should not have access could get it, or already holds administrator-level rights nobody uses. Act now.
- **Medium**: a real over-grant or weak guard that needs a reviewer's decision.
- **Low**: worth knowing, clutter, or something the tool cannot verify. No urgency.

A finding that only says "use could not be proven" is never high.

## Roles and IAM users (Findings inbox, `src/analyzer/analyze.js`)

| Finding | Severity |
|---|---|
| Data-plane actions not in event history (`data-event`) | medium when it can write or delete in every bucket or table (`Resource: *`); otherwise low |
| Actions CloudTrail cannot record, SQS messages (`not-logged`) | low |
| Checked by AWS, never logged (`authorization-only`) | medium for `iam:PassRole` on every role; otherwise low |
| Service used before the stored history (`before-window`) | medium when the unverified actions change access (see below); otherwise low |
| Service used, actions not visible (`service-unknown`) | medium when the unverified actions change access; otherwise low |
| Event names not mapped (`unmapped-event`) | medium when writes are among them; otherwise low |
| Wildcard on every resource (`wildcard`) | high for `*`, or a pattern reaching the identity plane (`iam:*`, `iam:Put*`, `organizations:*`); medium when it can write, or read data itself (`s3:Get*`); low when read-only (`ec2:Describe*`); low on service-linked roles |
| Allow with `NotAction` on every resource (`wildcard`) | high; medium when IAM is among the exclusions |
| Unexpected principal used the role (`external-principal`) | medium |
| Role not used in the window (`role-idle`) | medium when it can write; low when read-only or service-linked. Roles under 14 days old are skipped. An unused administrator role is high through the rule control *Administrator access not used in 90 days* |

"Changes access" means the lists in `src/analyzer/sensitive.js`: IAM, Organizations and Identity Center policy and credential actions; resource policies and grants (KMS, S3, Lambda, Secrets Manager, ECR, SNS, SQS); code that runs as a role; switching off CloudTrail, GuardDuty or Config.

### Risk score (High at 50, Medium at 25)

| Reason | Points |
|---|---|
| Anyone can assume the role (no condition) | 50 |
| Grants effectively every action | 40 |
| Other broad trust | 10 |
| Unexpected principal used it | 20 |
| Wildcards on every resource | 20 each high, 10 each medium, read-only none; at most 30 |
| Unused permission-management actions | 1 each, at most 20 |
| Unused write actions | 1 per 10, at most 15 |
| Write actions that cannot be verified | 1 per 5, at most 10 |
| Idle | 10 |

### IAM user credentials (`src/analyzer/users.js`)

| Finding | Points |
|---|---|
| Console password without MFA | 50 |
| Access key older than a year | 25 |
| Access key older than the rotation age | 15 |
| Access key never used or unused past the stale age | 10 |
| Console password never used or unused past the stale age | 10 |
| Two active keys; console password and keys together | 5 each |

## Trust map (`src/trustmap.js`)

| Finding | Severity |
|---|---|
| Anyone can assume it (`public`) | high; medium when organisation or account conditions narrow it |
| Allow with NotPrincipal | high |
| Whole account trusted (`account-root`) | outside your estate high; another of your accounts medium; the role's own account low, medium if the role is High risk; low with MFA or a vendor's ExternalId; info when narrowed by PrincipalArn or tags |
| Outside account without ExternalId | high for a whole account, medium for a named role |
| OIDC without a subject | high (GitHub, GitLab.com, Terraform Cloud, Buildkite, Google, unknown providers); medium where the issuer is already yours (Bitbucket workspace, EKS cluster, CircleCI org, Azure tenant) |
| OIDC subject is a broad wildcard | high when it spans repositories or organisations; medium otherwise; low for Bitbucket repository-wide |
| OIDC or SAML without an audience | low |
| Cognito without an identity pool | high |
| Cognito guests can assume it | medium |
| Cognito without amr | low |
| More than one Identity Center, or not your organisation's | high |
| Trusts an IAM user | low |
| Points at a deleted identity | low |
| `sts:*` or `*` in a trust policy | low |

## Google Cloud (`src/gcp/analyze.js`)

| Finding | Severity |
|---|---|
| Granted to everyone | high |
| Owner; can set IAM policy; can become other service accounts | high |
| Editor | medium; high on a default service account |
| Any identity from a federated source; outsider or anyone can impersonate | high |
| Outside your domain | medium |
| User-managed key | high when it never expires on a high-risk account; medium past the rotation age; low otherwise |
| Bound to a deleted identity; disabled but still granted | low |
| A service account from a project outside the connection (`gcp.foreign-sa`) | medium; high when it can become a service account |
| Everyone in your own domain can become a service account (`gcp.domain-impersonator`) | medium |
| Impersonation or `actAs` granted on a whole project or folder (`gcp.wide-impersonation`; not Owner or Editor, which are their own finding) | medium |
| Can create keys for a service account (`gcp.key-create`) | medium |

### Trust map, Google Cloud (`src/gcp/trust.js`)

The same findings, per way in: public (low when public access prevention is enforced on the bucket), outside your domain, a foreign service account, a federated source with no attribute condition, wide impersonation, key creation and keys by age. Owner or Editor granted on a whole project or folder is informational; conditional bindings and paths across clouds are informational.

### Resource-level policies (`src/gcp/resources.js`)

Buckets, BigQuery datasets and tables, Pub/Sub topics and subscriptions, KMS keys and key rings, Secret Manager secrets, Cloud Run services, Cloud Functions and Artifact Registry repositories. Each role × member is a grant; a role *administers* when it can change access or is `*.admin`, *uses the data* when it reads or writes contents, else it *reads settings*.

| Rule | Severity |
|---|---|
| `allUsers` or `allAuthenticatedUsers` (`res.public`) | high for data or administer; medium for settings only; low on a bucket with public access prevention enforced |
| A user, group or domain outside your domain, or a service account from a project you do not connect (`res.external-account`) | high for data or administer; medium for settings |
| Another project in your connections, or an AWS account through federation that is connected here (`res.cross-account`) | low (an AWS account that is not connected counts as outside) |
| Every permission of a service, granted outside the project (`res.broad-actions`) | low |
| Bound to a deleted identity (`res.deleted-principal`) | low |

Google-managed service agents and convenience members (`projectViewer:` and the like) are never findings.

## Resource access (`src/analyzer/resourcePolicy.js`)

Resource-based policies of S3 buckets, KMS keys (customer managed), DynamoDB tables, SQS queues, SNS topics, Secrets Manager secrets, Lambda functions and ECR repositories. Each Allow statement × principal is a grant; how far it reaches counts its conditions (`aws:PrincipalOrgID`/`OrgPaths`, `aws:PrincipalAccount`, `aws:SourceAccount`, `aws:SourceOwner`, `kms:CallerAccount`, `aws:PrincipalArn`, `aws:SourceArn`) and Deny guards that apply to everyone with exactly one negated condition (`aws:PrincipalIsAWSService = false` exempts services from the guard). Network conditions (`aws:SourceVpce`, `SourceVpc`, `SourceIp`) do not keep other accounts out; they only lower *public*. A grant can *administer* (`*`, `service:*`, NotAction, or anything that changes access), *use the data* (reads data or writes), or *read settings*.

| Rule | Severity |
|---|---|
| Anyone (`*`) can use it | high when it reaches the data or can administer; medium for settings only, or when only a network condition limits it; low when S3 Block Public Access (`RestrictPublicBuckets`, bucket or account) already blocks it |
| Allow with NotPrincipal | high |
| Shared with an account outside your estate (not connected, not in your organisation; another organisation; a service acting for one) | high for data or administer; medium for settings only |
| AWS service principal without `aws:SourceAccount` / `aws:SourceArn` / `aws:SourceOrgID` | medium; low for settings only |
| Shared with another of your accounts or your organisation | low |
| Every action of a service granted outside the account | low |
| Names a deleted identity | low |

The resource's own account (the default KMS key policy, say) is never a finding. An account's resources are read with its inventory; everything is worked out again within a minute of an account being onboarded or removed, or a `res.*` control changing.

## Radar changes (`src/radarHistory.js`, `src/trustSync.js`, `src/resourceSync.js`)

| Change | Severity |
|---|---|
| Role gained admin-level permissions | high |
| New caller: an IAM user, or from another account | high; other new callers warn |
| New way in or guard removed | follows the trust finding |
| Role gained permissions; first denied calls | warn |
| Role idle 90 days; role created; new event name not identified | info |
| Role trimmed | good |
| Resource opened to anyone; shared outside the estate (a policy that changed, or a new resource on a later scan) | high, or warn when the finding is medium |
