// The gcloud commands to let Curious Monkey read a Google Cloud organization, folder or project: a read-only role,
// a service account holding it, and either workload identity federation from this app's own AWS role (no secret
// to store) or a key.
export const GCP_READER_PERMISSIONS = [
  'resourcemanager.organizations.get', 'resourcemanager.organizations.getIamPolicy',
  'resourcemanager.folders.get', 'resourcemanager.folders.list', 'resourcemanager.folders.getIamPolicy',
  'resourcemanager.projects.get', 'resourcemanager.projects.list', 'resourcemanager.projects.getIamPolicy',
  'iam.serviceAccounts.get', 'iam.serviceAccounts.list', 'iam.serviceAccounts.getIamPolicy', 'iam.serviceAccountKeys.list',
  'iam.roles.get', 'iam.roles.list',
  'iam.workloadIdentityPools.get', 'iam.workloadIdentityPools.list', 'iam.workloadIdentityPoolProviders.get', 'iam.workloadIdentityPoolProviders.list',
];
// folders cannot hold custom roles: predefined roles that together cover the list above
export const GCP_READER_PREDEFINED = ['roles/iam.securityReviewer', 'roles/browser', 'roles/iam.workloadIdentityPoolViewer'];

const SA_NAME = 'curious-monkey-reader', POOL = 'curious-monkey', PROVIDER = 'aws-scanner';   // pool and provider IDs are 4 to 32 characters
const AWS_ROLE_MAPPING = "google.subject=assertion.arn,attribute.aws_role=assertion.arn.contains('assumed-role') ? assertion.arn.extract('{account_arn}assumed-role/') + 'assumed-role/' + assertion.arn.extract('assumed-role/{role_name}/') : assertion.arn";

/** The AWS role behind this app's identity: arn:aws:sts::<acct>:assumed-role/<role>/<session> -> { account, role }. */
export function awsRoleOf(arn) {
  const m = String(arn || '').match(/^arn:aws[\w-]*:(?:sts|iam)::(\d{12}):(?:assumed-role|role)\/([^/]+)/);
  return m ? { account: m[1], role: m[2], sessionArn: `arn:aws:sts::${m[1]}:assumed-role/${m[2]}` } : null;
}

export function gcpSnippets({ scopeType, scopeId, mode = 'wif', home = 'my-identity-project', homeNumber = 'PROJECT_NUMBER', orgId = '', aws = null }) {
  const sa = `${SA_NAME}@${home}.iam.gserviceaccount.com`;
  const id = scopeId || (scopeType === 'project' ? 'PROJECT_ID' : scopeType === 'folder' ? 'FOLDER_ID' : 'ORG_ID');
  const steps = [];
  const custom = scopeType !== 'folder';
  const roleParent = scopeType === 'organization' ? `--organization=${id}` : `--project=${id}`;
  const roleName = scopeType === 'organization' ? `organizations/${id}/roles/curiousMonkeyReader` : `projects/${id}/roles/curiousMonkeyReader`;
  if (custom) {
    steps.push({ title: 'A read-only role with only what the scan needs', code:
`gcloud iam roles create curiousMonkeyReader ${roleParent} \\
  --title="Curious Monkey reader" --stage=GA \\
  --permissions=${GCP_READER_PERMISSIONS.join(',')}` });
  }
  steps.push({ title: 'A service account to hold it', code:
`gcloud services enable iam.googleapis.com cloudresourcemanager.googleapis.com sts.googleapis.com iamcredentials.googleapis.com --project=${home}
gcloud iam service-accounts create ${SA_NAME} --project=${home} --display-name="Curious Monkey reader"` });
  const bind = scopeType === 'organization' ? `gcloud organizations add-iam-policy-binding ${id}` : scopeType === 'folder' ? `gcloud resource-manager folders add-iam-policy-binding ${id}` : `gcloud projects add-iam-policy-binding ${id}`;
  steps.push({ title: `Grant it on the ${scopeType}`, code: (custom ? [roleName] : GCP_READER_PREDEFINED)
    .map((r) => `${bind} \\\n  --member="serviceAccount:${sa}" --role="${r}" --condition=None`).join('\n') });
  if (mode === 'wif') {
    const acct = aws?.account || 'AWS_ACCOUNT_ID', roleArn = aws?.sessionArn || `arn:aws:sts::${acct}:assumed-role/SCANNER_ROLE_NAME`;
    steps.push({ title: 'Let this app’s AWS role in, and nothing else', code:
`gcloud iam workload-identity-pools create ${POOL} --project=${home} --location=global --display-name="Curious Monkey"
gcloud iam workload-identity-pools providers create-aws ${PROVIDER} --project=${home} --location=global \\
  --workload-identity-pool=${POOL} --account-id=${acct} \\
  --attribute-mapping="${AWS_ROLE_MAPPING}" \\
  --attribute-condition="attribute.aws_role=='${roleArn}'"
gcloud iam service-accounts add-iam-policy-binding ${sa} --project=${home} \\
  --role=roles/iam.workloadIdentityUser \\
  --member="principalSet://iam.googleapis.com/projects/${homeNumber}/locations/global/workloadIdentityPools/${POOL}/attribute.aws_role/${roleArn}"` });
  } else {
    steps.push({ title: 'A key for it (prefer federation: a key works from anywhere until deleted)', code:
`gcloud iam service-accounts keys create curious-monkey-key.json --iam-account=${sa}` });
  }
  return { steps, serviceAccount: sa, pool: POOL, provider: PROVIDER, permissions: GCP_READER_PERMISSIONS, predefined: custom ? [] : GCP_READER_PREDEFINED, orgId };
}
