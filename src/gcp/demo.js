// A small invented Google Cloud organization for AWS_MODE=demo and the tests. Nothing here is real.
// It is wired to the demo AWS estate both ways: an AWS role signs in to Google Cloud through workload identity
// federation, and a Google service account is trusted by an AWS role (see demo/estate.js, lake-reader).
export const DEMO_ORG = { id: '100000000001', domain: 'acme.example' };
const ORG = `organizations/${DEMO_ORG.id}`;
export const DEMO_EXPORTER_ID = '104857600000000000001';     // the unique ID an AWS trust policy names

const FOLDERS = [
  { name: 'folders/200000000001', displayName: 'production', parent: ORG },
  { name: 'folders/200000000002', displayName: 'staging', parent: ORG },
  { name: 'folders/200000000003', displayName: 'shared', parent: ORG },
];
const PROJECTS = [
  { projectId: 'acme-payments-prod', number: '300000000001', name: 'Payments', parent: 'folders/200000000001', labels: { env: 'production' } },
  { projectId: 'acme-data-stg', number: '300000000002', name: 'Data platform (staging)', parent: 'folders/200000000002', labels: { env: 'staging' } },
  { projectId: 'acme-shared-ci', number: '300000000003', name: 'Shared CI and identity', parent: 'folders/200000000003', labels: { env: 'shared' } },
];
const sa = (name, project) => `${name}@${project}.iam.gserviceaccount.com`;
const POOL = (pool) => `principalSet://iam.googleapis.com/projects/300000000003/locations/global/workloadIdentityPools/${pool}`;
const daysAgo = (d) => new Date(Date.now() - d * 864e5).toISOString();

const SAS = {
  'acme-payments-prod': [
    { email: sa('payments-api', 'acme-payments-prod'), uniqueId: '104857600000000000010', displayName: 'Payments API (GKE)' },
    { email: '300000000001-compute@developer.gserviceaccount.com', uniqueId: '104857600000000000011', displayName: 'Compute Engine default service account' },
    { email: sa('bq-exporter', 'acme-payments-prod'), uniqueId: DEMO_EXPORTER_ID, displayName: 'Exports BigQuery tables to the AWS lake' },
  ],
  'acme-data-stg': [
    { email: sa('lake-sync', 'acme-data-stg'), uniqueId: '104857600000000000020', displayName: 'Syncs the AWS lake into GCS' },
    { email: sa('etl-runner', 'acme-data-stg'), uniqueId: '104857600000000000021', displayName: 'Dataflow ETL runner' },
    { email: sa('analytics', 'acme-data-stg'), uniqueId: '104857600000000000022', displayName: 'Analytics jobs' },
  ],
  'acme-shared-ci': [
    { email: sa('deployer', 'acme-shared-ci'), uniqueId: '104857600000000000030', displayName: 'GitHub Actions deployer' },
    { email: sa('terraform', 'acme-shared-ci'), uniqueId: '104857600000000000031', displayName: 'Terraform (legacy key)' },
    { email: sa('cm-reader', 'acme-shared-ci'), uniqueId: '104857600000000000032', displayName: 'Curious Monkey reader' },
  ],
};
const KEYS = {
  [sa('bq-exporter', 'acme-payments-prod')]: [{ name: 'k-bq-1', keyType: 'USER_MANAGED', validAfterTime: daysAgo(400), validBeforeTime: '9999-12-31T23:59:59Z' }],
  [sa('terraform', 'acme-shared-ci')]: [{ name: 'k-tf-1', keyType: 'USER_MANAGED', validAfterTime: daysAgo(900), validBeforeTime: '9999-12-31T23:59:59Z' },
    { name: 'k-tf-2', keyType: 'USER_MANAGED', validAfterTime: daysAgo(30), validBeforeTime: daysAgo(-60) }],
};
const B = (role, members, condition) => ({ role, members, ...(condition ? { condition } : {}) });

const POLICIES = {
  [ORG]: [
    B('roles/owner', ['user:alice@acme.example', `serviceAccount:${sa('terraform', 'acme-shared-ci')}`]),
    B('roles/iam.securityReviewer', ['group:secops@acme.example']),
    B('roles/browser', ['domain:acme.example']),
    B(`${ORG}/roles/curiousMonkeyReader`, [`serviceAccount:${sa('cm-reader', 'acme-shared-ci')}`]),
  ],
  'folders/200000000001': [
    B('roles/iam.serviceAccountUser', [`serviceAccount:${sa('deployer', 'acme-shared-ci')}`]),
    B('roles/run.admin', [`serviceAccount:${sa('deployer', 'acme-shared-ci')}`]),
  ],
  'folders/200000000002': [B('roles/editor', ['group:data-team@acme.example'])],
  'projects/acme-payments-prod': [
    B('roles/editor', ['serviceAccount:300000000001-compute@developer.gserviceaccount.com']),
    B('roles/cloudsql.client', [`serviceAccount:${sa('payments-api', 'acme-payments-prod')}`]),
    B('roles/secretmanager.secretAccessor', [`serviceAccount:${sa('payments-api', 'acme-payments-prod')}`]),
    B('roles/bigquery.dataViewer', [`serviceAccount:${sa('bq-exporter', 'acme-payments-prod')}`]),
    B('roles/storage.objectViewer', ['deleted:serviceAccount:old-reports@acme-payments-prod.iam.gserviceaccount.com?uid=104857600000000000099']),
  ],
  'projects/acme-data-stg': [
    B('roles/storage.admin', [`serviceAccount:${sa('lake-sync', 'acme-data-stg')}`]),
    B('roles/bigquery.dataEditor', [`serviceAccount:${sa('lake-sync', 'acme-data-stg')}`]),
    B('roles/dataflow.admin', [`serviceAccount:${sa('etl-runner', 'acme-data-stg')}`]),
    B('roles/bigquery.admin', [`serviceAccount:${sa('analytics', 'acme-data-stg')}`]),
    B('roles/viewer', ['user:vendor.dev@gmail.com']),
    // a federated identity granted roles directly, with no service account in between
    B('roles/storage.objectViewer', [`${POOL('aws-estate')}/attribute.aws_role/arn:aws:sts::222222222222:assumed-role/lake-reader`]),
  ],
  'projects/acme-shared-ci': [
    B('roles/artifactregistry.writer', [`serviceAccount:${sa('deployer', 'acme-shared-ci')}`]),
    B('roles/iam.workloadIdentityPoolAdmin', ['user:alice@acme.example']),
  ],
};
const SA_POLICIES = {
  [sa('payments-api', 'acme-payments-prod')]: [B('roles/iam.workloadIdentityUser', ['serviceAccount:acme-payments-prod.svc.id.goog[payments/api]'])],
  [sa('lake-sync', 'acme-data-stg')]: [B('roles/iam.workloadIdentityUser', [`${POOL('aws-estate')}/attribute.aws_role/arn:aws:sts::222222222222:assumed-role/data-etl`])],
  // any identity in AWS account 111111111111 can become this service account: the provider has no condition
  [sa('etl-runner', 'acme-data-stg')]: [B('roles/iam.workloadIdentityUser', [`${POOL('aws-legacy')}/*`])],
  [sa('analytics', 'acme-data-stg')]: [B('roles/iam.serviceAccountTokenCreator', ['group:data-team@acme.example'])],
  [sa('deployer', 'acme-shared-ci')]: [B('roles/iam.workloadIdentityUser', [`${POOL('github')}/attribute.repository/acme-corp/platform`])],
};
const WIF = {
  'acme-shared-ci': [
    { name: 'projects/300000000003/locations/global/workloadIdentityPools/aws-estate/providers/aws-222', displayName: 'AWS data-platform-stg', aws: { accountId: '222222222222' },
      attributeMapping: { 'google.subject': 'assertion.arn', 'attribute.aws_role': "assertion.arn.contains('assumed-role') ? assertion.arn.extract('{account_arn}assumed-role/') + 'assumed-role/' + assertion.arn.extract('assumed-role/{role_name}/') : assertion.arn" },
      attributeCondition: "attribute.aws_role.startsWith('arn:aws:sts::222222222222:assumed-role/')" },
    { name: 'projects/300000000003/locations/global/workloadIdentityPools/aws-legacy/providers/aws-111', displayName: 'AWS payments-prod (legacy)', aws: { accountId: '111111111111' },
      attributeMapping: { 'google.subject': 'assertion.arn' }, attributeCondition: '' },
    { name: 'projects/300000000003/locations/global/workloadIdentityPools/github/providers/github-actions', displayName: 'GitHub Actions', oidc: { issuerUri: 'https://token.actions.githubusercontent.com', allowedAudiences: [] },
      attributeMapping: { 'google.subject': 'assertion.sub', 'attribute.repository': 'assertion.repository' }, attributeCondition: "assertion.repository_owner == 'acme-corp'" },
  ],
};

// what the roles above allow, cut down to a believable size
const svc = (p, verbs) => verbs.map((v) => `${p}.${v}`);
const READ = (p, r = ['get', 'list']) => svc(p, r);
const PERMS = {
  'roles/cloudsql.client': ['cloudsql.instances.connect', 'cloudsql.instances.get'],
  'roles/secretmanager.secretAccessor': ['secretmanager.versions.access'],
  'roles/bigquery.dataViewer': [...READ('bigquery.datasets'), ...READ('bigquery.tables'), 'bigquery.tables.getData', 'bigquery.tables.export'],
  'roles/bigquery.dataEditor': [...READ('bigquery.datasets'), ...svc('bigquery.tables', ['get', 'list', 'create', 'update', 'delete', 'getData', 'updateData', 'export'])],
  'roles/bigquery.admin': [...svc('bigquery.datasets', ['get', 'list', 'create', 'update', 'delete', 'setIamPolicy']), ...svc('bigquery.tables', ['get', 'list', 'create', 'update', 'delete', 'getData', 'updateData', 'export', 'setIamPolicy']), ...svc('bigquery.jobs', ['create', 'list', 'get', 'delete'])],
  'roles/storage.admin': [...svc('storage.buckets', ['get', 'list', 'create', 'delete', 'update', 'setIamPolicy', 'getIamPolicy']), ...svc('storage.objects', ['get', 'list', 'create', 'delete', 'update'])],
  'roles/storage.objectViewer': ['storage.objects.get', 'storage.objects.list'],
  'roles/dataflow.admin': [...svc('dataflow.jobs', ['create', 'get', 'list', 'update', 'cancel']), 'storage.buckets.get', 'compute.machineTypes.get'],
  'roles/run.admin': [...svc('run.services', ['get', 'list', 'create', 'update', 'delete', 'setIamPolicy'])],
  'roles/iam.serviceAccountUser': ['iam.serviceAccounts.actAs', 'iam.serviceAccounts.get', 'iam.serviceAccounts.list'],
  'roles/iam.serviceAccountTokenCreator': ['iam.serviceAccounts.getAccessToken', 'iam.serviceAccounts.getOpenIdToken', 'iam.serviceAccounts.signBlob', 'iam.serviceAccounts.signJwt', 'iam.serviceAccounts.implicitDelegation'],
  'roles/iam.workloadIdentityUser': ['iam.serviceAccounts.getAccessToken', 'iam.serviceAccounts.getOpenIdToken'],
  'roles/iam.securityReviewer': ['resourcemanager.organizations.getIamPolicy', 'resourcemanager.folders.getIamPolicy', 'resourcemanager.projects.getIamPolicy', 'iam.roles.list', 'iam.roles.get', 'iam.serviceAccounts.getIamPolicy'],
  'roles/iam.workloadIdentityPoolAdmin': [...svc('iam.workloadIdentityPools', ['create', 'delete', 'get', 'list', 'update']), ...svc('iam.workloadIdentityPoolProviders', ['create', 'delete', 'get', 'list', 'update'])],
  'roles/artifactregistry.writer': ['artifactregistry.repositories.uploadArtifacts', 'artifactregistry.repositories.downloadArtifacts'],
  'roles/browser': ['resourcemanager.organizations.get', 'resourcemanager.folders.get', 'resourcemanager.folders.list', 'resourcemanager.projects.get', 'resourcemanager.projects.list'],
  [`${ORG}/roles/curiousMonkeyReader`]: ['resourcemanager.organizations.getIamPolicy', 'resourcemanager.folders.getIamPolicy', 'resourcemanager.projects.getIamPolicy', 'iam.serviceAccounts.list', 'iam.serviceAccountKeys.list', 'iam.roles.get'],
};
// basic roles do not include getting another service account's token: that needs Token Creator, even for Owner
const TOKEN = new Set(PERMS['roles/iam.serviceAccountTokenCreator']);
const ALL = [...new Set(Object.values(PERMS).flat())].filter((p) => !TOKEN.has(p));
const many = (prefix, n) => Array.from({ length: n }, (_, i) => `${prefix}.p${String(i).padStart(4, '0')}`);
PERMS['roles/viewer'] = [...ALL.filter((p) => /\.(get|list|getIamPolicy)$/.test(p)), ...many('viewer.read', 1800)];
PERMS['roles/editor'] = [...ALL.filter((p) => !/setIamPolicy|iam\.roles|organizations/.test(p)), ...many('editor.write', 5200)];
PERMS['roles/owner'] = [...ALL, 'resourcemanager.projects.setIamPolicy', 'resourcemanager.folders.setIamPolicy', 'resourcemanager.organizations.setIamPolicy', 'iam.serviceAccountKeys.create', ...many('owner.all', 6400)];
const TITLES = { 'roles/owner': 'Owner', 'roles/editor': 'Editor', 'roles/viewer': 'Viewer' };

export function demoGcpGateway() {
  const projects = PROJECTS.map((p) => ({ ...p, state: 'ACTIVE' }));
  const policy = (resource) => ({ version: 3, bindings: POLICIES[resource] || [] });
  return {
    async organization() { return { name: ORG, displayName: DEMO_ORG.domain }; },
    async folders() { return FOLDERS; },
    async projects() { return projects; },
    async project(id) { return projects.find((p) => p.projectId === id) || null; },
    async iamPolicy(resource) { return policy(resource); },
    async serviceAccounts(projectId) { return SAS[projectId] || []; },
    async serviceAccountKeys(email) { return KEYS[email] || []; },
    async serviceAccountPolicy(projectId, email) { return { version: 3, bindings: SA_POLICIES[email] || [] }; },
    async customRoles(parent) { return Object.keys(PERMS).filter((n) => n.startsWith(`${parent}/roles/`)).map((n) => ({ name: n, title: 'Curious Monkey reader', includedPermissions: PERMS[n], stage: 'GA' })); },
    async role(name) { return PERMS[name] ? { name, title: TITLES[name] || name.split('/').pop(), includedPermissions: PERMS[name], stage: 'GA' } : null; },
    async wifProviders(projectId) { return WIF[projectId] || []; },
    async whoami() { return { email: sa('cm-reader', 'acme-shared-ci') }; },
  };
}
