import { h, get, post, api, num, ago, fmtDate, toast, copy, field, confirmDialog, ApiError } from '../lib.js';
import { session, go } from '../main.js';

const REGIONS = ['us-east-1', 'us-east-2', 'us-west-2', 'eu-west-1', 'eu-central-1', 'ap-southeast-1', 'ap-southeast-2', 'ap-southeast-3', 'ap-northeast-1', 'ap-south-1'];
const STATUS = { connected: 'b-green', pending: 'b-medium', error: 'b-high' };
const SOURCE_LABEL = { 'event-history': 'Event History', s3: 'S3 trail' };
const MODE_LABEL = { assume_role: 'Assumes a role', access_key: 'IAM user key' };
const RE = {
  account: /^\d{12}$/, role: /^[\w+=,.@-]{1,64}$/, arn: /^arn:aws[\w-]*:(iam|sts)::\d{12}:[\w+=,.@/-]+$/,
  bucket: /^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$/, org: /^o-[a-z0-9]{10,32}$/, key: /^(AKIA|ASIA)[A-Z0-9]{12,20}$/,
};
const LOOKBACK = { 'event-history': [30, 60, 90], s3: [30, 90, 180, 365, 730] };
const VOLUMES = [[1000, 'about 1,000'], [10000, 'about 10,000'], [50000, 'about 50,000'], [100000, 'about 100,000'], [500000, 'about 500,000']];
const WORKER_CONCURRENCY = 2;

// ---------- shared helpers ----------
const input = (obj, key, props = {}) => {
  const el = h('input', { value: obj[key] ?? '', ...props });
  el.addEventListener('input', () => { obj[key] = el.value.trim(); el.removeAttribute('aria-invalid'); });
  return el;
};
function choices(name, options, current, onPick) {
  return h('div', { class: 'choices', role: 'radiogroup' }, options.map((o) => {
    const r = h('input', { type: 'radio', name, value: o.value, checked: o.value === current });
    r.addEventListener('change', () => onPick(o.value));
    return h('label', { class: 'choice' }, r, h('div', { class: 'choice-b' },
      h('div', { class: 'row' }, h('b', null, o.title), o.badge && h('span', { class: 'badge b-banana' }, o.badge)),
      o.text && h('p', { class: 'small muted' }, o.text),
      o.points && h('ul', { class: 'points' }, o.points.map(([kind, t]) => h('li', { class: kind }, t)))));
  }));
}
/** Show a message under the field with this data-f name. Returns false so validators can `return fail(...)`. */
function fail(root, f, msg) {
  const el = root.querySelector(`[data-f="${f}"]`);
  const holder = el?.closest('.field, fieldset') || root;
  holder.querySelector(':scope > .err')?.remove();
  holder.append(h('div', { class: 'err', role: 'alert' }, msg));
  if (el) { el.setAttribute('aria-invalid', 'true'); el.focus?.(); }
  return false;
}
const clearErrs = (root) => { root.querySelectorAll('.err').forEach((e) => e.remove()); root.querySelectorAll('[aria-invalid]').forEach((e) => e.removeAttribute('aria-invalid')); };
const dur = (s) => (s < 90 ? 'about a minute' : s < 3600 ? `about ${Math.round(s / 60)} min` : s < 48 * 3600 ? `about ${(Math.round(s / 1800) / 2).toString()} h` : `about ${Math.round(s / 86400)} days`);

/** First-scan time per region. Event History: 2 calls/s, 50 events/call. S3: file downloads, not request-limited. */
export function estimate({ perDay, lookback }) {
  const history = Math.max(lookback * 4, Math.ceil((perDay * lookback) / 50)) * 0.6;
  const filesPerDay = Math.min(288, Math.max(24, perDay / 20));
  const s3 = (filesPerDay * lookback) / 40 + (perDay * lookback) / 25000;
  return { history, s3 };
}

const blankModel = () => ({
  name: '', accountId: '', environment: 'production', regions: new Set(['us-east-1', 'ap-southeast-3']),
  eventSource: 'event-history', lookbackDays: 90, s3: { bucket: '', prefix: '', orgId: '', region: '' }, perDay: 10000,
  authMode: 'assume_role', baseIdentity: 'system', roleName: 'CuriousMonkeyScanner', trustPrincipal: '',
  keys: { accessKeyId: '', secretAccessKey: '', sessionToken: '' }, rebuildHistory: false,
});
function modelFrom(a) {
  return { ...blankModel(), name: a.name, accountId: a.account_id, environment: a.environment, regions: new Set(a.regions),
    eventSource: a.event_source, lookbackDays: a.lookback_days,
    s3: { bucket: a.s3_bucket || '', prefix: a.s3_prefix || '', orgId: a.s3_org_id || '', region: a.s3_region || '' },
    authMode: a.auth_mode, baseIdentity: a.base_identity, roleName: a.role_name || 'CuriousMonkeyScanner', trustPrincipal: a.trust_principal || '' };
}
const keysTyped = (m) => !!(m.keys.accessKeyId || m.keys.secretAccessKey);
function payload(m, { create }) {
  const p = {
    name: m.name, environment: m.environment, regions: [...m.regions], eventSource: m.eventSource, lookbackDays: Number(m.lookbackDays),
    s3: m.eventSource === 's3' ? { bucket: m.s3.bucket, prefix: m.s3.prefix || null, orgId: m.s3.orgId || null, region: m.s3.region || null } : null,
    authMode: m.authMode, baseIdentity: m.authMode === 'access_key' ? 'stored' : m.baseIdentity, roleName: m.roleName, trustPrincipal: m.trustPrincipal || null,
    credentials: keysTyped(m) ? { accessKeyId: m.keys.accessKeyId, secretAccessKey: m.keys.secretAccessKey, sessionToken: m.keys.sessionToken || null } : null,
  };
  if (create) p.accountId = m.accountId;
  else if (m.rebuildHistory) p.rebuildHistory = true;
  return p;
}

// ---------- validators (client side; the server checks again) ----------
function checkDetails(root, m, taken) {
  clearErrs(root);
  if (!m.name) return fail(root, 'name', 'Give the account a name.');
  if (!RE.account.test(m.accountId)) return fail(root, 'accountId', 'AWS account IDs are 12 digits, no dashes.');
  if (taken.has(m.accountId)) return fail(root, 'accountId', 'This AWS account is already connected.');
  if (!m.regions.size) return fail(root, 'regions', 'Pick at least one region.');
  return true;
}
function checkSource(root, m) {
  clearErrs(root);
  if (m.eventSource !== 's3') return true;
  if (!RE.bucket.test(m.s3.bucket)) return fail(root, 's3.bucket', 'Enter the bucket name only, e.g. kbi-org-cloudtrail (no s3:// and no path).');
  if (m.s3.orgId && !RE.org.test(m.s3.orgId)) return fail(root, 's3.orgId', 'Organization IDs look like o-abc123def4.');
  return true;
}
function checkKeys(root, m, { required }) {
  if (!keysTyped(m)) return required ? fail(root, 'credentials', 'Enter the access key ID and secret.') : true;
  if (!RE.key.test(m.keys.accessKeyId)) return fail(root, 'credentials', 'Access key IDs start with AKIA (long-lived) or ASIA (temporary).');
  if (m.keys.secretAccessKey.length < 30) return fail(root, 'secret', 'That secret is too short.');
  if (m.keys.accessKeyId.startsWith('ASIA') && !m.keys.sessionToken) return fail(root, 'token', 'Keys starting with ASIA are temporary and need their session token.');
  return true;
}
function checkAccess(root, m, { hasStored = false, keysInThisStep = true } = {}) {
  clearErrs(root);
  if (m.authMode === 'assume_role') {
    if (!RE.role.test(m.roleName)) return fail(root, 'roleName', 'Role names use letters, numbers and + = , . @ _ - (up to 64).');
    if (m.trustPrincipal && !RE.arn.test(m.trustPrincipal)) return fail(root, 'trustPrincipal', 'Use an IAM role or user ARN, e.g. arn:aws:iam::123456789012:role/curious-monkey-worker.');
    if (m.baseIdentity === 'stored') return checkKeys(root, m, { required: !hasStored });
    return true;
  }
  return keysInThisStep ? checkKeys(root, m, { required: !hasStored }) : true;
}

// ---------- sections ----------
function detailsSection(m, { lockId = false } = {}) {
  const env = h('select', { 'data-f': 'environment' }, ['production', 'staging', 'development', 'sandbox'].map((e) => h('option', { value: e, selected: e === m.environment }, e)));
  env.addEventListener('change', () => { m.environment = env.value; });
  const regions = h('div', { class: 'pill-bar', 'data-f': 'regions', tabindex: '-1' }, REGIONS.map((r) => {
    const b = h('button', { type: 'button', class: 'chip', 'aria-pressed': m.regions.has(r) }, r);
    b.addEventListener('click', () => { m.regions.has(r) ? m.regions.delete(r) : m.regions.add(r); b.setAttribute('aria-pressed', String(m.regions.has(r))); });
    return b;
  }));
  return h('div', { class: 'stack form' },
    field('Name', input(m, 'name', { 'data-f': 'name', placeholder: 'e.g. payments-prod', maxlength: '80' })),
    lockId ? field('AWS account ID', h('input', { value: m.accountId, disabled: true }), 'The account ID cannot change. Remove the account and connect it again to use another one.')
      : field('AWS account ID', input(m, 'accountId', { 'data-f': 'accountId', inputmode: 'numeric', maxlength: '12', placeholder: '123456789012' }), 'Twelve digits, no dashes.'),
    field('Environment', env),
    h('fieldset', null, h('legend', null, 'Regions to read CloudTrail from'), regions,
      h('span', { class: 'hint' }, 'CloudTrail keeps events per region. Keep us-east-1: IAM and sign-in events are recorded there. Add every region where this account runs workloads.')));
}

function sourceSection(m, rerender, { editing = false, original = null } = {}) {
  const lb = h('select', { 'data-f': 'lookbackDays' }, LOOKBACK[m.eventSource].map((d) => h('option', { value: d, selected: d === Number(m.lookbackDays) }, `${d} days`)));
  lb.addEventListener('change', () => { m.lookbackDays = Number(lb.value); rerender(); });
  const vol = h('select', { 'aria-label': 'Events per day in one region' }, VOLUMES.map(([v, l]) => h('option', { value: v, selected: v === m.perDay }, l)));
  vol.addEventListener('change', () => { m.perDay = Number(vol.value); rerender(); });
  const e = estimate({ perDay: m.perDay, lookback: Number(m.lookbackDays) });
  const capped = Number(m.lookbackDays) > 90;
  const eh = capped ? estimate({ perDay: m.perDay, lookback: 90 }).history : e.history;
  const waves = Math.ceil(m.regions.size / WORKER_CONCURRENCY) || 1;
  const s3Fields = m.eventSource === 's3' && h('div', { class: 'stack form sub' },
    field('S3 bucket the trail writes to', input(m.s3, 'bucket', { 'data-f': 's3.bucket', placeholder: 'kbi-org-cloudtrail' })),
    field('Key prefix (optional)', input(m.s3, 'prefix', { 'data-f': 's3.prefix', placeholder: 'leave empty if the trail has none' }), 'Only if the trail was set up with a prefix. Files then live under <prefix>/AWSLogs/…'),
    field('Organization ID (organization trails only)', input(m.s3, 'orgId', { 'data-f': 's3.orgId', placeholder: 'o-abc123def4' }), 'An organization trail writes to AWSLogs/<org-id>/<account-id>/…'),
    field('Bucket region (optional)', input(m.s3, 'region', { 'data-f': 's3.region', placeholder: 'e.g. ap-southeast-3' }), 'Defaults to the region being read. Set it when the bucket is somewhere else.'));
  const widened = editing && original && Number(m.lookbackDays) > original.lookback_days;
  return h('div', { class: 'stack form' },
    choices('source', [
      { value: 'event-history', title: 'CloudTrail Event History', badge: 'Works right away', points: [
        ['good', 'Nothing to set up. Every account has it.'],
        ['bad', 'At most 90 days back.'],
        ['bad', 'Management events only, so S3 object and DynamoDB item access stays unconfirmed.'],
        ['bad', 'Slow: AWS allows 2 requests a second, about 100 events a second per region.']] },
      { value: 's3', title: 'CloudTrail trail in S3', badge: 'Faster, longer history', points: [
        ['good', 'Fast: no request limit, usually minutes instead of hours.'],
        ['good', 'As far back as the bucket keeps files (up to 2 years here).'],
        ['good', 'Includes data events if the trail logs them, so object and item calls count as use.'],
        ['bad', 'Needs a trail delivering to S3 and read access to that bucket. Adds small S3 request charges.']] },
    ], m.eventSource, (v) => { m.eventSource = v; if (v === 'event-history' && m.lookbackDays > 90) m.lookbackDays = 90; rerender(); }),
    s3Fields,
    field('How far back to read', lb, m.eventSource === 's3' ? 'Only files that still exist in the bucket can be read.' : 'Event History cannot go further back than 90 days.'),
    widened && h('div', { class: 'alert ok' }, `The next scan backfills the extra ${Number(m.lookbackDays) - original.lookback_days} days. History already stored is kept and not read again.`),
    h('section', { class: 'estimate' },
      h('div', { class: 'row' }, h('b', null, 'First scan estimate'), h('span', { class: 'small muted' }, 'for'), vol, h('span', { class: 'small muted' }, 'CloudTrail events a day in a region')),
      h('table', null, h('thead', null, h('tr', null, h('th', null, 'Source'), h('th', null, 'Per region'), h('th', null, `All ${m.regions.size} region${m.regions.size === 1 ? '' : 's'}`))),
        h('tbody', null,
          h('tr', { class: m.eventSource === 'event-history' ? 'picked' : null }, h('td', null, 'Event History', capped && h('span', { class: 'tiny muted' }, ' (90 days only)')), h('td', null, dur(eh)), h('td', null, dur(eh * waves))),
          h('tr', { class: m.eventSource === 's3' ? 'picked' : null }, h('td', null, 'S3 trail'), h('td', null, dur(e.s3)), h('td', null, dur(e.s3 * waves))))),
      h('p', { class: 'tiny muted' }, `Rough figures for ${m.lookbackDays} days. Event History time is set by the AWS limit of 2 requests a second (50 events each), split into 6-hour slices. Regions run side by side, ${WORKER_CONCURRENCY} at a time per worker. Daily scans afterwards only read the new hours and take seconds. Scan activity shows a live estimate while it runs.`)),
    editing && h('label', { class: 'check-row' }, (() => { const c = h('input', { type: 'checkbox', checked: m.rebuildHistory }); c.addEventListener('change', () => { m.rebuildHistory = c.checked; }); return c; })(),
      h('span', null, h('b', null, 'Rebuild stored history. '), h('span', { class: 'small muted' }, 'Deletes the stored activity for this account and reads it again on the next scan. Only needed if stored history is wrong; switching source or widening the window does not need it.'))));
}

function identityBox(identity) {
  if (!identity) return null;
  if (identity.awsMode === 'demo') return h('div', { class: 'alert ok' }, 'Demo mode: the worker makes no AWS calls, so any setting here works.');
  const w = identity.worker;
  if (!w) return h('div', { class: 'alert warn' }, 'No worker has reported its identity yet. Start a worker and reload this page to see which credentials it has.');
  if (w.error) return h('div', { class: 'alert bad' }, h('b', null, 'The worker has no usable AWS credentials. '), w.error, ' Use stored keys below, or give the worker a role or keys in .env.');
  const human = /AWSReservedSSO_|:user\/(?!curious)/i.test(w.arn || '');
  return h('div', { class: `alert ${human ? 'warn' : 'ok'}` },
    h('div', null, 'The worker runs as ', h('code', null, w.arn), w.alive ? '' : ' (last seen worker, not running now)', '.'),
    human && h('div', null, 'That looks like a person’s credentials. The scanner role would trust that person, and SSO sessions expire. A worker role or a dedicated user is safer.'));
}

function keyFields(m, { hint, hasStored }) {
  return h('div', { class: 'stack form sub' },
    hasStored && h('p', { class: 'small muted' }, `Saved key: ${hint}. Leave these empty to keep it.`),
    field('Access key ID', input(m.keys, 'accessKeyId', { 'data-f': 'credentials', autocomplete: 'off', spellcheck: 'false', placeholder: 'AKIA…' })),
    field('Secret access key', input(m.keys, 'secretAccessKey', { 'data-f': 'secret', type: 'password', autocomplete: 'new-password' })),
    field('Session token (temporary keys only)', input(m.keys, 'sessionToken', { 'data-f': 'token', type: 'password', autocomplete: 'off' }),
      'Only for keys starting with ASIA. Those expire within hours, after which scans fail until you paste new ones, so they suit a quick test, not daily scans.'),
    h('p', { class: 'tiny muted' }, 'Keys are encrypted before they are stored and are never shown again.'));
}

function accessSection(m, identity, rerender, { editing = false, account = null, keysHere = false } = {}) {
  const hasStored = !!account?.has_credentials;
  if (!m.trustPrincipal && m.baseIdentity === 'system') m.trustPrincipal = identity?.worker?.principal || identity?.configuredPrincipal || '';
  const tp = input(m, 'trustPrincipal', { 'data-f': 'trustPrincipal', placeholder: 'arn:aws:iam::123456789012:role/curious-monkey-worker' });
  return h('div', { class: 'stack form' },
    choices('mode', [
      { value: 'assume_role', title: 'Assume a scanner role', badge: 'Recommended', text: 'A read-only role in this account, assumed by the worker with your workspace ExternalId. Short-lived credentials, nothing long-lived stored per account.' },
      { value: 'access_key', title: 'IAM user access key', text: 'A dedicated read-only IAM user in this account. Its access key is stored encrypted and used directly. Simpler, but the key is long-lived: rotate it.' },
    ], m.authMode, (v) => { m.authMode = v; rerender(); }),
    m.authMode === 'assume_role' && h('div', { class: 'stack form' },
      h('fieldset', null, h('legend', null, 'Which credentials assume the role'),
        choices('base', [
          { value: 'system', title: 'The worker’s own credentials', text: 'Whatever the worker already has: its instance, task or pod role, or AWS keys in its .env.' },
          { value: 'stored', title: 'An access key saved on this account', text: 'Use this when the worker has no AWS identity of its own, or this account needs a different one.' },
        ], m.baseIdentity, (v) => { m.baseIdentity = v; if (v === 'stored' && m.trustPrincipal === (identity?.worker?.principal || '')) m.trustPrincipal = ''; rerender(); })),
      m.baseIdentity === 'system' ? identityBox(identity) : keyFields(m, { hint: account?.credentials_hint, hasStored }),
      field('Scanner role name', input(m, 'roleName', { 'data-f': 'roleName' }), 'The role the template creates in this account.'),
      field('Who the role trusts', tp, m.baseIdentity === 'system'
        ? 'Filled in from the worker’s identity. A session ARN cannot go in a trust policy, so the role behind it is used.'
        : 'The ARN of the IAM user (or role) that owns the key above. Used only to write the template.')),
    m.authMode === 'access_key' && (keysHere ? keyFields(m, { hint: account?.credentials_hint, hasStored })
      : h('p', { class: 'small muted' }, 'You create the user from the template on the next step, then paste its access key there.')));
}

function snippetsBox(m, snip) {
  const st = { tab: 'terraform' };
  const body = h('div');
  const draw = () => {
    const text = st.tab === 'terraform' ? snip.terraform : snip.cloudformation;
    body.replaceChildren(h('div', { class: 'tabs', role: 'tablist' }, [['terraform', 'Terraform'], ['cloudformation', 'CloudFormation']].map(([k, l]) =>
      h('button', { role: 'tab', 'aria-selected': st.tab === k, onClick: () => { st.tab = k; draw(); } }, l))),
      h('pre', null, text), h('div', { class: 'row' }, h('button', { class: 'btn sm', onClick: () => copy(text) }, 'Copy')));
  };
  draw();
  const reader = m.authMode === 'assume_role' ? `arn:aws:iam::${m.accountId}:role/${m.roleName}` : `arn:aws:iam::${m.accountId}:user/${snip.userName || 'curious-monkey-scanner'}`;
  const prefix = m.s3.prefix ? `${m.s3.prefix.replace(/^\/+|\/+$/g, '')}/` : '';
  const bucketPolicy = m.eventSource === 's3' && { Version: '2012-10-17', Statement: [
    { Sid: 'CuriousMonkeyList', Effect: 'Allow', Principal: { AWS: reader }, Action: ['s3:ListBucket', 's3:GetBucketLocation'], Resource: `arn:aws:s3:::${m.s3.bucket}` },
    { Sid: 'CuriousMonkeyRead', Effect: 'Allow', Principal: { AWS: reader }, Action: 's3:GetObject', Resource: `arn:aws:s3:::${m.s3.bucket}/${prefix}AWSLogs/*` }] };
  const json = (o) => JSON.stringify(o, null, 2);
  return h('div', { class: 'stack' }, body,
    h('p', { class: 'small' }, m.eventSource === 's3'
      ? 'Read-only on IAM and CloudTrail, plus the trail’s log files in S3. Every other S3 object, DynamoDB item, secret and parameter is explicitly denied, and KMS decrypt is only allowed for CloudTrail-encrypted files.'
      : 'Read-only on IAM and CloudTrail. S3 objects, DynamoDB items, secrets, parameters, KMS decrypt and Lambda invoke are explicitly denied, so even a leaked credential cannot read your data.'),
    m.authMode === 'assume_role' && h('details', null, h('summary', { class: 'btn sm' }, 'What the worker’s credentials need'),
      h('div', { class: 'stack' }, h('p', { class: 'small' }, 'Attach this to the identity that assumes the role. It grants nothing else.'), h('pre', null, json(snip.basePolicy)),
        h('p', { class: 'small muted' }, 'ExternalId for this workspace: ', h('code', null, snip.externalId)))),
    bucketPolicy && h('details', null, h('summary', { class: 'btn sm' }, 'Bucket in another account (e.g. log archive)?'),
      h('div', { class: 'stack' }, h('p', { class: 'small' }, `Add this to the bucket policy of ${m.s3.bucket}. If the trail uses a KMS key, its key policy must also let ${reader} decrypt.`), h('pre', null, json(bucketPolicy)))));
}

const snippetQuery = (m) => new URLSearchParams(Object.entries({ mode: m.authMode, roleName: m.roleName, principal: m.trustPrincipal || '',
  bucket: m.eventSource === 's3' ? m.s3.bucket : '', prefix: m.eventSource === 's3' ? m.s3.prefix : '' }).filter(([, v]) => v));

// ---------- list ----------
export async function accountsPage(ctx) {
  const { items } = await get('/accounts');
  ctx.setCrumbs('Accounts');
  const can = (p) => session.user.permissions.includes(p);
  return h('div', { class: 'stack-lg' },
    h('header', { class: 'head' }, h('div', null, h('div', { class: 'eyebrow' }, 'ACCOUNTS'), h('h1', null, 'Cloud accounts'), h('p', { class: 'muted' }, 'Each account is read with a read-only identity that can see IAM and CloudTrail, and is explicitly denied your data.')),
      can('accounts') && h('a', { class: 'btn primary', href: '#/accounts/new' }, 'Connect an AWS account')),
    items.length ? items.map((a) => accountCard(a, ctx, can)) : h('div', { class: 'card empty' }, 'No accounts connected yet.'));
}

function accountCard(a, ctx, can) {
  const dataBox = h('div', { class: 'card-b' });
  const loadData = async () => {
    const r = await get(`/accounts/${a.id}/data-events`);
    dataBox.replaceChildren(r.items.length ? h('div', { class: 'stack' }, h('div', { class: 'scroll' }, h('table', null, h('thead', null, h('tr', null, h('th', null, 'Source'), h('th', null, 'Resource type'), h('th', null, 'Covers'), h('th', null, 'Read/write'), h('th', null, 'Used as evidence'))),
      h('tbody', null, r.items.map((x) => h('tr', null, h('td', null, x.source_name, h('div', { class: 'tiny muted' }, x.source_type)), h('td', { class: 'mono small' }, x.resource_type), h('td', { class: 'mono small' }, x.arn_patterns.join(', ')), h('td', null, x.read_write),
        h('td', null, x.readable ? h('span', { class: 'badge b-green' }, 'yes') : h('span', { class: 'muted' }, 'no'))))))),
      h('p', { class: 'small muted' }, r.note)) : h('p', { class: 'muted' }, 'No data event logging found. Without it, object-level and item-level permissions can never be verified.'));
  };
  const det = h('details', null, h('summary', { class: 'btn sm' }, 'Buckets and resources with data events'), dataBox);
  det.addEventListener('toggle', () => { if (det.open) loadData(); });
  return h('section', { class: 'card' },
    h('div', { class: 'card-h' }, h('div', { class: 'row' }, h('h2', null, a.name), h('span', { class: `badge ${STATUS[a.status]}` }, a.status), h('span', { class: 'small muted mono' }, `${a.account_id} · ${a.environment}`)),
      h('div', { class: 'row' }, can('scan') && h('button', { class: 'btn sm', onClick: async () => { try { await post(`/accounts/${a.id}/scan`); toast('Scan queued'); go('#/scans'); } catch (x) { toast(x.message, true); } } }, 'Scan now'),
        can('accounts') && a.status !== 'connected' && h('button', { class: 'btn sm primary', onClick: async () => { try { await post(`/accounts/${a.id}/verify`); toast('Checking the connection. Progress is on Scan activity.'); go('#/scans'); } catch (x) { toast(x.message, true); } } }, 'Verify connection'),
        h('a', { class: 'btn sm', href: `#/?account=${a.id}` }, 'Radar'),
        h('a', { class: 'btn sm', href: `#/accounts/${a.id}/unidentified` }, 'Unidentified calls'),
        can('accounts') && h('a', { class: 'btn sm', href: `#/accounts/${a.id}/edit` }, 'Edit'),
        can('accounts') && h('button', { class: 'btn sm danger', onClick: async () => { if (await confirmDialog({ title: `Remove ${a.name}?`, message: 'This deletes the account from Curious Monkey together with its stored scan history, findings and drafts. Nothing changes in AWS.', confirmLabel: 'Remove account', danger: true })) { await api('DELETE', `/accounts/${a.id}`); ctx.reload(); } } }, 'Remove'))),
    a.status === 'error' && h('div', { class: 'card-b' }, h('div', { class: 'alert bad' }, a.status_detail?.message || 'The account could not be reached.')),
    h('div', { class: 'card-b stack' },
      a.history && historyBars(a.history),
      h('dl', { class: 'kv' },
        h('dt', null, 'Reads from'), h('dd', null, SOURCE_LABEL[a.event_source], a.event_source === 's3' && h('span', { class: 'mono small' }, ` s3://${a.s3_bucket}${a.s3_prefix ? `/${a.s3_prefix}` : ''}`), h('span', { class: 'muted' }, ` · ${a.lookback_days} days`)),
        h('dt', null, 'Access'), h('dd', null, MODE_LABEL[a.auth_mode], a.auth_mode === 'assume_role' && h('span', { class: 'mono small' }, ` ${a.role_arn}`),
          h('span', { class: 'muted' }, a.auth_mode === 'access_key' ? ` · key ${a.credentials_hint || 'missing'}` : a.base_identity === 'stored' ? ` · from stored key ${a.credentials_hint || 'missing'}` : ' · from the worker’s credentials')),
        h('dt', null, 'Regions'), h('dd', null, a.regions.join(', ')),
        h('dt', null, 'Roles found'), h('dd', null, num(a.roles)), h('dt', null, 'Last scan'), h('dd', null, a.last_scan_at ? `${fmtDate(a.last_scan_at)} (${ago(a.last_scan_at)})` : 'never')),
      a.checkpoints.length > 0 && h('div', null, h('h3', null, 'Stored history'), h('p', { class: 'small muted' }, 'Each daily scan continues from the newest stored event. It never re-reads history that is already saved.'),
        h('div', { class: 'scroll' }, h('table', null, h('thead', null, h('tr', null, h('th', null, 'Region'), h('th', null, 'History starts'), h('th', null, 'Stored up to'), h('th', null, 'Events read'), h('th', null, 'Gap'))),
          h('tbody', null, a.checkpoints.map((c) => h('tr', null, h('td', { class: 'mono small' }, c.region), h('td', { class: 'small' }, fmtDate(c.first)), h('td', { class: 'small' }, fmtDate(c.last)), h('td', null, num(c.events)),
            h('td', null, c.gap ? h('span', { class: 'badge b-medium', title: 'The worker was down longer than the history lasts, so some days were never read.' }, 'gap') : 'none'))))))),
      det));
}

/** How far back each region has been read, and whether it has reached the present. */
function historyBars(hist) {
  if (!hist.regions?.length) return h('div', { class: 'provisional' }, h('b', null, 'HISTORY NOT READ YET'), h('span', null, 'Results appear as soon as the first slices are read.'));
  return h('div', { class: 'stack' },
    h('div', { class: 'row' }, h('span', { class: 'eyebrow grow' }, 'CLOUDTRAIL HISTORY READ'),
      h('span', { class: `state ${hist.complete ? '' : 'prov'}` }, hist.complete ? 'Complete · results final' : `${hist.progress}% · results provisional`)),
    hist.regions.map((r) => {
      const bar = h('i', { class: r.complete ? 'done' : null }); bar.style.width = `${Math.max(1, r.progress)}%`;
      return h('div', { class: 'history-row' }, h('span', { class: 'mono' }, r.region), h('span', { class: 'track', role: 'img', 'aria-label': `${r.region}: ${r.progress}% read` }, bar),
        h('span', { class: 'tiny muted' }, r.complete ? 'complete' : r.first ? `${r.progress}% · back to ${new Date(r.first).toLocaleDateString('en-GB', { day: '2-digit', month: 'short' })}` : 'not started'));
    }));
}

// ---------- wizard: nothing is saved until the last step ----------
const STEPS = ['Account', 'CloudTrail source', 'Access', 'Deploy and connect'];
const STEP_OF = { name: 1, accountId: 1, environment: 1, regions: 1, eventSource: 2, lookbackDays: 2, 's3.bucket': 2, s3: 2, roleName: 3, trustPrincipal: 3, baseIdentity: 3, authMode: 3 };

export async function newAccountPage() {
  const [{ items }, identity] = await Promise.all([get('/accounts'), get('/onboarding/identity').catch(() => null)]);
  const taken = new Set(items.map((a) => a.account_id));
  const m = blankModel();
  const st = { step: 1, snip: null, pendingError: null };
  const body = h('div', { class: 'stack-lg' });

  const stepper = () => h('ol', { class: 'steps' }, STEPS.map((l, i) => {
    const n = i + 1, done = st.step > n;
    const label = h('span', { class: st.step === n ? 'name' : 'muted' }, l);
    return h('li', { 'aria-current': st.step === n ? 'step' : null },
      h('span', { class: `badge ${done ? 'b-green' : st.step === n ? 'b-banana' : 'b-neutral'}` }, done ? '✓' : n),
      done ? h('button', { type: 'button', class: 'link-btn', onClick: () => { st.step = n; render(); } }, l) : label);
  }));
  const nav = (card, { next, nextLabel = 'Next', back = true }) => h('div', { class: 'wizard-nav' },
    back && h('button', { type: 'button', class: 'btn', onClick: () => { st.step--; render(); } }, 'Back'),
    h('span', { class: 'grow' }),
    h('button', { type: 'button', class: 'btn primary', onClick: next }, nextLabel));

  function render() {
    let card;
    const rerender = () => render();
    if (st.step === 1) {
      card = h('section', { class: 'card' }, h('div', { class: 'card-b stack form' }, detailsSection(m)));
      card.append(h('div', { class: 'card-f' }, nav(card, { back: false, next: () => { if (checkDetails(card, m, taken)) { st.step = 2; render(); } } })));
    } else if (st.step === 2) {
      card = h('section', { class: 'card' }, h('div', { class: 'card-b stack form' }, sourceSection(m, rerender)));
      card.append(h('div', { class: 'card-f' }, nav(card, { next: () => { if (checkSource(card, m)) { st.step = 3; render(); } } })));
    } else if (st.step === 3) {
      card = h('section', { class: 'card' }, h('div', { class: 'card-b stack form' }, accessSection(m, identity, rerender)));
      card.append(h('div', { class: 'card-f' }, nav(card, { next: () => { if (checkAccess(card, m, { keysInThisStep: false })) { st.step = 4; st.snip = null; render(); } } })));
    } else {
      card = step4();
    }
    body.replaceChildren(stepper(), card);
    if (st.pendingError) { const [f, msg] = st.pendingError; st.pendingError = null; fail(card, f, msg); }
    card.querySelector('input:not([type=radio]):not([disabled]), select')?.focus({ preventScroll: true });
  }

  function step4() {
    const card = h('section', { class: 'card' });
    const snipBox = h('div', null, h('span', { class: 'spin' }), ' Preparing the template…');
    const load = async () => { try { st.snip = st.snip || await get(`/onboarding/snippets?${snippetQuery(m)}`); snipBox.replaceChildren(snippetsBox(m, st.snip)); } catch (e) { snipBox.replaceChildren(h('div', { class: 'alert bad' }, e.message)); } };
    load();
    const edit = (n) => h('button', { type: 'button', class: 'link-btn small', onClick: () => { st.step = n; render(); } }, 'Change');
    const connect = h('button', { type: 'button', class: 'btn primary' }, 'Connect and start first scan');
    connect.addEventListener('click', async () => {
      clearErrs(card);
      if (m.authMode === 'access_key' && !checkKeys(card, m, { required: true })) return;
      connect.disabled = true; connect.textContent = 'Connecting…';
      try {
        const acct = await post('/accounts', payload(m, { create: true }));
        await post(`/accounts/${acct.id}/verify`);
        toast(`${acct.name} added. The first step checks access; if it fails, the reason shows here and on the account.`);
        go('#/scans');
      } catch (x) {
        connect.disabled = false; connect.textContent = 'Connect and start first scan';
        const f = x instanceof ApiError && x.field;
        const target = f === 'credentials' ? (m.authMode === 'access_key' ? 4 : 3) : STEP_OF[f?.split('.')[0] === 's3' ? 's3.bucket' : f];
        if (target && target !== 4) { st.pendingError = [f, x.message]; st.step = target; render(); return; }
        if (f) fail(card, f, x.message); else card.querySelector('.card-f').prepend(h('div', { class: 'err', role: 'alert' }, x.message));
      }
    });
    card.append(
      h('div', { class: 'card-h' }, h('h2', null, `Deploy in account ${m.accountId}`)),
      h('div', { class: 'card-b stack form' },
        h('dl', { class: 'kv summary' },
          h('dt', null, 'Account'), h('dd', null, `${m.name} · ${m.accountId} · ${m.environment} · ${[...m.regions].join(', ')} `, edit(1)),
          h('dt', null, 'Reads from'), h('dd', null, `${SOURCE_LABEL[m.eventSource]}${m.eventSource === 's3' ? ` s3://${m.s3.bucket}${m.s3.prefix ? `/${m.s3.prefix}` : ''}` : ''} · ${m.lookbackDays} days `, edit(2)),
          h('dt', null, 'Access'), h('dd', null, m.authMode === 'assume_role' ? `Assumes ${m.roleName} with ${m.baseIdentity === 'system' ? 'the worker’s credentials' : 'a stored key'} ` : 'IAM user access key ', edit(3))),
        snipBox,
        m.authMode === 'access_key' && h('div', { class: 'stack' }, h('h3', null, 'Paste the scanner user’s access key'),
          h('p', { class: 'small muted' }, 'Create it after applying the template: aws iam create-access-key --user-name curious-monkey-scanner'),
          keyFields(m, { hasStored: false }))),
      h('div', { class: 'card-f' }, h('div', { class: 'wizard-nav' },
        h('button', { type: 'button', class: 'btn', onClick: () => { st.step = 3; render(); } }, 'Back'), h('span', { class: 'grow' }),
        h('span', { class: 'small muted' }, 'Nothing is saved until you connect.'), connect)));
    return card;
  }

  render();
  return h('div', { class: 'stack-lg' }, h('header', { class: 'head' }, h('div', null, h('div', { class: 'crumbs' }, h('a', { href: '#/accounts' }, 'Cloud accounts'), ' / New'), h('h1', null, 'Connect an AWS account'))), body);
}

// ---------- edit ----------
export async function editAccountPage(ctx, id) {
  const [a, identity] = await Promise.all([get(`/accounts/${id}`), get('/onboarding/identity').catch(() => null)]);
  const m = modelFrom(a);
  const root = h('div', { class: 'stack-lg' });
  const sections = h('div', { class: 'stack-lg' });
  const tpl = h('div', { class: 'card-b' });
  const tplDet = h('details', null, h('summary', { class: 'btn sm' }, 'Show the template for these settings'), tpl);
  tplDet.addEventListener('toggle', async () => { if (tplDet.open) { tpl.replaceChildren(h('span', { class: 'spin' })); try { tpl.replaceChildren(snippetsBox(m, await get(`/onboarding/snippets?${snippetQuery(m)}`))); } catch (e) { tpl.replaceChildren(h('div', { class: 'alert bad' }, e.message)); } } });

  const draw = () => {
    const card = (title, sub, content) => h('section', { class: 'card' }, h('div', { class: 'card-h' }, h('div', null, h('h2', null, title), sub && h('p', { class: 'small muted' }, sub))), h('div', { class: 'card-b stack form' }, content));
    sections.replaceChildren(
      card('Account', null, detailsSection(m, { lockId: true })),
      card('CloudTrail source', 'Switching source keeps the stored history and continues from where it stopped.', sourceSection(m, draw, { editing: true, original: a })),
      card('Access', 'Changing access sets the account to pending until it is verified again.', accessSection(m, identity, draw, { editing: true, account: a, keysHere: true })),
      h('section', { class: 'card' }, h('div', { class: 'card-h' }, h('div', null, h('h2', null, 'Template'), h('p', { class: 'small muted' }, 'Re-apply it in the account if you changed the source, role name or trust.'))), h('div', { class: 'card-b' }, tplDet)));
  };
  draw();
  const save = h('button', { type: 'button', class: 'btn primary' }, 'Save changes');
  const formErr = h('div', { class: 'err', role: 'alert' });
  save.addEventListener('click', async () => {
    formErr.textContent = '';
    const ok = checkDetails(sections, m, new Set()) && checkSource(sections, m) && checkAccess(sections, m, { hasStored: a.has_credentials });
    if (!ok) return;
    if (m.rebuildHistory && !await confirmDialog({ title: 'Rebuild stored history?', message: `All stored activity for ${a.name} is deleted and read again from CloudTrail on the next scan. With Event History only the last 90 days can be read back.`, confirmLabel: 'Rebuild history', danger: true })) return;
    save.disabled = true;
    try {
      const out = await api('PATCH', `/accounts/${a.id}`, payload(m, { create: false }));
      if (out.accessChanged || m.rebuildHistory) {
        const verify = await confirmDialog({ title: 'Saved. Verify now?', message: 'Access or source changed. Verifying runs a scan with the new settings, so you see at once whether they work.', confirmLabel: 'Verify and scan' });
        if (verify) { await post(`/accounts/${a.id}/verify`).catch((x) => toast(x.message, true)); go('#/scans'); return; }
      }
      toast('Saved'); go('#/accounts');
    } catch (x) {
      save.disabled = false;
      if (x instanceof ApiError && x.field) fail(sections, x.field, x.message); else formErr.textContent = x.message;
    }
  });
  root.append(h('header', { class: 'head' }, h('div', null, h('div', { class: 'crumbs' }, h('a', { href: '#/accounts' }, 'Cloud accounts'), ` / ${a.name}`), h('h1', null, `Edit ${a.name}`))),
    sections, h('div', { class: 'wizard-nav sticky' }, h('a', { class: 'btn', href: '#/accounts' }, 'Cancel'), h('span', { class: 'grow' }), formErr, save));
  return root;
}

// ---------- event coverage ----------
export const pct = (n, d) => (d ? `${n / d < 0.001 && n > 0 ? '<0.1' : Math.round((n / d) * 1000) / 10}%` : '–');
export const COVERAGE_ROWS = [
  ['assume_events', 'Role sessions started', 'AssumeRole calls into a role in this account. They tell who used each role.'],
  ['role_calls', 'API calls made by a role', 'Counted as activity for that role.'],
  ['recovered_role', '…tied to the role by name', 'The event had no sessionIssuer, so the role was found from the session ARN.', true],
  ['no_permission', '…needing no IAM permission', 'Console sign-in and similar. Nothing to grant.', true],
  ['unmapped', '…with an unmapped event name', 'The event name is not an IAM action name. Its service stays unconfirmed until mapped below.', true],
  ['no_resources', '…that named no resource', 'Resources of those actions are never narrowed to the ones seen.', true],
  ['not_role', 'Not made by a role', 'IAM users, root and AWS services. Out of scope: only roles are analyzed.'],
  ['other_role', 'Made by a role this account does not have', 'A deleted role, or a role in another account.'],
];

