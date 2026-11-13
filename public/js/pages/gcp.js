// Google Cloud pages: connecting an organization, folder or project; the Identities page's Google Cloud list; one identity.
// Permissions only for now: who can do what, and where they can come from. No audit logs are read.
import { h, get, post, api, num, ago, fmtDate, toast, copy, riskBadge, confirmDialog, loadEnvironments, envName, tile, pager, searchBox, syncUrl, urlSet } from '../lib.js';
import { session, go } from '../main.js';
import { identityShell, section } from './identity.js';

const SEV = { high: 'b-high', medium: 'b-medium', low: 'b-low', info: 'b-neutral' };
const VIA = { key: 'Key', wif: 'Federation', gke: 'GKE workload', token: 'Impersonation', actAs: 'Act as', 'key-create': 'Can mint keys' };
const VIA_HELP = {
  key: 'A user-managed key: works from anywhere until it is deleted.',
  wif: 'A federated identity (AWS, GitHub…) exchanged for this service account’s token.',
  gke: 'A Kubernetes service account running as it through GKE workload identity.',
  token: 'Can get its access token or sign as it (Token Creator and similar).',
  actAs: 'Can attach it to something they deploy (VMs, Cloud Run, Dataflow…) and run code as it.',
  'key-create': 'Can create a key for it and use that.',
};
const can = (p) => session.user.permissions.includes(p);
const shortRole = (r) => String(r).replace(/^roles\//, '').replace(/^(projects|organizations)\/[^/]+\/roles\//, 'custom: ');
const where = (r) => (r.resourceType === 'organization' ? 'Organization' : r.resourceType === 'folder' ? `Folder ${r.resource.split('/')[1]}` : r.resourceType === 'project' ? `Project ${r.project}` : 'This service account');
const nameOf = (x) => x.email || x.origin?.label || x.member;

/** AWS | Google Cloud, above the Roles and Accounts pages. */
export const cloudTabs = (current, base = '#/accounts') => h('div', { class: 'tabs cloud-tabs', role: 'tablist', 'aria-label': 'Cloud' },
  [['aws', 'AWS', base], ['gcp', 'Google Cloud', `${base}?cloud=gcp`]].map(([k, l, href]) => h('a', { role: 'tab', href, 'aria-selected': current === k ? 'true' : 'false' }, l)));
export const GCP_CONNECTIONS = '#/accounts?cloud=gcp';

// ---------------------------------------------------------------- Accounts page: Google Cloud connections
export async function gcpSection(ctx) {
  let r;
  try { r = await get('/gcp/connections'); } catch { return null; }          // members limited to accounts: not shown
  await loadEnvironments();
  return h('div', { class: 'stack-lg' },
    h('header', { class: 'head' }, h('div', null, h('div', { class: 'eyebrow' }, 'ACCOUNTS · GOOGLE CLOUD'), h('h1', null, 'Google Cloud organizations and projects'),
      h('p', { class: 'muted' }, 'Read-only: IAM policies, service accounts, keys and workload identity federation. Who can do what and where they can come from; audit logs are not read yet.')),
    can('accounts') && h('a', { class: 'btn primary', href: '#/gcp/new' }, 'Connect Google Cloud')),
    r.items.length ? r.items.map((c) => connectionCard(c, ctx)) : h('div', { class: 'card empty' }, 'No Google Cloud connected yet.'));
}

function connectionCard(c, ctx) {
  const STATUS = { connected: 'b-green', pending: 'b-neutral', error: 'b-high' };
  const projBox = h('div', { class: 'card-b' });
  const loadProjects = async () => {
    const { items } = await get('/gcp/projects');
    const envList = await loadEnvironments();
    projBox.replaceChildren(h('div', { class: 'scroll' }, h('table', { class: 'small' }, h('thead', null, h('tr', null, h('th', null, 'Project'), h('th', null, 'Under'), h('th', null, 'Environment'))),
      h('tbody', null, items.filter((p) => p.connection === c.id).map((p) => {
        const sel = h('select', { 'aria-label': `Environment of ${p.projectId}`, disabled: !can('accounts') }, [['', `From ${p.environmentSource === 'label' ? 'its label' : 'the connection'}`], ...envList.map((e) => [e.id, e.name])].map(([v, l]) => h('option', { value: v, selected: p.environmentSource === 'set' ? v === p.environment : v === '' }, l)));
        sel.addEventListener('change', async () => { try { await api('PUT', `/gcp/connections/${c.id}/projects/${encodeURIComponent(p.projectId)}/environment`, { environment: sel.value || null }); toast('Saved'); } catch (x) { toast(x.message, true); } });
        return h('tr', null, h('td', null, h('div', { class: 'name' }, p.name), h('div', { class: 'tiny muted mono' }, p.projectId)), h('td', { class: 'mono tiny' }, p.parent || ''), h('td', null, sel, h('div', { class: 'tiny muted' }, envName(p.environment))));
      })))), h('p', { class: 'small muted' }, 'A project lands in the environment chosen here; otherwise its env or environment label; otherwise the connection’s.'));
  };
  const det = h('details', null, h('summary', { class: 'btn sm' }, `Projects (${c.projects})`), projBox);
  det.addEventListener('toggle', () => { if (det.open) loadProjects(); });
  const scope = `${c.scopeType} ${c.scopeId}`;
  return h('section', { class: 'card' },
    h('div', { class: 'card-h' }, h('div', { class: 'row' }, h('h2', null, c.name), h('span', { class: `badge ${STATUS[c.status]}` }, c.scanning ? 'scanning' : c.status), h('span', { class: 'small muted mono' }, `${scope} · ${envName(c.environment)}`)),
      h('div', { class: 'row' },
        can('scan') && h('button', { class: 'btn sm', onClick: async () => { try { const r = await post(`/gcp/connections/${c.id}/scan`); toast(r.message); } catch (x) { toast(x.message, true); } } }, 'Scan now'),
        h('a', { class: 'btn sm', href: '#/identities?type=gcp' }, 'Identities'),
        h('a', { class: 'btn sm', href: '#/space' }, 'Space'),
        can('accounts') && h('a', { class: 'btn sm', href: `#/gcp/${c.id}/edit` }, 'Edit'),
        can('accounts') && h('button', { class: 'btn sm danger', onClick: async () => { if (await confirmDialog({ title: `Remove ${c.name}?`, message: 'Curious Monkey forgets this connection and everything read from it. Nothing changes in Google Cloud; delete the reader service account and pool there yourself.', confirmLabel: 'Remove', danger: true })) { await api('DELETE', `/gcp/connections/${c.id}`); ctx.reload(); } } }, 'Remove'))),
    c.status === 'error' && h('div', { class: 'card-b' }, h('div', { class: 'alert bad' }, c.detail?.message || 'The last scan failed.', c.nextScanAt && h('div', { class: 'small' }, `Next try ${ago(c.nextScanAt)}.`))),
    c.scanning && c.progress && h('div', { class: 'card-b' }, h('div', { class: 'alert' }, h('span', { class: 'spin' }), ` Reading: ${c.progress.stage}${c.progress.projects ? ` · ${c.progress.done || 0} of ${c.progress.projects} projects` : ''}`)),
    h('div', { class: 'card-b stack' },
      h('dl', { class: 'kv' },
        h('dt', null, 'Access'), h('dd', null, c.authMode === 'wif' ? 'Workload identity federation from this app’s AWS role' : 'Service account key',
          h('span', { class: 'mono small muted' }, c.authMode === 'wif' ? ` · pool ${c.wif?.poolId} / ${c.wif?.providerId}${c.wif?.serviceAccount ? ` → ${c.wif.serviceAccount}` : ''}` : ` · ${c.keyHint || 'missing'}`)),
        h('dt', null, 'Found'), h('dd', null, `${num(c.projects)} projects · ${num(c.serviceAccounts)} service accounts · ${num(c.principals)} identities`, c.high ? h('span', { class: 'badge b-high', style: 'margin-left:8px' }, `${c.high} high risk`) : null),
        h('dt', null, 'Last scan'), h('dd', null, c.lastScanAt ? `${fmtDate(c.lastScanAt)} (${ago(c.lastScanAt)})` : 'not yet', c.detail?.skipped?.length ? h('span', { class: 'small muted' }, ` · ${c.detail.skipped.length} policies could not be read`) : null)),
      det));
}

// ---------------------------------------------------------------- connect / edit
export async function gcpConnectPage(ctx, id = null) {
  const editing = !!id;
  const existing = editing ? (await get('/gcp/connections')).items.find((x) => x.id === id) : null;
  if (editing && !existing) return h('div', { class: 'empty' }, 'That connection no longer exists.');
  const envList = await loadEnvironments();
  ctx.setCrumbs(h('a', { href: GCP_CONNECTIONS }, 'Accounts · Google Cloud'), editing ? `Edit ${existing.name}` : 'Connect Google Cloud');
  const m = { name: existing?.name || '', scopeType: existing?.scopeType || 'organization', scopeId: existing?.scopeId || '', environment: existing?.environment || envList[0].id,
    authMode: existing?.authMode || 'wif', home: '', projectNumber: existing?.wif?.projectNumber || '', poolId: existing?.wif?.poolId || 'curious-monkey', providerId: existing?.wif?.providerId || 'aws-scanner',
    serviceAccount: existing?.wif?.serviceAccount || '', key: '' };
  const err = h('div', { class: 'err', role: 'alert' }), result = h('div'), cmds = h('div', { class: 'stack' });
  const input = (k, attrs = {}) => { const i = h('input', { value: m[k], ...attrs }); i.addEventListener('input', () => { m[k] = i.value.trim(); refreshCmds(); }); return i; };
  const choice = (k, opts, onPick) => h('div', { class: 'pill-bar', role: 'radiogroup' }, opts.map(([v, l]) => {
    const b = h('button', { type: 'button', class: 'chip', 'aria-pressed': m[k] === v, disabled: editing && k === 'scopeType' });
    b.textContent = l; b.addEventListener('click', () => { m[k] = v; draw(); onPick?.(); }); return b; }));
  let t;
  const refreshCmds = () => { clearTimeout(t); t = setTimeout(async () => {
    try {
      const q = new URLSearchParams({ scopeType: m.scopeType, mode: m.authMode, ...(m.scopeId ? { scopeId: m.scopeId } : {}), ...(m.home ? { home: m.home } : {}), ...(m.projectNumber ? { homeNumber: m.projectNumber } : {}) });
      const s = await get(`/gcp/onboarding?${q}`);
      if (!m.serviceAccount && m.home) m.serviceAccount = s.serviceAccount;
      cmds.replaceChildren(
        m.authMode === 'wif' && h('div', { class: `alert ${s.aws ? 'ok' : 'warn'}` }, s.aws ? `Federation will trust only this app’s AWS role: ${s.aws.sessionArn}. No Google secret is stored.`
          : 'The worker has not reported its AWS identity yet, so the role in the commands is a placeholder. Start a worker (or set SCANNER_PRINCIPAL_ARN) and reload.'),
        ...s.steps.map((st, i) => h('div', { class: 'stack', style: 'gap:6px' }, h('div', { class: 'row' }, h('b', null, `${i + 1}. ${st.title}`), h('span', { class: 'spacer' }), h('button', { class: 'btn sm', type: 'button', onClick: () => copy(st.code) }, 'Copy')),
          h('pre', { class: 'code' }, st.code))),
        h('p', { class: 'small muted' }, `The role grants ${s.permissions.length} read permissions: IAM policies, service accounts and key metadata, roles, workload identity pools. It cannot read data, secrets or key material, and cannot change anything.`));
    } catch (x) { cmds.replaceChildren(h('div', { class: 'alert bad' }, x.message)); }
  }, 250); };

  const box = h('div', { class: 'stack-lg' });
  function draw() {
    const scopeHint = { organization: 'The numeric organization ID (gcloud organizations list).', folder: 'The numeric folder ID.', project: 'The project ID, such as acme-payments-prod.' }[m.scopeType];
    const env = h('select', null, envList.map((e) => h('option', { value: e.id, selected: m.environment === e.id }, e.name))); env.addEventListener('change', () => { m.environment = env.value; });
    const keyArea = h('textarea', { rows: 6, class: 'mono', placeholder: editing && existing.authMode === 'key' ? `Saved (${existing.keyHint}). Paste a new key only to replace it.` : 'Paste the JSON key file, or choose it below', spellcheck: 'false' });
    keyArea.addEventListener('input', () => { m.key = keyArea.value; });
    const file = h('input', { type: 'file', accept: '.json,application/json' });
    file.addEventListener('change', async () => { const fl = file.files[0]; if (fl) { m.key = await fl.text(); keyArea.value = `${m.key.slice(0, 120)}…`; } });
    box.replaceChildren(
      h('section', { class: 'card' }, h('div', { class: 'card-h' }, h('h2', null, '1. What to read')),
        h('div', { class: 'card-b stack' },
          h('div', { class: 'field' }, h('label', null, 'Name', input('name', { placeholder: 'e.g. acme.example organization', maxlength: 80 }))),
          h('div', { class: 'field' }, h('span', { class: 'label' }, 'Scope'), choice('scopeType', [['organization', 'Organization'], ['folder', 'Folder'], ['project', 'One project']], refreshCmds),
            h('span', { class: 'hint' }, 'An organization or folder includes every project under it. Connect each organization once.')),
          h('div', { class: 'field' }, h('label', null, m.scopeType === 'project' ? 'Project ID' : `${m.scopeType === 'organization' ? 'Organization' : 'Folder'} ID`, input('scopeId', { class: 'mono', disabled: editing, spellcheck: 'false' })), h('span', { class: 'hint' }, scopeHint)),
          h('div', { class: 'field' }, h('label', null, 'Environment for projects without one', env), h('span', { class: 'hint' }, 'A project’s env or environment label wins over this; each project can also be set on the Accounts page.')))),
      h('section', { class: 'card' }, h('div', { class: 'card-h' }, h('h2', null, '2. How Curious Monkey signs in')),
        h('div', { class: 'card-b stack' },
          choice('authMode', [['wif', 'Workload identity federation (recommended)'], ['key', 'Service account key']], refreshCmds),
          h('div', { class: 'field' }, h('label', null, 'Project that holds the reader service account and pool', input('home', { class: 'mono', placeholder: 'e.g. acme-shared-ci', spellcheck: 'false' })),
            h('span', { class: 'hint' }, 'Usually a central security or identity project. Fills in the commands below.')),
          m.authMode === 'wif' ? h('div', { class: 'grid2' },
            h('div', { class: 'field' }, h('label', null, 'Its project number', input('projectNumber', { class: 'mono', inputmode: 'numeric' })), h('span', { class: 'hint' }, 'Digits, not the ID: gcloud projects describe <id> --format="value(projectNumber)"')),
            h('div', { class: 'field' }, h('label', null, 'Service account to become', input('serviceAccount', { class: 'mono', placeholder: 'curious-monkey-reader@<project>.iam.gserviceaccount.com' }))),
            h('div', { class: 'field' }, h('label', null, 'Pool ID', input('poolId', { class: 'mono' }))),
            h('div', { class: 'field' }, h('label', null, 'Provider ID', input('providerId', { class: 'mono' }))))
            : h('div', { class: 'field' }, h('label', null, 'Key file', keyArea), file, h('span', { class: 'hint' }, 'Stored encrypted and never shown again. A key works from anywhere until it is deleted; rotate it, or move to federation.')))),
      h('section', { class: 'card' }, h('div', { class: 'card-h' }, h('h2', null, '3. Run these in Google Cloud'), h('span', { class: 'small muted' }, 'Cloud Shell or any gcloud with rights to grant roles at the scope')), h('div', { class: 'card-b' }, cmds)),
      h('section', { class: 'card' }, h('div', { class: 'card-b stack' }, err, result,
        h('div', { class: 'row' },
          h('button', { class: 'btn', type: 'button', onClick: test }, 'Test connection'), h('span', { class: 'spacer' }),
          h('a', { class: 'btn', href: GCP_CONNECTIONS }, 'Cancel'),
          h('button', { class: 'btn primary', type: 'button', onClick: save }, editing ? 'Save changes' : 'Connect and scan')))));
    refreshCmds();
  }
  const body = () => ({ name: m.name, scopeType: m.scopeType, scopeId: m.scopeId, environment: m.environment, authMode: m.authMode,
    ...(m.authMode === 'wif' ? { wif: { projectNumber: m.projectNumber, poolId: m.poolId, providerId: m.providerId, serviceAccount: m.serviceAccount } } : {}), ...(m.key ? { key: m.key } : {}) });
  async function test(e) {
    e.target.disabled = true; err.textContent = ''; result.replaceChildren(h('div', { class: 'alert' }, h('span', { class: 'spin' }), ' Signing in to Google Cloud and reading the scope…'));
    try {
      const r = await post('/gcp/connections/test', { ...body(), ...(editing ? { id } : {}) });
      result.replaceChildren(r.ok ? h('div', { class: 'alert ok' }, h('b', null, 'It works. '), `Signed in as ${r.identity}; ${r.projects} project${r.projects === 1 ? '' : 's'} in scope${r.sample.length ? ` (${r.sample.join(', ')}${r.projects > r.sample.length ? '…' : ''})` : ''}.`, r.policyReadable ? '' : ' The scope’s own IAM policy could not be read: check the role binding.')
        : h('div', { class: 'alert bad' }, h('b', null, 'That did not work. '), h('span', { class: 'mono small' }, r.message)));
    } catch (x) { result.replaceChildren(); err.textContent = x.message; }
    e.target.disabled = false;
  }
  async function save(e) {
    e.target.disabled = true; err.textContent = '';
    try {
      if (editing) { await api('PATCH', `/gcp/connections/${id}`, body()); toast('Saved'); }
      else { await post('/gcp/connections', body()); toast('Connected. The first scan starts within 30 seconds.'); }
      go(GCP_CONNECTIONS);
    } catch (x) { err.textContent = x.message; e.target.disabled = false; }
  }
  draw();
  return h('div', { class: 'stack-lg' }, h('header', { class: 'head' }, h('div', null, h('div', { class: 'eyebrow' }, 'GOOGLE CLOUD'), h('h1', null, editing ? `Edit ${existing.name}` : 'Connect Google Cloud'),
    h('p', { class: 'muted' }, 'Curious Monkey reads IAM only: policies, service accounts, key metadata, workload identity federation. It shows who can do what and where they can come from, including paths from and to your AWS accounts.'))), box);
}

// ---------------------------------------------------------------- Roles page: Google Cloud tab
const F = { q: '', kinds: new Set(), risks: new Set(), source: '', project: '', hideManaged: true, sort: 'risk', page: 1 };   // kept when you come back by the tab link
const URL_KEYS = ['q', 'kinds', 'risks', 'source', 'project', 'hideManaged', 'sort', 'page'];
export async function gcpRolesTab(ctx) {
  ctx.setCrumbs('Identities', 'Google Cloud');
  // every filter is in the address (#/identities?type=gcp&risks=High&source=key), so links from Space and elsewhere, reloads and Back open the same list
  const P = ctx.params;
  if (URL_KEYS.some((k) => P.has(k))) Object.assign(F, { q: P.get('q') || '', kinds: urlSet(P, 'kinds'), risks: urlSet(P, 'risks'), project: P.get('project') || '', source: P.get('source') || '',
    hideManaged: P.get('hideManaged') !== '0', sort: P.get('sort') || 'risk', page: Math.max(1, Number(P.get('page')) || 1) });
  const list = h('div'), count = h('span', { class: 'count' }), tiles = h('div', { class: 'tiles' });
  let first = true, search = null;
  const qs = () => {
    const p = new URLSearchParams({ sort: F.sort, limit: '25', offset: String((F.page - 1) * 25) });
    if (F.q) p.set('q', F.q); if (F.kinds.size === 1) p.set('kind', [...F.kinds][0]); if (F.risks.size === 1) p.set('risk', [...F.risks][0]);
    if (F.source) p.set('source', F.source); if (F.project) p.set('project', F.project); if (F.hideManaged) p.set('hideManaged', '1');
    return p;
  };
  const chips = h('div', { class: 'filters' });
  async function load() {
    let r;
    syncUrl({ type: 'gcp', q: F.q, kinds: F.kinds, risks: F.risks, source: F.source, project: F.project, hideManaged: F.hideManaged ? '' : '0', sort: F.sort === 'risk' ? '' : F.sort, page: F.page > 1 ? F.page : '' });
    try { r = await get(`/gcp/principals?${qs()}`); } catch (x) { list.replaceChildren(h('div', { class: 'alert bad' }, x.message)); return; }
    count.textContent = `${num(r.total)} identities`;
    if (first) { first = false; drawFilters(r); drawTiles(r); }
    list.replaceChildren(r.items.length ? table(r.items) : h('div', { class: 'empty' }, r.total === 0 && !F.q && !F.kinds.size && !F.risks.size && !F.source && !F.project
      ? h('div', null, 'No Google Cloud identities yet. ', can('accounts') ? h('span', null, 'Connect an organization or project on ', h('a', { href: GCP_CONNECTIONS }, 'Accounts → Google Cloud'), '.') : 'An admin connects Google Cloud on the Accounts page.') : 'Nothing matches these filters.'),
    r.total > 25 && pager({ page: F.page, total: r.total, size: 25, onPage: (n) => { F.page = n; load(); } }));
  }
  async function drawTiles(r) {
    const k = r.facets.kinds, risks = r.facets.risks;
    const [keys, aws] = await Promise.all([get('/gcp/principals?source=key&limit=1'), get('/gcp/principals?source=aws&limit=1')]);
    tiles.replaceChildren(
      tile('Identities', num(Object.values(k).reduce((a, b) => a + b, 0)), `${num(k.serviceAccount || 0)} service accounts, ${num((k.user || 0) + (k.group || 0))} people and groups`, { onClick: () => set({ kinds: new Set(), risks: new Set(), source: '' }) }),
      tile('High risk', num(risks.High || 0), `${num(risks.Medium || 0)} medium`, { onClick: () => set({ risks: new Set(['High']) }) }),
      tile('Service accounts with keys', num(keys.total), 'keys work from anywhere until deleted', { onClick: () => set({ source: 'key' }) }),
      tile('Reachable from AWS', num(aws.total), 'through workload identity federation', { onClick: () => set({ source: 'aws' }) }));
  }
  const set = (patch) => { Object.assign(F, patch, { page: 1 }); drawFilters(null); load(); };
  let facets = null;
  function drawFilters(r) {
    if (r) facets = r;
    const fx = facets;
    search?.cancel();
    search = searchBox({ placeholder: 'Search email, member or name', label: 'Search identities', value: F.q, onSearch: (v) => { F.q = v; F.page = 1; load(); } });
    const pill = (set_, v, label) => { const b = h('button', { class: 'chip', type: 'button', 'aria-pressed': set_.has(v) }, label); b.addEventListener('click', () => { const on = set_.has(v); set_.clear(); if (!on) set_.add(v); set({}); }); return b; };
    const sel = (key, opts, label) => { const s = h('select', { 'aria-label': label }, opts.map(([v, l]) => h('option', { value: v, selected: F[key] === v }, l))); s.addEventListener('change', () => set({ [key]: s.value })); return s; };
    const managed = h('input', { type: 'checkbox', checked: F.hideManaged }); managed.addEventListener('change', () => set({ hideManaged: managed.checked }));
    chips.replaceChildren(search,
      h('div', { class: 'pill-bar', role: 'group', 'aria-label': 'Kind' }, ...Object.entries(fx?.facets.kinds || {}).sort((a, b) => b[1] - a[1]).map(([k, n]) => pill(F.kinds, k, `${fx.facets.kindLabels[k] || k} ${n}`))),
      h('div', { class: 'pill-bar', role: 'group', 'aria-label': 'Risk' }, ...['High', 'Medium', 'Low'].map((x) => pill(F.risks, x, x))),
      sel('source', [['', 'Any way in'], ['key', 'Has keys'], ['wif', 'Federated'], ['aws', 'From AWS'], ['impersonate', 'Impersonated'], ['gke', 'From GKE']], 'Way in'),
      sel('project', [['', 'All projects'], ...(fx?.projects || []).map((p) => [p.projectId, `${p.projectId} · ${envName(p.environment)}`])], 'Project'),
      sel('sort', [['risk', 'Riskiest first'], ['permissions', 'Most permissions'], ['reach', 'Widest reach'], ['name', 'Name']], 'Sort'),
      h('label', { class: 'check small' }, managed, h('span', null, 'Hide Google-managed service agents')), count);
  }
  const ways = (x) => {
    const s = x.sources, out = [];
    if (x.keys) out.push(h('span', { class: 'badge b-medium', title: VIA_HELP.key }, `${x.keys} key${x.keys === 1 ? '' : 's'}`));
    if (x.kind !== 'federated') for (const a of s.aws || []) out.push(h('span', { class: 'badge b-aws', title: 'Federated from AWS' }, a));
    if (s.wif && !(s.aws || []).length && x.kind !== 'federated') out.push(h('span', { class: 'badge b-neutral', title: VIA_HELP.wif }, 'federated'));
    if (s.gke) out.push(h('span', { class: 'badge b-neutral', title: VIA_HELP.gke }, 'GKE'));
    const imp = (s.token || 0) + (s.actAs || 0) + (s['key-create'] || 0);
    if (imp) out.push(h('span', { class: 'tiny muted', title: 'People, groups and service accounts that can impersonate it, act as it or mint keys for it' }, `${imp} can become it`));
    if (x.kind === 'federated' && x.origin) out.push(h('span', { class: `badge ${x.origin.cloud === 'aws' ? 'b-aws' : 'b-neutral'}` }, x.origin.label));
    return out.length ? out : [h('span', { class: 'muted' }, '—')];
  };
  const table = (items) => h('div', { class: 'scroll' }, h('table', null,
    h('thead', null, h('tr', null, h('th', null, 'Identity'), h('th', null, 'Risk'), h('th', null, 'Can do'), h('th', null, 'Ways in'), h('th', null, 'Findings'))),
    h('tbody', null, items.map((x) => h('tr', { class: 'link', tabindex: '0', onClick: () => go(`#/identities/gcp/${x.id}`), onKeydown: (e) => { if (e.key === 'Enter') go(`#/identities/gcp/${x.id}`); } },
      h('td', null, h('div', { class: 'name' }, nameOf(x)), h('div', { class: 'tiny muted' }, [x.kindLabel, x.project, x.name, x.managed ? 'Google-managed' : null, x.disabled ? 'disabled' : null].filter(Boolean).join(' · '))),
      h('td', null, riskBadge(x.risk)),
      h('td', { class: 'nowrap small' }, `${num(x.permissions)} permissions`, h('div', { class: 'tiny muted' }, `${x.roles} role${x.roles === 1 ? '' : 's'} · ${x.reach.length} project${x.reach.length === 1 ? '' : 's'}`)),
      h('td', null, h('div', { class: 'row', style: 'gap:4px;flex-wrap:wrap' }, ...ways(x))),
      h('td', { class: 'small' }, x.reasons.filter((r) => r.severity !== 'info').slice(0, 2).map((r) => h('div', null, h('span', { class: `dot ${SEV[r.severity]}` }), r.title)), x.reasons.filter((r) => r.severity !== 'info').length > 2 ? h('div', { class: 'tiny muted' }, `+${x.reasons.filter((r) => r.severity !== 'info').length - 2} more`) : null))))));

  drawFilters(null); load();
  ctx.onLeave(() => search?.cancel());
  return h('div', { class: 'stack-lg' },
    h('header', { class: 'head' }, h('div', null, h('div', { class: 'eyebrow' }, 'IDENTITIES · GOOGLE CLOUD'), h('h1', null, 'Google Cloud identities'),
      h('p', { class: 'muted' }, 'Service accounts, people, groups and federated identities: what IAM lets them do, and where they can come from. Read from IAM policies; activity is not read yet, so nothing here says what was actually used.')),
    can('accounts') && h('div', { class: 'actions' }, h('a', { class: 'btn', href: GCP_CONNECTIONS }, 'Connections'))),
    tiles, h('section', { class: 'card' }, chips, list));
}

// ---------------------------------------------------------------- one identity
export async function gcpPrincipalPage(ctx, id) {
  const p = await get(`/gcp/principals/${id}`);
  ctx.setCrumbs(h('a', { href: '#/identities?type=gcp' }, 'Identities'), 'Google Cloud', nameOf(p));
  const findings = p.reasons.length ? h('ul', { class: 'plain stack', style: 'gap:8px' }, p.reasons.map((r) => h('li', null, h('span', { class: `badge ${SEV[r.severity]}` }, r.severity), ' ', h('b', null, r.title), h('div', { class: 'small muted' }, r.detail))))
    : h('p', { class: 'muted' }, 'Nothing stands out.');

  // where it can come from
  const own = p.sources.filter((s) => !s.wide), wide = p.sources.filter((s) => s.wide);
  const srcRow = (s) => h('tr', null,
    h('td', null, h('span', { class: 'badge b-neutral', title: VIA_HELP[s.via] }, VIA[s.via] || s.via)),
    h('td', null, s.via === 'key' ? h('div', null, s.keys.map((k) => h('div', { class: 'small' }, h('span', { class: 'mono' }, k.id.slice(0, 12)), ` · created ${ago(k.created)}`, k.expires ? ` · expires ${fmtDate(k.expires)}` : h('span', { class: 'badge b-medium', style: 'margin-left:6px' }, 'never expires'))))
      : s.origin ? h('div', null, h('div', { class: 'name' }, s.origin.label), h('div', { class: 'tiny muted' }, `pool ${s.origin.pool}${s.origin.providers?.length ? ` · ${s.origin.providers.map((x) => `${x.id}${x.condition ? ` (when ${x.condition})` : ' (no condition)'}`).join(', ')}` : ''}`))
        : s.via === 'gke' ? h('div', null, h('div', { class: 'name' }, `${s.namespace}/${s.ksa}`), h('div', { class: 'tiny muted' }, `Kubernetes service account in a GKE cluster of ${s.gkeProject}`))
          : h('div', { class: 'name' }, s.label)),
    h('td', { class: 'small' }, s.role ? shortRole(s.role) : '', s.at ? h('div', { class: 'tiny muted' }, s.atType === 'serviceAccount' ? 'on this service account' : `on ${s.at}`) : null),
    h('td', null, s.origin?.broad ? h('span', { class: 'badge b-high' }, 'any identity') : s.conditional ? h('span', { class: 'badge b-neutral' }, 'conditional') : null));
  const srcTable = (rows) => h('div', { class: 'scroll' }, h('table', { class: 'small' }, h('thead', null, h('tr', null, h('th', null, 'How'), h('th', null, 'Who or what'), h('th', null, 'Granted'), h('th', null, ''))), h('tbody', null, rows.map(srcRow))));
  const comesFrom = p.kind === 'serviceAccount' || p.kind === 'federated'
    ? section('Where it can come from', p.kind === 'federated' ? 'The federated source behind this identity.' : 'Anything listed here can run as this service account.',
      own.length ? srcTable(own) : h('p', { class: 'muted' }, 'Nothing is granted on the service account itself.'),
      wide.length > 0 && h('details', null, h('summary', { class: 'btn sm' }, `${wide.length} more through roles on its project, folder or organization`), h('p', { class: 'small muted' }, 'Roles like Owner, Editor or Service Account User on a whole project let the holder act as every service account in it.'), srcTable(wide)))
    : null;

  // the AWS side
  const awsRow = (l, dir) => h('tr', null,
    h('td', null, l.awsRoleId ? h('a', { href: `#/identities/${l.awsRoleId}` }, l.awsRole) : l.awsRole || h('b', null, 'any role')),
    h('td', { class: 'small' }, l.awsAccountName || 'not connected', h('div', { class: 'tiny muted mono' }, l.awsAccountId)),
    h('td', { class: 'small' }, dir === 'in' ? (l.via === 'direct' ? `holds ${l.grant} itself` : `becomes this service account (${shortRole(l.grant || '')})`) : `trusts it in statement ${l.statement + 1}`),
    h('td', null, l.broad ? h('span', { class: 'badge b-high' }, 'whole account') : null));
  const awsTable = (rows, dir) => h('div', { class: 'scroll' }, h('table', { class: 'small' }, h('thead', null, h('tr', null, h('th', null, 'AWS role'), h('th', null, 'Account'), h('th', null, 'How'), h('th', null, ''))), h('tbody', null, rows.map((l) => awsRow(l, dir)))));
  const aws = (p.aws.into.length || p.aws.out.length) ? section('Across clouds', 'Paths between this identity and your AWS accounts.',
    p.aws.into.length > 0 && h('div', null, h('h3', null, 'From AWS into Google Cloud'), awsTable(p.aws.into, 'in')),
    p.aws.out.length > 0 && h('div', null, h('h3', null, 'From Google Cloud into AWS'), h('p', { class: 'small muted' }, 'AWS roles whose trust policy accepts Google tokens for this service account (by its unique ID).'), awsTable(p.aws.out, 'out'))) : null;

  // what it can do
  const permBox = h('div');
  const showPerms = async (role) => {
    const r = await get(`/gcp/roles/permissions?name=${encodeURIComponent(role)}`);
    const filter = h('input', { type: 'search', placeholder: `Filter ${num(r.permissions.length)} permissions` });
    const ul = h('ul', { class: 'plain mono small perm-list' });
    const draw = () => { const n = filter.value.toLowerCase(); const shown = r.permissions.filter((x) => x.toLowerCase().includes(n)); ul.replaceChildren(...shown.slice(0, 400).map((x) => h('li', null, x)), shown.length > 400 ? h('li', { class: 'muted' }, `…and ${num(shown.length - 400)} more`) : null); };
    filter.addEventListener('input', draw); draw();
    permBox.replaceChildren(h('div', { class: 'stack' }, h('div', { class: 'row' }, h('b', null, r.title || role), h('span', { class: 'mono small muted' }, role), h('span', { class: 'spacer' }), h('button', { class: 'btn sm', onClick: () => permBox.replaceChildren() }, 'Close')), filter, ul));
    permBox.scrollIntoView({ block: 'nearest' });
  };
  const roles = section('What it can do', `${num(p.permissions)} distinct permissions across ${p.roles.length} role${p.roles.length === 1 ? '' : 's'}${p.reach.length ? `, reaching ${p.reach.length} project${p.reach.length === 1 ? '' : 's'}` : ''}. Roles on the organization or a folder reach every project under it.`,
    p.roles.length ? h('div', { class: 'scroll' }, h('table', { class: 'small' }, h('thead', null, h('tr', null, h('th', null, 'Role'), h('th', null, 'Granted on'), h('th', null, 'Reaches'), h('th', null, 'Permissions'), h('th', null, ''))),
      h('tbody', null, p.roles.map((r) => h('tr', null, h('td', null, h('div', { class: 'name' }, r.title || shortRole(r.role)), h('div', { class: 'tiny muted mono' }, r.role), r.basic && h('span', { class: 'badge b-medium' }, 'basic role')),
        h('td', null, where(r), r.condition && h('div', { class: 'tiny muted' }, `only when: ${r.condition}`)), h('td', null, r.resourceType === 'serviceAccount' ? '—' : `${r.reach} project${r.reach === 1 ? '' : 's'}`),
        h('td', null, num(r.permissions)), h('td', null, r.permissions ? h('button', { class: 'btn sm', onClick: () => showPerms(r.role) }, 'List') : null)))))) : h('p', { class: 'muted' }, 'No roles granted.'),
    permBox);
  const becomes = p.becomes.length ? section('Who it can become', 'Service accounts this identity can impersonate, act as or mint keys for. Their permissions are effectively its permissions too.',
    h('div', { class: 'scroll' }, h('table', { class: 'small' }, h('thead', null, h('tr', null, h('th', null, 'Service account'), h('th', null, 'Risk'), h('th', null, 'How'))),
      h('tbody', null, p.becomes.map((b) => h('tr', { class: 'link', onClick: () => go(`#/identities/gcp/${b.id}`) }, h('td', null, h('div', { class: 'name' }, b.email), h('div', { class: 'tiny muted' }, b.project)), h('td', null, riskBadge(b.risk)),
        h('td', null, b.via.map((v) => `${VIA[v.via] || v.via} (${shortRole(v.role)})`).join(', '))))))))
    : null;

  // the same frame as an AWS identity; activity is not read for Google Cloud, so there is no Activity tab
  const keys = p.sources.filter((x) => x.via === 'key').flatMap((x) => x.keys || []);
  const waysIn = p.kind === 'serviceAccount' || p.kind === 'federated';
  return identityShell(ctx, {
    path: `#/identities/gcp/${p.id}`,
    eyebrow: `GOOGLE CLOUD · ${p.kindLabel.toUpperCase()}`,
    name: nameOf(p),
    badges: [riskBadge(p.risk), p.project && h('span', { class: 'badge b-neutral' }, p.project), p.environment && h('span', { class: 'badge b-neutral' }, envName(p.environment)),
      p.uniqueId && h('span', { class: 'small muted mono', title: 'The ID AWS trust policies use for this service account' }, `unique ID ${p.uniqueId}`), p.managed && h('span', { class: 'badge b-neutral' }, 'Google-managed'), p.disabled && h('span', { class: 'badge b-high' }, 'disabled')],
    sub: [p.name && h('p', { class: 'muted' }, p.name), p.kind !== 'serviceAccount' && p.kind !== 'federated' && h('p', { class: 'mono small muted break' }, p.member)],
    actions: [h('a', { class: 'btn', href: '#/space' }, 'In Space')],
    notices: [h('p', { class: 'small muted' }, 'Read from IAM policies. Google Cloud activity is not read yet, so nothing here says what was actually used.')],
    tabs: [
      ['overview', 'Overview', () => h('div', { class: 'stack-lg' },
        h('section', { class: 'tiles' }, tile('Permissions', num(p.permissions), `across ${p.roles.length} role${p.roles.length === 1 ? '' : 's'}`), tile('Reaches', num(p.reach.length), `project${p.reach.length === 1 ? '' : 's'}`),
          waysIn && tile('Ways in', num(p.sources.filter((x) => !x.wide).length), `${num(p.sources.filter((x) => x.wide).length)} more through wider roles`), p.kind === 'serviceAccount' && tile('Keys', num(keys.length), keys.length ? 'user-managed, long-lived' : 'none'),
          tile('Can become', num(p.becomes.length), 'service accounts')),
        section('Why this risk level', `From the last scan of ${p.connection?.name || 'its connection'}${p.connection?.last_scan_at ? `, ${ago(p.connection.last_scan_at)}` : ''}.`, findings), aws)],
      ['permissions', 'Permissions', () => h('div', { class: 'stack-lg' }, roles, becomes)],
      waysIn && ['credentials', p.kind === 'federated' ? 'Where it comes from' : 'Credentials and ways in', () => h('div', { class: 'stack-lg' }, comesFrom)],
    ].filter(Boolean),
  }).el;
}
