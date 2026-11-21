// Trust map: who can get into your AWS and Google Cloud, one map for both. AWS from role trust policies; Google Cloud from
// IAM (federation, GKE, impersonation, actAs, keys, roles held by outsiders), with projects as accounts and what a way in
// reaches (a service account, or every one below a grant on a whole project or folder) as roles.
// Three rows above the view, each with one job: the filter (search, menus, pills), the summary (tiles that filter), and
// the view (Map | Sources | Ways in) with a panel for whatever is picked. A filter narrows everything and shows as a
// pill; a pick only opens the panel and focuses the map. Everything is in the address, so any view can be shared:
// #/trust?q=source:external finding:external-no-externalid&tab=ways&sel=...
import { h, svg, get, post, api, num, ago, loadEnvironments, envName, envs, tile, pager, menu, accountPicker, debounced, poll, modal, toast, ssoSet, softBreaks } from '../lib.js';
import { session } from '../main.js';

const SEV_ORDER = { high: 0, medium: 1, low: 2, info: 3, none: 4 };
const ATTENTION = new Set(['high', 'medium']);
// where a way in comes from, in the map's left column
const KINDS = [['public', 'Anyone'], ['external-account', 'Outside accounts'], ['oidc', 'CI and web identity'], ['saml', 'Identity Center and SAML'], ['unknown', 'Deleted identities']];
const KIND_NAME = Object.fromEntries(KINDS);
const GROUP_NAME = { ...KIND_NAME, 'connected-account': 'Your other accounts', 'same-account': 'The same account', service: 'Cloud services' };
const SHORT = { public: 'Anyone', 'external-account': 'Outside', oidc: 'OIDC', saml: 'SAML', 'connected-account': 'Your account', 'same-account': 'Same account', service: 'Service', unknown: 'Deleted' };
// the From menu: kinds of source, then kinds of identity provider (both are source: values)
const FROM = [['Anyone', 'public'], ['Outside accounts', 'external'], ['Your other accounts', 'connected'], ['CI and web identity', 'oidc'], ['Identity Center and SAML', 'saml'],
  ['The same account', 'same'], ['Cloud services', 'service'], ['Deleted identities', 'unknown'],
  null, ['GitHub Actions', 'github'], ['Bitbucket Pipelines', 'bitbucket'], ['GitLab', 'gitlab'], ['EKS clusters', 'eks'], ['GKE workloads', 'gke'], ['Terraform Cloud', 'terraform'], ['Google (into AWS)', 'google'], ['AWS (into Google Cloud)', 'aws'],
  ['Cognito identity pools', 'cognito'], ['IAM Identity Center', 'identity-center']];
const FROM_NAME = Object.fromEntries(FROM.filter(Boolean).map(([l, v]) => [v, l]));
const USED = [['A sign-in came through it', 'yes'], ['IAM says used, no sign-in tied to it', 'iam'], ['Never used', 'no'], ['Not known (Google Cloud without usage)', 'unknown']];
const USED_NAME = Object.fromEntries(USED.map(([l, v]) => [v, l]));
const USAGE_FINDINGS = new Set(['never-used', 'used-per-iam', 'used-unnamed', 'used-unattributed']);
const KEY_NAME = { fromenv: 'From environment', account: 'Account', env: 'Environment', source: 'From', finding: 'Finding', used: 'Used', severity: 'Severity', provider: 'Provider', from: 'From account',
  role: 'Role', roleid: 'Role', type: 'Principal', cond: 'Condition', has: 'Has', no: 'Without', text: 'Text', attention: 'Needs attention', expected: 'Expected', decided: 'Decided', new: 'New', cloud: 'Cloud' };
const KEYS = ['account', 'from', 'source', 'type', 'provider', 'finding', 'severity', 'role', 'roleid', 'cond', 'has', 'no', 'used', 'env', 'attention', 'expected', 'decided', 'new', 'fromenv', 'cloud'];
// Google Cloud: what a way in reaches is a service account, or every one below a grant (no page of its own: the project's)
const isGcp = (x) => String(x?.roleId || x?.id || '').startsWith('gcp:') || x?.cloud === 'gcp';
const roleHref = (x, tab = 'policies') => (!isGcp(x) ? `#/identities/${x.roleId}?tab=${tab}` : x.gcpId ? `#/identities/gcp/${x.gcpId}`
  : `#/identities?type=gcp&project=${encodeURIComponent(x.account || x.awsAccountId || '')}`);
const whatIsIt = (x) => (isGcp(x) ? 'service account' : 'role');
const PAGE = 50;
const plural = (n, w, ws = `${w}s`) => `${num(n)} ${n === 1 ? w : ws}`;
const cut = (s, n) => (String(s).length > n ? `${String(s).slice(0, n - 1)}…` : String(s));
const sevBadge = (s) => s && s !== 'none' && h('span', { class: `badge b-${s === 'info' ? 'neutral' : s}` }, s);
const usedText = (x) => (x.sessions ? `${plural(x.sessions, 'session')}${x.lastSeen ? ` · last ${ago(x.lastSeen)}` : ''}` : x.iamUsed || x.lastUsed ? 'IAM says used, no sign-in tied to it' : x.useUnknown ? 'use not known' : 'never used');

// ---------------------------------------------------------------- the query, as a list of terms
// The same grammar as the server: key:value (comma = either), -key:value excludes, "quoted values", free text.
function parse(q) {
  const out = [], re = /(-?)(\w+):("([^"]*)"|\S+)|"([^"]*)"|(\S+)/g; let m;
  while ((m = re.exec(q || ''))) {
    if (m[2] && KEYS.includes(m[2].toLowerCase())) out.push({ neg: !!m[1], key: m[2].toLowerCase(), value: m[4] ?? m[3] });
    else out.push({ neg: false, key: 'text', value: m[5] ?? m[0] });
  }
  return out;
}
const quote = (v) => (/[\s"]/.test(v) ? `"${String(v).replace(/"/g, '')}"` : v);
const write = (terms) => terms.map((t) => (t.key === 'text' ? quote(t.value) : `${t.neg ? '-' : ''}${t.key}:${quote(t.value)}`)).join(' ');
const valuesOf = (terms, key) => terms.filter((t) => t.key === key && !t.neg).flatMap((t) => t.value.toLowerCase().split(',').filter(Boolean));
function setValues(terms, key, values) {
  const rest = terms.filter((t) => !(t.key === key && !t.neg));
  return values.length ? [...rest, { neg: false, key, value: values.join(',') }] : rest;
}

export async function trustPage(ctx) {
  const params = ctx.params;
  // an old link to the Google Cloud tab (?cloud=gcp) opens the one map, filtered to Google Cloud
  const legacy = `${['gcp', 'aws'].includes(params.get('cloud')) && !/\bcloud:/.test(params.get('q') || '') ? ` cloud:${params.get('cloud')}` : ''}${/^[a-z][a-z0-9-]{4,61}$/.test(params.get('project') || '') ? ` account:${params.get('project')}` : ''}`;
  const S = {
    terms: parse(`${params.get('q') || ''}${legacy}`),
    sel: params.get('sel') || null,
    tab: ['map', 'grid', 'sources', 'ways'].includes(params.get('tab')) ? params.get('tab') : 'map',
    show: params.get('show') || null,                     // attention | all; null: decided by the size of the map
    open: new Set((params.get('open') || '').split(',').filter(Boolean)),
    opened: params.has('open'),
    sort: params.get('sort') || 'worst', dir: params.get('dir') === 'desc' ? 'desc' : 'asc', page: Math.max(0, Number(params.get('page')) || 0),
    srcSort: 'worst', expanded: new Set(),
    group: params.get('group') === '1',                    // ways in: the same trust grouped across accounts
  };
  const q = () => write(S.terms);
  // the map is coloured by what still needs a look: expected and accepted ways in keep their findings but not the colour
  const settle = (x) => { for (const l of [...x.map.links, ...x.map.sources]) if (l.open) { l.raw = l.worst; l.worst = l.open; } return x; };
  const [m0] = await Promise.all([get(`/trust?q=${encodeURIComponent(q())}`), loadEnvironments()]);
  let m = settle(m0);
  const canDecide = () => session.user.permissions.includes('decide');
  const ENV_ORDER = envs().map((e) => e.id);
  const ENV_COLOR = Object.fromEntries(envs().map((e) => [e.id, e.color]));

  // ---------------------------------------------------------------- the address
  function address(push = false) {
    const p = new URLSearchParams();
    if (q()) p.set('q', q());
    if (S.sel) p.set('sel', S.sel);
    if (S.tab !== 'map') p.set('tab', S.tab);
    if (S.show) p.set('show', S.show);
    if (S.opened) p.set('open', [...S.open].join(','));
    if (S.sort !== 'worst') p.set('sort', S.sort);
    if (S.dir === 'desc') p.set('dir', 'desc');
    if (S.group) p.set('group', '1');
    if (S.page) p.set('page', String(S.page));
    const url = `#/trust${p.toString() ? `?${p}` : ''}`;
    if (url !== location.hash) history[push ? 'pushState' : 'replaceState'](null, '', url);
    ctx.setCrumbs('Trust map', q() || 'Everything');
  }

  // ---------------------------------------------------------------- loading
  const root = h('div', { class: 'stack-lg tm2' });
  let loading = 0;
  async function refetch() {
    root.classList.add('tm2-busy'); loading++;
    try {
      m = settle(await get(`/trust?q=${encodeURIComponent(q())}`));
      if (S.sel && !known(S.sel)) S.sel = null;
      drawAll();
      if (S.tab === 'ways') loadWays();
    } finally { if (--loading === 0) root.classList.remove('tm2-busy'); }
  }
  function changeTerms(next) { S.terms = next; S.page = 0; S.expanded.clear(); address(); drawFilter(); refetch(); }

  // ---------------------------------------------------------------- header
  const exportMenu = () => menu('Export ▾', [
    ['Ways in (CSV)', `/api/trust.csv?q=${encodeURIComponent(q())}${S.sel ? `&sel=${encodeURIComponent(S.sel)}` : ''}`],
    ['Sources (CSV)', `/api/trust/sources.csv?q=${encodeURIComponent(q())}`],
    ['Third-party access (CSV)', `/api/trust/third-parties.csv?q=${encodeURIComponent(q())}`],
    ['The map as a picture (PNG)', () => savePng()]], { btnClass: 'btn' });
  // the map as drawn, with its colours, as a PNG at twice the size on screen
  async function savePng() {
    if (S.tab !== 'map') { S.tab = 'map'; address(); drawTabs(); drawView(); await new Promise((r) => requestAnimationFrame(() => r())); }
    const src = mapBox.querySelector('svg.tm2-svg');
    if (!src) { toast('Nothing on the map to save.', true); return; }
    const copy = src.cloneNode(true), all = [src, ...src.querySelectorAll('*')], out = [copy, ...copy.querySelectorAll('*')];
    // presentation attributes, not style attributes: the app's Content-Security-Policy allows no inline styles
    const PROPS = ['fill', 'stroke', 'stroke-width', 'stroke-dasharray', 'opacity', 'fill-opacity', 'stroke-opacity', 'font-family', 'font-size', 'font-weight', 'letter-spacing', 'text-anchor', 'dominant-baseline'];
    all.forEach((el, i) => { const cs = getComputedStyle(el); for (const p of PROPS) { const v = cs.getPropertyValue(p); if (v) out[i].setAttribute(p, v); } out[i].removeAttribute('class'); });
    const W = Number(src.getAttribute('width')), H = Number(src.getAttribute('height'));
    const bg = getComputedStyle(document.body).backgroundColor || '#fff';
    copy.insertBefore(svg('rect', { x: 0, y: 0, width: W, height: H, fill: bg }), copy.firstChild);
    const img = new Image();
    img.onload = () => {
      const c = document.createElement('canvas'); c.width = W * 2; c.height = H * 2;
      const g = c.getContext('2d'); g.scale(2, 2); g.drawImage(img, 0, 0);
      c.toBlob((b) => { const a = h('a', { href: URL.createObjectURL(b), download: `trust-map-${new Date().toISOString().slice(0, 10)}.png` }); document.body.append(a); a.click(); a.remove(); toast('Picture saved'); }, 'image/png');
    };
    img.onerror = () => toast('Could not draw the picture.', true);
    img.src = `data:image/svg+xml;charset=utf-8,${encodeURIComponent(new XMLSerializer().serializeToString(copy))}`;
  }
  const headActions = h('div', { class: 'row', style: 'gap:8px;align-items:center' });
  const asOf = h('span', { class: 'small muted' });
  const header = h('header', { class: 'head' },
    h('div', null, h('div', { class: 'eyebrow' }, 'TRUST MAP'), h('h1', null, m.clouds?.includes('gcp') ? 'Who can get into your cloud' : 'Who can get into your AWS'),
      h('p', { class: 'muted small', style: 'margin:4px 0 0' }, 'AWS from role trust policies: outside accounts, CI and identity providers, SAML, anyone, and your accounts trusting each other. ',
        m.clouds?.includes('gcp') ? 'Google Cloud from IAM: federation, GKE workloads, impersonation, actAs, keys, and roles held by identities from outside; a project is an account, a service account a role. ' : '',
        'IAM users\' keys and resource policies are not part of it (', h('a', { href: '#/identities?type=users' }, 'IAM users'), ' and ', h('a', { href: '#/resources' }, 'Resource access'), ' have their own lists).')),
    headActions);
  // which cloud: both, AWS or Google Cloud (a cloud: term, so it is a filter like the others)
  const cloudSeg = h('div', { class: 'seg', role: 'radiogroup', 'aria-label': 'Cloud' });
  const drawCloud = () => {
    const cur = valuesOf(S.terms, 'cloud')[0] || '';
    cloudSeg.replaceChildren(...[['', 'Both clouds'], ['aws', 'AWS'], ['gcp', 'Google Cloud']].map(([v, l]) => h('button', { type: 'button', role: 'radio', 'aria-checked': String(cur === v),
      onClick: () => { if (cur !== v) changeTerms(setValues(S.terms, 'cloud', v ? [v] : [])); } }, l)));
    cloudSeg.hidden = !m.clouds?.includes('gcp');
  };
  const drawHeader = () => { asOf.textContent = `as of ${ago(m.builtAt)}`; headActions.replaceChildren(cloudSeg, asOf, exportMenu()); drawCloud(); };

  // ---------------------------------------------------------------- filter bar
  const search = h('input', { type: 'search', class: 'tm2-search', 'aria-label': 'Filter by account, source, role or finding', list: 'tm2-keys',
    placeholder: 'Filter: a role, an account, a source… or key:value (finding:account-root)', spellcheck: 'false' });
  search.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && search.value.trim()) { const add = parse(search.value.trim()); search.value = ''; changeTerms([...S.terms, ...add]); }
  });
  const datalist = h('datalist', { id: 'tm2-keys' });
  const menus = h('div', { class: 'tm2-menus' });
  const pills = h('div', { class: 'tm2-pills', 'aria-label': 'Active filters' });
  const warn = h('div', { class: 'tm2-warn', role: 'status' });
  const help = h('details', { class: 'tm2-help' }, h('summary', { class: 'btn sm', 'aria-label': 'Query syntax', title: 'Query syntax' }, '?'),
    h('div', { class: 'tm2-help-pop' },
      h('p', { class: 'small muted', style: 'margin:0 0 6px' }, 'Type key:value and press Enter; a comma means either, - excludes, quotes keep spaces.'),
      [['account:payments-prod', 'roles in that account (name or 12-digit ID)'], ['from:123456789012', 'trusts that AWS account'],
        ['source:external,oidc', 'where it comes from; also github, bitbucket, eks, cognito, identity-center…'], ['finding:account-root', 'has that finding'], ['severity:high', 'has a finding that bad'],
        ['used:yes | iam | no', 'a sign-in came through it · only IAM says used · never'], ['env:production', 'account environment'], ['role:deploy', 'role name contains'],
        ['cond:ExternalId', 'a condition contains'], ['type:root | role | user | oidc | saml', 'what kind of principal'], ['-source:service', 'excludes']]
        .map(([k, v]) => h('div', { class: 'row', style: 'gap:10px;align-items:baseline' }, h('code', null, k), h('span', { class: 'small muted' }, v)))));
  const acctSel = new Set();
  let picker = null;
  ctx.onLeave(() => picker?.destroy());

  function drawFilter() {
    // accounts: the shared picker; the query names them by their 12-digit ID
    const accts = m.map.accounts.filter((a) => a.inScope && !a.planned).map((a) => ({ id: a.id, name: a.name, account_id: a.aws, environment: a.env, roles: a.inbound.roles + a.own + a.services }))
      .sort((a, b) => a.name.localeCompare(b.name));
    const wanted = valuesOf(S.terms, 'account');
    acctSel.clear(); for (const a of accts) if (wanted.includes(a.account_id) || wanted.includes(a.name.toLowerCase()) || wanted.includes(a.id)) acctSel.add(a.id);
    if (!picker) picker = accountPicker({ accounts: accts, selected: acctSel, onChange: () => changeTerms(setValues(S.terms, 'account', [...acctSel].map((id) => accts.find((a) => a.id === id)?.account_id).filter(Boolean))) });
    else picker.setAccounts(accts);
    const toggle = (key, v) => () => { const cur = valuesOf(S.terms, key); changeTerms(setValues(S.terms, key, cur.includes(v) ? cur.filter((x) => x !== v) : [...cur, v])); };
    const envVals = valuesOf(S.terms, 'env'), fromVals = valuesOf(S.terms, 'source'), usedVals = valuesOf(S.terms, 'used'), findVals = valuesOf(S.terms, 'finding');
    const counted = (n) => (n ? `  ${num(n)}` : '');
    const label = (name, vals) => `${name}${vals.length ? ` · ${vals.length}` : ''} ▾`;
    const bySev = (sev) => Object.entries(m.findingCountsAll).filter(([id]) => !USAGE_FINDINGS.has(id) && m.severities[id] === sev).sort((a, b) => b[1] - a[1]);
    const findingItems = ['high', 'medium', 'low', 'info'].flatMap((sev) => { const list = bySev(sev); return list.length ? [[sev === 'info' ? 'Notes' : `${sev[0].toUpperCase()}${sev.slice(1)}`, null], ...list.map(([id, n]) => [`${m.findings[id] || id}${counted(n)}`, toggle('finding', id), { checked: findVals.includes(id) }])] : []; });
    menus.replaceChildren(picker.el,
      menu(label('Environment', envVals), envs().map((e) => [envName(e.id), toggle('env', e.id), { checked: envVals.includes(e.id) }]), { align: 'start', btnClass: 'btn' }),
      menu(label('From', fromVals), FROM.map((x) => (x ? [x[0], toggle('source', x[1]), { checked: fromVals.includes(x[1]) }] : ['Identity providers', null])), { align: 'start', btnClass: 'btn' }),
      menu(label('Finding', findVals), findingItems.length ? findingItems : [['No findings here', null]], { align: 'start', btnClass: 'btn' }),
      menu(label('Used', usedVals), USED.map(([l, v]) => [l, toggle('used', v), { checked: usedVals.includes(v) }]), { align: 'start', btnClass: 'btn' }),
      viewsMenu(), help);
    datalist.replaceChildren(...[...KEYS.map((k) => `${k}:`), ...Object.keys(m.findings).map((id) => `finding:${id}`), ...Object.keys(FROM_NAME).map((v) => `source:${v}`)].map((v) => h('option', { value: v })));
    // one pill per filter, in words
    const nameOf = (key, v) => {
      if (key === 'account') return m.map.accounts.find((a) => a.aws === v || a.id === v || a.name.toLowerCase() === v)?.name || v;
      if (key === 'env') return envName(v);
      if (key === 'source') return FROM_NAME[v] || v;
      if (key === 'finding') return m.findings[v] || v;
      if (key === 'used') return USED_NAME[v] || v;
      if (key === 'roleid') return 'one role';
      if (key === 'new') return /^\d+$/.test(v) ? `last ${v} days` : v === 'weakened' || v === 'guard' ? 'a guard taken off' : 'last 7 days';
      if (['attention', 'expected', 'decided'].includes(key)) return { yes: 'yes', true: 'yes', no: 'no', false: 'no', due: 'review due', accepted: 'accepted' }[v] || v;
      return v;
    };
    pills.replaceChildren(...S.terms.map((t, i) => h('span', { class: `chip ev-on tm2-pill${t.neg ? ' tm2-not' : ''}` },
      h('span', { class: 'muted' }, `${KEY_NAME[t.key] || t.key}${t.neg ? ' is not' : ''}: `), t.value.split(',').map((v) => nameOf(t.key, v.toLowerCase())).join(' or '),
      h('button', { type: 'button', class: 'chip-x', 'aria-label': `Remove ${KEY_NAME[t.key] || t.key} filter`, onClick: () => changeTerms(S.terms.filter((_, j) => j !== i)) }, '×'))),
    S.terms.length ? h('button', { type: 'button', class: 'btn sm', onClick: () => changeTerms([]) }, 'Clear all') : h('span', { class: 'small muted' }, 'No filter: every way in.'));
    // a mistake in the query is named, with the fix one click away
    const fix = (w) => {
      const mean = w.match(/Did you mean (\S+)\?$/)?.[1];
      const key = w.match(/^No filter called "([^"]+)"/)?.[1], bad = w.match(/^No finding called "([^"]+)"/)?.[1];
      if (!mean) return null;
      const next = key ? S.terms.flatMap((t) => (t.key === 'text' && t.value.toLowerCase().replace(/^-/, '').startsWith(`${key}:`) ? parse(mean) : [t]))
        : S.terms.map((t) => (t.key === 'finding' ? { ...t, value: t.value.split(',').map((v) => (v.toLowerCase() === bad ? mean : v)).join(',') } : t));
      return h('button', { type: 'button', class: 'link-btn', style: 'margin-left:8px', onClick: () => changeTerms(next) }, `Use ${mean}`);
    };
    warn.replaceChildren(...(m.warnings || []).map((w) => h('div', null, w, fix(w))));
  }
  // ---------------------------------------------------------------- saved views: a named filter, yours or shared
  let views = [];
  const loadViews = () => get('/views?page=trust').then((r) => { views = r.items; drawFilter(); }).catch(() => {});
  const here = () => { const p = new URLSearchParams(location.hash.split('?')[1] || ''); p.delete('page'); return p.toString(); };
  function viewsMenu() {
    const cur = here();
    return menu(`Views${views.length ? ` · ${views.length}` : ''} ▾`, [
      ...(views.length ? [['Saved', null], ...views.map((v) => [`${v.name}${v.shared ? ` · shared${v.mine ? '' : ` by ${v.owner || 'someone'}`}` : ''}`, `#/trust?${v.query}`, { checked: v.query === cur }])] : [['No saved views yet', null]]),
      ['Save this view…', () => saveView(), { disabled: !cur }],
      ...(views.some((v) => v.mine || (v.shared && session.user.permissions.includes('settings'))) ? [['Remove', null],
        ...views.filter((v) => v.mine || (v.shared && session.user.permissions.includes('settings'))).map((v) => [`Remove “${v.name}”`, async () => {
          try { await api('DELETE', `/views/${v.id}`); toast('View removed'); loadViews(); } catch (x) { toast(x.message, true); } }, { danger: true }])] : []),
    ], { align: 'start', btnClass: 'btn' });
  }
  function saveView() {
    const nameIn = h('input', { class: 'input', placeholder: 'Vendors without ExternalId', 'aria-label': 'Name of the view', maxlength: 80 });
    const shareIn = h('input', { type: 'checkbox' });
    const err = h('p', { class: 'small tm-bad', hidden: true });
    const save = h('button', { class: 'btn primary', onClick: async () => {
      if (!nameIn.value.trim()) { err.hidden = false; err.textContent = 'Give it a name.'; return; }
      save.disabled = true;
      try { await post('/views', { page: 'trust', name: nameIn.value.trim(), query: here(), shared: shareIn.checked }); bg.remove(); toast('View saved'); loadViews(); }
      catch (x) { save.disabled = false; err.hidden = false; err.textContent = x.message; }
    } }, 'Save');
    nameIn.addEventListener('keydown', (e) => { if (e.key === 'Enter') save.click(); });
    const bg = modal('Save this view', h('div', { class: 'stack' },
      h('p', { class: 'small muted', style: 'margin:0' }, 'The filter, the pick and the tab, under a name. It is offered under Views and in the search (Ctrl K).'),
      h('label', { class: 'field' }, h('span', null, 'Name'), nameIn),
      h('label', { class: 'tm2-check' }, shareIn, h('span', null, 'Share it with everyone in the workspace')), err),
    h('div', { class: 'actions' }, h('button', { class: 'btn', onClick: () => bg.remove() }, 'Cancel'), save));
    nameIn.focus();
  }

  const filterBar = h('section', { class: 'card tm2-filter' }, h('div', { class: 'card-b stack', style: 'gap:10px' },
    h('div', { class: 'tm2-filter-row' }, search, datalist, menus), pills, warn));

  // ---------------------------------------------------------------- tiles
  const tiles = h('div', { class: 'tiles tm2-tiles' });
  const has = (key, v) => valuesOf(S.terms, key).includes(v);
  const only = (key, v) => () => changeTerms(has(key, v) ? setValues(S.terms, key, valuesOf(S.terms, key).filter((x) => x !== v)) : setValues(S.terms, key, [v]));
  function drawTiles() {
    const M = m.map, hubs = hubsOf();
    const outside = M.sources.filter((s) => s.group === 'external-account');
    const ci = M.sources.filter((s) => s.group === 'oidc');
    const clusters = M.accounts.reduce((n, a) => n + a.clusterSources, 0);
    const between = M.links.filter((l) => l.kind === 'account' && !hubs.has(l.from)).length;
    const anyone = M.sources.find((s) => s.group === 'public');
    const R = m.review;
    tiles.replaceChildren(
      tile('Needs attention', num(R.attentionHigh + R.attentionMedium), `${num(R.attentionHigh)} high · ${num(R.attentionMedium)} medium${R.expected || R.accepted ? ` · ${num(R.expected + R.accepted)} reviewed` : ''}`,
        { bad: R.attentionHigh > 0, pressed: has('attention', 'yes'), onClick: only('attention', 'yes') }),
      tile('New · 7 days', plural(R.changed7, 'way in', 'ways in'), R.weakened7 ? `${num(R.weakened7)} lost a guard (ExternalId, subject, MFA…)` : 'new trust, or a guard taken off',
        { bad: R.weakened7 > 0, pressed: has('new', '7'), onClick: only('new', '7') }),
      (R.expected || R.expectedDue) ? tile('Expected', plural(R.expected, 'way in', 'ways in'), R.expectedDue ? `${num(R.expectedDue)} due for another look` : 'reviewed and accepted as they are',
        { bad: R.expectedDue > 0, pressed: has('expected', R.expectedDue ? 'due' : 'yes'), onClick: only('expected', R.expectedDue ? 'due' : 'yes') }) : null,
      anyone && tile('Anyone can assume', plural(anyone.roles, 'role'), 'principal "*"', { bad: anyone.worst === 'high', pressed: has('source', 'public'), onClick: only('source', 'public') }),
      tile('From outside', plural(outside.length, 'account'), `${num(outside.filter((s) => !s.vendor && s.cloud !== 'gcp').length)} without ExternalId on every statement${outside.some((s) => s.cloud === 'gcp') ? ` · ${num(outside.filter((s) => s.cloud === 'gcp').length)} in Google Cloud` : ''}`, { pressed: has('source', 'external'), onClick: only('source', 'external') }),
      tile('CI and web identity', plural(ci.length, 'provider'), clusters ? `+ ${plural(clusters, 'EKS cluster')}, counted on their accounts` : 'GitHub, Bitbucket, Google, Cognito…', { pressed: has('source', 'oidc'), onClick: only('source', 'oidc') }),
      tile('Between your accounts', plural(between, 'line'), hubs.size ? `+ ${plural(hubs.size, 'hub')} reaching ${num(hubThreshold())}+ accounts` : 'one account trusting another', { pressed: has('source', 'connected'), onClick: only('source', 'connected') }),
      tile('Never used', plural(m.usage.no, 'way in', 'ways in'), `${num(m.usage.iam)} more only IAM says are used`, { pressed: has('used', 'no'), onClick: only('used', 'no') }));
  }

  // ---------------------------------------------------------------- hubs: accounts whose trust reaches a third of the estate
  const hubThreshold = () => Math.max(5, Math.ceil(m.map.accounts.filter((a) => a.inScope && !a.planned).length / 3));
  function hubsOf() {
    const out = new Map();
    for (const l of m.map.links) if (l.kind === 'account') out.set(l.from, (out.get(l.from) || 0) + 1);
    return new Set([...out].filter(([, n]) => n >= hubThreshold()).map(([id]) => id));
  }

  // ---------------------------------------------------------------- tabs
  const tabBar = h('div', { class: 'tm2-tabbar' });
  const view = h('div', { class: 'tm2-view' });
  const panel = h('aside', { class: 'tm2-panel card', 'aria-label': 'Details' });
  const live = h('div', { class: 'sr-only', 'aria-live': 'polite' });
  const body = h('div', { class: 'tm2-body' }, view, panel);
  function drawTabs() {
    const srcCount = m.summary.reduce((n, g) => n + g.sources.length, 0);
    const tab = (k, text) => h('button', { role: 'tab', 'aria-selected': String(S.tab === k), onClick: () => { S.tab = k; address(); drawTabs(); drawView(); } }, text);
    tabBar.replaceChildren(h('div', { class: 'tabs', role: 'tablist', 'aria-label': 'View' },
      tab('map', 'Map'), tab('grid', 'Grid'), tab('sources', `Sources ${num(srcCount)}`), tab('ways', `Ways in ${num(m.total)}`)),
    S.tab === 'map' && h('div', { class: 'row tm2-mapopts' },
      h('div', { class: 'seg', role: 'radiogroup', 'aria-label': 'Lines shown' },
        ...[['attention', 'Needs attention'], ['all', 'Everything']].map(([k, l]) => h('button', { type: 'button', role: 'radio', 'aria-checked': String(showMode() === k), onClick: () => { S.show = k; address(); drawView(); } }, l))),
      keyBtn()));
  }

  // ---------------------------------------------------------------- the map
  const mapBox = h('div', { class: 'tm2-map', tabindex: '0', role: 'application', 'aria-label': 'Trust map. Arrow keys move between boxes, Enter opens or picks, Escape closes.' });
  const hover = h('div', { class: 'tm2-hover', hidden: true });
  let order = [], focusIdx = -1;
  const showMode = () => S.show || (m.map.links.length <= 40 ? 'all' : 'attention');
  let firstKey = true;
  try { firstKey = !localStorage.getItem('cm-trust-key-seen'); } catch { /* storage may be off */ }
  const keyBox = h('div', { class: 'tm2-key', hidden: !firstKey },
    h('div', { class: 'row', style: 'justify-content:space-between' }, h('b', { class: 'small' }, 'How to read the map'), h('button', { class: 'sp-x', 'aria-label': 'Close the key', onClick: () => { keyBox.hidden = true; try { localStorage.setItem('cm-trust-key-seen', '1'); } catch { /* fine */ } } }, '×')),
    h('div', null, h('i', { class: 'k-line k-high' }), 'High-risk trust behind the line'),
    h('div', null, h('i', { class: 'k-line k-medium' }), 'Loose trust (medium)'),
    h('div', null, h('i', { class: 'k-line k-ok' }), 'Nothing above low'),
    h('div', null, h('i', { class: 'k-line k-ok k-dash' }), 'Dashed: never used (no sign-in, and IAM has no record)'),
    h('div', null, h('i', { class: 'k-arc' }), 'Arcs on the right: your accounts trusting each other'),
    h('div', null, h('i', { class: 'k-box' }), '▸ a group: click to open it · a number: what is inside'),
    h('div', null, h('i', { class: 'k-line k-ok k-thick' }), 'Thicker: more roles behind the line'),
    h('p', { class: 'tiny muted', style: 'margin:4px 0 0' }, 'Hubs (accounts whose trust reaches a third of the estate) and EKS clusters (inside the account they reach) are counted, not drawn: pick one to see its lines.'));
  function keyBtn() { return h('button', { type: 'button', class: 'btn sm', 'aria-expanded': String(!keyBox.hidden), onClick: () => { keyBox.hidden = !keyBox.hidden; drawTabs(); } }, 'Key'); }

  // which node a source or an account is drawn as: itself, or its group while the group is closed
  const accountNode = (a) => (S.open.has(`e:${envOf(a)}`) ? a.id : `e:${envOf(a)}`);
  const envOf = (a) => (ENV_ORDER.includes(a.env) ? a.env : 'other');
  const sourceNode = (s) => (S.open.has(`g:${s.group}`) ? s.id : `g:${s.group}`);
  function known(id) {
    const M = m.map;
    return M.accounts.some((a) => a.id === id) || M.sources.some((s) => s.id === id) || M.links.some((l) => l.id === id);
  }

  function drawMap() {
    const M = m.map, hubs = hubsOf();
    const acc = new Map(M.accounts.map((a) => [a.id, a])), src = new Map(M.sources.map((s) => [s.id, s]));
    const mode = showMode();
    const focus = S.sel && known(S.sel) ? S.sel : null;
    // the lines to draw: everything, or what needs attention; around a pick, everything touching it
    let lines;
    if (focus) {
      const l = M.links.find((x) => x.id === focus);
      lines = l ? [l] : M.links.filter((x) => x.from === focus || x.to === focus);
    } else lines = M.links.filter((l) => !(l.kind === 'account' && hubs.has(l.from)) && (mode === 'all' || ATTENTION.has(l.worst)));
    // the groups open by default: everything on a small map
    if (!S.opened && !focus && M.links.length <= 40) { for (const [g] of KINDS) S.open.add(`g:${g}`); for (const e of [...ENV_ORDER, 'other']) S.open.add(`e:${e}`); }

    // nodes on each side
    const left = [], right = [];
    const inFocus = new Set();
    if (focus) { inFocus.add(focus); for (const l of lines) { inFocus.add(l.from); inFocus.add(l.to); } }
    const nodeOfSrc = (s) => (focus ? s.id : sourceNode(s));
    const nodeOfAcc = (a) => (focus ? a.id : accountNode(a));
    // left: kinds of source, open ones with their sources
    for (const [g, name] of KINDS) {
      const all = M.sources.filter((s) => s.group === g && (!focus || inFocus.has(s.id)));
      if (!all.length) continue;
      const withLines = new Set(lines.filter((l) => l.kind === 'outside').map((l) => l.from));
      const shown = all.filter((s) => focus || mode === 'all' || withLines.has(s.id));
      if (focus) { left.push({ head: name, n: all.length }); all.forEach((s) => left.push({ id: s.id, src: s })); continue; }
      const open = S.open.has(`g:${g}`);
      left.push({ id: `g:${g}`, group: g, name, n: all.length, worst: all.reduce((w, s) => (SEV_ORDER[s.worst] < SEV_ORDER[w] ? s.worst : w), 'none'), open, hidden: all.length - shown.length });
      if (open) { shown.forEach((s) => left.push({ id: s.id, src: s, indent: true })); if (all.length > shown.length) left.push({ more: `+ ${num(all.length - shown.length)} with nothing to flag`, group: g, indent: true }); }
    }
    // right: environments, open ones with their accounts; hubs are listed under the map instead of drawing their arcs
    // every account you can see when nothing is filtered; with a filter, only those it leaves something in
    const filtered = S.terms.length > 0;
    const accounts = M.accounts.filter((a) => (focus ? inFocus.has(a.id) : lines.some((l) => l.from === a.id || l.to === a.id)
      || (filtered ? a.inbound.roles + a.own + a.services > 0 : a.inScope)));
    for (const env of [...ENV_ORDER, 'other']) {
      const all = accounts.filter((a) => envOf(a) === env).sort((a, b) => (b.inbound.high - a.inbound.high) || (b.inbound.medium - a.inbound.medium) || a.name.localeCompare(b.name));
      if (!all.length) continue;
      const name = env === 'other' ? 'Other' : envName(env);
      if (focus) { right.push({ head: name, n: all.length, color: ENV_COLOR[env] }); all.forEach((a) => right.push({ id: a.id, acc: a })); continue; }
      const touched = new Set(lines.flatMap((l) => [l.to, l.kind === 'account' ? l.from : null]));
      const shown = all.filter((a) => mode === 'all' || touched.has(a.id));
      const open = S.open.has(`e:${env}`);
      right.push({ id: `e:${env}`, env, name, n: all.length, color: ENV_COLOR[env], high: all.reduce((n, a) => n + a.inbound.high, 0), medium: all.reduce((n, a) => n + a.inbound.medium, 0), open });
      if (open) { shown.forEach((a) => right.push({ id: a.id, acc: a, indent: true })); if (all.length > shown.length) right.push({ more: `+ ${num(all.length - shown.length)} with nothing to flag`, env, indent: true }); }
    }

    // bundle the lines between what is drawn
    const bundles = new Map();
    for (const l of lines) {
      const a = l.kind === 'outside' ? (src.get(l.from) ? nodeOfSrc(src.get(l.from)) : null) : (acc.get(l.from) ? nodeOfAcc(acc.get(l.from)) : null);
      const b = acc.get(l.to) ? nodeOfAcc(acc.get(l.to)) : null;
      if (!a || !b || a === b) continue;
      const k = `${a}>${b}`;
      if (!bundles.has(k)) bundles.set(k, { id: k, a, b, kind: l.kind, worst: 'none', roles: 0, lines: [], sessions: 0, iamUsed: false });
      const x = bundles.get(k);
      x.lines.push(l); x.roles += l.roles; x.sessions += l.sessions; x.iamUsed ||= l.iamUsed;
      if (SEV_ORDER[l.worst] < SEV_ORDER[x.worst]) x.worst = l.worst;
    }

    // layout in real pixels for the width there is, so text stays readable
    const W = Math.max(560, Math.floor(mapBox.clientWidth || 900));
    const NODE = 36, GAP = 6, HEAD = 26, LX = 0, LW = Math.round(Math.min(310, Math.max(200, W * 0.34))), RX = Math.round(W * 0.47), RW = Math.round(Math.min(290, Math.max(190, W * 0.3))), ARC = RX + RW;
    const pos = new Map();
    const place = (list, x, w) => {
      let y = 4;
      const out = [];
      for (const n of list) {
        if (n.head) { out.push({ ...n, x, y: y + 16 }); y += HEAD; continue; }
        const ind = n.indent ? 14 : 0, hgt = n.more ? 26 : NODE;
        const p = { x: x + ind, y, w: w - ind, h: hgt };
        if (n.id) pos.set(n.id, p);
        out.push({ ...n, ...p });
        y += hgt + GAP;
      }
      return [out, y];
    };
    const [L, lh] = place(left, LX, LW), [R, rh] = place(right, RX, RW);
    const hubList = focus ? [] : [...hubs].map((id) => acc.get(id)).filter(Boolean);
    const H = Math.max(lh, rh, 120) + 8;

    const s = svg('svg', { width: W, height: H, viewBox: `0 0 ${W} ${H}`, class: 'tm2-svg', role: 'img', 'aria-label': `Trust map: ${plural(bundles.size, 'line')} shown` });
    const marker = (k) => svg('marker', { id: `tm2-a-${k}`, viewBox: '0 0 10 10', refX: 9, refY: 5, markerWidth: 6, markerHeight: 6, orient: 'auto-start-reverse' }, svg('path', { d: 'M0 0 L10 5 L0 10 z', class: `tm2-m-${k}` }));
    s.append(svg('defs', null, marker('high'), marker('medium'), marker('ok')),
      svg('rect', { x: 0, y: 0, width: W, height: H, class: 'tm2-bg', onClick: () => pick(null) }));
    const sevClass = (w) => (w === 'high' ? 'high' : w === 'medium' ? 'medium' : 'ok');
    const drawn = [...bundles.values()].sort((a, b) => SEV_ORDER[b.worst] - SEV_ORDER[a.worst]);
    for (const x of drawn) {
      const a = pos.get(x.a), b = pos.get(x.b);
      if (!a || !b) continue;
      const ya = a.y + a.h / 2, yb = b.y + b.h / 2;
      let d;
      if (x.kind === 'outside') d = `M${a.x + a.w} ${ya} C ${a.x + a.w + 90} ${ya}, ${b.x - 90} ${yb}, ${b.x - 4} ${yb}`;
      else { const o = ya < yb ? -4 : 4, bulge = Math.min(W - ARC - 12, 30 + Math.abs(yb - ya) * 0.4); d = `M${ARC} ${ya + o} C ${ARC + bulge} ${ya + o}, ${ARC + bulge} ${yb - o}, ${ARC + 4} ${yb - o}`; }
      const k = sevClass(x.worst);
      const one = x.lines.length === 1 ? x.lines[0] : null;
      const title = `${nameOf(x.a)} → ${nameOf(x.b)} · ${x.lines.length > 1 ? `${plural(x.lines.length, 'line')} · ` : ''}${plural(x.roles, 'role')}${x.worst !== 'none' ? ` · worst ${x.worst}` : ''} · ${usedText(x)}`;
      s.append(svg('path', { d, class: `tm2-line tm2-l-${k}${x.sessions || x.iamUsed ? '' : ' tm2-dash'}${one && S.sel === one.id ? ' tm2-sel' : ''}`,
        'stroke-width': Math.min(6, 1.4 + Math.log2(1 + x.roles) * 0.9), 'marker-end': `url(#tm2-a-${k})` }));
      s.append(svg('path', { d, class: 'tm2-hit', onClick: (e) => { e.stopPropagation(); if (one) pick(one.id); else openBoth(x); },
        onMouseenter: (e) => showHover(e, title), onMousemove: (e) => moveHover(e), onMouseleave: hideHover }));
    }
    // boxes
    order = [];
    const box = (n) => {
      if (n.head) return svg('text', { x: n.x, y: n.y, class: 'tm2-head', fill: n.color || null }, `${n.head.toUpperCase()} · ${n.n}`);
      if (n.more) return svg('g', { class: 'tm2-more', onClick: () => { S.show = 'all'; address(); drawTabs(); drawView(); } }, svg('text', { x: n.x + 4, y: n.y + 17, class: 'tm2-sub' }, `${n.more} · show`));
      let label, sub, worst, kind, dashed = false, chevron = null, color = null;
      if (n.group) { label = n.name; sub = `${plural(n.n, 'source')}${n.hidden && n.open ? ` · ${num(n.hidden)} quiet` : ''}`; worst = n.worst; kind = 'group'; chevron = n.open ? '▾' : '▸'; }
      else if (n.env) { label = n.name; sub = `${plural(n.n, 'account')}${n.high ? ` · ${num(n.high)} high` : ''}${n.medium ? ` · ${num(n.medium)} medium` : ''}`; kind = 'group'; chevron = n.open ? '▾' : '▸'; color = n.color; }
      else if (n.src) {
        const x = n.src; label = x.label; worst = x.worst; kind = 'source';
        sub = [x.group === 'external-account' ? (x.cloud === 'gcp' ? 'outside your organization' : x.vendor ? 'ExternalId' : 'no ExternalId') : SHORT[x.group], plural(x.roles, x.cloud === 'gcp' ? 'way in' : 'role'), plural(x.accounts, x.cloud === 'gcp' ? 'project' : 'account'), x.highRiskRoles ? `${num(x.highRiskRoles)} high-risk` : null].filter(Boolean).join(' · ');
      } else {
        const a = n.acc; label = a.name; kind = 'account'; color = ENV_COLOR[a.env] || null; dashed = !a.inScope || a.planned;
        sub = a.planned ? `${a.aws} · planned, not scanned` : !a.inScope ? `${a.aws} · not in your scope`
          : `${a.cloud === 'gcp' ? 'Google Cloud' : a.aws} · ${a.inbound.high ? `${num(a.inbound.high)} high · ` : ''}${a.inbound.medium ? `${num(a.inbound.medium)} medium · ` : ''}${plural(a.inbound.roles, a.cloud === 'gcp' ? 'service account' : 'role')} reachable${a.clusterSources ? ` · ${plural(a.clusterSources, 'cluster')}` : ''}`;
        if (hubs.has(a.id)) sub = `${a.aws} · hub: reaches ${num(M.links.filter((l) => l.from === a.id).length)} accounts`;
      }
      const isSel = S.sel === n.id;
      const idx = order.push(n) - 1;
      const g = svg('g', { class: `tm2-node tm2-${kind}${isSel ? ' tm2-picked' : ''}${focusIdx === idx ? ' tm2-kfocus' : ''}`, id: `tm2-n-${idx}`,
        onClick: (e) => { e.stopPropagation(); activate(n); }, onMouseenter: (e) => showHover(e, `${label} · ${sub}`), onMousemove: (e) => moveHover(e), onMouseleave: hideHover },
        svg('rect', { x: n.x, y: n.y, width: n.w, height: n.h, class: `tm2-box${dashed ? ' tm2-dashed' : ''}` }),
        color && svg('rect', { x: n.x, y: n.y, width: 4, height: n.h, fill: color }),
        svg('text', { x: n.x + 12, y: n.y + 15, class: 'tm2-label' }, `${chevron ? `${chevron} ` : ''}${cut(label, Math.floor((n.w - 40) / 7))}`),
        svg('text', { x: n.x + 12, y: n.y + 29, class: 'tm2-sub' }, cut(sub, Math.floor((n.w - 30) / 6))),
        worst && ATTENTION.has(worst) && svg('circle', { cx: n.x + n.w - 12, cy: n.y + n.h / 2, r: 4.5, class: `tm2-dot-${worst}` }));
      return g;
    };
    for (const n of [...L, ...R]) s.append(box(n));
    mapBox.setAttribute('aria-activedescendant', focusIdx >= 0 ? `tm2-n-${focusIdx}` : '');
    const hubRow = hubList.length ? h('div', { class: 'tm2-hubs' }, h('span', { class: 'tm2-cap' }, 'HUBS'),
      hubList.map((a) => h('button', { type: 'button', class: 'chip', title: `${a.name} trusts into ${M.links.filter((l) => l.from === a.id).length} of your accounts. Pick it to see the lines.`, onClick: () => pick(a.id) },
        `${a.name} → ${num(M.links.filter((l) => l.from === a.id).length)}`))) : null;
    const top = h('div', { class: 'tm2-maphead' },
      focus ? h('div', { class: 'row', style: 'gap:8px;align-items:center' }, h('button', { type: 'button', class: 'btn sm', onClick: () => pick(null) }, '← Back to the whole map'),
        h('span', { class: 'small muted' }, `Around ${nameOf(focus)}: every line, whatever its severity`))
        : h('div', { class: 'tm2-cols' }, h('span', null, 'WHERE IT COMES FROM'), h('span', null, 'YOUR ACCOUNTS'), h('span', null, 'BETWEEN THEM')),
      !focus && mode === 'attention' && h('span', { class: 'small muted' }, `${plural(lines.length, 'line')} need attention of ${num(M.links.length)}. `,
        h('button', { type: 'button', class: 'link-btn', onClick: () => { S.show = 'all'; address(); drawTabs(); drawView(); } }, 'Show everything')));
    const emptyNote = !L.length && !R.length ? h('p', { class: 'muted small', style: 'padding:16px' }, S.terms.length ? 'Nothing matches this filter.' : 'No roles yet.') : null;
    const canvas = h('div', { class: 'tm2-canvas' }, emptyNote || s, hover);
    mapBox.replaceChildren(top, keyBox, canvas, hubRow);
  }
  // a bundled line: open the groups at both ends
  function openBoth(x) { S.opened = true; for (const id of [x.a, x.b]) if (/^[ge]:/.test(id)) S.open.add(id); address(); drawView(); }
  function activate(n) {
    if (n.group || n.env) { S.opened = true; S.open.has(n.id) ? S.open.delete(n.id) : S.open.add(n.id); address(); drawView(); return; }
    if (n.more) { S.show = 'all'; address(); drawTabs(); drawView(); return; }
    pick(n.id);
  }
  function nameOf(id) {
    if (!id) return '';
    if (/^g:/.test(id)) return KIND_NAME[id.slice(2)] || id;
    if (/^e:/.test(id)) return id === 'e:other' ? 'Other' : envName(id.slice(2));
    if (id.includes('>')) { const [a, b] = id.split('>'); return `${nameOf(a)} → ${nameOf(b)}`; }
    return m.map.accounts.find((a) => a.id === id)?.name || m.map.sources.find((s) => s.id === id)?.label || id;
  }
  // one hover card, drawn by the page (also on keyboard focus)
  function showHover(e, text) { hover.textContent = text; hover.hidden = false; moveHover(e); }
  function moveHover(e) {
    const r = mapBox.querySelector('.tm2-canvas')?.getBoundingClientRect(); if (!r) return;
    hover.style.left = `${Math.min(e.clientX - r.left + 14, r.width - 300)}px`; hover.style.top = `${e.clientY - r.top + 14}px`;
  }
  function hideHover() { hover.hidden = true; }
  // keyboard: the map is one tab stop; arrows move between boxes, Enter opens or picks, Escape closes
  mapBox.addEventListener('keydown', (e) => {
    const n = order.length; if (!n) return;
    if (['ArrowDown', 'ArrowUp', 'ArrowLeft', 'ArrowRight'].includes(e.key)) {
      e.preventDefault();
      const cur = order[focusIdx];
      if (e.key === 'ArrowDown') focusIdx = Math.min(n - 1, focusIdx + 1);
      else if (e.key === 'ArrowUp') focusIdx = Math.max(0, focusIdx - 1);
      else { // jump to the other column, at about the same height
        const right = e.key === 'ArrowRight';
        const cands = order.map((x, i) => [x, i]).filter(([x]) => (right ? x.x > (cur?.x ?? -1) : x.x < (cur?.x ?? 1e9)) && !x.more);
        if (cands.length) focusIdx = cands.sort((a, b) => Math.abs(a[0].y - (cur?.y || 0)) - Math.abs(b[0].y - (cur?.y || 0)))[0][1];
      }
      const x = order[focusIdx];
      mapBox.querySelectorAll('.tm2-kfocus').forEach((el) => el.classList.remove('tm2-kfocus'));
      const el = mapBox.querySelector(`#tm2-n-${focusIdx}`); el?.classList.add('tm2-kfocus'); el?.scrollIntoView({ block: 'nearest' });
      mapBox.setAttribute('aria-activedescendant', `tm2-n-${focusIdx}`);
      live.textContent = x ? `${x.name || x.src?.label || x.acc?.name || x.more || ''}` : '';
    } else if (e.key === 'Enter' || e.key === ' ') { if (order[focusIdx]) { e.preventDefault(); activate(order[focusIdx]); } }
  });
  mapBox.addEventListener('focus', () => { if (focusIdx < 0 && order.length) { focusIdx = 0; mapBox.querySelector('#tm2-n-0')?.classList.add('tm2-kfocus'); } });

  // ---------------------------------------------------------------- sources tab
  function drawSources() {
    const rows = m.summary.flatMap((g) => g.sources.map((s) => ({ ...s, group: g.group })));
    const by = { worst: (a, b) => SEV_ORDER[a.worst] - SEV_ORDER[b.worst] || b.roles - a.roles, source: (a, b) => a.label.localeCompare(b.label), roles: (a, b) => b.roles - a.roles,
      accounts: (a, b) => b.accounts - a.accounts, sessions: (a, b) => b.sessions - a.sessions, used: (a, b) => new Date(b.lastSeen || 0) - new Date(a.lastSeen || 0), high: (a, b) => b.highRiskRoles - a.highRiskRoles,
      admin: (a, b) => b.adminAccounts - a.adminAccounts, first: (a, b) => new Date(a.firstSeen || 8.64e15) - new Date(b.firstSeen || 8.64e15) };
    rows.sort(by[S.srcSort] || by.worst);
    const th = (k, l) => h('th', { 'aria-sort': S.srcSort === k ? 'descending' : null }, by[k] ? h('button', { type: 'button', class: 'th-sort', onClick: () => { S.srcSort = k; drawView(); } }, l) : l);
    const open = (s) => { if (s.node && known(s.node)) pick(s.node); else changeTerms([...S.terms, ...parse(s.query)]); };
    view.replaceChildren(h('section', { class: 'card' },
      h('div', { class: 'card-h' }, h('div', null, h('h2', null, 'Where it comes from'), h('p', { class: 'small muted', style: 'margin:2px 0 0' }, 'Every source, inside your accounts too. Pick one for its details; one with no box on the map filters to it.'))),
      rows.length ? h('div', { class: 'table-wrap' }, h('table', { class: 'tbl tm2-src' },
        h('thead', null, h('tr', null, th('source', 'Source'), th('worst', 'Worst'), th('roles', 'Roles'), th('accounts', 'Accounts'), th('high', 'High-risk roles'), th('admin', 'Administers'), h('th', null, 'Findings'), th('sessions', 'Sessions'), th('first', 'First seen'), th('used', 'Last sign-in'))),
        h('tbody', null, rows.map((s) => h('tr', { class: S.sel && s.node === S.sel ? 'tm2-row-sel' : null },
          h('td', null, h('button', { type: 'button', class: 'link-btn tm2-srcname', onClick: () => open(s) }, s.label), h('span', { class: `src-tag g-${s.group}`, style: 'margin-left:8px' }, s.pkind === 'eks' ? 'EKS' : SHORT[s.group] || s.group),
            s.named?.owner && h('div', { class: 'tiny muted' }, `owner: ${s.named.owner}`), s.named?.vendor && !s.named.owner && h('div', { class: 'tiny muted' }, 'known vendor')),
          h('td', null, sevBadge(s.worst) || h('span', { class: 'muted small' }, '—')), h('td', { class: 'num' }, num(s.roles)), h('td', { class: 'num' }, num(s.accounts)),
          h('td', { class: 'num' }, s.highRiskRoles ? h('b', null, num(s.highRiskRoles)) : '—'), h('td', { class: 'num', title: 'Accounts where it reaches an administrator role' }, s.adminAccounts ? h('b', null, plural(s.adminAccounts, 'account')) : '—'),
          h('td', { class: 'num' }, s.findings ? num(s.findings) : '—'),
          h('td', { class: 'num' }, s.sessions ? num(s.sessions) : '—'), h('td', { class: 'small' }, s.firstSeen ? ago(s.firstSeen) : '—'), h('td', { class: 'small' }, s.lastSeen ? ago(s.lastSeen) : s.group === 'service' ? '—' : h('span', { class: 'muted' }, 'none seen')))))))
        : h('div', { class: 'card-b' }, h('p', { class: 'muted small' }, 'Nothing matches this filter.'))));
  }

  // ---------------------------------------------------------------- ways in tab, paged by the server
  let ways = null, waysKey = '';
  const guards = (conds) => {
    const tags = [];
    const any = (re) => conds.some((c) => re.test(c));
    if (any(/^sts:ExternalId /i)) tags.push('ExternalId');
    if (any(/:sub /i)) tags.push('subject');
    if (any(/:aud /i)) tags.push('audience');
    if (any(/:amr /i)) tags.push('amr');
    if (any(/^aws:MultiFactorAuth/i)) tags.push('MFA');
    if (any(/^aws:Principal(OrgID|OrgPaths) /i)) tags.push('organisation');
    if (any(/^aws:PrincipalArn /i)) tags.push('principal ARN');
    if (any(/^aws:SourceIp /i)) tags.push('source IP');
    return tags;
  };
  async function loadWays() {
    const key = JSON.stringify([q(), S.sel, S.sort, S.dir, S.page, S.group]);
    if (key === waysKey && ways) return drawWays();
    waysKey = key;
    view.classList.add('tm2-busy');
    try {
      const sel = S.sel ? `&sel=${encodeURIComponent(S.sel)}` : '';
      const r = S.group ? await get(`/trust/groups?q=${encodeURIComponent(q())}${sel}&page=${S.page}&size=${PAGE}`)
        : await get(`/trust/ways?q=${encodeURIComponent(q())}${sel}&sort=${S.sort}&dir=${S.dir}&page=${S.page}&size=${PAGE}`);
      if (key !== waysKey) return;
      ways = r; drawWays();
    } finally { view.classList.remove('tm2-busy'); }
  }
  // ---------------------------------------------------------------- review: decisions, expected trust, what changed
  function afterReview(msg) { toast(msg); waysKey = ''; lineKey = ''; refetch(); }
  const DECISION = { accept: 'Accepted', investigate: 'Investigating' };
  function reviewChips(e) {
    const out = [];
    if (e.change) out.push(h('span', { class: `tm2-chip ${e.change.kind === 'weakened' ? 'bad' : 'new'}`, title: e.change.kind === 'weakened' ? `Taken off ${ago(e.change.at)}: ${e.change.guards.join(', ')}` : `${e.change.roleCreated ? 'Role created' : 'Trust added'} ${ago(e.change.at)}` },
      e.change.kind === 'weakened' ? `GUARD OFF · ${ago(e.change.at)}` : `NEW · ${ago(e.change.at)}`));
    if (e.expected) out.push(h('span', { class: 'tm2-chip ok', title: `${e.expected.note}${e.expected.by ? ` — ${e.expected.by}` : ''}` }, 'EXPECTED'));
    else if (e.expectedDue) out.push(h('span', { class: 'tm2-chip warn', title: `Expected until ${e.expectedDue.reviewBy}: ${e.expectedDue.note}` }, 'REVIEW DUE'));
    else if (e.decided) out.push(h('span', { class: `tm2-chip ${e.accepted ? 'ok' : 'warn'}` }, e.accepted ? 'ACCEPTED' : 'DECIDED'));
    return out;
  }
  async function decide(f, decision) {
    try {
      if (decision) await post(`/flags/${f.id}/decision`, { decision }); else await api('DELETE', `/flags/${f.id}/decision`);
      afterReview(decision ? `${DECISION[decision]}: ${FIND_TITLE(f.finding)}` : 'Decision cleared');
    } catch (err) { toast(err.message, true); }
  }
  const FIND_TITLE = (id) => m.findings?.[id] || id;
  function decisionsBox(e) {
    if (!e.flags?.length) return null;
    return h('div', null, h('div', { class: 'tm2-cap' }, 'REVIEW'),
      ...e.flags.map((f) => h('div', { class: 'tm2-decide' },
        h('span', { class: 'small' }, FIND_TITLE(f.finding)),
        f.decision ? h('span', { class: `tm2-chip ${f.decision === 'accept' ? 'ok' : 'warn'}`, title: [f.note, f.by, f.at && ago(f.at)].filter(Boolean).join(' · ') }, DECISION[f.decision] || f.decision) : null,
        !f.id ? h('span', { class: 'tiny muted' }, 'in the Findings inbox within a minute')
          : canDecide() ? h('span', { class: 'row', style: 'gap:4px' },
            f.decision !== 'accept' && h('button', { type: 'button', class: 'btn xs', onClick: () => decide(f, 'accept') }, 'Accept'),
            f.decision !== 'investigate' && h('button', { type: 'button', class: 'btn xs', onClick: () => decide(f, 'investigate') }, 'Investigate'),
            f.decision && h('button', { type: 'button', class: 'btn xs ghost', onClick: () => decide(f, null) }, 'Clear'))
          : null)),
      h('a', { class: 'tiny', href: `#/findings?category=trust&q=${encodeURIComponent(e.role)}` }, 'In the Findings inbox →'));
  }
  /** "Mark as expected…": who it comes from is fixed; which roles, accounts and findings it covers, why, and until when. */
  async function expectDialog({ source, sourceLabel, roles = '*', accounts = [], ways: given = null, sel = null }) {
    let rows = given;
    if (!rows) rows = (await get(`/trust/ways?q=${encodeURIComponent(q())}&sel=${encodeURIComponent(sel)}&size=500`)).rows;
    const findings = [...new Set(rows.flatMap((e) => e.findings.filter((f) => f.severity !== 'info').map((f) => f.id)))];
    const year = new Date(Date.now() + 365 * 864e5).toISOString().slice(0, 10);
    const rolesIn = h('input', { class: 'input', value: roles, 'aria-label': 'Roles it covers' });
    const acctIn = h('input', { class: 'input', value: accounts.join(', '), placeholder: 'every account', 'aria-label': 'Accounts it covers' });
    const noteIn = h('textarea', { class: 'input', rows: 3, placeholder: 'Why this is fine: the vendor and contract, the pipeline, the break-glass process…', 'aria-label': 'Why it is expected' });
    const dateIn = h('input', { class: 'input', type: 'date', value: year, 'aria-label': 'Look again by' });
    const boxes = findings.map((id) => h('input', { type: 'checkbox', checked: true, value: id }));
    const err = h('p', { class: 'small tm-bad', hidden: true });
    const save = h('button', { class: 'btn primary', onClick: async () => {
      const accts = acctIn.value.split(/[\s,]+/).filter(Boolean);
      if (accts.some((a) => !/^\d{12}$/.test(a))) { err.hidden = false; err.textContent = 'Accounts are 12-digit IDs, separated by commas.'; return; }
      if (noteIn.value.trim().length < 3) { err.hidden = false; err.textContent = 'Say why it is expected; the next reviewer reads this.'; return; }
      save.disabled = true;
      try {
        await post('/trust/expected', { source, sourceLabel, roles: rolesIn.value.trim() || '*', accounts: accts, findings: boxes.filter((b) => b.checked).map((b) => b.value), note: noteIn.value.trim(), reviewBy: dateIn.value || null });
        bg.remove(); afterReview('Marked as expected');
      } catch (x) { save.disabled = false; err.hidden = false; err.textContent = x.message; }
    } }, 'Mark as expected');
    const bg = modal('Mark as expected', h('div', { class: 'stack' },
      h('p', { class: 'small muted', style: 'margin:0' }, 'Ways in from ', h('b', null, sourceLabel), ' that match stay on the map and in exports, but leave "Needs attention" and the Findings inbox. A finding not ticked here, or the review date passing, brings them back.'),
      h('label', { class: 'field' }, h('span', null, 'Roles (a name, or a pattern such as ci-*)'), rolesIn),
      h('label', { class: 'field' }, h('span', null, 'Accounts (12-digit IDs; empty for every account)'), acctIn),
      findings.length ? h('div', { class: 'tm2-checks', role: 'group', 'aria-label': 'Accepted with these findings' }, h('div', { class: 'label' }, 'Accepted with these findings'), ...boxes.map((b) => h('label', { class: 'tm2-check' }, b, h('span', null, FIND_TITLE(b.value)))))
        : h('p', { class: 'small muted' }, 'No findings: it would only be marked as reviewed.'),
      h('label', { class: 'field' }, h('span', null, 'Why'), noteIn),
      h('label', { class: 'field' }, h('span', null, 'Look again by'), dateIn), err),
    h('div', { class: 'actions' }, h('button', { class: 'btn', onClick: () => bg.remove() }, 'Cancel'), save));
    noteIn.focus();
  }
  // names for where trust comes from: shown to everyone, so set by reviewers who see every account
  const canName = () => canDecide() && !session.user.scope_accounts;
  const nameBtn = (s) => canName() && s.id.startsWith('src:') && h('button', { type: 'button', class: 'btn sm', onClick: () => nameDialog(s) }, s.named?.custom ? 'Edit the name…' : 'Name it…');
  function nameDialog(s) {
    const own = s.named?.custom ? s.named : null;
    const nameIn = h('input', { class: 'input', value: own?.name || s.named?.name || '', placeholder: 'Vendor or team name', maxlength: 120, 'aria-label': 'Name' });
    const ownerIn = h('input', { class: 'input', value: own?.owner || s.named?.owner || '', placeholder: 'Who looks after it here', maxlength: 120, 'aria-label': 'Owner' });
    const purposeIn = h('textarea', { class: 'input', rows: 2, placeholder: 'What it is for: monitoring, backups, the deploy pipeline…', 'aria-label': 'What it is for' }, own?.purpose || s.named?.purpose || '');
    const dateIn = h('input', { class: 'input', type: 'date', value: s.named?.reviewBy ? String(s.named.reviewBy).slice(0, 10) : '', 'aria-label': 'Review by' });
    const err = h('p', { class: 'small tm-bad', hidden: true });
    const save = h('button', { class: 'btn primary', onClick: async () => {
      if (!nameIn.value.trim()) { err.hidden = false; err.textContent = 'Give it a name.'; return; }
      save.disabled = true;
      try { await post('/trust/names', { source: s.id, name: nameIn.value.trim(), owner: ownerIn.value.trim() || null, purpose: purposeIn.value.trim() || null, reviewBy: dateIn.value || null }); bg.remove(); afterReview('Named'); }
      catch (x) { save.disabled = false; err.hidden = false; err.textContent = x.message; }
    } }, 'Save');
    const bg = modal(`Name ${s.aws || s.label}`, h('div', { class: 'stack' },
      h('p', { class: 'small muted', style: 'margin:0' }, 'Everyone sees this name on the Trust map, in its exports and in the search.', s.named?.vendor ? ` The public list of known AWS accounts calls it ${s.named.vendor}.` : ''),
      h('label', { class: 'field' }, h('span', null, 'Name'), nameIn), h('label', { class: 'field' }, h('span', null, 'Owner'), ownerIn),
      h('label', { class: 'field' }, h('span', null, 'What it is for'), purposeIn), h('label', { class: 'field' }, h('span', null, 'Review by'), dateIn), err),
    h('div', { class: 'actions' }, own && h('button', { class: 'btn danger', onClick: async () => {
      try { await api('DELETE', `/trust/names?source=${encodeURIComponent(s.id)}`); bg.remove(); afterReview('Name removed'); } catch (x) { toast(x.message, true); } } }, 'Remove the name'),
    h('span', { class: 'grow' }), h('button', { class: 'btn', onClick: () => bg.remove() }, 'Cancel'), save));
    nameIn.focus();
  }
  async function unexpect(id) {
    try { await api('DELETE', `/trust/expected/${id}`); afterReview('No longer expected'); } catch (err) { toast(err.message, true); }
  }
  const expectBtn = (opts) => canDecide() && h('button', { type: 'button', class: 'btn sm', onClick: () => expectDialog(opts).catch((x) => toast(x.message, true)) }, 'Mark as expected…');

  const groupSwitch = () => h('div', { class: 'seg', role: 'radiogroup', 'aria-label': 'How ways in are listed' },
    ...[[false, 'Each way in'], [true, 'Group the same trust']].map(([v, l]) => h('button', { type: 'button', role: 'radio', 'aria-checked': String(S.group === v),
      onClick: () => { if (S.group === v) return; S.group = v; S.page = 0; S.expanded.clear(); ways = null; address(); drawView(); } }, l)));
  async function decideGroup(g, decision) {
    try {
      for (let i = 0; i < g.undecided.length; i += 200) await post('/findings/decisions', { ids: g.undecided.slice(i, i + 200), decision, note: `Same trust in ${g.accounts} accounts, decided together on the Trust map` });
      afterReview(`${DECISION[decision]}: ${plural(g.undecided.length, 'finding')} in ${plural(g.accounts, 'account')}`);
    } catch (err) { toast(err.message, true); }
  }
  function drawGroups() {
    const total = ways.total;
    const row = (g) => {
      const id = `g|${g.key}`, open = S.expanded.has(id), gs = guards(g.conditions);
      return h('div', { class: `tm2-way tm2-grp${open ? ' open' : ''}`, role: 'row' },
        h('button', { type: 'button', class: 'tm2-way-main', 'aria-expanded': String(open), onClick: () => { open ? S.expanded.delete(id) : S.expanded.add(id); drawWays(); } },
          h('span', { class: `tm2-dot tm2-dot-${g.attention ? g.worst : 'none'}`, title: g.worst }),
          h('span', { class: 'tm2-c-role' }, h('span', { class: 'name', title: g.role }, ...roleName(g.role), g.expected === g.ways ? h('span', { class: 'tm2-chip ok' }, 'EXPECTED') : g.accepted === g.ways ? h('span', { class: 'tm2-chip ok' }, 'ACCEPTED') : null),
            h('span', { class: 'tiny muted' }, `in ${plural(g.accounts, 'account')}${g.ways > g.accounts ? ` · ${plural(g.ways, 'statement')}` : ''}`)),
          h('span', { class: 'tm2-c-from' }, h('span', { class: 'tm2-src' }, h('span', { class: `src-tag g-${g.group}` }, g.pkind === 'eks' ? 'EKS' : SHORT[g.group] || g.group), h('span', { class: 'tm2-src-name', title: g.source }, ...softBreaks(g.source))),
            h('span', { class: 'mono tiny muted tm-ell', title: g.principal }, g.principal)),
          h('span', { class: 'tm2-c-guard' }, g.conditions.length ? gs.map((t) => h('span', { class: 'tm2-guard' }, t)) : g.group === 'service' ? h('span', { class: 'tiny muted' }, '—') : h('span', { class: 'tiny tm2-none' }, 'no conditions')),
          h('span', { class: 'tm2-c-find' }, g.findings.length ? g.findings.map((f) => h('span', { class: 'tm2-find' }, sevBadge(f.severity), h('span', null, f.title))) : h('span', { class: 'tiny muted' }, 'nothing to flag')),
          h('span', { class: 'tm2-c-used tiny' }, g.sessions ? [h('b', null, num(g.sessions)), ` sessions · ${ago(g.lastSeen)}`] : h('span', { class: 'muted' }, g.group === 'service' ? '—' : 'never used')),
          h('span', { class: 'tm2-c-risk tiny' }, g.attention ? h('b', { class: 'tm-bad' }, `${num(g.attention)} need attention`) : '', g.admin ? h('span', { class: 'tm2-chip bad', title: 'Ways in that reach an administrator role' }, `ADMIN ×${num(g.admin)}`) : null)),
        open && h('div', { class: 'tm2-way-more tm2-grp-more' },
          h('div', null, h('div', { class: 'tm2-cap' }, `ACCOUNTS${g.members.length < g.ways ? ` · THE FIRST ${g.members.length}` : ''}`),
            h('div', { class: 'tm2-grp-list' }, g.members.map((x) => h('a', { class: 'tm2-grp-acct', href: roleHref(x) },
              h('span', { class: `tm2-dot tm2-dot-${x.attention ? x.worst : 'none'}` }), h('span', null, x.account), h('span', { class: 'tiny muted' }, `${envName(x.env) || ''}${x.sessions ? ` · ${num(x.sessions)} sessions` : ''}${x.expected ? ' · expected' : x.accepted ? ' · accepted' : ''}`))))),
          h('div', null, h('div', { class: 'tm2-cap' }, 'CONDITIONS'), g.conditions.length ? g.conditions.map((c) => h('code', { class: 'cond-line' }, c)) : h('p', { class: 'small muted' }, 'None: the principal alone is enough.'),
            h('div', { class: 'tm2-cap', style: 'margin-top:8px' }, 'REVIEW'),
            g.undecided.length ? h('p', { class: 'small', style: 'margin:0 0 6px' }, `${plural(g.undecided.length, 'finding')} not decided yet, across the accounts.`) : h('p', { class: 'small muted', style: 'margin:0 0 6px' }, g.findings.length ? 'Every finding is decided or expected.' : 'Nothing to decide.'),
            h('div', { class: 'row tm2-way-acts', style: 'gap:8px' },
              canDecide() && g.undecided.length > 0 && h('button', { type: 'button', class: 'btn sm', onClick: () => decideGroup(g, 'accept') }, `Accept in all ${plural(g.accounts, 'account')}`),
              canDecide() && g.undecided.length > 0 && h('button', { type: 'button', class: 'btn sm', onClick: () => decideGroup(g, 'investigate') }, 'Investigate'),
              g.group !== 'service' && g.expected < g.ways && expectBtn({ source: g.sourceKey, sourceLabel: g.source, roles: g.role, ways: [{ findings: g.findings }] }),
              h('button', { type: 'button', class: 'btn sm', onClick: () => changeTerms([...S.terms, ...parse(`role:${quote(g.role)}`)]) }, 'Filter to this role')))));
    };
    const pg = total > PAGE ? pager({ page: S.page + 1, total, size: PAGE, label: `${num(S.page * PAGE + 1)}–${num(Math.min(total, S.page * PAGE + PAGE))} of ${num(total)}`, onPage: (p) => { S.page = p - 1; address(); loadWays(); } }) : null;
    view.replaceChildren(h('section', { class: 'card' },
      h('div', { class: 'card-h' }, h('div', null, h('h2', null, 'The same trust, grouped'), h('p', { class: 'small muted', style: 'margin:2px 0 0' },
        `${plural(ways.ways, 'way in', 'ways in')} as ${plural(total, 'pattern')}: one row per role name, where it comes from and its findings. Open one for its accounts; a decision applies to all of them.`)),
      h('div', { class: 'row', style: 'gap:8px' }, groupSwitch(), pg)),
      total ? h('div', { class: 'tm2-ways', role: 'table' },
        h('div', { class: 'tm2-way-head', role: 'row' }, h('span'), h('div', { class: 'tm2-th' }, 'Role name'), h('div', { class: 'tm2-th' }, 'From'), h('div', { class: 'tm2-th' }, 'Guarded by'), h('div', { class: 'tm2-th' }, 'Findings'), h('div', { class: 'tm2-th' }, 'Used'), h('div', { class: 'tm2-th' }, 'Attention')),
        ways.groups.map(row))
        : h('div', { class: 'card-b' }, h('p', { class: 'muted small' }, 'Nothing here.')),
      pg && h('div', { class: 'card-b row', style: 'justify-content:flex-end' }, pg)));
  }

  function drawWays() {
    if (S.tab !== 'ways' || !ways) return;
    if (S.group) { if (ways.groups) drawGroups(); return; }
    if (!ways.rows) return;
    const sortBy = (k) => () => { if (S.sort === k) S.dir = S.dir === 'asc' ? 'desc' : 'asc'; else { S.sort = k; S.dir = 'asc'; } S.page = 0; address(); loadWays(); };
    const th = (k, l) => h('div', { class: 'tm2-th', role: 'columnheader', 'aria-sort': S.sort === k ? (S.dir === 'asc' ? 'ascending' : 'descending') : null },
      h('button', { type: 'button', class: 'th-sort', onClick: sortBy(k) }, l, S.sort === k ? (S.dir === 'asc' ? ' ↑' : ' ↓') : ''));
    const row = (e) => {
      const id = `${e.roleId}|${e.statement}|${e.principal}`, open = S.expanded.has(id);
      const g = guards(e.conditions);
      const findings = e.findings.filter((f) => f.severity !== 'info');
      return h('div', { class: `tm2-way${open ? ' open' : ''}`, role: 'row' },
        h('button', { type: 'button', class: 'tm2-way-main', 'aria-expanded': String(open), onClick: () => { open ? S.expanded.delete(id) : S.expanded.add(id); drawWays(); } },
          h('span', { class: `tm2-dot tm2-dot-${e.attention || e.worst === 'low' || e.worst === 'info' || e.worst === 'none' ? e.worst : 'none'}`, title: e.attention ? e.worst : `${e.worst}${e.expected ? ', expected' : e.accepted ? ', accepted' : ''}` }),
          h('span', { class: 'tm2-c-role' }, h('span', { class: 'name', title: e.role }, ...roleName(e.role), ...reviewChips(e)), h('span', { class: 'tiny muted' }, `${isGcp(e) ? `project ${e.account}` : `${e.account} · ${e.awsAccountId}`} · ${e.sid || `statement ${e.statement + 1}`}`)),
          h('span', { class: 'tm2-c-from' }, h('span', { class: 'tm2-src' }, h('span', { class: `src-tag g-${e.group}` }, e.pkind === 'eks' ? 'EKS' : SHORT[e.group] || e.group), h('span', { class: 'tm2-src-name', title: e.named?.name || e.source }, ...softBreaks(e.named?.name || e.source))),
            ((t) => h('span', { class: 'mono tiny muted tm-ell', title: t }, t))(e.named ? `${e.principalAccount || e.source} · ${e.principal}` : e.principal)),
          h('span', { class: 'tm2-c-guard' }, e.conditions.length ? [...g.map((t) => h('span', { class: 'tm2-guard' }, t)), g.length < e.conditions.length ? h('span', { class: 'tiny muted' }, `+${e.conditions.length - g.length}`) : null]
            : e.group === 'service' ? h('span', { class: 'tiny muted' }, '—') : h('span', { class: 'tiny tm2-none' }, 'no conditions')),
          h('span', { class: 'tm2-c-find' }, findings.length ? findings.map((f) => h('span', { class: 'tm2-find' }, sevBadge(f.severity), h('span', null, f.title))) : h('span', { class: 'tiny muted' }, 'nothing to flag')),
          h('span', { class: 'tm2-c-used tiny' }, e.sessions ? [h('b', null, num(e.sessions)), ` sessions · ${ago(e.lastSeen)}`] : e.lastUsed ? `IAM: used ${ago(e.lastUsed.at)}` : h('span', { class: 'muted' }, e.group === 'service' ? '—' : 'never used')),
          h('span', { class: 'tm2-c-risk' }, e.risk ? h('span', { class: `badge b-${String(e.risk).toLowerCase()}`, title: 'Risk of the role it leads to' }, e.risk) : null,
            e.admin ? h('span', { class: 'tm2-chip bad', title: `The role can do ${num(e.granted)} things: an administrator` }, 'ADMIN') : null)),
        open && h('div', { class: 'tm2-way-more' },
          h('div', null, h('div', { class: 'tm2-cap' }, 'CONDITIONS'), e.conditions.length ? e.conditions.map((c) => h('code', { class: 'cond-line' }, c)) : h('p', { class: 'small muted' }, 'None: the principal alone is enough.')),
          h('div', null, h('div', { class: 'tm2-cap' }, 'FINDINGS'), e.findings.length ? e.findings.map((f) => h('div', { class: 'tm2-fdetail' }, sevBadge(f.severity), h('div', null, h('b', null, f.title), f.detail && h('div', { class: 'small muted' }, f.detail)))) : h('p', { class: 'small muted' }, 'Nothing to flag.')),
          h('div', null, h('div', { class: 'tm2-cap' }, 'SEEN COMING IN'), e.callerCount ? [h('p', { class: 'small', style: 'margin:0 0 4px' }, `${plural(e.callerCount, 'caller')}, ${plural(e.sessions, 'session')}${e.firstSeen ? `, first ${ago(e.firstSeen)}` : ''}. The latest:`),
            ...e.seen.map((x) => h('div', { class: 'small' }, h('span', { class: 'mono' }, cut(x.display, 90)), h('span', { class: 'muted' }, ` · ${num(x.sessions)} · ${ago(x.lastSeen)}`)))]
            : h('p', { class: 'small muted' }, e.lastUsed ? `No sign-in tied to this statement; IAM last used ${ago(e.lastUsed.at)}.` : 'Nothing in the history read.'),
          h('div', { class: 'tm2-cap', style: 'margin-top:8px' }, 'ACTIONS'), h('code', { class: 'cond-line' }, e.actions.join(', ')),
          e.change && h('p', { class: 'small', style: 'margin:8px 0 0' }, e.change.kind === 'weakened' ? h('b', { class: 'tm-bad' }, `${e.change.guards.join(', ')} taken off ${ago(e.change.at)}.`) : `${e.change.roleCreated ? 'The role was created' : 'This trust was added'} ${ago(e.change.at)}.`)),
          e.idc && h('div', null, h('div', { class: 'tm2-cap' }, `WHO GETS IT · ${e.idc.permissionSet}`),
            ...e.idc.who.map((w) => h('div', { class: 'small' }, h('span', { class: 'tm2-guard' }, w.type), ' ', w.name)),
            e.idc.count > e.idc.who.length && h('p', { class: 'tiny muted' }, `and ${num(e.idc.count - e.idc.who.length)} more`)),
          decisionsBox(e),
          (e.expected || e.expectedDue) && h('div', null, h('div', { class: 'tm2-cap' }, e.expected ? 'EXPECTED' : 'EXPECTED · REVIEW DUE'),
            h('p', { class: 'small', style: 'margin:0' }, (e.expected || e.expectedDue).note),
            h('p', { class: 'tiny muted', style: 'margin:2px 0 0' }, [e.expected?.by, e.expected?.at && ago(e.expected.at), (e.expected || e.expectedDue).reviewBy && `look again by ${String((e.expected || e.expectedDue).reviewBy).slice(0, 10)}`].filter(Boolean).join(' · ')),
            canDecide() && h('button', { type: 'button', class: 'btn xs ghost', style: 'margin-top:4px', onClick: () => unexpect((e.expected || e.expectedDue).id) }, 'No longer expected')),
          h('div', { class: 'row tm2-way-acts', style: 'gap:8px;margin-top:8px' }, h('a', { class: 'btn sm', href: roleHref(e) }, isGcp(e) ? (e.gcpId ? 'Open the service account' : 'Its project\'s identities') : 'Open the role'), !isGcp(e) && h('a', { class: 'btn sm', href: `#/identities/${e.roleId}?tab=history` }, 'Its history'),
            !e.expected && e.group !== 'service' && expectBtn({ source: e.sourceKey, sourceLabel: e.source, roles: e.role, accounts: [e.awsAccountId], ways: [e] }),
            e.type === 'aws-root' && h('a', { class: 'btn sm', href: `#/identities/${e.roleId}/trust`, title: 'Name the identities seen coming in from this account, with safety checks and approval' }, 'Specific trust draft →'))));
    };
    const total = ways.total;
    const pg = total > PAGE ? pager({ page: S.page + 1, total, size: PAGE, label: `${num(S.page * PAGE + 1)}–${num(Math.min(total, S.page * PAGE + PAGE))} of ${num(total)}`, onPage: (p) => { S.page = p - 1; address(); loadWays(); } }) : null;
    view.replaceChildren(h('section', { class: 'card' },
      h('div', { class: 'card-h' }, h('div', null, h('h2', null, 'Ways in'), h('p', { class: 'small muted', style: 'margin:2px 0 0' },
        S.sel ? ['Following the pick: ', h('b', null, nameOf(S.sel)), '. '] : 'Every statement that lets someone in. ', 'Open a row for its conditions, findings and callers.')),
      h('div', { class: 'row', style: 'gap:8px' }, S.sel && h('button', { class: 'btn sm', onClick: () => pick(null) }, 'All ways in'), groupSwitch(), pg)),
      total ? h('div', { class: 'tm2-ways', role: 'table' },
        h('div', { class: 'tm2-way-head', role: 'row' }, h('span'), th('role', 'Role'), th('source', 'From'), h('div', { class: 'tm2-th' }, 'Guarded by'), th('worst', 'Findings'), th('used', 'Used'), th('reach', 'Reaches')),
        ways.rows.map(row))
        : h('div', { class: 'card-b' }, h('p', { class: 'muted small' }, 'Nothing here.')),
      pg && h('div', { class: 'card-b row', style: 'justify-content:flex-end' }, pg)));
  }

  // ---------------------------------------------------------------- the grid: sources down, accounts across
  // One cell per pair in the colour of what still needs a look. A source that is everywhere is a full row; an odd cell
  // stands out; nothing crosses.
  function drawGrid() {
    const M = m.map;
    const cols = M.accounts.filter((a) => !a.planned && M.links.some((l) => l.to === a.id))
      .sort((a, b) => (ENV_ORDER.indexOf(a.env) - ENV_ORDER.indexOf(b.env)) || a.name.localeCompare(b.name));
    const byPair = new Map(M.links.map((l) => [`${l.from}|${l.to}`, l]));
    const rowIds = [...new Set(M.links.map((l) => l.from))];
    const rows = rowIds.map((id) => ({ id, label: nameOf(id), cells: M.links.filter((l) => l.from === id), src: M.sources.find((x) => x.id === id) }))
      .sort((a, b) => (SEV_ORDER[worstOf(a.cells)] - SEV_ORDER[worstOf(b.cells)]) || b.cells.length - a.cells.length || a.label.localeCompare(b.label));
    const sevClass = (w) => (w === 'high' ? 'high' : w === 'medium' ? 'medium' : 'ok');
    const head = h('tr', null, h('th', { class: 'tm2-g-corner' }, h('span', { class: 'tiny muted' }, `${plural(rows.length, 'source')} × ${plural(cols.length, 'account')}`)),
      ...cols.map((a) => h('th', { class: 'tm2-g-col', title: `${a.name} · ${envName(a.env)}` }, h('span', { class: 'tm2-g-env', style: null, 'data-env': a.env }), h('span', { class: 'tm2-g-colname' }, a.name))));
    const body = rows.map((r) => h('tr', { class: S.sel === r.id ? 'tm2-row-sel' : null },
      h('th', { class: 'tm2-g-row' }, h('button', { type: 'button', class: 'link-btn', onClick: () => pick(r.id) }, cut(r.label, 34)),
        h('span', { class: 'tiny muted' }, ` ${r.src ? SHORT[r.src.group] || '' : 'your account'} · ${num(r.cells.length)}`)),
      ...cols.map((a) => {
        const l = byPair.get(`${r.id}|${a.id}`);
        return h('td', { class: 'tm2-g-cell' }, l ? h('button', { type: 'button', class: `tm2-g-dot g-${sevClass(l.worst)}${l.sessions || l.iamUsed ? '' : ' unused'}${S.sel === l.id ? ' sel' : ''}`,
          'aria-label': `${r.label} → ${a.name}: ${plural(l.roles, 'role')}, worst ${l.worst}`, title: `${r.label} → ${a.name} · ${plural(l.roles, 'role')} · ${l.worst}${l.expected ? ` · ${num(l.expected)} expected` : ''} · ${usedText(l)}`,
          onClick: () => pick(l.id) }) : null);
      })));
    view.replaceChildren(h('section', { class: 'card' },
      h('div', { class: 'card-h' }, h('div', null, h('h2', null, 'Grid'), h('p', { class: 'small muted', style: 'margin:2px 0 0' },
        'Where it comes from, down; your accounts, across, by environment. A cell is red or amber when something there still needs a look; hollow when never used. Pick one for its details.'))),
      cols.length && rows.length ? h('div', { class: 'tm2-grid-wrap' }, h('table', { class: 'tm2-grid' }, h('thead', null, head), h('tbody', null, body)))
        : h('div', { class: 'card-b' }, h('p', { class: 'muted small' }, 'Nothing matches this filter.'))));
    for (const el of view.querySelectorAll('.tm2-g-env')) { const c = ENV_COLOR[el.dataset.env]; if (c) el.style.background = c; }
  }
  const worstOf = (ls) => ls.reduce((w, l) => (SEV_ORDER[l.worst] < SEV_ORDER[w] ? l.worst : w), 'none');

  // ---------------------------------------------------------------- the panel: whatever is picked
  let lineRoles = null, lineKey = '';
  const facts = (rows) => h('dl', { class: 'tm-facts' }, rows.filter(Boolean).flatMap(([k, v, tone]) => [h('dt', null, k), h('dd', { class: tone ? `tm-${tone}` : null }, v)]));
  const listOf = (title, items, empty) => h('div', { class: 'tm-sect' }, h('div', { class: 'tm-sect-h' }, h('span', null, title), h('span', { class: 'mono' }, num(items.length))),
    items.length ? h('div', { class: 'tm-list' }, items) : h('p', { class: 'tiny muted', style: 'margin:4px 0' }, empty || 'none'));
  // an Identity Center role by its permission set (the full name is on hover); any long name wraps between words
  const roleName = (name) => { const set = ssoSet(name); return set ? [...softBreaks(set), h('span', { class: 'tm2-chip', title: `IAM Identity Center permission set · ${name}` }, 'SSO')] : softBreaks(name); };
  const roleText = (name) => { const set = ssoSet(name); return set ? `${set} (SSO)` : name; };
  const item = ({ label, meta, worst, onClick, href, title }) => {
    const kids = [h('span', { class: `tm2-dot tm2-dot-${worst || 'none'}` }), h('span', { class: 'tm-item-b' }, h('span', { class: 'tm-item-l', title: title || (typeof label === 'string' ? label : null) }, label), meta && h('span', { class: 'tm-item-m', title: meta }, meta)), sevBadge(worst)];
    return href ? h('a', { class: 'tm-item', href }, ...kids) : h('button', { type: 'button', class: 'tm-item', onClick }, ...kids);
  };
  const filterTo = (terms) => h('button', { type: 'button', class: 'btn sm primary', title: 'Add it to the filter: the counts, the map, both tables and the export narrow to it', onClick: () => changeTerms([...S.terms, ...parse(terms)]) }, 'Filter to this');
  const waysBtn = () => h('button', { type: 'button', class: 'btn sm', onClick: () => { S.tab = 'ways'; S.page = 0; address(); drawTabs(); drawView(); } }, 'Its ways in');
  let acctChain = null;
  function drawPanel() {
    const M = m.map;
    const close = h('button', { class: 'sp-x', 'aria-label': 'Close', onClick: () => pick(null) }, '×');
    const headOf = (eyebrow, title, sub, worst) => h('div', { class: 'tm-side-h' },
      h('div', { class: 'tm-eyebrow' }, eyebrow, worst === 'high' && h('span', { class: 'tm-tag' }, 'HIGH'), worst === 'medium' && h('span', { class: 'tm-tag warn' }, 'MEDIUM')),
      h('div', { class: 'row', style: 'justify-content:space-between;gap:8px;align-items:flex-start' }, h('b', { class: 'tm-title' }, title), close), sub && h('div', { class: 'tm-sub-t' }, sub));
    const l = S.sel?.includes('>') && M.links.find((x) => x.id === S.sel);
    const s = M.sources.find((x) => x.id === S.sel), a = M.accounts.find((x) => x.id === S.sel);
    panel.classList.toggle('open', !!(l || s || a));
    if (l) {
      const from = M.accounts.find((x) => x.id === l.from) || M.sources.find((x) => x.id === l.from), to = M.accounts.find((x) => x.id === l.to);
      const rolesBox = h('div', { class: 'tm-sect' }, h('p', { class: 'tiny muted' }, 'Loading the roles…'));
      panel.replaceChildren(headOf(l.kind === 'account' ? 'ACCOUNT → ACCOUNT' : `${(KIND_NAME[from?.group] || 'OUTSIDE').toUpperCase()} → ACCOUNT`, `${from?.name || from?.label || '?'} → ${to?.name || '?'}`,
        `${plural(l.roles, 'role')} · ${plural(l.ways, 'statement')}`, l.worst),
      facts([['Findings', l.findings ? plural(l.findings, 'finding') : 'nothing to flag', l.findings ? 'bad' : 'ok'],
        ['Leads to', l.highRiskRoles ? `${plural(l.highRiskRoles, 'high-risk role')} of ${l.roles}` : 'no high-risk role', l.highRiskRoles ? 'bad' : null],
        l.admin ? ['Administrator', `${plural(l.admin, 'way in', 'ways in')} reach an administrator role`, 'bad'] : null,
        ['Used', usedText(l), l.sessions || l.iamUsed ? null : 'warn']]),
      rolesBox,
      h('div', { class: 'tm-actions' }, filterTo(l.query), waysBtn(), expectBtn({ source: l.from, sourceLabel: nameOf(l.from), accounts: [to?.aws].filter(Boolean), sel: l.id })));
      const key = `${q()}|${l.id}`;
      const fill = (r) => rolesBox.replaceChildren(listOf(r.rows.some(isGcp) ? 'What it reaches' : 'Roles behind it', groupRoles(r.rows).map((x) => item({ label: roleText(x.role), title: x.role, worst: x.worst, href: roleHref(x),
        meta: [x.findings.slice(0, 2).join(' · ') || (x.conditions ? plural(x.conditions, 'condition') : 'no conditions'), usedText(x), x.risk ? `${x.risk} risk role` : null].filter(Boolean).join(' · ') }))),
      r.total > r.rows.length && h('p', { class: 'tiny muted' }, `The first ${num(r.rows.length)} of ${num(r.total)} statements; the rest under Its ways in.`));
      if (lineKey === key && lineRoles) fill(lineRoles);
      else { lineKey = key; get(`/trust/ways?q=${encodeURIComponent(q())}&sel=${encodeURIComponent(l.id)}&size=200`).then((r) => { if (lineKey !== key) return; lineRoles = r; fill(r); }).catch(() => rolesBox.replaceChildren(h('p', { class: 'tiny muted' }, 'Could not load the roles.'))); }
    } else if (s) {
      const out = M.links.filter((x) => x.from === s.id);
      const chainBox = h('div', { class: 'tm-sect' });
      panel.replaceChildren(headOf(s.named?.inOrg ? 'YOUR ORGANISATION · NOT ONBOARDED' : (KIND_NAME[s.group] || s.group).toUpperCase(), s.label,
        s.group === 'external-account' && s.cloud === 'gcp' ? `${s.aws || ''} · ${s.named?.inOrg ? 'your project, no connection reads it' : 'outside your organization (Google Cloud)'}`
          : s.group === 'external-account' ? `${s.named ? `${s.aws} · ` : ''}AWS account not connected here · ${s.vendor ? 'every statement requires sts:ExternalId' : 'at least one statement has no sts:ExternalId'}` : null, s.worst),
      s.named && h('div', { class: 'tm-named' }, s.named.purpose && h('p', { class: 'small', style: 'margin:0' }, s.named.purpose),
        h('p', { class: 'tiny muted', style: 'margin:2px 0 0' }, [s.named.owner && `owner: ${s.named.owner}`, s.named.reviewBy && `review by ${String(s.named.reviewBy).slice(0, 10)}`,
          s.named.vendor && (s.named.name === s.named.vendor ? 'named from the public list of known AWS accounts (fwd:cloudsec)' : `known as ${s.named.vendor} in fwd:cloudsec's list`)].filter(Boolean).join(' · '))),
      facts([['Reaches', `${plural(s.roles, 'role')} in ${plural(s.accounts, 'account')}`], ['Leads to', s.highRiskRoles ? plural(s.highRiskRoles, 'high-risk role') : 'no high-risk role', s.highRiskRoles ? 'bad' : null],
        ['Administers', s.adminAccounts ? `an administrator role in ${plural(s.adminAccounts, 'account')}` : 'no administrator role', s.adminAccounts ? 'bad' : null],
        ['Findings', s.findings ? plural(s.findings, 'finding') : 'nothing to flag', s.findings ? 'bad' : 'ok'], ['Used', usedText(s), s.sessions ? null : 'warn'],
        s.firstSeen ? ['First seen', ago(s.firstSeen)] : null]),
      listOf('Accounts it can get into', out.sort((x, y) => SEV_ORDER[x.worst] - SEV_ORDER[y.worst]).map((x) => item({ label: nameOf(x.to), worst: x.worst, meta: `${plural(x.roles, 'role')} · ${usedText(x)}`, onClick: () => pick(x.id) }))),
      chainBox,
      h('div', { class: 'tm-actions' }, filterTo(s.query), waysBtn(), expectBtn({ source: s.id, sourceLabel: s.label, sel: s.id }), nameBtn(s),
        s.named?.inOrg && s.cloud !== 'gcp' && session.user.permissions.includes('accounts') && h('button', { type: 'button', class: 'btn sm', onClick: () => addPlanned(s) }, 'Add as planned')));
      loadChain(s.id, chainBox);
    } else if (a) {
      acctChain = h('div', { class: 'tm-sect' });
      const inn = M.links.filter((x) => x.to === a.id), out = M.links.filter((x) => x.from === a.id);
      const gp = a.cloud === 'gcp';
      panel.replaceChildren(headOf(a.planned ? 'PLANNED · NOT ONBOARDED' : `${(envName(a.env) || 'account').toUpperCase()} ${gp ? 'GOOGLE CLOUD PROJECT' : 'ACCOUNT'}${a.inScope ? '' : ' · NOT IN YOUR SCOPE'}`, a.name, a.planned ? `${a.aws} · not scanned yet` : a.aws, a.inbound.worst),
        a.planned ? facts([['Who can get in', 'Not known until it is onboarded.', 'warn'], ['It can get into', out.length ? plural(out.length, 'account') : 'nothing seen']])
          : facts([['From outside it', a.inbound.roles ? `${plural(a.inbound.roles, gp ? 'service account' : 'role')}${a.inbound.high ? ` · ${num(a.inbound.high)} high` : ''}${a.inbound.medium ? ` · ${num(a.inbound.medium)} medium` : ''}` : gp ? 'nothing' : 'no role', a.inbound.high ? 'bad' : null],
            ['Inside it', gp ? `${plural(a.own, 'service account')} reached from inside the project (its own identities, key holders) · ${plural(a.services, 'service account')} Google service agents${a.clusters ? ` · ${plural(a.clusters, 'service account')} its ${plural(a.clusterSources, 'GKE workload')}` : ''}`
              : `${plural(a.own, 'role')} trust the account itself · ${plural(a.services, 'role')} AWS services${a.clusters ? ` · ${plural(a.clusters, 'role')} its ${plural(a.clusterSources, 'EKS cluster')}` : ''}`]]),
        !a.planned && listOf('Who can get in', inn.sort((x, y) => SEV_ORDER[x.worst] - SEV_ORDER[y.worst]).map((x) => item({ label: nameOf(x.from), worst: x.worst,
          meta: `${x.kind === 'account' ? 'your account' : SHORT[M.sources.find((y) => y.id === x.from)?.group] || ''} · ${plural(x.roles, 'role')} · ${usedText(x)}`, onClick: () => pick(x.id) })), 'nothing from outside this account'),
        out.length > 0 && listOf('It can get into', out.map((x) => item({ label: nameOf(x.to), worst: x.worst, meta: `${plural(x.roles, 'role')} · ${usedText(x)}`, onClick: () => pick(x.id) }))),
        out.length > 0 && acctChain,
        h('div', { class: 'tm-actions' }, a.planned ? (session.user.permissions.includes('accounts') ? h('a', { class: 'btn sm primary', href: `#/accounts/new?from=${a.id}` }, 'Onboard it') : null)
          : [filterTo(`account:${a.aws}`), waysBtn(), h('a', { class: 'btn sm', href: `#/space?view=account&account=${encodeURIComponent(a.id)}` }, 'Open in Space')]));
    } else {
      // nothing picked: what needs attention most, and how to read the map
      const worst = [...M.sources].filter((x) => ATTENTION.has(x.worst)).sort((x, y) => SEV_ORDER[x.worst] - SEV_ORDER[y.worst] || y.roles - x.roles).slice(0, 6);
      const accts = [...M.accounts].filter((x) => x.inbound.high).sort((x, y) => y.inbound.high - x.inbound.high).slice(0, 6);
      panel.replaceChildren(h('div', { class: 'tm-side-h' }, h('div', { class: 'tm-eyebrow' }, 'START HERE'),
        h('div', { class: 'tm-sub-t' }, `${plural(m.total, 'way')} in to ${plural(m.roles, 'role')}${q() ? ` · of ${num(m.totalEdges)} in all` : ''}. Pick a source, an account or a line for its details.`)),
      listOf('Sources that need attention', worst.map((x) => item({ label: x.label, worst: x.worst, meta: `${KIND_NAME[x.group]} · ${plural(x.roles, 'role')} · ${plural(x.accounts, 'account')}`, onClick: () => pick(x.id) })), 'none'),
      listOf('Accounts with high-risk ways in', accts.map((x) => item({ label: x.name, worst: 'high', meta: `${num(x.inbound.high)} high · ${envName(x.env)}`, onClick: () => pick(x.id) })), 'none'),
      expectedBox);
      loadExpected();
    }
    if (a && M.links.some((x) => x.from === a.id)) loadChain(a.id, acctChain);
    live.textContent = l || s || a ? `${nameOf(S.sel)} picked` : '';
  }
  // expected trust: every rule, what it covers now, and a way to drop it
  const expectedBox = h('div', { class: 'tm-sect' });
  let expectedAt = null;
  async function loadExpected() {
    if (expectedAt === m.builtAt) return;
    expectedAt = m.builtAt;
    try {
      const { items } = await get('/trust/expected');
      expectedBox.replaceChildren(h('div', { class: 'tm-sect-h' }, h('span', null, 'Expected trust'), h('span', { class: 'mono' }, num(items.length))),
        items.length ? h('div', { class: 'tm-list' }, items.map((r) => h('div', { class: 'tm-item tm-exp' },
          h('span', { class: `tm2-dot tm2-dot-${r.due ? 'medium' : 'none'}` }),
          h('span', { class: 'tm-item-b' }, h('span', { class: 'tm-item-l' }, `${r.sourceLabel}${r.roles !== '*' ? ` → ${r.roles}` : ''}`),
            h('span', { class: 'tm-item-m' }, [r.note, r.covers ? plural(r.covers, 'way in', 'ways in') : r.due ? `${plural(r.due, 'way in', 'ways in')} due for review` : 'covers nothing now',
              r.reviewBy && `look again by ${String(r.reviewBy).slice(0, 10)}`, r.createdBy].filter(Boolean).join(' · '))),
          canDecide() && h('button', { type: 'button', class: 'btn xs ghost', 'aria-label': `No longer expect ${r.sourceLabel}`, onClick: () => unexpect(r.id) }, '×'))))
          : h('p', { class: 'tiny muted', style: 'margin:4px 0' }, 'None yet. Pick a source or a line, or open a way in, and mark what you have reviewed as expected.'));
    } catch { expectedBox.replaceChildren(); }
  }
  // where a pick leads next: the roles it gets into, then the roles those get into
  async function loadChain(id, box) {
    box.replaceChildren(h('p', { class: 'tiny muted' }, 'Following where it leads…'));
    try {
      const c = await get(`/trust/chain?sel=${encodeURIComponent(id)}`);
      if (S.sel !== id) return;
      const later = c.levels.slice(1);
      if (!later.length) { box.replaceChildren(h('div', { class: 'tm-sect-h' }, h('span', null, 'Where it leads next')), h('p', { class: 'tiny muted', style: 'margin:4px 0' }, 'Nowhere further: no role it gets into is trusted by another role.')); return; }
      const sure = later.flatMap((l) => l.roles).filter((r) => r.sure), maybe = later.flatMap((l) => l.roles).filter((r) => !r.sure);
      box.replaceChildren(h('div', { class: 'tm-sect-h' }, h('span', null, 'Where it leads next'), h('span', { class: 'mono' }, num(c.roles))),
        h('p', { class: 'tiny', style: 'margin:4px 0' }, `Through the ${plural(c.levels[0].total, 'role')} it gets into: ${plural(sure.length, 'more role')} named in their trust${maybe.length ? `, ${num(maybe.length)} more possible (a whole account trusted)` : ''}`,
          c.moreAccounts ? `, in ${plural(c.moreAccounts, 'more account')}` : '', c.admin ? h('b', { class: 'tm-bad' }, ` · ${plural(c.admin, 'administrator role')} on the way`) : '', '.'),
        h('div', { class: 'tm-list' }, [...sure, ...maybe].slice(0, 8).map((r) => item({ label: roleText(r.role), title: r.role, worst: r.admin ? 'high' : 'none', href: roleHref(r),
          meta: `${r.account} · from ${r.from}${r.sure ? '' : ' · possible'}${r.admin ? ' · admin' : ''}` }))),
        sure.length + maybe.length > 8 && h('p', { class: 'tiny muted' }, `and ${num(sure.length + maybe.length - 8)} more`));
    } catch { box.replaceChildren(); }
  }
  async function addPlanned(s) {
    try { await post('/accounts/planned', { name: s.named.name, accountId: s.aws, note: 'Seen on the Trust map: an account of the organisation, not onboarded yet' }); afterReview(`${s.named.name} added as planned`); }
    catch (x) { toast(x.message, true); }
  }
  // ways in of one line, by role
  function groupRoles(rows) {
    const by = new Map();
    for (const e of rows) {
      const r = by.get(e.roleId) || { roleId: e.roleId, role: e.role, risk: e.risk, worst: 'none', findings: new Set(), conditions: 0, sessions: 0, lastSeen: null, lastUsed: null };
      if (SEV_ORDER[e.worst] < SEV_ORDER[r.worst]) r.worst = e.worst;
      e.findings.filter((f) => f.severity !== 'info').forEach((f) => r.findings.add(f.title));
      r.conditions += e.conditions.length; r.sessions = Math.max(r.sessions, e.sessions);
      if (e.lastSeen && (!r.lastSeen || e.lastSeen > r.lastSeen)) r.lastSeen = e.lastSeen;
      r.lastUsed ||= e.lastUsed; by.set(e.roleId, r);
    }
    return [...by.values()].map((r) => ({ ...r, findings: [...r.findings] })).sort((a, b) => SEV_ORDER[a.worst] - SEV_ORDER[b.worst] || a.role.localeCompare(b.role));
  }

  // ---------------------------------------------------------------- picking
  function pick(id) {
    const was = S.sel;
    S.sel = id && known(id) ? id : null;
    if (S.sel === was) return;
    S.page = 0; focusIdx = -1;
    address(!was && !!S.sel);                              // a new pick is a history entry, so Back closes it
    drawPanel(); drawView();
  }
  const esc = (e) => { if (e.key === 'Escape' && S.sel && !e.defaultPrevented && !document.querySelector('.menu-list:not([hidden]), .acct-picker[open]')) pick(null); };
  document.addEventListener('keydown', esc);
  ctx.onLeave(() => document.removeEventListener('keydown', esc));

  // ---------------------------------------------------------------- drawing
  function drawView() {
    body.classList.toggle('tm2-wide', S.tab === 'ways');
    if (S.tab === 'map') { view.replaceChildren(mapBox); drawMap(); }
    else if (S.tab === 'grid') drawGrid();
    else if (S.tab === 'sources') drawSources();
    else { if (!ways) view.replaceChildren(h('div', { class: 'muted small', style: 'padding:16px' }, h('span', { class: 'spin' }), ' Loading')); loadWays(); }
  }
  function drawAll() { drawHeader(); drawFilter(); drawTiles(); drawTabs(); drawPanel(); drawView(); }

  // re-lay the map when its width changes
  const ro = new ResizeObserver(debounced(() => { if (S.tab === 'map' && mapBox.isConnected) drawMap(); }, 120));
  ro.observe(view);
  ctx.onLeave(() => ro.disconnect());
  // fresh numbers every few minutes while the tab is visible
  ctx.onLeave(poll(() => { if (!loading) refetch(); }, 3 * 60_000));

  if (S.sel && !known(S.sel)) S.sel = null;
  root.append(header, filterBar, tiles, h('div', { class: 'tm2-viewwrap' }, tabBar, body), live);
  address();
  drawAll();
  loadViews();
  requestAnimationFrame(() => { if (S.tab === 'map') drawMap(); });   // once the box has its real width
  return root;
}
