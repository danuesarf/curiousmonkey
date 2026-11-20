// Watch · Resources: who resource-based policies let in. Buckets, keys, tables, queues, topics, secrets, functions
// and repositories whose policy reaches beyond their own account: anyone, accounts outside your estate, your other
// accounts, AWS services. Each resource opens on the right with who can get in, its findings and the policy itself.
import { h, get, post, api, num, ago, toast, copy, fmtDate, loadEnvironments, tile, pager, searchBox, accountPicker, syncUrl, urlSet } from '../lib.js';
import { session } from '../main.js';

const SHORT = { s3: 'S3', kms: 'KMS', dynamodb: 'DynamoDB', sqs: 'SQS', sns: 'SNS', secretsmanager: 'Secrets', lambda: 'Lambda', ecr: 'ECR',
  gcs: 'GCS', bigquery: 'BigQuery', pubsub: 'Pub/Sub', cloudkms: 'Cloud KMS', gsecret: 'Secret Mgr', cloudrun: 'Cloud Run', cloudfunctions: 'Functions', artifactregistry: 'Artifacts' };
const CLOUDS = [['', 'Both clouds'], ['aws', 'AWS'], ['gcp', 'Google Cloud']];
const EXPOSURE_BADGE = { public: 'b-high', external: 'b-medium', 'cross-account': 'b-amber', service: 'b-neutral', private: 'b-green', none: 'b-neutral' };
const REACH = { public: ['Anyone', 'b-high'], external: ['Outside your estate', 'b-medium'], org: ['Your organisation', 'b-amber'], connected: ['Your account', 'b-amber'],
  same: ['This account', 'b-green'], service: ['AWS service', 'b-neutral'] };
const ACCESS = { admin: 'Administer / change access', data: 'Use the data', read: 'Read settings' };
const EXPOSURES = [['', 'Shared beyond the account'], ['public', 'Public'], ['external', 'Outside accounts'], ['cross-account', 'Your other accounts'],
  ['service', 'AWS services'], ['private', 'This account only'], ['none', 'No resource policy'], ['all', 'Every resource']];
const STATES = [['', 'Any state'], ['attention', 'Needs attention'], ['open', 'With findings'], ['expected', 'Marked expected']];
const SORTS = [['risk', 'Most exposed first'], ['changed', 'Policy changed lately'], ['name', 'By name'], ['account', 'By account']];
const canDecide = () => session.user.permissions.includes('decide');

/** One finding with the reviewer's call. A decision updates the card in place, then `onDecided`. */
function findingCard(f, onDecided) {
  let el;
  const draw = () => {
    const note = h('input', { placeholder: f.decision === 'expected' ? 'Why it is expected' : 'Why it is expected (needed for Expected), or a note', value: f.note || '', 'aria-label': 'Note' });
    const choose = async (decision, btn) => {
      btn.disabled = true;
      try {
        await post(`/resource-findings/${f.id}/decision`, { decision, note: note.value.trim() || undefined });
        Object.assign(f, { decision, note: note.value.trim() || null, decided_by: session.user.name, decided_at: new Date().toISOString() });
        toast('Decision saved'); redraw(); onDecided?.(f);
      } catch (e) { toast(e.message, true); btn.disabled = false; note.focus(); }
    };
    const clearIt = async () => {
      try { await api('DELETE', `/resource-findings/${f.id}/decision`); Object.assign(f, { decision: null, note: null, decided_by: null }); toast('Decision cleared'); redraw(); onDecided?.(f); }
      catch (e) { toast(e.message, true); }
    };
    const open = f.status === 'open';
    return h('article', { class: `finding ${f.severity}` },
      h('div', { class: 'row' }, h('span', { class: `badge b-${f.severity}` }, f.severity), h('h3', null, f.title),
        !open && h('span', { class: 'badge b-green' }, `resolved ${ago(f.resolved_at)}`),
        f.decision && h('span', { class: `badge ${f.decision === 'expected' ? 'b-green' : 'b-amber'}`, title: f.decided_at ? fmtDate(f.decided_at) : '' }, `${f.decision} · ${f.decided_by || 'someone'}`)),
      h('p', null, f.detail),
      f.note && h('p', { class: 'small muted' }, h('b', null, 'Note: '), f.note),
      f.actions.length > 0 && h('div', { class: 'acts' }, f.actions.slice(0, 30).map((a) => h('code', null, a)), f.actions.length > 30 && h('span', { class: 'small muted' }, `+${f.actions.length - 30} more`)),
      f.conditions.length > 0 && h('p', { class: 'small mono muted' }, `Conditions: ${f.conditions.join(' · ')}`),
      h('p', { class: 'small mono muted' }, `Statement ${f.sid || f.statement + 1} · ${f.principal}`),
      f.suggestion && h('p', { class: 'small' }, h('b', null, 'Suggestion: '), f.suggestion),
      h('p', { class: 'tiny muted' }, 'Control: ', h('a', { href: `#/policy?q=${encodeURIComponent(f.control)}`, class: 'mono' }, f.control)),
      open && canDecide() && h('div', { class: 'stack' }, note,
        h('div', { class: 'row' },
          (() => { const b = h('button', { class: `btn sm${f.decision === 'expected' ? ' primary' : ''}`, title: 'Accepted: it stays listed, out of "Needs attention", until the grant changes' }, 'Expected'); b.addEventListener('click', () => choose('expected', b)); return b; })(),
          (() => { const b = h('button', { class: `btn sm${f.decision === 'investigate' ? ' primary' : ''}` }, 'Investigate'); b.addEventListener('click', () => choose('investigate', b)); return b; })(),
          f.decision && h('button', { class: 'btn sm', onClick: clearIt }, 'Clear decision'))));
  };
  const redraw = () => { const next = draw(); el.replaceWith(next); el = next; };
  el = draw();
  return el;
}

/** Who the policy lets in: one row per statement and principal. */
function grantsTable(d) {
  const rows = (d.grants || []).filter((g) => g.kind !== 'deleted');
  if (!rows.length) return h('p', { class: 'small muted' }, d.policy ? 'The policy allows nobody (only Deny statements).' : 'No resource policy: only identities in this account whose own IAM policies allow it can use it.');
  return h('div', { class: 'scroll' }, h('table', null,
    h('thead', null, h('tr', null, ['Who', 'Reaches', 'Can', 'Limited by'].map((x) => h('th', null, x)))),
    h('tbody', null, rows.map((g) => {
      const [label, cls] = d.cloud === 'gcp' && g.reach === 'same' ? ['Your organisation', 'b-green'] : d.cloud === 'gcp' && g.reach === 'connected' ? ['Another connection', 'b-amber'] : REACH[g.reach] || [g.reach, 'b-neutral'];
      const who = g.kind === 'public' ? (/^all(Authenticated)?Users$/.test(g.principal) ? g.principal : 'Anyone (principal "*")') : g.kind === 'not-principal' ? 'Everyone except a list' : g.principal.replace(/^arn:aws[a-z-]*:iam::/, '');
      return h('tr', null,
        h('td', null, h('div', { class: 'mono small' }, who), g.accountName && h('div', { class: 'tiny muted' }, g.accountName), g.sid && h('div', { class: 'tiny muted' }, `Statement ${g.sid}`)),
        h('td', null, h('span', { class: `badge ${cls}` }, label)),
        h('td', { class: 'small' }, ACCESS[g.access] || g.access, h('div', { class: 'tiny muted mono' }, g.actions.slice(0, 3).join(', '), g.actions.length > 3 ? ` +${g.actions.length - 3}` : '')),
        h('td', { class: 'tiny' }, [...(g.narrowedBy || []), ...(g.network || []).map((n) => `network: ${n}`)].join(' · ') || (g.conditions.length ? g.conditions.join(' · ') : h('span', { class: 'muted' }, 'nothing'))));
    }))));
}

function notes(d) {
  const x = d.extra || {}, out = [];
  if (x.unreadable) out.push(h('div', { class: 'provisional' }, h('b', null, 'NOT READ'), `The scanner may not read this policy: ${x.unreadable}. For a KMS key, the key policy itself has to let the scanner role call kms:GetKeyPolicy.`));
  if (d.service === 's3') {
    const b = x.bucketBlock, a = x.accountBlock;
    const state = (c) => (!c ? 'not set' : c.unknown ? 'not readable' : c.RestrictPublicBuckets && c.BlockPublicPolicy ? 'on' : c.RestrictPublicBuckets || c.BlockPublicPolicy ? 'partly on' : 'off');
    out.push(h('p', { class: 'small muted' }, `Block Public Access: bucket ${state(b)}, account ${state(a)}.`, x.restrictPublic ? ' Public policies are restricted: only this account and AWS services get through them.' : ''));
  }
  if (d.service === 'gcs') {
    const pap = x.publicAccessPrevention;
    out.push(h('p', { class: 'small muted' }, `Public access prevention: ${pap === 'enforced' ? 'enforced (allUsers and allAuthenticatedUsers are refused)' : pap ? `${pap} (not enforced)` : 'not read'}.`));
  }
  if (d.cloud === 'gcp') out.push(h('p', { class: 'tiny muted' }, 'Resource-level IAM policy, read with the Google Cloud scan. Roles granted on the project, folder or organization also reach it; they are on the identities\' pages.'));
  if (d.service === 'kms' && x.state) out.push(h('p', { class: 'small muted' }, `Key ${x.state.toLowerCase()} · ${x.usage || ''}${x.multiRegion ? ' · multi-Region' : ''}`));
  return out;
}

const DEFAULT = { q: '', cloud: '', exposure: '', service: '', state: '', severity: new Set(), accounts: new Set(), control: '', sort: 'risk', page: 1 };
const SIZE = 50;

export async function resourcesPage(ctx) {
  ctx.setCrumbs('Watch', 'Resource access');
  const P = ctx.params;
  const f = { ...DEFAULT, q: P.get('q') || '', cloud: ['aws', 'gcp'].includes(P.get('cloud')) ? P.get('cloud') : '', exposure: EXPOSURES.some(([k]) => k === P.get('exposure')) ? P.get('exposure') : '', service: SHORT[P.get('service')] ? P.get('service') : '',
    state: STATES.some(([k]) => k === P.get('state')) ? P.get('state') : '', severity: urlSet(P, 'severity'), accounts: urlSet(P, 'accounts'),
    control: /^res\.[a-z-]{3,60}$/.test(P.get('control') || '') ? P.get('control') : '', sort: SORTS.some(([k]) => k === P.get('sort')) ? P.get('sort') : 'risk', page: Math.max(1, Number(P.get('page')) || 1) };
  const [accts] = await Promise.all([get('/accounts'), loadEnvironments().catch(() => [])]);
  const accounts = accts.items.filter((a) => a.status !== 'planned');
  for (const id of [...f.accounts]) if (!accounts.some((a) => a.id === id)) f.accounts.delete(id);

  let data = { items: [], total: 0, exposure: {}, services: {}, severity: {}, attention: 0, labels: { exposure: {}, services: {} } };
  let active = 0, detailSeq = 0;
  const tiles = h('div', { class: 'tiles' });
  const count = h('span', { class: 'count' });
  const listEl = h('div');
  const detail = h('div', { class: 'inbox-detail', 'aria-live': 'polite' });
  const waiting = h('span', { class: 'mono small muted' });

  const search = searchBox({ value: f.q, placeholder: 'Find a resource, account or principal', label: 'Search resources', onSearch: (v) => { f.q = v.trim(); f.page = 1; load(); } });
  ctx.onLeave(search.cancel);
  const ctlChip = f.control ? h('button', { class: 'chip', type: 'button', 'aria-pressed': 'true', title: 'Show every control', onClick: () => { f.control = ''; f.page = 1; ctlChip.remove(); load(); } }, `Control: ${f.control} ×`) : null;
  const select = (label, options, key) => {
    const s = h('select', { 'aria-label': label }, options.map(([v, l]) => h('option', { value: v, selected: f[key] === v }, l)));
    s.addEventListener('change', () => { f[key] = s.value; f.page = 1; load(); });
    return s;
  };
  const svcSel = h('select', { 'aria-label': 'Type of resource' });
  svcSel.addEventListener('change', () => { f.service = svcSel.value; f.page = 1; load(); });
  const expSel = select('Exposure', EXPOSURES, 'exposure');
  const picker = accountPicker({ accounts, selected: f.accounts, onChange: () => { f.page = 1; load(); } });
  ctx.onLeave(picker.destroy);

  const params = () => {
    const p = new URLSearchParams({ page: f.page, limit: SIZE, sort: f.sort });
    if (f.q) p.set('q', f.q); if (f.cloud) p.set('cloud', f.cloud); if (f.exposure) p.set('exposure', f.exposure); if (f.service) p.set('service', f.service); if (f.state) p.set('state', f.state);
    if (f.severity.size) p.set('severity', [...f.severity].join(',')); if (f.accounts.size) p.set('accounts', [...f.accounts].join(',')); if (f.control) p.set('control', f.control);
    return p;
  };
  const toUrl = () => syncUrl({ q: f.q, cloud: f.cloud, exposure: f.exposure, service: f.service, state: f.state, severity: f.severity, accounts: f.accounts, control: f.control,
    sort: f.sort === 'risk' ? '' : f.sort, page: f.page > 1 ? f.page : '' });

  let seq = 0;
  async function load({ keep = false } = {}) {
    toUrl();
    const mine = ++seq;
    const r = await get(`/resources?${params()}`);
    if (mine !== seq) return;
    data = r;
    if (!keep) active = 0;
    active = Math.min(active, Math.max(0, data.items.length - 1));
    draw();
  }

  function drawTiles() {
    const e = data.exposure;
    const expTile = (k, label) => tile(label, num(e[k] || 0), f.exposure === k ? 'filtered · click to clear' : 'click to filter',
      { pressed: f.exposure === k, bad: k === 'public' && e[k] > 0, onClick: () => { f.exposure = f.exposure === k ? '' : k; expSel.value = f.exposure; f.page = 1; load(); } });
    tiles.replaceChildren(
      tile('Needs attention', num(data.attention), f.state === 'attention' ? 'filtered · click to clear' : 'high or medium, not expected',
        { pressed: f.state === 'attention', bad: data.attention > 0, onClick: () => { f.state = f.state === 'attention' ? '' : 'attention'; f.page = 1; load(); } }),
      expTile('public', 'Public'), expTile('external', 'Outside accounts'), expTile('cross-account', 'Your other accounts'), expTile('service', 'AWS services'));
    waiting.textContent = `${num(data.attention)} need${data.attention === 1 ? 's' : ''} attention`;
    const svcs = Object.entries(data.services);
    svcSel.replaceChildren(h('option', { value: '' }, 'Every type'), ...svcs.map(([k, n]) => h('option', { value: k, selected: f.service === k }, `${data.labels.services[k] || k} (${num(n)})`)),
      f.service && !data.services[f.service] ? h('option', { value: f.service, selected: true }, `${data.labels.services[f.service] || f.service} (0)`) : null);
    count.textContent = `${num(data.total)} resource${data.total === 1 ? '' : 's'}`;
  }

  const emptyText = () => {
    if (!accounts.length) return 'No accounts yet. Connect one to start.';
    if (!f.q && !f.exposure && !f.service && !f.state && !f.accounts.size && !f.control && !f.severity.size) return 'Nothing here is shared beyond its own account, or no scan has read resource policies yet. Scans read them with the inventory; the scanner role needs the read permissions listed on each account.';
    return 'No resources match these filters.';
  };

  function drawList() {
    if (!data.items.length) { listEl.replaceChildren(h('div', { class: 'empty' }, emptyText())); return; }
    const rows = data.items.map((x, i) => h('tr', { class: `link${i === active ? ' active' : ''}`, 'aria-selected': String(i === active), 'data-i': i, onClick: () => setActive(i) },
      h('td', null, x.worst ? h('span', { class: `badge b-${x.worst}` }, x.worst) : h('span', { class: 'muted small' }, '—')),
      h('td', { class: 'small nowrap' }, SHORT[x.service] || x.service),
      h('td', null, h('div', { class: 'f-title' }, x.name), h('div', { class: 'tiny muted' }, `${x.cloud === 'gcp' ? `${x.project_id || x.account_name} · Google Cloud` : x.account_name}${x.region ? ` · ${x.region}` : ''}${x.unreadable ? ' · policy not readable' : ''}`)),
      h('td', null, h('span', { class: `badge ${EXPOSURE_BADGE[x.exposure]}` }, data.labels.exposure[x.exposure] || x.exposure)),
      h('td', { class: 'small nowrap' }, x.open ? `${x.open} open${x.expected ? ` · ${x.expected} expected` : ''}` : h('span', { class: 'muted' }, x.outside ? `${x.outside} outside` : '—'))));
    listEl.replaceChildren(h('div', { class: 'scroll' }, h('table', { class: 'inbox-table' },
      h('thead', null, h('tr', null, h('th', null, 'Worst'), h('th', null, 'Type'), h('th', null, 'Resource'), h('th', null, 'Exposure'), h('th', null, 'Findings'))),
      h('tbody', null, rows))),
    data.total > SIZE && pager({ page: f.page, total: data.total, size: SIZE, onPage: (n) => { f.page = n; load(); } }));
  }

  async function drawDetail() {
    const x = data.items[active];
    if (!x) { detail.replaceChildren(h('div', { class: 'empty card' }, data.items.length ? 'Pick a resource.' : 'Nothing to show.')); return; }
    const mine = ++detailSeq;
    detail.replaceChildren(h('div', { class: 'muted small' }, 'Loading…'));
    let d;
    try { d = await get(`/resources/${x.id}`); } catch (e) { if (mine === detailSeq) detail.replaceChildren(h('div', { class: 'empty' }, e.message)); return; }
    if (mine !== detailSeq) return;
    const open = d.findings.filter((y) => y.status === 'open'), gone = d.findings.filter((y) => y.status !== 'open');
    const onDecided = () => { ctx.refreshStatus?.(); load({ keep: true }); };
    detail.replaceChildren(
      h('div', { class: 'stack', style: 'gap:4px' },
        h('div', { class: 'eyebrow' }, d.cloud === 'gcp' ? `${d.label} · ${d.account_name} · project ${d.project_id || '?'}${d.region ? ` · ${d.region}` : ''}` : `${d.label} · ${d.account_name} · ${d.aws_account_id}${d.region ? ` · ${d.region}` : ''}`),
        h('div', { class: 'row' }, h('b', { class: 'name' }, d.name), h('span', { class: `badge ${EXPOSURE_BADGE[d.exposure]}` }, d.exposureLabel)),
        h('div', { class: 'row tiny muted' }, h('span', { class: 'mono' }, d.arn), h('button', { class: 'btn sm', onClick: () => copy(d.arn) }, d.cloud === 'gcp' ? 'Copy name' : 'Copy ARN')),
        h('p', { class: 'tiny muted' }, `Read ${ago(d.seen_at)}${d.policy_changed_at ? ` · policy changed ${fmtDate(d.policy_changed_at)}` : ''}`)),
      ...notes(d),
      h('h3', { class: 'small' }, 'Who can get in'), grantsTable(d),
      h('h3', { class: 'small' }, open.length ? `Findings (${open.length})` : 'Findings'),
      open.length ? open.map((y) => findingCard(y, onDecided)) : h('p', { class: 'small muted' }, 'None open.'),
      gone.length > 0 && h('details', null, h('summary', { class: 'small' }, `Resolved in the last 30 days (${gone.length})`), h('div', { class: 'stack' }, gone.map((y) => findingCard(y)))),
      d.policy && h('details', null, h('summary', { class: 'small' }, 'Policy document'),
        h('div', { class: 'stack' }, h('div', { class: 'row' }, h('button', { class: 'btn sm', onClick: () => copy(JSON.stringify(d.policy, null, 2)) }, 'Copy')), h('pre', null, JSON.stringify(d.policy, null, 2)))));
  }

  function setActive(i, scroll = false) {
    if (!data.items.length) return;
    active = Math.max(0, Math.min(i, data.items.length - 1));
    listEl.querySelectorAll('tr.link').forEach((tr) => { const on = Number(tr.dataset.i) === active; tr.classList.toggle('active', on); tr.setAttribute('aria-selected', String(on)); if (on && scroll) tr.scrollIntoView({ block: 'nearest' }); });
    drawDetail();
  }
  function draw() { drawTiles(); drawList(); drawDetail(); }

  // j/k move, / searches
  const onKey = (e) => {
    if (e.metaKey || e.ctrlKey || e.altKey || document.querySelector('.modal-bg, .side-panel-bg, .win')) return;
    const t = e.target;
    if (t instanceof HTMLElement && (t.isContentEditable || ['INPUT', 'TEXTAREA', 'SELECT'].includes(t.tagName))) { if (e.key === 'Escape') t.blur(); return; }
    if (e.key === 'j' || e.key === 'ArrowDown') { e.preventDefault(); setActive(active + 1, true); }
    else if (e.key === 'k' || e.key === 'ArrowUp') { e.preventDefault(); setActive(active - 1, true); }
    else if (e.key === '/') { e.preventDefault(); search.focus(); }
  };
  document.addEventListener('keydown', onKey);
  ctx.onLeave(() => document.removeEventListener('keydown', onKey));

  await load({ keep: true });
  return h('div', { class: 'stack-lg' },
    h('header', { class: 'head' }, h('div', null, h('div', { class: 'eyebrow' }, 'WATCH · RESOURCES'), h('h1', null, 'Resource access'),
      h('p', { class: 'small muted' }, 'Who resource policies let in from outside: on AWS, S3 buckets, KMS keys, DynamoDB tables, SQS queues, SNS topics, secrets, Lambda functions and ECR repositories; on Google Cloud, resource-level IAM on buckets, BigQuery, Pub/Sub, Cloud KMS, Secret Manager, Cloud Run, Cloud Functions and Artifact Registry.')),
      h('div', { class: 'stack', style: 'align-items:flex-end;gap:8px' }, waiting,
        h('button', { class: 'btn sm', onClick: () => { const p = params(); p.delete('page'); p.delete('limit'); location.href = `/api/resources.csv?${p}`; } }, 'Export CSV'))),
    tiles,
    h('section', { class: 'card' },
      h('div', { class: 'filters' }, search, ctlChip, select('Cloud', CLOUDS, 'cloud'), expSel, svcSel, picker.el, select('State', STATES, 'state'), select('Order', SORTS, 'sort'), count),
      picker.chips,
      h('div', { class: 'inbox' }, listEl, detail)),
    h('p', { class: 'tiny muted' }, h('kbd', null, 'j'), ' ', h('kbd', null, 'k'), ' move · ', h('kbd', null, '/'), ' search · Exposure is the widest grant after conditions and Deny guards. Identity policies in this account are not counted: they only reach this account\'s own identities.'));
}
