// Trust map · Google Cloud: who can get in. Ways into each service account (federation, GKE, impersonation, actAs,
// key minting, keys) and identities from outside granted roles directly, each with its findings. The outside sources
// are rolled up: one row per identity that comes in, with everything it reaches.
import { h, get, num, ago, tile, pager, searchBox, syncUrl, urlSet } from '../lib.js';
import { cloudTabs, GCP_CONNECTIONS } from './gcp.js';

const SEV = { high: 'b-high', medium: 'b-medium', low: 'b-low', info: 'b-neutral' };
const FROM_BADGE = { public: 'b-high', external: 'b-medium', 'other-org': 'b-medium', aws: 'b-amber', oidc: 'b-amber', gke: 'b-neutral', key: 'b-neutral', org: 'b-green', own: 'b-green', deleted: 'b-neutral' };
const TILES = ['public', 'external', 'other-org', 'own', 'aws', 'oidc', 'gke', 'key'];
const shortRole = (r) => String(r || '').replace(/^roles\//, '').replace(/^(projects|organizations)\/[^/]+\/roles\//, 'custom: ');
// federated members run to 150 characters: the start and the end say which pool and which identity
const clip = (t, n = 56) => (String(t).length > n ? `${String(t).slice(0, 22)}…${String(t).slice(-(n - 23))}` : String(t));
const memberLine = (m) => h('div', { class: 'tiny muted mono', title: m }, clip(m));
const sevBadge = (s) => (s && s !== 'none' ? h('span', { class: `badge ${SEV[s]}` }, s) : h('span', { class: 'muted small' }, '—'));

export async function gcpTrustPage(ctx) {
  ctx.setCrumbs('Trust map', 'Google Cloud');
  const P = ctx.params;
  const f = { q: P.get('q') || '', from: urlSet(P, 'from'), severity: urlSet(P, 'severity'), via: P.get('via') || '', connection: P.get('connection') || '', project: P.get('project') || '',
    attention: P.get('attention') === '1', sort: ['worst', 'target', 'source'].includes(P.get('sort')) ? P.get('sort') : 'worst', page: Math.max(0, Number(P.get('page')) || 0) };
  const SIZE = 50;
  let d;
  const qs = (extra = {}) => {
    const p = new URLSearchParams({ size: SIZE, page: f.page, sort: f.sort, ...extra });
    if (f.q) p.set('q', f.q); if (f.from.size) p.set('from', [...f.from].join(',')); if (f.severity.size) p.set('severity', [...f.severity].join(','));
    if (f.via) p.set('via', f.via); if (f.connection) p.set('connection', f.connection); if (f.project) p.set('project', f.project); if (f.attention) p.set('attention', '1');
    return p;
  };
  const tilesEl = h('div', { class: 'tiles' }), sourcesEl = h('div'), waysEl = h('div'), count = h('span', { class: 'count' });
  const selects = h('div', { class: 'row', style: 'gap:8px;flex-wrap:wrap' });

  async function load() {
    syncUrl({ cloud: 'gcp', q: f.q, from: f.from, severity: f.severity, via: f.via, connection: f.connection, project: f.project, attention: f.attention ? '1' : '', sort: f.sort === 'worst' ? '' : f.sort, page: f.page || '' });
    d = await get(`/gcp/trust?${qs()}`);
    draw();
  }
  const search = searchBox({ value: f.q, placeholder: 'Filter: a service account, an identity, a role, a finding', label: 'Filter ways in', onSearch: (v) => { f.q = v.trim(); f.page = 0; load(); } });
  ctx.onLeave(search.cancel);
  const sel = (label, value, options, onChange) => {
    const s = h('select', { 'aria-label': label }, options.map(([v, l]) => h('option', { value: v, selected: value === v }, l)));
    s.addEventListener('change', () => { onChange(s.value); f.page = 0; load(); });
    return s;
  };

  function draw() {
    const c = d.counts;
    const tileFor = (k) => tile(d.labels.from[k], num(c.from[k] || 0), f.from.has(k) ? 'filtered · click to clear' : 'ways in',
      { pressed: f.from.has(k), bad: (k === 'public' || k === 'external') && c.from[k] > 0, onClick: () => { f.from.has(k) ? f.from.delete(k) : f.from.add(k); f.page = 0; load(); } });
    tilesEl.replaceChildren(
      tile('Needs attention', num(c.attention), f.attention ? 'filtered · click to clear' : 'high or medium', { pressed: f.attention, bad: c.attention > 0, onClick: () => { f.attention = !f.attention; f.page = 0; load(); } }),
      ...TILES.filter((k) => c.from[k] || f.from.has(k)).map(tileFor));
    selects.replaceChildren(
      sel('Severity', [...f.severity][0] || '', [['', 'Any severity'], ['high', 'High'], ['medium', 'Medium'], ['low', 'Low'], ['none', 'Nothing to flag']], (v) => { f.severity = new Set(v ? [v] : []); }),
      sel('How', f.via, [['', 'Any way in'], ...Object.entries(d.labels.via)], (v) => { f.via = v; }),
      d.connections.length > 1 && sel('Connection', f.connection, [['', 'Every connection'], ...d.connections.map((x) => [x.id, x.name])], (v) => { f.connection = v; }),
      sel('Project', f.project, [['', 'Every project'], ...d.projects.map((x) => [x.project_id, x.project_id])], (v) => { f.project = v; }),
      sel('Order', f.sort, [['worst', 'Worst first'], ['target', 'By service account'], ['source', 'By identity']], (v) => { f.sort = v; }));
    count.textContent = `${num(d.total)} way${d.total === 1 ? '' : 's'} in`;

    // ---- the outside sources
    sourcesEl.replaceChildren(d.sources.length ? h('div', { class: 'scroll' }, h('table', null,
      h('thead', null, h('tr', null, ['', 'Identity', 'From', 'How', 'Reaches'].map((x) => h('th', null, x)))),
      h('tbody', null, d.sources.slice(0, 30).map((s) => h('tr', null,
        h('td', null, sevBadge(s.worst)),
        h('td', null, h('div', null, s.label), s.member && s.member !== s.label && memberLine(s.member),
          s.awsRoleId && h('a', { class: 'tiny', href: `#/identities/${s.awsRoleId}` }, 'The AWS role →')),
        h('td', null, h('span', { class: `badge ${FROM_BADGE[s.from]}` }, d.labels.from[s.from])),
        h('td', { class: 'small' }, s.vias.map((v) => d.labels.via[v] || v).join(', ')),
        h('td', { class: 'small' }, [s.serviceAccounts.length && `${s.serviceAccounts.length} service account${s.serviceAccounts.length === 1 ? '' : 's'}`,
          s.projects.length && `${s.projects.length} resource${s.projects.length === 1 ? '' : 's'} or project${s.projects.length === 1 ? '' : 's'}`].filter(Boolean).join(' · '),
          h('div', { class: 'tiny muted', title: [...s.serviceAccounts, ...s.projects].join('\n') }, [...s.serviceAccounts.map((x) => x.split('@')[0]), ...s.projects].slice(0, 3).join(', '), s.targets > 3 ? ', …' : '')))))))
      : h('p', { class: 'small muted' }, 'Nothing from outside your organisation comes in, under these filters.'));

    // ---- every way in
    const row = (w) => h('tr', null,
      h('td', null, sevBadge(w.worst)),
      h('td', null, w.target.kind === 'serviceAccount'
        ? [h('a', { href: `#/identities/gcp/${w.target.id}` }, w.target.label), h('div', { class: 'tiny muted' }, `${w.target.project || ''}${w.target.env ? ` · ${w.target.env}` : ''}`)]
        // one grant on a whole project, folder or organization: every service account below it, listed on demand
        : w.target.kind === 'scope' ? h('details', null, h('summary', null, w.target.label),
          h('ul', { class: 'plain tiny', style: 'margin:4px 0 0;max-height:220px;overflow:auto' }, w.target.members.map((m) => h('li', null, h('a', { href: `#/identities/gcp/${m.id}` }, m.label), m.risk === 'High' ? h('span', { class: 'badge b-high', style: 'margin-left:6px' }, 'high risk') : null))))
        : [h('div', null, w.target.label), h('div', { class: 'tiny muted' }, 'directly, no service account')]),
      h('td', null, h('span', { class: `badge ${FROM_BADGE[w.from]}` }, d.labels.from[w.from]), h('div', { class: 'small' }, w.principalId ? h('a', { href: `#/identities/gcp/${w.principalId}` }, w.label) : w.label),
        w.member && w.member !== w.label && memberLine(w.member), w.awsRoleId && h('a', { class: 'tiny', href: `#/identities/${w.awsRoleId}` }, 'The AWS role →')),
      h('td', { class: 'small' }, d.labels.via[w.via] || w.via, w.role && h('div', { class: 'tiny muted mono' }, shortRole(w.role)), w.at && h('div', { class: 'tiny muted' }, `on ${w.at.label}`),
        w.keys && h('div', { class: 'tiny muted' }, w.keys.map((k) => `created ${ago(k.created)}`).join(', '))),
      h('td', null, w.findings.length ? w.findings.map((x) => h('div', { class: 'small', title: x.detail }, sevBadge(x.severity), ' ', x.title)) : h('span', { class: 'tiny muted' }, 'nothing to flag')));
    waysEl.replaceChildren(d.items.length ? h('div', { class: 'scroll' }, h('table', null,
      h('thead', null, h('tr', null, ['', 'Way in to', 'From', 'How', 'Findings'].map((x) => h('th', null, x)))), h('tbody', null, d.items.map(row))))
      : h('div', { class: 'empty' }, c.all ? 'No way in matches these filters.' : 'No Google Cloud scanned yet, or nothing can get in.'),
    d.total > SIZE && pager({ page: f.page + 1, total: d.total, size: SIZE, onPage: (n) => { f.page = n - 1; load(); } }));
  }

  const [conns] = await Promise.all([get('/gcp/connections').catch(() => ({ items: [] }))]);
  const head = h('header', { class: 'head' },
    h('div', null, h('div', { class: 'eyebrow' }, 'TRUST MAP · GOOGLE CLOUD'), h('h1', null, 'Who can get into your Google Cloud'),
      h('p', { class: 'muted small', style: 'margin:4px 0 0' }, 'Ways into each service account (federation from AWS and CI, GKE workloads, impersonation, actAs, key minting, keys) and identities from outside your organisation granted roles directly. Read from IAM policies; conditions are shown, not evaluated.')),
    h('div', { class: 'row', style: 'gap:8px' }, h('button', { class: 'btn', onClick: () => { const p = qs(); p.delete('page'); p.delete('size'); location.href = `/api/gcp/trust.csv?${p}`; } }, 'Export CSV')));
  if (!conns.items.length) {
    return h('div', { class: 'stack-lg tm2' }, cloudTabs('gcp', '#/trust'), head, h('div', { class: 'card empty' }, 'No Google Cloud connected. ', h('a', { href: GCP_CONNECTIONS }, 'Connect an organization, folder or project'), ' to see who can get in.'));
  }
  await load();
  // a connection whose organization cannot be read has no domain: nobody there can be told to be outside it
  const noDomain = d.noDomain?.length ? h('div', { class: 'card card-b small', role: 'note' }, h('b', null, 'Your domain is not known for ', d.noDomain.join(', '), '. '),
    'Its reader cannot read the organization (a connection on a folder or a project), so users, groups and domains there are not checked against it. ',
    h('a', { href: '#/admin/config' }, 'Add your domains'), ' under Configuration → Google Cloud.') : null;
  return h('div', { class: 'stack-lg tm2' }, cloudTabs('gcp', '#/trust'), head, noDomain, tilesEl,
    h('section', { class: 'card' }, h('div', { class: 'card-h' }, h('div', null, h('h2', null, 'Who comes in from outside'), h('p', { class: 'small muted' }, 'One row per identity from outside your organisation, with everything it reaches.'))), h('div', { class: 'card-b' }, sourcesEl)),
    h('section', { class: 'card' }, h('div', { class: 'card-h' }, h('h2', null, 'Every way in'), count),
      h('div', { class: 'card-b stack' }, h('div', { class: 'filters' }, search, selects), waysEl)));
}
