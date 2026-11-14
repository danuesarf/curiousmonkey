import { h, get, post, num, pageTabs, riskBadge, teamBadge, usageBar, ago, toast, KIND, TEAM, loadEnvironments, tile, pager, searchBox, accountPicker, syncUrl, urlSet } from '../lib.js';
import { session, go } from '../main.js';
import { gcpRolesTab } from './gcp.js';
import { usersPage } from './users.js';

const DEFAULT = { q: '', accounts: new Set(), kinds: new Set(), risks: new Set(), teams: new Set(), unconfirmed: false, idle: false, openFlags: false, unidentified: false, policy: '', sort: 'risk', dir: 'desc', page: 1 };
const saved = { ...DEFAULT };   // kept when you come back by the rail link (no filters in the address)
const URL_KEYS = ['q', 'accounts', 'kinds', 'risks', 'teams', 'unconfirmed', 'idle', 'openFlags', 'unidentified', 'policy', 'sort', 'dir', 'page'];

/** Which kind of identity the list shows. Kept in the address as ?type=. Google Cloud is hidden from members limited to some AWS accounts. */
export const identityTypes = () => [['roles', 'Roles', '#/identities'], ['users', 'IAM users', '#/identities?type=users'], ...(session.user.scope_accounts ? [] : [['gcp', 'Google Cloud', '#/identities?type=gcp']])];

/** Identities: one page for roles, IAM users and Google Cloud identities, switched at the top. */
export async function identitiesPage(ctx) {
  const types = identityTypes();
  const type = types.some(([k]) => k === ctx.params.get('type')) ? ctx.params.get('type') : 'roles';
  const body = type === 'users' ? usersPage(ctx) : type === 'gcp' ? gcpRolesTab(ctx) : rolesList(ctx);
  return h('div', { class: 'stack-lg' }, pageTabs('Kind of identity', types, type), await body);
}

async function rolesList(ctx) {
  const f = saved;
  // every filter is in the address: #/identities?accounts=<id>,<id>&risks=High. A link, a reload or Back opens the same list.
  const P = ctx.params;
  if (URL_KEYS.some((k) => P.has(k))) {
    Object.assign(f, { ...DEFAULT, q: P.get('q') || '', accounts: urlSet(P, 'accounts'), kinds: urlSet(P, 'kinds'), risks: urlSet(P, 'risks'), teams: urlSet(P, 'teams'),
      unconfirmed: P.get('unconfirmed') === '1', idle: P.get('idle') === '1', openFlags: P.get('openFlags') === '1', unidentified: P.get('unidentified') === '1',
      policy: P.get('policy') || '', sort: P.get('sort') || 'risk', dir: P.get('dir') === 'asc' ? 'asc' : 'desc', page: Math.max(1, Number(P.get('page')) || 1) });
  }
  ctx.setCrumbs('Identities', 'Roles');
  const [ov, accts] = await Promise.all([get('/overview'), get('/accounts')]);
  const accounts = accts.items.filter((a) => a.status !== 'planned');     // planned accounts have no roles to list
  for (const id of [...f.accounts]) if (!accounts.some((a) => a.id === id)) f.accounts.delete(id);
  const list = h('div'), tiles = h('div', { class: 'tiles' });

  const query = () => {
    const p = new URLSearchParams();
    if (f.q) p.set('q', f.q);
    for (const k of ['accounts', 'kinds', 'risks', 'teams']) if (f[k].size) p.set(k, [...f[k]].join(','));
    if (f.unconfirmed) p.set('unconfirmed', '1'); if (f.idle) p.set('idle', '1'); if (f.openFlags) p.set('openFlags', '1'); if (f.unidentified) p.set('unidentified', '1');
    if (f.policy) p.set('hasPolicyKind', f.policy);
    p.set('sort', f.sort); p.set('dir', f.dir); p.set('page', f.page); p.set('limit', '25');
    return p.toString();
  };

  const toggle = (set, v, el) => () => { set.has(v) ? set.delete(v) : set.add(v); el.setAttribute('aria-pressed', set.has(v)); f.page = 1; load(); };
  const chip = (set, v, label) => { const b = h('button', { class: 'chip', type: 'button', 'aria-pressed': set.has(v) }, label); b.addEventListener('click', toggle(set, v, b)); return b; };
  const flag = (key, label) => { const b = h('button', { class: 'chip', type: 'button', 'aria-pressed': f[key] }, label); b.addEventListener('click', () => { f[key] = !f[key]; b.setAttribute('aria-pressed', f[key]); f.page = 1; load(); }); return b; };

  const toUrl = () => syncUrl({ q: f.q, accounts: f.accounts, kinds: f.kinds, risks: f.risks, teams: f.teams, unconfirmed: f.unconfirmed, idle: f.idle, openFlags: f.openFlags, unidentified: f.unidentified,
    policy: f.policy, sort: f.sort === DEFAULT.sort ? '' : f.sort, dir: f.dir === DEFAULT.dir ? '' : f.dir, page: f.page > 1 ? f.page : '' });
  async function load() {
    toUrl();
    const r = await get(`/roles?${query()}`);
    list.replaceChildren(r.items.length ? table(r) : h('div', { class: 'empty' }, accounts.length ? 'No roles match these filters.' : 'No accounts yet. Connect one to start.'),
      r.total > 25 && pager({ page: f.page, total: r.total, size: 25, onPage: (n) => { f.page = n; load(); } }));
    count.textContent = `${num(r.total)} roles`;
  }

  const sortTh = (key, label) => h('th', { 'aria-sort': f.sort === key ? (f.dir === 'asc' ? 'ascending' : 'descending') : 'none' },
    h('button', { class: 'chip', type: 'button', onClick: () => { f.dir = f.sort === key && f.dir === 'desc' ? 'asc' : 'desc'; f.sort = key; load(); } }, label, f.sort === key ? (f.dir === 'asc' ? ' ↑' : ' ↓') : ''));

  const table = (r) => h('div', { class: 'scroll' }, h('table', null,
    h('thead', null, h('tr', null, sortTh('name', 'Role'), sortTh('risk', 'Risk'), h('th', null, 'Used / unused / unconfirmed'), sortTh('unused', 'Unused'), h('th', null, 'Reviewer'), sortTh('activity', 'Last activity'), h('th', null, 'Findings'), h('th', null, 'State'))),
    h('tbody', null, r.items.map((x) => h('tr', { class: 'link', tabindex: '0', onClick: () => go(`#/identities/${x.id}`), onKeydown: (e) => { if (e.key === 'Enter') go(`#/identities/${x.id}`); } },
      h('td', null, h('div', { class: 'row', style: 'gap:8px' }, h('span', { class: 'name' }, x.name), x.has_unidentified && h('a', { class: 'unk-tag', href: `#/identities/${x.id}?identify=`, title: 'Has calls under unidentified event names', onClick: (e) => e.stopPropagation() }, 'UNK')), h('div', { class: 'tiny muted' }, `${x.account_name} · ${x.aws_account_id} · `, KIND[x.kind], x.permission_set ? ` (${x.permission_set})` : '')),
      h('td', null, riskBadge(x.risk)),
      h('td', { style: null }, usageBar(x.used_count, x.unused_count, x.unconfirmed_count), h('div', { class: 'tiny muted' }, `${num(x.used_count)} / ${num(x.unused_count)} / ${num(x.unconfirmed_count)} of ${num(x.granted_count)}`)),
      h('td', { class: 'nowrap' }, num(x.unused_count)),
      h('td', null, teamBadge(x.reviewer_team, x.requires_both)),
      h('td', { class: 'nowrap small' }, x.last_activity_at ? ago(x.last_activity_at) : 'none seen'),
      h('td', { class: 'small' }, x.open_flags ? `${x.decided_flags} of ${x.open_flags} decided` : 'none'),
      h('td', null, x.history?.complete ? h('span', { class: 'state' }, 'Final') : h('span', { class: 'state prov', title: 'History is still being read' }, `Provisional ${x.history?.progress ?? 0}%`)))))));

  const t = ov.totals;
  tiles.append(tile('Roles', num(t.roles), `${ov.byKind.map((k) => `${k.n} ${KIND[k.kind].toLowerCase()}`).join(', ')}`),
    tile('High risk', num(t.high), `${t.medium} medium, ${t.low} low`),
    tile('Permissions used', t.granted ? `${(() => { const p = (t.used / t.granted) * 100; return p < 1 ? (p > 0 ? '<1' : '0') : Math.round(p); })()}%` : 'none', `${num(t.used)} of ${num(t.granted)} granted`),
    tile('Unused', num(t.unused), 'safe to remove after review'),
    tile('Cannot be verified', num(t.unconfirmed), 'event history cannot prove them'));

  const count = h('span', { class: 'count' });
  const search = searchBox({ placeholder: 'Search role name or ARN', label: 'Search roles', value: f.q, onSearch: (v) => { f.q = v; f.page = 1; load(); } });
  const sel = (key, opts, label) => { const s = h('select', { 'aria-label': label }, opts.map(([v, l]) => h('option', { value: v, selected: f[key] === v }, l))); s.addEventListener('change', () => { f[key] = s.value; f.page = 1; load(); }); return s; };

  // ---- which accounts: one control in the filter bar, not a table above the roles (works the same for 5 or 500) ----
  await loadEnvironments();
  const title = h('h1');
  const drawTitle = () => { title.textContent = f.accounts.size ? `IAM roles in ${f.accounts.size} account${f.accounts.size > 1 ? 's' : ''}` : 'IAM roles across all accounts'; };
  const picker = accountPicker({ accounts, selected: f.accounts, onChange: () => { f.page = 1; drawTitle(); scanBtn.textContent = f.accounts.size ? `Scan ${f.accounts.size} selected` : 'Scan all accounts'; load(); } });

  const scanBtn = h('button', { class: 'btn primary', type: 'button', onClick: async (e) => {
    const ids = (f.accounts.size ? accounts.filter((a) => f.accounts.has(a.id)) : accounts).map((a) => a.id);
    e.target.disabled = true;
    const results = await Promise.allSettled(ids.map((id) => post(`/accounts/${id}/scan`)));
    const ok = results.filter((r) => r.status === 'fulfilled').length;
    toast(ok ? `Queued ${ok} scan${ok > 1 ? 's' : ''}. Follow progress under Scan activity.` : 'A scan is already running for the selected accounts.', !ok);
    e.target.disabled = false;
  } }, f.accounts.size ? `Scan ${f.accounts.size} selected` : 'Scan all accounts');

  const body = h('div', { class: 'stack-lg' },
    h('header', { class: 'head' },
      h('div', null, h('div', { class: 'eyebrow' }, 'IDENTITIES · ROLES'), title,
        h('p', { class: 'muted' }, 'Results stay provisional until each account’s CloudTrail history is fully read. History is stored, so it grows past the first read over time.')),
      h('div', { class: 'actions' }, h('a', { class: 'btn', download: '', href: '/api/roles.csv', title: 'Every role the filters match, as a spreadsheet', onClick: (e) => { e.currentTarget.href = `/api/roles.csv?${query()}`; } }, 'Download CSV'),
        session.user.permissions.includes('accounts') && h('a', { class: 'btn', href: '#/accounts/new' }, 'Connect account'), session.user.permissions.includes('scan') && scanBtn)),
    tiles,
    h('section', { class: 'card' },
      h('div', { class: 'filters' }, h('div', { class: 'row acct-row' }, picker.el, picker.chips), search,
        h('div', { class: 'pill-bar', role: 'group', 'aria-label': 'Role kind' }, ...Object.entries(KIND).map(([k, l]) => chip(f.kinds, k, l))),
        h('div', { class: 'pill-bar', role: 'group', 'aria-label': 'Risk' }, ...['High', 'Medium', 'Low'].map((r) => chip(f.risks, r, r))),
        h('div', { class: 'pill-bar', role: 'group', 'aria-label': 'Reviewer' }, ...Object.entries(TEAM).map(([k, l]) => chip(f.teams, k, l))),
        h('div', { class: 'pill-bar', role: 'group', 'aria-label': 'Findings' }, flag('unconfirmed', 'Has unverifiable'), flag('idle', 'Idle role'), flag('openFlags', 'Needs a decision'), flag('unidentified', 'Has unidentified calls')),
        sel('policy', [['', 'Any policy type'], ['inline', 'Has inline policy'], ['managed', 'Has attached policy']], 'Policy type'), count),
      list));
  drawTitle();
  load();
  ctx.onLeave(() => { search.cancel(); picker.destroy(); });
  return body;
}
