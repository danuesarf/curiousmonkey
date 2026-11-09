import { h, get, post, num, riskBadge, teamBadge, usageBar, ago, toast, KIND, TEAM } from '../lib.js';
import { session, go } from '../main.js';

const DEFAULT = { q: '', accounts: new Set(), kinds: new Set(), risks: new Set(), teams: new Set(), unconfirmed: false, idle: false, openFlags: false, unidentified: false, policy: '', sort: 'risk', dir: 'desc', page: 1 };
const saved = { ...DEFAULT };   // survives navigating to a role and back

export async function overview(ctx) {
  const f = saved;
  // a link can open the list already filtered: #/roles?accounts=<id>,<id>&risks=High
  const ids = (k) => (ctx.params.get(k) || '').split(',').filter(Boolean);
  if (ids('accounts').length || ids('risks').length) Object.assign(f, { ...DEFAULT, accounts: new Set(ids('accounts')), risks: new Set(ids('risks')), kinds: new Set(), teams: new Set() });
  ctx.setCrumbs('Roles');
  const [ov, accts] = await Promise.all([get('/overview'), get('/accounts')]);
  const accounts = accts.items.filter((a) => a.status !== 'planned');     // planned accounts have no roles to list
  for (const id of [...f.accounts]) if (!accounts.some((a) => a.id === id)) f.accounts.delete(id);
  const list = h('div'), tiles = h('div', { class: 'tiles' });
  let timer;

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

  async function load() {
    const r = await get(`/roles?${query()}`);
    list.replaceChildren(r.items.length ? table(r) : h('div', { class: 'empty' }, accounts.length ? 'No roles match these filters.' : 'No accounts yet. Connect one to start.'),
      r.total > 25 && pager(r.total));
    count.textContent = `${num(r.total)} roles`;
  }
  const pager = (total) => h('div', { class: 'pager' }, h('span', { class: 'small muted' }, `Page ${f.page} of ${Math.ceil(total / 25)}`),
    h('button', { class: 'btn sm', disabled: f.page <= 1, onClick: () => { f.page--; load(); } }, 'Previous'),
    h('button', { class: 'btn sm', disabled: f.page * 25 >= total, onClick: () => { f.page++; load(); } }, 'Next'));

  const sortTh = (key, label) => h('th', { 'aria-sort': f.sort === key ? (f.dir === 'asc' ? 'ascending' : 'descending') : 'none' },
    h('button', { class: 'chip', type: 'button', onClick: () => { f.dir = f.sort === key && f.dir === 'desc' ? 'asc' : 'desc'; f.sort = key; load(); } }, label, f.sort === key ? (f.dir === 'asc' ? ' ↑' : ' ↓') : ''));

  const table = (r) => h('div', { class: 'scroll' }, h('table', null,
    h('thead', null, h('tr', null, sortTh('name', 'Role'), sortTh('risk', 'Risk'), h('th', null, 'Used / unused / unconfirmed'), sortTh('unused', 'Unused'), h('th', null, 'Reviewer'), sortTh('activity', 'Last activity'), h('th', null, 'Findings'), h('th', null, 'State'))),
    h('tbody', null, r.items.map((x) => h('tr', { class: 'link', tabindex: '0', onClick: () => go(`#/roles/${x.id}`), onKeydown: (e) => { if (e.key === 'Enter') go(`#/roles/${x.id}`); } },
      h('td', null, h('div', { class: 'row', style: 'gap:8px' }, h('span', { class: 'name' }, x.name), x.has_unidentified && h('a', { class: 'unk-tag', href: `#/roles/${x.id}?identify=`, title: 'Has calls under unidentified event names', onClick: (e) => e.stopPropagation() }, 'UNK')), h('div', { class: 'tiny muted' }, `${x.account_name} · ${x.aws_account_id} · `, KIND[x.kind], x.permission_set ? ` (${x.permission_set})` : '')),
      h('td', null, riskBadge(x.risk)),
      h('td', { style: null }, usageBar(x.used_count, x.unused_count, x.unconfirmed_count), h('div', { class: 'tiny muted' }, `${num(x.used_count)} / ${num(x.unused_count)} / ${num(x.unconfirmed_count)} of ${num(x.granted_count)}`)),
      h('td', { class: 'nowrap' }, num(x.unused_count)),
      h('td', null, teamBadge(x.reviewer_team, x.requires_both)),
      h('td', { class: 'nowrap small' }, x.last_activity_at ? ago(x.last_activity_at) : 'none seen'),
      h('td', { class: 'small' }, x.open_flags ? `${x.decided_flags} of ${x.open_flags} decided` : 'none'),
      h('td', null, x.history?.complete ? h('span', { class: 'state' }, 'Final') : h('span', { class: 'state prov', title: 'History is still being read' }, `Provisional ${x.history?.progress ?? 0}%`)))))));

  const t = ov.totals;
  const tile = (label, value, sub) => h('div', { class: 'tile' }, h('span', { class: 'small muted' }, label), h('b', null, value), sub && h('span', { class: 'tiny muted' }, sub));
  tiles.append(tile('Roles', num(t.roles), `${ov.byKind.map((k) => `${k.n} ${KIND[k.kind].toLowerCase()}`).join(', ')}`),
    tile('High risk', num(t.high), `${t.medium} medium, ${t.low} low`),
    tile('Permissions used', t.granted ? `${(() => { const p = (t.used / t.granted) * 100; return p < 1 ? (p > 0 ? '<1' : '0') : Math.round(p); })()}%` : 'none', `${num(t.used)} of ${num(t.granted)} granted`),
    tile('Unused', num(t.unused), 'safe to remove after review'),
    tile('Cannot be verified', num(t.unconfirmed), 'event history cannot prove them'));

  const count = h('span', { class: 'count' });
  const search = h('input', { type: 'search', placeholder: 'Search role name or ARN', 'aria-label': 'Search roles', value: f.q });
  search.addEventListener('input', () => { clearTimeout(timer); timer = setTimeout(() => { f.q = search.value; f.page = 1; load(); }, 250); });
  const sel = (key, opts, label) => { const s = h('select', { 'aria-label': label }, opts.map(([v, l]) => h('option', { value: v, selected: f[key] === v }, l))); s.addEventListener('change', () => { f[key] = s.value; f.page = 1; load(); }); return s; };

  // ---- which accounts: one control in the filter bar, not a table above the roles (works the same for 5 or 500) ----
  const ENVS = ['production', 'shared', 'staging', 'development', 'sandbox'].filter((e) => accounts.some((a) => a.environment === e));
  const acctLabel = h('span');
  const acctChips = h('div', { class: 'pill-bar acct-chips' });
  const title = h('h1');
  const drawTitle = () => { title.textContent = f.accounts.size ? `IAM roles in ${f.accounts.size} account${f.accounts.size > 1 ? 's' : ''}` : 'IAM roles across all accounts'; };
  const acctSearch = h('input', { type: 'search', placeholder: `Find among ${accounts.length} accounts`, 'aria-label': 'Find an account' });
  const acctList = h('div', { class: 'acct-list', role: 'group', 'aria-label': 'Accounts' });
  const changed = () => { f.page = 1; drawAccounts(); drawTitle(); scanBtn.textContent = f.accounts.size ? `Scan ${f.accounts.size} selected` : 'Scan all accounts'; load(); };
  function drawAccounts() {
    acctLabel.textContent = f.accounts.size === 0 ? `All ${accounts.length} accounts` : f.accounts.size === 1 ? accounts.find((a) => f.accounts.has(a.id))?.name || '1 account' : `${f.accounts.size} of ${accounts.length} accounts`;
    const picked = accounts.filter((a) => f.accounts.has(a.id));
    acctChips.replaceChildren(...picked.slice(0, 4).map((a) => h('span', { class: 'chip ev-on' }, a.name,
      h('button', { type: 'button', class: 'chip-x', 'aria-label': `Remove ${a.name}`, onClick: () => { f.accounts.delete(a.id); changed(); } }, '×'))),
      picked.length > 4 ? h('span', { class: 'small muted' }, `+${picked.length - 4} more`) : null,
      picked.length ? h('button', { type: 'button', class: 'btn sm', onClick: () => { f.accounts.clear(); changed(); } }, 'Clear') : null);
    const needle = acctSearch.value.trim().toLowerCase();
    const shown = accounts.filter((a) => !needle || `${a.name} ${a.account_id} ${a.environment} ${a.ou || ''}`.toLowerCase().includes(needle))
      .sort((a, b) => (f.accounts.has(b.id) - f.accounts.has(a.id)) || a.name.localeCompare(b.name));
    acctList.replaceChildren(...(shown.length ? shown.map((a) => {
      const cb = h('input', { type: 'checkbox', checked: f.accounts.has(a.id) });
      cb.addEventListener('change', () => { cb.checked ? f.accounts.add(a.id) : f.accounts.delete(a.id); changed(); });
      return h('label', { class: 'acct-opt' }, cb, h('span', { class: 'acct-opt-b' }, h('span', { class: 'name' }, a.name), h('span', { class: 'tiny muted' }, `${a.account_id} · ${a.environment}${a.ou ? ` · ${a.ou}` : ''}`)),
        h('span', { class: 'mono tiny muted' }, `${num(a.roles)} roles`));
    }) : [h('p', { class: 'small muted', style: 'margin:8px' }, 'No account matches.')]));
  }
  acctSearch.addEventListener('input', drawAccounts);
  const onlyEnv = (env) => { f.accounts = new Set(accounts.filter((a) => a.environment === env).map((a) => a.id)); changed(); };
  const acctPicker = h('details', { class: 'acct-picker' },
    h('summary', { class: 'btn', 'aria-label': 'Choose accounts' }, h('span', { class: 'muted' }, 'Accounts: '), acctLabel, ' ▾'),
    h('div', { class: 'acct-pop' }, acctSearch,
      h('div', { class: 'pill-bar' }, h('button', { type: 'button', class: 'chip', onClick: () => { f.accounts.clear(); changed(); } }, 'All'),
        ...ENVS.map((e) => h('button', { type: 'button', class: 'chip', onClick: () => onlyEnv(e) }, `${e[0].toUpperCase()}${e.slice(1)} only`))),
      acctList));
  // close when clicking elsewhere or pressing Escape
  const outside = (e) => { if (acctPicker.open && !acctPicker.contains(e.target)) acctPicker.open = false; };
  const esc = (e) => { if (e.key === 'Escape' && acctPicker.open) { acctPicker.open = false; acctPicker.querySelector('summary').focus(); } };
  document.addEventListener('click', outside); document.addEventListener('keydown', esc);
  acctPicker.addEventListener('toggle', () => { if (acctPicker.open) acctSearch.focus(); });

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
      h('div', null, h('div', { class: 'eyebrow' }, 'ROLES'), title,
        h('p', { class: 'muted' }, 'Results stay provisional until each account’s CloudTrail history is fully read. History is stored, so it grows past the first read over time.')),
      h('div', { class: 'actions' }, session.user.permissions.includes('accounts') && h('a', { class: 'btn', href: '#/accounts/new' }, 'Connect account'), session.user.permissions.includes('scan') && scanBtn)),
    tiles,
    h('section', { class: 'card' },
      h('div', { class: 'filters' }, h('div', { class: 'row acct-row' }, acctPicker, acctChips), search,
        h('div', { class: 'pill-bar', role: 'group', 'aria-label': 'Role kind' }, ...Object.entries(KIND).map(([k, l]) => chip(f.kinds, k, l))),
        h('div', { class: 'pill-bar', role: 'group', 'aria-label': 'Risk' }, ...['High', 'Medium', 'Low'].map((r) => chip(f.risks, r, r))),
        h('div', { class: 'pill-bar', role: 'group', 'aria-label': 'Reviewer' }, ...Object.entries(TEAM).map(([k, l]) => chip(f.teams, k, l))),
        h('div', { class: 'pill-bar', role: 'group', 'aria-label': 'Findings' }, flag('unconfirmed', 'Has unverifiable'), flag('idle', 'Idle role'), flag('openFlags', 'Needs a decision'), flag('unidentified', 'Has unidentified calls')),
        sel('policy', [['', 'Any policy type'], ['inline', 'Has inline policy'], ['managed', 'Has attached policy']], 'Policy type'), count),
      list));
  drawAccounts(); drawTitle();
  load();
  ctx.onLeave(() => { clearTimeout(timer); document.removeEventListener('click', outside); document.removeEventListener('keydown', esc); });
  return body;
}
