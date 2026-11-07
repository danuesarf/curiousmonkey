import { h, get, post, num, riskBadge, teamBadge, usageBar, ago, toast, KIND, TEAM } from '../lib.js';
import { session, go } from '../main.js';

const DEFAULT = { q: '', accounts: new Set(), kinds: new Set(), risks: new Set(), teams: new Set(), unconfirmed: false, idle: false, openFlags: false, unidentified: false, policy: '', sort: 'risk', dir: 'desc', page: 1 };
const saved = { ...DEFAULT };   // survives navigating to a role and back

export async function overview(ctx) {
  const f = saved;
  ctx.setCrumbs('Roles');
  const [ov, accts] = await Promise.all([get('/overview'), get('/accounts')]);
  const accounts = accts.items;
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

  const scopeCard = h('section', { class: 'card', 'aria-labelledby': 'acct-h' },
    h('div', { class: 'card-h' }, h('h2', { id: 'acct-h' }, 'Accounts in scope'),
      h('div', { class: 'pill-bar' },
        h('button', { class: 'btn sm', onClick: () => { f.accounts.clear(); f.page = 1; ctx.reload(); } }, 'All accounts'),
        h('button', { class: 'btn sm', onClick: () => { f.accounts = new Set(accounts.filter((a) => a.environment === 'production').map((a) => a.id)); f.page = 1; ctx.reload(); } }, 'Production only'))),
    accounts.length ? h('div', { class: 'scroll' }, h('table', null,
      h('thead', null, h('tr', null, h('th', null, ''), h('th', null, 'Account'), h('th', null, 'Roles'), h('th', null, 'Data events found'), h('th', null, 'Last scan'))),
      h('tbody', null, accounts.map((a) => {
        const cb = h('input', { type: 'checkbox', checked: f.accounts.has(a.id), 'aria-label': `Include ${a.name}` });
        cb.addEventListener('change', () => { cb.checked ? f.accounts.add(a.id) : f.accounts.delete(a.id); f.page = 1; load(); });
        return h('tr', null, h('td', null, cb), h('td', null, h('div', { class: 'name' }, a.name), h('div', { class: 'tiny muted' }, `${a.account_id} · ${a.environment}`)),
          h('td', null, num(a.roles)), h('td', null, a.data_event_sources ? `${a.data_event_sources} sources` : 'none'),
          h('td', { class: 'small' }, a.status === 'connected' ? ago(a.last_scan_at) : h('span', { class: 'badge b-medium' }, a.status)));
      })))) : h('div', { class: 'empty' }, 'No accounts connected yet.', h('div', null, h('a', { class: 'btn primary', href: '#/accounts/new' }, 'Connect an AWS account'))));

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
      h('div', null, h('div', { class: 'eyebrow' }, 'ROLES'), h('h1', null, f.accounts.size ? `IAM roles in ${f.accounts.size} account${f.accounts.size > 1 ? 's' : ''}` : 'IAM roles across all accounts'),
        h('p', { class: 'muted' }, 'Results stay provisional until each account’s CloudTrail history is fully read. History is stored, so it grows past the first read over time.')),
      h('div', { class: 'actions' }, session.user.permissions.includes('accounts') && h('a', { class: 'btn', href: '#/accounts/new' }, 'Connect account'), session.user.permissions.includes('scan') && scanBtn)),
    tiles, scopeCard,
    h('section', { class: 'card' },
      h('div', { class: 'filters' }, search,
        h('div', { class: 'pill-bar', role: 'group', 'aria-label': 'Role kind' }, ...Object.entries(KIND).map(([k, l]) => chip(f.kinds, k, l))),
        h('div', { class: 'pill-bar', role: 'group', 'aria-label': 'Risk' }, ...['High', 'Medium', 'Low'].map((r) => chip(f.risks, r, r))),
        h('div', { class: 'pill-bar', role: 'group', 'aria-label': 'Reviewer' }, ...Object.entries(TEAM).map(([k, l]) => chip(f.teams, k, l))),
        h('div', { class: 'pill-bar', role: 'group', 'aria-label': 'Findings' }, flag('unconfirmed', 'Has unverifiable'), flag('idle', 'Idle role'), flag('openFlags', 'Needs a decision'), flag('unidentified', 'Has unidentified calls')),
        sel('policy', [['', 'Any policy type'], ['inline', 'Has inline policy'], ['managed', 'Has attached policy']], 'Policy type'), count),
      list));
  load();
  ctx.onLeave(() => clearTimeout(timer));
  return body;
}
