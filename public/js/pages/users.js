// IAM users: long-lived credentials. Every access key with its ID, status, age and last use; console passwords and MFA;
// groups; what each key did. A user's permission analysis is the same as a role's (Roles page, "Permissions" tab).
import { h, get, num, ago, fmtDate, fmtDay, riskBadge, envName, loadEnvironments, tile, pager, searchBox, accountPicker, syncUrl, urlSet } from '../lib.js';
import { go } from '../main.js';

const F = { q: '', accounts: new Set(), risk: '', flag: '', sort: 'risk', page: 1 };   // kept when you come back by the rail link
const URL_KEYS = ['q', 'accounts', 'account', 'risk', 'flag', 'sort', 'page'];
const FLAGS = [['oldKey', 'Key older than 90 days'], ['unusedKey', 'Unused key'], ['twoKeys', 'Two active keys'], ['noMfa', 'Console without MFA'], ['console', 'Has a console password'], ['hasKeys', 'Has access keys'], ['inactive', 'Inactive 90 days']];
const dayText = (n) => (n == null ? '—' : n === 0 ? 'today' : n === 1 ? '1 day' : `${num(n)} days`);
const usedText = (k) => (k.lastUsed ? `${ago(k.lastUsed)}${k.lastService ? ` · ${k.lastService}` : ''}${k.lastRegion ? ` · ${k.lastRegion}` : ''}` : 'never used');
const statusBadge = (s) => h('span', { class: `badge ${s === 'Active' ? 'b-green' : s === 'Inactive' ? 'b-neutral' : 'b-low'}` }, s);

/** One key on one line: ID, status, age (red past the rotation limit), last use. */
function keyLine(k, rules) {
  return h('div', { class: 'key-line' },
    h('span', { class: 'mono' }, k.id), statusBadge(k.status),
    h('span', { class: `small ${k.old ? 'key-bad' : 'muted'}`, title: `Created ${fmtDate(k.created)}` }, `${dayText(k.ageDays)} old`),
    h('span', { class: `small ${k.unused ? 'key-bad' : 'muted'}`, title: k.trailCalls ? `${num(k.trailCalls)} calls seen in CloudTrail` : 'No call seen in CloudTrail' }, k.status === 'Active' ? `used ${usedText(k)}` : k.lastUsed ? `last used ${ago(k.lastUsed)}` : 'never used'),
    k.old && h('span', { class: 'badge b-medium', title: `Rotate keys every ${rules.rotateDays} days` }, 'rotate'),
    k.unused && h('span', { class: 'badge b-medium', title: `Unused for more than ${rules.staleDays} days` }, 'deactivate'));
}

export async function usersPage(ctx) {
  ctx.setCrumbs('IAM users');
  await loadEnvironments();
  // every filter is in the address: #/users?accounts=<id>,<id>&flag=oldKey. (`account=` from older links still works.)
  const P = ctx.params;
  if (URL_KEYS.some((k) => P.has(k))) {
    const ids = urlSet(P, 'accounts'); if (P.get('account')) ids.add(P.get('account'));
    Object.assign(F, { q: P.get('q') || '', accounts: ids, risk: P.get('risk') || '', flag: P.get('flag') || '', sort: P.get('sort') || 'risk', page: Math.max(1, Number(P.get('page')) || 1) });
  }
  const accounts = (await get('/accounts')).items.filter((a) => a.status !== 'planned');
  for (const id of [...F.accounts]) if (!accounts.some((a) => a.id === id)) F.accounts.delete(id);
  const list = h('div'), tiles = h('div', { class: 'tiles' }), count = h('span', { class: 'count' });
  const qs = () => new URLSearchParams({ sort: F.sort, limit: '25', offset: String((F.page - 1) * 25), ...(F.q ? { q: F.q } : {}), ...(F.accounts.size ? { accounts: [...F.accounts].join(',') } : {}), ...(F.risk ? { risk: F.risk } : {}), ...(F.flag ? { flag: F.flag } : {}) });
  const set = (p) => { Object.assign(F, p, { page: 1 }); load(); };
  async function load() {
    syncUrl({ q: F.q, accounts: F.accounts, risk: F.risk, flag: F.flag, sort: F.sort === 'risk' ? '' : F.sort, page: F.page > 1 ? F.page : '' });
    const r = await get(`/iam-users?${qs()}`);
    count.textContent = `${num(r.total)} users`;
    const t = r.totals;
    const flagTile = (label, value, sub, flag, bad) => tile(label, value, sub, { onClick: () => set({ flag: F.flag === flag ? '' : flag }), pressed: F.flag === flag && !!flag, bad });
    tiles.replaceChildren(
      flagTile('IAM users', num(t.users), `${num(t.high)} high risk · ${num(t.inactive)} inactive 90 days`, ''),
      flagTile('Active access keys', num(t.activeKeys), 'long-lived: they work from anywhere until deleted', 'hasKeys'),
      flagTile(`Keys older than ${r.rules.rotateDays} days`, num(t.oldKeys), 'rotate them, or move the workload to a role', 'oldKey', t.oldKeys > 0),
      flagTile('Unused keys', num(t.unusedKeys), `never used, or not in ${r.rules.staleDays} days: deactivate`, 'unusedKey', t.unusedKeys > 0),
      flagTile('Console without MFA', num(t.consoleNoMfa), `${num(t.console)} users can sign in to the console`, 'noMfa', t.consoleNoMfa > 0));
    list.replaceChildren(r.items.length ? table(r.items, r.rules) : h('div', { class: 'empty' }, t.users ? 'No user matches these filters.' : 'No IAM users found. A scanner role created before user monitoring needs iam:ListUsers and the other user reads; see the account’s setup.'),
      r.total > 25 && pager({ page: F.page, total: r.total, size: 25, onPage: (n) => { F.page = n; load(); } }));
    drawFilters(r);
  }
  // the account picker and the search box are built once, so an open list and the cursor stay put while the results reload
  const picker = accountPicker({ accounts, selected: F.accounts, onChange: () => set({}) });
  const search = searchBox({ placeholder: 'Search user, ARN or access key ID', label: 'Search users', value: F.q, onSearch: (v) => { F.q = v; F.page = 1; load(); } });
  const rest = h('div', { style: 'display:contents' });
  const filters = h('div', { class: 'filters' }, search, h('div', { class: 'row acct-row' }, picker.el, picker.chips), rest);
  function drawFilters(r) {
    const sel = (key, opts, label) => { const s = h('select', { 'aria-label': label }, opts.map(([v, l]) => h('option', { value: v, selected: F[key] === v }, l))); s.addEventListener('change', () => set({ [key]: s.value })); return s; };
    rest.replaceChildren(
      h('div', { class: 'pill-bar', role: 'group', 'aria-label': 'Risk' }, ...['High', 'Medium', 'Low'].map((x) => h('button', { class: 'chip', type: 'button', 'aria-pressed': String(F.risk === x), onClick: () => set({ risk: F.risk === x ? '' : x }) }, x))),
      sel('flag', [['', 'Anything'], ...FLAGS.map(([k, l]) => [k, `${l} (${r.counts[k]})`])], 'Finding'),
      sel('sort', [['risk', 'Riskiest first'], ['keyAge', 'Oldest key first'], ['lastSeen', 'Longest unused first'], ['calls', 'Busiest first'], ['name', 'Name']], 'Sort'), count);
  }
  const table = (items, rules) => h('div', { class: 'scroll' }, h('table', { class: 'users-table' },
    h('thead', null, h('tr', null, h('th', null, 'User'), h('th', null, 'Risk'), h('th', null, 'Access keys · ID, status, age, last use'), h('th', null, 'Console'), h('th', null, 'Activity'), h('th', null, 'Findings'))),
    h('tbody', null, items.map((u) => h('tr', { class: 'link', tabindex: '0', onClick: (e) => { if (!e.target.closest('a')) go(`#/users/${u.id}`); }, onKeydown: (e) => { if (e.key === 'Enter') go(`#/users/${u.id}`); } },
      h('td', null, h('div', { class: 'name' }, u.name), h('div', { class: 'tiny muted' }, `${u.account.name} · ${u.account.awsAccountId} · ${envName(u.account.environment)}`),
        u.groups.length ? h('div', { class: 'tiny muted' }, `groups: ${u.groups.join(', ')}`) : null),
      h('td', null, riskBadge(u.risk)),
      h('td', null, u.keys.length ? h('div', { class: 'stack', style: 'gap:4px' }, ...u.keys.filter((k) => k.status !== 'Deleted').map((k) => keyLine(k, rules))) : h('span', { class: 'muted small' }, 'no access keys')),
      h('td', { class: 'small nowrap' }, u.console.password ? h('div', null, u.console.mfa.length ? h('span', { class: 'badge b-green' }, 'MFA') : h('span', { class: 'badge b-high' }, 'no MFA'),
        h('div', { class: 'tiny muted' }, u.console.lastUsed ? `signed in ${ago(u.console.lastUsed)}` : 'never signed in')) : h('span', { class: 'muted' }, 'no password')),
      h('td', { class: 'small nowrap' }, u.calls7 ? `${num(u.calls7)} calls · 7 d` : h('span', { class: 'muted' }, 'none in 7 days'), h('div', { class: 'tiny muted' }, u.lastSeen ? `last ${ago(u.lastSeen)}` : 'never seen')),
      h('td', { class: 'small' }, u.reasons.slice(0, 2).map((x) => h('div', null, x)), u.reasons.length > 2 ? h('div', { class: 'tiny muted' }, `+${u.reasons.length - 2} more`) : null))))));

  load();
  ctx.onLeave(() => { search.cancel(); picker.destroy(); });
  return h('div', { class: 'stack-lg' },
    h('header', { class: 'head' }, h('div', null, h('div', { class: 'eyebrow' }, 'IAM USERS'), h('h1', null, 'IAM users and access keys'),
      h('p', { class: 'muted' }, 'Long-lived credentials: every access key with its ID, status, age and last use, console passwords and MFA. Secret keys are never readable, here or in AWS; only their IDs.')),
    h('div', { class: 'actions' }, h('a', { class: 'btn', href: '#/space?who=users' }, 'In Space'), h('a', { class: 'btn', href: '#/?who=users' }, 'On the radar'))),
    tiles, h('section', { class: 'card' }, filters, list));
}

export async function userPage(ctx, id) {
  const u = await get(`/iam-users/${id}`);
  ctx.setCrumbs(h('a', { href: '#/users' }, 'IAM users'), u.account.name, u.name);
  const section = (title, sub, ...kids) => h('section', { class: 'card' }, h('div', { class: 'card-h' }, h('div', null, h('h2', null, title), sub && h('p', { class: 'muted small' }, sub))), h('div', { class: 'card-b stack' }, ...kids));
  const kv = (...pairs) => h('dl', { class: 'kv' }, ...pairs.flatMap(([k, v]) => [h('dt', null, k), h('dd', null, v)]));
  const keys = section('Access keys', 'The secret part of a key is shown once, when it is created, and never again; only the ID is listed.',
    u.keys.length ? h('div', { class: 'scroll' }, h('table', { class: 'small' },
      h('thead', null, h('tr', null, h('th', null, 'Access key ID'), h('th', null, 'Status'), h('th', null, 'Created'), h('th', null, 'Age'), h('th', null, 'Last used (IAM)'), h('th', null, 'Seen in CloudTrail'), h('th', null, 'From'))),
      h('tbody', null, u.keys.map((k) => h('tr', null,
        h('td', { class: 'mono' }, k.id), h('td', null, statusBadge(k.status), k.deletedAt && h('div', { class: 'tiny muted' }, `removed ${ago(k.deletedAt)}`)),
        h('td', null, fmtDay(k.created)), h('td', { class: k.old ? 'key-bad' : null }, dayText(k.ageDays), k.old && h('div', { class: 'tiny' }, 'rotate')),
        h('td', { class: k.unused ? 'key-bad' : null }, k.lastUsed ? usedText(k) : 'never', k.unused && h('div', { class: 'tiny' }, k.status === 'Active' ? 'deactivate' : '')),
        h('td', null, k.trailCalls ? `${num(k.trailCalls)} calls` : 'none', k.trailLast && h('div', { class: 'tiny muted' }, `${fmtDay(k.trailFirst)} to ${fmtDay(k.trailLast)}`)),
        h('td', { class: 'mono tiny' }, k.sourceIps.slice(0, 3).join(', '), k.sourceIps.length > 3 ? ` +${k.sourceIps.length - 3}` : '')))))) : h('p', { class: 'muted' }, 'No access keys.'));
  const consoleBox = section('Console sign-in', null, u.console.password
    ? kv(['Password', `set ${fmtDay(u.console.created)}`], ['Last sign-in', u.console.lastUsed ? `${fmtDate(u.console.lastUsed)} (${ago(u.console.lastUsed)})` : 'never'],
      ['MFA', u.console.mfa.length ? u.console.mfa.map((m) => `${m.type} · ${m.serial.split('/').pop()}${m.enabled ? ` · since ${fmtDay(m.enabled)}` : ''}`).join('; ') : h('span', { class: 'badge b-high' }, 'none')])
    : h('p', { class: 'muted' }, 'No console password: this user can only use access keys.'));
  const who = section('Who used it · 30 days', 'Calls by each access key, and by console or temporary sessions.',
    u.callers.length ? h('div', { class: 'scroll' }, h('table', { class: 'small' }, h('thead', null, h('tr', null, h('th', null, 'Credential'), h('th', null, 'Calls'), h('th', null, 'Refused'), h('th', null, 'First seen'), h('th', null, 'Last seen'))),
      h('tbody', null, u.callers.map((c) => h('tr', null, h('td', { class: c.kind === 'access-key' ? 'mono' : null }, c.display), h('td', null, num(c.calls30)), h('td', { class: c.denied30 ? 'key-bad' : null }, num(c.denied30)),
        h('td', null, fmtDay(c.first_seen)), h('td', null, c.last_seen ? ago(c.last_seen) : '—')))))) : h('p', { class: 'muted' }, 'No call seen in the history read so far.'),
    u.assumes.length > 0 && h('div', null, h('h3', null, 'Roles it assumed'), h('ul', { class: 'plain stack', style: 'gap:4px' }, u.assumes.map((r) => h('li', null, h('a', { href: `#/roles/${r.id}` }, r.name), h('span', { class: 'small muted' }, ` · ${r.account_name} · ${num(r.sessions_count)} sessions${r.last_seen ? `, last ${ago(r.last_seen)}` : ''}`))))));
  const pol = section('Policies', `Its own policies and those of its groups. Permissions used and unused are on the analysis page.`,
    u.policies.length ? h('ul', { class: 'plain stack', style: 'gap:4px' }, u.policies.map((p) => h('li', null, h('span', { class: 'badge b-neutral' }, p.kind === 'group' ? `group ${p.name.split('/')[0]}` : p.kind), ' ', h('b', null, p.kind === 'group' ? p.name.split('/').slice(1).join('/') : p.name), p.arn ? h('span', { class: 'mono tiny muted' }, ` ${p.arn}`) : null)))
      : h('p', { class: 'muted' }, 'No policies: it can do nothing.'),
    kv(['Permissions', `${num(u.permissions.granted)} granted · ${num(u.permissions.used)} used · ${num(u.permissions.unused)} never used · ${num(u.permissions.unconfirmed)} cannot be verified`], ['Groups', u.groups.join(', ') || 'none']));
  return h('div', { class: 'stack-lg' },
    h('header', { class: 'head' }, h('div', null, h('div', { class: 'eyebrow' }, `IAM USER · ${u.account.name}`), h('h1', null, u.name),
      h('div', { class: 'row', style: 'gap:8px;flex-wrap:wrap' }, riskBadge(u.risk), h('span', { class: 'badge b-neutral' }, envName(u.account.environment)), h('span', { class: 'small muted mono' }, u.arn)),
      h('p', { class: 'small muted' }, `Created ${fmtDay(u.created)} (${dayText(u.ageDays)} ago) · user ID ${u.userId || '—'} · ${u.lastSeen ? `last active ${ago(u.lastSeen)}` : 'never seen active'}`)),
    h('div', { class: 'actions' }, h('a', { class: 'btn primary', href: `#/roles/${u.id}` }, 'Permission analysis'), h('a', { class: 'btn', href: `#/space?view=account&account=${u.account.id}&who=users&sel=${u.id}` }, 'In Space'))),
    h('section', { class: 'card' }, h('div', { class: 'card-b stack' }, h('h3', null, 'Why this risk level'),
      u.reasons.length ? h('ul', { class: 'plain' }, u.reasons.map((x) => h('li', null, x))) : h('p', { class: 'muted' }, 'Nothing stands out.'))),
    keys, consoleBox, who, pol);
}
