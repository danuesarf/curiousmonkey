// The command palette: Ctrl/⌘ K anywhere. Type a role, IAM user, access key ID, account, Google service account or
// page name and go there, without knowing which page it lives on.
import { h, get, debounced, envName, KIND } from './lib.js';

// [label, address, permission(s), extra words to match]
const PAGES = [
  ['Radar', '#/', 'view', 'home estate'], ['Space', '#/space', 'view', 'map 3d'], ['Trust map', '#/trust', 'view', 'who can get in'],
  ['Events', '#/events', 'view', 'calls cloudtrail history'], ['Findings', '#/findings', 'view', 'review inbox decisions'], ['Access reviews', '#/reviews', 'view', 'uar evidence audit sign-off snapshot'],
  ['Identities · Roles', '#/identities', 'view', 'iam roles list'], ['Identities · IAM users', '#/identities?type=users', 'view', 'access keys'],
  ['Identities · Google Cloud', '#/identities?type=gcp', 'view', 'gcp service accounts', 'unscoped'],
  ['Unidentified calls', '#/unidentified', 'view', 'unknown event names'], ['Accounts', '#/accounts', 'view', 'aws onboarding connect'],
  ['Operations · Scans', '#/operations/scans', 'ops', 'queue jobs'], ['Operations · Workers', '#/operations/workers', 'ops', 'health'], ['Operations · Database', '#/operations/database', 'ops', 'postgres disk'],
  ['Admin · Members', '#/admin/members', 'members', 'users invite password'], ['Admin · Audit log', '#/admin/audit', 'audit', ''],
  ['Admin · Alerts', '#/admin/alerts', 'settings', 'slack webhook notify digest'], ['Admin · Configuration', '#/admin/config', 'settings', 'settings sso environments'],
];
const GCP_KIND = { serviceAccount: 'SA', user: 'USER', group: 'GROUP', federated: 'FEDERATED' };

let open = null;
export const paletteOpen = () => !!open;
export function closePalette() { if (!open) return; const o = open; open = null; o.search.cancel(); document.removeEventListener('keydown', o.onKey, true); o.bg.remove(); o.opener?.focus?.(); }

/**
 * Opens the palette. `user` is the signed-in member (permissions decide which pages are offered);
 * `navigate(hash)` goes to the chosen address.
 */
export function openPalette({ user, navigate }) {
  if (open) return;
  const can = (p) => [].concat(p).some((x) => user.permissions.includes(x));
  const pages = PAGES.filter(([, , perm, , only]) => can(perm) && !(only === 'unscoped' && user.scope_accounts));
  const input = h('input', { type: 'search', class: 'pal-input', placeholder: 'Search roles, users, keys, accounts, pages…', 'aria-label': 'Search everything', autocomplete: 'off', spellcheck: 'false',
    role: 'combobox', 'aria-expanded': 'true', 'aria-controls': 'pal-list', 'aria-autocomplete': 'list' });
  const list = h('div', { class: 'pal-list', id: 'pal-list', role: 'listbox', 'aria-label': 'Results' });
  const foot = h('div', { class: 'pal-foot tiny muted' }, h('kbd', null, '↑'), ' ', h('kbd', null, '↓'), ' move · ', h('kbd', null, 'Enter'), ' open · ', h('kbd', null, 'Esc'), ' close');
  let items = [], active = 0, found = null, seq = 0, waiting = false;

  const pick = (it) => { closePalette(); navigate(it.href); };
  const row = (it, i) => h('div', { class: `pal-row${i === active ? ' on' : ''}`, role: 'option', id: `pal-${i}`, 'aria-selected': String(i === active), onClick: () => pick(it), onMousemove: () => { if (active !== i) { active = i; mark(); } } },
    h('span', { class: 'pal-kind' }, it.kind), h('span', { class: 'pal-name' }, it.name), h('span', { class: 'pal-sub' }, it.sub),
    it.risk ? h('span', { class: `badge b-${it.risk.toLowerCase()}` }, it.risk) : null);
  function mark() {
    list.querySelectorAll('.pal-row').forEach((el, i) => { el.classList.toggle('on', i === active); el.setAttribute('aria-selected', String(i === active)); });
    input.setAttribute('aria-activedescendant', items.length ? `pal-${active}` : '');
    list.querySelector('.pal-row.on')?.scrollIntoView({ block: 'nearest' });
  }
  function draw() {
    const q = input.value.trim(), needle = q.toLowerCase();
    const r = found && found.q === q ? found : null;
    items = [
      ...(r ? [
        ...r.roles.map((x) => ({ kind: 'ROLE', name: x.name, sub: `${x.account} · ${KIND[x.kind] || x.kind}`, risk: x.risk, href: `#/identities/${x.id}` })),
        ...r.users.map((x) => ({ kind: 'IAM USER', name: x.name, sub: x.account, risk: x.risk, href: `#/identities/${x.id}` })),
        ...r.keys.map((x) => ({ kind: 'KEY', name: x.id, sub: `${x.status} · ${x.user} · ${x.account}`, risk: x.risk, href: `#/identities/${x.userId}?tab=credentials` })),
        ...r.gcp.map((x) => ({ kind: GCP_KIND[x.kind] || 'GOOGLE', name: x.name, sub: x.project || 'Google Cloud', risk: x.risk, href: `#/identities/gcp/${x.id}` })),
        ...r.accounts.map((x) => ({ kind: 'ACCOUNT', name: x.name, sub: `${x.awsAccountId} · ${envName(x.environment)} · its roles`, href: `#/identities?accounts=${x.id}` })),
      ] : []),
      ...pages.filter(([label, , , words]) => !needle || `${label} ${words}`.toLowerCase().includes(needle)).map(([label, href]) => ({ kind: 'GO TO', name: label, sub: '', href })),
      ...(q.length >= 2 && can('view') ? [{ kind: 'GO TO', name: `Events for “${q}”`, sub: 'search every call', href: `#/events?q=${encodeURIComponent(q)}` }] : []),
    ];
    active = Math.min(active, Math.max(0, items.length - 1));
    list.replaceChildren(...(items.length ? items.map(row) : [h('p', { class: 'pal-empty muted small' }, waiting ? 'Searching…' : `Nothing matches “${q}”.`)]),
      waiting && items.length ? h('p', { class: 'pal-empty muted tiny' }, 'Searching…') : null);
    mark();
  }
  const search = debounced(async () => {
    const q = input.value.trim(), mine = ++seq;
    if (q.length < 2) { found = null; waiting = false; draw(); return; }
    try { const r = await get(`/search?q=${encodeURIComponent(q)}`); if (mine !== seq || !open) return; found = r; }
    catch { if (mine !== seq) return; found = null; }
    waiting = false; active = 0; draw();
  }, 150);
  input.addEventListener('input', () => { active = 0; waiting = input.value.trim().length >= 2; draw(); search(); });

  const onKey = (e) => {
    if (e.key === 'Escape') { e.preventDefault(); e.stopPropagation(); closePalette(); }
    else if (e.key === 'ArrowDown' || (e.key === 'n' && e.ctrlKey)) { e.preventDefault(); if (items.length) { active = (active + 1) % items.length; mark(); } }
    else if (e.key === 'ArrowUp' || (e.key === 'p' && e.ctrlKey)) { e.preventDefault(); if (items.length) { active = (active - 1 + items.length) % items.length; mark(); } }
    else if (e.key === 'Enter') { e.preventDefault(); if (items[active]) pick(items[active]); }
    else if (e.key === 'Tab') e.preventDefault();          // focus stays in the box
    else return;
    e.stopPropagation();                                    // the page under it (Findings' j/k, a window's Esc) does not see these
  };
  const bg = h('div', { class: 'pal-bg', onMousedown: (e) => { if (e.target === bg) closePalette(); } },
    h('div', { class: 'pal', role: 'dialog', 'aria-modal': 'true', 'aria-label': 'Search' }, input, list, foot));
  open = { bg, onKey, search, opener: document.activeElement };
  document.addEventListener('keydown', onKey, true);
  document.body.append(bg);
  draw(); input.focus();
}
