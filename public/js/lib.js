// replaceChildren would print `false`/`null` from `cond && node`. Drop them everywhere.
const nativeReplace = Element.prototype.replaceChildren;
Element.prototype.replaceChildren = function (...kids) { return nativeReplace.apply(this, kids.flat(Infinity).filter((k) => k != null && k !== false)); };
const nativeAppend = Element.prototype.append;
Element.prototype.append = function (...kids) { return nativeAppend.apply(this, kids.flat(Infinity).filter((k) => k != null && k !== false)); };
import { paint, COLOUR_ATTRS } from './theme.js';
export { paint } from './theme.js';
// Tiny DOM helpers. Everything goes in as text nodes, so data from the API can never become markup.
export function h(tag, props, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(props || {})) {
    if (v == null || v === false) continue;
    if (k === 'class') el.className = v;
    else if (k === 'style') el.style.cssText = paint(v); // CSSOM, allowed under the strict CSP (a style attribute is not)
    else if (k.startsWith('on') && typeof v === 'function') el.addEventListener(k.slice(2).toLowerCase(), v);
    else if (k === 'value') el.value = v;
    else if (k === 'checked' || k === 'disabled' || k === 'selected') el[k] = Boolean(v);
    else el.setAttribute(k, v === true ? (k.startsWith('aria-') ? 'true' : '') : v);
  }
  add(el, kids);
  return el;
}
export function add(el, kids) {
  for (const k of kids.flat(Infinity)) {
    if (k == null || k === false) continue;
    el.append(k instanceof Node ? k : document.createTextNode(String(k)));
  }
  return el;
}
export const svg = (tag, props, ...kids) => {
  const el = document.createElementNS('http://www.w3.org/2000/svg', tag);
  for (const [k, v] of Object.entries(props || {})) {
    if (v == null || v === false) continue;
    if (k === 'style') el.style.cssText = paint(v);
    else if (k.startsWith('on') && typeof v === 'function') el.addEventListener(k.slice(2).toLowerCase(), v);
    else el.setAttribute(k, COLOUR_ATTRS.has(k) ? paint(String(v)) : v);
  }
  return add(el, kids);
};
export const clear = (el) => { while (el.firstChild) el.removeChild(el.firstChild); return el; };

let csrf = '';
export const setCsrf = (t) => { csrf = t; };
export class ApiError extends Error { constructor(status, body) { super(body?.message || body?.error || `Request failed (${status})`); this.status = status; this.code = body?.error; this.field = body?.field; } }
export async function api(method, path, body) {
  const r = await fetch(`/api${path}`, { method, credentials: 'same-origin',
    headers: { 'content-type': 'application/json', ...(csrf ? { 'x-csrf-token': csrf } : {}) }, body: body === undefined ? undefined : JSON.stringify(body) });
  const type = r.headers.get('content-type') || '';
  const data = type.includes('json') ? await r.json() : await r.text();
  if (!r.ok) throw new ApiError(r.status, data);
  return data;
}
export const get = (p) => api('GET', p);
// A GET remembered for a moment, so going back and forth between two views does not wait on the network again.
const remembered = new Map();
export function getCached(path, maxAgeMs = 45_000) {
  const e = remembered.get(path);
  if (e && Date.now() - e.at < maxAgeMs) return e.p;
  const p = get(path);
  remembered.set(path, { at: Date.now(), p });
  p.catch(() => remembered.delete(path));
  if (remembered.size > 40) remembered.delete(remembered.keys().next().value);
  return p;
}
export const post = (p, b) => api('POST', p, b ?? {});

export function toast(msg, bad = false) {
  const t = h('div', { class: `toast${bad ? ' bad' : ''}`, role: 'status' }, msg);
  document.body.append(t); setTimeout(() => t.remove(), bad ? 6000 : 3000);
}
export function modal(title, body, footer) {
  const bg = h('div', { class: 'modal-bg', onClick: (e) => { if (e.target === bg) bg.remove(); } });
  bg.append(h('div', { class: 'modal', role: 'dialog', 'aria-modal': 'true', 'aria-label': title },
    h('div', { class: 'row', style: null }, h('h2', null, title), h('span', { class: 'grow' })), body, footer || h('div', { class: 'actions' }, h('button', { class: 'btn', onClick: () => bg.remove() }, 'Close'))));
  document.body.append(bg); return bg;
}
export const copy = async (text) => { try { await navigator.clipboard.writeText(text); toast('Copied'); } catch { toast('Copy failed. Select the text and copy it yourself.', true); } };

// Every time on screen is shown in one zone. This is the only place that names it.
export const TZ = 'Asia/Jakarta', TZ_LABEL = 'WIB';
export const fmtDate = (d) => d ? new Date(d).toLocaleString('en-GB', { day: '2-digit', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit', timeZone: TZ }) + ` ${TZ_LABEL}` : 'never';
export const fmtDay = (d) => d ? new Date(d).toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric', timeZone: TZ }) : 'never';
/** 14:05, or 14:05:09 with seconds */
export const fmtClock = (d, seconds = false) => new Date(d).toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit', ...(seconds ? { second: '2-digit' } : {}), timeZone: TZ });
/** 12 Nov, 14:05, or 12 Nov, 14:05:09 with seconds */
export const fmtStamp = (d, seconds = false) => new Date(d).toLocaleString('en-GB', { day: '2-digit', month: 'short', hour: '2-digit', minute: '2-digit', ...(seconds ? { second: '2-digit' } : {}), timeZone: TZ });
export const ago = (d) => {
  if (!d) return 'never';
  const s = Math.max(0, (Date.now() - new Date(d)) / 1000);
  if (s < 90) return 'just now'; if (s < 5400) return `${Math.round(s / 60)} min ago`; if (s < 129600) return `${Math.round(s / 3600)} h ago`; return `${Math.round(s / 86400)} days ago`;
};
/**
 * How current the CloudTrail data is. `at` is when the newest read reached the present (minus the delivery lag).
 * Fine while within two catch-up intervals (or a day when catch-up is off), amber after that, red after a day and a half.
 */
export function freshness(at, everyMinutes = 0, lagMinutes = 15) {
  if (!at) return { tone: 'bad', behind: null, text: 'not read up to the present yet' };
  const min = Math.max(0, Math.round((Date.now() - new Date(at)) / 60000));
  const okFor = everyMinutes > 0 ? everyMinutes * 2 + lagMinutes + 10 : 26 * 60;
  const tone = min > 36 * 60 ? 'bad' : min > okFor ? 'warn' : 'good';
  const behind = min < 60 ? `${min} min` : min < 6 * 60 ? `${Math.floor(min / 60)} h${min % 60 ? ` ${min % 60} min` : ''}` : min < 48 * 60 ? `${Math.round(min / 60)} h` : `${Math.round(min / 1440)} days`;
  const time = new Date(at).toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit' }) + (min >= 20 * 60 ? ` ${new Date(at).toLocaleDateString('en-GB', { day: '2-digit', month: 'short' })}` : '');
  return { tone, min, behind, time, text: `read up to ${time} · ${behind} behind` };
}
/** One colour per severity, for every page (Radar, Space, the bell, Trust, Track). */
export const COLOR = { high: '#ff5a4f', warn: '#f0b45a', info: '#8ec5ff', good: '#6fe3b0' };
export const TONE_COLOR = { good: COLOR.good, warn: COLOR.warn, bad: COLOR.high };
/** What a change on the Radar feed and in the bell is called. */
export const CHANGE_KIND = { 'new-caller': 'NEW CALLER', denied: '⚠ DENIED', grew: 'GREW', unidentified: 'UNIDENTIFIED', 'new-role': 'NEW ROLE', dead: 'COLD', cleaned: 'CLEANED', 'new-path': 'NEW PATH' };
export const num = (n) => Number(n || 0).toLocaleString('en-US');
export const TEAM = { infrasec: 'Infrastructure Security', infosec: 'Information Security' };
export const ROLE_LABEL = { owner: 'Owner', admin: 'Admin', reviewer: 'Security reviewer', account_owner: 'Account owner', auditor: 'Auditor' };
/** Which identities a view shows: all, roles only or IAM users only. Kept in the URL as ?who=. */
export const WHO = [['all', 'All'], ['roles', 'Roles'], ['users', 'IAM users']];
export const whoOf = (params) => (['roles', 'users'].includes(params.get('who')) ? params.get('who') : 'all');
export const whoQs = (who, sep = '?') => (who === 'all' ? '' : `${sep}who=${who}`);
export function whoControl(who, onPick, label = 'Show') {
  return h('div', { class: 'stack', style: 'gap:6px' }, h('h2', { class: 'eyebrow' }, label),
    h('div', { class: 'rtabs', role: 'radiogroup', 'aria-label': 'Which identities' }, WHO.map(([k, l]) => h('button', { role: 'radio', 'aria-checked': String(who === k), title: k === 'users' ? 'Only IAM users: long-lived access keys and console passwords' : k === 'roles' ? 'Only IAM roles' : 'Roles and IAM users', onClick: () => onPick(k) }, l))));
}
/** A row of tabs that are links, so each tab has its own address (same look as the AWS | Google Cloud tabs). tabs: [key, label, href]. */
export const pageTabs = (label, tabs, current) => h('div', { class: 'tabs cloud-tabs', role: 'tablist', 'aria-label': label },
  tabs.map(([k, text, href]) => h('a', { role: 'tab', href, 'aria-selected': String(current === k) }, text)));
export const KIND = { custom: 'Custom', 'service-linked': 'Service-linked', 'identity-center': 'Identity Center', 'iam-user': 'IAM user' };
export const riskBadge = (r) => h('span', { class: `badge b-${String(r).toLowerCase()}` }, r);
export const teamBadge = (t, both) => h('span', { class: 'badge b-neutral' }, both ? 'Both teams' : TEAM[t] || t);
export function usageBar(used, unused, unconf) {
  const total = Math.max(used + unused + unconf, 1);
  const bar = h('div', { class: 'bar', role: 'img', 'aria-label': `${used} used, ${unused} unused, ${unconf} unconfirmed` });
  for (const [c, n] of [['u', used], ['n', unused], ['c', unconf]]) { const i = h('i', { class: c }); i.style.width = `${(n / total) * 100}%`; bar.append(i); }
  return bar;
}
export const field = (label, input, hint) => h('div', { class: 'field' }, h('label', null, label, input), hint && h('span', { class: 'hint' }, hint));
export function busy(btn, fn) {
  return async (...a) => {
    const t = btn.textContent; btn.disabled = true;
    try { return await fn(...a); } catch (e) { toast(e.message, true); } finally { btn.disabled = false; btn.textContent = t; }
  };
}

// In-app replacement for window.confirm. Resolves true or false.
export function confirmDialog({ title, message, confirmLabel = 'Confirm', danger = false }) {
  return new Promise((resolve) => {
    let bg;
    const done = (v) => { document.removeEventListener('keydown', onKey); bg.remove(); resolve(v); };
    const onKey = (e) => { if (e.key === 'Escape') done(false); };
    const ok = h('button', { class: `btn ${danger ? 'danger-solid' : 'primary'}`, onClick: () => done(true) }, confirmLabel);
    bg = modal(title, h('p', null, message), h('div', { class: 'actions' }, ok, h('button', { class: 'btn', onClick: () => done(false) }, 'Cancel')));
    bg.firstChild.classList.add('confirm');
    document.addEventListener('keydown', onKey);
    ok.focus();
  });
}

// ---------- environments: names, colours and order, set on the Configuration page ----------
let envCache = null, envList = [];
/** The workspace's environments in order, cached for the page's life; `fresh` after they were edited. */
export function loadEnvironments(fresh = false) {
  if (!envCache || fresh) envCache = get('/environments').then((r) => { envList = r.environments; return envList; }).catch((e) => { envCache = null; throw e; });
  return envCache;
}
/** An environment's name, once loadEnvironments has run; its id otherwise */
export const envName = (id) => envList.find((e) => e.id === id)?.name || id || '';
/** Environments as already loaded, in order */
export const envs = () => envList;
const mix = (hex, to, t) => `#${[1, 3, 5].map((i) => Math.round(parseInt(hex.slice(i, i + 2), 16) * (1 - t) + to * t).toString(16).padStart(2, '0')).join('')}`;
/** base, a darker dim and a light hot shade of one environment colour, as the maps draw them */
export const envPalette = (hex) => ({ base: hex, dim: mix(hex, 0, 0.3), hot: mix(hex, 255, 0.55) });

// ---------- pieces every list page shares ----------
export const r1 = (v) => Math.round(v * 10) / 10;
/** A summary tile. With `onClick` it is a button (a filter shortcut); `pressed` marks the active one, `bad` the one to look at. */
export function tile(label, value, sub, { onClick, pressed, bad } = {}) {
  const kids = [h('span', { class: 'small muted' }, label), h('b', null, value), sub && h('span', { class: 'tiny muted' }, sub)];
  return onClick ? h('button', { class: `tile${bad ? ' tile-bad' : ''}`, type: 'button', 'aria-pressed': pressed == null ? null : String(pressed), onClick }, ...kids) : h('div', { class: 'tile' }, ...kids);
}
/** "Page 2 of 7", Previous, Next. `onPage` gets the new page number. */
export function pager({ page, total, size, onPage, label, prev = 'Previous', next = 'Next' }) {
  return h('div', { class: 'pager' }, h('span', { class: 'small muted' }, label ?? `Page ${page} of ${Math.ceil(total / size)}`),
    h('button', { class: 'btn sm', disabled: page <= 1, onClick: () => onPage(page - 1) }, prev),
    h('button', { class: 'btn sm', disabled: page * size >= total, onClick: () => onPage(page + 1) }, next));
}
/** Runs `fn` once things stop changing for `ms`. `.cancel()` drops a pending run (call it when the page is left). */
export function debounced(fn, ms = 250) {
  let t;
  const run = (...a) => { clearTimeout(t); t = setTimeout(() => fn(...a), ms); };
  run.cancel = () => clearTimeout(t);
  return run;
}
/** A search box that calls `onSearch(text)` 250 ms after typing stops. */
export function searchBox({ value = '', placeholder, label, onSearch, ms = 250 }) {
  const input = h('input', { type: 'search', placeholder, 'aria-label': label || placeholder, value });
  const run = debounced(() => onSearch(input.value), ms);
  input.addEventListener('input', run);
  return Object.assign(input, { cancel: run.cancel });
}
/** Calls `fn` every `ms`, but not while the tab is in the background; comes back with one call when the tab is shown again. Returns a stop function. */
export function poll(fn, ms) {
  const t = setInterval(() => { if (!document.hidden) fn(); }, ms);
  const shown = () => { if (!document.hidden) fn(); };
  document.addEventListener('visibilitychange', shown);
  return () => { clearInterval(t); document.removeEventListener('visibilitychange', shown); };
}

// ---------- filters live in the address ----------
/** A comma list in the address, as a Set */
export const urlSet = (params, key) => new Set((params.get(key) || '').split(',').filter(Boolean));
/** Writes the page's filters into the address (only the ones that are set), without adding a history entry or redrawing.
 *  Reload, a copied link and Back to this page then give the same view. */
export function syncUrl(filters) {
  const p = new URLSearchParams();
  for (const [k, v] of Object.entries(filters)) {
    const val = v instanceof Set ? [...v].join(',') : v === true ? '1' : v;
    if (val == null || val === false || val === '') continue;
    p.set(k, String(val));
  }
  const [path] = location.hash.split('?'), qs = p.toString();
  history.replaceState(null, '', `${path}${qs ? `?${qs}` : ''}`);
}

/**
 * The account picker used on every page that filters by account: a searchable list with environment shortcuts.
 * `selected` is a Set of account ids that the picker changes in place; `onChange` runs after each change.
 * With `multi: false` one account at most is picked (Events). `setAccounts` swaps the list when it arrives late.
 */
export function accountPicker({ accounts, selected, onChange, multi = true }) {
  let list = accounts;
  const label = h('span');
  const chips = h('div', { class: 'pill-bar acct-chips' });
  const search = h('input', { type: 'search', placeholder: `Find among ${list.length} accounts`, 'aria-label': 'Find an account' });
  const options = h('div', { class: 'acct-list', role: 'group', 'aria-label': 'Accounts' });
  const changed = () => { redraw(); onChange(); };
  function redraw() {
    label.textContent = selected.size === 0 ? `All ${list.length} accounts` : selected.size === 1 ? list.find((a) => selected.has(a.id))?.name || '1 account' : `${selected.size} of ${list.length} accounts`;
    const picked = list.filter((a) => selected.has(a.id));
    chips.replaceChildren(...picked.slice(0, 4).map((a) => h('span', { class: 'chip ev-on' }, a.name,
      h('button', { type: 'button', class: 'chip-x', 'aria-label': `Remove ${a.name}`, onClick: () => { selected.delete(a.id); changed(); } }, '×'))),
      picked.length > 4 ? h('span', { class: 'small muted' }, `+${picked.length - 4} more`) : null,
      picked.length ? h('button', { type: 'button', class: 'btn sm', onClick: () => { selected.clear(); changed(); } }, 'Clear') : null);
    const needle = search.value.trim().toLowerCase();
    const shown = list.filter((a) => !needle || `${a.name} ${a.account_id} ${a.environment} ${envName(a.environment)} ${a.ou || ''}`.toLowerCase().includes(needle))
      .sort((a, b) => (selected.has(b.id) - selected.has(a.id)) || a.name.localeCompare(b.name));
    options.replaceChildren(...(shown.length ? shown.map((a) => {
      const cb = h('input', { type: 'checkbox', checked: selected.has(a.id) });
      cb.addEventListener('change', () => {
        if (!multi) { selected.clear(); picker.open = false; }
        cb.checked ? selected.add(a.id) : selected.delete(a.id); changed();
      });
      return h('label', { class: 'acct-opt' }, cb, h('span', { class: 'acct-opt-b' }, h('span', { class: 'name' }, a.name), h('span', { class: 'tiny muted' }, `${a.account_id} · ${envName(a.environment)}${a.ou ? ` · ${a.ou}` : ''}`)),
        h('span', { class: 'mono tiny muted' }, `${num(a.roles)} roles`));
    }) : [h('p', { class: 'small muted', style: 'margin:8px' }, 'No account matches.')]));
  }
  search.addEventListener('input', redraw);
  const shortcuts = h('div', { class: 'pill-bar' });
  const drawShortcuts = () => {
    const ids = envList.map((e) => e.id).filter((e) => list.some((a) => a.environment === e));
    shortcuts.replaceChildren(h('button', { type: 'button', class: 'chip', onClick: () => { selected.clear(); changed(); } }, 'All'),
      ...(multi ? ids.map((e) => h('button', { type: 'button', class: 'chip', onClick: () => { selected.clear(); for (const a of list) if (a.environment === e) selected.add(a.id); changed(); } }, `${envName(e)} only`)) : []));
  };
  const picker = h('details', { class: 'acct-picker' },
    h('summary', { class: 'btn', 'aria-label': 'Choose accounts' }, h('span', { class: 'muted' }, multi ? 'Accounts: ' : 'Account: '), label, ' ▾'),
    h('div', { class: 'acct-pop' }, search, shortcuts, options));
  // close when clicking elsewhere or pressing Escape
  const outside = (e) => { if (picker.open && !picker.contains(e.target)) picker.open = false; };
  const esc = (e) => { if (e.key === 'Escape' && picker.open) { picker.open = false; picker.querySelector('summary').focus(); } };
  document.addEventListener('click', outside); document.addEventListener('keydown', esc);
  picker.addEventListener('toggle', () => { if (picker.open) search.focus(); });
  drawShortcuts(); redraw();
  return {
    el: picker, chips, redraw,
    setAccounts(next) { list = next; search.placeholder = `Find among ${list.length} accounts`; drawShortcuts(); redraw(); },
    destroy() { document.removeEventListener('click', outside); document.removeEventListener('keydown', esc); },
  };
}

/**
 * A "More" menu: a button that opens a short list of actions. items: [label, href | onClick, { danger, disabled }].
 * Arrow keys move, Escape or a click outside closes, focus returns to the button.
 */
export function menu(label, items, { title } = {}) {
  const list = h('div', { class: 'menu-list', role: 'menu', hidden: true });
  const btn = h('button', { class: 'btn sm menu-btn', type: 'button', 'aria-haspopup': 'menu', 'aria-expanded': 'false', title: title || label }, label);
  const wrap = h('div', { class: 'menu' }, btn, list);
  const close = (focus = false) => { list.hidden = true; btn.setAttribute('aria-expanded', 'false'); document.removeEventListener('click', outside, true); window.removeEventListener('scroll', onMove, true); window.removeEventListener('resize', onMove); if (focus) btn.focus(); };
  const onMove = () => close();
  // placed against the window, so a scrolling table or card around the button cannot clip it; opens upward near the bottom
  const place = () => {
    const r = btn.getBoundingClientRect(), w = list.offsetWidth, ht = list.offsetHeight;
    list.style.left = `${Math.max(8, Math.min(r.right - w, window.innerWidth - w - 8))}px`;
    list.style.top = `${r.bottom + 4 + ht > window.innerHeight - 8 ? Math.max(8, r.top - 4 - ht) : r.bottom + 4}px`;
  };
  const outside = (e) => { if (!wrap.contains(e.target)) close(); };
  const entries = items.filter(Boolean).map(([l, act, o = {}]) => {
    const el = typeof act === 'string' ? h('a', { href: act, role: 'menuitem', class: o.danger ? 'danger' : '' }, l)
      : h('button', { type: 'button', role: 'menuitem', class: o.danger ? 'danger' : '', disabled: !!o.disabled }, l);
    el.addEventListener('click', (e) => { e.stopPropagation(); close(); if (typeof act === 'function') act(e); });
    return el;
  });
  list.append(...entries);
  btn.addEventListener('click', (e) => {
    e.stopPropagation();
    if (!list.hidden) return close();
    list.hidden = false; btn.setAttribute('aria-expanded', 'true'); place();
    document.addEventListener('click', outside, true); window.addEventListener('scroll', onMove, true); window.addEventListener('resize', onMove);
    entries.find((x) => !x.disabled)?.focus();
  });
  list.addEventListener('keydown', (e) => {
    const live = entries.filter((x) => !x.disabled), i = live.indexOf(document.activeElement);
    if (e.key === 'Escape') { e.preventDefault(); e.stopPropagation(); close(true); }
    else if (e.key === 'ArrowDown') { e.preventDefault(); live[(i + 1) % live.length]?.focus(); }
    else if (e.key === 'ArrowUp') { e.preventDefault(); live[(i - 1 + live.length) % live.length]?.focus(); }
    else if (e.key === 'Tab') close();
  });
  wrap.addEventListener('click', (e) => e.stopPropagation());
  return wrap;
}
