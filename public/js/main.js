import { h, svg, clear, get, getCached, post, setCsrf, toast, ApiError, ROLE_LABEL, TEAM, freshness, TONE_COLOR, paint } from './lib.js';
import { theme, setTheme, initTheme } from './theme.js';
import * as authPages from './pages/auth.js';
import { overview } from './pages/overview.js';
import { rolePage } from './pages/role.js';
import { recommendationPage } from './pages/recommendation.js';
import { accountsPage, newAccountPage, editAccountPage } from './pages/accounts.js';
import { membersPage } from './pages/members.js';
import { auditPage } from './pages/audit.js';
import { opsPage } from './pages/ops.js';
import { radarPage } from './pages/radar.js';
import { spacePage } from './pages/space.js';
import { eventsPage } from './pages/events.js';
import { trustPage } from './pages/trust.js';
import { sectorPage } from './pages/sector.js';
import { trackPage } from './pages/track.js';
import { unidentifiedPage } from './pages/unidentified.js';
import { settingsPage } from './pages/settings.js';
import { workersPage } from './pages/workers.js';

const root = document.getElementById('app');
const state = { user: null, leave: [], status: null };
export const session = state;

// [pattern, page, rail item, full-bleed scene]
const routes = [
  [/^#?\/?$/, () => radarPage, 'radar', true],
  [/^#\/track$/, () => trackPage, 'radar', true],
  [/^#\/space$/, () => spacePage, 'space', true],
  [/^#\/events$/, () => eventsPage, 'events'],
  [/^#\/trust$/, () => trustPage, 'trust', false],
  [/^#\/roles$/, () => overview, 'roles'],
  [/^#\/roles\/([\w-]+)\/scan$/, (m) => (c) => sectorPage(c, m[1]), 'radar', true],
  [/^#\/roles\/([\w-]+)\/recommendation$/, (m) => (c) => recommendationPage(c, m[1]), 'roles'],
  [/^#\/roles\/([\w-]+)$/, (m) => (c) => rolePage(c, m[1]), 'roles'],
  [/^#\/accounts\/new$/, () => newAccountPage, 'accounts'],
  [/^#\/accounts\/([\w-]+)\/(coverage|unidentified)$/, (m) => (c) => unidentifiedPage(c, m[1]), 'accounts'],
  [/^#\/accounts\/([\w-]+)\/edit$/, (m) => (c) => editAccountPage(c, m[1]), 'accounts'],
  [/^#\/accounts$/, () => accountsPage, 'accounts'],
  [/^#\/scans$/, () => opsPage, 'scans'],
  [/^#\/workers$/, () => workersPage, 'workers'],
  [/^#\/members$/, () => membersPage, 'members'],
  [/^#\/audit$/, () => auditPage, 'audit'],
  [/^#\/settings$/, () => settingsPage, 'settings'],
];

// inside a window (below) navigation stays in the window; otherwise it changes the page
export function go(hash) { if (win) return void winGo(hash); location.hash = hash; }
const can = (p) => state.user?.permissions.includes(p);

const ICON = {
  radar: 'M12 12m-9 0a9 9 0 1 0 18 0a9 9 0 1 0 -18 0M12 12m-4 0a4 4 0 1 0 8 0a4 4 0 1 0 -8 0M12 12L19 6',
  trust: 'M12 3l7 3v6c0 4.5-3 7.5-7 9-4-1.5-7-4.5-7-9V6zM9 12l2 2 4-4',
  events: 'M4 6h16M4 12h16M4 18h11M18 16l2.5 2.5M16.5 17.5a2 2 0 1 0 0.01 0',
  space: 'M3 15l9 4.5 9-4.5-9-4.5zM12 6.5a2 2 0 1 0 0.01 0M6.5 9.5a1.2 1.2 0 1 0 0.01 0M17.5 8a1.2 1.2 0 1 0 0.01 0',
  roles: 'M4 6h16M4 12h16M4 18h10', scans: 'M3 12h4l3-8 4 16 3-8h4', accounts: 'M4 7h16v12H4zM8 7V4h8v3',
  members: 'M9 11a4 4 0 1 0 0-8 4 4 0 0 0 0 8zM2 21c0-4 3-6 7-6s7 2 7 6M17 11a3 3 0 1 0 0-6M22 20c0-3-2-5-4-5', audit: 'M6 3h9l4 4v14H6zM9 12h7M9 16h7M9 8h3',
  workers: 'M5 5h14v6H5zM5 13h14v6H5zM8 8h.01M8 16h.01M12 8h4M12 16h4',
  settings: 'M4 6h10M18 6h2M4 12h4M12 12h8M4 18h12M20 18h0M16 4v4M10 10v4M16 16v4',
};
const mark = (size = 40) => svg('svg', { width: size, height: size, viewBox: '0 0 40 40', 'aria-hidden': 'true' },
  svg('circle', { cx: 20, cy: 20, r: 18, fill: 'none', stroke: '#1f4a35' }), svg('circle', { cx: 20, cy: 20, r: 11, fill: 'none', stroke: '#1f4a35' }),
  svg('path', { d: 'M20 20 L38 20 A18 18 0 0 0 32.7 7.3 Z', fill: '#f6e016', 'fill-opacity': '0.25' }), svg('path', { d: 'M20 20 L38 20', stroke: '#f6e016', 'stroke-width': '1.5' }),
  svg('path', { d: 'M26 12 q4 2 3 7 q-3 -2 -6 -1 q0 -4 3 -6z', fill: '#f6e016' }));
export { mark };

// ---------- a window over the current page ----------
// Any page can be opened in a window on top of the one being looked at (Space does this for sessions, calls, a role,
// the trust map), so the place you were is still there when it closes. Nothing is fetched or built until it opens;
// closing it runs the page's own clean-up and drops it. Links and go() inside the window move the window, not the page.
const WIN_ICON = () => svg('svg', { class: 'win-ico', width: 12, height: 12, viewBox: '0 0 12 12', 'aria-hidden': 'true' },
  svg('path', { d: 'M1.5 3.5h7v7h-7zM4 3.5v-2h6.5V8h-2', fill: 'none', stroke: 'currentColor', 'stroke-width': 1.2 }));
export { WIN_ICON as windowIcon };
let win = null;
const routeOf = (hash) => { const [path, qs] = String(hash).split('?'); for (const [re, pick, , full] of routes) { const m = path.match(re); if (m) return { page: pick(m), full, params: new URLSearchParams(qs || '') }; } return null; };
async function winGo(hash, push = true) {
  const mine = win; if (!mine) return;
  mine.leave.forEach((f) => f()); mine.leave = [];
  if (push && mine.at && mine.at !== hash) mine.back.push(mine.at);
  mine.at = hash; mine.backBtn.hidden = !mine.back.length; mine.tab.href = hash;
  const r = routeOf(hash);
  mine.body.className = `win-body${r?.full ? ' full' : ''}`;
  mine.body.replaceChildren(h('div', { class: 'muted', style: 'padding:24px' }, h('span', { class: 'spin' }), ' Loading'));
  if (!r) { mine.body.replaceChildren(h('div', { class: 'empty' }, 'Nothing here.')); return; }
  try {
    const out = await r.page({ params: r.params, inWindow: true, onLeave: (f) => mine.leave.push(f), reload: () => winGo(hash, false), refreshStatus, openWindow, setNotices: () => {},
      setCrumbs: (...parts) => { const last = parts[parts.length - 1]; if (last && !(mine.named && !mine.back.length)) mine.title.textContent = typeof last === 'string' ? last : last.textContent; } });
    if (win !== mine || mine.at !== hash) return;       // closed, or moved on, while it loaded
    mine.body.replaceChildren(out); mine.body.scrollTop = 0;
  } catch (e) {
    if (win !== mine || mine.at !== hash) return;
    mine.body.replaceChildren(h('div', { class: 'alert bad', style: 'margin:20px' }, e instanceof ApiError ? e.message : 'Something went wrong while loading this.'));
    console.error(e);
  }
}
export function openWindow(hash, { title = '', eyebrow = '' } = {}) {
  closeWindow();
  const titleEl = h('b', { class: 'win-title' }, title), body = h('div', { class: 'win-body' });
  const backBtn = h('button', { class: 'btn sm', hidden: true, onClick: () => { const prev = win?.back.pop(); if (prev) winGo(prev, false); } }, '← Back');
  const tab = h('a', { class: 'btn sm', href: hash, target: '_blank', rel: 'noopener', title: 'Open this in a new browser tab' }, 'New tab ↗');
  const close = h('button', { class: 'btn sm primary', onClick: () => closeWindow() }, 'Close');
  const dlg = h('div', { class: 'win', role: 'dialog', 'aria-modal': 'true', 'aria-label': title || 'Window' },
    h('div', { class: 'win-head' }, backBtn, h('div', { class: 'stack', style: 'gap:2px;min-width:0;flex:1' }, eyebrow ? h('span', { class: 'eyebrow' }, eyebrow) : null, titleEl), tab, close), body);
  // links inside move the window; ones that open a new tab, or are held with a key, are left alone
  dlg.addEventListener('click', (ev) => {
    const a = ev.target.closest?.('a[href^="#/"]');
    if (!a || a.target || ev.metaKey || ev.ctrlKey || ev.shiftKey || ev.button) return;
    ev.preventDefault(); winGo(a.getAttribute('href'));
  });
  const onKey = (ev) => { if (ev.key === 'Escape') closeWindow(); };
  document.addEventListener('keydown', onKey);
  win = { dlg, body, title: titleEl, named: !!title, backBtn, tab, onKey, leave: [], back: [], at: null, url: location.href, opener: document.activeElement };
  document.body.append(dlg); close.focus();
  winGo(hash, false);
}
export function closeWindow() {
  if (!win) return;
  const w = win; win = null;
  w.leave.forEach((f) => f());
  document.removeEventListener('keydown', w.onKey); w.dlg.remove();
  if (location.href !== w.url) history.replaceState(null, '', w.url);    // a page in the window may have rewritten the address
  w.opener?.focus?.();
}

// ---------- the bell: what needs a look in the last 24 hours ----------
// Everywhere it lists the estate's flagged events and takes you to Space. A page can put its own list there while
// it is open (Space does, so picking one selects it in place).
const KIND_LABEL = { 'new-caller': 'NEW CALLER', denied: '⚠ DENIED', grew: 'GREW', unidentified: 'UNIDENTIFIED', 'new-role': 'NEW ROLE', dead: 'COLD', cleaned: 'CLEANED', 'new-path': 'NEW PATH' };
const NOTICE_TONE = { high: '#ff5a4f', warn: '#fab219', medium: '#fab219', info: '#ffffff', good: '#6fe3b0', low: '#d5dceb' };
let notices = null, bellOpen = false;      // a page's own list, or null for the estate's
const bellEl = h('div', { class: 'bell' });
export function setNotices(n) { notices = n; drawBell(); }
const hourText = (start, b) => new Date(start + b * 36e5).toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit', timeZone: 'Asia/Jakarta' });
async function drawBell() {
  let n = notices;
  if (!n && state.user) {
    try {
      const f = await getCached('/space/flags', 60_000), start = new Date(f.hourStart).getTime();
      n = { title: 'Needs a look · last 24 h', items: f.items.map((e) => ({ kind: KIND_LABEL[e.kind] || e.kind.toUpperCase(), tone: e.severity, text: e.title, where: `${e.accountName || 'an account'}${e.roleName ? ` · ${e.roleName}` : ''}`,
        time: hourText(start, e.hour), onPick: () => go(`#/space?sel=${e.accountId}&hour=${e.hour}`) })) };
    } catch { n = { title: 'Needs a look · last 24 h', items: [] }; }
    if (notices) n = notices;
  }
  if (!n) { bellEl.replaceChildren(); return; }
  const worst = n.items.some((e) => e.tone === 'high') ? 'high' : n.items.some((e) => e.tone === 'warn' || e.tone === 'medium') ? 'warn' : n.items.length ? 'info' : 'none';
  const btn = h('button', { class: `bell-btn bell-${worst}`, 'aria-expanded': String(bellOpen), 'aria-haspopup': 'true', title: n.title,
    onClick: (ev) => { ev.stopPropagation(); bellOpen = !bellOpen; drawBell(); } },
    svg('svg', { width: 16, height: 16, viewBox: '0 0 16 16', 'aria-hidden': 'true' }, svg('path', { d: 'M8 1.5a4 4 0 0 0-4 4v3L2.5 11h11L12 8.5v-3a4 4 0 0 0-4-4zM6.5 13a1.5 1.5 0 0 0 3 0', fill: 'none', stroke: 'currentColor', 'stroke-width': 1.4 })),
    n.items.length ? `${n.items.length} TO LOOK AT` : 'NOTHING FLAGGED');
  const pop = bellOpen ? h('div', { class: 'bell-pop', role: 'menu', 'aria-label': n.title },
    h('div', { class: 'bell-head' }, h('span', { class: 'eyebrow' }, n.title), h('span', { class: 'mono faint' }, String(n.items.length))),
    ...(n.items.length ? n.items.slice(0, 40).map((e) => h('button', { class: 'bell-item', role: 'menuitem', style: `border-left-color:${NOTICE_TONE[e.tone] || '#fff'}`, onClick: () => { bellOpen = false; drawBell(); e.onPick(); } },
      h('span', { class: 'bell-top' }, h('span', { style: `color:${NOTICE_TONE[e.tone] || '#fff'}` }, e.kind), h('span', { class: 'faint' }, e.time)),
      h('span', { class: 'bell-text' }, e.text), h('span', { class: 'faint tiny' }, e.where)))
      : [h('p', { class: 'muted small', style: 'margin:10px 12px' }, 'Nothing flagged in the last 24 hours.')])) : null;
  bellEl.replaceChildren(btn, ...(pop ? [pop] : []));
}
document.addEventListener('click', (ev) => { if (bellOpen && !bellEl.contains(ev.target)) { bellOpen = false; drawBell(); } });
document.addEventListener('keydown', (ev) => { if (bellOpen && ev.key === 'Escape') { bellOpen = false; drawBell(); } });

const statusBar = h('header', { class: 'status' });
const crumbsEl = h('span', { class: 'crumbs' });
export function setCrumbs(...parts) { crumbsEl.replaceChildren(...parts.flatMap((p, i) => [i ? ' · ' : '', p])); }

/** The status bar on every screen: how much history is read, and unidentified calls waiting. */
export async function refreshStatus() {
  if (!state.user) return;
  try { state.status = await get('/status'); } catch { return; }
  const s = state.status;
  const C = 2 * Math.PI * 10, frac = Math.max(0, Math.min(1, s.progress / 100));
  const upTo = s.readUpTo ? new Date(s.readUpTo).toLocaleDateString('en-GB', { day: '2-digit', month: 'short' }) : null;
  const eta = s.etaSeconds == null ? null : s.etaSeconds < 3600 ? `about ${Math.max(1, Math.round(s.etaSeconds / 60))} min left` : `about ${Math.round(s.etaSeconds / 1800) / 2} h left`;
  // two questions, two answers: is the history all there (the dial), and how current is it (the line under it)
  const fr = s.complete && s.accounts > 0 ? freshness(s.freshAt, s.tailEveryMinutes, s.deliveryLagMinutes) : null;
  const meter = h('a', { href: '#/scans', class: `meter${s.complete ? '' : ' reading'}`,
    title: fr ? `History: every account's lookback is read. Freshness: the least current account${s.stalest ? ` (${s.stalest.name})` : ''} is ${fr.text}.${s.tailEveryMinutes > 0 ? ` New events are read every ${s.tailEveryMinutes} min; CloudTrail itself delivers them ${s.deliveryLagMinutes} min or so late.` : ' Catch-up reads are off, so new events wait for the daily scan.'}` : null },
    svg('svg', { width: 26, height: 26, viewBox: '0 0 26 26', 'aria-hidden': 'true' },
      svg('circle', { cx: 13, cy: 13, r: 10, fill: 'none', stroke: '#1f4a35', 'stroke-width': 3 }),
      svg('circle', { cx: 13, cy: 13, r: 10, fill: 'none', stroke: s.complete ? '#6fe3b0' : '#f6e016', 'stroke-width': 3, 'stroke-dasharray': `${(C * frac).toFixed(1)} ${C.toFixed(1)}`, transform: 'rotate(-90 13 13)' })),
    h('span', null, h('b', { style: null }, s.accounts === 0 ? 'NO ACCOUNTS YET' : s.complete ? 'HISTORY COMPLETE' : `HISTORY ${s.progress}% READ`),
      h('span', { class: fr ? `fresh-${fr.tone}` : null }, s.accounts === 0 ? 'Connect one to start' : fr ? fr.text : [upTo && `up to ${upTo}`, eta, 'results are provisional'].filter(Boolean).join(' · '))));
  meter.querySelector('b').style.color = paint(s.complete ? '#6fe3b0' : '#f6e016');
  if (fr && fr.tone !== 'good') meter.lastChild.lastChild.style.color = paint(TONE_COLOR[fr.tone]);
  const firstAcct = s.reading?.[0]?.id;
  if (!bellEl.firstChild) drawBell();
  statusBar.replaceChildren(crumbsEl, h('span', { class: 'spacer' }), can('view') ? bellEl : null,
    s.unidentified > 0 && h('a', { class: 'unk-badge', href: firstAcct ? `#/accounts/${firstAcct}/unidentified` : '#/accounts', title: 'Calls under event names not yet identified' },
      svg('svg', { width: 16, height: 16, viewBox: '0 0 16 16', 'aria-hidden': 'true' }, svg('circle', { cx: 8, cy: 8, r: 6.5, fill: 'none', stroke: '#f0b45a', 'stroke-width': 1.5, 'stroke-dasharray': '3 2' }), svg('circle', { cx: 8, cy: 8, r: 1.8, fill: '#f0b45a' })),
      `${s.unidentified} UNIDENTIFIED`),
    meter, themeBtn());
}
setInterval(() => refreshStatus(), 20000);

// ---------- light / dark ----------
const SUN = 'M12 4V2M12 22v-2M4 12H2M22 12h-2M6.3 6.3 4.9 4.9M19.1 19.1l-1.4-1.4M6.3 17.7l-1.4 1.4M19.1 4.9l-1.4 1.4M12 8a4 4 0 1 0 0 8 4 4 0 0 0 0-8z';
const MOON = 'M20 14.5A8 8 0 0 1 9.5 4a8 8 0 1 0 10.5 10.5z';
function themeBtn() {
  const light = theme() === 'light';
  return h('button', { class: 'theme-btn', title: light ? 'Switch to the dark theme' : 'Switch to the light theme', 'aria-label': light ? 'Dark theme' : 'Light theme',
    onClick: () => { setTheme(light ? 'dark' : 'light'); refreshStatus(); render(); } },
    svg('svg', { width: 18, height: 18, viewBox: '0 0 24 24', fill: 'none', stroke: 'currentColor', 'stroke-width': '1.6', 'stroke-linecap': 'round', 'aria-hidden': 'true' }, svg('path', { d: light ? MOON : SUN })));
}
initTheme();

function shell(active, content, full) {
  const item = (key, href, label, perm) => (!perm || can(perm)) && h('a', { class: 'item', href, 'aria-current': active === key ? 'page' : null },
    svg('svg', { width: 20, height: 20, viewBox: '0 0 24 24', fill: 'none', stroke: 'currentColor', 'stroke-width': '1.6', 'aria-hidden': 'true' }, svg('path', { d: ICON[key] })), label);
  setCrumbs({ radar: 'Radar', space: 'Space', events: 'Events', trust: 'Trust map', roles: 'Roles', scans: 'Scans', accounts: 'Accounts', members: 'Members', audit: 'Audit', settings: 'Configuration', workers: 'Health' }[active] || '');
  if (!statusBar.firstChild) statusBar.append(crumbsEl);
  refreshStatus();
  return h('div', { class: 'shell' },
    h('nav', { class: 'rail', 'aria-label': 'Main' },
      h('a', { class: 'home', href: '#/', 'aria-label': 'Curious Monkey radar' }, mark()),
      item('radar', '#/', 'Radar', 'view'), item('space', '#/space', 'Space', 'view'), item('trust', '#/trust', 'Trust', 'view'), item('events', '#/events', 'Events', 'view'), item('roles', '#/roles', 'Roles', 'view'), item('scans', '#/scans', 'Scans', 'ops'), item('workers', '#/workers', 'Health', 'ops'),
      item('accounts', '#/accounts', 'Accounts', 'view'), item('members', '#/members', 'Members', 'members'), item('audit', '#/audit', 'Audit', 'audit'), item('settings', '#/settings', 'Config', 'settings'),
      h('div', { class: 'me' },
        h('span', { class: 'avatar', title: `${state.user.name} · ${ROLE_LABEL[state.user.role]}${state.user.team ? `, ${TEAM[state.user.team]}` : ''}` }, (state.user.name || '?').split(/[.\s_-]+/).map((x) => x[0]).join('').slice(0, 2).toUpperCase()),
        h('button', { onClick: async () => { await post('/auth/signout'); state.user = null; setCsrf(''); go('#/signin'); } }, 'Sign out'))),
    h('div', { class: 'frame' }, statusBar, h('main', { class: full ? 'main full' : 'main', id: 'content' }, content)));
}

async function render() {
  closeWindow();
  state.leave.forEach((f) => f()); state.leave = [];
  if (notices) { notices = null; }
  bellOpen = false; drawBell();
  document.querySelectorAll('.modal-bg').forEach((m) => m.remove());   // a dialog belongs to the page it was opened on
  const hash = location.hash;
  const [path, qs] = hash.split('?'); const params = new URLSearchParams(qs || '');
  try {
    if (path === '#/reset') return mount(authPages.resetPassword(params));
    if (!state.user) {
      try { const me = await get('/auth/me'); state.user = me.user; setCsrf(me.csrf); } catch (e) { if (!(e instanceof ApiError) || e.status !== 401) throw e; }
    }
    const st = state.user ? null : await get('/auth/state');
    if (!state.user) {
      if (path === '#/signup') return mount(authPages.signUp(params, st));
      if (st.needsSetup) return mount(authPages.signUp(params, st));
      return mount(authPages.signIn(st));
    }
    if (state.user.needsMfaSetup) return mount(authPages.mfaSetup());
    if (['#/signin', '#/signup'].includes(path)) return go('#/');
    for (const [re, pick, key, full] of routes) {
      const m = path.match(re);
      if (!m) continue;
      const page = pick(m);
      const content = h('div', { class: 'stack-lg' }, h('div', { class: 'muted', style: null }, h('span', { class: 'spin' }), ' Loading'));
      mount(shell(key, content, full));
      const out = await page({ params, onLeave: (f) => state.leave.push(f), reload: render, setCrumbs, refreshStatus, openWindow, setNotices });
      clear(content); content.append(out);
      return;
    }
    mount(shell('', h('div', { class: 'empty' }, 'Nothing here.')));
  } catch (e) {
    if (e instanceof ApiError && e.status === 401) { state.user = null; return go('#/signin'); }
    if (e instanceof ApiError && e.code === 'mfa_setup_required') { state.user.needsMfaSetup = true; return render(); }
    const c = document.getElementById('content');
    const box = h('div', { class: 'alert bad' }, e instanceof ApiError ? e.message : 'Something went wrong while loading this page.');
    c ? (clear(c), c.append(box)) : mount(box);
    console.error(e);
  }
}
function mount(node) { clear(root); root.append(node); window.scrollTo(0, 0); }
window.addEventListener('hashchange', render);
render();
