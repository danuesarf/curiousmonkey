import { h, svg, clear, get, post, setCsrf, toast, ApiError, ROLE_LABEL, TEAM } from './lib.js';
import * as authPages from './pages/auth.js';
import { overview } from './pages/overview.js';
import { rolePage } from './pages/role.js';
import { recommendationPage } from './pages/recommendation.js';
import { accountsPage, newAccountPage, editAccountPage } from './pages/accounts.js';
import { membersPage } from './pages/members.js';
import { auditPage } from './pages/audit.js';
import { opsPage } from './pages/ops.js';
import { radarPage } from './pages/radar.js';
import { trustPage } from './pages/trust.js';
import { sectorPage } from './pages/sector.js';
import { trackPage } from './pages/track.js';
import { unidentifiedPage } from './pages/unidentified.js';

const root = document.getElementById('app');
const state = { user: null, leave: [], status: null };
export const session = state;

// [pattern, page, rail item, full-bleed scene]
const routes = [
  [/^#?\/?$/, () => radarPage, 'radar', true],
  [/^#\/track$/, () => trackPage, 'radar', true],
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
  [/^#\/members$/, () => membersPage, 'members'],
  [/^#\/audit$/, () => auditPage, 'audit'],
];

export function go(hash) { location.hash = hash; }
const can = (p) => state.user?.permissions.includes(p);

const ICON = {
  radar: 'M12 12m-9 0a9 9 0 1 0 18 0a9 9 0 1 0 -18 0M12 12m-4 0a4 4 0 1 0 8 0a4 4 0 1 0 -8 0M12 12L19 6',
  trust: 'M12 3l7 3v6c0 4.5-3 7.5-7 9-4-1.5-7-4.5-7-9V6zM9 12l2 2 4-4',
  roles: 'M4 6h16M4 12h16M4 18h10', scans: 'M3 12h4l3-8 4 16 3-8h4', accounts: 'M4 7h16v12H4zM8 7V4h8v3',
  members: 'M9 11a4 4 0 1 0 0-8 4 4 0 0 0 0 8zM2 21c0-4 3-6 7-6s7 2 7 6M17 11a3 3 0 1 0 0-6M22 20c0-3-2-5-4-5', audit: 'M6 3h9l4 4v14H6zM9 12h7M9 16h7M9 8h3',
};
const mark = (size = 40) => svg('svg', { width: size, height: size, viewBox: '0 0 40 40', 'aria-hidden': 'true' },
  svg('circle', { cx: 20, cy: 20, r: 18, fill: 'none', stroke: '#1f4a35' }), svg('circle', { cx: 20, cy: 20, r: 11, fill: 'none', stroke: '#1f4a35' }),
  svg('path', { d: 'M20 20 L38 20 A18 18 0 0 0 32.7 7.3 Z', fill: '#f6e016', 'fill-opacity': '0.25' }), svg('path', { d: 'M20 20 L38 20', stroke: '#f6e016', 'stroke-width': '1.5' }),
  svg('path', { d: 'M26 12 q4 2 3 7 q-3 -2 -6 -1 q0 -4 3 -6z', fill: '#f6e016' }));
export { mark };

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
  const meter = h('a', { href: '#/scans', class: `meter${s.complete ? '' : ' reading'}` },
    svg('svg', { width: 26, height: 26, viewBox: '0 0 26 26', 'aria-hidden': 'true' },
      svg('circle', { cx: 13, cy: 13, r: 10, fill: 'none', stroke: '#1f4a35', 'stroke-width': 3 }),
      svg('circle', { cx: 13, cy: 13, r: 10, fill: 'none', stroke: s.complete ? '#6fe3b0' : '#f6e016', 'stroke-width': 3, 'stroke-dasharray': `${(C * frac).toFixed(1)} ${C.toFixed(1)}`, transform: 'rotate(-90 13 13)' })),
    h('span', null, h('b', { style: null }, s.accounts === 0 ? 'NO ACCOUNTS YET' : s.complete ? 'HISTORY COMPLETE' : `HISTORY ${s.progress}% READ`),
      h('span', null, s.accounts === 0 ? 'Connect one to start' : s.complete ? 'Results are final' : [upTo && `up to ${upTo}`, eta, 'results are provisional'].filter(Boolean).join(' · '))));
  meter.querySelector('b').style.color = s.complete ? '#6fe3b0' : '#f6e016';
  const firstAcct = s.reading?.[0]?.id;
  statusBar.replaceChildren(crumbsEl, h('span', { class: 'spacer' }),
    s.unidentified > 0 && h('a', { class: 'unk-badge', href: firstAcct ? `#/accounts/${firstAcct}/unidentified` : '#/accounts', title: 'Calls under event names not yet identified' },
      svg('svg', { width: 16, height: 16, viewBox: '0 0 16 16', 'aria-hidden': 'true' }, svg('circle', { cx: 8, cy: 8, r: 6.5, fill: 'none', stroke: '#f0b45a', 'stroke-width': 1.5, 'stroke-dasharray': '3 2' }), svg('circle', { cx: 8, cy: 8, r: 1.8, fill: '#f0b45a' })),
      `${s.unidentified} UNIDENTIFIED`),
    meter);
}
setInterval(() => refreshStatus(), 20000);

function shell(active, content, full) {
  const item = (key, href, label, perm) => (!perm || can(perm)) && h('a', { class: 'item', href, 'aria-current': active === key ? 'page' : null },
    svg('svg', { width: 20, height: 20, viewBox: '0 0 24 24', fill: 'none', stroke: 'currentColor', 'stroke-width': '1.6', 'aria-hidden': 'true' }, svg('path', { d: ICON[key] })), label);
  setCrumbs({ radar: 'Radar', trust: 'Trust map', roles: 'Roles', scans: 'Scans', accounts: 'Accounts', members: 'Members', audit: 'Audit' }[active] || '');
  if (!statusBar.firstChild) statusBar.append(crumbsEl);
  refreshStatus();
  return h('div', { class: 'shell' },
    h('nav', { class: 'rail', 'aria-label': 'Main' },
      h('a', { class: 'home', href: '#/', 'aria-label': 'Curious Monkey radar' }, mark()),
      item('radar', '#/', 'Radar', 'view'), item('trust', '#/trust', 'Trust', 'view'), item('roles', '#/roles', 'Roles', 'view'), item('scans', '#/scans', 'Scans', 'ops'),
      item('accounts', '#/accounts', 'Accounts', 'view'), item('members', '#/members', 'Members', 'members'), item('audit', '#/audit', 'Audit', 'audit'),
      h('div', { class: 'me' },
        h('span', { class: 'avatar', title: `${state.user.name} · ${ROLE_LABEL[state.user.role]}${state.user.team ? `, ${TEAM[state.user.team]}` : ''}` }, (state.user.name || '?').split(/[.\s_-]+/).map((x) => x[0]).join('').slice(0, 2).toUpperCase()),
        h('button', { onClick: async () => { await post('/auth/signout'); state.user = null; setCsrf(''); go('#/signin'); } }, 'Sign out'))),
    h('div', { class: 'frame' }, statusBar, h('main', { class: full ? 'main full' : 'main', id: 'content' }, content)));
}

async function render() {
  state.leave.forEach((f) => f()); state.leave = [];
  const hash = location.hash;
  const [path, qs] = hash.split('?'); const params = new URLSearchParams(qs || '');
  try {
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
      const out = await page({ params, onLeave: (f) => state.leave.push(f), reload: render, setCrumbs, refreshStatus });
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
