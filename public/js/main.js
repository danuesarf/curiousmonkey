import { h, clear, get, post, setCsrf, toast, ApiError, ROLE_LABEL, TEAM } from './lib.js';
import { logo } from './art.js';
import * as authPages from './pages/auth.js';
import { overview } from './pages/overview.js';
import { rolePage } from './pages/role.js';
import { recommendationPage } from './pages/recommendation.js';
import { accountsPage, newAccountPage } from './pages/accounts.js';
import { membersPage } from './pages/members.js';
import { auditPage } from './pages/audit.js';
import { opsPage } from './pages/ops.js';

const root = document.getElementById('app');
const state = { user: null, leave: [] };
export const session = state;

const routes = [
  [/^#?\/?$/, () => overview, 'overview'],
  [/^#\/roles\/([\w-]+)\/recommendation$/, (m) => (c) => recommendationPage(c, m[1]), 'overview'],
  [/^#\/roles\/([\w-]+)$/, (m) => (c) => rolePage(c, m[1]), 'overview'],
  [/^#\/accounts\/new$/, () => newAccountPage, 'accounts'],
  [/^#\/accounts$/, () => accountsPage, 'accounts'],
  [/^#\/scans$/, () => opsPage, 'scans'],
  [/^#\/members$/, () => membersPage, 'members'],
  [/^#\/audit$/, () => auditPage, 'audit'],
];

export function go(hash) { location.hash = hash; }
const can = (p) => state.user?.permissions.includes(p);

function shell(active, content) {
  const link = (href, key, label, perm, extra) => (!perm || can(perm)) && h('a', { href, 'aria-current': active === key ? 'page' : null }, h('span', null, label), extra);
  return h('div', { class: 'shell' },
    h('nav', { class: 'side', 'aria-label': 'Main' },
      h('a', { class: 'brand', href: '#/' }, logo(), 'Curious Monkey'),
      h('div', { class: 'nav' },
        link('#/', 'overview', 'IAM roles', 'view'),
        link('#/scans', 'scans', 'Scan activity', 'ops'),
        link('#/accounts', 'accounts', 'Cloud accounts', 'view')),
      h('div', { class: 'nav' }, h('div', { class: 'nav-label' }, 'Workspace'),
        link('#/members', 'members', 'Members and roles', 'members'),
        link('#/audit', 'audit', 'Audit log', 'audit')),
      h('div', { class: 'me' }, h('span', { class: 'avatar', 'aria-hidden': 'true' }, (state.user.name || '?').slice(0, 1).toUpperCase()),
        h('div', { class: 'stack', style: null }, h('div', { class: 'name small' }, state.user.name),
          h('div', { class: 'tiny muted' }, ROLE_LABEL[state.user.role], state.user.team ? `, ${TEAM[state.user.team]}` : '')),
        h('button', { class: 'btn sm', onClick: async () => { await post('/auth/signout'); state.user = null; setCsrf(''); go('#/signin'); } }, 'Sign out'))),
    h('main', { class: 'main', id: 'content' }, content));
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
    for (const [re, pick, key] of routes) {
      const m = path.match(re);
      if (!m) continue;
      const page = pick(m);
      const content = h('div', { class: 'stack-lg' }, h('div', { class: 'muted' }, h('span', { class: 'spin' }), ' Loading'));
      mount(shell(key, content));
      const out = await page({ params, onLeave: (f) => state.leave.push(f), reload: render });
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
