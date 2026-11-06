import { h, get, fmtDate, num } from '../lib.js';

export async function auditPage(ctx) {
  const st = { action: '', actor: '', page: 1 };
  const list = h('div');
  const load = async () => {
    const p = new URLSearchParams({ page: st.page, limit: 100 }); if (st.action) p.set('action', st.action); if (st.actor) p.set('actor', st.actor);
    const r = await get(`/audit?${p}`);
    list.replaceChildren(...[r.items.length ? h('div', { class: 'scroll' }, h('table', null, h('thead', null, h('tr', null, ['When', 'Who', 'Action', 'Detail', 'IP'].map((x) => h('th', null, x)))),
      h('tbody', null, r.items.map((e) => h('tr', null, h('td', { class: 'nowrap small' }, fmtDate(e.at)), h('td', { class: 'small' }, e.actor_email || 'system'), h('td', null, h('code', null, e.action)),
        h('td', { class: 'small muted' }, e.detail ? JSON.stringify(e.detail).slice(0, 160) : ''), h('td', { class: 'small mono muted' }, e.ip || '')))))) : h('div', { class: 'empty' }, 'Nothing recorded yet.'),
      r.total > 100 && h('div', { class: 'pager' }, h('span', { class: 'small muted' }, `${num(r.total)} entries`), h('button', { class: 'btn sm', disabled: st.page <= 1, onClick: () => { st.page--; load(); } }, 'Newer'), h('button', { class: 'btn sm', disabled: st.page * 100 >= r.total, onClick: () => { st.page++; load(); } }, 'Older'))].filter(Boolean));
  };
  const mk = (key, ph) => { const i = h('input', { type: 'search', placeholder: ph, 'aria-label': ph }); let t; i.addEventListener('input', () => { clearTimeout(t); t = setTimeout(() => { st[key] = i.value; st.page = 1; load(); }, 250); }); return i; };
  load();
  return h('div', { class: 'stack-lg' }, h('header', { class: 'head' }, h('div', null, h('h1', null, 'Audit log'), h('p', { class: 'muted' }, 'Sign-ins, decisions, approvals, exports, and every change to members and accounts. It cannot be edited from the portal.'))),
    h('section', { class: 'card' }, h('div', { class: 'filters' }, mk('action', 'Action starts with (e.g. flag.)'), mk('actor', 'Person')), list));
}
