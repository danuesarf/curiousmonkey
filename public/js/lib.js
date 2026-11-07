// replaceChildren would print `false`/`null` from `cond && node`. Drop them everywhere.
const nativeReplace = Element.prototype.replaceChildren;
Element.prototype.replaceChildren = function (...kids) { return nativeReplace.apply(this, kids.flat(Infinity).filter((k) => k != null && k !== false)); };
// Tiny DOM helpers. Everything goes in as text nodes, so data from the API can never become markup.
export function h(tag, props, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(props || {})) {
    if (v == null || v === false) continue;
    if (k === 'class') el.className = v;
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
  for (const [k, v] of Object.entries(props || {})) el.setAttribute(k, v);
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

export const fmtDate = (d) => d ? new Date(d).toLocaleString('en-GB', { day: '2-digit', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit', timeZone: 'Asia/Jakarta' }) + ' WIB' : 'never';
export const fmtDay = (d) => d ? new Date(d).toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric', timeZone: 'Asia/Jakarta' }) : 'never';
export const ago = (d) => {
  if (!d) return 'never';
  const s = Math.max(0, (Date.now() - new Date(d)) / 1000);
  if (s < 90) return 'just now'; if (s < 5400) return `${Math.round(s / 60)} min ago`; if (s < 129600) return `${Math.round(s / 3600)} h ago`; return `${Math.round(s / 86400)} days ago`;
};
export const num = (n) => Number(n || 0).toLocaleString('en-US');
export const TEAM = { infrasec: 'Infrastructure Security', infosec: 'Information Security' };
export const ROLE_LABEL = { owner: 'Owner', admin: 'Admin', reviewer: 'Security reviewer', account_owner: 'Account owner', auditor: 'Auditor' };
export const KIND = { custom: 'Custom', 'service-linked': 'Service-linked', 'identity-center': 'Identity Center' };
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
