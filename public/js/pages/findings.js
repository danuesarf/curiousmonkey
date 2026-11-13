// Review · Findings: every open finding across roles and IAM users, decided one at a time or many at once,
// without leaving the list. The finding card is shared with the role page's Findings tab.
import { h, get, post, api, num, ago, toast, KIND, TEAM, loadEnvironments, tile, pager, searchBox, accountPicker, syncUrl, urlSet } from '../lib.js';
import { session } from '../main.js';

export const CAT = { 'data-event': 'Data events', 'authorization-only': 'Not logged', 'not-logged': 'Not logged', 'before-window': 'Before window', 'service-unknown': 'Service used', 'unmapped-event': 'Unmapped events', wildcard: 'Wildcard', 'external-principal': 'Unexpected principal', 'trust-wildcard': 'Trust policy', 'role-idle': 'Idle role' };
export const ACTION_CATS = new Set(['data-event', 'authorization-only', 'not-logged', 'before-window', 'service-unknown', 'unmapped-event']);
/** The decisions a finding takes, in the order the buttons and the 1–3 keys use. */
export const OPTIONS = { action: [['keep_scoped', 'Keep, scoped'], ['keep', 'Keep as is'], ['remove', 'Remove']], other: [['accept', 'Accept'], ['investigate', 'Investigate']] };
const optionsFor = (category) => (ACTION_CATS.has(category) ? OPTIONS.action : OPTIONS.other);
const DECIDED = { keep_scoped: 'keep, scoped', keep: 'keep', remove: 'remove', accept: 'accept', investigate: 'investigate' };
const canDecide = () => session.user.permissions.includes('decide');

/**
 * One finding with its evidence and decision buttons. A decision updates the card in place (no page reload) and then
 * calls `onDecided(f)`. `f.actions` may be cut short by the list API; `f.action_count` then says how many there are.
 */
export function findingCard(f, { onDecided, onIdentify, head } = {}) {
  let el;
  const draw = () => {
    const opts = optionsFor(f.category), isAct = ACTION_CATS.has(f.category);
    const res = h('input', { placeholder: 'Narrow to resources (comma separated ARNs)', value: (f.decided_resources || []).join(', '), 'aria-label': 'Resources to keep' });
    const note = h('input', { placeholder: 'Note for the record', value: f.note || '', 'aria-label': 'Note' });
    const choose = async (decision, btn) => {
      btn.disabled = true;
      try {
        const resources = decision === 'keep_scoped' && res.value ? res.value.split(',').map((s) => s.trim()).filter(Boolean) : undefined;
        await post(`/flags/${f.id}/decision`, { decision, note: note.value || undefined, resources });
        Object.assign(f, { decision, note: note.value || null, decided_resources: resources || null, decided_by: session.user.name, decided_at: new Date().toISOString() });
        toast('Decision saved'); redraw(); onDecided?.(f);
      } catch (e) { toast(e.message, true); btn.disabled = false; }
    };
    const clearIt = async () => {
      try { await api('DELETE', `/flags/${f.id}/decision`); Object.assign(f, { decision: null, decided_by: null, decided_at: null }); toast('Decision cleared'); redraw(); onDecided?.(f); }
      catch (e) { toast(e.message, true); }
    };
    const actionCount = f.action_count ?? f.actions.length, resourceCount = f.resource_count ?? f.resources.length;
    return h('article', { class: `finding ${f.severity}` },
      head,
      h('div', { class: 'row' }, h('span', { class: 'badge b-neutral' }, CAT[f.category] || f.category), h('span', { class: `badge b-${f.severity}` }, f.severity), h('h3', null, f.title),
        f.decision && h('span', { class: 'badge b-green' }, `${DECIDED[f.decision] || f.decision} by ${f.decided_by || 'someone'}`)),
      h('p', null, f.reason), f.evidence && h('p', { class: 'small muted' }, f.evidence),
      f.actions.length > 0 && h('div', { class: 'acts' }, f.actions.slice(0, 40).map((a) => h('code', null, a)), actionCount > 40 && h('span', { class: 'small muted' }, `+${actionCount - 40} more`)),
      f.resources.length > 0 && h('p', { class: 'small mono muted' }, `Granted on: ${f.resources.slice(0, 4).join(', ')}${resourceCount > 4 ? '…' : ''}`),
      f.suggestion && h('p', { class: 'small' }, h('b', null, 'Suggestion: '), f.suggestion),
      f.category === 'unmapped-event' && onIdentify && h('div', { class: 'row' }, h('button', { class: 'btn sm amber', onClick: () => onIdentify(null) }, 'Identify these event names')),
      canDecide() && h('div', { class: 'stack' }, isAct && res, note,
        h('div', { class: 'row' }, opts.map(([v, l], i) => { const b = h('button', { class: `btn sm${f.decision === v ? ' primary' : ''}`, title: `Key ${i + 1}` }, l); b.addEventListener('click', () => choose(v, b)); return b; }),
          f.decision && h('button', { class: 'btn sm', onClick: clearIt }, 'Clear decision'))));
  };
  const redraw = () => { const next = draw(); el.replaceWith(next); el = next; };
  el = draw();
  return el;
}

// ---------- the inbox ----------
const DEFAULT = { q: '', severity: new Set(), category: '', accounts: new Set(), who: 'all', state: 'open', mine: false, sort: 'severity', page: 1 };
const SIZE = 50;
const STATES = [['open', 'Needs a decision'], ['decided', 'Decided'], ['all', 'All open findings']];
const SORTS = [['severity', 'Most severe first'], ['role', 'By role'], ['newest', 'Newest first']];

export async function findingsPage(ctx) {
  ctx.setCrumbs('Review', 'Findings');
  const P = ctx.params;
  const f = { ...DEFAULT, q: P.get('q') || '', severity: urlSet(P, 'severity'), category: P.get('category') || '', accounts: urlSet(P, 'accounts'),
    who: ['roles', 'users'].includes(P.get('who')) ? P.get('who') : 'all', state: STATES.some(([k]) => k === P.get('state')) ? P.get('state') : 'open',
    mine: P.get('mine') === '1', sort: SORTS.some(([k]) => k === P.get('sort')) ? P.get('sort') : 'severity', page: Math.max(1, Number(P.get('page')) || 1) };
  const [accts] = await Promise.all([get('/accounts'), loadEnvironments().catch(() => [])]);
  const accounts = accts.items.filter((a) => a.status !== 'planned');
  for (const id of [...f.accounts]) if (!accounts.some((a) => a.id === id)) f.accounts.delete(id);

  let data = { items: [], total: 0, severity: {}, categories: [], waiting: { open: 0, high: 0 } };
  let active = 0;                      // index of the finding shown on the right
  const selected = new Set();          // finding ids ticked for a bulk decision
  const byId = (id) => data.items.find((x) => x.id === id);

  // ----- layout -----
  const waiting = h('span', { class: 'mono small muted' });
  const tiles = h('div', { class: 'tiles' });
  const count = h('span', { class: 'count' });
  const listEl = h('div');
  const detail = h('div', { class: 'inbox-detail', 'aria-live': 'polite' });
  const bulk = h('div', { class: 'bulk-bar', hidden: true, role: 'region', 'aria-label': 'Decide the selected findings' });
  const bulkNote = h('input', { placeholder: 'Note for the record (all selected)', 'aria-label': 'Note for the selected findings' });

  const search = searchBox({ value: f.q, placeholder: 'Find a role or finding', label: 'Search role, account or finding', onSearch: (v) => { f.q = v.trim(); f.page = 1; load(); } });
  ctx.onLeave(search.cancel);
  const catSel = h('select', { 'aria-label': 'Finding type' });
  catSel.addEventListener('change', () => { f.category = catSel.value; f.page = 1; load(); });
  const select = (label, options, key) => {
    const s = h('select', { 'aria-label': label }, options.map(([v, l]) => h('option', { value: v, selected: f[key] === v }, l)));
    s.addEventListener('change', () => { f[key] = s.value; f.page = 1; load(); });
    return s;
  };
  const picker = accountPicker({ accounts, selected: f.accounts, onChange: () => { f.page = 1; load(); } });
  ctx.onLeave(picker.destroy);
  const mineBox = session.user.team && (() => {
    const cb = h('input', { type: 'checkbox', checked: f.mine });
    cb.addEventListener('change', () => { f.mine = cb.checked; f.page = 1; load(); });
    return h('label', { class: 'row small', style: 'gap:6px', title: `Roles ${TEAM[session.user.team] || session.user.team} reviews, and roles both teams review` }, cb, 'My team’s');
  })();

  const toUrl = () => syncUrl({ q: f.q, severity: f.severity, category: f.category, accounts: f.accounts, who: f.who === 'all' ? '' : f.who,
    state: f.state === 'open' ? '' : f.state, mine: f.mine, sort: f.sort === 'severity' ? '' : f.sort, page: f.page > 1 ? f.page : '' });
  const qs = () => {
    const p = new URLSearchParams({ page: f.page, limit: SIZE, sort: f.sort, state: f.state });
    if (f.q) p.set('q', f.q); if (f.severity.size) p.set('severity', [...f.severity].join(',')); if (f.category) p.set('category', f.category);
    if (f.accounts.size) p.set('accounts', [...f.accounts].join(',')); if (f.who !== 'all') p.set('who', f.who); if (f.mine) p.set('mine', '1');
    return p.toString();
  };

  let seq = 0;
  /** Fetches the list. `keep` holds the place: the row at the same position becomes active (the next one, when the decided one left the list). */
  async function load({ keep = false } = {}) {
    toUrl();
    const mine = ++seq;
    const r = await get(`/findings?${qs()}`);
    if (mine !== seq) return;                       // a newer load started while this one was on the wire
    data = r;
    if (!keep) { active = 0; selected.clear(); }
    for (const id of [...selected]) if (!byId(id)) selected.delete(id);
    active = Math.min(active, Math.max(0, data.items.length - 1));
    draw();
  }

  function drawTiles() {
    const s = data.severity, sevTile = (k, label) => tile(label, num(s[k] || 0), f.severity.has(k) ? 'filtered · click to clear' : 'click to filter',
      { pressed: f.severity.has(k), bad: k === 'high' && s.high > 0, onClick: () => { f.severity.has(k) ? f.severity.delete(k) : f.severity.add(k); f.page = 1; load(); } });
    tiles.replaceChildren(sevTile('high', 'High'), sevTile('medium', 'Medium'), sevTile('low', 'Low'));
    waiting.textContent = `${num(data.waiting.open)} waiting · ${num(data.waiting.high)} high`;
    const cats = data.categories;
    catSel.replaceChildren(h('option', { value: '' }, 'Every type'), ...cats.map((c) => h('option', { value: c.category, selected: f.category === c.category }, `${CAT[c.category] || c.category} (${num(c.n)})`)),
      f.category && !cats.some((c) => c.category === f.category) ? h('option', { value: f.category, selected: true }, `${CAT[f.category] || f.category} (0)`) : null);
    count.textContent = `${num(data.total)} finding${data.total === 1 ? '' : 's'}`;
  }

  const emptyText = () => {
    if (!accounts.length) return 'No accounts yet. Connect one to start.';
    const filtered = f.q || f.severity.size || f.category || f.accounts.size || f.who !== 'all' || f.mine;
    if (f.state === 'open' && !filtered) return 'Nothing waiting for a decision. Every open finding has one.';
    return 'No findings match these filters.';
  };

  function drawList() {
    if (!data.items.length) { listEl.replaceChildren(h('div', { class: 'empty' }, emptyText())); return; }
    const all = h('input', { type: 'checkbox', 'aria-label': 'Select every finding on this page', checked: data.items.every((x) => selected.has(x.id)) });
    all.addEventListener('change', () => { for (const x of data.items) all.checked ? selected.add(x.id) : selected.delete(x.id); drawList(); drawBulk(); });
    const rows = [];
    let lastRole = null;
    data.items.forEach((x, i) => {
      if (f.sort === 'role' && x.role_id !== lastRole) {
        lastRole = x.role_id;
        rows.push(h('tr', { class: 'group' }, h('td', { colspan: 5 }, h('a', { href: `#/identities/${x.role_id}`, class: 'name' }, x.role_name),
          h('span', { class: 'tiny muted' }, ` · ${x.account_name} · ${KIND[x.role_kind] || x.role_kind}`))));
      }
      const cb = h('input', { type: 'checkbox', checked: selected.has(x.id), 'aria-label': `Select ${x.title} on ${x.role_name}` });
      cb.addEventListener('click', (e) => e.stopPropagation());
      cb.addEventListener('change', () => { cb.checked ? selected.add(x.id) : selected.delete(x.id); drawBulk(); all.checked = data.items.every((y) => selected.has(y.id)); });
      rows.push(h('tr', { class: `link${i === active ? ' active' : ''}${selected.has(x.id) ? ' picked' : ''}`, 'aria-selected': String(i === active), 'data-i': i, onClick: () => setActive(i) },
        h('td', { class: 'cb' }, cb),
        h('td', null, h('span', { class: `badge b-${x.severity}` }, x.severity)),
        h('td', { class: 'small nowrap' }, CAT[x.category] || x.category),
        h('td', null, h('div', { class: 'f-title' }, x.title),
          f.sort !== 'role' && h('div', { class: 'tiny muted' }, h('span', { class: 'name' }, x.role_name), ` · ${x.account_name}${x.role_kind === 'iam-user' ? ' · IAM user' : ''}`)),
        h('td', { class: 'small nowrap' }, x.decision ? h('span', { class: 'badge b-green', title: `${x.decided_by || 'someone'} · ${ago(x.decided_at)}` }, DECIDED[x.decision]) : h('span', { class: 'muted' }, f.state === 'open' ? ago(x.created_at) : 'waiting'))));
    });
    listEl.replaceChildren(h('div', { class: 'scroll' }, h('table', { class: 'inbox-table' },
      h('thead', null, h('tr', null, h('th', { class: 'cb' }, all), h('th', null, 'Severity'), h('th', null, 'Type'), h('th', null, f.sort === 'role' ? 'Finding' : 'Finding · role'), h('th', null, f.state === 'open' ? 'Found' : 'Decision'))),
      h('tbody', null, rows))),
    data.total > SIZE && pager({ page: f.page, total: data.total, size: SIZE, onPage: (n) => { f.page = n; load(); } }));
  }

  function drawDetail() {
    const x = data.items[active];
    if (!x) { detail.replaceChildren(h('div', { class: 'empty card' }, data.items.length ? 'Pick a finding.' : 'Nothing to show.')); return; }
    const href = `#/identities/${x.role_id}`;
    const head = h('div', { class: 'stack', style: 'gap:2px' }, h('div', { class: 'eyebrow' }, `${KIND[x.role_kind] || x.role_kind} · ${x.account_name} · ${x.aws_account_id}`),
      h('div', { class: 'row' }, h('a', { class: 'name', href }, x.role_name), h('span', { class: `badge b-${String(x.role_risk).toLowerCase()}` }, `${x.role_risk} risk`),
        h('span', { class: 'badge b-neutral' }, x.requires_both ? 'Both teams' : TEAM[x.reviewer_team] || x.reviewer_team || 'No reviewer')));
    detail.replaceChildren(findingCard(x, {
      head,
      onDecided: () => { ctx.refreshStatus(); load({ keep: true }); },
      onIdentify: x.category === 'unmapped-event' ? () => { location.hash = `${href}?identify=`; } : null,
    }), h('p', { class: 'tiny muted' }, h('a', { href }, x.role_kind === 'iam-user' ? 'Open the user' : 'Open the role'), ' for activity, permissions and policies.'));
  }

  /** The decisions every selected finding takes, so one click fits them all. */
  const commonOptions = (items) => {
    if (!items.length) return [];
    const kinds = new Set(items.map((x) => ACTION_CATS.has(x.category)));
    return kinds.size === 1 ? optionsFor(items[0].category) : [];
  };
  function drawBulk() {
    const items = data.items.filter((x) => selected.has(x.id));
    bulk.hidden = !items.length || !canDecide();
    if (bulk.hidden) return;
    const opts = commonOptions(items), decidedCount = items.filter((x) => x.decision).length;
    bulk.replaceChildren(h('b', { class: 'mono small' }, `${items.length} selected`),
      opts.length ? opts.map(([v, l], i) => h('button', { class: 'btn sm', title: `Key ${i + 1}`, onClick: () => decide(items, v) }, l))
        : h('span', { class: 'small muted' }, 'These findings take different decisions (keep/remove vs accept/investigate). Select one kind.'),
      bulkNote,
      decidedCount > 0 && h('button', { class: 'btn sm', onClick: () => undecide(items.filter((x) => x.decision)) }, `Clear ${decidedCount} decision${decidedCount === 1 ? '' : 's'}`),
      h('button', { class: 'btn sm', onClick: () => { selected.clear(); draw(); } }, 'Unselect'));
  }

  async function decide(items, decision) {
    if (!canDecide()) return;
    if (!items.length) return;
    if (!commonOptions(items).some(([v]) => v === decision)) return toast('Those findings do not take that decision.', true);
    try {
      const r = await post('/findings/decisions', { ids: items.map((x) => x.id), decision, note: bulkNote.value.trim() || undefined });
      toast(`${r.decided} decision${r.decided === 1 ? '' : 's'} saved`);
      for (const x of items) selected.delete(x.id);
      bulkNote.value = '';
      ctx.refreshStatus(); await load({ keep: true });
    } catch (e) { toast(e.message, true); if (e.status === 404 || e.status === 409) load(); }
  }
  async function undecide(items) {
    try { const r = await post('/findings/decisions/clear', { ids: items.map((x) => x.id) }); toast(`${r.cleared} decision${r.cleared === 1 ? '' : 's'} cleared`); ctx.refreshStatus(); await load({ keep: true }); }
    catch (e) { toast(e.message, true); }
  }

  function setActive(i, scroll = false) {
    if (!data.items.length) return;
    active = Math.max(0, Math.min(i, data.items.length - 1));
    listEl.querySelectorAll('tr.link').forEach((tr) => { const on = Number(tr.dataset.i) === active; tr.classList.toggle('active', on); tr.setAttribute('aria-selected', String(on)); if (on && scroll) tr.scrollIntoView({ block: 'nearest' }); });
    drawDetail();
  }
  function draw() { drawTiles(); drawList(); drawDetail(); drawBulk(); }

  // ----- keyboard: j/k move, x selects, 1–3 decide, Esc unselects, / searches -----
  const onKey = (e) => {
    if (e.metaKey || e.ctrlKey || e.altKey) return;
    if (document.querySelector('.modal-bg, .side-panel-bg, .win')) return;
    const t = e.target;
    if (t instanceof HTMLElement && (t.isContentEditable || ['INPUT', 'TEXTAREA', 'SELECT'].includes(t.tagName))) {
      if (e.key === 'Escape') t.blur();
      return;
    }
    const x = data.items[active];
    if (e.key === 'j' || e.key === 'ArrowDown') { e.preventDefault(); setActive(active + 1, true); }
    else if (e.key === 'k' || e.key === 'ArrowUp') { e.preventDefault(); setActive(active - 1, true); }
    else if (e.key === 'x' && x) { selected.has(x.id) ? selected.delete(x.id) : selected.add(x.id); drawList(); drawBulk(); }
    else if (e.key === 'Escape' && selected.size) { selected.clear(); drawList(); drawBulk(); }
    else if (e.key === '/') { e.preventDefault(); search.focus(); }
    else if (['1', '2', '3'].includes(e.key) && x && canDecide()) {
      const items = selected.size ? data.items.filter((y) => selected.has(y.id)) : [x];
      const opt = commonOptions(items)[Number(e.key) - 1];
      if (opt) decide(items, opt[0]);
      else toast(commonOptions(items).length ? `Key ${e.key} has no decision for ${items.length > 1 ? 'these findings' : 'this finding'}.` : 'The selected findings take different decisions. Select one kind.', true);
    }
  };
  document.addEventListener('keydown', onKey);
  ctx.onLeave(() => document.removeEventListener('keydown', onKey));

  await load({ keep: true });
  return h('div', { class: 'stack-lg' },
    h('header', { class: 'head' }, h('div', null, h('div', { class: 'eyebrow' }, 'REVIEW · FINDINGS'), h('h1', null, 'Findings'),
      h('p', { class: 'small muted' }, 'Every open finding on the roles and IAM users you can see. Decide here without opening each role.')), waiting),
    tiles,
    h('section', { class: 'card' },
      h('div', { class: 'filters' }, search, catSel, picker.el, mineBox, select('Identities', [['all', 'Roles and IAM users'], ['roles', 'Roles'], ['users', 'IAM users']], 'who'),
        select('Decision', STATES, 'state'), select('Order', SORTS, 'sort'), count),
      picker.chips, bulk,
      h('div', { class: 'inbox' }, listEl, detail)),
    h('p', { class: 'tiny muted' }, h('kbd', null, 'j'), ' ', h('kbd', null, 'k'), ' move · ', h('kbd', null, 'x'), ' select · ', h('kbd', null, '1'), '–', h('kbd', null, '3'), ' decide the selected (or the open) finding · ',
      h('kbd', null, 'Esc'), ' unselect · ', h('kbd', null, '/'), ' search'));
}
