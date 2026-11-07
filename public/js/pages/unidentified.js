// Unidentified calls: CloudTrail event names that did not match an IAM action.
// Each one has a state: open → (suggested) → identified, or unresolved with a note,
// which reopens after 30 days if the name is still being called.
import { h, get, post, api, num, ago, fmtDate, toast } from '../lib.js';
import { session, go } from '../main.js';
import { COVERAGE_ROWS, pct } from './accounts.js';

export const STATE = {
  open: ['Open', 'amber'], suggested: ['Suggestion to review', 'prov'], identified: ['Identified', ''], unresolved: ["Can't resolve", 'idle'], reopened: ['Reopened', 'amber'],
};
const stateTag = (s) => h('span', { class: `state ${STATE[s]?.[1] || ''}` }, STATE[s]?.[0] || s);

/** The buttons that settle one event name. Shared by this page and the Identify panel on a role. */
export function identifyControls(u, { accountId, bedrock, onChange }) {
  const canDecide = session.user.permissions.includes('decide');
  const m = u.mapping;
  const err = h('div', { class: 'err', role: 'alert' });
  const inp = h('input', { class: 'action-input', value: m?.action || '', placeholder: 'service:ActionName', 'aria-label': `IAM action for ${u.event_name}`, spellcheck: 'false', disabled: !canDecide });
  const note = h('input', { placeholder: 'Why it cannot be resolved (kept with the decision)', 'aria-label': 'Note', value: u.state === 'unresolved' ? m?.note || '' : '' });
  const noteRow = h('div', { class: 'row', hidden: true }, note, h('button', { class: 'btn sm', onClick: () => run(() => post('/event-mappings/unresolved', { rawAction: u.raw_action, note: note.value.trim() }), 'Marked as can’t resolve. It reopens in 30 days if it is still called.') }, 'Save note'));
  async function run(fn, msg) { err.textContent = ''; try { await fn(); if (msg) toast(msg); onChange(); } catch (x) { err.textContent = x.message; } }
  const save = (action) => {
    if (action !== null && !/^[a-z0-9-]+:[A-Za-z0-9]+$/.test(action)) { err.textContent = 'Use the form service:ActionName, for example s3:GetObject.'; return; }
    run(() => api('PUT', '/event-mappings', { rawAction: u.raw_action, action }), 'Saved. It applies to stored history at the next analysis.');
  };
  const ask = h('button', { class: 'btn sm', disabled: !bedrock, title: bedrock ? 'Ask Bedrock which IAM action this is' : 'Bedrock is off. Set BEDROCK_ENABLED=true on the server.' }, 'Ask Bedrock');
  ask.addEventListener('click', () => { ask.disabled = true; ask.textContent = 'Asking…'; run(async () => {
    const r = await post(`/accounts/${accountId}/unmapped/suggest`, { rawActions: [u.raw_action] });
    if (!r.suggested.length) throw new Error(r.rejected.length ? 'Bedrock’s answer was not a real IAM action, so it was dropped.' : 'Bedrock had no suggestion.');
  }); });
  if (!canDecide) return h('div', { class: 'tiny muted' }, 'You can view this. Deciding needs the decide permission.');
  return h('div', { class: 'stack' },
    m?.status === 'suggested' && h('div', { class: 'suggest' }, h('div', { class: 'eyebrow' }, `BEDROCK SUGGESTS${m.confidence != null ? ` · ${Math.round(m.confidence * 100)}% SURE` : ''}`),
      h('div', { class: 'act' }, m.action || 'No permission needed'), m.note && h('div', { class: 'tiny muted' }, m.note),
      h('div', { class: 'row' }, h('button', { class: 'btn sm primary', onClick: () => save(m.action ?? null) }, 'Accept'), h('span', { class: 'tiny muted' }, 'or type another below'))),
    h('div', { class: 'row' }, inp, h('button', { class: 'btn sm primary', onClick: () => save(inp.value.trim()) }, 'Save action')),
    h('div', { class: 'row' }, u.state !== 'identified' && ask,
      h('button', { class: 'btn sm', title: 'The call is checked by no IAM permission', onClick: () => save(null) }, 'No permission'),
      u.state !== 'unresolved' && h('button', { class: 'btn sm', onClick: () => { noteRow.hidden = false; note.focus(); } }, 'Can’t resolve'),
      m && h('button', { class: 'btn sm', onClick: () => run(() => api('DELETE', `/event-mappings?raw=${encodeURIComponent(u.raw_action)}`), u.state === 'identified' ? 'Cleared. The name is open again.' : 'Reopened.') }, u.state === 'identified' ? 'Clear' : 'Reopen')),
    noteRow, err);
}

export function eventFacts(u) {
  return h('dl', { class: 'facts' },
    h('dt', null, 'Event'), h('dd', { class: 'mono' }, u.event_name), h('dt', null, 'Source'), h('dd', { class: 'mono' }, u.event_source),
    h('dt', null, 'Calls'), h('dd', null, `${num(u.count)} · last ${ago(u.last_seen)}`),
    h('dt', null, 'Roles'), h('dd', null, (u.role_names || []).slice(0, 4).join(', ') || '—'),
    u.param_keys?.length > 0 && [h('dt', null, 'Parameters'), h('dd', { class: 'mono tiny', title: 'Request parameter names. Values are never stored.' }, u.param_keys.slice(0, 8).join(', '))],
    u.mapping?.decided_by && [h('dt', null, 'Decided'), h('dd', null, `${u.mapping.decided_by} · ${fmtDate(u.mapping.decided_at)}`)],
    u.state === 'unresolved' && u.mapping?.reopen_at && [h('dt', null, 'Reopens'), h('dd', null, `${fmtDate(u.mapping.reopen_at)} if still called`)]);
}

export async function unidentifiedPage(ctx, id) {
  const st = { days: 30, tab: 'todo' };
  const root = h('div', { class: 'stack-lg' });
  let changed = false;

  async function draw() {
    const [a, c] = await Promise.all([get(`/accounts/${id}`), get(`/accounts/${id}/coverage?days=${st.days}`)]);
    ctx.setCrumbs(h('a', { href: '#/accounts' }, 'Accounts'), a.name, 'Unidentified calls');
    const t = c.totals;
    const groups = { todo: c.unmapped.filter((u) => ['open', 'suggested', 'reopened'].includes(u.state)), identified: c.unmapped.filter((u) => u.state === 'identified'), unresolved: c.unmapped.filter((u) => u.state === 'unresolved') };
    const period = h('select', { 'aria-label': 'Period' }, [7, 30, 90, 365].map((d) => h('option', { value: d, selected: d === st.days }, `Last ${d} days`)));
    period.addEventListener('change', () => { st.days = Number(period.value); draw(); });
    const onChange = () => { changed = true; draw(); ctx.refreshStatus(); };
    const askAll = h('button', { class: 'btn sm', disabled: !c.bedrockEnabled || !groups.todo.length || !session.user.permissions.includes('decide') }, 'Ask Bedrock for all open');
    askAll.addEventListener('click', async () => {
      askAll.disabled = true; askAll.textContent = 'Asking Bedrock…';
      try { const r = await post(`/accounts/${id}/unmapped/suggest`, {}); toast(`${r.suggested.length} suggestion(s)${r.rejected.length ? `, ${r.rejected.length} dropped: not real IAM actions` : ''}. Review each one.`); onChange(); }
      catch (x) { toast(x.message, true); askAll.disabled = false; askAll.textContent = 'Ask Bedrock for all open'; }
    });

    // coverage strip: where every event went
    const parts = [['assume_events', '#6fe3b0', 'Role sessions'], ['role_calls', '#f6e016', 'Role calls'], ['not_role', '#5f8c73', 'Not a role'], ['other_role', '#3b5f4c', 'Role not in this account']];
    const strip = h('div', { class: 'covbar', role: 'img', 'aria-label': 'Share of events by outcome' }, parts.map(([k, col]) => {
      const s = h('span', { title: `${k}: ${num(t[k])}` }); s.style.flex = String(t[k] || 0); s.style.background = col; return s; }));
    const unk = h('span'); unk.style.flex = String(t.unmapped || 0); unk.style.background = 'repeating-linear-gradient(45deg,#f0b45a 0 3px,transparent 3px 6px)'; strip.append(unk);

    const list = groups[st.tab];
    root.replaceChildren(
      h('header', { class: 'head' }, h('div', null, h('div', { class: 'eyebrow' }, 'UNIDENTIFIED CALLS'), h('h1', null, a.name),
        h('p', { class: 'muted' }, 'CloudTrail names a call by event source and event name. Most match an IAM action; the ones that do not land here. Their calls are kept, and that service stays unconfirmed — never removed — until each name is settled.')),
        h('div', { class: 'row' }, period, askAll)),
      changed && h('div', { class: 'alert ok row' }, h('span', { class: 'grow' }, 'Decisions changed. They apply to stored history at the next analysis.'),
        h('button', { class: 'btn sm primary', onClick: async () => { try { await post(`/accounts/${id}/scan`); toast('Re-analyzing'); go('#/scans'); } catch (x) { toast(x.message, true); } } }, 'Re-analyze now')),
      !c.bedrockEnabled && h('div', { class: 'alert warn' }, 'Bedrock is off, so suggestions are unavailable. You can still settle each name by hand.'),
      h('section', { class: 'card' }, h('div', { class: 'card-h' }, h('h2', null, 'Where every event went'), h('span', { class: 'tiny muted' }, `${num(t.events)} events read`)),
        h('div', { class: 'card-b stack' }, strip,
          h('div', { class: 'row tiny muted' }, parts.map(([k, col, label]) => h('span', { class: 'row', style: 'gap:6px' }, swatch(col), `${label} ${pct(t[k], t.events)}`)),
            h('span', { class: 'row', style: 'gap:6px;color:#f0b45a' }, swatch('#f0b45a'), `Unidentified ${pct(t.unmapped, t.role_calls)} of role calls`)),
          h('details', null, h('summary', { class: 'btn sm' }, 'Full breakdown by region'),
            h('div', { class: 'scroll' }, h('table', null,
              h('thead', null, h('tr', null, h('th', null, 'Outcome'), ...c.regions.map((r) => h('th', { class: 'right mono' }, r.region)), h('th', { class: 'right' }, 'Total'))),
              h('tbody', null, COVERAGE_ROWS.map(([k, label, help, sub]) => h('tr', null, h('td', null, h('div', { class: sub ? 'sub-row' : 'name' }, label), h('div', { class: 'tiny muted' }, help)),
                ...c.regions.map((r) => h('td', { class: 'right' }, num(r[k]))), h('td', { class: 'right' }, h('b', null, num(t[k]))))))))))),
      h('div', { class: 'tabs', role: 'tablist' }, [['todo', 'To settle'], ['identified', 'Identified'], ['unresolved', 'Can’t resolve']].map(([k, label]) =>
        h('button', { role: 'tab', class: 'tab', 'aria-selected': String(st.tab === k), onClick: () => { st.tab = k; draw(); } }, label, h('span', { class: 'mono tiny muted' }, ` ${groups[k].length}`)))),
      !list.length ? h('div', { class: 'card empty' }, st.tab === 'todo' ? 'Nothing to settle. Every event name in this account is identified or marked.' : 'None.')
        : h('div', { class: 'stack' }, list.map((u) => h('section', { class: 'card' },
          h('div', { class: 'card-h' }, h('div', { class: 'row' }, h('span', { class: 'unk-tag' }, 'UNK'), h('b', { class: 'mono', style: 'overflow-wrap:anywhere' }, u.raw_action)), stateTag(u.state)),
          h('div', { class: 'card-b', style: 'display:grid;grid-template-columns:minmax(0,1fr) minmax(0,1.3fr);gap:20px' }, eventFacts(u),
            identifyControls(u, { accountId: id, bedrock: c.bedrockEnabled, onChange }))))));
  }
  await draw();
  return root;
}

function swatch(c) { const s = h('span', { 'aria-hidden': 'true' }); Object.assign(s.style, { display: 'inline-block', width: '10px', height: '10px', background: c }); return s; }
