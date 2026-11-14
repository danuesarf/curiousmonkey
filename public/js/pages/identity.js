// One identity, one page. An IAM role, an IAM user or a Google Cloud identity opens here, with tabs:
//   Overview · Activity · Permissions · Credentials · Policies and trust · Findings
// Tabs that do not apply to a kind of identity are left out. The tab is kept in the address (?tab=), so a link opens it.
import { h, svg, get, num, fmtDate, fmtDay, ago, riskBadge, teamBadge, usageBar, copy, modal, KIND, searchBox, pager, tile, envName, loadEnvironments, TZ, TZ_LABEL } from '../lib.js';
import { session, go } from '../main.js';
import { identifyControls, eventFacts, STATE } from './unidentified.js';
import { findingCard } from './findings.js';
import { sectorView } from './sector.js';
import { userParts } from './users.js';

/**
 * The frame every identity shares: eyebrow, name, badges, one primary action, notices, then tabs.
 * tabs: [key, label, render()] where render returns a node (or a promise of one) and runs when the tab is first opened.
 * `label` may be a function, read again by `shell.relabel()` (the Findings count changes as decisions are made).
 */
export function identityShell(ctx, { path, eyebrow, name, badges, sub, actions, notices, tabs }) {
  const keys = tabs.map(([k]) => k);
  let tab = keys.includes(ctx.params.get('tab')) ? ctx.params.get('tab') : keys[0];
  const bar = h('div', { class: 'tabs', role: 'tablist', 'aria-label': 'Sections of this identity' });
  const panel = h('div', { class: 'stack-lg', role: 'tabpanel' });
  const built = new Map();
  const drawBar = () => bar.replaceChildren(...tabs.map(([k, l]) => h('button', { role: 'tab', 'aria-selected': String(k === tab), onClick: () => show(k) }, typeof l === 'function' ? l() : l)));
  async function show(k, first = false) {
    tab = k; drawBar();
    // the address follows the tab, except in a window over another page, where the address belongs to that page
    if (!first && !ctx.inWindow) history.replaceState(null, '', `${path}${k === keys[0] ? '' : `?tab=${k}`}`);
    if (!built.has(k)) {
      panel.replaceChildren(h('div', { class: 'muted' }, h('span', { class: 'spin' }), ' Loading'));
      try { built.set(k, await tabs.find(([x]) => x === k)[2]()); }
      catch (e) { built.set(k, h('div', { class: 'alert bad' }, e.message || 'This section could not be loaded.')); }
    }
    if (tab === k) panel.replaceChildren(built.get(k));
  }
  show(tab, true);
  const el = h('div', { class: 'stack-lg' },
    h('header', { class: 'head' },
      h('div', null, h('div', { class: 'eyebrow' }, eyebrow), h('h1', { class: 'break' }, name), h('div', { class: 'row', style: 'gap:8px;flex-wrap:wrap' }, badges), sub),
      actions && h('div', { class: 'actions' }, actions)),
    notices, bar, panel);
  return { el, show, relabel: drawBar };
}
export const section = (title, sub, ...kids) => h('section', { class: 'card' }, h('div', { class: 'card-h' }, h('div', null, h('h2', null, title), sub && h('p', { class: 'muted small' }, sub))), h('div', { class: 'card-b stack' }, ...kids));

/** An IAM role or an IAM user. */
export async function identityPage(ctx, id) {
  const d = await get(`/roles/${id}`);
  const r = d.role, isUser = r.kind === 'iam-user';
  // an IAM user has more to show: keys, console sign-in, groups
  const [u] = await Promise.all([isUser ? get(`/iam-users/${id}`) : null, loadEnvironments().catch(() => [])]);
  const parts = u ? userParts(u) : null;
  const hist = d.history || { complete: true };
  const unmappedFlag = d.flags.find((f) => f.category === 'unmapped-event');
  const openIdentify = (raw) => identifyPanel(r, raw, ctx);
  const canRec = session.user.permissions.includes('recommend') && r.kind !== 'service-linked';
  const waiting = () => d.flags.filter((f) => !f.decision).length;

  let shell;
  const tabs = [
    ['overview', 'Overview', () => overviewTab(d, u, hist, (k) => shell.show(k))],
    ['activity', 'Activity', () => activityTab(d, parts, ctx)],
    ['permissions', 'Permissions', () => permsTab(d)],
    isUser && ['credentials', 'Credentials', () => h('div', { class: 'stack-lg' }, parts.keys, parts.consoleBox)],
    ['policies', isUser ? 'Policies' : 'Policies and trust', () => policiesTab(d, parts)],
    ['history', 'History', () => historyTab(d)],
    ['findings', () => `Findings${d.flags.length ? ` ${waiting() ? `${waiting()} of ${d.flags.length}` : d.flags.length}` : ''}`, () => findingsTab(d, ctx, openIdentify, () => shell.relabel())],
  ].filter(Boolean);

  shell = identityShell(ctx, {
    path: `#/identities/${r.id}`,
    eyebrow: `${isUser ? 'IAM USER' : 'ROLE'} · ${r.account_name}`,
    name: r.name,
    badges: [riskBadge(r.risk), h('span', { class: 'badge b-neutral' }, KIND[r.kind]), h('span', { class: 'badge b-neutral' }, envName(r.environment)), teamBadge(r.reviewer_team, r.requires_both), h('span', { class: 'small muted mono' }, r.arn)],
    sub: u && h('p', { class: 'small muted' }, `Created ${fmtDay(u.created)} · user ID ${u.userId || '—'} · ${u.lastSeen ? `last active ${ago(u.lastSeen)}` : 'never seen active'}`),
    actions: [
      h('a', { class: 'btn', href: isUser ? `#/space?view=account&account=${r.account_id}&who=users&sel=${r.id}` : `#/space?view=account&account=${r.account_id}&sel=${r.id}` }, 'In Space'),
      r.kind === 'service-linked' ? h('span', { class: 'alert warn small' }, 'Service-linked: managed by AWS. Report only.')
        : canRec && h('a', { class: 'btn primary', href: `#/identities/${r.id}/recommendation` }, 'Recommend least-privilege policy')],
    notices: [
      !hist.complete && h('div', { class: 'provisional' }, h('b', null, `PROVISIONAL · ${hist.progress}% OF HISTORY READ`),
        h('span', null, `Used counts are “at least” and never-called counts “at most” until the rest of CloudTrail history is read${hist.readUpTo ? ` (read back to ${fmtDay(hist.backTo || hist.readUpTo)})` : ''}. Approval waits for it.`)),
      unmappedFlag && h('div', { class: 'unk-box' }, h('div', { class: 'row' }, h('span', { class: 'unk-tag' }, 'UNK'),
        h('span', { class: 'grow small' }, `Some calls by this ${isUser ? 'user' : 'role'} use event names that are not identified yet. Those services stay unconfirmed — nothing in them will be removed until each name is settled.`),
        h('button', { class: 'btn sm amber', onClick: () => openIdentify(null) }, 'Identify'))),
      r.kind === 'identity-center' && h('div', { class: 'alert warn' }, `This role comes from the Identity Center permission set "${r.permission_set}". Changes belong in the permission set, not on the role.`)],
    tabs,
  });
  ctx.setCrumbs(h('a', { href: isUser ? '#/identities?type=users' : '#/identities' }, 'Identities'), r.account_name, r.name);
  if (ctx.params.has('identify')) setTimeout(() => openIdentify(ctx.params.get('identify') || null));
  return shell.el;
}

// ---------- History ----------
const GROUPS = [['', 'Everything'], ['policy', 'Permissions'], ['access', 'Who can get in'], ['credentials', 'Credentials'], ['risk', 'Risk'], ['review', 'Reviews'], ['lifecycle', 'Created or removed']];
const MARK = { 'policy-added': '+', 'policy-removed': '−', 'policy-changed': '~', 'trust-changed': '~', 'boundary-changed': '~', risk: '▲', 'key-status': '•', 'key-created': '+', 'key-deleted': '−',
  password: '•', mfa: '•', deleted: '×', restored: '+', created: '+', 'radar-new-caller': '→', 'radar-grew': '▲', 'radar-cleaned': '▼', 'radar-denied': '!', 'radar-dead': '·',
  decision: '✓', undecided: '↺', approval: '✓' };

async function historyTab(d) {
  const r = d.role, isUser = r.kind === 'iam-user';
  const { items, since } = await get(`/roles/${r.id}/history`);
  let group = '';
  const list = h('div', { class: 'timeline' });
  const day = (t) => new Date(t).toLocaleDateString('en-GB', { timeZone: TZ, day: '2-digit', month: 'short', year: 'numeric' });
  const time = (t) => new Date(t).toLocaleTimeString('en-GB', { timeZone: TZ, hour: '2-digit', minute: '2-digit' });
  const draw = () => {
    const shown = items.filter((x) => !group || x.group === group);
    if (!shown.length) { list.replaceChildren(h('div', { class: 'empty' }, group ? 'Nothing of this kind.' : 'Nothing recorded yet.')); return; }
    const out = []; let last = null;
    for (const x of shown) {
      const dd = day(x.at);
      if (dd !== last) { out.push(h('div', { class: 'tl-day' }, dd)); last = dd; }
      const sub = [x.by && `by ${x.by}`, x.detail?.bulk && 'from the Findings inbox', x.detail?.text, x.detail?.from && x.detail?.to && x.kind === 'boundary-changed' && `${x.detail.from || 'none'} → ${x.detail.to || 'none'}`,
        x.kind === 'risk' && x.detail?.reasons?.length && x.detail.reasons.slice(0, 2).join(' · '), x.kind === 'key-deleted' && 'seen gone at this scan'].filter(Boolean).join(' · ');
      out.push(h('div', { class: `tl-item g-${x.group || 'other'}${x.kind === 'risk' && x.detail?.to === 'High' ? ' bad' : ''}` },
        h('span', { class: 'tl-mark', 'aria-hidden': 'true' }, MARK[x.kind] || '•'),
        h('span', { class: 'tl-time mono tiny muted' }, time(x.at)),
        h('div', { class: 'tl-body' }, h('div', null, x.title), sub && h('div', { class: 'tiny muted' }, sub)),
        x.diff && h('button', { class: 'btn sm', onClick: () => showDiff(r.id, x) }, x.kind === 'policy-added' || x.kind === 'policy-removed' ? 'View document' : 'Compare')));
    }
    list.replaceChildren(...out);
  };
  const chips = h('div', { class: 'pill-bar', role: 'group', 'aria-label': 'Kind of change' }, GROUPS.filter(([g]) => g !== 'credentials' || isUser).map(([g, l]) => {
    const n = items.filter((x) => !g || x.group === g).length;
    const b = h('button', { class: 'chip', type: 'button', 'aria-pressed': String(group === g), disabled: !n && !!g }, `${l} ${n}`);
    b.addEventListener('click', () => { group = g; chips.querySelectorAll('button').forEach((x) => x.setAttribute('aria-pressed', String(x === b))); draw(); });
    return b;
  }));
  draw();
  return h('section', { class: 'card' },
    h('div', { class: 'card-h' }, h('div', null, h('h2', null, 'History'),
      h('p', { class: 'muted small' }, `Policy, trust, credential and risk changes are compared at each daily scan${since ? `, recorded since ${day(since)}` : ' from the next scan on'}. Callers and decisions come from their own records. Times in ${TZ_LABEL}.`))),
    h('div', { class: 'card-b stack' }, chips, list));
}

/** Pretty JSON with keys sorted, so a reordering alone is not a change. */
const sortKeys = (v) => (Array.isArray(v) ? v.map(sortKeys) : v && typeof v === 'object' ? Object.fromEntries(Object.keys(v).sort().map((k) => [k, sortKeys(v[k])])) : v);
const pretty = (v) => (v == null ? '' : JSON.stringify(sortKeys(v), null, 2));
/** Line diff: [' '|'+'|'-', text]. Common ends are trimmed first; a very large middle is shown as removed then added. */
export function lineDiff(a, b) {
  const A = a ? a.split('\n') : [], B = b ? b.split('\n') : [];
  let s = 0; while (s < A.length && s < B.length && A[s] === B[s]) s++;
  let e = 0; while (e < A.length - s && e < B.length - s && A[A.length - 1 - e] === B[B.length - 1 - e]) e++;
  const a2 = A.slice(s, A.length - e), b2 = B.slice(s, B.length - e), mid = [];
  if (a2.length * b2.length > 4e6) { a2.forEach((x) => mid.push(['-', x])); b2.forEach((x) => mid.push(['+', x])); }
  else {
    const n = a2.length, m = b2.length, L = new Uint32Array((n + 1) * (m + 1));
    for (let i = n - 1; i >= 0; i--) for (let j = m - 1; j >= 0; j--) L[i * (m + 1) + j] = a2[i] === b2[j] ? L[(i + 1) * (m + 1) + j + 1] + 1 : Math.max(L[(i + 1) * (m + 1) + j], L[i * (m + 1) + j + 1]);
    let i = 0, j = 0;
    while (i < n && j < m) {
      if (a2[i] === b2[j]) { mid.push([' ', a2[i]]); i++; j++; }
      else if (L[(i + 1) * (m + 1) + j] >= L[i * (m + 1) + j + 1]) mid.push(['-', a2[i++]]);
      else mid.push(['+', b2[j++]]);
    }
    while (i < n) mid.push(['-', a2[i++]]); while (j < m) mid.push(['+', b2[j++]]);
  }
  return [...A.slice(0, s).map((x) => [' ', x]), ...mid, ...A.slice(A.length - e).map((x) => [' ', x])];
}
async function showDiff(roleId, x) {
  const ev = await get(`/roles/${roleId}/history/${x.id}`);
  const lines = lineDiff(pretty(ev.detail.before), pretty(ev.detail.after));
  // long unchanged runs fold, keeping three lines of context next to each change
  const rows = []; let run = [], changed = false;
  const flush = (end) => {
    const head = changed ? 3 : 0, tail = end ? 0 : 3;
    if (run.length > head + tail + 2) rows.push(...run.slice(0, head), ['…', `${run.length - head - tail} unchanged lines`], ...run.slice(run.length - tail));
    else rows.push(...run);
    run = [];
  };
  for (const l of lines) { if (l[0] === ' ') run.push(l); else { flush(false); rows.push(l); changed = true; } }
  flush(true);
  const added = lines.filter((l) => l[0] === '+').length, removed = lines.filter((l) => l[0] === '-').length;
  modal(x.title, h('div', { class: 'stack' },
    h('p', { class: 'small muted' }, `${new Date(ev.at).toLocaleString('en-GB', { timeZone: TZ })} · `, ev.detail.before && ev.detail.after ? `${added} line${added === 1 ? '' : 's'} added, ${removed} removed` : ev.detail.after ? 'the document as attached' : 'the document as it was before', ev.detail.arn ? ` · ${ev.detail.arn}` : ''),
    h('pre', { class: 'diff' }, rows.map(([t, s]) => h('span', { class: t === '+' ? 'add' : t === '-' ? 'del' : t === '…' ? 'fold' : '' }, `${t === '…' ? '' : `${t} `}${s}\n`)))),
  h('div', { class: 'actions' }, ev.detail.after && h('button', { class: 'btn', onClick: () => copy(JSON.stringify(ev.detail.after, null, 2)) }, 'Copy new document'), h('button', { class: 'btn', onClick: (e) => e.target.closest('.modal-bg').remove() }, 'Close')));
}

function overviewTab(d, u, hist, open) {
  const r = d.role;
  const jump = (k, text) => h('button', { class: 'link-btn small', type: 'button', onClick: () => open(k) }, text);
  const callers = d.principals.slice(0, 5);
  const activeKeys = u ? u.keys.filter((k) => k.status === 'Active') : [];
  return h('div', { class: 'stack-lg' },
    h('section', { class: 'tiles' },
      tile('Granted', num(r.granted_count), `${r.inline_count} inline, ${r.attached_count} attached`),
      tile('Used', `${hist.complete ? '' : '≥ '}${num(r.used_count)}`, 'seen in event history'), tile('Unused', `${hist.complete ? '' : '≤ '}${num(r.unused_count)}`, 'no evidence of use'), tile('Cannot be verified', num(r.unconfirmed_count), 'event history cannot prove'),
      tile('Last activity', r.last_activity_at ? ago(r.last_activity_at) : 'none', `IAM last used: ${r.last_used_at ? ago(r.last_used_at) : 'never'}`)),
    h('div', { class: 'card' }, h('div', { class: 'card-b stack' }, h('h3', null, 'Why this risk level'),
      r.risk_reasons.length ? h('ul', { class: 'plain' }, r.risk_reasons.map((x) => h('li', null, x))) : h('p', { class: 'muted' }, 'Nothing stands out.'),
      d.window?.first && h('p', { class: 'small muted' }, `Evidence window: ${fmtDay(d.window.first)} to ${fmtDay(d.window.last)}. Anything older is invisible to this tool.`))),
    u && h('div', { class: 'card' }, h('div', { class: 'card-b stack' }, h('div', { class: 'row' }, h('h3', { class: 'grow' }, 'Credentials'), jump('credentials', 'Keys and console sign-in →')),
      h('p', { class: 'small' }, activeKeys.length ? `${activeKeys.length} active access key${activeKeys.length > 1 ? 's' : ''}${u.oldestKeyDays != null ? `, the oldest ${num(u.oldestKeyDays)} days old` : ''}.` : 'No active access key.', ' ',
        u.console.password ? (u.console.mfa.length ? 'Console password with MFA.' : h('span', { class: 'key-bad' }, 'Console password without MFA.')) : 'No console password.',
        u.groups.length ? ` Groups: ${u.groups.join(', ')}.` : ''))),
    h('div', { class: 'card' }, h('div', { class: 'card-b stack' }, h('div', { class: 'row' }, h('h3', { class: 'grow' }, u ? 'Who used it' : 'Who got in'), jump('activity', 'All activity and sessions →')),
      callers.length ? h('ul', { class: 'plain stack', style: 'gap:4px' }, callers.map((p) => h('li', { class: 'small' }, h('span', { class: 'name' }, p.display), h('span', { class: 'muted' }, ` · ${p.kind} · ${num(p.sessions_count)} session${p.sessions_count === 1 ? '' : 's'} · last ${ago(p.last_seen)}`),
        p.caller?.trust && !p.caller.trust.matched && p.kind !== 'service' ? h('span', { class: 'badge b-high', style: 'margin-left:6px' }, 'Not named in trust policy') : null)),
        d.principals.length > 5 ? h('li', { class: 'small muted' }, `+${d.principals.length - 5} more`) : null)
        : h('p', { class: 'small muted' }, u ? 'No call seen in the history read so far.' : 'Nobody assumed this role in the window.'),
      !u && h('p', { class: 'small muted' }, 'Everyone the trust policy lets in, used or not, is on the ', h('a', { href: `#/trust?q=${encodeURIComponent(r.name)}` }, 'Trust map'), '.'))),
    gcpCard(r.id));
}

/** Sessions of this role: one list, the same on every identity. A session opens its replay in a window over the page. */
function sessionsSection(roleId, ctx) {
  const box = h('div', { class: 'muted small' }, h('span', { class: 'spin' }), ' Loading sessions');
  const open = (s) => { const hash = `#/track?role=${roleId}&session=${s.id}`; ctx.inWindow ? go(hash) : ctx.openWindow(hash, { title: s.sessionName || 'Session', eyebrow: 'TRACK · CALL BY CALL' }); };
  get(`/sessions?role=${roleId}&limit=50`).then((r) => {
    box.className = '';
    box.replaceChildren(r.items.length ? h('div', { class: 'scroll' }, h('table', { class: 'small' },
      h('thead', null, h('tr', null, h('th', null, 'Session'), h('th', null, 'Started by'), h('th', null, 'Calls'), h('th', null, 'Started'), h('th', null, ''))),
      h('tbody', null, r.items.map((s) => h('tr', { class: 'link', tabindex: '0', onClick: () => open(s), onKeydown: (e) => { if (e.key === 'Enter') open(s); } },
        h('td', { class: 'mono' }, s.sessionName || s.id.slice(0, 8)),
        h('td', null, s.principal || s.callerArn || 'Unknown caller'),
        h('td', { class: 'nowrap' }, num(s.calls), s.denied > 0 && h('span', { class: 'badge b-high', style: 'margin-left:6px' }, `${s.denied} denied`)),
        h('td', { class: 'nowrap' }, s.startKnown ? ago(s.startedAt) : 'earlier than the stored history'),
        h('td', { class: 'nowrap' }, s.isJump && h('span', { class: 'badge b-neutral' }, 'jumped in'), s.hasJumps && h('span', { class: 'badge b-neutral', style: 'margin-left:4px' }, 'jumps on'), h('span', { class: 'link-btn', style: 'margin-left:8px' }, 'Replay'))))))) 
      : h('p', { class: 'muted small' }, `No session recorded. Sessions come from AssumeRole events and are kept for ${r.retentionDays} days.`));
  }).catch((e) => { box.textContent = e.message; });
  return h('section', { class: 'card' }, h('div', { class: 'card-h' }, h('h2', null, 'Sessions'), h('span', { class: 'small muted' }, 'Pick one to replay it call by call, with every role it jumped into.')), h('div', { class: 'card-b' }, box));
}

function activityTab(d, parts, ctx) {
  const isUser = d.role.kind === 'iam-user';
  return h('div', { class: 'stack-lg' },
    h('section', { class: 'card' }, h('div', { class: 'card-h' }, h('h2', null, 'Activity, last 90 days'), h('span', { class: 'small muted' }, 'Red bars include calls AWS denied. Denied calls are not counted as use.')),
      h('div', { class: 'card-b' }, d.daily.length ? chart(d.daily) : h('p', { class: 'muted' }, 'No calls were seen in the window.'))),
    isUser ? parts.who
      : h('section', { class: 'card', id: 'principals' }, h('div', { class: 'card-h' }, h('h2', null, 'Who assumed this role')),
        d.principals.length ? h('div', { class: 'stack', style: null }, d.principals.map(principalCard)) : h('div', { class: 'empty' }, 'Nobody assumed this role in the window.')),
    !isUser && sessionsSection(d.role.id, ctx),
    d.passRoles.length > 0 && h('section', { class: 'card' }, h('div', { class: 'card-h' }, h('h2', null, `Roles this ${isUser ? 'user' : 'role'} passed to services`), h('span', { class: 'small muted' }, 'Inferred from request parameters. CloudTrail does not log iam:PassRole itself.')),
      h('div', { class: 'scroll' }, h('table', null, h('thead', null, h('tr', null, h('th', null, 'Passed role'), h('th', null, 'Service'), h('th', null, 'Times'), h('th', null, 'Last seen'))),
        h('tbody', null, d.passRoles.map((p) => h('tr', null, h('td', { class: 'mono small' }, p.passed_role_arn), h('td', null, p.service), h('td', null, num(p.count)), h('td', { class: 'small' }, ago(p.last_seen))))))))
  );
}

function policiesTab(d, parts) {
  return h('div', { class: 'stack-lg' },
    parts?.pol,
    d.policies.map((p) => h('section', { class: 'card' }, h('div', { class: 'card-h' }, h('h2', null, p.name), h('div', { class: 'row' }, h('span', { class: 'badge b-neutral' }, p.kind), p.aws_managed && h('span', { class: 'badge b-banana' }, 'AWS managed'),
      h('button', { class: 'btn sm', onClick: () => copy(JSON.stringify(p.document, null, 2)) }, 'Copy'))), h('div', { class: 'card-b' }, h('pre', null, JSON.stringify(p.document, null, 2))))),
    d.role.kind !== 'iam-user' && h('section', { class: 'card' }, h('div', { class: 'card-h' }, h('h2', null, 'Trust policy'), h('span', { class: 'small muted' }, 'Who is allowed to assume this role')),
      h('div', { class: 'card-b' }, h('pre', null, JSON.stringify(d.role.trust_policy, null, 2)))));
}

/** Where this role reaches into Google Cloud, or which Google service accounts can become it. Filled in when known. */
function gcpCard(roleId) {
  const box = h('div');
  get(`/gcp/aws-role/${roleId}`).then((x) => {
    if (!x.into.length && !x.from.length) return;
    const li = (label, meta, href, bad) => h('li', null, h('a', { href }, label), h('span', { class: 'small muted' }, ` · ${meta}`), bad ? h('span', { class: 'badge b-high', style: 'margin-left:6px' }, 'any role in the account') : null);
    box.replaceChildren(h('section', { class: 'card' }, h('div', { class: 'card-b stack' }, h('h3', null, 'Across clouds · Google Cloud'),
      x.into.length > 0 && h('div', null, h('p', { class: 'small muted' }, 'Through workload identity federation, this role can act in Google Cloud as:'),
        h('ul', { class: 'plain stack', style: 'gap:4px' }, x.into.map((l) => li(l.gcpEmail || `${l.grant} on ${l.gcpProject}`, `${l.gcpProject} · pool ${l.pool}${l.awsRole ? '' : ' (open to the whole AWS account)'}`, `#/identities/gcp/${l.gcpPrincipal}`, l.broad)))),
      x.from.length > 0 && h('div', null, h('p', { class: 'small muted' }, 'Its trust policy lets these Google service accounts in:'),
        h('ul', { class: 'plain stack', style: 'gap:4px' }, x.from.map((l) => li(l.gcpEmail || `unknown service account ${l.uniqueId}`, `${l.gcpProject || 'not in a connected organization'} · statement ${l.statement + 1}`, l.gcpPrincipal ? `#/identities/gcp/${l.gcpPrincipal}` : `#/trust?q=${encodeURIComponent('provider:google')}`)))))));
  }).catch(() => {});
  return box;
}

function chart(daily) {
  const w = 900, hgt = 120, days = 90, bw = w / days;
  const byDay = new Map(daily.map((x) => [String(x.day).slice(0, 10), x]));
  const max = Math.max(1, ...daily.map((x) => x.calls));
  const s = svg('svg', { class: 'chart', viewBox: `0 0 ${w} ${hgt}`, role: 'img', 'aria-label': 'Calls per day over the last 90 days', preserveAspectRatio: 'none' });
  for (let i = 0; i < days; i++) {
    const dt = new Date(Date.now() - (days - 1 - i) * 864e5).toISOString().slice(0, 10), x = byDay.get(dt);
    if (!x) continue;
    const bh = Math.max(2, (x.calls / max) * (hgt - 10));
    s.append(svg('rect', { class: x.denied ? 'bad' : 'ok', x: i * bw + 1, y: hgt - bh, width: bw - 2, height: bh }, svg('title', {}, `${dt}: ${x.calls} calls${x.denied ? `, ${x.denied} denied` : ''}`)));
  }
  return s;
}

function principalCard(p) {
  const t = p.caller?.trust;
  return h('div', { class: 'card-b stack', style: null },
    h('div', { class: 'row' }, h('span', { class: 'name' }, p.display), h('span', { class: 'badge b-neutral' }, p.kind), h('span', { class: 'small muted mono' }, p.via),
      p.mfa === true && h('span', { class: 'badge b-green' }, 'MFA'), t && !t.matched && p.kind !== 'service' && h('span', { class: 'badge b-high' }, 'Not named in trust policy')),
    h('dl', { class: 'kv' },
      h('dt', null, 'First / last seen'), h('dd', null, `${fmtDate(p.first_seen)}  to  ${fmtDate(p.last_seen)}`),
      h('dt', null, 'Sessions'), h('dd', null, num(p.sessions_count)),
      p.source_ips?.length > 0 && [h('dt', null, 'Source IPs'), h('dd', { class: 'mono small' }, p.source_ips.join(', '))],
      p.source_identity && [h('dt', null, 'Source identity'), h('dd', null, p.source_identity)],
      p.session_tags?.length > 0 && [h('dt', null, 'Session tags'), h('dd', { class: 'mono small' }, p.session_tags.join(', '))],
      h('dt', null, 'Conditions on entry'),
      h('dd', null, t?.matched ? (t.conditions.length ? h('ul', { class: 'plain' }, t.conditions.map((c) => h('li', { class: 'mono small' }, c)))
        : h('span', { class: 'muted' }, 'None. The trust statement allows this principal without conditions.')) : h('span', { class: 'muted' }, 'Not matched to a trust statement.')),
      p.top_actions?.length > 0 && [h('dt', null, 'Top actions'), h('dd', null, h('div', { class: 'acts' }, p.top_actions.map((a) => h('code', null, `${a.action} ×${a.count}`))))]));
}

function findingsTab(d, ctx, openIdentify, onCount) {
  if (!d.flags.length) return h('div', { class: 'empty card' }, 'No open findings.');
  // a decision updates its card in place; the rest of the page stays as it is
  const waiting = h('span', { class: 'small muted' });
  const count = () => { const n = d.flags.filter((f) => !f.decision).length; waiting.textContent = n ? `${n} of ${d.flags.length} waiting for a decision` : 'Every finding has a decision.'; };
  count();
  return h('div', { class: 'stack', id: 'flags' },
    h('div', { class: 'row' }, waiting, h('span', { class: 'grow' }), h('a', { class: 'small', href: '#/findings' }, 'Findings on every identity →')),
    d.flags.map((f) => findingCard(f, { onIdentify: openIdentify, onDecided: () => { count(); onCount(); ctx.refreshStatus(); } })));
}

function permsTab(d) {
  const list = h('div'); const st = { status: '', service: '', q: '', page: 1 };
  const picked = h('span', { class: 'small muted' });
  const id = d.role.id;
  const load = async () => {
    const p = new URLSearchParams({ page: st.page, limit: 100 }); for (const k of ['status', 'service', 'q']) if (st[k]) p.set(k, st[k]);
    const r = await get(`/roles/${id}/actions?${p}`);
    picked.textContent = st.service ? `Only ${st.service}` : '';
    list.replaceChildren(r.items.length ? h('div', { class: 'scroll' }, h('table', null, h('thead', null, h('tr', null, h('th', null, 'Action'), h('th', null, 'Status'), h('th', null, 'Level'), h('th', null, 'Calls'), h('th', null, 'Last seen'), h('th', null, 'Why'))),
      h('tbody', null, r.items.map((a) => h('tr', null, h('td', { class: 'mono small' }, a.action),
        h('td', null, h('span', { class: `badge ${a.status === 'used' ? 'b-green' : a.status === 'unused' ? 'b-neutral' : 'b-medium'}` }, a.status)),
        h('td', { class: 'small' }, a.access_level || ''), h('td', null, num(a.event_count)), h('td', { class: 'small' }, a.last_seen ? fmtDay(a.last_seen) : ''), h('td', { class: 'small muted' }, a.reason || '')))))) : h('div', { class: 'empty' }, 'Nothing matches.'),
      r.total > 100 && pager({ page: st.page, total: r.total, size: 100, label: `${num(r.total)} actions, page ${st.page}`, onPage: (n) => { st.page = n; load(); } }));
  };
  const q = searchBox({ placeholder: 'Search actions', onSearch: (v) => { st.q = v; st.page = 1; load(); } });
  const status = h('select', { 'aria-label': 'Status' }, [['', 'Any status'], ['used', 'Used'], ['unused', 'Unused'], ['unconfirmed', 'Cannot be verified']].map(([v, l]) => h('option', { value: v }, l)));
  status.addEventListener('change', () => { st.status = status.value; st.page = 1; load(); });
  load();
  // the dish is drawn when its data arrives; the tables under it do not wait for it
  const dish = h('section', { class: 'card' }, h('div', { class: 'card-b muted' }, h('span', { class: 'spin' }), ' Drawing the sector scan'));
  if (d.role.granted_count > 0) sectorView(id, { onService: (svc) => { st.service = svc || ''; st.page = 1; load(); } }).then((el) => dish.replaceChildren(el)).catch(() => dish.remove());
  return h('div', { class: 'stack-lg' },
    d.role.granted_count > 0 && dish,
    h('section', { class: 'card' }, h('div', { class: 'card-h' }, h('h2', null, 'By service')),
      h('div', { class: 'scroll' }, h('table', null, h('thead', null, h('tr', null, h('th', null, 'Service'), h('th', null, 'Mix'), h('th', null, 'Used'), h('th', null, 'Unused'), h('th', null, 'Unverifiable'), h('th', null, 'Advisor last used'))),
        h('tbody', null, d.services.slice(0, 60).map((s) => { const adv = d.advisor.find((a) => a.service === s.service);
          return h('tr', { class: 'link', onClick: () => { st.service = s.service; st.page = 1; load(); window.scrollTo(0, document.body.scrollHeight); } }, h('td', { class: 'mono small' }, s.service), h('td', null, usageBar(s.used, s.unused, s.unconfirmed)),
            h('td', null, s.used), h('td', null, s.unused), h('td', null, s.unconfirmed), h('td', { class: 'small' }, adv ? (adv.last_authenticated ? fmtDay(adv.last_authenticated) : 'never') : '—')); }))))),
    h('section', { class: 'card' }, h('div', { class: 'filters' }, q, status, h('button', { class: 'btn sm', onClick: () => { st.service = ''; st.page = 1; load(); } }, 'All services'), picked), list));
}

/** Side panel: settle the unidentified event names this role called, without leaving the role. */
export async function identifyPanel(r, raw, ctx) {
  document.querySelector('.side-panel-bg')?.remove();
  const body = h('div', { class: 'stack-lg' }, h('span', { class: 'spin' }));
  const close = () => { bg.remove(); document.removeEventListener('keydown', esc); };
  const esc = (e) => { if (e.key === 'Escape') close(); };
  let changed = false;
  const panel = h('aside', { class: 'side-panel', role: 'dialog', 'aria-modal': 'true', 'aria-label': 'Identify event names' },
    h('div', { class: 'row' }, h('div', { class: 'grow' }, h('div', { class: 'eyebrow', style: 'color:#f0b45a' }, 'IDENTIFY'), h('h2', null, 'Unidentified calls')),
      h('button', { class: 'btn sm', onClick: () => { close(); if (changed) ctx.reload(); } }, 'Close')),
    h('p', { class: 'small muted' }, `Event names called by ${r.name} that did not match an IAM action. A decision applies to every account and to history already stored, at the next analysis.`),
    body);
  const bg = h('div', { class: 'side-panel-bg', onClick: (e) => { if (e.target === bg) { close(); if (changed) ctx.reload(); } } }, panel);
  document.body.append(bg); document.addEventListener('keydown', esc); ctx.onLeave(close);
  async function draw() {
    const c = await get(`/accounts/${r.account_id}/coverage?days=365`);
    let items = c.unmapped.filter((u) => (u.role_names || []).includes(r.name));
    if (raw) items = items.sort((a, b) => (b.raw_action === raw) - (a.raw_action === raw));
    body.replaceChildren(!items.length ? h('div', { class: 'alert ok' }, 'Nothing left to identify for this role.')
      : items.map((u) => h('section', { class: 'stack', style: 'border-top:1px solid var(--line);padding-top:14px' },
        h('div', { class: 'row' }, h('span', { class: 'unk-tag' }, 'UNK'), h('b', { class: 'mono small grow', style: 'overflow-wrap:anywhere' }, u.raw_action), h('span', { class: `state ${STATE[u.state]?.[1] || ''}` }, STATE[u.state]?.[0] || u.state)),
        eventFacts(u), identifyControls(u, { accountId: r.account_id, bedrock: c.bedrockEnabled, onChange: () => { changed = true; draw(); ctx.refreshStatus(); } }))),
      h('a', { class: 'small', href: `#/unidentified?account=${r.account_id}` }, 'All unidentified calls in this account'));
  }
  await draw();
  panel.querySelector('button')?.focus();
}
