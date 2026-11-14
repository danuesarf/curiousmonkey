// Review → Access reviews: evidence for periodic user access reviews. A review freezes every role and IAM user in
// some accounts, with who used it in a period and every decision; each review team signs it off. Download as CSV, or
// print (and save as PDF) from the browser.
import { h, get, post, api, num, ago, fmtDate, fmtDay, toast, modal, field, TEAM, KIND, riskBadge, tile, pager, searchBox, envs, envName, loadEnvironments } from '../lib.js';
import { session, go } from '../main.js';

const can = (p) => session.user.permissions.includes(p);
// the date as the person's own calendar shows it, not UTC's (in Jakarta the UTC date is yesterday until 07:00)
const iso = (d) => d.toLocaleDateString('en-CA');
const period = (r) => `${fmtDay(r.from)} to ${fmtDay(r.to)}`;
const statusBadge = (r) => (r.status === 'signed' ? h('span', { class: 'badge b-green' }, 'Signed off')
  : h('span', { class: 'badge b-medium' }, `${r.signoffs.length} of ${r.teams.length} sign-offs`));

// ---------- the list ----------
export async function reviewsPage(ctx) {
  ctx.setCrumbs('Review', 'Access reviews');
  const [{ items }] = await Promise.all([get('/reviews'), loadEnvironments().catch(() => [])]);
  return h('div', { class: 'stack-lg' },
    h('header', { class: 'head' }, h('div', null, h('div', { class: 'eyebrow' }, 'REVIEW · ACCESS REVIEWS'), h('h1', null, 'Access reviews'),
      h('p', { class: 'muted' }, 'Evidence for a periodic user access review. A review freezes every role and IAM user in the accounts you pick: risk, permissions, who used it in the period, access keys and every decision. Each review team then signs it off. Later scans do not change it.')),
    can('decide') && h('div', { class: 'actions' }, h('button', { class: 'btn primary', onClick: () => newReview() }, 'New review'))),
    h('section', { class: 'card' }, items.length ? h('div', { class: 'scroll' }, h('table', null,
      h('thead', null, h('tr', null, h('th', null, 'Review'), h('th', null, 'Period'), h('th', null, 'Accounts'), h('th', null, 'Identities'), h('th', null, 'Status'), h('th', null, 'Taken'))),
      h('tbody', null, items.map((r) => h('tr', { class: 'link', tabindex: '0', onClick: () => go(`#/reviews/${r.id}`), onKeydown: (e) => { if (e.key === 'Enter') go(`#/reviews/${r.id}`); } },
        h('td', { class: 'name' }, r.name), h('td', { class: 'nowrap' }, period(r)),
        h('td', null, r.accounts.length > 3 ? `${r.accounts.slice(0, 3).map((a) => a.name).join(', ')} +${r.accounts.length - 3}` : r.accounts.map((a) => a.name).join(', ')),
        h('td', null, num(r.totals.identities), r.totals.undecided ? h('span', { class: 'tiny muted' }, ` · ${num(r.totals.undecided)} undecided`) : null),
        h('td', null, statusBadge(r)), h('td', { class: 'nowrap small' }, `${ago(r.createdAt)} by ${r.createdBy || 'someone'}`))))))
      : h('div', { class: 'empty' }, can('decide') ? 'No review yet. Start one: it takes a few seconds and records everything as it stands now.' : 'No review yet.')));
}

function newReview() {
  const today = new Date(), back = (n) => iso(new Date(Date.now() - n * 864e5));
  const qStart = new Date(Date.UTC(today.getUTCFullYear(), Math.floor(today.getUTCMonth() / 3) * 3 - 3, 1)), qEnd = new Date(Date.UTC(today.getUTCFullYear(), Math.floor(today.getUTCMonth() / 3) * 3, 0));
  const name = h('input', { value: `Access review ${today.toLocaleDateString('en-GB', { month: 'long', year: 'numeric' })}`, maxlength: 120 });
  const from = h('input', { type: 'date', value: back(90), max: iso(today) }), to = h('input', { type: 'date', value: iso(today), max: iso(today) });
  const preset = (label, f, t) => h('button', { class: 'btn sm', type: 'button', onClick: () => { from.value = f; to.value = t; } }, label);
  const acctBox = h('div', { class: 'check-grid' }, h('span', { class: 'muted small' }, 'Loading accounts…'));
  let boxes = [];
  get('/accounts').then((r) => {
    const list = r.items.filter((a) => a.status !== 'planned');
    boxes = list.map((a) => { const cb = h('input', { type: 'checkbox', value: a.id, checked: true }); return [cb, h('label', null, cb, h('span', null, a.name, h('span', { class: 'tiny muted' }, ` · ${envName(a.environment)}`)))]; });
    const byEnv = (env) => h('button', { class: 'btn sm', type: 'button', onClick: () => boxes.forEach(([cb], i) => { cb.checked = !env || list[i].environment === env; }) }, env ? envName(env) : 'All');
    acctBox.replaceChildren(...boxes.map(([, l]) => l));
    acctBox.before(h('div', { class: 'row', style: 'gap:6px;flex-wrap:wrap' }, h('span', { class: 'small muted' }, 'Only:'), byEnv(''), ...envs().filter((e) => list.some((a) => a.environment === e.id)).map((e) => byEnv(e.id))));
  }).catch((e) => { acctBox.textContent = e.message; });
  const teams = Object.entries(TEAM).map(([k, l]) => { const cb = h('input', { type: 'checkbox', value: k, checked: true }); return [cb, h('label', null, cb, l)]; });
  const err = h('div', { class: 'err', role: 'alert' });
  const save = h('button', { class: 'btn primary', type: 'submit' }, 'Take the snapshot');
  const m = modal('New access review', h('form', { class: 'stack', onSubmit: async (e) => {
    e.preventDefault(); err.textContent = ''; save.disabled = true; save.textContent = 'Taking the snapshot…';
    try {
      const r = await post('/reviews', { name: name.value, from: from.value, to: to.value, accounts: boxes.filter(([cb]) => cb.checked).map(([cb]) => cb.value), teams: teams.filter(([cb]) => cb.checked).map(([cb]) => cb.value) });
      m.remove(); toast(`Review taken: ${num(r.totals.identities)} identities`); go(`#/reviews/${r.id}`);
    } catch (x) { err.textContent = x.message; save.disabled = false; save.textContent = 'Take the snapshot'; }
  } },
  field('Name', name),
  h('div', { class: 'field' }, h('span', { class: 'label' }, 'Period'), h('div', { class: 'row', style: 'gap:8px;flex-wrap:wrap' }, from, h('span', { class: 'muted' }, 'to'), to),
    h('div', { class: 'row', style: 'gap:6px;flex-wrap:wrap' }, preset('Last 30 days', back(30), iso(today)), preset('Last 90 days', back(90), iso(today)), preset('Last quarter', iso(qStart), iso(qEnd))),
    h('span', { class: 'hint' }, 'Who used each identity, and how often, is counted in this period. Everything else (risk, keys, decisions) is as it stands now.')),
  h('div', { class: 'field' }, h('span', { class: 'label' }, 'Accounts'), acctBox),
  h('div', { class: 'field' }, h('span', { class: 'label' }, 'Signed off by'), h('div', { class: 'check-grid' }, teams.map(([, l]) => l))),
  err, h('div', { class: 'actions' }, save, h('button', { class: 'btn', type: 'button', onClick: () => m.remove() }, 'Cancel'))), h('span'));
  name.focus(); name.select();
}

// ---------- one review ----------
const DECIDED = { keep_scoped: 'keep, scoped', keep: 'keep', remove: 'remove', accept: 'accept', investigate: 'investigate' };
const SIZE = 50;

export async function reviewPage(ctx, id) {
  const r = await get(`/reviews/${id}`);
  ctx.setCrumbs(h('a', { href: '#/reviews' }, 'Access reviews'), r.name);
  const f = { q: '', account: '', kind: '', risk: '', unused: false, undecided: false, page: 1 };
  const list = h('div'), count = h('span', { class: 'count' });
  const open = new Set();

  const qs = () => { const p = new URLSearchParams({ page: f.page, limit: SIZE }); for (const k of ['q', 'account', 'kind', 'risk']) if (f[k]) p.set(k, f[k]); if (f.unused) p.set('unused', '1'); if (f.undecided) p.set('undecided', '1'); return p; };
  async function load() {
    const d = await get(`/reviews/${id}/items?${qs()}`);
    count.textContent = `${num(d.total)} identit${d.total === 1 ? 'y' : 'ies'}`;
    list.replaceChildren(d.items.length ? h('div', { class: 'scroll' }, h('table', { class: 'review-table' },
      h('thead', null, h('tr', null, h('th', null, 'Identity'), h('th', null, 'Risk'), h('th', null, 'Calls in period'), h('th', null, 'Who used it'), h('th', null, 'Findings'), h('th', null, 'Credentials'))),
      h('tbody', null, d.items.flatMap((x) => {
        const row = h('tr', { class: 'link', tabindex: '0', 'aria-expanded': String(open.has(x.n)) },
          h('td', null, h('div', { class: 'name' }, x.name), h('div', { class: 'tiny muted' }, `${x.account} · ${KIND[x.kind] || x.kind}`)),
          h('td', null, riskBadge(x.risk)),
          h('td', { class: 'nowrap' }, x.period.calls ? num(x.period.calls) : h('span', { class: 'key-bad' }, 'none'), x.period.denied ? h('span', { class: 'tiny muted' }, ` · ${num(x.period.denied)} denied`) : null),
          h('td', { class: 'small' }, x.callers.length ? `${x.callers.slice(0, 2).map((c) => c.name).join(', ')}${x.callers.length + x.moreCallers > 2 ? ` +${x.callers.length + x.moreCallers - 2}` : ''}` : h('span', { class: 'muted' }, '—')),
          h('td', { class: 'nowrap small' }, x.findings.length ? `${x.findings.length} open` : h('span', { class: 'muted' }, 'none'), x.findings.some((g) => !g.decision) ? h('span', { class: 'badge b-medium', style: 'margin-left:6px' }, `${x.findings.filter((g) => !g.decision).length} undecided`) : null),
          h('td', { class: 'small' }, x.user ? credentials(x.user) : h('span', { class: 'muted' }, 'role')));
        const toggle = () => { open.has(x.n) ? open.delete(x.n) : open.add(x.n); load(); };
        row.addEventListener('click', toggle); row.addEventListener('keydown', (e) => { if (e.key === 'Enter') toggle(); });
        return open.has(x.n) ? [row, h('tr', { class: 'detail-row' }, h('td', { colspan: 6 }, identityDetail(x)))] : [row];
      })))) : h('div', { class: 'empty' }, 'No identity matches these filters.'),
    d.total > SIZE && pager({ page: f.page, total: d.total, size: SIZE, onPage: (n) => { f.page = n; load(); } }));
  }

  const search = searchBox({ placeholder: 'Find an identity or ARN', label: 'Search identities in this review', onSearch: (v) => { f.q = v.trim(); f.page = 1; load(); } });
  ctx.onLeave(search.cancel);
  const sel = (label, key, opts) => { const s = h('select', { 'aria-label': label }, opts.map(([v, l]) => h('option', { value: v }, l))); s.addEventListener('change', () => { f[key] = s.value; f.page = 1; load(); }); return s; };
  const chip = (key, label) => { const b = h('button', { class: 'chip', type: 'button', 'aria-pressed': 'false' }, label); b.addEventListener('click', () => { f[key] = !f[key]; b.setAttribute('aria-pressed', String(f[key])); f.page = 1; load(); }); return b; };
  const t = r.totals;
  const incomplete = r.accounts.filter((a) => !a.historyComplete);

  // sign-off
  const mine = session.user.team, canSign = can('approve') && mine && r.teams.includes(mine) && !r.signoffs.some((s) => s.team === mine);
  const signCard = h('section', { class: 'card' },
    h('div', { class: 'card-h' }, h('div', null, h('h2', null, 'Sign-off'), h('p', { class: 'muted small' }, r.status === 'signed' ? 'Every team listed has signed this review off.' : `Each team below signs off once. ${r.teams.length - r.signoffs.length} still to go.`)),
      canSign && h('button', { class: 'btn primary', onClick: () => signOff(r, ctx) }, `Sign off for ${TEAM[mine] || mine}`)),
    h('div', { class: 'card-b stack' }, r.teams.map((team) => {
      const s = r.signoffs.find((x) => x.team === team);
      return h('div', { class: 'signoff-row' }, h('span', { class: `badge ${s ? 'b-green' : 'b-neutral'}` }, s ? 'Signed' : 'Waiting'), h('b', null, TEAM[team] || team),
        s ? h('span', { class: 'small' }, `${s.by}${s.email ? ` (${s.email})` : ''}, ${fmtDate(s.at)}`, s.note && h('span', { class: 'muted' }, ` · “${s.note}”`)) : h('span', { class: 'small muted' }, 'not yet'));
    })));

  await load();
  const removeBtn = can('decide') && !r.signoffs.length && h('button', { class: 'btn', onClick: async () => {
    if (!confirm(`Remove the review "${r.name}"? Nobody has signed it off yet.`)) return;
    try { await api('DELETE', `/reviews/${id}`); toast('Review removed'); go('#/reviews'); } catch (e) { toast(e.message, true); }
  } }, 'Remove');
  return h('div', { class: 'stack-lg review-page' },
    h('header', { class: 'head' }, h('div', null, h('div', { class: 'eyebrow' }, 'REVIEW · ACCESS REVIEW'), h('h1', null, r.name), h('div', { class: 'row', style: 'gap:8px;flex-wrap:wrap' }, statusBadge(r),
      h('span', { class: 'small muted' }, `Period ${period(r)} · ${r.accounts.length} account${r.accounts.length === 1 ? '' : 's'} · taken ${fmtDate(r.takenAt)} by ${r.createdBy || 'someone'}`))),
    h('div', { class: 'actions' }, h('a', { class: 'btn', href: `/api/reviews/${id}/identities.csv`, download: '' }, 'Identities CSV'), h('a', { class: 'btn', href: `/api/reviews/${id}/decisions.csv`, download: '' }, 'Decisions CSV'),
      h('button', { class: 'btn', onClick: (e) => printReview(r, e.currentTarget) }, 'Print or save as PDF'), removeBtn)),
    incomplete.length > 0 && h('div', { class: 'alert warn' }, `When this was taken, CloudTrail history was not fully read for ${incomplete.map((a) => a.name).join(', ')}. Their call counts are “at least”, and “not used” may not be final.`),
    t.undecided > 0 && h('div', { class: 'alert warn' }, `${num(t.undecided)} finding${t.undecided === 1 ? ' had' : 's had'} no decision when this was taken. `, h('a', { href: '#/findings' }, 'Decide them'), ', then take a new review if the evidence must show them decided.'),
    signCard,
    h('section', { class: 'tiles' }, tile('Identities', num(t.identities), `${num(t.roles)} roles, ${num(t.users)} IAM users`), tile('High risk', num(t.high), `${num(t.medium)} medium`, { bad: t.high > 0 }),
      tile('Not used in the period', num(t.unusedInPeriod), 'candidates for removal'), tile('Findings undecided', num(t.undecided), `of ${num(t.findings)} open`, { bad: t.undecided > 0 }),
      tile('Keys to rotate', num(t.keysToRotate), `of ${num(t.activeKeys)} active, older than ${r.keyRules?.rotateDays ?? 90} days`), tile('Console without MFA', num(t.consoleWithoutMfa), 'IAM users')),
    h('section', { class: 'card' },
      h('div', { class: 'filters' }, search, sel('Account', 'account', [['', 'Every account'], ...r.accounts.map((a) => [a.id, a.name])]),
        sel('Kind', 'kind', [['', 'Roles and IAM users'], ['roles', 'Roles'], ['users', 'IAM users']]), sel('Risk', 'risk', [['', 'Any risk'], ['High', 'High'], ['Medium', 'Medium'], ['Low', 'Low']]),
        chip('unused', 'Not used in the period'), chip('undecided', 'Findings undecided'), count),
      list),
    h('p', { class: 'tiny muted' }, 'Accounts in this review: ', r.accounts.map((a) => `${a.name} (${a.awsAccountId}, ${envName(a.environment)})`).join(' · ')));
}

const credentials = (u) => {
  const active = u.keys.filter((k) => k.status === 'Active');
  return h('span', null, active.length ? `${active.length} key${active.length === 1 ? '' : 's'}` : 'no key',
    active.some((k) => k.rotate) ? h('span', { class: 'badge b-medium', style: 'margin-left:6px' }, 'rotate') : null,
    u.consolePassword ? (u.mfa.length ? ' · console, MFA' : h('span', { class: 'key-bad' }, ' · console, no MFA')) : '');
};

function identityDetail(x) {
  return h('div', { class: 'review-detail' },
    h('div', { class: 'stack', style: 'gap:4px' }, h('div', { class: 'mono tiny muted break' }, x.arn),
      x.why.length > 0 && h('div', { class: 'small' }, h('b', null, 'Why this risk: '), x.why.join(' · ')),
      h('div', { class: 'small' }, `Permissions: ${num(x.permissions.granted)} granted, ${num(x.permissions.used)} used, ${num(x.permissions.unused)} unused, ${num(x.permissions.unconfirmed)} cannot be verified. Last call ${x.lastCall ? fmtDay(x.lastCall) : 'never seen'}. Reviewed by ${x.reviewerTeam === 'both' ? 'both teams' : TEAM[x.reviewerTeam] || '—'}.`)),
    x.callers.length > 0 && h('div', null, h('div', { class: 'eyebrow' }, 'WHO USED IT IN THE PERIOD'),
      h('ul', { class: 'plain small' }, x.callers.map((c) => h('li', null, h('span', { class: 'name' }, c.name), h('span', { class: 'muted' }, ` · ${c.kind}${c.sessions ? ` · ${num(c.sessions)} sessions` : ''} · last ${fmtDay(c.lastSeen)}`))),
        x.moreCallers > 0 && h('li', { class: 'muted' }, `+${x.moreCallers} more`))),
    x.user && x.user.keys.length > 0 && h('div', null, h('div', { class: 'eyebrow' }, 'ACCESS KEYS'),
      h('ul', { class: 'plain small' }, x.user.keys.map((k) => h('li', null, h('span', { class: 'mono' }, k.id), ` · ${k.status} · ${k.ageDays} days old · last used ${k.lastUsed ? fmtDay(k.lastUsed) : 'never'}`, k.rotate ? h('span', { class: 'key-bad' }, ' · rotate') : null)))),
    x.findings.length > 0 && h('div', null, h('div', { class: 'eyebrow' }, 'FINDINGS AND DECISIONS'),
      h('ul', { class: 'plain small' }, x.findings.map((g) => h('li', null, h('span', { class: `badge b-${g.severity}` }, g.severity), ` ${g.title} · `,
        g.decision ? h('span', null, h('b', null, DECIDED[g.decision] || g.decision), ` by ${g.decidedBy || 'someone'}${g.decidedTeam ? ` (${TEAM[g.decidedTeam] || g.decidedTeam})` : ''}, ${fmtDay(g.decidedAt)}${g.note ? ` · “${g.note}”` : ''}`) : h('span', { class: 'key-bad' }, 'not decided'))))));
}

function signOff(r, ctx) {
  const note = h('textarea', { rows: 3, maxlength: 1000, placeholder: 'Optional: what was checked, who took part' });
  const err = h('div', { class: 'err', role: 'alert' });
  const team = TEAM[session.user.team] || session.user.team;
  const m = modal(`Sign off for ${team}`, h('form', { class: 'stack', onSubmit: async (e) => {
    e.preventDefault(); err.textContent = '';
    try { const out = await post(`/reviews/${r.id}/signoff`, { note: note.value || undefined }); m.remove(); toast(out.signed ? 'Signed. Every team has now signed this review off.' : 'Signed'); ctx.reload(); }
    catch (x) { err.textContent = x.message; }
  } }, h('p', null, `You confirm, for ${team}, that the access in this snapshot (${period(r)}) was reviewed. Your name, email and the time are recorded and cannot be changed.`),
  field('Note', note), err, h('div', { class: 'actions' }, h('button', { class: 'btn primary', type: 'submit' }, 'Sign off'), h('button', { class: 'btn', type: 'button', onClick: () => m.remove() }, 'Cancel'))), h('span'));
}

/** Builds the whole review as a printable report (every identity, every decision) and opens the print dialog. */
async function printReview(r, btn) {
  btn.disabled = true; const label = btn.textContent; btn.textContent = 'Preparing…';
  try {
    const { items } = await get(`/reviews/${r.id}/items?all=1`);
    const t = r.totals;
    const report = h('div', { class: 'print-report' },
      h('h1', null, r.name), h('p', null, `Access review · period ${period(r)} · taken ${fmtDate(r.takenAt)} by ${r.createdBy || 'someone'} · Curious Monkey`),
      h('h2', null, 'Sign-off'), h('table', null, h('tbody', null, r.teams.map((team) => { const s = r.signoffs.find((x) => x.team === team);
        return h('tr', null, h('td', null, TEAM[team] || team), h('td', null, s ? `Signed by ${s.by}${s.email ? ` (${s.email})` : ''}, ${fmtDate(s.at)}${s.note ? ` · “${s.note}”` : ''}` : 'Not signed off')); }))),
      h('h2', null, 'Summary'), h('p', null, `${num(t.identities)} identities (${num(t.roles)} roles, ${num(t.users)} IAM users). ${num(t.high)} high risk, ${num(t.medium)} medium. ${num(t.unusedInPeriod)} not used in the period. ${num(t.findings)} open findings, ${num(t.undecided)} without a decision. ${num(t.activeKeys)} active access keys, ${num(t.keysToRotate)} to rotate. ${num(t.consoleWithoutMfa)} console users without MFA.`),
      h('table', null, h('thead', null, h('tr', null, h('th', null, 'Account'), h('th', null, 'Account ID'), h('th', null, 'Environment'), h('th', null, 'Identities'), h('th', null, 'High'), h('th', null, 'Undecided'), h('th', null, 'History read'))),
        h('tbody', null, r.accounts.map((a) => h('tr', null, h('td', null, a.name), h('td', null, a.awsAccountId), h('td', null, envName(a.environment)), h('td', null, num(a.identities)), h('td', null, num(a.high)), h('td', null, num(a.undecided)),
          h('td', null, a.historyComplete ? 'complete' : 'partial'))))),
      ...r.accounts.map((a) => { const mine = items.filter((x) => x.awsAccountId === a.awsAccountId);
        return h('section', null, h('h2', null, `${a.name} (${a.awsAccountId})`), h('table', null,
          h('thead', null, h('tr', null, h('th', null, 'Identity'), h('th', null, 'Kind'), h('th', null, 'Risk'), h('th', null, 'Calls'), h('th', null, 'Who used it'), h('th', null, 'Credentials'), h('th', null, 'Findings and decisions'))),
          h('tbody', null, mine.map((x) => h('tr', null, h('td', null, x.name), h('td', null, KIND[x.kind] || x.kind), h('td', null, x.risk), h('td', null, num(x.period.calls)),
            h('td', null, [...x.callers.slice(0, 5).map((c) => c.name), x.callers.length + x.moreCallers > 5 ? `+${x.callers.length + x.moreCallers - 5}` : ''].filter(Boolean).join(', ') || '—'),
            h('td', null, x.user ? `${x.user.keys.filter((k) => k.status === 'Active').map((k) => `${k.id} (${k.ageDays} d)`).join(', ') || 'no key'}${x.user.consolePassword ? `; console${x.user.mfa.length ? ' + MFA' : ', no MFA'}` : ''}` : '—'),
            h('td', null, x.findings.length ? x.findings.map((g) => `${g.title}: ${g.decision ? `${DECIDED[g.decision] || g.decision} (${g.decidedBy || '?'}${g.decidedTeam ? `, ${TEAM[g.decidedTeam] || g.decidedTeam}` : ''})` : 'not decided'}`).join(' · ') : '—'))))));
      }));
    document.body.append(report);
    const done = () => { report.remove(); window.removeEventListener('afterprint', done); };
    window.addEventListener('afterprint', done);
    window.print();
  } catch (e) { toast(e.message, true); }
  finally { btn.disabled = false; btn.textContent = label; }
}
