// Home: the page after sign-in. It answers, in this order: what should I do first (a short ranked list, each item
// opening the page that does it), what changed since I last looked, and where everything is. The list is built on
// the server (GET /home), so the wall view and the daily digest say the same thing.
//
// States: first run (no account yet: the setup checklist is the page), reading (history still being read: what needs
// none of it comes first), steady. The wall view (?wall=1) shows the team's version, large, refreshing itself.
import { h, svg, get, post, api, num, ago, toast, TEAM, poll, wallMode, fmtDate, fmtClock } from '../lib.js';
import { session, go, changeRow } from '../main.js';

const SHOWN = 5;
const TIER_TAG = { blocking: 'BLOCKING', urgent: 'URGENT', hygiene: 'HYGIENE', setup: 'SETUP' };
const can = (p) => session.user.permissions.includes(p);
const ICON = {
  radar: 'M12 12m-9 0a9 9 0 1 0 18 0a9 9 0 1 0 -18 0M12 12m-4 0a4 4 0 1 0 8 0a4 4 0 1 0 -8 0M12 12L19 6',
  identities: 'M9 11a4 4 0 1 0 0-8 4 4 0 0 0 0 8zM2 21c0-4 3-6 7-6 1.5 0 2.8.3 3.9.8M16 14a2.5 2.5 0 1 0 0 5 2.5 2.5 0 0 0 0-5z',
  findings: 'M5 4h14v16H5zM8 9l2 2 4-4M8 15h8',
  accounts: 'M4 7h16v12H4zM8 7V4h8v3',
  check: 'M5 12.5l4.5 4.5L19 7.5',
};
const icon = (k, size = 20, sw = 1.6) => svg('svg', { width: size, height: size, viewBox: '0 0 24 24', fill: 'none', stroke: 'currentColor', 'stroke-width': sw, 'aria-hidden': 'true' }, svg('path', { d: ICON[k] }));

// one card per rail group, phrased as the question it answers; a group shows when the member can open something in it
const WAYS = [
  { icon: 'radar', group: 'WATCH', q: 'Is anything getting worse, and who can get in?', desc: 'Radar ranks accounts by how much they never use; Space plays a day of calls; Trust lists every way in.',
    pages: [['Radar', '#/radar', 'view'], ['Space', '#/space', 'view'], ['Trust', '#/trust', 'view']] },
  { icon: 'identities', group: 'INVESTIGATE', q: 'Who is this role, and what did it do?', desc: 'Look up any role, IAM user or key, and read every call it made in the lookback.',
    pages: [['Events', '#/events', 'view'], ['Identities', '#/identities', 'view']] },
  { icon: 'findings', group: 'REVIEW', q: 'What needs a decision from me?', desc: 'Decide findings in bulk, approve least-privilege drafts, sign off periodic access reviews.',
    pages: [['Findings', '#/findings', 'view'], ['Access reviews', '#/reviews', 'view']] },
  { icon: 'accounts', group: 'ADMIN', q: 'Is the app healthy and set up right?', desc: 'Connect accounts, watch scans and workers, manage members, single sign-on and alerts.',
    pages: [['Accounts', '#/accounts', 'view'], ['Operations', '#/operations/scans', 'ops'], ['Admin', '#/admin/members', ['members', 'audit', 'settings']]] },
];
const allowed = (perm) => [].concat(perm).some(can);

function greeting() {
  const hr = Number(fmtClock(new Date()).slice(0, 2));      // in the time zone the app shows times in
  const first = (session.user.name || '').split(/[\s.@_-]+/)[0];
  return `${hr < 5 ? 'Good evening' : hr < 12 ? 'Good morning' : hr < 18 ? 'Good afternoon' : 'Good evening'}${first ? `, ${first}` : ''}`;
}

const segments = (done, total) => h('span', { class: 'home-segs', 'aria-hidden': 'true' }, Array.from({ length: total }, (_, i) => h('span', { class: i < done ? 'on' : null })));

export async function homePage(ctx) {
  ctx.setCrumbs('Home');
  const wall = wallMode(ctx);
  if (wall.on) return wallPage(ctx, wall);
  const [d, unread] = await Promise.all([get('/home'), get('/changes/unread').catch(() => ({ count: 0, items: [] }))]);
  const page = h('div', { class: 'stack-lg home' });
  let showAll = false, checklistOpen = false;

  const draw = (data, feed) => {
    const out = [];
    out.push(head(data, wall));
    if (data.state === 'reading') out.push(provisional(data));
    if (data.state === 'first-run') { page.replaceChildren(...out, firstRun(data)); return; }
    if (!data.setup.hidden && data.setup.done < data.setup.total) out.push(setupStrip(data));
    if (checklistOpen) out.push(checklist(data));
    const left = data.evidence ? evidenceCard(data.evidence) : doFirst(data);
    const right = [queueCard(data), data.state === 'reading' ? readingCard(data) : null, feedCard(feed)];
    out.push(h('div', { class: 'home-cols' }, h('div', { class: 'home-main' }, left), h('div', { class: 'home-side' }, right)));
    out.push(h('div', { class: 'row', style: 'justify-content:space-between' }, h('span', { class: 'eyebrow' }, 'The estate at a glance'), h('a', { class: 'small', href: '#/radar' }, 'Open Radar')));
    out.push(estate(data));
    out.push(h('span', { class: 'eyebrow' }, 'Where things are'));
    out.push(ways());
    page.replaceChildren(...out);
  };

  // ----- do this first -----
  function doFirst(data) {
    const list = data.actions;
    const shown = showAll ? list : list.slice(0, SHOWN);
    const more = list.length - shown.length;
    const sub = list.length ? 'Most urgent first. Each one opens the page that does it.' : 'Nothing is waiting for you.';
    return h('section', { class: 'card home-todo', 'aria-labelledby': 'home-todo-h' },
      h('div', { class: 'card-h' }, h('div', null, h('h2', { id: 'home-todo-h' }, 'Do this first'), h('p', { class: 'small muted', style: 'margin:2px 0 0' }, sub)),
        data.snoozed ? h('button', { class: 'btn sm', onClick: async () => { await api('DELETE', '/home/snooze'); reload(); } }, `Show ${data.snoozed} put off`) : null),
      list.length ? h('ol', { class: 'home-list' }, shown.map((a, i) => actionRow(a, i))) : h('div', { class: 'empty' }, 'All clear. New findings, drafts and reviews will show up here.'),
      more > 0 ? h('div', { class: 'card-f' }, h('button', { class: 'btn sm', onClick: () => { showAll = true; draw(state.d, state.feed); } }, `Show ${more} more`)) : null);
  }
  function actionRow(a, i) {
    const first = i === 0;
    const notNow = h('button', { class: 'btn sm home-later', type: 'button', title: a.tier === 'setup' ? 'Hide this for 30 days' : 'Hide this for 7 days', onClick: async () => {
      try { const r = await post('/home/snooze', { key: a.key }); toast(`Hidden for ${r.days} days`); reload(); } catch (e) { toast(e.message, true); }
    } }, 'Not now');
    return h('li', { class: `home-item${first ? ' first' : ''}` },
      h('span', { class: 'home-num', 'aria-hidden': 'true' }, String(i + 1)),
      h('div', { class: 'home-body' },
        h('div', { class: 'row', style: 'gap:6px' }, h('span', { class: `home-tag t-${a.tier}` }, TIER_TAG[a.tier])),
        h('h3', null, a.title), h('p', null, a.why), a.meta ? h('span', { class: 'mono tiny faint' }, a.meta) : null),
      h('div', { class: 'home-acts' }, h('a', { class: `btn${first ? ' primary' : ''}`, href: a.href }, a.cta), notNow));
  }

  // ----- right column -----
  function queueCard(data) {
    const q = data.queue, rows = [
      [session.user.team ? 'Findings for your team' : 'Findings waiting', q.findingsMine, session.user.team ? '#/findings?mine=1' : '#/findings', 'bad', can('view')],
      ['Drafts waiting for your approval', q.drafts, '#/findings?state=drafts&mine=1', 'warn', can('approve') && session.user.team],
      ['Access reviews to sign off', q.reviewsToSign, '#/reviews', 'warn', can('approve') && session.user.team],
      ['Calls not yet identified', q.unidentified, '#/unidentified', null, can('view')],
      ['Failed scans, last 24 hours', q.failedScans, '#/operations/scans', 'bad', can('ops')],
    ].filter((r) => r[4]);
    return h('section', { class: 'card' },
      h('div', { class: 'card-h' }, h('h2', null, 'Your queue'), session.user.team ? h('span', { class: 'mono tiny faint' }, (TEAM[session.user.team] || '').toUpperCase()) : null),
      h('div', { class: 'home-queue' }, rows.map(([label, n, href, tone]) => h('a', { href }, h('span', null, label), h('b', { class: n ? `q-${tone || 'ink'}` : 'q-ok' }, num(n))))));
  }
  function feedCard(feed) {
    return h('section', { class: 'card' },
      h('div', { class: 'card-h' }, h('h2', null, 'Since you last looked'), h('a', { class: 'small', href: '#/radar?feed=30' }, 'Open the feed on Radar')),
      h('div', { class: 'card-b stack', style: 'gap:6px' },
        feed.items.length ? feed.items.slice(0, 5).map((c) => changeRow(c, () => go(c.role_id ? `#/identities/${c.role_id}?tab=history` : `#/radar?view=account&account=${c.account_id}`)))
          : h('p', { class: 'small muted', style: 'margin:0' }, 'Nothing new since you last looked.'),
        feed.count > 5 ? h('p', { class: 'tiny muted', style: 'margin:4px 0 0' }, `${num(feed.count - 5)} more on Radar.`) : null));
  }
  function readingCard(data) {
    return h('section', { class: 'card' },
      h('div', { class: 'card-h' }, h('h2', null, 'Reading CloudTrail history'), h('span', { class: 'mono tiny faint' }, `${data.accounts.complete} OF ${data.accounts.total} COMPLETE`)),
      h('div', { class: 'home-progress' }, data.accounts.reading.map((a) => h('div', null,
        h('span', { class: 'small' }, a.name), h('span', { class: 'home-bar', role: 'progressbar', 'aria-label': `${a.name}: history read`, 'aria-valuenow': a.progress, 'aria-valuemin': 0, 'aria-valuemax': 100 },
          h('span', { style: `width:${a.progress}%` })), h('span', { class: 'mono tiny muted' }, `${a.progress}%`)))),
      h('div', { class: 'card-f small muted' }, 'Each account’s history is read once. After that, scans pick up only new events, in minutes.'));
  }
  function evidenceCard(ev) {
    return h('section', { class: 'card' },
      h('div', { class: 'card-h' }, h('div', null, h('h2', null, 'Evidence'), h('p', { class: 'small muted', style: 'margin:2px 0 0' }, 'What an audit asks for, and where it is.'))),
      h('div', { class: 'home-queue' },
        h('a', { href: ev.latestSigned ? `#/reviews/${ev.latestSigned.id}` : '#/reviews' }, h('span', null, ev.latestSigned ? `Latest signed review: ${ev.latestSigned.name}` : 'No signed access review yet'),
          h('b', { class: 'q-ink' }, ev.latestSigned ? ago(ev.latestSigned.signedAt) : '—')),
        h('a', { href: '#/reviews' }, h('span', null, 'Reviews still open'), h('b', { class: 'q-ink' }, num(ev.open))),
        can('audit') ? h('a', { href: '#/admin/audit' }, h('span', null, 'Audit log: every decision, approval and change'), h('b', { class: 'q-ink' }, '→')) : null));
  }

  // ----- setup -----
  function setupStrip(data) {
    const s = data.setup, missing = s.steps.find((x) => !x.done);
    return h('div', { class: 'home-strip' },
      h('span', { class: 'mono tiny', style: 'letter-spacing:.1em' }, `SETUP ${s.done} OF ${s.total}`), segments(s.done, s.total),
      h('span', { class: 'small muted grow' }, missing ? `Next: ${missing.title.toLowerCase()}.` : ''),
      h('button', { class: 'btn sm', 'aria-expanded': String(checklistOpen), onClick: () => { checklistOpen = !checklistOpen; draw(state.d, state.feed); } }, checklistOpen ? 'Hide the checklist' : 'See the checklist'),
      h('button', { class: 'btn sm', title: 'Hide the setup checklist', 'aria-label': 'Hide the setup checklist', onClick: async () => { await post('/home/setup', { hidden: true }); reload(); } }, '×'));
  }
  function checklist(data, { big = false } = {}) {
    const firstOpen = data.setup.steps.findIndex((x) => !x.done);
    return h('section', { class: 'card' },
      h('div', { class: 'card-h' }, h('div', null, h('h2', null, 'Set up, in order'), h('p', { class: 'small muted', style: 'margin:2px 0 0' }, `${data.setup.done} of ${data.setup.total} done. Steps you cannot do yourself say who can.`)),
        segments(data.setup.done, data.setup.total)),
      h('ol', { class: 'home-list' }, data.setup.steps.map((st, i) => {
        const now = i === firstOpen;
        return h('li', { class: `home-item${now ? ' first' : ''}${st.done ? ' done' : ''}` },
          h('span', { class: 'home-num', 'aria-hidden': 'true' }, st.done ? icon('check', 16, 2.4) : String(i + 1)),
          h('div', { class: 'home-body' }, h('h3', null, st.title, st.done ? h('span', { class: 'sr-only' }, ' (done)') : null),
            !st.canDo && !st.done && st.key !== 'history' ? h('p', null, WHO[st.key] || 'An owner or admin does this.') : big ? h('p', null, STEP_WHY[st.key]) : null),
          !st.done && st.canDo && st.key !== 'history' && !(st.key === 'decide' && data.state === 'first-run') ? h('div', { class: 'home-acts' }, h('a', { class: `btn${now ? ' primary' : ''}`, href: st.href }, STEP_CTA[st.key])) : null);
      })));
  }
  function firstRun(data) {
    const left = checklist(data, { big: true });
    const promise = h('section', { class: 'card' }, h('div', { class: 'card-h' }, h('h2', null, 'What you’ll get')),
      ...[['Who used each role', 'Every caller, session and source over the lookback.'], ['What it never used', 'Each permission granted, used, unused, or not provable from history.'],
        ['A smaller policy, drafted', 'A least-privilege draft with safety checks, approved by your review teams.']]
        .map(([t, s], i) => h('div', { class: 'home-promise' }, h('span', { class: 'mono small fresh' }, `0${i + 1}`), h('div', null, h('b', null, t), h('p', { class: 'small muted', style: 'margin:2px 0 0' }, s)))));
    return h('div', { class: 'stack-lg' }, h('div', { class: 'home-cols' }, h('div', { class: 'home-main' }, left), h('div', { class: 'home-side' }, promise)),
      h('span', { class: 'eyebrow' }, 'Where things will be'), ways());
  }

  const state = { d, feed: unread };
  async function reload() {
    try { const [nd, nf] = await Promise.all([get('/home'), get('/changes/unread').catch(() => state.feed)]); state.d = nd; state.feed = nf; draw(nd, nf); } catch { /* keep what is shown */ }
  }
  ctx.onLeave(poll(reload, 120_000));        // every two minutes while the tab is visible
  draw(d, unread);
  return page;
}

const STEP_CTA = { accounts: 'Connect an account', team: 'Invite', sso: 'Set up SSO', alerts: 'Set up alerts', decide: 'Open findings' };
const STEP_WHY = {
  accounts: 'A read-only role in the account, or the organisation’s CloudTrail bucket for many accounts at once. The page writes the policy for you.',
  history: 'Up to 90 days of CloudTrail, read in the background. You can look around while it runs; findings are previews until it finishes.',
  team: 'Reviewers belong to Infrastructure Security or Information Security; that decides who signs off which roles.',
  sso: 'OIDC from your identity provider, with its groups mapped to roles here.',
  alerts: 'A rule per channel, and a daily list of what to do first if you want one.',
  decide: 'Once history is read: keep, scope or remove what each role was given but never used.',
};
const WHO = { accounts: 'Waiting for an owner or admin to connect an account.', team: 'An owner or admin invites members.', sso: 'An owner turns this on.', alerts: 'An owner or admin sets up alerts.', decide: 'Reviewers, admins and owners decide findings.' };

function head(data, wall) {
  const n = data.actions?.length || 0;
  const sub = data.state === 'first-run' ? 'A monkey only needs the banana. Six steps to find out which bananas your roles actually eat; the first takes about ten minutes.'
    : data.state === 'reading' ? 'While history is read, here is what you can do now. Nothing at the top waits on the scan.'
      : data.evidence ? 'Where the evidence is, and what changed.'
        : n ? `${n} ${n === 1 ? 'thing is' : 'things are'} waiting for you, most urgent first.` : 'Nothing is waiting for you.';
  const a = data.accounts;
  return h('header', { class: 'head' },
    h('div', null, h('span', { class: 'eyebrow' }, data.state === 'first-run' ? 'HOME · FIRST RUN' : 'HOME'),
      h('h1', null, data.state === 'first-run' ? 'Welcome to Curious Monkey' : greeting()), h('p', { class: 'muted', style: 'margin:0;max-width:680px' }, sub)),
    h('div', { class: 'home-fresh' },
      h('span', { class: 'mono tiny muted' }, a.total ? `${num(a.total)} ${a.total === 1 ? 'ACCOUNT' : 'ACCOUNTS'} · ${a.complete === a.total ? 'HISTORY COMPLETE' : `${a.complete} OF ${a.total} COMPLETE`}` : 'NO ACCOUNTS YET'),
      data.state !== 'first-run' ? wall.button : null));
}
function provisional(data) {
  const r = data.accounts.reading.length;
  return h('div', { class: 'provisional', role: 'status' }, h('b', null, 'PROVISIONAL'),
    h('span', { class: 'grow' }, `History is still being read for ${r} of ${data.accounts.total} ${data.accounts.total === 1 ? 'account' : 'accounts'}. Findings there are previews; approvals and access reviews open when each account finishes.`),
    h('a', { class: 'small', href: '#/operations/scans' }, 'Watch the scans'));
}
function estate(data) {
  const e = data.estate, f = e.findings, open = f.high + f.medium + f.low;
  const pct = (v) => (v == null ? '—' : `${Math.round(v * 100)}%`);
  const move = e.never30 == null ? 'no 30-day history yet' : Math.abs(e.never30) < 0.005 ? 'flat over 30 days' : `${e.never30 < 0 ? '▼' : '▲'} ${Math.abs(Math.round(e.never30 * 100))} ${Math.abs(Math.round(e.never30 * 100)) === 1 ? 'point' : 'points'} in 30 days`;
  const t = (label, value, sub, href, tone) => h('a', { class: `tile home-tile${tone ? ` tone-${tone}` : ''}`, href }, h('span', { class: 'small muted' }, label), h('b', null, value), h('span', { class: 'tiny muted' }, sub));
  return h('div', { class: 'tiles' },
    t('Accounts', num(data.accounts.total), data.accounts.complete === data.accounts.total ? 'all history read' : `${data.accounts.reading.length} still reading`, '#/accounts'),
    t('Identities', num(e.identities.roles + e.identities.users), `${num(e.identities.roles)} roles · ${num(e.identities.users)} IAM users`, '#/identities'),
    t('Open findings', num(open), `${num(f.high)} high · ${num(f.medium)} medium · ${num(f.low)} low`, '#/findings', f.high ? 'bad' : null),
    t('Never called, median role', pct(e.never), move, '#/radar', e.never30 != null && e.never30 < -0.005 ? 'good' : e.never30 > 0.005 ? 'warn' : null),
    t(`Keys over ${e.rotateDays} days`, num(e.keys.old), `of ${num(e.keys.active)} active access keys`, '#/identities?type=users&flag=oldKey', e.keys.old ? 'warn' : null));
}
function ways() {
  return h('div', { class: 'home-ways' }, WAYS.map((w) => {
    const pages = w.pages.filter(([, , p]) => allowed(p));
    if (!pages.length) return null;
    return h('div', { class: 'home-way' },
      h('div', { class: 'row', style: 'gap:8px' }, h('span', { class: 'fresh', style: 'display:flex' }, icon(w.icon)), h('span', { class: 'eyebrow' }, w.group)),
      h('b', null, w.q), h('p', { class: 'small muted' }, w.desc),
      h('div', { class: 'row', style: 'gap:6px;margin-top:auto' }, pages.map(([l, href]) => h('a', { class: 'btn sm', href }, l))));
  }));
}

// ---------- the wall view: the team's list, large, for a screen nobody sits at ----------
async function wallPage(ctx, wall) {
  const [d, feed] = await Promise.all([get('/home?wall=1'), get('/changes?days=1').catch(() => ({ items: [], total: 0 }))]);
  const clock = h('span', { class: 'home-clock mono' });
  const tick = () => { clock.textContent = fmtClock(new Date()); };
  tick(); const t = setInterval(tick, 15_000); ctx.onLeave(() => clearInterval(t));
  const team = d.team ? TEAM[d.team] : 'Everyone';
  return h('div', { class: 'home-wall' },
    h('header', { class: 'row', style: 'justify-content:space-between;align-items:flex-end' },
      h('div', null, h('span', { class: 'eyebrow' }, `WAITING ON THE TEAM · ${team.toUpperCase()}`), h('h1', null, d.actions.length ? `${d.actions.length} ${d.actions.length === 1 ? 'thing' : 'things'} waiting` : 'Nothing waiting')),
      h('div', { class: 'stack', style: 'align-items:flex-end;gap:4px' }, clock, h('span', { class: 'mono tiny muted' }, `AS OF ${fmtDate(new Date())}`), wall.button)),
    d.state === 'reading' ? provisional(d) : null,
    h('div', { class: 'home-cols' },
      h('ol', { class: 'home-list home-main wall' }, d.actions.slice(0, 8).map((a, i) => h('li', { class: `home-item${i === 0 ? ' first' : ''}` },
        h('span', { class: 'home-num' }, String(i + 1)),
        h('div', { class: 'home-body' }, h('span', { class: `home-tag t-${a.tier}` }, TIER_TAG[a.tier]), h('h3', null, a.title), a.meta ? h('span', { class: 'mono small faint' }, a.meta) : null)))),
      h('div', { class: 'home-side' }, h('section', { class: 'card' }, h('div', { class: 'card-h' }, h('h2', null, 'Last 24 hours'), h('span', { class: 'mono tiny faint' }, `${num(feed.total)} CHANGES`)),
        h('div', { class: 'card-b stack', style: 'gap:6px' }, feed.items.length ? feed.items.slice(0, 8).map((c) => changeRow({ ...c, unread: false }, null)) : h('p', { class: 'muted', style: 'margin:0' }, 'Nothing changed.'))))),
    estate(d));
}
