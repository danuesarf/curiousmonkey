// Event history: search the calls kept per role session. Every filter lives in the URL, so a search can be linked to.
import { h, get, copy, ago } from '../lib.js';
import { go } from '../main.js';

const RANGES = [['1h', 'Last hour'], ['24h', 'Last 24 hours'], ['7d', 'Last 7 days'], ['30d', 'Last 30 days']];
const OUTCOMES = [['all', 'Allowed and denied'], ['denied', 'Denied only'], ['allowed', 'Allowed only']];
const time = (t) => new Date(t).toLocaleString('en-GB', { day: '2-digit', month: 'short', hour: '2-digit', minute: '2-digit', second: '2-digit', timeZone: 'Asia/Jakarta' });
const SYNTAX = [['role:deploy', 'role name'], ['user:alice', 'session name or caller'], ['ip:10.0.', 'source IP'], ['action:s3:Get', 'IAM action or event'], ['resource:acme-reports', 'resource ARN'],
  ['error:AccessDenied', 'error code'], ['id:…', 'CloudTrail event ID'], ['-action:Describe', 'leave out']];

export async function eventsPage(ctx) {
  const P = ctx.params, f = { q: P.get('q') || '', account: P.get('account') || '', role: P.get('role') || '', session: P.get('session') || '', outcome: P.get('outcome') || 'all', range: P.get('range') || '24h' };
  const qs = (extra = {}) => { const s = new URLSearchParams(); for (const [k, v] of Object.entries({ ...f, ...extra })) if (v && !(k === 'outcome' && v === 'all')) s.set(k, v); return s.toString(); };
  const searchFor = (patch) => go(`#/events?${qs(patch)}`);
  ctx.setCrumbs('Events');
  // nothing waits: the page opens at once, the first 20 calls fill in, the account list fills in when it arrives
  const FIRST = 20, PAGE = 50;
  const firstP = get(`/events?${qs({ limit: FIRST })}`);

  // ---------- the search ----------
  const q = h('input', { type: 'search', value: f.q, class: 'mono', 'aria-label': 'Search calls', placeholder: 'Search: words, or role:, user:, ip:, action:, resource:, error:' });
  const select = (name, options, cur, label) => h('select', { 'aria-label': label, 'data-name': name }, options.map(([v, l]) => h('option', { value: v, selected: v === cur }, l)));
  const acct = select('account', [['', 'All accounts'], ...(f.account ? [[f.account, 'This account']] : [])], f.account, 'Account');
  get('/accounts').then(({ items }) => {
    acct.replaceChildren(...[['', 'All accounts'], ...items.filter((a) => a.status !== 'planned').map((a) => [a.id, `${a.name} · ${a.account_id}`])]
      .map(([v, l]) => h('option', { value: v, selected: v === f.account }, l)));
  }, () => {});
  const outcome = select('outcome', OUTCOMES, f.outcome, 'Result');
  const range = select('range', RANGES, f.range, 'Time range');
  const form = h('form', { class: 'ev-form', role: 'search', onSubmit: (e) => { e.preventDefault(); searchFor({ q: q.value.trim(), account: acct.value, outcome: outcome.value, range: range.value }); } },
    q, acct, outcome, range, h('button', { class: 'btn primary', type: 'submit' }, 'Search'));
  for (const s of [acct, outcome, range]) s.addEventListener('change', () => form.requestSubmit());
  const syntax = h('div', { class: 'ev-syntax' }, ...SYNTAX.map(([k, d]) => h('button', { type: 'button', class: 'chip', title: d, onClick: () => { q.value = `${q.value.trim()} ${k.endsWith('…') ? 'id:' : k}`.trim(); q.focus(); } }, k)));
  const chipsRow = h('div', { class: 'row' });
  const drawChips = (first) => chipsRow.replaceChildren(...[
    f.role && h('span', { class: 'chip ev-on' }, `Role: ${first?.items[0]?.role_name || 'one role'}`, h('a', { href: `#/events?${qs({ role: '' })}`, 'aria-label': 'Remove the role filter' }, ' ×')),
    f.session && h('span', { class: 'chip ev-on' }, `Session: ${first?.items[0]?.session_name || 'one session'}`, h('a', { href: `#/events?${qs({ session: '' })}`, 'aria-label': 'Remove the session filter' }, ' ×')),
  ].filter(Boolean));
  drawChips(null);

  // ---------- results ----------
  const body = h('tbody');
  const status = h('p', { class: 'small muted', 'aria-live': 'polite' });
  const more = h('button', { class: 'btn' }, 'Load older');
  let next = null, count = 0, loading = false;
  const detail = (x) => {
    const kv = (k, v) => v ? [h('dt', null, k), h('dd', null, v)] : [];
    return h('tr', { class: 'ev-detail' }, h('td', { colspan: 8 }, h('div', { class: 'ev-detail-body' },
      h('dl', { class: 'kv' },
        ...kv('Event ID', h('span', null, h('span', { class: 'mono small' }, x.event_id), ' ', h('button', { class: 'link-btn small', onClick: () => copy(x.event_id) }, 'Copy'))),
        ...kv('Event', h('span', { class: 'mono small' }, `${x.event_source}:${x.event_name}`)),
        ...kv('IAM action', x.action && h('span', { class: 'mono small' }, x.action)),
        ...kv('Result', x.denied ? h('span', { class: 'ev-bad' }, `Denied · ${x.error_code || 'no error code'}`) : x.error_code ? `Failed · ${x.error_code}` : 'Allowed'),
        ...kv('Resources', x.resources.length ? h('div', { class: 'stack mono small' }, x.resources.map((r) => h('span', { class: 'ev-res' }, r))) : null),
        ...kv('Role', `${x.role_name} · ${x.account_name} (${x.aws_account_id})`),
        ...kv('Session', h('span', { class: 'mono small' }, `${x.session_name || 'unnamed'} · ${x.access_key_id}`)),
        ...kv('Caller', x.caller_arn && h('span', { class: 'mono small' }, x.caller_arn)),
        ...kv('Entered via', [x.via, x.mfa == null ? null : x.mfa ? 'with MFA' : 'without MFA', x.source_identity && `source identity ${x.source_identity}`].filter(Boolean).join(' · ')),
        ...kv('Source IP', x.source_ip && h('span', { class: 'mono small' }, x.source_ip)),
        ...kv('User agent', x.user_agent && h('span', { class: 'mono small ev-ua' }, x.user_agent)),
        ...kv('Started', x.child_key_id && h('span', { class: 'mono small' }, `a new session ${x.child_key_id}`))),
      h('div', { class: 'row' },
        h('a', { class: 'btn sm primary', href: `#/track?role=${x.role_id}&session=${x.session_id}` }, 'Replay this session'),
        h('a', { class: 'btn sm', href: `#/events?${qs({ session: x.session_id, q: '' })}` }, 'Only this session'),
        x.source_ip && h('a', { class: 'btn sm', href: `#/events?${qs({ q: `ip:${x.source_ip}`, session: '' })}` }, 'Same IP'),
        h('a', { class: 'btn sm', href: `#/events?${qs({ q: `action:${x.event_source.split('.')[0]}:${x.event_name}` })}` }, 'Same event'),
        h('a', { class: 'btn sm', href: `#/roles/${x.role_id}` }, 'Open role')))));
  };
  const rowOf = (x) => {
    let open = null;
    const tr = h('tr', { class: `ev-row${x.denied ? ' ev-denied' : ''}`, tabindex: 0, 'aria-expanded': 'false' },
      h('td', { class: 'nowrap small' }, time(x.at)),
      h('td', { class: 'small' }, x.account_name),
      h('td', { class: 'small ev-clip' }, x.role_name),
      h('td', { class: 'small ev-clip', title: x.caller_arn || '' }, x.session_name || '—'),
      h('td', { class: 'mono small' }, `${x.event_source.split('.')[0]}:${x.event_name}`),
      h('td', { class: 'mono small ev-clip', title: x.resources.join('\n') }, x.resources[0] || '—', x.resources.length > 1 ? h('span', { class: 'muted' }, ` +${x.resources.length - 1}`) : null),
      h('td', { class: 'mono small nowrap' }, x.source_ip || '—'),
      h('td', null, x.denied ? h('span', { class: 'badge b-high' }, 'Denied') : x.error_code ? h('span', { class: 'badge b-medium', title: x.error_code }, 'Failed') : h('span', { class: 'muted small' }, 'OK')));
    const toggle = () => { if (open) { open.remove(); open = null; } else { open = detail(x); tr.after(open); } tr.setAttribute('aria-expanded', String(!!open)); };
    tr.addEventListener('click', (e) => { if (!e.target.closest('a,button')) toggle(); });
    tr.addEventListener('keydown', (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); toggle(); } });
    return tr;
  };
  const show = (page) => {
    body.append(...page.items.map(rowOf));
    count += page.items.length; next = page.next;
    more.hidden = !next;
    if (!count && !page.items.length) body.replaceChildren();
    status.textContent = count
      ? `${count.toLocaleString('en-US')} call${count === 1 ? '' : 's'}, newest first. Searched back to ${time(page.searched.from)} WIB${next ? '' : ', the start of the range'}.`
      : `No calls match between ${time(page.range.from)} and ${time(page.range.to)} WIB.`;
  };
  // older calls load by themselves when the end of the list comes into view; the button stays for keyboards and as a fallback
  const loadOlder = async () => {
    if (loading || !next) return;
    loading = true; more.disabled = true; more.textContent = 'Loading…';
    try { show(await get(`/events?${qs({ before: next, limit: PAGE })}`)); }
    catch { status.textContent = 'Could not load older calls. Try again.'; }
    finally { loading = false; more.disabled = false; more.textContent = 'Load older'; topUp(); }
  };
  // the observer only reports changes: if the end of the list is still in view after a page, keep going
  const topUp = () => setTimeout(() => { if (next && sentinel.isConnected && sentinel.getBoundingClientRect().top < innerHeight + 600) loadOlder(); }, 0);
  more.addEventListener('click', loadOlder);
  more.hidden = true;
  const sentinel = h('div', { 'aria-hidden': 'true', style: 'height:1px' });
  const io = new IntersectionObserver((es) => { if (es.some((e) => e.isIntersecting)) loadOlder(); }, { rootMargin: '600px 0px' });
  io.observe(sentinel);
  ctx.onLeave?.(() => io.disconnect());
  status.textContent = 'Loading the newest calls…';
  let retention = 30;
  const intro = h('p', { class: 'muted' });
  const drawIntro = () => { intro.textContent = `Every call your roles made through a session (assumed roles, Identity Center, OIDC, role chaining), kept for ${retention} days. Calls by IAM users with long-term keys and by root are counted for analysis but not kept one by one; the full record stays in your CloudTrail.`; };
  drawIntro();
  firstP.then((first) => { retention = first.retentionDays; drawIntro(); drawChips(first); show(first); topUp(); },
    (e) => { status.textContent = `Could not load calls: ${e.message}`; });

  return h('div', { class: 'stack-lg' },
    h('header', { class: 'head' }, h('div', null, h('div', { class: 'eyebrow' }, 'EVENTS'), h('h1', null, 'Event history'),
      intro),
      h('a', { class: 'btn', href: `/api/events.csv?${qs()}`, download: '' }, 'Download CSV')),
    h('section', { class: 'card' }, h('div', { class: 'card-b stack' }, form, syntax, chipsRow)),
    h('section', { class: 'card' },
      h('div', { class: 'scroll' }, h('table', { class: 'ev-table' },
        h('thead', null, h('tr', null, ...['Time (WIB)', 'Account', 'Role', 'Session', 'Event', 'Resource', 'Source IP', 'Result'].map((t) => h('th', null, t)))), body)),
      sentinel,
      h('div', { class: 'card-f row' }, status, h('span', { class: 'grow' }), more)));
}
