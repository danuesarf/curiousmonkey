import { h, svg, get, num, fmtDate, fmtDay, ago, riskBadge, teamBadge, usageBar, copy, modal, KIND, searchBox, pager, tile } from '../lib.js';
import { session } from '../main.js';
import { identifyControls, eventFacts, STATE } from './unidentified.js';
import { findingCard } from './findings.js';

export async function rolePage(ctx, id) {
  const d = await get(`/roles/${id}`);
  const r = d.role;
  let tab = 'who';
  const panel = h('div', { class: 'stack-lg' });
  const tabs = h('div', { class: 'tabs', role: 'tablist' });
  const TABS = [['who', 'Who used it'], ['findings', `Findings (${d.flags.length})`], ['perms', 'Permissions'], ['policies', 'Policies and trust']];
  const show = (t) => {
    tab = t;
    tabs.replaceChildren(...TABS.map(([k, l]) => h('button', { role: 'tab', 'aria-selected': k === tab, onClick: () => show(k) }, l)));
    const render = { who: () => whoTab(d), findings: () => findingsTab(d, ctx, openIdentify), perms: () => permsTab(d), policies: () => policiesTab(d) };
    panel.replaceChildren((Object.hasOwn(render, t) ? render[t] : render.who)());
  };
  const openIdentify = (raw) => identifyPanel(r, raw, ctx);
  show(ctx.params.get('tab') === 'findings' ? 'findings' : 'who');
  ctx.setCrumbs(h('a', { href: '#/roles' }, 'Roles'), r.account_name, r.name);
  if (ctx.params.has('identify')) setTimeout(() => openIdentify(ctx.params.get('identify') || null));
  const hist = d.history || { complete: true };
  const unmappedFlag = d.flags.find((f) => f.category === 'unmapped-event');

  const canRec = session.user.permissions.includes('recommend') && r.kind !== 'service-linked';
  return h('div', { class: 'stack-lg' },
    h('header', { class: 'head' },
      h('div', null, h('div', { class: 'eyebrow' }, `ROLE · ${r.account_name}`),
        h('h1', null, r.name), h('div', { class: 'row' }, riskBadge(r.risk), h('span', { class: 'badge b-neutral' }, KIND[r.kind]), teamBadge(r.reviewer_team, r.requires_both),
          h('span', { class: 'small muted mono' }, r.arn))),
      h('div', { class: 'actions' },
        h('a', { class: 'btn', href: `#/roles/${r.id}/scan` }, 'Sector scan'), h('a', { class: 'btn', href: `#/track?role=${r.id}` }, 'Track a session'),
        r.kind === 'service-linked' ? h('span', { class: 'alert warn small' }, 'Service-linked: managed by AWS. Report only.')
          : canRec && h('a', { class: 'btn primary', href: `#/roles/${r.id}/recommendation` }, 'Recommend least-privilege policy'))),
    !hist.complete && h('div', { class: 'provisional' }, h('b', null, `PROVISIONAL · ${hist.progress}% OF HISTORY READ`),
      h('span', null, `Used counts are “at least” and never-called counts “at most” until the rest of CloudTrail history is read${hist.readUpTo ? ` (read back to ${fmtDay(hist.backTo || hist.readUpTo)})` : ''}. Approval waits for it.`)),
    unmappedFlag && h('div', { class: 'unk-box' }, h('div', { class: 'row' }, h('span', { class: 'unk-tag' }, 'UNK'),
      h('span', { class: 'grow small' }, 'Some calls by this role use event names that are not identified yet. Those services stay unconfirmed — nothing in them will be removed until each name is settled.'),
      h('button', { class: 'btn sm amber', onClick: () => openIdentify(null) }, 'Identify'))),
    r.kind === 'iam-user' && h('div', { class: 'alert' }, 'This is an IAM user. Its access keys, console sign-in and MFA are on ', h('a', { href: `#/users/${r.id}` }, 'its IAM user page'), '.'),
    r.kind === 'identity-center' && h('div', { class: 'alert warn' }, `This role comes from the Identity Center permission set "${r.permission_set}". Changes belong in the permission set, not on the role.`),
    h('section', { class: 'tiles' },
      tile('Granted', num(r.granted_count), `${r.inline_count} inline, ${r.attached_count} attached`),
      tile('Used', `${hist.complete ? '' : '≥ '}${num(r.used_count)}`, 'seen in event history'), tile('Unused', `${hist.complete ? '' : '≤ '}${num(r.unused_count)}`, 'no evidence of use'), tile('Cannot be verified', num(r.unconfirmed_count), 'event history cannot prove'),
      tile('Last activity', r.last_activity_at ? ago(r.last_activity_at) : 'none', `IAM last used: ${r.last_used_at ? ago(r.last_used_at) : 'never'}`)),
    h('div', { class: 'card' }, h('div', { class: 'card-b stack' }, h('h3', null, 'Why this risk level'),
      r.risk_reasons.length ? h('ul', { class: 'plain' }, r.risk_reasons.map((x) => h('li', null, x))) : h('p', { class: 'muted' }, 'Nothing stands out.'),
      d.window?.first && h('p', { class: 'small muted' }, `Evidence window: ${fmtDay(d.window.first)} to ${fmtDay(d.window.last)}. Anything older is invisible to this tool.`))),
    gcpCard(r.id),
    tabs, panel);
}
/** Where this role reaches into Google Cloud, or which Google service accounts can become it. Filled in when known. */
function gcpCard(roleId) {
  const box = h('div');
  get(`/gcp/aws-role/${roleId}`).then((x) => {
    if (!x.into.length && !x.from.length) return;
    const li = (label, meta, href, bad) => h('li', null, h('a', { href }, label), h('span', { class: 'small muted' }, ` · ${meta}`), bad ? h('span', { class: 'badge b-high', style: 'margin-left:6px' }, 'any role in the account') : null);
    box.replaceChildren(h('section', { class: 'card' }, h('div', { class: 'card-b stack' }, h('h3', null, 'Across clouds · Google Cloud'),
      x.into.length > 0 && h('div', null, h('p', { class: 'small muted' }, 'Through workload identity federation, this role can act in Google Cloud as:'),
        h('ul', { class: 'plain stack', style: 'gap:4px' }, x.into.map((l) => li(l.gcpEmail || `${l.grant} on ${l.gcpProject}`, `${l.gcpProject} · pool ${l.pool}${l.awsRole ? '' : ' (open to the whole AWS account)'}`, `#/gcp/principals/${l.gcpPrincipal}`, l.broad)))),
      x.from.length > 0 && h('div', null, h('p', { class: 'small muted' }, 'Its trust policy lets these Google service accounts in:'),
        h('ul', { class: 'plain stack', style: 'gap:4px' }, x.from.map((l) => li(l.gcpEmail || `unknown service account ${l.uniqueId}`, `${l.gcpProject || 'not in a connected organization'} · statement ${l.statement + 1}`, l.gcpPrincipal ? `#/gcp/principals/${l.gcpPrincipal}` : `#/trust?q=${encodeURIComponent('provider:google')}`)))))));
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

function whoTab(d) {
  return h('div', { class: 'stack-lg' },
    h('section', { class: 'card' }, h('div', { class: 'card-h' }, h('h2', null, 'Activity, last 90 days'), h('span', { class: 'small muted' }, 'Red bars include calls AWS denied. Denied calls are not counted as use.')),
      h('div', { class: 'card-b' }, d.daily.length ? chart(d.daily) : h('p', { class: 'muted' }, 'No calls were seen in the window.'))),
    h('section', { class: 'card', id: 'principals' }, h('div', { class: 'card-h' }, h('h2', null, 'Who assumed this role')),
      d.principals.length ? h('div', { class: 'stack', style: null }, d.principals.map(principalCard)) : h('div', { class: 'empty' }, 'Nobody assumed this role in the window.')),
    d.passRoles.length > 0 && h('section', { class: 'card' }, h('div', { class: 'card-h' }, h('h2', null, 'Roles this role passed to services'), h('span', { class: 'small muted' }, 'Inferred from request parameters. CloudTrail does not log iam:PassRole itself.')),
      h('div', { class: 'scroll' }, h('table', null, h('thead', null, h('tr', null, h('th', null, 'Passed role'), h('th', null, 'Service'), h('th', null, 'Times'), h('th', null, 'Last seen'))),
        h('tbody', null, d.passRoles.map((p) => h('tr', null, h('td', { class: 'mono small' }, p.passed_role_arn), h('td', null, p.service), h('td', null, num(p.count)), h('td', { class: 'small' }, ago(p.last_seen))))))))
  );
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

function findingsTab(d, ctx, openIdentify) {
  if (!d.flags.length) return h('div', { class: 'empty card' }, 'No open findings.');
  // a decision updates its card in place; the rest of the page stays as it is
  const waiting = h('span', { class: 'small muted' });
  const count = () => { const n = d.flags.filter((f) => !f.decision).length; waiting.textContent = n ? `${n} of ${d.flags.length} waiting for a decision` : 'Every finding has a decision.'; };
  count();
  return h('div', { class: 'stack', id: 'flags' },
    h('div', { class: 'row' }, waiting, h('span', { class: 'grow' }), h('a', { class: 'small', href: '#/findings' }, 'Findings on every role →')),
    d.flags.map((f) => findingCard(f, { onIdentify: openIdentify, onDecided: () => { count(); ctx.refreshStatus(); } })));
}

function permsTab(d) {
  const list = h('div'); const st = { status: '', service: '', q: '', page: 1 };
  const id = d.role.id;
  const load = async () => {
    const p = new URLSearchParams({ page: st.page, limit: 100 }); for (const k of ['status', 'service', 'q']) if (st[k]) p.set(k, st[k]);
    const r = await get(`/roles/${id}/actions?${p}`);
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
  return h('div', { class: 'stack-lg' },
    h('section', { class: 'card' }, h('div', { class: 'card-h' }, h('h2', null, 'By service')),
      h('div', { class: 'scroll' }, h('table', null, h('thead', null, h('tr', null, h('th', null, 'Service'), h('th', null, 'Mix'), h('th', null, 'Used'), h('th', null, 'Unused'), h('th', null, 'Unverifiable'), h('th', null, 'Advisor last used'))),
        h('tbody', null, d.services.slice(0, 60).map((s) => { const adv = d.advisor.find((a) => a.service === s.service);
          return h('tr', { class: 'link', onClick: () => { st.service = s.service; st.page = 1; load(); window.scrollTo(0, document.body.scrollHeight); } }, h('td', { class: 'mono small' }, s.service), h('td', null, usageBar(s.used, s.unused, s.unconfirmed)),
            h('td', null, s.used), h('td', null, s.unused), h('td', null, s.unconfirmed), h('td', { class: 'small' }, adv ? (adv.last_authenticated ? fmtDay(adv.last_authenticated) : 'never') : '—')); }))))),
    h('section', { class: 'card' }, h('div', { class: 'filters' }, q, status, h('button', { class: 'btn sm', onClick: () => { st.service = ''; load(); } }, 'All services')), list));
}

function policiesTab(d) {
  return h('div', { class: 'stack-lg' },
    d.policies.map((p) => h('section', { class: 'card' }, h('div', { class: 'card-h' }, h('h2', null, p.name), h('div', { class: 'row' }, h('span', { class: 'badge b-neutral' }, p.kind), p.aws_managed && h('span', { class: 'badge b-banana' }, 'AWS managed'),
      h('button', { class: 'btn sm', onClick: () => copy(JSON.stringify(p.document, null, 2)) }, 'Copy'))), h('div', { class: 'card-b' }, h('pre', null, JSON.stringify(p.document, null, 2))))),
    h('section', { class: 'card' }, h('div', { class: 'card-h' }, h('h2', null, 'Trust policy'), h('span', { class: 'small muted' }, 'Who is allowed to assume this role')),
      h('div', { class: 'card-b' }, h('pre', null, JSON.stringify(d.role.trust_policy, null, 2)))));
}

/** Side panel: settle the unidentified event names this role called, without leaving the role. */
async function identifyPanel(r, raw, ctx) {
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
