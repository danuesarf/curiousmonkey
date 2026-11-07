import { h, svg, get, post, api, num, fmtDate, fmtDay, ago, riskBadge, teamBadge, usageBar, toast, copy, modal, KIND, TEAM, field } from '../lib.js';
import { session, go } from '../main.js';

const CAT = { 'data-event': 'Data events', 'authorization-only': 'Not logged', 'not-logged': 'Not logged', 'before-window': 'Before window', 'service-unknown': 'Service used', 'unmapped-event': 'Unmapped events', wildcard: 'Wildcard', 'external-principal': 'Unexpected principal', 'trust-wildcard': 'Trust policy', 'role-idle': 'Idle role' };
const ACTION_CATS = new Set(['data-event', 'authorization-only', 'not-logged', 'before-window', 'service-unknown', 'unmapped-event']);

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
    panel.replaceChildren({ who: () => whoTab(d), findings: () => findingsTab(d, ctx), perms: () => permsTab(d), policies: () => policiesTab(d) }[t]());
  };
  show('who');

  const canRec = session.user.permissions.includes('recommend') && r.kind !== 'service-linked';
  return h('div', { class: 'stack-lg' },
    h('header', { class: 'head' },
      h('div', null, h('div', { class: 'crumbs' }, h('a', { href: '#/' }, 'IAM roles'), ' / ', r.account_name),
        h('h1', null, r.name), h('div', { class: 'row' }, riskBadge(r.risk), h('span', { class: 'badge b-neutral' }, KIND[r.kind]), teamBadge(r.reviewer_team, r.requires_both),
          h('span', { class: 'small muted mono' }, r.arn))),
      h('div', { class: 'actions' },
        r.kind === 'service-linked' ? h('span', { class: 'alert warn small' }, 'Service-linked: managed by AWS. Report only.')
          : canRec && h('a', { class: 'btn primary', href: `#/roles/${r.id}/recommendation` }, 'Recommend least-privilege policy'))),
    r.kind === 'identity-center' && h('div', { class: 'alert warn' }, `This role comes from the Identity Center permission set "${r.permission_set}". Changes belong in the permission set, not on the role.`),
    h('section', { class: 'tiles' },
      tile('Granted', num(r.granted_count), `${r.inline_count} inline, ${r.attached_count} attached`),
      tile('Used', num(r.used_count), 'seen in event history'), tile('Unused', num(r.unused_count), 'no evidence of use'), tile('Cannot be verified', num(r.unconfirmed_count), 'event history cannot prove'),
      tile('Last activity', r.last_activity_at ? ago(r.last_activity_at) : 'none', `IAM last used: ${r.last_used_at ? ago(r.last_used_at) : 'never'}`)),
    h('div', { class: 'card' }, h('div', { class: 'card-b stack' }, h('h3', null, 'Why this risk level'),
      r.risk_reasons.length ? h('ul', { class: 'plain' }, r.risk_reasons.map((x) => h('li', null, x))) : h('p', { class: 'muted' }, 'Nothing stands out.'),
      d.window?.first && h('p', { class: 'small muted' }, `Evidence window: ${fmtDay(d.window.first)} to ${fmtDay(d.window.last)}. Anything older is invisible to this tool.`))),
    tabs, panel);
}
const tile = (l, v, s) => h('div', { class: 'tile' }, h('span', { class: 'small muted' }, l), h('b', null, v), h('span', { class: 'tiny muted' }, s));

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

function findingsTab(d, ctx) {
  if (!d.flags.length) return h('div', { class: 'empty card' }, 'No open findings.');
  const canDecide = session.user.permissions.includes('decide');
  return h('div', { class: 'stack', id: 'flags' }, d.flags.map((f) => {
    const isAct = ACTION_CATS.has(f.category);
    const opts = isAct ? [['keep_scoped', 'Keep, scoped'], ['keep', 'Keep as is'], ['remove', 'Remove']] : [['accept', 'Accept'], ['investigate', 'Investigate']];
    const res = h('input', { placeholder: 'Narrow to resources (comma separated ARNs)', value: (f.decided_resources || []).join(', '), 'aria-label': 'Resources to keep' });
    const note = h('input', { placeholder: 'Note for the record', value: f.note || '', 'aria-label': 'Note' });
    const choose = async (decision) => {
      try { await post(`/flags/${f.id}/decision`, { decision, note: note.value || undefined, resources: decision === 'keep_scoped' && res.value ? res.value.split(',').map((s) => s.trim()).filter(Boolean) : undefined });
        toast('Decision saved'); ctx.reload(); } catch (e) { toast(e.message, true); }
    };
    return h('article', { class: `flag ${f.severity}` },
      h('div', { class: 'row' }, h('span', { class: 'badge b-neutral' }, CAT[f.category] || f.category), h('span', { class: `badge b-${f.severity}` }, f.severity), h('h3', null, f.title),
        f.decision && h('span', { class: 'badge b-green' }, `${f.decision.replace('_', ' ')} by ${f.decided_by || 'someone'}`)),
      h('p', null, f.reason), f.evidence && h('p', { class: 'small muted' }, f.evidence),
      f.actions.length > 0 && h('div', { class: 'acts' }, f.actions.slice(0, 40).map((a) => h('code', null, a)), f.actions.length > 40 && h('span', { class: 'small muted' }, `+${f.actions.length - 40} more`)),
      f.resources.length > 0 && h('p', { class: 'small mono muted' }, `Granted on: ${f.resources.slice(0, 4).join(', ')}${f.resources.length > 4 ? '…' : ''}`),
      f.suggestion && h('p', { class: 'small' }, h('b', null, 'Suggestion: '), f.suggestion),
      canDecide && h('div', { class: 'stack' }, isAct && res, note,
        h('div', { class: 'row' }, opts.map(([v, l]) => h('button', { class: `btn sm${f.decision === v ? ' primary' : ''}`, onClick: () => choose(v) }, l)),
          f.decision && h('button', { class: 'btn sm', onClick: async () => { await api('DELETE', `/flags/${f.id}/decision`); ctx.reload(); } }, 'Clear decision'))));
  }));
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
      r.total > 100 && h('div', { class: 'pager' }, h('span', { class: 'small muted' }, `${num(r.total)} actions, page ${st.page}`),
        h('button', { class: 'btn sm', disabled: st.page <= 1, onClick: () => { st.page--; load(); } }, 'Previous'), h('button', { class: 'btn sm', disabled: st.page * 100 >= r.total, onClick: () => { st.page++; load(); } }, 'Next')));
  };
  const q = h('input', { type: 'search', placeholder: 'Search actions', 'aria-label': 'Search actions' }); let t; q.addEventListener('input', () => { clearTimeout(t); t = setTimeout(() => { st.q = q.value; st.page = 1; load(); }, 250); });
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
