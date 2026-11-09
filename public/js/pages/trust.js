// Trust map: who can get into your AWS. A 2D map of every way in, read from the trust policies: outside AWS accounts
// (vendors and other tenants), OIDC providers such as GitHub Actions or Bitbucket Pipelines, SAML, anyone, and your own
// accounts trusting each other. One line per (where it comes from -> account), coloured by its worst finding. Click a
// line, a source or an account for the roles behind it in the sidebar; the table below follows the selection.
// Everything is a query, so a view can be shared as a link: #/trust?q=finding:account-root from:123456789012
import { h, svg, get, num, ago } from '../lib.js';
import { go } from '../main.js';

const SEV = { high: 'b-high', medium: 'b-medium', low: 'b-low', info: 'b-neutral' };
const SEV_ORDER = { high: 0, medium: 1, low: 2, info: 3, none: 4 };
const LINE = { high: '#ff5a4f', medium: '#f0b45a', low: '#5f9c80', info: '#5f9c80', none: '#5f9c80' };
const DOT = { high: '#ff5a4f', medium: '#f0b45a', low: '#9fe8c4', info: '#7e978a', none: '#2f6e52' };
const ENV = { production: '#c68405', shared: '#676815', staging: '#4b95f0', development: '#37ac78', sandbox: '#a947a3' };
const ENV_ORDER = ['production', 'shared', 'staging', 'development', 'sandbox'];
const GROUPS = {
  public: ['Anyone', 'Principal "*" or NotPrincipal: no identity is required.'],
  'external-account': ['Outside AWS accounts', 'Vendors and other tenants: accounts not connected to Curious Monkey.'],
  oidc: ['OIDC and web identity', 'GitHub Actions, Bitbucket Pipelines, GitLab, EKS service accounts, Google, Cognito…'],
  saml: ['SAML', 'Identity providers that sign in people through SAML.'],
  'connected-account': ['Your other AWS accounts', 'Accounts connected to Curious Monkey.'],
  'same-account': ['The same account', 'Roles and users in the account the role lives in.'],
  service: ['AWS services', 'Services that assume the role on your behalf.'],
  unknown: ['Deleted identities', 'Principals that no longer resolve to an identity.'],
};
const SHORT = { public: 'Anyone', 'external-account': 'Outside account', oidc: 'OIDC', saml: 'SAML', 'connected-account': 'Your account', 'same-account': 'Same account', service: 'Service', unknown: 'Deleted' };
const QUICK = [
  ['Whole account (:root)', 'finding:account-root'], ['Anyone (*)', 'finding:public'], ['OIDC without sub', 'finding:oidc-no-sub'],
  ['Broad OIDC sub', 'finding:oidc-broad-sub'], ['Outside accounts, no ExternalId', 'finding:external-no-externalid'],
  ['GitHub Actions', 'provider:github'], ['Bitbucket', 'provider:bitbucket'], ['Google', 'provider:google'], ['EKS', 'provider:eks'],
  ['From other AWS accounts', 'source:aws -source:same'], ['Never used', 'finding:never-used'],
];
const PAGE = 20;
const plural = (n, w) => `${num(n)} ${w}${n === 1 ? '' : 's'}`;
const cut = (s, n) => (s.length > n ? `${s.slice(0, n - 1)}…` : s);
const sevBadge = (s) => s && s !== 'none' && h('span', { class: `badge ${SEV[s]}` }, s);

export async function trustPage(ctx) {
  const q = ctx.params.get('q') || '';
  const [m, accts] = await Promise.all([get(`/trust?q=${encodeURIComponent(q)}`), get('/accounts')]);
  ctx.setCrumbs('Trust map', q || 'All roles');
  const run = (next) => go(`#/trust${next.trim() ? `?q=${encodeURIComponent(next.trim())}` : ''}`);
  const withTerm = (term) => { const parts = q.split(/\s+/).filter((t) => t && !t.startsWith(term.split(':')[0] + ':')); return [...parts, term].join(' '); };
  const M = m.map;
  const acctBy = new Map(M.accounts.map((a) => [a.id, a]));
  const srcBy = new Map(M.sources.map((s) => [s.id, s]));
  const nameOf = (id) => acctBy.get(id)?.name || srcBy.get(id)?.label || '?';
  let sel = ctx.params.get('sel') || null;
  let page = 0;

  // ---------------------------------------------------------------- filter
  const input = h('input', { type: 'search', value: q, 'aria-label': 'Query', placeholder: 'e.g. finding:account-root from:123456789012 provider:github role:deploy', spellcheck: 'false', class: 'mono' });
  input.addEventListener('keydown', (e) => { if (e.key === 'Enter') run(input.value); });
  const acctSel = h('select', { 'aria-label': 'Account the roles live in' }, h('option', { value: '' }, 'Roles in all accounts'),
    accts.items.filter((a) => a.status !== 'planned').map((a) => h('option', { value: a.name, selected: new RegExp(`(^|\\s)account:"?${a.name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}"?(\\s|$)`, 'i').test(q) }, `Roles in ${a.name}`)));
  acctSel.addEventListener('change', () => { const rest = q.split(/\s+/).filter((t) => t && !t.startsWith('account:')).join(' '); run(acctSel.value ? `account:${acctSel.value} ${rest}` : rest); });
  const filters = h('section', { class: 'card' }, h('div', { class: 'card-b stack' },
    h('div', { class: 'row' }, acctSel, h('div', { class: 'grow', style: 'min-width:280px' }, input), h('button', { class: 'btn primary', onClick: () => run(input.value) }, 'Search'),
      q && h('button', { class: 'btn', onClick: () => run('') }, 'Clear')),
    h('div', { class: 'row', style: 'gap:6px;flex-wrap:wrap' }, QUICK.map(([label, term]) => h('button', { class: 'chip', 'aria-pressed': String(q.includes(term)), onClick: () => run(q.includes(term) ? q.replace(term, '') : withTerm(term)) }, label))),
    Object.keys(m.findingCounts).length > 0 && h('div', { class: 'row', style: 'gap:6px;flex-wrap:wrap;align-items:center' },
      h('span', { class: 'small muted' }, 'Findings here:'),
      Object.entries(m.findingCounts).sort((a, b) => b[1] - a[1]).map(([id, n]) => h('button', { class: 'chip', 'aria-pressed': String(q.includes(`finding:${id}`)), title: m.findings[id], onClick: () => run(withTerm(`finding:${id}`)) },
        m.findings[id] || id, h('span', { class: 'mono tiny', style: 'opacity:.8' }, ` ${num(n)}`)))),
    h('details', null, h('summary', { class: 'small muted', style: 'cursor:pointer' }, 'Query syntax'),
      h('div', { class: 'qhelp' },
        [['account:payments-prod', 'roles living in that account (name or 12-digit ID)'], ['from:123456789012', 'trusts that AWS account (also a name of a connected account)'],
          ['source:external | connected | same | aws | oidc | saml | service | public', 'where the trust comes from'], ['type:root | role | user | oidc | saml | service | public', 'what kind of principal'],
          ['provider:github | bitbucket | google | eks | "Bitbucket Pipelines · krom"', 'OIDC / SAML provider or AWS service'], ['finding:account-root', `one of: ${Object.keys(m.findings).join(', ')}`],
          ['severity:high', 'has a finding of that severity'], ['role:deploy', 'role name contains'], ['cond:ExternalId', 'a condition contains'], ['env:production', 'account environment'],
          ['has:findings · no:conditions · used:no', 'shortcuts'], ['-term', 'excludes, e.g. -source:service'], ['free text', 'matches role, account, principal, source, conditions']]
          .map(([k, v]) => h('div', { class: 'row', style: 'gap:12px;align-items:baseline' }, h('code', null, k), h('span', { class: 'small muted' }, v)))))));

  // ---------------------------------------------------------------- layout of the map
  const W = 1000, NODE = 38, GAP = 6, HEAD = 24, SX = 8, SW = 270, AX = 500, AW = 250, ARC = AX + AW;
  const pos = new Map(), heads = [];
  let y = 8;
  const srcGroups = ['public', 'external-account', 'oidc', 'saml', 'unknown'].map((g) => [g, M.sources.filter((s) => s.group === g)]).filter(([, l]) => l.length);
  for (const [g, list] of srcGroups) {
    heads.push({ x: SX, y: y + 14, text: `${GROUPS[g][0]} · ${list.length}` }); y += HEAD;
    for (const s of list) { pos.set(s.id, { x: SX, y, w: SW }); y += NODE + GAP; }
    y += 8;
  }
  const leftH = y;
  y = 8;
  const envOf = (a) => (ENV_ORDER.includes(a.env) ? a.env : 'other');
  const shown = M.accounts.filter((a) => a.inScope || M.links.some((l) => l.from === a.id || l.to === a.id));
  for (const env of [...ENV_ORDER, 'other']) {
    const list = shown.filter((a) => envOf(a) === env).sort((a, b) => (SEV_ORDER[a.inbound.worst] - SEV_ORDER[b.inbound.worst]) || a.name.localeCompare(b.name));
    if (!list.length) continue;
    heads.push({ x: AX, y: y + 14, text: `${env} · ${list.length}`, color: ENV[env] }); y += HEAD;
    for (const a of list) { pos.set(a.id, { x: AX, y, w: AW }); y += NODE + GAP; }
    y += 8;
  }
  const H = Math.max(leftH, y, 200) + 8;
  // centre the shorter column against the taller one
  const shift = (ids, by) => { for (const id of ids) pos.get(id).y += by; };
  const leftIds = M.sources.map((s) => s.id), rightIds = shown.map((a) => a.id);
  const dl = Math.round((H - leftH) / 2), dr = Math.round((H - y) / 2);
  heads.forEach((hd) => { hd.y += hd.x === SX ? dl : dr; });
  shift(leftIds, dl); shift(rightIds, dr);

  const svgEl = svg('svg', { viewBox: `0 0 ${W} ${H}`, class: 'tm-svg', role: 'group', 'aria-label': 'Trust map: where each way in comes from, and which account it reaches' });
  const side = h('div', { class: 'tm-side-in' });
  const table = h('section', { class: 'card' });

  const related = (id) => {
    if (!id) return null;
    if (id.includes('>')) { const l = M.links.find((x) => x.id === id); return l ? new Set([l.id, l.from, l.to]) : null; }
    const set = new Set([id]);
    for (const l of M.links) if (l.from === id || l.to === id) { set.add(l.id); set.add(l.from); set.add(l.to); }
    return set;
  };

  function drawMap() {
    const on = related(sel);
    const dim = (id) => (on && !on.has(id) ? 0.12 : 1);
    const pick = (id) => (e) => { e.stopPropagation(); select(sel === id ? null : id); };
    const key = (id) => (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); select(sel === id ? null : id); } };
    const defs = svg('defs', null, ...Object.entries({ high: LINE.high, medium: LINE.medium, ok: LINE.none, sel: '#ffffff' }).map(([k, c]) =>
      svg('marker', { id: `tm-arrow-${k}`, viewBox: '0 0 10 10', refX: 9, refY: 5, markerWidth: 6, markerHeight: 6, orient: 'auto-start-reverse' }, svg('path', { d: 'M0 0 L10 5 L0 10 z', fill: c }))));
    const lines = [], hits = [];
    const lineFor = (l) => {
      const a = pos.get(l.from), b = pos.get(l.to);
      if (!a || !b) return;
      const ya = a.y + NODE / 2, yb = b.y + NODE / 2;
      let d;
      if (l.kind === 'outside') d = `M${a.x + a.w} ${ya} C ${a.x + a.w + 110} ${ya}, ${b.x - 110} ${yb}, ${b.x - 4} ${yb}`;
      else {
        const o = ya < yb ? -5 : 5;                         // two directions between a pair stay apart
        const bulge = Math.min(232, 34 + Math.abs(yb - ya) * 0.42);
        d = `M${ARC} ${ya + o} C ${ARC + bulge} ${ya + o}, ${ARC + bulge} ${yb - o}, ${ARC + 4} ${yb - o}`;
      }
      const w = Math.min(5, 1.3 + Math.log2(l.roles.length) * 0.9);
      const isSel = sel === l.id, c = isSel ? '#fff' : LINE[l.worst];
      const mk = isSel ? 'sel' : l.worst === 'high' ? 'high' : l.worst === 'medium' ? 'medium' : 'ok';
      lines.push(svg('path', { d, fill: 'none', stroke: c, 'stroke-width': isSel ? w + 1 : w, opacity: dim(l.id) * (l.worst === 'high' || l.worst === 'medium' || isSel ? 0.95 : 0.6),
        'stroke-dasharray': l.sessions || l.iamUsed ? null : '5 4', 'marker-end': `url(#tm-arrow-${mk})` }));
      hits.push(svg('path', { d, fill: 'none', stroke: 'transparent', 'stroke-width': 14, class: 'tm-hit', tabindex: 0, role: 'button',
        'aria-label': `${nameOf(l.from)} to ${nameOf(l.to)}: ${plural(l.roles.length, 'role')}, worst ${l.worst}`, onClick: pick(l.id), onKeydown: key(l.id) },
        svg('title', null, `${nameOf(l.from)} → ${nameOf(l.to)} · ${plural(l.roles.length, 'role')}${l.worst !== 'none' ? ` · worst ${l.worst}` : ''}${l.sessions ? ` · ${num(l.sessions)} sessions seen` : l.iamUsed ? ' · IAM says used, no sign-in tied to it' : ' · never seen used'}`)));
    };
    // quiet lines first, so the risky ones sit on top
    [...M.links].sort((a, b) => SEV_ORDER[b.worst] - SEV_ORDER[a.worst]).forEach(lineFor);

    const nodeG = (id, p, { label, sub, color, worst, dashed, planned }) => {
      const isSel = sel === id;
      return svg('g', { class: 'tm-node', opacity: dim(id), tabindex: 0, role: 'button', 'aria-pressed': String(isSel), 'aria-label': `${label}. ${sub}`, onClick: pick(id), onKeydown: key(id) },
        svg('title', null, `${label} · ${sub}`),
        svg('rect', { x: p.x, y: p.y, width: p.w, height: NODE, fill: isSel ? '#10271d' : '#08170f', stroke: isSel ? '#fff' : worst === 'high' ? LINE.high : '#1f4a35',
          'stroke-width': isSel || worst === 'high' ? 1.5 : 1, 'stroke-dasharray': dashed ? '4 3' : null }),
        svg('rect', { x: p.x, y: p.y, width: 4, height: NODE, fill: color }),
        svg('text', { x: p.x + 12, y: p.y + 15, class: 'tm-label' }, cut(label, 34)),
        svg('text', { x: p.x + 12, y: p.y + 29, class: 'tm-sub' }, cut(sub, 44)),
        worst && worst !== 'none' && worst !== 'info' && svg('circle', { cx: p.x + p.w - 12, cy: p.y + NODE / 2, r: 4.5, fill: DOT[worst] }),
        planned && svg('text', { x: p.x + p.w - 22, y: p.y + 15, 'text-anchor': 'end', class: 'tm-sub' }, 'planned'));
    };
    const nodes = [
      ...M.sources.map((s) => nodeG(s.id, pos.get(s.id), { label: s.label, color: DOT[s.worst] === DOT.none ? '#4f6d60' : DOT[s.worst], worst: s.worst,
        sub: [s.group === 'external-account' ? (s.vendor ? 'vendor · ExternalId' : 'no ExternalId') : SHORT[s.group], plural(s.roles, 'role'), plural(s.accounts, 'account')].join(' · ') })),
      ...shown.map((a) => nodeG(a.id, pos.get(a.id), { label: a.name, color: ENV[a.env] || '#7e978a', worst: a.inbound.worst, dashed: !a.inScope, planned: a.planned,
        sub: `${a.aws} · ${a.inbound.roles ? `${plural(a.inbound.roles, 'role')} reachable` : 'nothing in from outside'}` })),
    ];
    const labels = heads.map((hd) => svg('text', { x: hd.x, y: hd.y, class: 'tm-head', fill: hd.color || null }, hd.text.toUpperCase()));
    const cols = [svg('text', { x: SX, y: H - 2, class: 'tm-col' }, ''),
      !M.sources.length && svg('text', { x: SX + 8, y: H / 2, class: 'tm-sub' }, 'Nothing outside your accounts can get in (for this query).')];
    svgEl.replaceChildren(defs, svg('rect', { x: 0, y: 0, width: W, height: H, fill: 'transparent', onClick: () => select(null) }), ...labels, ...lines, ...nodes, ...hits, ...cols.filter(Boolean));
  }

  // ---------------------------------------------------------------- sidebar
  const listBox = (title, items, { empty = 'none', filterable = items.length > 8 } = {}) => {
    const body = h('div', { class: 'tm-list' });
    const fill = (needle = '') => body.replaceChildren(...(items.filter((i) => !needle || i.text.toLowerCase().includes(needle)).map((i) => i.el)), ...(items.length ? [] : [h('p', { class: 'tiny muted', style: 'margin:4px 0' }, empty)]));
    fill();
    const f = filterable && h('input', { type: 'search', class: 'tm-filter', placeholder: `Filter ${items.length}…`, 'aria-label': `Filter ${title}` });
    if (f) f.addEventListener('input', () => fill(f.value.trim().toLowerCase()));
    return h('div', { class: 'tm-sect' }, h('div', { class: 'tm-sect-h' }, h('span', null, title), h('span', { class: 'mono' }, num(items.length))), f, body);
  };
  const item = ({ label, meta, worst, badge, onClick, href }) => {
    const kids = [h('span', { class: 'tm-dot', style: `background:${DOT[worst || 'none']}` }),
      h('span', { class: 'tm-item-b' }, h('span', { class: 'tm-item-l' }, label), meta && h('span', { class: 'tm-item-m' }, meta)), badge];
    const el = href ? h('a', { class: 'tm-item', href }, ...kids) : h('button', { class: 'tm-item', onClick }, ...kids);
    return { el, text: `${label} ${meta || ''}` };
  };
  const roleItem = (r) => item({ label: r.role, worst: r.worst, href: `#/roles/${r.roleId}?tab=policies`,
    meta: [r.findings.filter((f) => f.severity !== 'info').map((f) => f.title).slice(0, 2).join(' · ') || (r.conditions ? `${plural(r.conditions, 'condition')}` : 'no conditions'),
      r.sessions ? `${num(r.sessions)} sessions · last ${ago(r.lastSeen)}` : r.iamLastUsed ? `IAM last used ${ago(r.iamLastUsed)}` : 'never used'].join(' · '), badge: sevBadge(r.worst) });
  const head = (eyebrow, title, sub, worst) => h('div', { class: 'tm-side-h' },
    h('div', { class: 'tm-eyebrow' }, eyebrow, worst === 'high' && h('span', { class: 'tm-tag' }, '⚠ HIGH RISK'), worst === 'medium' && h('span', { class: 'tm-tag warn' }, 'LOOSE TRUST')),
    h('div', { class: 'row', style: 'justify-content:space-between;gap:8px;align-items:flex-start' }, h('b', { class: 'tm-title' }, title),
      h('button', { class: 'sp-x', 'aria-label': 'Close', onClick: () => select(null) }, '×')),
    sub && h('div', { class: 'tm-sub-t' }, sub));
  const facts = (rows) => h('dl', { class: 'tm-facts' }, rows.filter(Boolean).flatMap(([k, v, tone]) => [h('dt', null, k), h('dd', { class: tone ? `tm-${tone}` : null }, v)]));
  const actions = (list) => h('div', { class: 'tm-actions' }, list.filter(Boolean).map(([label, fn, primary]) => typeof fn === 'string'
    ? h('a', { class: `btn sm${primary ? ' primary' : ''}`, href: fn }, label) : h('button', { class: `btn sm${primary ? ' primary' : ''}`, onClick: fn }, label)));

  function drawSide() {
    const l = sel?.includes('>') && M.links.find((x) => x.id === sel);
    const s = srcBy.get(sel), a = acctBy.get(sel);
    if (l) {
      const from = acctBy.get(l.from) || srcBy.get(l.from), to = acctBy.get(l.to);
      const highs = l.roles.filter((r) => r.worst === 'high').length;
      side.replaceChildren(head(l.kind === 'account' ? 'ACCOUNT → ACCOUNT' : `${(GROUPS[from.group]?.[0] || 'OUTSIDE').toUpperCase()} → ACCOUNT`, `${from.name || from.label} → ${to.name}`,
        `${l.kind === 'account' ? `${from.aws} trusts into ${to.aws}` : `into ${to.aws}`} · ${plural(l.roles.length, 'role')} · ${plural(l.ways, 'statement')}`, l.worst),
      facts([['High risk', highs ? `${plural(highs, 'role')} of ${l.roles.length}` : 'none', highs ? 'bad' : 'ok'],
        ['Findings', l.findings ? plural(l.findings, 'finding') : 'nothing to flag', l.findings ? 'bad' : 'ok'],
        ['Seen coming in', l.sessions ? `${num(l.sessions)} sessions` : l.iamUsed ? 'no sign-in tied to it, but IAM says its roles are used' : 'never: no sign-in, and IAM has no record of use', l.sessions || l.iamUsed ? null : 'warn']]),
      listBox('Roles it can assume', l.roles.map(roleItem)),
      actions([['Filter to this', () => run(l.query), true], ['Show ways in', () => table.scrollIntoView({ behavior: 'smooth' })]]));
    } else if (s) {
      const out = M.links.filter((x) => x.from === s.id);
      side.replaceChildren(head((GROUPS[s.group]?.[0] || s.group).toUpperCase(), s.label,
        s.group === 'external-account' ? `AWS account not connected here · ${s.vendor ? 'vendor pattern: every statement requires sts:ExternalId' : 'at least one statement has no sts:ExternalId'}` : GROUPS[s.group]?.[1], s.worst),
      facts([['Reaches', `${plural(s.roles, 'role')} in ${plural(s.accounts, 'account')}`], ['Findings', s.findings ? plural(s.findings, 'finding') : 'nothing to flag', s.findings ? 'bad' : 'ok'],
        ['Seen coming in', s.seen ? `${num(s.seen)} sessions` : 'never, in the stored history', s.seen ? null : 'warn']]),
      listBox('Accounts it can get into', out.map((x) => item({ label: nameOf(x.to), worst: x.worst, meta: `${plural(x.roles.length, 'role')}${x.sessions ? ` · ${num(x.sessions)} sessions` : x.iamUsed ? ' · IAM says used' : ' · never used'}`, badge: sevBadge(x.worst), onClick: () => select(x.id) }))),
      actions([['Filter to this', () => run(withTerm(s.query)), true]]));
    } else if (a) {
      const inn = M.links.filter((x) => x.to === a.id), out = M.links.filter((x) => x.from === a.id);
      side.replaceChildren(head(`${(a.env || 'account').toUpperCase()} ACCOUNT${a.inScope ? '' : ' · NOT IN YOUR SCOPE'}`, a.name, `${a.aws}${a.planned ? ' · planned, not scanned' : ''}`, a.inbound.worst),
      facts([['Reachable from outside it', a.inbound.roles ? plural(a.inbound.roles, 'role') : 'no role', a.inbound.worst === 'high' ? 'bad' : null],
        ['Trust inside it', `${plural(a.own, 'role')} trust its own account · ${plural(a.services, 'role')} trust AWS services`]]),
      listBox('Who can get in', inn.map((x) => item({ label: nameOf(x.from), worst: x.worst, meta: `${x.kind === 'account' ? 'your account' : SHORT[srcBy.get(x.from)?.group] || ''} · ${plural(x.roles.length, 'role')}${x.sessions ? ` · ${num(x.sessions)} sessions` : x.iamUsed ? ' · IAM says used' : ' · never used'}`, badge: sevBadge(x.worst), onClick: () => select(x.id) })), { empty: 'nothing from outside this account' }),
      out.length > 0 && listBox('It can get into', out.map((x) => item({ label: nameOf(x.to), worst: x.worst, meta: `${plural(x.roles.length, 'role')}${x.sessions ? ` · ${num(x.sessions)} sessions` : x.iamUsed ? ' · IAM says used' : ' · never used'}`, badge: sevBadge(x.worst), onClick: () => select(x.id) }))),
      actions([['Filter to this', () => run(withTerm(`account:${a.aws}`)), true], ['Open in Space', `#/space?view=account&account=${a.id}`]]));
    } else {
      // nothing picked: where things come from (every group, inside ones too), and how to read the map
      const groups = m.summary.map((g) => listBox(GROUPS[g.group]?.[0] || g.group, g.sources.map((x) => {
        const node = M.sources.find((n) => n.query === x.query) || (g.group === 'connected-account' && M.accounts.find((n) => x.query === `from:${n.aws}`));
        return item({ label: x.label, worst: x.worst, meta: `${plural(x.roles, 'role')} · ${plural(x.accounts, 'account')}${x.findings ? ` · ${plural(x.findings, 'finding')}` : ''}`,
          badge: sevBadge(x.worst), onClick: () => (node ? select(node.id) : run(withTerm(x.query))) });
      }), { filterable: g.sources.length > 6 }));
      side.replaceChildren(h('div', { class: 'tm-side-h' }, h('div', { class: 'tm-eyebrow' }, 'REACHABLE FROM'),
        h('div', { class: 'tm-sub-t' }, `${plural(m.total, 'way')} in to ${plural(m.roles, 'role')}${q ? ` · of ${num(m.totalEdges)} in all` : ''}. Click a line, a source or an account.`)),
      ...(groups.length ? groups : [h('p', { class: 'small muted' }, q ? 'Nothing matches this query.' : 'No roles yet.')]),
      h('div', { class: 'tm-legend' },
        h('div', null, h('i', { style: `border-top:3px solid ${LINE.high}` }), 'High-risk trust behind the line'),
        h('div', null, h('i', { style: `border-top:3px solid ${LINE.medium}` }), 'Loose trust (medium)'),
        h('div', null, h('i', { style: `border-top:2px solid ${LINE.none}` }), 'Nothing serious to flag'),
        h('div', null, h('i', { style: `border-top:2px dashed ${LINE.none}` }), 'Dashed: never used (no sign-in, and IAM has no record of use)'),
        h('div', null, h('i', { style: 'border-top:2px solid #5f9c80;width:18px;height:10px;border-right:2px solid #5f9c80;border-radius:0 8px 8px 0' }), 'Arcs on the right: your accounts trusting each other'),
        h('div', null, h('i', { style: 'border:1px dashed #5f9c80;height:10px' }), 'Dashed box: an account outside your scope'),
        h('div', null, h('i', { style: 'border:none' }), 'Thicker line: more roles behind it')));
    }
  }

  // ---------------------------------------------------------------- ways in, following the selection
  const rowsFor = () => {
    if (!sel) return m.rows;
    const l = sel.includes('>') && M.links.find((x) => x.id === sel);
    const ids = l ? new Set(l.roles.map((r) => r.roleId)) : null;
    const fromOf = (e) => (e.group === 'connected-account' ? M.accounts.find((a) => a.aws === e.principalAccount)?.id
      : `src:${e.group === 'external-account' ? `acct:${e.principalAccount}` : e.group === 'unknown' ? 'deleted' : `${e.group}:${e.source}`}`);
    if (l) return m.rows.filter((e) => ids.has(e.roleId) && e.accountId === l.to && fromOf(e) === l.from);
    if (srcBy.has(sel)) return m.rows.filter((e) => fromOf(e) === sel);
    return m.rows.filter((e) => e.accountId === sel || fromOf(e) === sel);
  };
  function drawTable() {
    const rows = rowsFor(), pages = Math.max(1, Math.ceil(rows.length / PAGE));
    page = Math.min(page, pages - 1);
    const slice = rows.slice(page * PAGE, page * PAGE + PAGE);
    const pager = () => rows.length > PAGE && h('div', { class: 'row', style: 'gap:8px;align-items:center' },
      h('span', { class: 'small muted' }, `${num(page * PAGE + 1)}–${num(Math.min(rows.length, page * PAGE + PAGE))} of ${num(rows.length)}`),
      h('button', { class: 'btn sm', disabled: page === 0, onClick: () => { page--; drawTable(); } }, 'Previous'),
      h('button', { class: 'btn sm', disabled: page >= pages - 1, onClick: () => { page++; drawTable(); } }, 'Next'));
    table.replaceChildren(
      h('div', { class: 'card-h' }, h('div', null, h('h2', null, 'Ways in'), h('p', { class: 'small muted', style: 'margin:2px 0 0' },
        sel ? `Following the selection on the map: ${sel.includes('>') ? `${nameOf(M.links.find((x) => x.id === sel).from)} → ${nameOf(M.links.find((x) => x.id === sel).to)}` : nameOf(sel)}.` : 'Every statement that lets someone in, the worst first.',
        m.truncated ? ` The first ${num(m.rows.length)} of ${num(m.total)} are loaded; narrow the query or export the CSV for all.` : '')),
        h('div', { class: 'row', style: 'gap:8px' }, sel && h('button', { class: 'btn sm', onClick: () => select(null) }, 'Show all'), pager())),
      !rows.length ? h('div', { class: 'card-b' }, h('p', { class: 'muted small' }, sel && m.truncated ? 'Not among the loaded rows. Use “Filter to this” in the sidebar.' : 'Nothing here.'))
        : h('div', { class: 'tm-ways' }, slice.map((e) => h('div', { class: 'tm-way' },
          h('span', { class: 'tm-dot', style: `background:${DOT[e.worst]}`, title: e.worst }),
          h('div', { class: 'tm-way-role' }, h('a', { href: `#/roles/${e.roleId}?tab=policies`, class: 'name' }, e.role),
            h('div', { class: 'tiny muted' }, `${e.account} · ${e.awsAccountId} · ${e.sid || `statement ${e.statement + 1}`}`)),
          h('div', { class: 'tm-way-from' }, h('div', { class: 'row', style: 'gap:6px;flex-wrap:nowrap;min-width:0' }, h('span', { class: `src-tag g-${e.group}` }, SHORT[e.group] || e.group), h('span', { class: 'tm-ell' }, e.source)),
            h('div', { class: 'mono tiny muted tm-ell', title: e.principal }, e.principal)),
          h('div', { class: 'tm-way-cond' }, e.conditions.length
            ? h('details', null, h('summary', { class: 'tiny' }, plural(e.conditions.length, 'condition')), h('div', { class: 'stack', style: 'gap:2px;margin-top:4px' }, e.conditions.map((c) => h('code', { class: 'cond-line' }, c))))
            : h('span', { class: 'tiny', style: 'color:#f0b45a' }, 'no conditions')),
          h('div', { class: 'tm-way-f' }, e.findings.filter((f) => f.severity !== 'info').length
            ? e.findings.filter((f) => f.severity !== 'info').map((f) => h('div', { class: 'tm-find', title: f.detail }, h('span', { class: `badge ${SEV[f.severity]}` }, f.severity), h('span', { class: 'tm-ftext' }, f.title)))
            : h('span', { class: 'tiny muted' }, e.findings.length ? e.findings.map((f) => f.title).join(' · ') : 'nothing to flag')),
          h('div', { class: 'tm-way-seen tiny' }, e.seen.length ? [h('b', null, num(e.seen.reduce((n, s) => n + Number(s.sessions || 0), 0))), ` sessions · ${ago(e.seen.map((s) => s.lastSeen).filter(Boolean).sort().at(-1))}`]
            : e.lastUsed ? h('span', { title: 'IAM RoleLastUsed. No sign-in in the CloudTrail read was tied to this statement.' }, `IAM: used ${ago(e.lastUsed.at)}`)
            : h('span', { class: 'muted' }, e.type === 'service' ? '—' : 'never used'))))),
      rows.length > PAGE && h('div', { class: 'card-b row', style: 'justify-content:flex-end' }, pager()));
  }

  function select(id) {
    sel = id; page = 0;
    const p = new URLSearchParams(location.hash.split('?')[1] || '');
    if (id) p.set('sel', id); else p.delete('sel');
    history.replaceState(null, '', `#/trust${p.toString() ? `?${p}` : ''}`);
    drawMap(); drawSide(); drawTable();
  }
  if (sel && !acctBy.has(sel) && !srcBy.has(sel) && !M.links.some((l) => l.id === sel)) sel = null;
  drawMap(); drawSide(); drawTable();

  const outside = M.links.filter((l) => l.kind === 'outside').length, between = M.links.filter((l) => l.kind === 'account').length;
  const risky = M.links.filter((l) => l.worst === 'high').length;
  return h('div', { class: 'stack-lg' },
    h('header', { class: 'head' },
      h('div', null, h('div', { class: 'eyebrow' }, 'TRUST MAP'), h('h1', null, 'Who can get into your AWS'),
        h('p', { class: 'muted' }, 'Every way in, read from the trust policies: vendors and other tenants, CI providers, SAML, anyone, and your own accounts trusting each other. One line per source and account, red when the trust behind it is high risk.')),
      h('div', { class: 'row' }, h('a', { class: 'btn', href: `/api/trust.csv?q=${encodeURIComponent(q)}` }, 'Export CSV'))),
    filters,
    h('div', { class: 'tm-layout' },
      h('section', { class: 'card tm-mapcard' },
        h('div', { class: 'tm-stats' },
          h('span', null, h('b', null, num(M.sources.length)), ' outside sources'),
          h('span', null, h('b', null, num(outside)), ' lines in from outside'),
          h('span', null, h('b', null, num(between)), ' account → account'),
          h('span', { class: risky ? 'tm-bad' : null }, h('b', null, num(risky)), ' high-risk lines')),
        h('div', { class: 'tm-cols' }, h('span', null, 'WHERE IT COMES FROM'), h('span', null, 'YOUR ACCOUNTS'), h('span', null, 'BETWEEN YOUR ACCOUNTS')),
        h('div', { class: 'tm-scroll' }, svgEl)),
      h('aside', { class: 'tm-side', 'aria-live': 'polite', 'aria-label': 'Details' }, side)),
    table);
}
