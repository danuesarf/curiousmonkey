// Trust map: who can reach each role (AWS accounts, OIDC providers such as GitHub Actions or Bitbucket Pipelines,
// SAML, Google, AWS services, anyone), with the conditions on the way in, what was seen using it, and what is wrong.
// Everything is a query, so a view can be shared as a link: #/trust?q=finding:account-root from:123456789012
import { h, get, num, ago } from '../lib.js';
import { go } from '../main.js';

const SEV = { high: 'b-high', medium: 'b-medium', low: 'b-low', info: 'b-neutral' };
const SEV_COLOR = { high: '#ff6b5e', medium: '#f0b45a', low: '#9fe8c4', info: '#7e978a', none: '#2f6e52' };
const GROUPS = {
  public: ['Anyone', 'Principal "*" or NotPrincipal: no identity is required.'],
  'external-account': ['AWS accounts outside your estate', 'Accounts that are not connected to Curious Monkey.'],
  oidc: ['OIDC and web identity', 'GitHub Actions, Bitbucket Pipelines, GitLab, EKS service accounts, Google, Cognito…'],
  saml: ['SAML', 'Identity providers that sign in people through SAML.'],
  'connected-account': ['Your other AWS accounts', 'Accounts connected to Curious Monkey.'],
  'same-account': ['The same account', 'Roles and users in the account the role lives in.'],
  service: ['AWS services', 'Services that assume the role on your behalf.'],
  unknown: ['Unknown or deleted', 'Principals that no longer resolve to an identity.'],
};
const QUICK = [
  ['Whole account (:root)', 'finding:account-root'], ['Anyone (*)', 'finding:public'], ['OIDC without sub', 'finding:oidc-no-sub'],
  ['Broad OIDC sub', 'finding:oidc-broad-sub'], ['Outside accounts, no ExternalId', 'finding:external-no-externalid'],
  ['GitHub Actions', 'provider:github'], ['Bitbucket', 'provider:bitbucket'], ['Google', 'provider:google'], ['EKS', 'provider:eks'],
  ['From other AWS accounts', 'source:aws -source:same'], ['Never used', 'finding:never-used'],
];

export async function trustPage(ctx) {
  const q = ctx.params.get('q') || '';
  const [m, accts] = await Promise.all([get(`/trust?q=${encodeURIComponent(q)}`), get('/accounts')]);
  ctx.setCrumbs('Trust map', q || 'All roles');
  const run = (next) => go(`#/trust${next.trim() ? `?q=${encodeURIComponent(next.trim())}` : ''}`);
  const withTerm = (term) => { const parts = q.split(/\s+/).filter((t) => t && !t.startsWith(term.split(':')[0] + ':')); return [...parts, term].join(' '); };

  const input = h('input', { type: 'search', value: q, 'aria-label': 'Query', placeholder: 'e.g. finding:account-root from:123456789012 provider:github role:deploy', spellcheck: 'false', class: 'mono' });
  input.addEventListener('keydown', (e) => { if (e.key === 'Enter') run(input.value); });
  const acctSel = h('select', { 'aria-label': 'Account the roles live in' }, h('option', { value: '' }, 'Roles in all accounts'),
    accts.items.map((a) => h('option', { value: a.name, selected: new RegExp(`(^|\\s)account:"?${a.name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}"?(\\s|$)`, 'i').test(q) }, `Roles in ${a.name}`)));
  acctSel.addEventListener('change', () => { const rest = q.split(/\s+/).filter((t) => t && !t.startsWith('account:')).join(' '); run(acctSel.value ? `account:${acctSel.value} ${rest}` : rest); });

  return h('div', { class: 'stack-lg' },
    h('header', { class: 'head' },
      h('div', null, h('div', { class: 'eyebrow' }, 'TRUST MAP'), h('h1', null, 'Who can reach your roles'),
        h('p', { class: 'muted' }, 'Every way into every role, read from the trust policies: other AWS accounts, OIDC providers, SAML, Google, AWS services, or anyone. With the conditions on the way in, what was actually seen coming in, and what is wrong with it.')),
      h('div', { class: 'row' }, h('a', { class: 'btn', href: `/api/trust.csv?q=${encodeURIComponent(q)}` }, 'Export CSV'))),

    h('section', { class: 'card' }, h('div', { class: 'card-b stack' },
      h('div', { class: 'row' }, acctSel, h('div', { class: 'grow', style: 'min-width:280px' }, input), h('button', { class: 'btn primary', onClick: () => run(input.value) }, 'Search'),
        q && h('button', { class: 'btn', onClick: () => run('') }, 'Clear')),
      h('div', { class: 'row', style: 'gap:6px;flex-wrap:wrap' }, QUICK.map(([label, term]) => h('button', { class: 'chip', 'aria-pressed': String(q.includes(term)), onClick: () => run(q.includes(term) ? q.replace(term, '') : withTerm(term)) }, label))),
      h('details', null, h('summary', { class: 'small muted', style: 'cursor:pointer' }, 'Query syntax'),
        h('div', { class: 'qhelp' },
          [['account:payments-prod', 'roles living in that account (name or 12-digit ID)'], ['from:123456789012', 'trusts that AWS account (also a name of a connected account)'],
            ['source:external | connected | same | aws | oidc | saml | service | public', 'where the trust comes from'], ['type:root | role | user | oidc | saml | service | public', 'what kind of principal'],
            ['provider:github | bitbucket | google | eks | "Bitbucket Pipelines · krom"', 'OIDC / SAML provider or AWS service'], ['finding:account-root', `one of: ${Object.keys(m.findings).join(', ')}`],
            ['severity:high', 'has a finding of that severity'], ['role:deploy', 'role name contains'], ['cond:ExternalId', 'a condition contains'], ['env:production', 'account environment'],
            ['has:findings · no:conditions · used:no', 'shortcuts'], ['-term', 'excludes, e.g. -source:service'], ['free text', 'matches role, account, principal, source, conditions']]
            .map(([k, v]) => h('div', { class: 'row', style: 'gap:12px;align-items:baseline' }, h('code', null, k), h('span', { class: 'small muted' }, v))))))),

    h('section', { class: 'stack' },
      h('div', { class: 'row', style: 'justify-content:space-between' }, h('h2', null, 'Reachable from'),
        h('span', { class: 'small muted' }, `${num(m.total)} way${m.total === 1 ? '' : 's'} in to ${num(m.roles)} role${m.roles === 1 ? '' : 's'}${q ? ` · of ${num(m.totalEdges)} in all` : ''}`)),
      !m.summary.length ? h('div', { class: 'card empty' }, q ? 'Nothing matches this query.' : 'No roles yet.')
        : h('div', { class: 'reach-grid' }, m.summary.map((g) => h('div', { class: 'reach-group' },
          h('div', { class: 'stack', style: 'gap:2px' }, h('b', null, GROUPS[g.group]?.[0] || g.group), h('span', { class: 'tiny muted' }, GROUPS[g.group]?.[1] || '')),
          h('div', { class: 'stack', style: 'gap:4px' }, g.sources.slice(0, 12).map((s) => {
            const b = h('button', { class: 'reach-src', onClick: () => run(withTerm(s.query)) },
              h('span', { class: 'n' }, s.label),
              h('span', { class: 'mono tiny muted' }, `${s.roles} role${s.roles > 1 ? 's' : ''} · ${s.accounts} acct${s.accounts > 1 ? 's' : ''}`),
              s.findings > 0 && h('span', { class: `badge ${SEV[s.worst]}` }, `${s.findings}`));
            b.style.borderLeftColor = SEV_COLOR[s.worst]; return b;
          }), g.sources.length > 12 && h('span', { class: 'tiny muted' }, `+${g.sources.length - 12} more`)))))),

    Object.keys(m.findingCounts).length > 0 && h('section', { class: 'row', style: 'gap:6px;flex-wrap:wrap' },
      h('span', { class: 'small muted' }, 'Findings in these results:'),
      Object.entries(m.findingCounts).sort((a, b) => b[1] - a[1]).map(([id, n]) => h('button', { class: 'chip', 'aria-pressed': String(q.includes(`finding:${id}`)), title: m.findings[id], onClick: () => run(withTerm(`finding:${id}`)) },
        m.findings[id] || id, h('span', { class: 'mono tiny', style: 'opacity:.8' }, ` ${num(n)}`)))),

    m.rows.length > 0 && h('section', { class: 'card' },
      h('div', { class: 'card-h' }, h('h2', null, 'Ways in'), m.truncated && h('span', { class: 'small muted' }, `Showing the first ${m.rows.length}. Narrow the query or export the CSV for all of them.`)),
      h('div', { class: 'scroll' }, h('table', { class: 'trust-table' },
        h('thead', null, h('tr', null, h('th', null, 'Role'), h('th', null, 'Comes from'), h('th', null, 'Conditions on the way in'), h('th', null, 'Findings'), h('th', null, 'Seen coming in'))),
        h('tbody', null, m.rows.map((e) => h('tr', null,
          h('td', null, h('a', { href: `#/roles/${e.roleId}?tab=policies`, class: 'name' }, e.role), h('div', { class: 'tiny muted' }, `${e.account} · ${e.awsAccountId}${e.sid ? ` · ${e.sid}` : ` · statement ${e.statement + 1}`}`)),
          h('td', null, h('div', { class: 'row', style: 'gap:6px' }, h('span', { class: `src-tag g-${e.group}` }, (GROUPS[e.group]?.[0] || e.group).replace('AWS accounts outside your estate', 'External account').replace('Your other AWS accounts', 'Your account').replace('OIDC and web identity', 'OIDC')),
            h('span', null, e.source)), h('div', { class: 'mono tiny muted', style: 'overflow-wrap:anywhere' }, e.principal)),
          h('td', null, e.conditions.length ? h('div', { class: 'stack', style: 'gap:2px' }, e.conditions.map((c) => h('code', { class: 'cond-line' }, c))) : h('span', { class: 'tiny', style: 'color:#f0b45a' }, 'none')),
          h('td', null, e.findings.length ? h('div', { class: 'stack', style: 'gap:4px' }, e.findings.map((f) => h('details', { class: 'fnd' },
            h('summary', null, h('span', { class: `badge ${SEV[f.severity]}` }, f.severity), ' ', f.title), h('p', { class: 'tiny muted' }, f.detail))))
            : h('span', { class: 'tiny muted' }, '—')),
          h('td', null, e.seen.length ? h('div', { class: 'stack', style: 'gap:2px' }, e.seen.slice(0, 3).map((s) => h('span', { class: 'tiny' }, s.display, h('span', { class: 'muted' }, ` · ${num(s.sessions)} sessions · ${ago(s.lastSeen)}`))),
            e.seen.length > 3 && h('span', { class: 'tiny muted' }, `+${e.seen.length - 3} more`)) : h('span', { class: 'tiny muted' }, e.type === 'service' ? '—' : 'never')))))))));
}
