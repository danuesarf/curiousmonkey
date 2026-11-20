// Specific trust: a draft trust policy that replaces a whole-account principal (arn:aws:iam::<account>:root) with the
// identities seen coming in from it. Pick who stays, draft, check, approve, export; nothing is changed in AWS.
import { h, get, post, num, ago, toast, copy, modal, TEAM, riskBadge, tile, fmtDay } from '../lib.js';
import { session } from '../main.js';

const NAMED = {
  role: (c) => (c.pathKnown ? ['Exact ARN', 'b-green', 'Read from IAM, path included'] : ['Name only', 'b-amber', `${c.pathWhy === 'not-found' ? 'Not in its account\'s inventory (deleted, or renamed since)' : 'Its account is not scanned'}: the path is not known, so the draft allows the name at any path`]),
  user: () => ['Exact ARN', 'b-green', 'IAM user'],
  unnamed: () => ['Unique ID', 'b-amber', 'CloudTrail named it only by its ID. Allowed with aws:userid until its account is onboarded or rescanned'],
  merged: () => ['Not tied', 'b-neutral', 'Recorded before callers were kept by account: it cannot be placed in the draft'],
};
const KIND_LABEL = { role: 'Role', user: 'IAM user', unnamed: 'Identity', merged: 'Older sign-ins' };
const CHANGE = { narrow: ['NARROW', 'warn'], remove: ['REMOVE', 'bad'], keep: ['KEEP', ''] };

export async function trustRecommendationPage(ctx, roleId) {
  const [d, t] = await Promise.all([get(`/roles/${roleId}`), get(`/roles/${roleId}/trust-recommendation`)]);
  const r = d.role, rec = t.draft;
  ctx.setCrumbs(h('a', { href: '#/identities' }, 'Identities'), h('a', { href: `#/identities/${roleId}` }, r.name), 'Specific trust');
  const canRec = session.user.permissions.includes('recommend');
  const accounts = [...new Set(t.roots.map((x) => x.account))];

  // who stays: everyone seen, unless the last draft left them out
  const left = new Set(rec?.excluded || []);
  let style = rec?.style || 'condition';
  const make = async (b) => {
    b.disabled = true; b.textContent = 'Drafting…';
    try { await post(`/roles/${roleId}/trust-recommend`, { exclude: [...left], style }); ctx.reload(); }
    catch (x) { toast(x.message, true); b.disabled = false; b.textContent = rec ? 'Draft again' : 'Draft from history'; }
  };
  const draftBtn = canRec && t.roots.length > 0 && h('button', { class: 'btn primary', onClick: (e) => make(e.currentTarget) }, rec ? 'Draft again' : 'Draft from history');
  const styleSeg = h('div', { class: 'seg', role: 'radiogroup', 'aria-label': 'How the identities are named' },
    ...[['condition', 'aws:PrincipalArn condition'], ['principal', 'Name them in Principal']].map(([v, l]) => {
      const b = h('button', { type: 'button', role: 'radio', 'aria-checked': String(style === v), title: v === 'condition'
        ? 'Keeps the account as the principal and allows only these ARNs. Recommended by AWS for cross-account trust: keeps working when a role is deleted and recreated, and allows a role at an unknown path.'
        : 'Lists the role and user ARNs in Principal. IAM turns them into unique IDs when saved: a role deleted and recreated is locked out until the policy is saved again.' }, l);
      b.addEventListener('click', () => { style = v; styleSeg.querySelectorAll('button').forEach((x) => x.setAttribute('aria-checked', String(x === b))); });
      return b;
    }));

  const provBanner = !t.complete && h('div', { class: 'provisional' }, h('b', null, 'PROVISIONAL · HISTORY STILL BEING READ'),
    h('span', null, 'Identities that came in during the unread part are not in the draft yet. It cannot be approved until the read is complete.'));
  const head = h('header', { class: 'head' },
    h('div', null, h('div', { class: 'eyebrow' }, 'RECOMMENDATION · TRUST'), h('h1', null, 'Specific trust draft'),
      h('div', { class: 'row' }, riskBadge(r.risk), h('span', { class: 'small muted' }, t.roots.length
        ? `Trusts ${accounts.length === 1 ? 'a whole account' : `${accounts.length} whole accounts`}: ${accounts.join(', ')}`
        : 'Trusts no whole account'))),
    canRec && t.roots.length > 0 && h('div', { class: 'actions' }, styleSeg, draftBtn));

  if (!t.roots.length) {
    return h('div', { class: 'stack-lg' }, head, h('div', { class: 'card empty' }, 'This role\'s trust policy names no whole account (no :root and no bare account ID), so there is nothing to narrow here. ',
      h('a', { href: `#/trust?q=${encodeURIComponent(`roleid:${r.id}`)}` }, 'Its ways in are on the Trust map.')));
  }

  // ---- who came in
  const callerRows = t.callers.map((c) => {
    const [label, cls, why] = (NAMED[c.kind] || NAMED.merged)(c);
    const can = canRec && c.kind !== 'merged';
    const box = h('input', { type: 'checkbox', checked: !left.has(c.key), disabled: !can, 'aria-label': `Keep ${c.name || c.uid || c.display}` });
    box.addEventListener('change', () => { if (box.checked) left.delete(c.key); else left.add(c.key); count(); });
    const stale = c.lastSeen && Date.now() - new Date(c.lastSeen) > 60 * 864e5;
    return h('tr', null,
      h('td', null, box),
      h('td', null, h('div', null, c.name || c.uid || c.display), h('div', { class: 'tiny muted mono' }, c.arn || c.display), c.namedFromId && h('div', { class: 'tiny muted' }, `named from ID ${c.namedFromId}`)),
      h('td', { class: 'small' }, KIND_LABEL[c.kind], h('div', { class: 'tiny muted mono' }, c.account || '—')),
      h('td', null, h('span', { class: `badge ${cls}`, title: why }, label)),
      h('td', { class: 'small nowrap' }, num(c.sessions), h('div', { class: 'tiny muted' }, c.via)),
      h('td', { class: 'small nowrap' }, c.lastSeen ? ago(c.lastSeen) : '—', stale && h('div', { class: 'tiny', style: 'color:#f0b45a' }, 'quiet 60+ days')));
  });
  const leftNote = h('span', { class: 'small muted' });
  const count = () => { leftNote.textContent = left.size ? `${left.size} left out: ${left.size === 1 ? 'it loses' : 'they lose'} access when the draft is applied.` : 'Everyone seen stays in.'; };
  count();
  const callersCard = h('section', { class: 'card' },
    h('div', { class: 'card-h' }, h('div', null, h('h2', null, 'Who came in'), h('p', { class: 'small muted' },
      `Every identity seen assuming this role through a whole-account principal, from ${r.account_name}'s own CloudTrail${t.windowDays ? ` (${t.windowDays} days read)` : ''}. Untick one to leave it out.`)),
      h('span', { class: 'badge b-neutral' }, `${t.callers.length} seen`)),
    h('div', { class: 'card-b stack' },
      t.callers.length ? h('div', { class: 'scroll' }, h('table', null,
        h('thead', null, h('tr', null, h('th', null, 'Keep'), h('th', null, 'Identity'), h('th', null, 'Kind · account'), h('th', null, 'Named by'), h('th', null, 'Sessions'), h('th', null, 'Last seen'))),
        h('tbody', null, callerRows)))
        : h('p', { class: 'small muted' }, t.complete ? 'Nobody came in through a whole-account principal in the history read. The draft removes them.' : 'Nobody seen yet in the part of the history read so far.'),
      t.callers.length > 0 && h('div', { class: 'row' }, leftNote, h('span', { class: 'grow' }), canRec && rec && h('button', { class: 'btn sm', onClick: (e) => make(e.currentTarget) }, 'Draft again with these'))));

  if (!rec) return h('div', { class: 'stack-lg' }, head, provBanner, callersCard, h('div', { class: 'card empty' }, 'No draft yet. Pick who stays above, then Draft from history.'));

  // ---- the draft
  const failed = rec.checks.some((c) => c.status === 'fail');
  const approvedTeams = new Set(rec.approvals.map((a) => a.team));
  const waiting = rec.requiredTeams.filter((x) => !approvedTeams.has(x));
  const canApprove = session.user.permissions.includes('approve') && rec.status === 'draft' && !rec.stale && !failed && t.complete && session.user.team && waiting.includes(session.user.team);
  const acc = rec.accounts;
  const json = (o) => JSON.stringify(o, null, 2);
  return h('div', { class: 'stack-lg' }, head, provBanner,
    rec.stale && h('div', { class: 'alert warn' }, rec.staleWhy === 'trust' ? 'The role\'s trust policy changed after this draft was made, so it cannot be approved. Draft it again.'
      : `${rec.newCallers.length === 1 ? 'An identity' : `${rec.newCallers.length} identities`} came in after this draft was made (${rec.newCallers.map((c) => c.name || c.uid || c.display).join(', ')}). Draft again so ${rec.newCallers.length === 1 ? 'it is' : 'they are'} in it, or left out on purpose.`),
    rec.status === 'approved' && h('div', { class: 'alert ok' }, 'Approved. Apply the trust policy below (update-assume-role-policy). Curious Monkey does not change your AWS account.'),
    callersCard,
    h('section', { class: 'card' }, h('div', { class: 'card-h' },
      h('div', { class: 'row' }, h('span', { class: 'badge b-banana' }, 'From event history'), h('span', { class: 'badge b-neutral' }, rec.style === 'principal' ? 'Named in Principal' : 'aws:PrincipalArn'), h('span', { class: 'small muted' }, ago(rec.created_at))),
      h('div', { class: 'row' }, ['json', 'terraform', 'cli'].map((f) => h('button', { class: 'btn sm', onClick: () => exportIt(rec, f) }, `Export ${f === 'json' ? 'JSON' : f === 'cli' ? 'AWS CLI' : 'Terraform'}`)))),
      h('div', { class: 'card-b stack' }, rec.summary && h('p', null, rec.summary),
        h('div', { class: 'tiles' },
          tile('Whole accounts narrowed', num(acc.filter((a) => a.outcome === 'narrowed').length)), tile('Removed', num(acc.filter((a) => a.outcome === 'removed').length), 'nobody came in'),
          tile('Identities kept', num(acc.reduce((n, a) => n + a.kept, 0))), tile('Left out', num(rec.excluded.length), rec.excluded.length ? 'lose access' : null),
          tile('Size', `${JSON.stringify(rec.policy).length}`, 'of 2,048 characters')),
        h('ul', { class: 'plain stack', style: 'gap:4px' }, rec.changes.map((c) => { const [l, k] = CHANGE[c.kind] || [c.kind, '']; return h('li', { class: 'small' }, h('span', { class: `tm2-chip ${k}` }, l), ' ', h('span', { class: 'muted' }, `${c.statement}: `), c.text); })))),
    h('section', { class: 'card' }, h('div', { class: 'card-h' }, h('h2', null, 'Safety checks'), failed ? h('span', { class: 'badge b-high' }, 'Cannot be approved') : h('span', { class: 'badge b-green' }, 'All required checks pass')),
      h('div', { class: 'card-b' }, rec.checks.map((c) => h('div', { class: 'check' }, h('span', { class: `ic ${c.status}`, 'aria-hidden': 'true' }, { pass: '✓', fail: '✕', warn: '!', skipped: '–' }[c.status]),
        h('div', null, h('div', { class: 'name' }, c.label, h('span', { class: 'sr' }, ` ${c.status}`)), c.detail && h('div', { class: 'small muted' }, c.detail)))))),
    h('section', { class: 'card' }, h('div', { class: 'card-h' }, h('h2', null, 'Trust policy'), h('button', { class: 'btn sm', onClick: () => copy(json(rec.policy)) }, 'Copy the draft')),
      h('div', { class: 'card-b' }, h('div', { class: 'tm2-diff' }, h('div', null, h('div', { class: 'tm2-cap' }, 'NOW'), h('pre', { class: 'code' }, json(rec.before))),
        h('div', null, h('div', { class: 'tm2-cap' }, 'DRAFT'), h('pre', { class: 'code' }, json(rec.policy)))))),
    h('section', { class: 'card' }, h('div', { class: 'card-h' }, h('h2', null, 'Approval'), h('span', { class: 'small muted' }, r.requires_both ? 'High risk: both security teams must approve.' : `Reviewed by ${TEAM[r.reviewer_team]}.`)),
      h('div', { class: 'card-b stack' },
        h('div', { class: 'row' }, rec.requiredTeams.map((x) => h('span', { class: `badge ${approvedTeams.has(x) ? 'b-green' : 'b-neutral'}` }, `${TEAM[x]}: ${approvedTeams.has(x) ? `approved by ${rec.approvals.find((a) => a.team === x)?.name || 'someone'}` : 'waiting'}`))),
        canApprove ? h('button', { class: 'btn primary', onClick: async (e) => { e.currentTarget.disabled = true; try { const o = await post(`/trust-recommendations/${rec.id}/approve`); toast(o.approved ? 'Approved' : `Recorded. Waiting for ${o.waitingFor.map((x) => TEAM[x]).join(' and ')}.`); ctx.reload(); } catch (x) { toast(x.message, true); e.currentTarget.disabled = false; } } }, `Approve as ${TEAM[session.user.team]}`)
          : h('p', { class: 'small muted' }, rec.status === 'approved' ? `Approved ${fmtDay(rec.approvals.at(-1)?.approved_at)}.` : failed ? 'Fix the failing checks first.' : rec.stale ? 'Draft again first.' : !t.complete ? 'Waiting for the history read to finish.'
            : !session.user.permissions.includes('approve') ? 'Your role cannot approve.' : !session.user.team ? 'Only members of a security team can approve.' : 'Your team has no approval to give on this role.'))));
}

async function exportIt(rec, format) {
  try {
    const out = await get(`/trust-recommendations/${rec.id}/export?format=${format}`);
    const text = typeof out === 'string' ? out : JSON.stringify(out, null, 2);
    modal(format === 'cli' ? 'AWS CLI' : format === 'terraform' ? 'Terraform' : 'Trust policy JSON', h('div', { class: 'stack' }, rec.status !== 'approved' && h('div', { class: 'alert warn' }, 'Not approved yet. Treat this as a draft.'), h('pre', null, text)),
      h('div', { class: 'actions' }, h('button', { class: 'btn primary', onClick: () => copy(text) }, 'Copy'), h('button', { class: 'btn', onClick: (e) => e.target.closest('.modal-bg').remove() }, 'Close')));
  } catch (e) { toast(e.message, true); }
}
