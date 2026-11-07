import { h, get, post, num, ago, toast, copy, modal, TEAM, riskBadge } from '../lib.js';
import { session } from '../main.js';

const SOURCE = { ai: ['AI draft', 'b-banana'], rules: ['Rules draft', 'b-neutral'], 'rules-fallback': ['Rules draft (AI fell back)', 'b-medium'] };

export async function recommendationPage(ctx, roleId) {
  const [d, rec] = await Promise.all([get(`/roles/${roleId}`), get(`/roles/${roleId}/recommendation`)]);
  const r = d.role;
  const instruction = h('textarea', { placeholder: 'Optional. For example: keep read access to the payments bucket, drop everything that writes to DynamoDB.', 'aria-label': 'Instruction for the drafter', maxlength: '600' });
  const make = (useAi) => async (e) => {
    const b = e.currentTarget; b.disabled = true; b.textContent = 'Drafting…';
    try { await post(`/roles/${roleId}/recommend`, { instruction: instruction.value || undefined, useAi }); ctx.reload(); } catch (x) { toast(x.message, true); b.disabled = false; b.textContent = useAi ? 'Draft with AI' : 'Draft with rules only'; }
  };
  const canRec = session.user.permissions.includes('recommend');
  ctx.setCrumbs(h('a', { href: '#/roles' }, 'Roles'), h('a', { href: `#/roles/${roleId}` }, r.name), 'Recommendation');
  const hist = d.history || { complete: true };
  const provBanner = !hist.complete && h('div', { class: 'provisional' }, h('b', null, `PROVISIONAL · ${hist.progress}% OF HISTORY READ`),
    h('span', null, 'This draft is built from the history read so far. Calls in the unread part may still need permissions it removes, so it cannot be approved until history is complete.'));
  const head = h('header', { class: 'head' },
    h('div', null, h('div', { class: 'eyebrow' }, 'RECOMMENDATION'),
      h('h1', null, 'Least-privilege draft'), h('div', { class: 'row' }, riskBadge(r.risk), h('span', { class: 'small muted' }, `${num(r.granted_count)} granted, ${num(r.used_count)} used`))),
    canRec && h('div', { class: 'actions' }, h('button', { class: 'btn', onClick: make(false) }, 'Draft with rules only'), h('button', { class: 'btn primary', onClick: make(undefined) }, 'Draft with AI')));
  const ask = canRec && h('section', { class: 'card' }, h('div', { class: 'card-b stack' }, h('label', { class: 'label' }, 'Tell the drafter what you want', instruction),
    h('p', { class: 'small muted' }, 'The drafter can only keep or narrow access. Anything that adds access, uses a service-wide wildcard, or would break calls seen in the window is rejected before you see it.')));

  if (!rec) return h('div', { class: 'stack-lg' }, head, provBanner, ask, h('div', { class: 'card empty' }, 'No draft yet. Create one with the buttons above.'));

  const [label, cls] = SOURCE[rec.source] || [rec.source, 'b-neutral'];
  const failed = rec.checks.some((c) => c.status === 'fail');
  const approvedTeams = new Set(rec.approvals.map((a) => a.team));
  const waiting = rec.requiredTeams.filter((t) => !approvedTeams.has(t));
  const canApprove = session.user.permissions.includes('approve') && rec.status === 'draft' && !rec.stale && !failed && hist.complete && session.user.team && waiting.includes(session.user.team);

  const diff = rec.diff;
  const held = diff.heldBack;
  return h('div', { class: 'stack-lg' }, head, provBanner, ask,
    rec.stale && h('div', { class: 'alert warn' }, 'This role changed after the draft was made, so it cannot be approved. Draft it again.'),
    rec.status === 'approved' && h('div', { class: 'alert ok' }, 'Approved. Apply the policy below and remove the old ones. Curious Monkey does not change your AWS account.'),
    h('section', { class: 'card' }, h('div', { class: 'card-h' }, h('div', { class: 'row' }, h('span', { class: `badge ${cls}` }, label), rec.model && h('span', { class: 'small muted mono' }, rec.model), h('span', { class: 'small muted' }, ago(rec.created_at))),
      h('div', { class: 'row' }, h('button', { class: 'btn sm', onClick: () => exportIt(rec, 'json') }, 'Export JSON'), h('button', { class: 'btn sm', onClick: () => exportIt(rec, 'terraform') }, 'Export Terraform'))),
      h('div', { class: 'card-b stack' }, rec.summary && h('p', null, rec.summary), rec.instruction && h('p', { class: 'small muted' }, `Your instruction: “${rec.instruction}”`),
        h('div', { class: 'tiles' }, tile('Kept', num(diff.kept)), tile('Removed', num(diff.removedCount)), tile('Resources narrowed', num(diff.narrowedCount)),
          tile('Policies', String(rec.policies.length), rec.policies.map((p) => `${p.size} chars`).join(', ')),
          held?.count > 0 && heldTile(held, roleId)),
        diff.removedCount > 0 && h('p', { class: 'small muted' }, 'Removed by service: ', Object.entries(diff.removedByService).sort((a, b) => b[1] - a[1]).slice(0, 12).map(([s, n]) => `${s} (${num(n)})`).join(', ')))),
    h('section', { class: 'card' }, h('div', { class: 'card-h' }, h('h2', null, 'Safety checks'), failed ? h('span', { class: 'badge b-high' }, 'Cannot be approved') : h('span', { class: 'badge b-green' }, 'All required checks pass')),
      h('div', { class: 'card-b' }, rec.checks.map((c) => h('div', { class: 'check' }, h('span', { class: `ic ${c.status}`, 'aria-hidden': 'true' }, { pass: '✓', fail: '✕', warn: '!', skipped: '–' }[c.status]),
        h('div', null, h('div', { class: 'name' }, c.label, h('span', { class: 'sr' }, ` ${c.status}`)), c.detail && h('div', { class: 'small muted' }, c.detail)))))),
    rec.policies.map((p) => h('section', { class: 'card' }, h('div', { class: 'card-h' }, h('h2', { class: 'mono' }, p.name), h('button', { class: 'btn sm', onClick: () => copy(JSON.stringify(p.document, null, 2)) }, 'Copy')),
      h('div', { class: 'card-b' }, h('pre', null, JSON.stringify(p.document, null, 2))))),
    diff.removedSample?.length > 0 && h('section', { class: 'card' }, h('div', { class: 'card-h' }, h('h2', null, 'Removed permissions'), h('span', { class: 'small muted' }, `Showing ${diff.removedSample.length} of ${num(diff.removedCount)}`)),
      h('div', { class: 'card-b' }, h('div', { class: 'acts' }, diff.removedSample.map((a) => h('code', null, a))))),
    h('section', { class: 'card' }, h('div', { class: 'card-h' }, h('h2', null, 'Approval'), h('span', { class: 'small muted' }, r.requires_both ? 'High risk: both security teams must approve.' : `Reviewed by ${TEAM[r.reviewer_team]}.`)),
      h('div', { class: 'card-b stack' },
        h('div', { class: 'row' }, rec.requiredTeams.map((t) => h('span', { class: `badge ${approvedTeams.has(t) ? 'b-green' : 'b-neutral'}` }, `${TEAM[t]}: ${approvedTeams.has(t) ? `approved by ${rec.approvals.find((a) => a.team === t)?.name || 'someone'}` : 'waiting'}`))),
        canApprove ? h('button', { class: 'btn primary', style: null, onClick: async (e) => { e.currentTarget.disabled = true; try { const o = await post(`/recommendations/${rec.id}/approve`); toast(o.approved ? 'Approved' : `Recorded. Waiting for ${o.waitingFor.map((t) => TEAM[t]).join(' and ')}.`); ctx.reload(); } catch (x) { toast(x.message, true); e.currentTarget.disabled = false; } } }, `Approve as ${TEAM[session.user.team]}`)
          : h('p', { class: 'small muted' }, rec.status === 'approved' ? 'Nothing left to approve.' : failed ? 'Fix the failing checks first.' : rec.stale ? 'Draft again first.' : !hist.complete ? `Waiting for history: ${hist.progress}% read.` : !session.user.permissions.includes('approve') ? 'Your role cannot approve.' : !session.user.team ? 'Only members of a security team can approve.' : 'Your team has no approval to give on this role.'))));
}
function heldTile(held, roleId) {
  return h('div', { class: 'tile warn' }, h('span', { class: 'small', style: 'color:#f0b45a' }, 'Held back · unidentified'), h('b', null, num(held.count)),
    h('span', { class: 'tiny muted' }, `kept in ${held.services.slice(0, 3).join(', ')}${held.services.length > 3 ? '…' : ''} until event names are settled`),
    h('a', { class: 'tiny', href: `#/roles/${roleId}?identify=` }, 'Identify them'));
}
const tile = (l, v, s) => h('div', { class: 'tile' }, h('span', { class: 'small muted' }, l), h('b', null, v), s && h('span', { class: 'tiny muted' }, s));

async function exportIt(rec, format) {
  try {
    const out = await get(`/recommendations/${rec.id}/export?format=${format}`);
    const text = format === 'terraform' ? out : JSON.stringify(out, null, 2);
    modal(format === 'terraform' ? 'Terraform' : 'Policy JSON', h('div', { class: 'stack' }, rec.status !== 'approved' && h('div', { class: 'alert warn' }, 'Not approved yet. Treat this as a draft.'), h('pre', null, text)),
      h('div', { class: 'actions' }, h('button', { class: 'btn primary', onClick: () => copy(text) }, 'Copy'), h('button', { class: 'btn', onClick: (e) => e.target.closest('.modal-bg').remove() }, 'Close')));
  } catch (e) { toast(e.message, true); }
}
