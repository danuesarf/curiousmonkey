import { h, get, post, api, fmtDate, ago, toast, copy, field, modal, ROLE_LABEL, TEAM } from '../lib.js';
import { session } from '../main.js';

const MATRIX = [['View roles and findings', ['view'], 'owner admin reviewer account_owner auditor'], ['Start a scan', ['scan'], 'owner admin reviewer account_owner'], ['Connect accounts', ['accounts'], 'owner admin'],
  ['Decide on findings', ['decide'], 'owner admin reviewer'], ['Draft policies', ['recommend'], 'owner admin reviewer account_owner'], ['Approve policies', ['approve'], 'owner reviewer'],
  ['Export policies', ['export'], 'owner admin reviewer account_owner'], ['Manage members', ['members'], 'owner admin'], ['Read audit log', ['audit'], 'owner admin auditor'], ['Single sign-on mappings', ['sso'], 'owner']];

export async function membersPage(ctx) {
  const [m, a] = await Promise.all([get('/members'), get('/accounts')]);
  const isOwner = session.user.role === 'owner';
  const sso = isOwner ? await get('/sso/mappings') : null;
  const accts = a.items;
  const scopeLabel = (ids) => (ids ? ids.map((i) => accts.find((x) => x.id === i)?.name || 'unknown').join(', ') : 'All accounts');

  const invite = () => {
    const email = h('input', { type: 'email', required: true }), role = h('select', null, Object.keys(ROLE_LABEL).filter((r) => isOwner || r !== 'owner').map((r) => h('option', { value: r }, ROLE_LABEL[r])));
    const team = h('select', null, [['', 'No team'], ...Object.entries(TEAM)].map(([v, l]) => h('option', { value: v }, l)));
    const scope = h('select', { multiple: true, size: Math.min(accts.length + 1, 5), 'aria-label': 'Accounts this person can see' }, accts.map((x) => h('option', { value: x.id }, x.name)));
    const err = h('div', { class: 'err' });
    const m1 = modal('Invite a member', h('form', { class: 'stack', onSubmit: async (e) => {
      e.preventDefault(); err.textContent = '';
      try { const picked = [...scope.selectedOptions].map((o) => o.value);
        const r = await post('/members/invite', { email: email.value, role: role.value, team: team.value || null, scope_accounts: picked.length ? picked : null });
        m1.remove(); modal('Invite link', h('div', { class: 'stack' }, h('p', null, `Send this link to ${r.email}. It works once and expires in ${r.expiresInDays} days. Curious Monkey does not send email.`), h('pre', null, r.link)),
          h('div', { class: 'actions' }, h('button', { class: 'btn primary', onClick: () => copy(r.link) }, 'Copy link'), h('button', { class: 'btn', onClick: (ev) => { ev.target.closest('.modal-bg').remove(); ctx.reload(); } }, 'Done'))); } catch (x) { err.textContent = x.message; }
    } }, field('Email', email), field('Role', role), field('Review team', team, 'Required for security reviewers. Decides which approvals they can give.'), field('Accounts they can see', scope, 'Leave empty for all accounts.'), err, h('button', { class: 'btn primary', type: 'submit' }, 'Create invite')), h('span'));
  };
  // Owners only: a single-use link the member opens to choose a new password. Shown once, not emailed.
  const reset = (u) => {
    const mfa = h('input', { type: 'checkbox' });
    const err = h('div', { class: 'err', role: 'alert' });
    const m3 = modal(`Reset password for ${u.name}`, h('form', { class: 'stack', onSubmit: async (e) => { e.preventDefault(); err.textContent = '';
      try {
        const r = await post(`/members/${u.id}/reset-password`, { resetMfa: mfa.checked });
        m3.remove();
        const box = modal('Reset link ready', h('div', { class: 'stack' },
          h('p', null, `Send this to ${r.email} yourself, over a channel you trust. It works once and expires in ${r.expiresInHours} hours. Their current password keeps working until they use it.`),
          r.resetMfa && h('p', { class: 'small muted' }, 'Using it also resets their two-factor sign-in.'),
          h('input', { readonly: true, value: r.link, onFocus: (ev) => ev.target.select(), 'aria-label': 'Reset link' }),
          h('p', { class: 'small muted' }, 'This is the only time the link is shown. Making a new one cancels this one.'),
          h('div', { class: 'actions' }, h('button', { class: 'btn primary', type: 'button', onClick: () => copy(r.link) }, 'Copy link'), h('button', { class: 'btn', type: 'button', onClick: () => box.remove() }, 'Done'))), h('span'));
      } catch (x) { err.textContent = x.message; } } },
      h('p', null, `Creates a link ${u.email} opens to choose a new password. Nothing changes until they use it; then all their sessions are signed out.`),
      h('label', { class: 'row' }, mfa, h('span', null, 'Also reset their two-factor sign-in (they lost their authenticator app)')),
      err, h('button', { class: 'btn primary', type: 'submit' }, 'Create reset link')), h('span'));
  };
  const edit = (u) => {
    const role = h('select', null, Object.keys(ROLE_LABEL).map((r) => h('option', { value: r, selected: r === u.role }, ROLE_LABEL[r])));
    const team = h('select', null, [['', 'No team'], ...Object.entries(TEAM)].map(([v, l]) => h('option', { value: v, selected: v === (u.team || '') }, l)));
    const scope = h('select', { multiple: true, size: Math.min(accts.length + 1, 5) }, accts.map((x) => h('option', { value: x.id, selected: u.scope_accounts?.includes(x.id) }, x.name)));
    const err = h('div', { class: 'err' });
    const m2 = modal(`Edit ${u.name}`, h('form', { class: 'stack', onSubmit: async (e) => { e.preventDefault();
      try { const picked = [...scope.selectedOptions].map((o) => o.value); await api('PATCH', `/members/${u.id}`, { role: role.value, team: team.value || null, scope_accounts: picked.length ? picked : null }); m2.remove(); toast('Saved. Their sessions were ended.'); ctx.reload(); } catch (x) { err.textContent = x.message; } } },
      field('Role', role), field('Review team', team), field('Accounts', scope, 'Leave empty for all accounts.'), err, h('button', { class: 'btn primary', type: 'submit' }, 'Save')), h('span'));
  };

  return h('div', { class: 'stack-lg' },
    h('header', { class: 'head' }, h('div', null, h('h1', null, 'Members and roles'), h('p', { class: 'muted' }, 'Roles decide what someone can do. The review team decides which approvals they can give. Both can be limited to some accounts.')),
      h('button', { class: 'btn primary', onClick: invite }, 'Invite a member')),
    h('section', { class: 'card' }, h('div', { class: 'scroll' }, h('table', null,
      h('thead', null, h('tr', null, ['Member', 'Role', 'Review team', 'Accounts', 'Two-factor', 'Last sign-in', ''].map((x) => h('th', null, x)))),
      h('tbody', null, m.members.map((u) => h('tr', null, h('td', null, h('div', { class: 'name' }, u.name), h('div', { class: 'tiny muted' }, u.email, u.sso ? ' · SSO' : '')),
        h('td', null, ROLE_LABEL[u.role], u.disabled && h('span', { class: 'badge b-high' }, 'disabled')), h('td', null, u.team ? TEAM[u.team] : '—'), h('td', { class: 'small' }, scopeLabel(u.scope_accounts)),
        h('td', null, u.totp_confirmed ? h('span', { class: 'badge b-green' }, 'on') : u.sso ? 'via SSO' : h('span', { class: 'badge b-medium' }, 'not set up')), h('td', { class: 'small' }, ago(u.last_login_at)),
        h('td', { class: 'right' }, h('div', { class: 'row' }, h('button', { class: 'btn sm', onClick: () => edit(u) }, 'Edit'),
          isOwner && !u.sso && !u.disabled && h('button', { class: 'btn sm', title: 'Make a single-use link to choose a new password', onClick: () => reset(u) }, 'Reset password'),
          h('button', { class: 'btn sm', onClick: async () => { await api('PATCH', `/members/${u.id}`, { disabled: !u.disabled }); ctx.reload(); } }, u.disabled ? 'Enable' : 'Disable')))))))),
      m.invites.length > 0 && h('div', { class: 'card-b' }, h('h3', null, 'Pending invites'), h('ul', { class: 'plain' }, m.invites.map((i) => h('li', { class: 'small' }, `${i.email} as ${ROLE_LABEL[i.role]}, expires ${fmtDate(i.expires_at)}`))))),
    h('section', { class: 'card' }, h('div', { class: 'card-h' }, h('h2', null, 'What each role can do')), h('div', { class: 'scroll' }, h('table', null,
      h('thead', null, h('tr', null, h('th', null, 'Permission'), Object.keys(ROLE_LABEL).map((r) => h('th', null, ROLE_LABEL[r])))),
      h('tbody', null, MATRIX.map(([label, , who]) => h('tr', null, h('td', null, label), Object.keys(ROLE_LABEL).map((r) => h('td', null, who.split(' ').includes(r) ? h('span', { class: 'badge b-green' }, 'yes') : h('span', { class: 'muted' }, '—')))))))),
      h('div', { class: 'card-b small muted' }, 'Approving also needs a review team. High-risk roles need an approval from both Infrastructure Security and Information Security. Identity Center roles go to Information Security, service-linked roles to Infrastructure Security.')),
    isOwner && ssoCard(sso, ctx));
}

function ssoCard(sso, ctx) {
  const group = h('input', { placeholder: 'IdP group name' }), role = h('select', null, Object.keys(ROLE_LABEL).map((r) => h('option', { value: r }, ROLE_LABEL[r]))), team = h('select', null, [['', 'No team'], ...Object.entries(TEAM)].map(([v, l]) => h('option', { value: v }, l)));
  return h('section', { class: 'card' }, h('div', { class: 'card-h' }, h('h2', null, 'Single sign-on group mappings'), h('span', { class: 'small muted' }, 'OIDC sign-in maps IdP groups to roles. This path has not been tested against a live identity provider.')),
    h('div', { class: 'card-b stack' }, sso.items.length ? h('ul', { class: 'plain' }, sso.items.map((s) => h('li', { class: 'row' }, h('code', null, s.group_name), '→', ROLE_LABEL[s.role], s.team && `, ${TEAM[s.team]}`, h('button', { class: 'btn sm', onClick: async () => { await api('DELETE', `/sso/mappings/${encodeURIComponent(s.group_name)}`); ctx.reload(); } }, 'Remove')))) : h('p', { class: 'muted' }, 'No mappings yet.'),
      h('form', { class: 'row', onSubmit: async (e) => { e.preventDefault(); try { await api('PUT', '/sso/mappings', { group_name: group.value, role: role.value, team: team.value || null }); ctx.reload(); } catch (x) { toast(x.message, true); } } }, group, role, team, h('button', { class: 'btn', type: 'submit' }, 'Add mapping'))));
}
