import { h, post, get, field, toast, setCsrf, copy } from '../lib.js';
import { monkey, logo } from '../art.js';
import { session, go } from '../main.js';

const artPanel = () => h('aside', { class: 'auth-art' },
  h('div', { class: 'row' }, h('span', { class: 'tag bad' }, 'AdministratorAccess'), h('span', { class: 'tag good' }, 'ec2:DescribeInstances')),
  h('h2', null, 'The monkey only needs the banana. Don\'t give it the bazooka.'),
  monkey(),
  h('p', { class: 'small', style: null }, 'Curious Monkey reads CloudTrail to see what each IAM role really does, then drafts the smallest policy that still works.'));

async function afterAuth(res) { session.user = res.user; setCsrf(res.csrf); go('#/'); }

export function signIn(st) {
  const err = h('div', { class: 'err', role: 'alert' });
  const email = h('input', { type: 'email', autocomplete: 'username', required: true });
  const pw = h('input', { type: 'password', autocomplete: 'current-password', required: true });
  const code = h('input', { inputmode: 'numeric', autocomplete: 'one-time-code', maxlength: '6', placeholder: '6-digit code' });
  const codeField = field('Authenticator code', code, 'From your authenticator app.'); codeField.hidden = true;
  const btn = h('button', { class: 'btn primary', type: 'submit' }, 'Sign in');
  const form = h('form', { onSubmit: async (e) => {
    e.preventDefault(); err.textContent = ''; btn.disabled = true;
    try { await afterAuth(await post('/auth/signin', { email: email.value, password: pw.value, code: code.value || undefined })); }
    catch (x) { if (x.code === 'mfa_required') { codeField.hidden = false; code.focus(); err.textContent = ''; } else err.textContent = x.message; }
    finally { btn.disabled = false; }
  } },
    h('div', { class: 'row' }, logo(), h('b', null, 'Curious Monkey')),
    h('h1', null, 'Sign in'), h('p', { class: 'muted' }, st.workspace ? `Workspace: ${st.workspace}` : 'Review what your IAM roles really use.'),
    field('Work email', email), field('Password', pw), codeField, err, btn,
    st.oidc && h('a', { class: 'btn', href: '/api/auth/oidc/login' }, 'Sign in with company SSO'),
    h('p', { class: 'small muted' }, 'New here? Ask a workspace owner for an invite link.'));
  return h('div', { class: 'auth' }, h('div', { class: 'auth-form' }, form), artPanel());
}

export function signUp(params, st) {
  const invite = params.get('invite');
  const first = st.needsSetup;
  const err = h('div', { class: 'err', role: 'alert' });
  const name = h('input', { autocomplete: 'name', required: true });
  const email = h('input', { type: 'email', autocomplete: 'email', required: true });
  const ws = h('input', { required: true, placeholder: 'e.g. KBI Security' });
  const pw = h('input', { type: 'password', autocomplete: 'new-password', required: true, minlength: '12' });
  if (invite) get(`/auth/invite/${invite}`).then((i) => { email.value = i.email; email.readOnly = true; }).catch((e) => { err.textContent = e.message; });
  const btn = h('button', { class: 'btn primary', type: 'submit' }, first ? 'Create workspace' : 'Create account');
  const form = h('form', { onSubmit: async (e) => {
    e.preventDefault(); err.textContent = ''; btn.disabled = true;
    try { await afterAuth(await post('/auth/signup', { name: name.value, email: email.value, password: pw.value, workspaceName: first ? ws.value : undefined, invite: invite || undefined })); }
    catch (x) { err.textContent = x.message; } finally { btn.disabled = false; }
  } },
    h('div', { class: 'row' }, logo(), h('b', null, 'Curious Monkey')),
    h('h1', null, first ? 'Set up your workspace' : 'Join your team'),
    h('p', { class: 'muted' }, first ? 'You will be the owner. Two-factor sign-in is required next.' : 'You were invited to this workspace.'),
    first && field('Workspace name', ws), field('Your name', name), field('Work email', email), field('Password', pw, 'At least 12 characters.'), err, btn,
    !first && h('a', { href: '#/signin' }, 'I already have an account'));
  return h('div', { class: 'auth' }, h('div', { class: 'auth-form' }, form), artPanel());
}

export function mfaSetup() {
  const box = h('div', { class: 'stack' }, h('span', { class: 'spin' }));
  const err = h('div', { class: 'err', role: 'alert' });
  const code = h('input', { inputmode: 'numeric', maxlength: '6', autocomplete: 'one-time-code', placeholder: '6-digit code' });
  post('/auth/mfa/start').then((s) => {
    box.replaceChildren(
      h('p', null, 'Scan this with an authenticator app (1Password, Google Authenticator, Authy).'),
      h('img', { src: s.qr, alt: 'QR code for your authenticator app', width: '220', height: '220' }),
      h('p', { class: 'small muted' }, 'Or enter this key by hand:'), h('code', { class: 'small' }, s.secret),
      h('button', { class: 'btn sm', type: 'button', onClick: () => copy(s.secret) }, 'Copy key'));
  }).catch((e) => { box.replaceChildren(h('div', { class: 'err' }, e.message)); });
  const form = h('form', { onSubmit: async (e) => {
    e.preventDefault(); err.textContent = '';
    try { await post('/auth/mfa/confirm', { code: code.value }); session.user.needsMfaSetup = false; session.user.totpConfirmed = true; toast('Two-factor is on'); go('#/'); location.reload(); }
    catch (x) { err.textContent = x.message; }
  } },
    h('div', { class: 'row' }, logo(), h('b', null, 'Curious Monkey')), h('h1', null, 'Turn on two-factor'),
    h('p', { class: 'muted' }, 'Your role can change what other people are allowed to do, so it needs a second factor.'),
    box, field('Code from the app', code), err, h('button', { class: 'btn primary', type: 'submit' }, 'Confirm and continue'));
  return h('div', { class: 'auth' }, h('div', { class: 'auth-form' }, form), artPanel());
}
