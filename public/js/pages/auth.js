import { h, svg, post, get, field, toast, setCsrf, copy } from '../lib.js';
import { session, go, mark } from '../main.js';
const logo = () => mark(28);

const artPanel = () => h('aside', { class: 'auth-art' }, radarArt(),
  h('h2', null, 'Every role on one radar. ', h('span', null, 'Keep the banana, drop the bazooka.')));

/** Decorative: a sweep passing over a used permission (banana) and a never-called admin grant (red). */
function radarArt() {
  const still = matchMedia('(prefers-reduced-motion: reduce)').matches;
  const ring = (r, dash) => svg('circle', { cx: 300, cy: 300, r, fill: 'none', stroke: '#1f4a35', 'stroke-dasharray': dash ? '3 6' : null });
  return svg('svg', { viewBox: '0 0 600 600', 'aria-hidden': 'true' },
    svg('defs', null, svg('radialGradient', { id: 'aw', cx: 0, cy: 0, r: 260, gradientUnits: 'userSpaceOnUse' }, svg('stop', { offset: 0, 'stop-color': '#f6e016', 'stop-opacity': 0.28 }), svg('stop', { offset: 1, 'stop-color': '#f6e016', 'stop-opacity': 0.02 }))),
    svg('circle', { cx: 300, cy: 300, r: 270, fill: '#051209', stroke: '#1f4a35' }), ring(200, true), ring(130, true), ring(60, true),
    svg('path', { d: 'M30 300 H570 M300 30 V570', stroke: '#16392a' }),
    [[180, 210, 2], [400, 180, 1.6], [420, 380, 1.6], [230, 420, 1.6], [350, 470, 1.4], [140, 330, 1.4], [470, 280, 1.4], [260, 140, 1.4]].map(([x, y, r]) => svg('circle', { cx: x, cy: y, r, fill: '#5f8c73' })),
    svg('g', { transform: 'translate(300 300)' }, svg('g', null,
      svg('path', { d: 'M0 0 L260 0 A260 260 0 0 0 225 -130 Z', fill: 'url(#aw)' }), svg('path', { d: 'M0 0 L260 0', stroke: '#f6e016', 'stroke-width': 2.5 }),
      !still && svg('animateTransform', { attributeName: 'transform', type: 'rotate', from: '0', to: '360', dur: '6s', repeatCount: 'indefinite' }))),
    svg('circle', { cx: 360, cy: 250, r: 7, fill: '#f6e016' }), svg('circle', { cx: 360, cy: 250, r: 16, fill: 'none', stroke: '#f6e016', class: 'blink' }),
    svg('text', { x: 382, y: 248, fill: '#f6e016', 'font-family': 'Geist Mono, monospace', 'font-size': 14 }, 'ec2:DescribeInstances'),
    svg('text', { x: 382, y: 266, fill: '#a9bfb2', 'font-size': 12 }, 'called 2,140 times'),
    svg('path', { d: 'M196 470 l12 12 M208 470 l-12 12', stroke: '#ff6b5e', 'stroke-width': 2.5 }),
    svg('text', { x: 218, y: 482, fill: '#ff6b5e', 'font-family': 'Geist Mono, monospace', 'font-size': 14 }, 'AdministratorAccess'),
    svg('text', { x: 218, y: 500, fill: '#a9bfb2', 'font-size': 12 }, 'never called · 90 days'));
}

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
