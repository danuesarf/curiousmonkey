import { h, svg, post, get, field, toast, setCsrf, copy, setWorkspaceTimeZone } from '../lib.js';
import { session, go, mark } from '../main.js';
const logo = () => mark(28);

const still = () => matchMedia('(prefers-reduced-motion: reduce)').matches;
const pause = (ms) => new Promise((r) => { setTimeout(r, still() ? 0 : ms); });
const fromMarkup = (m) => document.importNode(new DOMParser().parseFromString(m, 'image/svg+xml').documentElement, true);

// The monkey, in two layers: the head sits behind the form, the paws in front of its top edge.
// Parsed from markup so the light theme leaves his fur alone. No style attributes (CSP).
const HEAD = `<svg xmlns="http://www.w3.org/2000/svg" class="au-head" viewBox="0 0 240 190" aria-hidden="true">
<ellipse cx="120" cy="216" rx="62" ry="66" fill="#8a5a34"/><ellipse cx="120" cy="226" rx="40" ry="46" fill="#f0d2a8"/>
<circle cx="58" cy="102" r="24" fill="#8a5a34"/><circle cx="58" cy="102" r="13" fill="#e8b98a"/>
<circle cx="182" cy="102" r="24" fill="#8a5a34"/><circle cx="182" cy="102" r="13" fill="#e8b98a"/>
<circle cx="120" cy="100" r="60" fill="#8a5a34"/><ellipse cx="120" cy="118" rx="44" ry="34" fill="#f0d2a8"/>
<ellipse cx="101" cy="90" rx="19" ry="21" fill="#f0d2a8"/><ellipse cx="139" cy="90" rx="19" ry="21" fill="#f0d2a8"/>
<g class="au-pupils"><circle cx="101" cy="91" r="6.5" fill="#0d2a1c"/><circle cx="139" cy="91" r="6.5" fill="#0d2a1c"/><circle cx="103.5" cy="88.5" r="2.2" fill="#ffffff"/><circle cx="141.5" cy="88.5" r="2.2" fill="#ffffff"/></g>
<g class="au-brows" fill="none" stroke="#5a3a20" stroke-width="2.5" stroke-linecap="round"><path d="M92 74 q10 -7 20 -1"/><path d="M130 72 q10 -6 20 2"/></g>
<circle cx="115" cy="112" r="2.4" fill="#5a3a20"/><circle cx="126" cy="112" r="2.4" fill="#5a3a20"/>
<path d="M94 126 Q120 158 146 126 Q120 136 94 126 Z" fill="#6b2f1f"/><path d="M106 138 Q120 148 134 138" stroke="#e07a6a" stroke-width="4" fill="none" stroke-linecap="round"/>
</svg>`;
const HANDS = `<svg xmlns="http://www.w3.org/2000/svg" class="au-hands" viewBox="0 0 240 190" aria-hidden="true">
<defs><clipPath id="au-edge"><rect x="-60" y="-120" width="360" height="249"/></clipPath></defs>
<g clip-path="url(#au-edge)" stroke="#8a5a34" stroke-width="20" stroke-linecap="round"><path class="au-arm au-l" d="M56 136 V236"/><path class="au-arm au-r" d="M184 136 V236"/></g>
<g class="au-paw au-l"><ellipse cx="56" cy="130" rx="21" ry="15" fill="#e8b98a"/><path d="M47 124 v9 M56 122 v11 M65 124 v9" stroke="#c99a6e" stroke-width="2" stroke-linecap="round"/></g>
<g class="au-paw au-r"><ellipse cx="184" cy="130" rx="21" ry="15" fill="#e8b98a"/><path d="M175 124 v9 M184 122 v11 M193 124 v9" stroke="#c99a6e" stroke-width="2" stroke-linecap="round"/></g>
</svg>`;

/** Decorative radar behind the form. The sweep lights each blip as it passes (delays match its 6 s turn).
 *  Banana: a permission in use. Red: an admin grant never called, which drops off when you sign in. Amber: unknown. */
function radar() {
  const ring = (r, cls) => svg('circle', { cx: 800, cy: 800, r, class: cls });
  const mono = (x, y, cls, text) => svg('text', { x, y, class: `au-mono ${cls}` }, text);
  const note = (x, y, text) => svg('text', { x, y, class: 'au-note' }, text);
  const dots = [[470, 520, 3], [1010, 380, 2.5], [1290, 760, 2.5], [560, 1180, 2.5], [930, 1270, 2.2], [330, 760, 2.2], [1080, 1210, 2.2], [640, 330, 2.2], [1330, 430, 2.2], [240, 1120, 2.2]];
  return svg('svg', { class: 'au-radar', viewBox: '0 0 1600 1600', 'aria-hidden': 'true' },
    svg('defs', null, svg('radialGradient', { id: 'au-glow', cx: 800, cy: 800, r: 700, gradientUnits: 'userSpaceOnUse' },
      svg('stop', { offset: 0, class: 'au-stop', 'stop-opacity': 0.26 }), svg('stop', { offset: 1, class: 'au-stop', 'stop-opacity': 0.02 }))),
    ring(700, 'au-disc'), [560, 420, 280, 140].map((r) => ring(r, 'au-ring')),
    svg('path', { d: 'M100 800 H1500 M800 100 V1500', class: 'au-cross' }),
    svg('g', { class: 'au-dots' }, dots.map(([cx, cy, r]) => svg('circle', { cx, cy, r }))),
    ring(700, 'au-pulse'),
    svg('g', { class: 'au-sweep' }, svg('path', { d: 'M800 800 L1500 800 A700 700 0 0 0 1406.2 450 Z', fill: 'url(#au-glow)' }), svg('path', { d: 'M800 800 L1500 800', class: 'au-beam' })),
    svg('g', { class: 'au-blip au-kept', style: '--d:-0.54s' },
      svg('circle', { cx: 1130, cy: 590, r: 7, class: 'au-banana' }), svg('circle', { cx: 1130, cy: 590, r: 16, class: 'au-echo' }),
      mono(1154, 588, 'au-yes', 'ec2:DescribeInstances'), note(1154, 606, 'called 2,140 times')),
    svg('g', { class: 'au-blip', style: '--d:-3.27s' }, svg('g', { class: 'au-bazooka' },
      svg('path', { d: 'M272 942 l16 16 M288 942 l-16 16', class: 'au-x' }),
      mono(302, 948, 'au-no', 'AdministratorAccess'), note(302, 966, 'never called in 90 days'))),
    svg('g', { class: 'au-blip au-unknown', style: '--d:-5.42s' },
      svg('circle', { cx: 1160, cy: 1050, r: 6.5, class: 'au-hollow' }), svg('circle', { cx: 1160, cy: 1050, r: 16, class: 'au-echo' }),
      mono(1184, 1048, 'au-maybe', 'kms:Decrypt'), note(1184, 1066, 'not visible in event history')));
}

/** The page every sign-in screen shares: the radar, the monkey peeking over the form, and his moods.
 *  watch(input, 'read' | 'secret') makes him read along or cover his eyes; busy / ok / fail / idle follow a submit. */
function stage(form) {
  form.classList.add('au-panel');
  const head = fromMarkup(HEAD), hands = fromMarkup(HANDS);
  const root = h('div', { class: 'au' }, radar(), h('div', { class: 'au-mid' }, head, form, hands), h('p', { class: 'au-motto' }, 'Keep the banana, drop the bazooka.'));
  let focused = null, kind = null, phase = null, tracking = false;
  const redraw = () => {
    const mode = phase === 'busy' || phase === 'ok' ? phase
      : kind === 'secret' ? (focused.type === 'text' ? 'peek' : 'secret')
        : kind === 'read' ? 'read' : phase === 'err' ? 'err' : 'idle';
    root.className = `au m-${mode}${tracking ? ' tracking' : ''}`;
  };
  let frame = 0;
  root.addEventListener('pointermove', (e) => {
    if (e.pointerType === 'touch' || still()) return;
    cancelAnimationFrame(frame);
    frame = requestAnimationFrame(() => {
      const r = head.getBoundingClientRect();
      const dx = e.clientX - (r.left + r.width / 2), dy = e.clientY - (r.top + r.height * 0.48);
      const d = Math.hypot(dx, dy) || 1, k = Math.min(1, d / 160);
      root.style.setProperty('--ex', (dx / d * k).toFixed(3));
      root.style.setProperty('--ey', (dy / d * k).toFixed(3));
      if (!tracking) { tracking = true; redraw(); }
    });
  });
  root.addEventListener('pointerleave', () => { tracking = false; redraw(); });
  redraw();
  return {
    root,
    watch(input, as) {
      const on = () => { focused = input; kind = as; redraw(); };
      input.addEventListener('focus', on);
      input.addEventListener('au-toggle', on);
      input.addEventListener('blur', () => { if (focused === input) { focused = null; kind = null; redraw(); } });
      input.addEventListener('input', () => {
        if (as === 'read') root.style.setProperty('--tx', (Math.min(1, input.value.length / 28) * 2 - 1).toFixed(2));
        if (phase === 'err') { phase = null; redraw(); }
      });
    },
    busy() { phase = 'busy'; redraw(); },
    idle() { phase = null; redraw(); },
    ok() { phase = 'ok'; redraw(); return pause(900); },
    fail() {
      phase = 'err'; redraw();
      head.classList.remove('au-shake'); void head.getBoundingClientRect(); head.classList.add('au-shake');
    },
  };
}

/** A password field with a Show button. The button keeps focus in the field, so the monkey can peek. */
let fieldSeq = 0;
function secretField(label, input, hint) {
  input.id ||= `au-secret-${++fieldSeq}`;
  const btn = h('button', { class: 'btn au-show', type: 'button', 'aria-controls': input.id, 'aria-label': `Show ${label.toLowerCase()}`,
    onPointerdown: (e) => { if (document.activeElement === input) e.preventDefault(); },
    onClick: () => {
      const show = input.type === 'password';
      input.type = show ? 'text' : 'password';
      btn.textContent = show ? 'Hide' : 'Show';
      btn.setAttribute('aria-label', `${show ? 'Hide' : 'Show'} ${label.toLowerCase()}`);
      input.dispatchEvent(new Event('au-toggle'));
    } }, 'Show');
  return h('div', { class: 'field' }, h('label', { for: input.id }, label), h('div', { class: 'au-secret' }, input, btn), hint && h('span', { class: 'hint' }, hint));
}

async function afterAuth(res) { session.user = res.user; setCsrf(res.csrf); setWorkspaceTimeZone(res.display?.timeZone); go('#/'); }
const brand = () => h('div', { class: 'row' }, logo(), h('b', null, 'Curious Monkey'));

export function signIn(st) {
  const err = h('div', { class: 'err', role: 'alert' });
  const email = h('input', { type: 'email', autocomplete: 'username', required: true });
  const pw = h('input', { type: 'password', autocomplete: 'current-password', required: true });
  const code = h('input', { inputmode: 'numeric', autocomplete: 'one-time-code', maxlength: '6', placeholder: '6-digit code' });
  const codeField = field('Authenticator code', code, 'From your authenticator app.'); codeField.hidden = true;
  const btn = h('button', { class: 'btn primary', type: 'submit' }, 'Sign in');
  const form = h('form', { onSubmit: async (e) => {
    e.preventDefault(); err.textContent = ''; btn.disabled = true; btn.textContent = 'Signing in…'; s.busy();
    try {
      const res = await post('/auth/signin', { email: email.value, password: pw.value, code: code.value || undefined });
      btn.textContent = 'Signed in'; await s.ok(); await afterAuth(res);
    } catch (x) {
      btn.disabled = false; btn.textContent = 'Sign in';
      if (x.code === 'mfa_required') { s.idle(); codeField.hidden = false; code.focus(); } else { s.fail(); err.textContent = x.message; }
    }
  } },
    brand(),
    h('h1', null, 'Sign in'), h('p', { class: 'muted' }, st.workspace ? `Workspace: ${st.workspace}` : 'Review what your IAM roles really use.'),
    field('Work email', email), secretField('Password', pw), codeField, err, btn,
    st.oidc && h('a', { class: 'btn', href: '/api/auth/oidc/login' }, st.oidcLabel ? `Sign in with ${st.oidcLabel}` : 'Sign in with company SSO'),
    h('p', { class: 'small muted' }, 'New here? Ask a workspace owner for an invite link.'));
  const s = stage(form);
  s.watch(email, 'read'); s.watch(pw, 'secret'); s.watch(code, 'read');
  return s.root;
}

/** Choose a new password from a link an owner made on the Members page. Works signed in or not. */
export function resetPassword(params) {
  const token = params.get('token') || '';
  const err = h('div', { class: 'err', role: 'alert' });
  const who = h('p', { class: 'muted' }, 'Checking your link…');
  const pw = h('input', { type: 'password', autocomplete: 'new-password', required: true, minlength: '12' });
  const pw2 = h('input', { type: 'password', autocomplete: 'new-password', required: true, minlength: '12' });
  const btn = h('button', { class: 'btn primary', type: 'submit', disabled: true }, 'Set new password');
  const mfaNote = h('p', { class: 'small muted', hidden: true }, 'Your two-factor sign-in was also reset. You will set up your authenticator again after signing in.');
  get(`/auth/reset/${encodeURIComponent(token)}`).then((r) => {
    who.textContent = `New password for ${r.email}.`; mfaNote.hidden = !r.resetMfa; btn.disabled = false; pw.focus();
  }).catch((e) => { who.textContent = ''; err.textContent = e.message; s.fail(); });
  const form = h('form', { onSubmit: async (e) => {
    e.preventDefault(); err.textContent = '';
    if (pw.value !== pw2.value) { err.textContent = 'The two passwords are different.'; s.fail(); return; }
    btn.disabled = true; s.busy();
    try {
      const r = await post('/auth/reset', { token, password: pw.value });
      session.user = null; setCsrf('');
      s.ok();
      form.replaceChildren(brand(), h('h1', null, 'Password changed'),
        h('p', { class: 'muted' }, `Sign in as ${r.email} with your new password. Any other sessions were signed out.`),
        r.mfaReset && h('p', { class: 'small muted' }, 'You will set up your authenticator app again right after signing in.'),
        h('a', { class: 'btn primary', href: '#/signin' }, 'Go to sign in'));
    } catch (x) { err.textContent = x.message; btn.disabled = false; s.fail(); }
  } },
    brand(),
    h('h1', null, 'Choose a new password'), who, mfaNote,
    secretField('New password', pw, 'At least 12 characters.'), secretField('Repeat it', pw2), err, btn,
    h('a', { href: '#/signin' }, 'Back to sign in'));
  const s = stage(form);
  s.watch(pw, 'secret'); s.watch(pw2, 'secret');
  return s.root;
}

export function signUp(params, st) {
  const invite = params.get('invite');
  const first = st.needsSetup;
  const err = h('div', { class: 'err', role: 'alert' });
  const name = h('input', { autocomplete: 'name', required: true });
  const email = h('input', { type: 'email', autocomplete: 'email', required: true });
  const ws = h('input', { required: true, placeholder: 'e.g. Acme Security' });
  const pw = h('input', { type: 'password', autocomplete: 'new-password', required: true, minlength: '12' });
  if (invite) get(`/auth/invite/${invite}`).then((i) => { email.value = i.email; email.readOnly = true; }).catch((e) => { err.textContent = e.message; s.fail(); });
  const label = first ? 'Create workspace' : 'Create account';
  const btn = h('button', { class: 'btn primary', type: 'submit' }, label);
  const form = h('form', { onSubmit: async (e) => {
    e.preventDefault(); err.textContent = ''; btn.disabled = true; btn.textContent = first ? 'Creating workspace…' : 'Creating account…'; s.busy();
    try {
      const res = await post('/auth/signup', { name: name.value, email: email.value, password: pw.value, workspaceName: first ? ws.value : undefined, invite: invite || undefined });
      await s.ok(); await afterAuth(res);
    } catch (x) { err.textContent = x.message; btn.disabled = false; btn.textContent = label; s.fail(); }
  } },
    brand(),
    h('h1', null, first ? 'Set up your workspace' : 'Join your team'),
    h('p', { class: 'muted' }, first ? 'You will be the owner. Two-factor sign-in is required next.' : 'You were invited to this workspace.'),
    first && field('Workspace name', ws), field('Your name', name), field('Work email', email), secretField('Password', pw, 'At least 12 characters.'), err, btn,
    !first && h('a', { href: '#/signin' }, 'I already have an account'));
  const s = stage(form);
  s.watch(ws, 'read'); s.watch(name, 'read'); s.watch(email, 'read'); s.watch(pw, 'secret');
  return s.root;
}

export function mfaSetup() {
  const box = h('div', { class: 'stack au-qr' }, h('span', { class: 'spin' }));
  const err = h('div', { class: 'err', role: 'alert' });
  const code = h('input', { inputmode: 'numeric', maxlength: '6', autocomplete: 'one-time-code', placeholder: '6-digit code' });
  const btn = h('button', { class: 'btn primary', type: 'submit' }, 'Confirm and continue');
  post('/auth/mfa/start').then((q) => {
    box.replaceChildren(
      h('p', null, 'Scan this with an authenticator app (1Password, Google Authenticator, Authy).'),
      h('img', { src: q.qr, alt: 'QR code for your authenticator app', width: '220', height: '220' }),
      h('p', { class: 'small muted' }, 'Or enter this key by hand:'), h('code', { class: 'small' }, q.secret),
      h('button', { class: 'btn sm', type: 'button', onClick: () => copy(q.secret) }, 'Copy key'));
  }).catch((e) => { box.replaceChildren(h('div', { class: 'err' }, e.message)); s.fail(); });
  const form = h('form', { onSubmit: async (e) => {
    e.preventDefault(); err.textContent = ''; btn.disabled = true; btn.textContent = 'Checking…'; s.busy();
    try {
      await post('/auth/mfa/confirm', { code: code.value });
      btn.textContent = 'Two-factor is on'; await s.ok();
      session.user.needsMfaSetup = false; session.user.totpConfirmed = true; toast('Two-factor is on'); go('#/'); location.reload();
    } catch (x) { err.textContent = x.message; btn.disabled = false; btn.textContent = 'Confirm and continue'; s.fail(); }
  } },
    brand(), h('h1', null, 'Turn on two-factor'),
    h('p', { class: 'muted' }, 'Your role can change what other people are allowed to do, so it needs a second factor.'),
    box, field('Code from the app', code), err, btn);
  const s = stage(form);
  s.watch(code, 'read');
  return s.root;
}
