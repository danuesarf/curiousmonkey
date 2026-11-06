import { Router } from 'express';
import { z } from 'zod';
import crypto from 'node:crypto';
import { config, oidcEnabled } from '../config.js';
import { query, tx } from '../db.js';
import { audit } from '../audit.js';
import { hashPassword, verifyPassword, encrypt, decrypt, sha256, sign, unsign, randomToken } from '../auth/crypto.js';
import * as totp from '../auth/totp.js';
import { createSession, destroySession, requireUser, needsMfaSetup, throttle } from '../auth/sessions.js';
import { PERMS } from '../auth/rbac.js';

export const auth = Router();
const wrap = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);
const email = z.string().trim().toLowerCase().email().max(200);
const password = z.string().min(12, 'Use at least 12 characters').max(200);

export const publicUser = (u) => u && ({ id: u.id, email: u.email, name: u.name, role: u.role, team: u.team, scope_accounts: u.scope_accounts,
  totpConfirmed: u.totp_confirmed, sso: Boolean(u.oidc_subject), permissions: PERMS[u.role] || [], needsMfaSetup: needsMfaSetup(u) });

const domainOk = (e) => !config.allowedEmailDomains.length || config.allowedEmailDomains.includes(e.split('@')[1]);

auth.get('/state', wrap(async (req, res) => {
  const users = (await query('SELECT count(*)::int n FROM users')).rows[0].n;
  const ws = (await query('SELECT name FROM workspace')).rows[0];
  res.json({ needsSetup: users === 0, workspace: ws?.name || null, oidc: oidcEnabled(), signupOpen: users === 0 });
}));

auth.get('/invite/:token', wrap(async (req, res) => {
  const r = (await query(`SELECT email, role, team FROM invites WHERE token_hash=$1 AND accepted_at IS NULL AND expires_at > now()`, [sha256(req.params.token)])).rows[0];
  if (!r) return res.status(404).json({ error: 'invite_invalid', message: 'This invite link is invalid or has expired.' });
  res.json(r);
}));

auth.post('/signup', wrap(async (req, res) => {
  const body = z.object({ name: z.string().trim().min(1).max(100), email, password, workspaceName: z.string().trim().min(1).max(100).optional(), invite: z.string().optional() }).parse(req.body);
  if (!domainOk(body.email)) return res.status(403).json({ error: 'domain_not_allowed', message: 'That email domain is not allowed for this workspace.' });
  const user = await tx(async (c) => {
    await c.query('LOCK TABLE users IN EXCLUSIVE MODE');                       // two first sign-ups cannot both become owner
    const n = (await c.query('SELECT count(*)::int n FROM users')).rows[0].n;
    const hash = hashPassword(body.password);
    if (n === 0) {
      await c.query(`INSERT INTO workspace(name, slug, external_id) VALUES ($1,$2,$3)
         ON CONFLICT (id) DO UPDATE SET name=EXCLUDED.name, slug=EXCLUDED.slug`,
        [body.workspaceName || 'My workspace', (body.workspaceName || 'workspace').toLowerCase().replace(/[^a-z0-9]+/g, '-').slice(0, 40), `cm-${randomToken(12)}`]);
      return (await c.query(`INSERT INTO users(email, name, password_hash, role) VALUES ($1,$2,$3,'owner') RETURNING *`, [body.email, body.name, hash])).rows[0];
    }
    if (!body.invite) throw Object.assign(new Error('Sign-up is by invitation. Ask a workspace owner for an invite link.'), { status: 403, code: 'invite_required' });
    const inv = (await c.query(`SELECT * FROM invites WHERE token_hash=$1 AND accepted_at IS NULL AND expires_at > now() FOR UPDATE`, [sha256(body.invite)])).rows[0];
    if (!inv || inv.email.toLowerCase() !== body.email) throw Object.assign(new Error('This invite is invalid, expired, or for a different email.'), { status: 403, code: 'invite_invalid' });
    await c.query('UPDATE invites SET accepted_at=now() WHERE token_hash=$1', [inv.token_hash]);
    return (await c.query(`INSERT INTO users(email, name, password_hash, role, team, scope_accounts) VALUES ($1,$2,$3,$4,$5,$6) RETURNING *`,
      [body.email, body.name, hash, inv.role, inv.team, inv.scope_accounts])).rows[0];
  });
  req.user = user;
  await audit(req, 'auth.signup', { type: 'user', id: user.id }, { role: user.role });
  const csrf = await createSession(res, user, req);
  res.status(201).json({ user: publicUser(user), csrf });
}));

auth.post('/signin', wrap(async (req, res) => {
  const b = z.object({ email, password: z.string().max(200), code: z.string().max(10).optional() }).parse(req.body);
  const k = throttle.key(req, b.email);
  if (throttle.blocked(k)) return res.status(429).json({ error: 'too_many_attempts', message: 'Too many attempts. Try again in 15 minutes.' });
  const u = (await query('SELECT * FROM users WHERE lower(email)=$1', [b.email])).rows[0];
  const pwOk = verifyPassword(b.password, u?.password_hash);
  if (!u || u.disabled || !pwOk) { throttle.fail(k); await audit(req, 'auth.signin_failed', {}, { email: b.email }); return res.status(401).json({ error: 'bad_credentials', message: 'Email or password is incorrect.' }); }
  if (u.totp_confirmed) {
    if (!b.code) return res.status(401).json({ error: 'mfa_required', message: 'Enter the 6-digit code from your authenticator app.' });
    if (!totp.verify(decrypt(u.totp_secret), b.code)) { throttle.fail(k); await audit(req, 'auth.mfa_failed', { type: 'user', id: u.id }, { email: b.email }); return res.status(401).json({ error: 'bad_code', message: 'That code is not right or has expired.' }); }
  }
  throttle.clear(k);
  req.user = u;
  const csrf = await createSession(res, u, req);
  await audit(req, 'auth.signin', { type: 'user', id: u.id });
  res.json({ user: publicUser(u), csrf });
}));

auth.post('/signout', wrap(async (req, res) => { await audit(req, 'auth.signout'); await destroySession(req, res); res.json({ ok: true }); }));

auth.get('/me', wrap(async (req, res) => {
  if (!req.user) return res.status(401).json({ error: 'unauthenticated' });
  res.json({ user: publicUser(req.user), csrf: req.session.csrf });
}));

auth.post('/mfa/start', requireUser, wrap(async (req, res) => {
  if (req.user.totp_confirmed) return res.status(409).json({ error: 'already_enrolled', message: 'Two-factor is already on for this account.' });
  const secret = totp.newSecret();
  await query('UPDATE users SET totp_secret=$2, totp_confirmed=false WHERE id=$1', [req.user.id, encrypt(secret)]);
  const u = totp.uri(secret, req.user.email);
  res.json({ secret, uri: u, qr: await totp.qrDataUrl(u) });
}));

auth.post('/mfa/confirm', requireUser, wrap(async (req, res) => {
  const { code } = z.object({ code: z.string().max(10) }).parse(req.body);
  const u = (await query('SELECT totp_secret FROM users WHERE id=$1', [req.user.id])).rows[0];
  if (!u.totp_secret || !totp.verify(decrypt(u.totp_secret), code)) return res.status(400).json({ error: 'bad_code', message: 'That code is not right. Check the time on your phone and try again.' });
  await query('UPDATE users SET totp_confirmed=true WHERE id=$1', [req.user.id]);
  await audit(req, 'auth.mfa_enabled', { type: 'user', id: req.user.id });
  res.json({ ok: true });
}));

// ---- OIDC (sign in with your IdP). Stateless: the login state rides in a signed, short-lived cookie. ----
let clientP;
const oidcClient = async () => {
  if (!clientP) clientP = (async () => {
    const { Issuer } = await import('openid-client');
    const issuer = await Issuer.discover(config.oidc.issuer);
    return new issuer.Client({ client_id: config.oidc.clientId, client_secret: config.oidc.clientSecret, redirect_uris: [`${config.publicUrl}/api/auth/oidc/callback`], response_types: ['code'] });
  })().catch((e) => { clientP = null; throw e; });
  return clientP;
};

auth.get('/oidc/login', wrap(async (req, res) => {
  if (!oidcEnabled()) return res.status(404).json({ error: 'oidc_disabled' });
  const { generators } = await import('openid-client');
  const st = { state: generators.state(), nonce: generators.nonce(), verifier: generators.codeVerifier(), exp: Date.now() + 10 * 60e3 };
  res.cookie('cm_oidc', sign(st), { httpOnly: true, sameSite: 'lax', secure: config.cookieSecure, maxAge: 600e3, path: '/api/auth/oidc' });
  const c = await oidcClient();
  res.redirect(c.authorizationUrl({ scope: config.oidc.scopes, state: st.state, nonce: st.nonce, code_challenge: generators.codeChallenge(st.verifier), code_challenge_method: 'S256' }));
}));

auth.get('/oidc/callback', wrap(async (req, res) => {
  const raw = (req.headers.cookie || '').split(';').map((s) => s.trim()).find((s) => s.startsWith('cm_oidc='))?.slice(8);
  const st = unsign(raw);
  if (!st) return res.status(400).send('Sign-in expired. Start again.');
  const c = await oidcClient();
  const tokens = await c.callback(`${config.publicUrl}/api/auth/oidc/callback`, c.callbackParams(req), { state: st.state, nonce: st.nonce, code_verifier: st.verifier });
  const claims = tokens.claims();
  const groups = [].concat(claims[config.oidc.groupsClaim] || []);
  const maps = (await query('SELECT * FROM sso_group_mappings WHERE group_name = ANY($1)', [groups])).rows;
  const order = ['owner', 'admin', 'reviewer', 'account_owner', 'auditor'];
  const best = maps.sort((a, b) => order.indexOf(a.role) - order.indexOf(b.role))[0];
  if (!best) { await audit(req, 'auth.oidc_denied', {}, { email: claims.email, groups }); return res.status(403).send('Your account is not in any group mapped to a Curious Monkey role.'); }
  const emailAddr = String(claims.email || '').toLowerCase();
  const user = await tx(async (cl) => {
    const n = (await cl.query('SELECT count(*)::int n FROM users')).rows[0].n;
    if (n === 0) await cl.query(`INSERT INTO workspace(name, slug, external_id) VALUES ('My workspace','workspace',$1) ON CONFLICT (id) DO NOTHING`, [`cm-${randomToken(12)}`]);
    const ex = (await cl.query('SELECT id FROM users WHERE oidc_subject=$1 OR lower(email)=$2', [claims.sub, emailAddr])).rows[0];
    if (ex) return (await cl.query(`UPDATE users SET oidc_subject=$2, role=$3, team=$4, scope_accounts=$5, name=$6 WHERE id=$1 RETURNING *`,
      [ex.id, claims.sub, best.role, best.team, best.scope_accounts, claims.name || emailAddr])).rows[0];
    return (await cl.query(`INSERT INTO users(email, name, role, team, scope_accounts, oidc_subject) VALUES ($1,$2,$3,$4,$5,$6) RETURNING *`,
      [emailAddr, claims.name || emailAddr, best.role, best.team, best.scope_accounts, claims.sub])).rows[0];
  });
  req.user = user;
  await createSession(res, user, req);
  await audit(req, 'auth.oidc_signin', { type: 'user', id: user.id }, { groups });
  res.clearCookie('cm_oidc', { path: '/api/auth/oidc' });
  res.redirect('/');
}));
export { crypto };
