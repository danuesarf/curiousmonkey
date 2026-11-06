import { config } from '../config.js';
import { query } from '../db.js';
import { sha256, randomToken } from './crypto.js';
import { can } from './rbac.js';

const COOKIE = 'cm_session';
const parseCookies = (h = '') => Object.fromEntries(h.split(';').map((c) => c.trim().split(/=(.*)/s).slice(0, 2)).filter(([k]) => k));

export async function createSession(res, user, req) {
  const token = randomToken(), csrf = randomToken(16);
  const hours = config.sessionHours;
  await query(`INSERT INTO sessions(id, user_id, csrf, ip, user_agent, expires_at) VALUES ($1,$2,$3,$4,$5, now() + make_interval(hours => $6))`,
    [sha256(token), user.id, csrf, req.ip, (req.get('user-agent') || '').slice(0, 200), hours]);
  res.cookie(COOKIE, token, { httpOnly: true, sameSite: 'lax', secure: config.cookieSecure, path: '/', maxAge: hours * 3600e3 });
  await query('UPDATE users SET last_login_at=now() WHERE id=$1', [user.id]);
  return csrf;
}
export async function destroySession(req, res) {
  const t = parseCookies(req.headers.cookie)[COOKIE];
  if (t) await query('DELETE FROM sessions WHERE id=$1', [sha256(t)]);
  res.clearCookie(COOKIE, { path: '/' });
}

/** Attaches req.user / req.session when a valid session cookie is present. */
export async function loadSession(req, res, next) {
  try {
    const t = parseCookies(req.headers.cookie)[COOKIE];
    if (t) {
      const r = await query(`SELECT s.id AS sid, s.csrf, u.* FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.id=$1 AND s.expires_at > now() AND NOT u.disabled`, [sha256(t)]);
      if (r.rows[0]) { const { sid, csrf, ...u } = r.rows[0]; req.user = u; req.session = { id: sid, csrf }; }
    }
    next();
  } catch (e) { next(e); }
}

export const needsMfaSetup = (u) => Boolean(u && !u.oidc_subject && ['owner', 'admin', 'reviewer'].includes(u.role) && !u.totp_confirmed);

/** Cookie auth means every state-changing request must carry the CSRF token the page was given. */
export function csrfGuard(req, res, next) {
  if (['GET', 'HEAD', 'OPTIONS'].includes(req.method) || !req.session) return next();
  if (req.get('x-csrf-token') !== req.session.csrf) return res.status(403).json({ error: 'bad_csrf', message: 'Reload the page and try again.' });
  next();
}

export const requireUser = (req, res, next) => {
  if (!req.user) return res.status(401).json({ error: 'unauthenticated' });
  if (needsMfaSetup(req.user) && !req.originalUrl.startsWith('/api/auth/')) return res.status(403).json({ error: 'mfa_setup_required', message: 'Set up two-factor sign-in first.' });
  next();
};
export const requirePerm = (perm) => (req, res, next) =>
  can(req.user, perm) ? next() : res.status(403).json({ error: 'forbidden', message: `Your role cannot do this (${perm}).` });

// Sign-in throttle: 10 failures per 15 minutes per ip+email. Per process; put a gateway limit in front for multi-replica setups.
const fails = new Map();
export const throttle = {
  key: (req, email) => `${req.ip}|${String(email || '').toLowerCase()}`,
  blocked(k) { const f = (fails.get(k) || []).filter((t) => t > Date.now() - 15 * 60e3); fails.set(k, f); return f.length >= 10; },
  fail(k) { fails.set(k, [...(fails.get(k) || []), Date.now()]); },
  clear(k) { fails.delete(k); },
};
