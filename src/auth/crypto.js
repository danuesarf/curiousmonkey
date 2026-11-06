import crypto from 'node:crypto';
import { config } from '../config.js';

export const sha256 = (s) => crypto.createHash('sha256').update(s).digest('hex');
export const randomToken = (bytes = 32) => crypto.randomBytes(bytes).toString('base64url');

// scrypt, per-user salt, parameters stored with the hash so they can be raised later
export function hashPassword(pw) {
  const salt = crypto.randomBytes(16);
  const N = 2 ** 15, r = 8, p = 1;
  const key = crypto.scryptSync(pw, salt, 64, { N, r, p, maxmem: 128 * N * r * 2 });
  return `scrypt$${N}$${r}$${p}$${salt.toString('base64')}$${key.toString('base64')}`;
}
export function verifyPassword(pw, stored) {
  if (!stored) { crypto.scryptSync(pw, 'x'.repeat(16), 64); return false; }  // keep timing similar for unknown users
  const [, N, r, p, salt, key] = stored.split('$');
  const got = crypto.scryptSync(pw, Buffer.from(salt, 'base64'), 64, { N: +N, r: +r, p: +p, maxmem: 128 * +N * +r * 2 });
  return crypto.timingSafeEqual(got, Buffer.from(key, 'base64'));
}

const encKey = () => crypto.createHash('sha256').update(config.dataEncryptionKey || config.sessionSecret || 'dev-only-key').digest();
export function encrypt(text) {
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aes-256-gcm', encKey(), iv);
  const enc = Buffer.concat([c.update(text, 'utf8'), c.final()]);
  return `v1.${iv.toString('base64')}.${c.getAuthTag().toString('base64')}.${enc.toString('base64')}`;
}
export function decrypt(blob) {
  const [, iv, tag, enc] = blob.split('.');
  const d = crypto.createDecipheriv('aes-256-gcm', encKey(), Buffer.from(iv, 'base64'));
  d.setAuthTag(Buffer.from(tag, 'base64'));
  return Buffer.concat([d.update(Buffer.from(enc, 'base64')), d.final()]).toString('utf8');
}

export function sign(payload) {
  const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const mac = crypto.createHmac('sha256', config.sessionSecret || 'dev-only-key').update(body).digest('base64url');
  return `${body}.${mac}`;
}
export function unsign(token) {
  const [body, mac] = String(token || '').split('.');
  if (!body || !mac) return null;
  const want = crypto.createHmac('sha256', config.sessionSecret || 'dev-only-key').update(body).digest('base64url');
  if (mac.length !== want.length || !crypto.timingSafeEqual(Buffer.from(mac), Buffer.from(want))) return null;
  try { const p = JSON.parse(Buffer.from(body, 'base64url').toString()); return p.exp && p.exp < Date.now() ? null : p; } catch { return null; }
}
