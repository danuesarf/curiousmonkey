// RFC 6238 time-based one-time passwords, 30 s step, 6 digits, SHA-1 (what authenticator apps expect).
import crypto from 'node:crypto';
import QRCode from 'qrcode';

const ALPHA = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
export const newSecret = () => {
  const b = crypto.randomBytes(20); let bits = '', out = '';
  for (const x of b) bits += x.toString(2).padStart(8, '0');
  for (let i = 0; i + 5 <= bits.length; i += 5) out += ALPHA[parseInt(bits.slice(i, i + 5), 2)];
  return out;
};
const decode32 = (s) => {
  let bits = ''; for (const ch of s.replace(/=+$/, '').toUpperCase()) bits += ALPHA.indexOf(ch).toString(2).padStart(5, '0');
  const out = []; for (let i = 0; i + 8 <= bits.length; i += 8) out.push(parseInt(bits.slice(i, i + 8), 2));
  return Buffer.from(out);
};
export function code(secret, t = Date.now(), step = 30) {
  const ctr = Buffer.alloc(8); ctr.writeBigUInt64BE(BigInt(Math.floor(t / 1000 / step)));
  const h = crypto.createHmac('sha1', decode32(secret)).update(ctr).digest();
  const o = h[19] & 15;
  return String(((h[o] & 0x7f) << 24 | h[o + 1] << 16 | h[o + 2] << 8 | h[o + 3]) % 1e6).padStart(6, '0');
}
export function verify(secret, input, t = Date.now()) {
  const s = String(input || '').replace(/\s/g, '');
  if (!/^\d{6}$/.test(s)) return false;
  return [-1, 0, 1].some((d) => crypto.timingSafeEqual(Buffer.from(code(secret, t + d * 30000)), Buffer.from(s)));  // one step of clock drift each way
}
export const uri = (secret, email, issuer = 'Curious Monkey') =>
  `otpauth://totp/${encodeURIComponent(issuer)}:${encodeURIComponent(email)}?secret=${secret}&issuer=${encodeURIComponent(issuer)}&digits=6&period=30`;
export const qrDataUrl = (u) => QRCode.toDataURL(u, { margin: 1, width: 220 });
