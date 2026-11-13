// Single sign-on (OIDC) set on the Configuration page, by an owner. A saved setup overrides the OIDC_* environment
// variables; removing it falls back to them. The client secret is stored encrypted and never returned.
// Presets fill in what an identity provider fixes (JumpCloud's issuer, scopes and group claim) so the owner only
// pastes the client ID and secret.
import { z } from 'zod';
import { config } from './config.js';
import { query } from './db.js';
import { encrypt, decrypt } from './auth/crypto.js';

const KEY = 'sso.oidc';
export const ENV_OIDC = { ...config.oidc };                    // as the process started

export const PRESETS = {
  jumpcloud: {
    label: 'JumpCloud',
    issuers: { us: 'https://oauth.id.jumpcloud.com/', eu: 'https://oauth.id.eu.jumpcloud.com/', in: 'https://oauth.id.in.jumpcloud.com/' },
    scopes: 'openid email profile',     // groups come from the app's group attribute, not from a scope
    groupsClaim: 'groups',
  },
  generic: { label: 'Other OIDC provider', issuers: {}, scopes: 'openid email profile groups', groupsClaim: 'groups' },
};

const https = z.string().trim().url('Use the issuer URL from your identity provider.').max(300)
  .refine((u) => u.startsWith('https://'), 'The issuer must use https.');
export const SsoInput = z.object({
  enabled: z.boolean(),
  provider: z.enum(Object.keys(PRESETS)),
  issuer: https,
  clientId: z.string().trim().min(1, 'Paste the client ID.').max(300),
  clientSecret: z.string().max(500).optional(),        // empty or missing: keep the one already saved
  groupsClaim: z.string().trim().min(1).max(100).regex(/^[\w:./-]+$/, 'Use the claim name only, such as groups.'),
  scopes: z.string().trim().min(6).max(300).refine((s) => s.split(/\s+/).includes('openid'), 'Scopes must include openid.'),
  buttonLabel: z.string().trim().max(60).optional(),
});

let saved = null;     // { enabled, provider, issuer, clientId, secret (encrypted), groupsClaim, scopes, buttonLabel, updatedAt, updatedBy }
let version = 0;      // changes whenever the effective setup changes, so the OIDC client is rebuilt
export const ssoVersion = () => version;

function apply() {
  const before = JSON.stringify(config.oidc);
  if (saved?.enabled) {
    let secret = '';
    try { secret = saved.secret ? decrypt(saved.secret) : ''; } catch { secret = ''; }   // key rotated: treat as missing
    Object.assign(config.oidc, { issuer: saved.issuer, clientId: saved.clientId, clientSecret: secret, groupsClaim: saved.groupsClaim, scopes: saved.scopes, buttonLabel: saved.buttonLabel || '' });
  } else if (saved && !saved.enabled) {
    Object.assign(config.oidc, { issuer: '', clientId: '', clientSecret: '', buttonLabel: '' });     // turned off here: off, even if env has values
  } else {
    Object.assign(config.oidc, { ...ENV_OIDC, buttonLabel: '' });
  }
  if (JSON.stringify(config.oidc) !== before) version++;
}

export async function refreshSso() {
  let row;
  try { row = (await query(`SELECT value, updated_at, updated_by FROM app_settings WHERE key=$1`, [KEY])).rows[0]; } catch (e) { if (e.code !== '42P01') throw e; }
  saved = row ? { ...row.value, updatedAt: row.updated_at, updatedBy: row.updated_by } : null;
  apply();
}

/** What the Configuration page shows. Never the secret. */
export function ssoView() {
  const envSet = Boolean(ENV_OIDC.issuer && ENV_OIDC.clientId && ENV_OIDC.clientSecret);
  const s = saved;
  return {
    source: s ? 'saved' : envSet ? 'env' : 'none',
    enabled: s ? s.enabled : envSet,
    provider: s?.provider || (ENV_OIDC.issuer && !ENV_OIDC.issuer.includes('jumpcloud.com') ? 'generic' : 'jumpcloud'),
    issuer: s?.issuer ?? ENV_OIDC.issuer,
    clientId: s?.clientId ?? ENV_OIDC.clientId,
    hasSecret: s ? Boolean(s.secret) : Boolean(ENV_OIDC.clientSecret),
    groupsClaim: s?.groupsClaim ?? ENV_OIDC.groupsClaim,
    scopes: s?.scopes ?? ENV_OIDC.scopes,
    buttonLabel: s?.buttonLabel || '',
    envSet,
    updatedAt: s?.updatedAt || null,
    redirectUri: `${config.publicUrl}/api/auth/oidc/callback`,
    loginUrl: `${config.publicUrl}/api/auth/oidc/login`,
    presets: PRESETS,
  };
}

/** Validate and save. Returns { errors } or { changed: [field names] } (the secret is reported as changed, never shown). */
export async function saveSso(input, userId) {
  const r = SsoInput.safeParse(input);
  if (!r.success) return { errors: Object.fromEntries(r.error.issues.map((i) => [i.path.join('.') || 'form', i.message])) };
  const b = r.data;
  const prev = saved || {};
  const secret = b.clientSecret ? encrypt(b.clientSecret) : prev.secret || (ENV_OIDC.clientSecret ? encrypt(ENV_OIDC.clientSecret) : null);
  if (b.enabled && !secret) return { errors: { clientSecret: 'Paste the client secret.' } };
  const value = { enabled: b.enabled, provider: b.provider, issuer: b.issuer, clientId: b.clientId, secret, groupsClaim: b.groupsClaim, scopes: b.scopes.replace(/\s+/g, ' '), buttonLabel: b.buttonLabel || '' };
  const changed = ['enabled', 'provider', 'issuer', 'clientId', 'groupsClaim', 'scopes', 'buttonLabel'].filter((k) => prev[k] !== value[k]);
  if (b.clientSecret) changed.push('clientSecret');
  await query(`INSERT INTO app_settings(key, value, updated_by, updated_at) VALUES ($1,$2,$3,now())
               ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value, updated_by=EXCLUDED.updated_by, updated_at=now()`, [KEY, JSON.stringify(value), userId || null]);
  await refreshSso();
  return { changed };
}

/** Forget the setup made here; the environment variables (if any) apply again. */
export async function clearSso() {
  const n = (await query(`DELETE FROM app_settings WHERE key=$1`, [KEY])).rowCount;
  await refreshSso();
  return n > 0;
}
