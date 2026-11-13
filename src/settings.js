// Settings an owner or admin can change in the portal (Configuration page). Environment variables give the
// defaults; a saved value overrides them. The values are applied onto `config`, so code that reads config.ai
// or config.scanner picks them up. The API applies a change at once; the worker re-reads every 30 seconds.
import { z } from 'zod';
import { config } from './config.js';
import { query } from './db.js';
import { refreshEnvironments } from './environments.js';
import { refreshSso } from './sso.js';

export const EVENT_HISTORY_MAX_DAYS = 90;        // AWS limit for LookupEvents; not configurable
export const LOOKBACK_CEILING_DAYS = 730;        // the most this tool will ever read back from an S3 trail
export const SLICE_CHOICES = [6, 2, 1, 0.5, 0.25];

// key -> [schema, path in config, read from env at startup]
const DEFS = {
  'ai.enabled':               [z.boolean(), ['ai', 'enabled']],
  'ai.region':                [z.string().trim().regex(/^[a-z]{2}(-gov)?-[a-z]+-\d$/, 'Use an AWS region such as us-east-1.'), ['ai', 'region']],
  'ai.modelId':               [z.string().trim().min(3).max(200).regex(/^[\w.:/-]+$/, 'Use a Bedrock model ID, inference profile ID or ARN.'), ['ai', 'modelId']],
  'ai.maxTokens':             [z.number().int().min(1000).max(64000), ['ai', 'maxTokens']],
  'history.defaultLookbackDays': [z.number().int().min(1).max(LOOKBACK_CEILING_DAYS), ['scanner', 'defaultLookbackDays']],
  'history.maxLookbackDays':  [z.number().int().min(EVENT_HISTORY_MAX_DAYS).max(LOOKBACK_CEILING_DAYS), ['scanner', 'maxLookbackDays']],
  'history.sliceHours':       [z.number().refine((v) => SLICE_CHOICES.includes(v), 'Pick one of the slice sizes.'), ['scanner', 'sliceHours']],
  'history.tailEveryMinutes': [z.number().int().min(0).max(1440), ['scanner', 'tailEveryMinutes']],
};
const at = (path) => path.reduce((o, k) => o?.[k], config);
const put = (path, v) => { const o = path.slice(0, -1).reduce((x, k) => x[k], config); o[path.at(-1)] = v; };

// Defaults as the process started (environment or built-in), before any saved value.
if (config.scanner.defaultLookbackDays == null) config.scanner.defaultLookbackDays = Number(process.env.DEFAULT_LOOKBACK_DAYS || 90);
if (config.scanner.maxLookbackDays == null) config.scanner.maxLookbackDays = Math.min(Number(process.env.MAX_LOOKBACK_DAYS || 365), LOOKBACK_CEILING_DAYS);
if (config.scanner.tailEveryMinutes == null) config.scanner.tailEveryMinutes = Number(process.env.TAIL_EVERY_MINUTES ?? 30);
const DEFAULTS = Object.fromEntries(Object.entries(DEFS).map(([k, [, p]]) => [k, at(p)]));
let saved = {};
let loadedAt = 0;

/** Read saved settings and apply them. Missing table (before migrations) is not an error. */
export async function refreshSettings() {
  let rows = [];
  try { rows = (await query(`SELECT key, value, updated_at, updated_by FROM app_settings`)).rows; } catch (e) { if (e.code !== '42P01') throw e; }
  saved = Object.fromEntries(rows.filter((r) => DEFS[r.key]).map((r) => [r.key, r]));
  for (const [k, [schema, path]] of Object.entries(DEFS)) {
    const s = saved[k] && schema.safeParse(saved[k].value);
    put(path, s?.success ? s.data : DEFAULTS[k]);
  }
  await refreshEnvironments();
  await refreshSso();
  loadedAt = Date.now();
  return current();
}

/** Every setting with its effective value, its default and whether it was changed here. */
export function current() {
  return Object.fromEntries(Object.entries(DEFS).map(([k, [, path]]) => [k, {
    value: at(path), default: DEFAULTS[k], overridden: !!saved[k], updatedAt: saved[k]?.updated_at || null,
  }]));
}

/** Validate and save. `null` for a key resets it to its default. Returns the keys that changed. */
export async function saveSettings(patch, userId) {
  const errors = {};
  const clean = {};
  for (const [k, v] of Object.entries(patch || {})) {
    if (!DEFS[k]) { errors[k] = 'Unknown setting.'; continue; }
    if (v === null) { clean[k] = null; continue; }
    const r = DEFS[k][0].safeParse(v);
    if (!r.success) errors[k] = r.error.issues[0]?.message || 'Invalid value.'; else clean[k] = r.data;
  }
  const next = { ...Object.fromEntries(Object.entries(current()).map(([k, s]) => [k, s.value])), ...Object.fromEntries(Object.entries(clean).map(([k, v]) => [k, v ?? DEFAULTS[k]])) };
  if (next['history.defaultLookbackDays'] > next['history.maxLookbackDays'] && !errors['history.defaultLookbackDays'])
    errors['history.defaultLookbackDays'] = 'The default cannot be longer than the maximum.';
  if (Object.keys(errors).length) return { errors };
  const changed = [];
  for (const [k, v] of Object.entries(clean)) {
    if (v === null) { if ((await query(`DELETE FROM app_settings WHERE key=$1`, [k])).rowCount) changed.push(k); continue; }
    if (JSON.stringify(current()[k].value) === JSON.stringify(v) && saved[k]) continue;
    await query(`INSERT INTO app_settings(key, value, updated_by, updated_at) VALUES ($1,$2,$3,now())
                 ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value, updated_by=EXCLUDED.updated_by, updated_at=now()`, [k, JSON.stringify(v), userId || null]);
    changed.push(k);
  }
  await refreshSettings();
  return { changed };
}

/** How far back an account is read: its own setting, capped by the source and the workspace maximum. */
export const effectiveLookback = (account) => Math.min(account.lookback_days || config.scanner.defaultLookbackDays,
  account.event_source === 's3' ? config.scanner.maxLookbackDays : EVENT_HISTORY_MAX_DAYS);

/** Keep a long-running process (the worker) in step with changes made in the portal. */
export function watchSettings(everyMs = 30_000) {
  const t = setInterval(() => refreshSettings().catch(() => {}), everyMs);
  t.unref?.();
  return () => clearInterval(t);
}
export const settingsAge = () => Date.now() - loadedAt;
