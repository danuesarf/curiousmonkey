// Configuration page: Bedrock and how far back CloudTrail history is read.
import { Router } from 'express';
import { z } from 'zod';
import { config } from '../config.js';
import { query } from '../db.js';
import { audit } from '../audit.js';
import { requireUser, requirePerm } from '../auth/sessions.js';
import { current, saveSettings, effectiveLookback, EVENT_HISTORY_MAX_DAYS, LOOKBACK_CEILING_DAYS, SLICE_CHOICES } from '../settings.js';
import { historyFor } from '../history.js';

export const settings = Router();
settings.use(requireUser);
const wrap = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

const ENV = { 'ai.enabled': 'BEDROCK_ENABLED', 'ai.region': 'BEDROCK_REGION', 'ai.modelId': 'BEDROCK_MODEL_ID', 'ai.maxTokens': 'AI_MAX_TOKENS',
  'history.defaultLookbackDays': 'DEFAULT_LOOKBACK_DAYS', 'history.maxLookbackDays': 'MAX_LOOKBACK_DAYS', 'history.sliceHours': 'SCAN_SLICE_HOURS' };

/** What the account form needs: the lookback it may offer. */
settings.get('/settings/limits', requirePerm('view'), (req, res) => res.json({
  defaultLookbackDays: config.scanner.defaultLookbackDays, maxLookbackDays: config.scanner.maxLookbackDays, eventHistoryMaxDays: EVENT_HISTORY_MAX_DAYS,
}));

settings.get('/settings', requirePerm('settings'), wrap(async (req, res) => {
  const [accts, cps, recs, maps] = await Promise.all([
    query(`SELECT id, name, account_id, environment, event_source, lookback_days, regions FROM cloud_accounts ORDER BY name`),
    query(`SELECT account_id, region, first_event_time, last_event_time, events_read, caught_up_at, gap_detected FROM scan_checkpoints`),
    query(`SELECT source, model, count(*)::int AS n, max(created_at) AS last FROM recommendations WHERE created_at > now() - interval '30 days' GROUP BY source, model ORDER BY n DESC`),
    query(`SELECT count(*)::int AS n, max(suggested_at) AS last FROM event_action_map WHERE source='bedrock' AND suggested_at > now() - interval '30 days'`),
  ]);
  const hist = await historyFor(accts.rows);
  const byAcct = new Map();
  for (const c of cps.rows) { if (!byAcct.has(c.account_id)) byAcct.set(c.account_id, []); byAcct.get(c.account_id).push(c); }
  const now = Date.now();
  res.json({
    settings: Object.fromEntries(Object.entries(current()).map(([k, v]) => [k, { ...v, env: ENV[k] }])),
    choices: { sliceHours: SLICE_CHOICES, lookbackCeiling: LOOKBACK_CEILING_DAYS, eventHistoryMaxDays: EVENT_HISTORY_MAX_DAYS },
    awsMode: config.awsMode,
    ai: { recommendations: recs.rows, mappingSuggestions: maps.rows[0] },
    history: accts.rows.map((a) => {
      const eff = effectiveLookback(a);
      const h = hist.get(a.id);
      const regions = a.regions.map((r) => {
        const c = (byAcct.get(a.id) || []).find((x) => x.region === r);
        const back = c?.first_event_time ? Math.round((now - new Date(c.first_event_time)) / 864e5) : 0;
        return { region: r, backTo: c?.first_event_time || null, upTo: c?.last_event_time || null, daysRead: Math.min(back, eff), events: Number(c?.events_read || 0), complete: !!c?.caught_up_at && back >= eff - 1, gap: !!c?.gap_detected };
      });
      return { id: a.id, name: a.name, accountId: a.account_id, environment: a.environment, source: a.event_source, lookbackDays: a.lookback_days, effectiveDays: eff,
        cappedBy: a.lookback_days > eff ? (a.event_source === 's3' ? 'workspace' : 'event-history') : null, complete: !!h?.complete, regions };
    }),
  });
}));

settings.put('/settings', requirePerm('settings'), wrap(async (req, res) => {
  const before = current();
  const r = await saveSettings(z.record(z.string(), z.any()).parse(req.body || {}), req.user.id);
  if (r.errors) return res.status(400).json({ error: 'invalid', message: Object.values(r.errors)[0], fields: r.errors });
  if (r.changed.length) {
    const after = current();
    await audit(req, 'settings.update', { type: 'settings' }, Object.fromEntries(r.changed.map((k) => [k, { from: before[k].value, to: after[k].value }])));
  }
  res.json({ changed: r.changed });
}));

/** One tiny Converse call with the given (or saved) region and model. Nothing is saved. */
settings.post('/settings/bedrock/test', requirePerm('settings'), wrap(async (req, res) => {
  const b = z.object({ region: z.string().trim().regex(/^[a-z]{2}(-gov)?-[a-z]+-\d$/).optional(), modelId: z.string().trim().min(3).max(200).regex(/^[\w.:/-]+$/).optional() }).parse(req.body || {});
  const region = b.region || config.ai.region, modelId = b.modelId || config.ai.modelId;
  if (config.awsMode === 'demo') return res.json({ ok: false, region, modelId, error: 'Demo mode does not call AWS.', hint: 'Run with AWS_MODE=aws to test Bedrock.' });
  const t0 = Date.now();
  try {
    const { BedrockRuntimeClient, ConverseCommand } = await import('@aws-sdk/client-bedrock-runtime');
    const client = new BedrockRuntimeClient({ region, maxAttempts: 1 });
    const r = await client.send(new ConverseCommand({ modelId, messages: [{ role: 'user', content: [{ text: 'Reply with the single word OK.' }] }], inferenceConfig: { maxTokens: 10, temperature: 0 } }));
    const reply = (r.output?.message?.content || []).map((c) => c.text || '').join('').trim().slice(0, 40);
    await audit(req, 'settings.bedrock_test', { type: 'settings' }, { region, modelId, ok: true });
    res.json({ ok: true, region, modelId, latencyMs: Date.now() - t0, reply, inputTokens: r.usage?.inputTokens ?? null, outputTokens: r.usage?.outputTokens ?? null });
  } catch (e) {
    await audit(req, 'settings.bedrock_test', { type: 'settings' }, { region, modelId, ok: false, error: e.name });
    res.json({ ok: false, region, modelId, latencyMs: Date.now() - t0, error: `${e.name}: ${String(e.message).slice(0, 300)}`, hint: bedrockHint(e) });
  }
}));

function bedrockHint(e) {
  const m = `${e.name} ${e.message}`;
  if (/on-demand throughput isn.t supported|inference profile/i.test(m)) return 'This model needs an inference profile. Use its profile ID, for example apac.… or global.… in front of the model ID.';
  if (/AccessDenied/i.test(m) && /model/i.test(m)) return 'Model access is not granted in this account and region. Request access in the Bedrock console, or check the identity has bedrock:InvokeModel on it.';
  if (/AccessDenied|not authorized/i.test(m)) return 'The portal’s identity lacks bedrock:InvokeModel for this model (and the inference profile, if one is used).';
  if (/ResourceNotFound|could not resolve|model identifier is invalid|ValidationException/i.test(m)) return 'The model ID is not available in this region. Check the ID and region in the Bedrock console.';
  if (/credentials|Could not load/i.test(m)) return 'The portal has no AWS credentials. Give its pod an IAM role (IRSA) or set credentials.';
  if (/Throttl/i.test(m)) return 'Bedrock is throttling this account. Try again shortly or raise the quota.';
  return null;
}
