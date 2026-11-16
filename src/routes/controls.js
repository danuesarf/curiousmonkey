// Admin → Manage policy: the catalogue of controls (built-in and custom), their severity and whether they are on.
import { Router } from 'express';
import { z } from 'zod';
import { audit } from '../audit.js';
import { requireUser, requirePerm } from '../auth/sessions.js';
import { sendCsv } from '../csv.js';
import { can } from '../auth/rbac.js';
import { listControls, controlsCsv, setOverride, saveCustom, deleteCustom, isBuiltin, ControlError, exportPolicy, importPolicy, BY_ID } from '../controls.js';
import { previewIdentityRule, compileIdentityRule, IDENTITY_KEYS, CLOUDS } from '../identityRules.js';
import { compileWayIn, trustIndex, clearTrustIndex, forViewer, KEYS as WAYIN_KEYS, WAYIN_REVIEW_KEYS } from '../trustmap.js';
import { inScope } from '../auth/rbac.js';
import { syncRules } from '../policySync.js';

export const controls = Router();
controls.use(requireUser);
const wrap = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch((e) => {
  if (e instanceof ControlError) return res.status(e.status).json({ error: e.status === 404 ? 'not_found' : e.status === 409 ? 'conflict' : 'invalid', message: e.message, field: e.field });
  if (e instanceof z.ZodError) { const i = e.issues[0]; return res.status(400).json({ error: 'invalid', message: i?.message || 'Invalid value.', field: i?.path?.[0] }); }
  return next(e);
});

/** What is wrong with a rule, if anything. */
const checkRule = (target, rule) => (target === 'identity' ? compileIdentityRule(rule).errors : compileWayIn(rule).errors);
const wayInItems = (rows) => rows.map((e) => ({ id: e.roleId, cloud: 'aws', name: `${e.named?.name || e.source} → ${e.role}`, kind: e.group, risk: e.risk, account: e.account, environment: e.environment }));

const WAYIN_HELP = { account: 'the account the role is in', from: 'where it comes from: an account ID, a name, a provider', source: 'the kind of source: external, connected, same, oidc, saml, public, or a provider (github, bitbucket, eks…)',
  type: 'the kind of principal: root, role, user, oidc, saml, public', provider: 'the identity provider, by name or host', role: 'the role\'s name', cond: 'a condition it has (cond:externalid)',
  env: 'the account\'s environment', has: 'has:conditions, has:admin (leads to an administrator role), has:name, has:org', no: 'no:conditions, no:sub, no:aud, no:externalid, no:mfa, no:admin',
  used: 'yes, iam or no', new: 'added or weakened in that many days (new = 7)', fromenv: 'the environment of the account it comes from, when that is one of yours' };

controls.get('/controls', requirePerm('view'), wrap(async (req, res) => {
  const r = await listControls(req.user, String(req.query.q || '').slice(0, 300));
  res.json({ ...r, canEdit: can(req.user, 'settings'),
    clouds: CLOUDS, keys: { identity: IDENTITY_KEYS,
      'way-in': Object.fromEntries(WAYIN_KEYS.filter((k) => !WAYIN_REVIEW_KEYS.includes(k) && WAYIN_HELP[k]).map((k) => [k, { help: WAYIN_HELP[k] }])) } });
}));
controls.get('/controls.csv', requirePerm('view'), wrap(async (req, res) => {
  sendCsv(res, 'controls', controlsCsv((await listControls(req.user, String(req.query.q || '').slice(0, 300))).items));
}));

// what a rule matches now, without saving it
controls.post('/controls/test', requirePerm('view'), wrap(async (req, res) => {
  const b = z.object({ target: z.enum(['identity', 'way-in']), rule: z.string().trim().max(2000) }).parse(req.body);
  const t0 = performance.now();
  if (b.target === 'identity') { const r = await previewIdentityRule(req.user, b.rule); return res.json({ ...r, ms: Math.round(performance.now() - t0) }); }
  const c = compileWayIn(b.rule);
  if (c.errors.length) return res.json({ errors: c.errors, total: 0, of: null, items: [] });
  // straight from the Trust map's kept index: no query, one pass over the ways in
  const ix = await trustIndex();
  const mine = ix.edges.filter((e) => e.group !== 'service' && inScope(req.user, e.accountId));
  const hits = mine.filter(c.test);
  res.json({ errors: [], total: hits.length, of: mine.length, items: wayInItems(hits.slice(0, 25).map((e) => (req.user.scope_accounts ? forViewer(e, req.user) : e))), ms: Math.round(performance.now() - t0) });
}));

// the policy as a file: what this workspace changed and added
controls.get('/controls/export', requirePerm('view'), wrap(async (req, res) => {
  res.setHeader('Content-Disposition', `attachment; filename="policy-${new Date().toISOString().slice(0, 10)}.json"`);
  res.type('application/json').send(JSON.stringify(await exportPolicy(), null, 2));
}));
controls.post('/controls/import', requirePerm('settings'), wrap(async (req, res) => {
  const b = z.object({ policy: z.unknown(), dryRun: z.boolean().default(false), replace: z.boolean().default(false) }).parse(req.body);
  const r = await importPolicy(req.user, b.policy, { dryRun: b.dryRun, replace: b.replace }, checkRule);
  if (!r.dryRun) {
    await audit(req, 'control.import', { type: 'control', id: 'policy' }, { overrides: r.overrides, created: r.created, updated: r.updated, removed: r.removed, reset: r.reset, skipped: r.skipped.length, replace: b.replace });
    clearTrustIndex();
    r.filed = await syncRules();
  }
  res.json({ ok: true, ...r });
}));

controls.post('/controls', requirePerm('settings'), wrap(async (req, res) => {
  const r = await saveCustom(req.user, null, req.body, checkRule);
  await audit(req, 'control.create', { type: 'control', id: r.id }, { name: r.name, target: r.target, rule: r.rule, severity: r.severity });
  const filed = r.target === 'identity' ? await syncRules() : (clearTrustIndex(), null);
  res.status(201).json({ ok: true, id: r.id, filed });
}));
controls.put('/controls/:id', requirePerm('settings'), wrap(async (req, res) => {
  const id = String(req.params.id);
  if (isBuiltin(id)) {
    const r = await setOverride(req.user, id, req.body);
    await audit(req, 'control.change', { type: 'control', id }, { before: r.before, after: r.after, note: req.body?.note || null });
    const b = BY_ID.get(id);
    if (id.startsWith('trust.') || b.target === 'way-in') clearTrustIndex();
    const filed = b.target === 'identity' ? await syncRules() : null;
    return res.json({ ok: true, ...r, filed });
  }
  if (!id.startsWith('custom.')) throw new ControlError(404, 'No such control.');
  const r = await saveCustom(req.user, id, req.body, checkRule);
  await audit(req, 'control.update', { type: 'control', id: r.id }, { name: r.name, rule: r.rule, severity: r.severity, enabled: r.enabled });
  const filed = r.target === 'identity' ? await syncRules() : (clearTrustIndex(), null);
  res.json({ ok: true, id: r.id, filed });
}));
controls.delete('/controls/:id', requirePerm('settings'), wrap(async (req, res) => {
  const r = await deleteCustom(String(req.params.id));
  await audit(req, 'control.delete', { type: 'control', id: String(req.params.id) }, { name: r.name });
  clearTrustIndex();
  res.json({ ok: true, ...r });
}));
