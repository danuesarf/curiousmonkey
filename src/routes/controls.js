// Admin → Manage policy: the catalogue of controls (built-in and custom), their severity and whether they are on.
import { Router } from 'express';
import { z } from 'zod';
import { audit } from '../audit.js';
import { requireUser, requirePerm } from '../auth/sessions.js';
import { sendCsv } from '../csv.js';
import { can } from '../auth/rbac.js';
import { listControls, controlsCsv, setOverride, saveCustom, deleteCustom, previewIdentityRule, compileIdentityRule, isBuiltin, ControlError,
  IDENTITY_KEYS, WAYIN_REVIEW_KEYS } from '../controls.js';
import { parseQuery, queryWarnings, trustWays, clearTrustIndex, KEYS as WAYIN_KEYS } from '../trustmap.js';
import { syncCustom } from '../policySync.js';

export const controls = Router();
controls.use(requireUser);
const wrap = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch((e) => {
  if (e instanceof ControlError) return res.status(e.status).json({ error: e.status === 404 ? 'not_found' : e.status === 409 ? 'conflict' : 'invalid', message: e.message, field: e.field });
  if (e instanceof z.ZodError) { const i = e.issues[0]; return res.status(400).json({ error: 'invalid', message: i?.message || 'Invalid value.', field: i?.path?.[0] }); }
  return next(e);
});

/** What is wrong with a rule, if anything. */
function checkRule(target, rule) {
  if (target === 'identity') return compileIdentityRule(rule).errors;
  const terms = parseQuery(rule);
  if (!terms.length) return ['Write at least one term: an empty rule would match every way in.'];
  const review = terms.find((t) => WAYIN_REVIEW_KEYS.includes(t.key));
  if (review) return [`${review.key}: describes the review, not the trust, so a control cannot use it.`];
  return queryWarnings(terms);
}
const wayInItems = (rows) => rows.map((e) => ({ id: e.roleId, name: `${e.named?.name || e.source} → ${e.role}`, kind: e.group, risk: e.risk, account: e.account, environment: e.environment }));

const WAYIN_HELP = { account: 'the account the role is in', from: 'where it comes from: an account ID, a name, a provider', source: 'the kind of source: external, connected, same, oidc, saml, public, or a provider (github, bitbucket, eks…)',
  type: 'the kind of principal: root, role, user, oidc, saml, public', provider: 'the identity provider, by name or host', role: 'the role\'s name', cond: 'a condition it has (cond:externalid)',
  env: 'the account\'s environment', has: 'has:conditions, has:admin (leads to an administrator role), has:name, has:org', no: 'no:conditions, no:sub, no:aud, no:externalid, no:mfa, no:admin',
  used: 'yes, iam or no', new: 'added or weakened in that many days (new:7)' };

controls.get('/controls', requirePerm('view'), wrap(async (req, res) => {
  const r = await listControls(req.user, String(req.query.q || '').slice(0, 300));
  res.json({ ...r, canEdit: can(req.user, 'settings'),
    keys: { identity: Object.fromEntries(Object.entries(IDENTITY_KEYS).map(([k, [, help]]) => [k, help])),
      'way-in': Object.fromEntries(WAYIN_KEYS.filter((k) => !WAYIN_REVIEW_KEYS.includes(k) && WAYIN_HELP[k]).map((k) => [k, WAYIN_HELP[k]])) } });
}));
controls.get('/controls.csv', requirePerm('view'), wrap(async (req, res) => {
  sendCsv(res, 'controls', controlsCsv((await listControls(req.user, String(req.query.q || '').slice(0, 300))).items));
}));

// what a rule matches now, without saving it
controls.post('/controls/test', requirePerm('view'), wrap(async (req, res) => {
  const b = z.object({ target: z.enum(['identity', 'way-in']), rule: z.string().trim().max(2000) }).parse(req.body);
  const errors = checkRule(b.target, b.rule);
  if (errors.length) return res.json({ errors, total: 0, of: null, items: [] });
  if (b.target === 'identity') return res.json(await previewIdentityRule(req.user, b.rule));
  const [w, all] = await Promise.all([trustWays(req.user, `${b.rule} -type:service`, { size: 25 }), trustWays(req.user, '-type:service', { size: 1 })]);
  res.json({ errors: [], total: w.total, of: all.total, items: wayInItems(w.rows) });
}));

controls.post('/controls', requirePerm('settings'), wrap(async (req, res) => {
  const r = await saveCustom(req.user, null, req.body, checkRule);
  await audit(req, 'control.create', { type: 'control', id: r.id }, { name: r.name, target: r.target, rule: r.rule, severity: r.severity });
  const filed = r.target === 'identity' ? await syncCustom() : (clearTrustIndex(), null);
  res.status(201).json({ ok: true, id: r.id, filed });
}));
controls.put('/controls/:id', requirePerm('settings'), wrap(async (req, res) => {
  const id = String(req.params.id);
  if (isBuiltin(id)) {
    const r = await setOverride(req.user, id, req.body);
    await audit(req, 'control.change', { type: 'control', id }, { before: r.before, after: r.after, note: req.body?.note || null });
    if (id.startsWith('trust.')) clearTrustIndex();
    return res.json({ ok: true, ...r });
  }
  if (!id.startsWith('custom.')) throw new ControlError(404, 'No such control.');
  const r = await saveCustom(req.user, id, req.body, checkRule);
  await audit(req, 'control.update', { type: 'control', id: r.id }, { name: r.name, rule: r.rule, severity: r.severity, enabled: r.enabled });
  const filed = r.target === 'identity' ? await syncCustom() : (clearTrustIndex(), null);
  res.json({ ok: true, id: r.id, filed });
}));
controls.delete('/controls/:id', requirePerm('settings'), wrap(async (req, res) => {
  const r = await deleteCustom(String(req.params.id));
  await audit(req, 'control.delete', { type: 'control', id: String(req.params.id) }, { name: r.name });
  clearTrustIndex();
  res.json({ ok: true, ...r });
}));
