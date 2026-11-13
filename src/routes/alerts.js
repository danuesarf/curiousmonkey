// Admin → Alerts: where alerts go (destinations), what sends them (rules), and the log of what was sent.
// Owners and admins only (the `settings` permission), like the rest of the configuration.
import { Router } from 'express';
import { z } from 'zod';
import { audit } from '../audit.js';
import { requireUser, requirePerm } from '../auth/sessions.js';
import { alertsView, createDestination, updateDestination, deleteDestination, testDestination, createRule, updateRule, deleteRule, AlertError } from '../alerts.js';

export const alerts = Router();
alerts.use(requireUser);
const uuid = z.string().uuid();
// AlertError and zod errors become 4xx answers the page can show next to the field
const wrap = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch((e) => {
  if (e instanceof AlertError) return res.status(e.status).json({ error: e.status === 404 ? 'not_found' : 'invalid', message: e.message, field: e.field });
  if (e instanceof z.ZodError) { const i = e.issues[0]; return res.status(400).json({ error: 'invalid', message: i?.message || 'Invalid value.', field: i?.path?.join('.') }); }
  return next(e);
});

alerts.get('/alerts', requirePerm('settings'), wrap(async (req, res) => res.json(await alertsView())));

alerts.post('/alerts/destinations', requirePerm('settings'), wrap(async (req, res) => {
  const d = await createDestination(req.body, req.user.id);
  await audit(req, 'alert.destination.create', { type: 'alert_destination', id: d.id }, { name: d.name, kind: d.kind, url: d.urlHint });
  res.status(201).json(d);
}));
alerts.put('/alerts/destinations/:id', requirePerm('settings'), wrap(async (req, res) => {
  const d = await updateDestination(uuid.parse(req.params.id), req.body);
  await audit(req, 'alert.destination.update', { type: 'alert_destination', id: d.id }, { name: d.name, urlChanged: Boolean(req.body?.url) });
  res.json(d);
}));
alerts.delete('/alerts/destinations/:id', requirePerm('settings'), wrap(async (req, res) => {
  const id = uuid.parse(req.params.id), d = await deleteDestination(id);
  await audit(req, 'alert.destination.delete', { type: 'alert_destination', id }, { name: d.name });
  res.json({ ok: true });
}));
alerts.post('/alerts/destinations/:id/test', requirePerm('settings'), wrap(async (req, res) => {
  const id = uuid.parse(req.params.id), r = await testDestination(id);
  await audit(req, 'alert.destination.test', { type: 'alert_destination', id }, { ok: r?.ok ?? false, status: r?.status ?? null });
  res.json({ ok: Boolean(r?.ok), status: r?.status ?? null, error: r?.ok ? null : r?.error || 'Not sent.' });
}));

alerts.post('/alerts/rules', requirePerm('settings'), wrap(async (req, res) => {
  const r = await createRule(req.body, req.user.id);
  await audit(req, 'alert.rule.create', { type: 'alert_rule', id: r.id }, { name: r.name, trigger: r.trigger, mode: r.mode });
  res.status(201).json(r);
}));
alerts.put('/alerts/rules/:id', requirePerm('settings'), wrap(async (req, res) => {
  const r = await updateRule(uuid.parse(req.params.id), req.body);
  await audit(req, 'alert.rule.update', { type: 'alert_rule', id: r.id }, { name: r.name, changed: Object.keys(req.body || {}) });
  res.json(r);
}));
alerts.delete('/alerts/rules/:id', requirePerm('settings'), wrap(async (req, res) => {
  const id = uuid.parse(req.params.id), r = await deleteRule(id);
  await audit(req, 'alert.rule.delete', { type: 'alert_rule', id }, { name: r.name });
  res.json({ ok: true });
}));
