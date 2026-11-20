// Watch → Resources: who resource-based policies let in, and reviewers' calls on what they find.
import { Router } from 'express';
import { z } from 'zod';
import { audit } from '../audit.js';
import { requireUser, requirePerm } from '../auth/sessions.js';
import { sendCsv } from '../csv.js';
import { listResources, resourceDetail, decide, undecide, resourcesCsv, DecisionError } from '../resourcesApi.js';

export const resources = Router();
resources.use(requireUser);
const wrap = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch((e) => {
  if (e instanceof DecisionError) return res.status(e.status).json({ error: 'conflict', message: e.message });
  if (e instanceof z.ZodError) { const i = e.issues[0]; return res.status(400).json({ error: 'invalid', message: i?.message || 'Invalid value.', field: i?.path?.[0] }); }
  return next(e);
});

resources.get('/resources', requirePerm('view'), wrap(async (req, res) => { res.json(await listResources(req.user, req.query)); }));
resources.get('/resources.csv', requirePerm('view'), wrap(async (req, res) => { sendCsv(res, 'resource-access', await resourcesCsv(req.user, req.query)); }));
resources.get('/resources/:id', requirePerm('view'), wrap(async (req, res) => { res.json(await resourceDetail(req.user, req.params.id)); }));
resources.post('/resource-findings/:id/decision', requirePerm('decide'), wrap(async (req, res) => {
  const r = await decide(req.user, req.params.id, req.body);
  await audit(req, 'resource.decide', { type: 'resource_finding', id: r.finding.id }, { resource: r.finding.resource_name, control: r.finding.control, decision: r.decision, note: r.note });
  res.json({ ok: true, decision: r.decision });
}));
resources.delete('/resource-findings/:id/decision', requirePerm('decide'), wrap(async (req, res) => {
  const r = await undecide(req.user, req.params.id);
  await audit(req, 'resource.undecide', { type: 'resource_finding', id: r.finding.id }, { resource: r.finding.resource_name, control: r.finding.control });
  res.json({ ok: true });
}));
