// Admin → Extensions (turn optional features on or off), and the Networking extension's API.
import { Router } from 'express';
import { z } from 'zod';
import { audit } from '../audit.js';
import { requireUser, requirePerm } from '../auth/sessions.js';
import { listExtensions, setExtension, isEnabled } from '../extensions.js';
import { networkOverview, networkFindings, networkDetail, networkInventory, decideNetFinding, undecideNetFinding, NetError } from '../network/api.js';
import { requestNetworkRead } from '../network/sync.js';
import { clearCache } from '../cache.js';

export const extensions = Router();
extensions.use(requireUser);
const wrap = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch((e) => {
  if (e instanceof NetError || e.status === 404) return res.status(e.status || 404).json({ error: e.status === 400 ? 'invalid' : 'not_found', message: e.message });
  if (e instanceof z.ZodError) { const i = e.issues[0]; return res.status(400).json({ error: 'invalid', message: i?.message || 'Invalid value.' }); }
  return next(e);
});
// the extension's pages answer only while it is on
const on = (key) => wrap(async (req, res, next) => ((await isEnabled(key)) ? next() : res.status(404).json({ error: 'extension_off', message: 'The Networking extension is turned off. An admin can turn it on under Admin → Extensions.' })));

extensions.get('/extensions', requirePerm('view'), wrap(async (req, res) => { res.json({ items: await listExtensions() }); }));
extensions.put('/extensions/:key', requirePerm('settings'), wrap(async (req, res) => {
  const b = z.object({ enabled: z.boolean() }).parse(req.body);
  const changed = await setExtension(req.params.key, b.enabled, req.user.id);
  if (changed) {
    await audit(req, b.enabled ? 'extension.enable' : 'extension.disable', { type: 'extension', id: req.params.key });
    if (b.enabled && req.params.key === 'networking') await requestNetworkRead();
    clearCache();
  }
  res.json({ ok: true, changed, items: await listExtensions() });
}));

extensions.get('/network', requirePerm('view'), on('networking'), wrap(async (req, res) => { res.json(await networkOverview(req.user)); }));
extensions.get('/network/findings', requirePerm('view'), on('networking'), wrap(async (req, res) => { res.json(await networkFindings(req.user, req.query)); }));
extensions.get('/network/node', requirePerm('view'), on('networking'), wrap(async (req, res) => { res.json(await networkDetail(req.user, String(req.query.id || ''))); }));
extensions.get('/network/inventory', requirePerm('view'), on('networking'), wrap(async (req, res) => { res.json(await networkInventory(req.user, req.query)); }));
extensions.post('/network/read', requirePerm('scan'), on('networking'), wrap(async (req, res) => {
  await requestNetworkRead();
  await audit(req, 'network.read', { type: 'extension', id: 'networking' });
  res.json({ ok: true });
}));
extensions.post('/network-findings/:id/decision', requirePerm('decide'), on('networking'), wrap(async (req, res) => {
  const r = await decideNetFinding(req.user, req.params.id, z.object({ decision: z.enum(['expected', 'investigate']), note: z.string().max(1000).optional() }).parse(req.body));
  await audit(req, 'network.decide', { type: 'net_finding', id: r.id }, { control: r.control, decision: r.decision, note: r.note });
  clearCache();
  res.json({ ok: true });
}));
extensions.delete('/network-findings/:id/decision', requirePerm('decide'), on('networking'), wrap(async (req, res) => {
  const r = await undecideNetFinding(req.user, req.params.id);
  await audit(req, 'network.undecide', { type: 'net_finding', id: r.id }, { control: r.control });
  clearCache();
  res.json({ ok: true });
}));
