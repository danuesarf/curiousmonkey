// Home: the page after sign-in (GET /home), its "Not now" and setup-checklist switches, the team's version for the wall
// view, and the list of least-privilege drafts waiting for approval (the Findings page's Drafts view).
import { Router } from 'express';
import { z } from 'zod';
import { requireUser, requirePerm } from '../auth/sessions.js';
import { homeFor, homeForTeam, snooze, unsnoozeAll, setSetupHidden, waitingDrafts } from '../homeApi.js';
import { historyFor } from '../history.js';
import { query } from '../db.js';
import { scopeSql } from '../auth/rbac.js';

export const home = Router();
home.use(requireUser);
const wrap = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

home.get('/home', requirePerm('view'), wrap(async (req, res) => {
  // the wall view: the team's list, in the member's own accounts
  if (req.query.wall === '1') return res.json(await homeForTeam({ team: req.user.team || null, accounts: req.user.scope_accounts || null }));
  res.json(await homeFor(req.user));
}));

home.post('/home/snooze', requirePerm('view'), wrap(async (req, res) => {
  const b = z.object({ key: z.string().min(1).max(80).regex(/^[\w:-]+$/), days: z.number().int().min(1).max(90).optional() }).parse(req.body || {});
  res.json(await snooze(req.user, b.key, b.days));
}));
home.delete('/home/snooze', requirePerm('view'), wrap(async (req, res) => { await unsnoozeAll(req.user); res.json({ ok: true }); }));

home.post('/home/setup', requirePerm('view'), wrap(async (req, res) => {
  const b = z.object({ hidden: z.boolean() }).parse(req.body || {});
  await setSetupHidden(req.user, b.hidden);
  res.json({ hidden: b.hidden });
}));

/** Drafts waiting for approval in the member's accounts. `mine=1`: only the ones the member's team still has to approve. */
home.get('/recommendations', requirePerm('view'), wrap(async (req, res) => {
  const q = z.object({ status: z.literal('draft').default('draft'), mine: z.enum(['0', '1']).optional() }).parse(req.query);
  const p = []; const accounts = (await query(`SELECT * FROM cloud_accounts a WHERE a.status <> 'planned' AND ${scopeSql(req.user, 'a.id', p)}`, p)).rows;
  const hist = await historyFor(accounts);
  const complete = accounts.filter((a) => hist.get(a.id).complete).map((a) => a.id);
  const items = await waitingDrafts(req.user, q.mine === '1' ? req.user.team || null : null, complete);
  res.json({ items, total: items.length, reading: accounts.length - complete.length, team: req.user.team || null });
}));
