// Review → Access reviews: frozen snapshots for periodic user access reviews, signed off by each review team.
import { Router } from 'express';
import { z } from 'zod';
import { audit } from '../audit.js';
import { requireUser, requirePerm } from '../auth/sessions.js';
import { sendCsv } from '../csv.js';
import { createReview, listReviews, getReview, reviewItems, signOff, deleteReview, reviewCsv, ReviewError } from '../accessReviews.js';

export const reviews = Router();
reviews.use(requireUser);
const uuid = z.string().uuid();
const wrap = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch((e) => {
  if (e instanceof ReviewError) return res.status(e.status).json({ error: e.status === 404 ? 'not_found' : e.status === 409 ? 'conflict' : e.status === 403 ? 'forbidden' : 'invalid', message: e.message, field: e.field });
  if (e instanceof z.ZodError) { const i = e.issues[0]; return res.status(400).json({ error: 'invalid', message: i?.message || 'Invalid value.', field: i?.path?.join('.') }); }
  return next(e);
});
const id = (req) => { const r = uuid.safeParse(req.params.id); if (!r.success) throw new ReviewError(404, 'That review does not exist.'); return r.data; };

reviews.get('/reviews', requirePerm('view'), wrap(async (req, res) => res.json({ items: await listReviews(req.user) })));
reviews.post('/reviews', requirePerm('decide'), wrap(async (req, res) => {
  const r = await createReview(req.user, req.body);
  await audit(req, 'review.create', { type: 'access_review', id: r.id }, { name: req.body?.name, from: req.body?.from, to: req.body?.to, accounts: req.body?.accounts?.length, identities: r.totals.identities });
  res.status(201).json(r);
}));
reviews.get('/reviews/:id', requirePerm('view'), wrap(async (req, res) => res.json(await getReview(req.user, id(req)))));
reviews.get('/reviews/:id/items', requirePerm('view'), wrap(async (req, res) => res.json(await reviewItems(req.user, id(req), req.query))));
for (const which of ['identities', 'decisions']) {
  reviews.get(`/reviews/:id/${which}.csv`, requirePerm('view'), wrap(async (req, res) => {
    const r = await getReview(req.user, id(req));
    sendCsv(res, `${r.name.replace(/[^\w.-]+/g, '-').slice(0, 60)}-${which}`, await reviewCsv(req.user, r.id, which));
  }));
}
reviews.post('/reviews/:id/signoff', requirePerm('approve'), wrap(async (req, res) => {
  const out = await signOff(req.user, id(req), req.body);
  await audit(req, 'review.signoff', { type: 'access_review', id: req.params.id }, { team: out.team, complete: out.signed });
  res.json(out);
}));
reviews.delete('/reviews/:id', requirePerm('decide'), wrap(async (req, res) => {
  const r = await deleteReview(req.user, id(req));
  await audit(req, 'review.delete', { type: 'access_review', id: r.id }, { name: r.name });
  res.json({ ok: true });
}));
