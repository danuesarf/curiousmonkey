import { Router } from 'express';
import { z } from 'zod';
import { config } from '../config.js';
import { query } from '../db.js';
import { audit } from '../audit.js';
import { requireUser, requirePerm } from '../auth/sessions.js';
import { ROLES, TEAMS } from '../auth/rbac.js';
import { sha256, randomToken } from '../auth/crypto.js';
import { workerStatus } from '../workerStatus.js';
import { queueOverview, runDetail, jobLogs, retryJobs, cancelRun, rebuildRegion, SLICE_CHOICES } from '../queue.js';

export const admin = Router();
admin.use(requireUser);
const wrap = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);
const uuid = z.string().uuid();

// ---------- members ----------
admin.get('/members', requirePerm('members'), wrap(async (req, res) => {
  const [u, inv] = await Promise.all([
    query('SELECT id, email, name, role, team, scope_accounts, totp_confirmed, oidc_subject IS NOT NULL AS sso, disabled, last_login_at, created_at FROM users ORDER BY created_at'),
    query(`SELECT email, role, team, scope_accounts, expires_at, created_at FROM invites WHERE accepted_at IS NULL AND expires_at > now() ORDER BY created_at DESC`),
  ]);
  res.json({ members: u.rows, invites: inv.rows });
}));

const Grant = z.object({ role: z.enum(ROLES), team: z.enum(TEAMS).nullable().optional(), scope_accounts: z.array(z.string().uuid()).nullable().optional() });
const teamRule = (g) => (['reviewer'].includes(g.role) && !g.team) ? 'Reviewers must belong to Infrastructure Security or Information Security.' : null;

admin.post('/members/invite', requirePerm('members'), wrap(async (req, res) => {
  const b = Grant.extend({ email: z.string().trim().toLowerCase().email() }).parse(req.body);
  if (b.role === 'owner' && req.user.role !== 'owner') return res.status(403).json({ error: 'forbidden', message: 'Only an owner can invite another owner.' });
  const problem = teamRule(b); if (problem) return res.status(400).json({ error: 'team_required', message: problem });
  if ((await query('SELECT 1 FROM users WHERE lower(email)=$1', [b.email])).rowCount) return res.status(409).json({ error: 'exists', message: 'That person already has an account.' });
  const token = randomToken(24);
  await query(`INSERT INTO invites(token_hash, email, role, team, scope_accounts, created_by, expires_at) VALUES ($1,$2,$3,$4,$5,$6, now() + interval '7 days')`,
    [sha256(token), b.email, b.role, b.team || null, b.scope_accounts || null, req.user.id]);
  await audit(req, 'member.invite', { type: 'invite' }, { email: b.email, role: b.role, team: b.team });
  // No email is sent. The link is shown once; the owner shares it.
  res.status(201).json({ link: `${config.publicUrl}/#/signup?invite=${token}`, email: b.email, expiresInDays: 7 });
}));

admin.patch('/members/:id', requirePerm('members'), wrap(async (req, res) => {
  const id = uuid.parse(req.params.id);
  const b = Grant.partial().extend({ disabled: z.boolean().optional() }).parse(req.body);
  const target = (await query('SELECT * FROM users WHERE id=$1', [id])).rows[0];
  if (!target) return res.status(404).json({ error: 'not_found' });
  if ((target.role === 'owner' || b.role === 'owner') && req.user.role !== 'owner') return res.status(403).json({ error: 'forbidden', message: 'Only an owner can change an owner.' });
  const next = { role: b.role ?? target.role, team: b.team === undefined ? target.team : b.team };
  const problem = teamRule(next); if (problem) return res.status(400).json({ error: 'team_required', message: problem });
  if (target.role === 'owner' && (b.role && b.role !== 'owner' || b.disabled)) {
    const owners = (await query(`SELECT count(*)::int n FROM users WHERE role='owner' AND NOT disabled`)).rows[0].n;
    if (owners <= 1) return res.status(409).json({ error: 'last_owner', message: 'A workspace needs at least one active owner.' });
  }
  await query(`UPDATE users SET role=$2, team=$3, scope_accounts=$4, disabled=$5 WHERE id=$1`,
    [id, next.role, next.team, b.scope_accounts === undefined ? target.scope_accounts : b.scope_accounts, b.disabled ?? target.disabled]);
  if (b.disabled || b.role) await query('DELETE FROM sessions WHERE user_id=$1', [id]);          // changes apply at once
  await audit(req, 'member.update', { type: 'user', id }, { email: target.email, ...b });
  res.json({ ok: true });
}));

admin.get('/sso/mappings', requirePerm('sso'), wrap(async (req, res) => res.json({ items: (await query('SELECT * FROM sso_group_mappings ORDER BY group_name')).rows })));
admin.put('/sso/mappings', requirePerm('sso'), wrap(async (req, res) => {
  const b = z.object({ group_name: z.string().trim().min(1).max(200) }).merge(Grant).parse(req.body);
  const problem = teamRule(b); if (problem) return res.status(400).json({ error: 'team_required', message: problem });
  await query(`INSERT INTO sso_group_mappings(group_name, role, team, scope_accounts) VALUES ($1,$2,$3,$4)
               ON CONFLICT (group_name) DO UPDATE SET role=EXCLUDED.role, team=EXCLUDED.team, scope_accounts=EXCLUDED.scope_accounts`, [b.group_name, b.role, b.team || null, b.scope_accounts || null]);
  await audit(req, 'sso.mapping', { type: 'group', id: b.group_name }, b);
  res.json({ ok: true });
}));
admin.delete('/sso/mappings/:group', requirePerm('sso'), wrap(async (req, res) => {
  await query('DELETE FROM sso_group_mappings WHERE group_name=$1', [req.params.group]);
  await audit(req, 'sso.mapping_delete', { type: 'group', id: req.params.group });
  res.json({ ok: true });
}));

// ---------- audit log ----------
admin.get('/audit', requirePerm('audit'), wrap(async (req, res) => {
  const p = []; const w = ['TRUE']; const q = req.query;
  if (q.action) { p.push(`${String(q.action).slice(0, 60)}%`); w.push(`action LIKE $${p.length}`); }
  if (q.actor) { p.push(`%${String(q.actor).slice(0, 80)}%`); w.push(`actor_email ILIKE $${p.length}`); }
  const limit = Math.min(Number(q.limit) || 100, 500), offset = (Math.max(Number(q.page) || 1, 1) - 1) * limit;
  const r = await query(`SELECT id, at, actor_email, action, target_type, target_id, detail, ip, count(*) OVER()::int AS total FROM audit_log WHERE ${w.join(' AND ')} ORDER BY id DESC LIMIT ${limit} OFFSET ${offset}`, p);
  res.json({ items: r.rows.map(({ total, ...x }) => x), total: r.rows[0]?.total ?? 0 });
}));

// ---------- scanner monitoring ----------
admin.get('/ops/workers', requirePerm('ops'), wrap(async (req, res) => res.json(await workerStatus({ range: String(req.query.range || '1h') })))) ;
admin.get('/ops/overview', requirePerm('ops'), wrap(async (req, res) => res.json(await queueOverview())));
admin.get('/ops/runs/:id', requirePerm('ops'), wrap(async (req, res) => {
  const d = await runDetail(uuid.parse(req.params.id));
  if (!d) return res.status(404).json({ error: 'not_found' });
  res.json(d);
}));
admin.get('/ops/jobs/:id/log', requirePerm('ops'), wrap(async (req, res) => res.json({ items: await jobLogs(uuid.parse(req.params.id)) })));
admin.post('/ops/runs/:id/retry', requirePerm('scan'), wrap(async (req, res) => {
  const n = await retryJobs({ runId: uuid.parse(req.params.id) });
  await audit(req, 'ops.retry_run', { type: 'run', id: req.params.id }, { jobs: n });
  res.json({ requeued: n });
}));
admin.post('/ops/jobs/:id/rebuild', requirePerm('scan'), wrap(async (req, res) => {
  const body = z.object({ sliceHours: z.number().nullable().optional() }).parse(req.body || {});
  const r = await rebuildRegion({ jobId: uuid.parse(req.params.id), sliceHours: body.sliceHours ?? null });
  if (r.error) {
    const msg = { 'not-found': 'No such job.', 'not-events': 'Only an events step can be rebuilt.', running: 'This step is running. Cancel the scan first.',
      slice: `Slice size must be one of ${SLICE_CHOICES.join(', ')} hours.` }[r.error];
    return res.status(r.error === 'not-found' ? 404 : 409).json({ error: msg });
  }
  await audit(req, 'ops.rebuild_region', { type: 'job', id: req.params.id }, { region: r.region, sliceHours: body.sliceHours ?? null });
  res.json(r);
}));
admin.post('/ops/jobs/:id/retry', requirePerm('scan'), wrap(async (req, res) => {
  const n = await retryJobs({ jobId: uuid.parse(req.params.id) });
  await audit(req, 'ops.retry_job', { type: 'job', id: req.params.id });
  res.json({ requeued: n });
}));
admin.post('/ops/runs/:id/cancel', requirePerm('scan'), wrap(async (req, res) => {
  const n = await cancelRun(uuid.parse(req.params.id));
  await audit(req, 'ops.cancel_run', { type: 'run', id: req.params.id }, { jobs: n });
  res.json({ canceled: n });
}));
