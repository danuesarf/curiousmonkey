import { Router } from 'express';
import { z } from 'zod';
import { config } from '../config.js';
import { query, tx } from '../db.js';
import { audit } from '../audit.js';
import { requireUser, requirePerm } from '../auth/sessions.js';
import { inScope, scopeSql } from '../auth/rbac.js';
import { enqueueRun } from '../queue.js';
import { scannerSnippets } from '../onboarding.js';
import { sealCredentials } from '../aws/credentials.js';
import { suggestMappings, decideMapping, markUnresolved } from '../recommender/eventMap.js';
import { listSessions, buildTrack } from '../sessions.js';
import { historyFor } from '../history.js';
import { effectiveLookback } from '../settings.js';
import { estate, accountRadar, changeFeed, markSeen, identities, blastRadius } from '../radarApi.js';
import { trustMap, toCsv } from '../trustmap.js';
import { loadMappings, translate } from '../analyzer/mappings.js';
import { recommend, latestRecommendation, approve, notifyApproved, toTerraform, loadRoleContext, Refusal } from '../recommender/index.js';

export const data = Router();
data.use(requireUser);
const wrap = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);
const uuid = z.string().uuid();
const NotFound = () => Object.assign(new Error('Not found'), { status: 404 });

const accountFor = async (req, id) => {
  const a = (await query('SELECT * FROM cloud_accounts WHERE id=$1', [uuid.parse(id)])).rows[0];
  if (!a || !inScope(req.user, a.id)) throw NotFound();
  return a;
};
const roleFor = async (req, id) => {
  const r = (await query('SELECT r.*, a.name AS account_name, a.account_id AS aws_account_id, a.environment FROM roles r JOIN cloud_accounts a ON a.id=r.account_id WHERE r.id=$1', [uuid.parse(id)])).rows[0];
  if (!r || !inScope(req.user, r.account_id)) throw NotFound();
  return r;
};

// ---------- onboarding and accounts ----------
const ROLE_NAME = /^[\w+=,.@-]{1,64}$/;
const ARN = /^arn:aws[\w-]*:(iam|sts)::\d{12}:[\w+=,.@\/-]+$/;
const S3In = z.object({
  bucket: z.string().regex(/^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$/, 'Not a valid S3 bucket name'),
  prefix: z.string().trim().max(200).regex(/^[\w!\-.*'()/]*$/, 'Prefix has characters S3 keys cannot use').optional().nullable(),
  orgId: z.string().trim().regex(/^o-[a-z0-9]{10,32}$/, 'Organization IDs look like o-abc123def4').optional().nullable().or(z.literal('')),
  region: z.string().regex(/^[a-z]{2}(-[a-z]+)+-\d$/).optional().nullable().or(z.literal('')),
});
const KeysIn = z.object({
  accessKeyId: z.string().trim().regex(/^(AKIA|ASIA)[A-Z0-9]{12,20}$/, 'Access key IDs start with AKIA or ASIA'),
  secretAccessKey: z.string().trim().min(30).max(128),
  sessionToken: z.string().trim().max(4000).optional().nullable().or(z.literal('')),
});
const AccountFields = {
  name: z.string().trim().min(1).max(80),
  environment: z.enum(['production', 'staging', 'development', 'sandbox']),
  ou: z.string().trim().max(120).nullable().or(z.literal('')),
  regions: z.array(z.string().regex(/^[a-z]{2}(-[a-z]+)+-\d$/)).min(1).max(20),
  eventSource: z.enum(['event-history', 's3']),
  lookbackDays: z.number().int().min(1).max(730),
  s3: S3In.nullable(),
  authMode: z.enum(['assume_role', 'access_key']),
  baseIdentity: z.enum(['system', 'stored']),
  roleName: z.string().regex(ROLE_NAME),
  trustPrincipal: z.string().trim().regex(ARN, 'Use an IAM role or user ARN').nullable().or(z.literal('')),
  credentials: KeysIn.nullable(),
};
const AccountIn = z.object({
  ...AccountFields, accountId: z.string().regex(/^\d{12}$/, 'AWS account IDs are 12 digits'),
  environment: AccountFields.environment.default('production'), ou: AccountFields.ou.default(null), regions: AccountFields.regions.default(config.scanner.defaultRegions),
  eventSource: AccountFields.eventSource.default('event-history'), lookbackDays: AccountFields.lookbackDays.optional(),
  s3: AccountFields.s3.default(null), authMode: AccountFields.authMode.default('assume_role'), baseIdentity: AccountFields.baseIdentity.default('system'),
  roleName: AccountFields.roleName.default(config.scanner.roleName), trustPrincipal: AccountFields.trustPrincipal.default(null),
  credentials: AccountFields.credentials.default(null),
});
const AccountPatch = z.object({ ...Object.fromEntries(Object.entries(AccountFields).map(([k, v]) => [k, v.optional()])), rebuildHistory: z.boolean().optional() });

const say = (res, message, field) => res.status(400).json({ error: 'invalid', message, field });
/** Rules that span several fields. Returns an error message or null. */
function checkAccount(x, hasStored, lookbackChanged = true) {
  if (x.eventSource === 's3' && !x.s3?.bucket) return ['Name the S3 bucket your trail writes to.', 's3.bucket'];
  if (x.eventSource === 'event-history' && x.lookbackDays > 90) return ['Event History only keeps 90 days. Pick 90 or less, or use an S3 trail.', 'lookbackDays'];
  if (lookbackChanged && x.lookbackDays > config.scanner.maxLookbackDays) return [`This workspace reads at most ${config.scanner.maxLookbackDays} days back. An owner or admin can raise it under Configuration.`, 'lookbackDays'];
  const needsKeys = x.authMode === 'access_key' || x.baseIdentity === 'stored';
  if (needsKeys && !x.credentials && !hasStored) return [x.authMode === 'access_key' ? 'Enter the scanner user’s access key.' : 'Enter the access key the worker should start from.', 'credentials'];
  return null;
}
function accountColumns(x, accountId, prev = {}) {
  const needsKeys = x.authMode === 'access_key' || x.baseIdentity === 'stored';
  const cols = {
    name: x.name, environment: x.environment, ou: x.ou || null, regions: x.regions,
    event_source: x.eventSource, lookback_days: x.lookbackDays,
    s3_bucket: x.eventSource === 's3' ? x.s3.bucket : null, s3_prefix: x.eventSource === 's3' ? x.s3.prefix || null : null,
    s3_org_id: x.eventSource === 's3' ? x.s3.orgId || null : null, s3_region: x.eventSource === 's3' ? x.s3.region || null : null,
    auth_mode: x.authMode, base_identity: x.authMode === 'access_key' ? 'stored' : x.baseIdentity,
    role_arn: x.authMode === 'assume_role' ? `arn:aws:iam::${accountId}:role/${x.roleName}` : null,
    trust_principal: x.authMode === 'assume_role' ? x.trustPrincipal || null : null,
  };
  if (x.credentials) {
    const sealed = sealCredentials({ ...x.credentials, sessionToken: x.credentials.sessionToken || undefined });
    cols.credentials_enc = sealed.enc; cols.credentials_hint = sealed.hint;
  } else if (!needsKeys) { cols.credentials_enc = null; cols.credentials_hint = null; }   // keys nobody uses are not kept
  else { cols.credentials_enc = prev.credentials_enc; cols.credentials_hint = prev.credentials_hint; }
  return cols;
}
/** The account as the API returns it. Stored secrets never leave the server. */
export function publicAccount(a) {
  const { credentials_enc, ...rest } = a;
  return { ...rest, has_credentials: !!credentials_enc, role_name: a.role_arn ? a.role_arn.split('/').pop() : null };
}

data.get('/onboarding/identity', requirePerm('accounts'), wrap(async (req, res) => {
  const w = (await query(`SELECT aws_identity, heartbeat_at > now() - interval '2 minutes' AS alive FROM workers
    WHERE aws_identity IS NOT NULL ORDER BY (heartbeat_at > now() - interval '2 minutes') DESC, heartbeat_at DESC LIMIT 1`)).rows[0];
  res.json({ awsMode: config.awsMode, configuredPrincipal: config.scanner.principalArn || null, worker: w ? { ...w.aws_identity, alive: w.alive } : null });
}));

data.get('/onboarding/snippets', requirePerm('accounts'), wrap(async (req, res) => {
  const ws = (await query('SELECT external_id FROM workspace')).rows[0];
  const q = z.object({
    mode: z.enum(['assume_role', 'access_key']).default('assume_role'),
    roleName: z.string().regex(ROLE_NAME).default(config.scanner.roleName),
    principal: z.string().regex(ARN).optional(),
    bucket: z.string().optional(), prefix: z.string().optional(),
  }).parse(Object.fromEntries(Object.entries(req.query).filter(([, v]) => v !== '')));
  const s3 = q.bucket ? S3In.parse({ bucket: q.bucket, prefix: q.prefix || null }) : null;
  const principal = q.principal || config.scanner.principalArn || null;
  const s = scannerSnippets({ mode: q.mode, principalArn: principal, roleName: q.roleName, externalId: ws.external_id, s3 });
  res.json({ ...s, roleName: q.roleName, externalId: ws.external_id, principalArn: principal, permissions: s.perms });
}));

data.post('/accounts', requirePerm('accounts'), wrap(async (req, res) => {
  const b = AccountIn.parse(req.body);
  if (b.lookbackDays == null) b.lookbackDays = Math.min(config.scanner.defaultLookbackDays, b.eventSource === 's3' ? config.scanner.maxLookbackDays : 90);
  const bad = checkAccount(b, false);
  if (bad) return say(res, ...bad);
  const dup = await query('SELECT 1 FROM cloud_accounts WHERE account_id=$1', [b.accountId]);
  if (dup.rowCount) return res.status(409).json({ error: 'exists', message: 'That AWS account is already connected.', field: 'accountId' });
  const cols = { account_id: b.accountId, ...accountColumns(b, b.accountId), created_by: req.user.id };
  const keys = Object.keys(cols);
  const row = (await query(`INSERT INTO cloud_accounts(${keys.join(',')}) VALUES (${keys.map((_, i) => `$${i + 1}`).join(',')}) RETURNING *`, Object.values(cols))).rows[0];
  await audit(req, 'account.create', { type: 'account', id: row.id }, { accountId: b.accountId, authMode: b.authMode, eventSource: b.eventSource });
  res.status(201).json(publicAccount(row));
}));

data.get('/accounts/:id', requirePerm('view'), wrap(async (req, res) => {
  res.json(publicAccount(await accountFor(req, req.params.id)));
}));

data.patch('/accounts/:id', requirePerm('accounts'), wrap(async (req, res) => {
  const a = await accountFor(req, req.params.id);
  const p = AccountPatch.parse(req.body);
  const cur = {
    name: a.name, environment: a.environment, ou: a.ou, regions: a.regions, eventSource: a.event_source, lookbackDays: a.lookback_days,
    s3: a.s3_bucket ? { bucket: a.s3_bucket, prefix: a.s3_prefix, orgId: a.s3_org_id, region: a.s3_region } : null,
    authMode: a.auth_mode, baseIdentity: a.base_identity, roleName: a.role_arn ? a.role_arn.split('/').pop() : config.scanner.roleName,
    trustPrincipal: a.trust_principal, credentials: null,
  };
  const next = { ...cur, ...Object.fromEntries(Object.entries(p).filter(([k, v]) => v !== undefined && k !== 'rebuildHistory')) };
  const bad = checkAccount(next, !!a.credentials_enc, p.lookbackDays !== undefined && p.lookbackDays !== a.lookback_days);
  if (bad) return say(res, ...bad);
  const cols = accountColumns(next, a.account_id, a);
  const accessChanged = ['auth_mode', 'base_identity', 'role_arn', 'credentials_enc', 'event_source', 's3_bucket', 's3_prefix', 's3_org_id', 's3_region']
    .some((k) => (cols[k] ?? null) !== (a[k] ?? null));
  if (accessChanged) { cols.status = 'pending'; cols.status_detail = null; }
  cols.updated_at = new Date();
  const keys = Object.keys(cols);
  const row = await tx(async (c) => {
    if (p.rebuildHistory) {
      // Start the stored history over. Analysis results are recomputed by the next scan.
      await c.query('DELETE FROM scan_checkpoints WHERE account_id=$1', [a.id]);
      await c.query('DELETE FROM trail_cursors WHERE account_id=$1', [a.id]);
      await c.query('DELETE FROM seen_events WHERE account_id=$1', [a.id]);
      for (const t of ['activity_daily', 'activity_resources', 'passrole_observed', 'principals']) {
        await c.query(`DELETE FROM ${t} WHERE role_id IN (SELECT id FROM roles WHERE account_id=$1)`, [a.id]);
      }
      // counts that would otherwise be added to again by the re-read
      for (const t of ['event_coverage', 'unmapped_events', 'track_sessions']) await c.query(`DELETE FROM ${t} WHERE account_id=$1`, [a.id]);
    }
    return (await c.query(`UPDATE cloud_accounts SET ${keys.map((k, i) => `${k}=$${i + 2}`).join(', ')} WHERE id=$1 RETURNING *`, [a.id, ...Object.values(cols)])).rows[0];
  });
  await audit(req, 'account.update', { type: 'account', id: a.id }, { changed: Object.keys(p).filter((k) => k !== 'credentials'), credentialsReplaced: !!p.credentials, rebuildHistory: !!p.rebuildHistory });
  res.json({ ...publicAccount(row), accessChanged });
}));

data.get('/accounts', requirePerm('view'), wrap(async (req, res) => {
  const p = [];
  const r = await query(`
    SELECT a.*, (SELECT count(*)::int FROM roles WHERE account_id=a.id AND deleted_at IS NULL) AS roles,
      (SELECT count(*)::int FROM data_event_sources WHERE account_id=a.id) AS data_event_sources,
      (SELECT json_build_object('id', id, 'status', status, 'trigger', trigger, 'created_at', created_at, 'finished_at', finished_at, 'error', error)
         FROM scan_runs WHERE account_id=a.id ORDER BY created_at DESC LIMIT 1) AS last_run,
      (SELECT coalesce(json_agg(json_build_object('region', region, 'first', first_event_time, 'last', last_event_time, 'events', events_read, 'gap', gap_detected)), '[]')
         FROM scan_checkpoints WHERE account_id=a.id) AS checkpoints
    FROM cloud_accounts a WHERE ${scopeSql(req.user, 'a.id', p)} ORDER BY a.name`, p);
  const hist = await historyFor(r.rows);
  res.json({ items: r.rows.map((a) => ({ ...publicAccount(a), history: hist.get(a.id) })) });
}));

data.get('/accounts/:id/data-events', requirePerm('view'), wrap(async (req, res) => {
  const a = await accountFor(req, req.params.id);
  const r = await query('SELECT source_name, source_type, resource_type, arn_patterns, read_write, readable FROM data_event_sources WHERE account_id=$1 ORDER BY resource_type, source_name', [a.id]);
  res.json({ items: r.rows, note: a.event_source === 's3' ? 'Rows marked readable belong to the trail this account reads from S3, so data-plane calls they log count as use. Calls not seen stay unconfirmed, because a trail may cover only some buckets or tables.' : 'CloudTrail Event History holds management events only. These sources record data events, which this scan cannot read, so the tool reports them but does not use them as evidence. Reading the trail from S3 would let it use them.' });
}));

// ---------- event coverage and event-name mappings ----------
const COVER = ['events', 'assume_events', 'role_calls', 'recovered_role', 'other_role', 'not_role', 'no_permission', 'unmapped', 'no_resources'];
data.get('/accounts/:id/coverage', requirePerm('view'), wrap(async (req, res) => {
  const a = await accountFor(req, req.params.id);
  const days = z.coerce.number().int().min(1).max(730).default(30).parse(req.query.days || undefined);
  const sum = COVER.map((c) => `sum(${c})::bigint AS ${c}`).join(', ');
  const [tot, reg, un] = await Promise.all([
    query(`SELECT ${sum}, min(day) AS first_day, max(day) AS last_day FROM event_coverage WHERE account_id=$1 AND day >= current_date - $2::int`, [a.id, days]),
    query(`SELECT region, ${sum} FROM event_coverage WHERE account_id=$1 AND day >= current_date - $2::int GROUP BY region ORDER BY region`, [a.id, days]),
    query(`SELECT u.raw_action, u.event_source, u.event_name, u.count, u.first_seen, u.last_seen, u.identity_type, u.param_keys,
             (SELECT count(DISTINCT d.role_id)::int FROM activity_daily d JOIN roles r ON r.id=d.role_id WHERE r.account_id=u.account_id AND d.action=u.raw_action) AS roles,
             CASE WHEN m.raw_action IS NULL THEN NULL ELSE json_build_object('action', m.action, 'status', m.status, 'source', m.source, 'confidence', m.confidence, 'note', m.note, 'decided_at', m.decided_at, 'reopen_at', m.reopen_at,
               'decided_by', (SELECT name FROM users WHERE id=m.decided_by)) END AS mapping,
             CASE WHEN m.raw_action IS NULL THEN 'open' WHEN m.status='suggested' THEN 'suggested' WHEN m.status='accepted' THEN 'identified'
                  WHEN m.reopen_at < now() AND u.last_seen > m.decided_at THEN 'reopened' ELSE 'unresolved' END AS state,
             (SELECT array_agg(DISTINCT r.name) FROM activity_daily d JOIN roles r ON r.id=d.role_id WHERE r.account_id=u.account_id AND d.action=u.raw_action) AS role_names
           FROM unmapped_events u LEFT JOIN event_action_map m ON m.raw_action=u.raw_action
           WHERE u.account_id=$1 ORDER BY (m.status='accepted') NULLS FIRST, u.count DESC LIMIT 500`, [a.id]),
  ]);
  const num = (r) => Object.fromEntries(Object.entries(r).map(([k, v]) => [k, COVER.includes(k) ? Number(v || 0) : v]));
  res.json({ days, totals: num(tot.rows[0]), regions: reg.rows.map(num), unmapped: un.rows, bedrockEnabled: config.ai.enabled });
}));

data.post('/accounts/:id/unmapped/suggest', requirePerm('decide'), wrap(async (req, res) => {
  const a = await accountFor(req, req.params.id);
  const b = z.object({ rawActions: z.array(z.string().max(200)).max(50).optional() }).parse(req.body || {});
  const items = (await query(
    `SELECT u.* FROM unmapped_events u LEFT JOIN event_action_map m ON m.raw_action=u.raw_action
     WHERE u.account_id=$1 AND (m.status IS NULL OR m.status <> 'accepted') ${b.rawActions ? 'AND u.raw_action = ANY($2)' : ''}
     ORDER BY u.count DESC LIMIT 50`, b.rawActions ? [a.id, b.rawActions] : [a.id])).rows;
  const out = await suggestMappings(items);
  await audit(req, 'mapping.suggest', { type: 'account', id: a.id }, { asked: items.length, suggested: out.suggested.length, rejected: out.rejected.length });
  res.json(out);
}));

data.put('/event-mappings', requirePerm('decide'), wrap(async (req, res) => {
  const b = z.object({ rawAction: z.string().max(200), action: z.string().max(200).nullable(), note: z.string().max(400).optional() }).parse(req.body);
  const seen = (await query('SELECT event_source, event_name FROM unmapped_events WHERE raw_action=$1 LIMIT 1', [b.rawAction])).rows[0];
  if (!seen) throw NotFound();
  const row = await decideMapping({ rawAction: b.rawAction, eventSource: seen.event_source, eventName: seen.event_name, action: b.action, userId: req.user.id, note: b.note || null });
  await audit(req, 'mapping.accept', { type: 'event-mapping', id: b.rawAction }, { action: row.action });
  res.json(row);
}));

data.post('/event-mappings/unresolved', requirePerm('decide'), wrap(async (req, res) => {
  const b = z.object({ rawAction: z.string().max(200), note: z.string().max(400) }).parse(req.body);
  const seen = (await query('SELECT event_source, event_name FROM unmapped_events WHERE raw_action=$1 LIMIT 1', [b.rawAction])).rows[0];
  if (!seen) throw NotFound();
  const row = await markUnresolved({ rawAction: b.rawAction, eventSource: seen.event_source, eventName: seen.event_name, note: b.note, userId: req.user.id });
  await audit(req, 'mapping.unresolved', { type: 'event-mapping', id: b.rawAction });
  res.json(row);
}));

data.delete('/event-mappings', requirePerm('decide'), wrap(async (req, res) => {
  const raw = z.string().max(200).parse(req.query.raw);
  await query('DELETE FROM event_action_map WHERE raw_action=$1', [raw]);
  await audit(req, 'mapping.clear', { type: 'event-mapping', id: raw });
  res.json({ ok: true });
}));

// ---------- sessions and tracks ----------
data.get('/sessions', requirePerm('view'), wrap(async (req, res) => {
  const q = z.object({ account: uuid.optional(), role: uuid.optional(), limit: z.coerce.number().int().min(1).max(200).default(50) }).parse(req.query);
  if (q.account && !inScope(req.user, q.account)) throw NotFound();
  if (q.role) await roleFor(req, q.role);
  res.json({ items: await listSessions(req.user, { accountId: q.account, roleId: q.role, limit: q.limit }), retentionDays: config.scanner.sessionRetentionDays });
}));
data.get('/sessions/:id/track', requirePerm('view'), wrap(async (req, res) => {
  const t = await buildTrack(req.user, uuid.parse(req.params.id));
  if (!t) throw NotFound();
  res.json(t);
}));

const startScan = (trigger) => wrap(async (req, res) => {
  const a = await accountFor(req, req.params.id);
  const run = await enqueueRun(a.id, { trigger, requestedBy: req.user.id });
  if (!run) return res.status(409).json({ error: 'scan_in_progress', message: 'A scan is already running for this account.' });
  await audit(req, `account.${trigger}`, { type: 'account', id: a.id });
  res.status(202).json({ runId: run });
});
data.post('/accounts/:id/verify', requirePerm('accounts'), startScan('onboarding'));
data.post('/accounts/:id/scan', requirePerm('scan'), startScan('manual'));
data.delete('/accounts/:id', requirePerm('accounts'), wrap(async (req, res) => {
  const a = await accountFor(req, req.params.id);
  await query('DELETE FROM cloud_accounts WHERE id=$1', [a.id]);
  await audit(req, 'account.delete', { type: 'account', id: a.id }, { accountId: a.account_id });
  res.json({ ok: true });
}));

// ---------- roles ----------
const csv = (v) => (v ? String(v).split(',').filter(Boolean) : []);
data.get('/roles', requirePerm('view'), wrap(async (req, res) => {
  const p = []; const where = ['r.deleted_at IS NULL', scopeSql(req.user, 'r.account_id', p)];
  const add = (sql, v) => { p.push(v); where.push(sql.replaceAll('?', `$${p.length}`)); };
  const q = req.query;
  if (q.q) add('(r.name ILIKE ? OR r.arn ILIKE ?)', `%${String(q.q).slice(0, 100)}%`);
  if (csv(q.accounts).length) add('r.account_id = ANY(?::uuid[])', csv(q.accounts).filter((x) => uuid.safeParse(x).success));
  if (csv(q.kinds).length) add('r.kind = ANY(?)', csv(q.kinds));
  if (csv(q.risks).length) add('r.risk = ANY(?)', csv(q.risks));
  if (csv(q.teams).length) add('r.reviewer_team = ANY(?)', csv(q.teams));
  if (q.unconfirmed === '1') where.push('r.unconfirmed_count > 0');
  if (q.idle === '1') where.push(`EXISTS (SELECT 1 FROM flags f WHERE f.role_id=r.id AND f.category='role-idle' AND f.status='open')`);
  if (q.openFlags === '1') where.push(`EXISTS (SELECT 1 FROM flags f WHERE f.role_id=r.id AND f.status='open' AND NOT EXISTS (SELECT 1 FROM review_decisions d WHERE d.flag_id=f.id))`);
  if (q.unidentified === '1') where.push(`EXISTS (SELECT 1 FROM flags f WHERE f.role_id=r.id AND f.category='unmapped-event' AND f.status='open')`);
  if (q.minUnused) add('r.unused_count >= ?', Math.max(0, Number(q.minUnused) | 0));
  if (q.hasPolicyKind === 'inline') where.push('r.inline_count > 0'); if (q.hasPolicyKind === 'managed') where.push('r.attached_count > 0');
  const sorts = { risk: 'r.risk_score', name: 'r.name', unused: 'r.unused_count', granted: 'r.granted_count', activity: 'r.last_activity_at' };
  const order = `${sorts[q.sort] || 'r.risk_score'} ${q.dir === 'asc' ? 'ASC' : 'DESC'} NULLS LAST, r.name`;
  const limit = Math.min(Number(q.limit) || 50, 100), offset = (Math.max(Number(q.page) || 1, 1) - 1) * limit;
  const rows = await query(`
    SELECT r.id, r.name, r.arn, r.kind, r.permission_set, r.risk, r.risk_score, r.reviewer_team, r.requires_both, r.granted_count, r.used_count, r.unused_count,
           r.unconfirmed_count, r.last_used_at, r.last_activity_at, r.inline_count, r.attached_count, a.name AS account_name, a.account_id AS aws_account_id, a.environment, r.account_id,
           (SELECT count(*)::int FROM flags f WHERE f.role_id=r.id AND f.status='open') AS open_flags,
           (SELECT count(*)::int FROM flags f JOIN review_decisions d ON d.flag_id=f.id WHERE f.role_id=r.id AND f.status='open') AS decided_flags,
           EXISTS (SELECT 1 FROM flags f WHERE f.role_id=r.id AND f.category='unmapped-event' AND f.status='open') AS has_unidentified,
           count(*) OVER()::int AS total
    FROM roles r JOIN cloud_accounts a ON a.id=r.account_id WHERE ${where.join(' AND ')} ORDER BY ${order} LIMIT ${limit} OFFSET ${offset}`, p);
  const fp = []; const fwhere = ['deleted_at IS NULL', scopeSql(req.user, 'account_id', fp)];
  const facets = await query(`SELECT risk, kind, reviewer_team, count(*)::int n FROM roles WHERE ${fwhere.join(' AND ')} GROUP BY ROLLUP(risk, kind, reviewer_team)`, fp);
  const accts = [...new Set(rows.rows.map((x) => x.account_id))];
  const hist = await historyFor(accts.length ? (await query('SELECT * FROM cloud_accounts WHERE id = ANY($1)', [accts])).rows : []);
  res.json({ items: rows.rows.map(({ total, ...r }) => ({ ...r, history: { progress: hist.get(r.account_id)?.progress ?? 0, complete: !!hist.get(r.account_id)?.complete } })), total: rows.rows[0]?.total ?? 0, facets: facets.rows });
}));

data.get('/roles/:id', requirePerm('view'), wrap(async (req, res) => {
  const role = await roleFor(req, req.params.id);
  const [pol, prin, flags, pass, svc, cp, daily, adv] = await Promise.all([
    query('SELECT name, kind, aws_managed, arn, document FROM role_policies WHERE role_id=$1 ORDER BY kind, name', [role.id]),
    query(`SELECT p.id, p.display, p.kind, p.via, p.caller, p.first_seen, p.last_seen, p.sessions_count, p.source_ips, p.mfa, p.source_identity, p.session_tags,
                  coalesce((SELECT json_agg(json_build_object('action', action, 'count', c)) FROM (SELECT action, sum(count)::int c FROM activity_daily WHERE principal_id=p.id GROUP BY action ORDER BY c DESC LIMIT 8) t), '[]') AS top_actions
             FROM principals p WHERE p.role_id=$1 ORDER BY p.last_seen DESC NULLS LAST`, [role.id]),
    query(`SELECT f.*, d.decision, d.note, d.resources AS decided_resources, d.decided_at, u.name AS decided_by FROM flags f
             LEFT JOIN review_decisions d ON d.flag_id=f.id LEFT JOIN users u ON u.id=d.decided_by
            WHERE f.role_id=$1 AND f.status='open' ORDER BY CASE f.severity WHEN 'high' THEN 0 WHEN 'medium' THEN 1 ELSE 2 END, f.category, f.key`, [role.id]),
    query('SELECT passed_role_arn, service, last_seen, count FROM passrole_observed WHERE role_id=$1 ORDER BY last_seen DESC', [role.id]),
    query(`SELECT split_part(action, ':', 1) AS service, count(*) FILTER (WHERE status='used')::int AS used, count(*) FILTER (WHERE status='unused')::int AS unused,
                  count(*) FILTER (WHERE status='unconfirmed')::int AS unconfirmed FROM role_actions WHERE role_id=$1 GROUP BY 1 ORDER BY 2 DESC, 1`, [role.id]),
    query('SELECT min(first_event_time) AS first, max(last_event_time) AS last FROM scan_checkpoints WHERE account_id=$1', [role.account_id]),
    query(`SELECT day, sum(count)::int AS calls, sum(error_count)::int AS denied FROM activity_daily WHERE role_id=$1 AND day > current_date - 90 GROUP BY day ORDER BY day`, [role.id]),
    query('SELECT service_namespace AS service, last_authenticated FROM advisor_services WHERE role_id=$1', [role.id]),
  ]);
  const rec = await latestRecommendation(role.id);
  const history = (await historyFor((await query('SELECT * FROM cloud_accounts WHERE id=$1', [role.account_id])).rows)).get(role.account_id);
  res.json({ role, history, policies: pol.rows, principals: prin.rows, flags: flags.rows, passRoles: pass.rows, services: svc.rows, window: cp.rows[0], daily: daily.rows, advisor: adv.rows, recommendation: rec });
}));

data.get('/roles/:id/actions', requirePerm('view'), wrap(async (req, res) => {
  const role = await roleFor(req, req.params.id);
  const p = [role.id]; const w = ['role_id=$1'];
  const q = req.query;
  if (['used', 'unused', 'unconfirmed'].includes(q.status)) { p.push(q.status); w.push(`status=$${p.length}`); }
  if (q.service) { p.push(`${String(q.service).toLowerCase()}:%`); w.push(`lower(action) LIKE $${p.length}`); }
  if (q.q) { p.push(`%${String(q.q).slice(0, 80)}%`); w.push(`action ILIKE $${p.length}`); }
  if (['Read', 'List', 'Write', 'Permissions', 'Tagging'].includes(q.level)) { p.push(q.level); w.push(`access_level=$${p.length}`); }
  const limit = Math.min(Number(q.limit) || 100, 500), offset = (Math.max(Number(q.page) || 1, 1) - 1) * limit;
  const r = await query(`SELECT action, status, reason, access_level, event_count, last_seen, count(*) OVER()::int AS total FROM role_actions WHERE ${w.join(' AND ')} ORDER BY status, action LIMIT ${limit} OFFSET ${offset}`, p);
  res.json({ items: r.rows.map(({ total, ...x }) => x), total: r.rows[0]?.total ?? 0 });
}));

// ---------- review decisions ----------
const ACTION_CATS = new Set(['data-event', 'authorization-only', 'not-logged', 'before-window', 'service-unknown', 'unmapped-event']);
data.post('/flags/:id/decision', requirePerm('decide'), wrap(async (req, res) => {
  const f = (await query('SELECT * FROM flags WHERE id=$1', [uuid.parse(req.params.id)])).rows[0];
  if (!f) throw NotFound();
  const role = await roleFor(req, f.role_id);
  const allowed = ACTION_CATS.has(f.category) ? ['keep_scoped', 'keep', 'remove'] : ['accept', 'investigate'];
  const b = z.object({ decision: z.enum(['keep_scoped', 'keep', 'remove', 'accept', 'investigate']), note: z.string().max(1000).optional(), resources: z.array(z.string().min(1).max(500)).max(50).optional() }).parse(req.body);
  if (!allowed.includes(b.decision)) return res.status(400).json({ error: 'bad_decision', message: `For this finding choose one of: ${allowed.join(', ')}.` });
  await query(
    `INSERT INTO review_decisions(flag_id, role_id, decision, resources, note, decided_by, team, decided_at) VALUES ($1,$2,$3,$4,$5,$6,$7, now())
     ON CONFLICT (flag_id) DO UPDATE SET decision=EXCLUDED.decision, resources=EXCLUDED.resources, note=EXCLUDED.note, decided_by=EXCLUDED.decided_by, team=EXCLUDED.team, decided_at=now()`,
    [f.id, role.id, b.decision, b.resources || null, b.note || null, req.user.id, req.user.team]);
  await audit(req, 'flag.decide', { type: 'flag', id: f.id }, { role: role.name, category: f.category, key: f.key, decision: b.decision });
  res.json({ ok: true });
}));
data.delete('/flags/:id/decision', requirePerm('decide'), wrap(async (req, res) => {
  const f = (await query('SELECT * FROM flags WHERE id=$1', [uuid.parse(req.params.id)])).rows[0];
  if (!f) throw NotFound();
  await roleFor(req, f.role_id);
  await query('DELETE FROM review_decisions WHERE flag_id=$1', [f.id]);
  await audit(req, 'flag.undecide', { type: 'flag', id: f.id });
  res.json({ ok: true });
}));

// ---------- recommendations ----------
data.post('/roles/:id/recommend', requirePerm('recommend'), wrap(async (req, res) => {
  const role = await roleFor(req, req.params.id);
  const b = z.object({ instruction: z.string().trim().max(600).optional(), useAi: z.boolean().optional() }).parse(req.body || {});
  const rec = await recommend(role.id, { instruction: b.instruction || null, userId: req.user.id, llm: b.useAi === false ? null : undefined });
  await audit(req, 'recommendation.create', { type: 'role', id: role.id }, { source: rec.source, role: role.name });
  res.status(201).json(await latestRecommendation(role.id));
}));
data.get('/roles/:id/recommendation', requirePerm('view'), wrap(async (req, res) => {
  const role = await roleFor(req, req.params.id);
  res.json(await latestRecommendation(role.id));
}));
data.post('/recommendations/:id/approve', requirePerm('approve'), wrap(async (req, res) => {
  const rec = (await query('SELECT role_id FROM recommendations WHERE id=$1', [uuid.parse(req.params.id)])).rows[0];
  if (!rec) throw NotFound();
  const role = await roleFor(req, rec.role_id);
  const out = await approve(req.params.id, req.user);
  await audit(req, 'recommendation.approve', { type: 'recommendation', id: req.params.id }, { role: role.name, team: req.user.team, complete: out.approved });
  if (out.approved) notifyApproved(req.params.id);
  res.json(out);
}));
data.get('/recommendations/:id/export', requirePerm('export'), wrap(async (req, res) => {
  const rec = (await query('SELECT * FROM recommendations WHERE id=$1', [uuid.parse(req.params.id)])).rows[0];
  if (!rec) throw NotFound();
  const role = await roleFor(req, rec.role_id);
  await audit(req, 'recommendation.export', { type: 'recommendation', id: rec.id }, { format: req.query.format || 'json' });
  if (req.query.format === 'terraform') return res.type('text/plain').send(toTerraform(role, rec));
  res.json({ role: role.name, approved: rec.status === 'approved', policies: rec.policies });
}));

// ---------- overview ----------
// ---------- radar, signal, sector scan ----------
const accountFilter = (req, p, col) => {
  const acct = req.query.account ? uuid.parse(req.query.account) : null;
  if (acct && !inScope(req.user, acct)) throw NotFound();
  const parts = [scopeSql(req.user, col, p)];
  if (acct) { p.push(acct); parts.push(`${col}=$${p.length}`); }
  return parts.join(' AND ');
};

/** Every role as a contact: how much it holds, how much it used, who calls it, what could not be identified. */
data.get('/radar', requirePerm('view'), wrap(async (req, res) => {
  const p = []; const where = accountFilter(req, p, 'r.account_id');
  const roles = (await query(
    `SELECT r.id, r.name, r.kind, r.risk, r.account_id, a.name AS account_name, a.account_id AS aws_account_id,
            r.granted_count, r.used_count, r.unused_count, r.unconfirmed_count, r.last_used_at,
            coalesce(d.calls,0)::int AS calls, coalesce(d.denied,0)::int AS denied
       FROM roles r JOIN cloud_accounts a ON a.id=r.account_id
       LEFT JOIN (SELECT role_id, sum(count) calls, sum(error_count) denied FROM activity_daily GROUP BY role_id) d ON d.role_id=r.id
      WHERE r.deleted_at IS NULL AND ${where} ORDER BY r.risk_score DESC, r.name LIMIT 3000`, p)).rows;
  const ids = roles.map((r) => r.id);
  const [acts, callers, accts, maps] = await Promise.all([
    ids.length ? query('SELECT DISTINCT role_id, action FROM activity_daily WHERE role_id = ANY($1)', [ids]) : { rows: [] },
    ids.length ? query(
      `SELECT p.key, max(p.display) AS display, max(p.kind) AS kind, array_agg(DISTINCT p.role_id) AS roles, sum(p.sessions_count)::int AS sessions
         FROM principals p WHERE p.role_id = ANY($1) AND p.kind <> 'session' GROUP BY p.key ORDER BY sum(p.sessions_count) DESC NULLS LAST LIMIT 24`, [ids]) : { rows: [] },
    query('SELECT * FROM cloud_accounts WHERE id = ANY($1)', [[...new Set(roles.map((r) => r.account_id))]]),
    loadMappings(),
  ]);
  const hist = await historyFor(accts.rows);
  const unk = new Map();
  for (const a of acts.rows) { const t = translate(a.action, maps); if (t.unmapped) { if (!unk.has(a.role_id)) unk.set(a.role_id, []); unk.get(a.role_id).push(a.action); } }
  res.json({
    roles: roles.map((r) => ({ ...r, unidentified: unk.get(r.id) || [], provisional: !hist.get(r.account_id)?.complete, progress: hist.get(r.account_id)?.progress ?? 0 })),
    callers: callers.rows,
    accounts: accts.rows.map((a) => ({ id: a.id, name: a.name, awsAccountId: a.account_id, environment: a.environment, progress: hist.get(a.id)?.progress ?? 0, complete: !!hist.get(a.id)?.complete }))
      .sort((a, b) => a.name.localeCompare(b.name)),
  });
}));

// ---- trust map: who can reach each role, and what is wrong with it ----
data.get('/trust', requirePerm('view'), wrap(async (req, res) => {
  res.json(await trustMap(req.user, String(req.query.q || '').slice(0, 500)));
}));
data.get('/trust.csv', requirePerm('view'), wrap(async (req, res) => {
  const m = await trustMap(req.user, String(req.query.q || '').slice(0, 500), { limit: 100000 });
  res.setHeader('Content-Type', 'text/csv; charset=utf-8');
  res.setHeader('Content-Disposition', 'attachment; filename="trust-map.csv"');
  res.send(toCsv(m.rows));
}));

// ---- radar v3 ----
data.get('/radar/estate', requirePerm('view'), wrap(async (req, res) => res.json(await estate(req.user))));
data.get('/radar/account/:id', requirePerm('view'), wrap(async (req, res) => {
  const r = await accountRadar(req.user, uuid.parse(req.params.id)); if (!r) throw NotFound(); res.json(r);
}));
data.get('/changes', requirePerm('view'), wrap(async (req, res) => {
  const accountId = req.query.account ? uuid.parse(req.query.account) : null;
  if (accountId && !inScope(req.user, accountId)) throw NotFound();
  res.json(await changeFeed(req.user, { accountId, days: req.query.days }));
}));
data.post('/changes/seen', requirePerm('view'), wrap(async (req, res) => { await markSeen(req.user); res.json({ ok: true }); }));
data.get('/blast/identities', requirePerm('view'), wrap(async (req, res) => res.json({ items: await identities(req.user, String(req.query.q || '').slice(0, 80)) })));
data.get('/blast', requirePerm('view'), wrap(async (req, res) => {
  const key = z.string().min(3).max(600).parse(req.query.key);
  res.json(await blastRadius(req.user, key));
}));

/** Calls per day over the stored history, with how far the read has got. */
data.get('/signal', requirePerm('view'), wrap(async (req, res) => {
  const p = []; const where = accountFilter(req, p, 'r.account_id');
  const days = (await query(
    `SELECT d.day, sum(d.count)::int AS calls, sum(d.error_count)::int AS denied FROM activity_daily d JOIN roles r ON r.id=d.role_id
      WHERE ${where} GROUP BY d.day ORDER BY d.day`, p)).rows;
  const ap = []; const accts = (await query(`SELECT * FROM cloud_accounts a WHERE ${accountFilter(req, ap, 'a.id')}`, ap)).rows;
  const hist = [...(await historyFor(accts)).values()];
  const lookback = Math.max(90, ...accts.map(effectiveLookback));
  res.json({ days, from: new Date(Date.now() - lookback * 864e5), to: new Date(), readUpTo: hist.filter((x) => !x.complete).map((x) => x.readUpTo).filter(Boolean).sort((a, b) => a - b)[0] || null,
    complete: hist.every((x) => x.complete) });
}));

/** One role cut by access level (rings) and service (sectors). */
data.get('/roles/:id/sector', requirePerm('view'), wrap(async (req, res) => {
  const role = await roleFor(req, req.params.id);
  const [lv, svc, used, denied] = await Promise.all([
    query(`SELECT coalesce(access_level,'Unknown') AS level, count(*)::int total, count(*) FILTER (WHERE status='used')::int used,
             count(*) FILTER (WHERE status='unconfirmed')::int unconfirmed FROM role_actions WHERE role_id=$1 GROUP BY 1`, [role.id]),
    query(`SELECT split_part(action, ':', 1) AS service, coalesce(access_level,'Unknown') AS level, count(*)::int total,
             count(*) FILTER (WHERE status='used')::int used, count(*) FILTER (WHERE status='unconfirmed')::int unconfirmed
             FROM role_actions WHERE role_id=$1 GROUP BY 1, 2`, [role.id]),
    query(`SELECT action, access_level AS level, event_count, last_seen FROM role_actions WHERE role_id=$1 AND status='used' ORDER BY event_count DESC LIMIT 50`, [role.id]),
    query(`SELECT action, sum(error_count)::int n FROM activity_daily WHERE role_id=$1 GROUP BY action HAVING sum(error_count) > 0 ORDER BY 2 DESC LIMIT 20`, [role.id]),
  ]);
  const unconfirmed = (await query(`SELECT reason, split_part(action, ':', 1) AS service, count(*)::int n FROM role_actions WHERE role_id=$1 AND status='unconfirmed' GROUP BY 1, 2 ORDER BY 3 DESC LIMIT 20`, [role.id])).rows;
  const history = (await historyFor((await query('SELECT * FROM cloud_accounts WHERE id=$1', [role.account_id])).rows)).get(role.account_id);
  res.json({ role: { id: role.id, name: role.name, account: role.account_name, kind: role.kind, risk: role.risk, granted: role.granted_count, used: role.used_count, unused: role.unused_count, unconfirmed: role.unconfirmed_count },
    levels: lv.rows, services: svc.rows, used: used.rows, denied: denied.rows, unconfirmed, history });
}));

/** What the status bar shows on every screen: history read so far, time left, unidentified calls. */
data.get('/status', requirePerm('view'), wrap(async (req, res) => {
  const ap = [];
  const accounts = (await query(`SELECT * FROM cloud_accounts a WHERE ${scopeSql(req.user, 'a.id', ap)}`, ap)).rows;
  const hist = await historyFor(accounts);
  const reading = accounts.filter((a) => !hist.get(a.id).complete);
  const ids = accounts.map((a) => a.id);
  const [eta, unk] = await Promise.all([
    ids.length ? query(`SELECT max((j.progress->>'etaSeconds')::int) AS eta FROM scan_jobs j JOIN scan_runs r ON r.id=j.run_id WHERE j.status='running' AND j.kind='events' AND r.account_id = ANY($1)`, [ids]) : { rows: [{}] },
    ids.length ? query(`SELECT count(DISTINCT u.raw_action)::int n FROM unmapped_events u LEFT JOIN event_action_map m ON m.raw_action=u.raw_action
      WHERE u.account_id = ANY($1) AND (m.status IS NULL OR m.status='suggested' OR (m.status='unresolved' AND m.reopen_at IS NOT NULL AND m.reopen_at < now() AND u.last_seen > m.decided_at))`, [ids]) : { rows: [{ n: 0 }] },
  ]);
  const progress = reading.length ? Math.floor(reading.reduce((s, a) => s + hist.get(a.id).progress, 0) / reading.length) : 100;
  const upTo = reading.map((a) => hist.get(a.id).readUpTo).filter(Boolean).sort((a, b) => a - b)[0] || null;
  res.json({ progress, complete: !reading.length, reading: reading.map((a) => ({ id: a.id, name: a.name, progress: hist.get(a.id).progress })), readUpTo: upTo,
    etaSeconds: eta.rows[0]?.eta ?? null, unidentified: unk.rows[0]?.n ?? 0, accounts: accounts.length });
}));

data.get('/overview', requirePerm('view'), wrap(async (req, res) => {
  const p = []; const sc = scopeSql(req.user, 'r.account_id', p);
  const [tot, byKind, queue, accounts] = await Promise.all([
    query(`SELECT count(*)::int roles, coalesce(sum(r.granted_count),0)::int granted, coalesce(sum(r.used_count),0)::int used, coalesce(sum(r.unused_count),0)::int unused,
                  coalesce(sum(r.unconfirmed_count),0)::int unconfirmed, count(*) FILTER (WHERE r.risk='High')::int high, count(*) FILTER (WHERE r.risk='Medium')::int medium, count(*) FILTER (WHERE r.risk='Low')::int low
             FROM roles r WHERE r.deleted_at IS NULL AND ${sc}`, p),
    query(`SELECT r.kind, count(*)::int n FROM roles r WHERE r.deleted_at IS NULL AND ${sc} GROUP BY r.kind`, p),
    query(`SELECT r.reviewer_team AS team, count(*)::int roles, count(*) FILTER (WHERE r.requires_both)::int both,
                  coalesce(sum((SELECT count(*) FROM flags f WHERE f.role_id=r.id AND f.status='open' AND NOT EXISTS (SELECT 1 FROM review_decisions d WHERE d.flag_id=f.id))),0)::int AS undecided
             FROM roles r WHERE r.deleted_at IS NULL AND ${sc} GROUP BY 1`, p),
    (() => { const ap = []; return query(`SELECT a.id, a.name, a.status, a.last_scan_at FROM cloud_accounts a WHERE ${scopeSql(req.user, 'a.id', ap)} ORDER BY a.name`, ap); })(),
  ]);
  res.json({ totals: tot.rows[0], byKind: byKind.rows, reviewQueue: queue.rows, accounts: accounts.rows });
}));
export { Refusal, loadRoleContext };
