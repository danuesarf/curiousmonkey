// Alerts: rules that post to Slack or a webhook when something worth knowing happens, at once or in a daily digest.
//
// One evaluator (alertsTick), run by the worker every minute under an advisory lock, reads what the scans already
// record: findings (flags), Radar changes, access keys, IAM user details and scan jobs. Each match is recorded once
// per rule (alert_hits); every match not sent yet goes out in one message (alert_deliveries), so a burst becomes one
// post, not fifty. A message that fails is tried once more two minutes later, then marked failed.
//
// Events (findings, changes, failed scans) count only from when the rule was created or last switched on, so a new
// rule does not post the backlog. Conditions (an old key, a password without MFA) are matched as they stand: a new
// rule posts what is true now, once; when the condition clears, the match is forgotten and can fire again.
import { z } from 'zod';
import { config, keyRules } from './config.js';
import { pool, query, tx } from './db.js';
import { encrypt, decrypt } from './auth/crypto.js';

export const TRIGGERS = {
  finding: { label: 'New finding', severity: true, more: '#/findings', hint: 'A finding the analysis raised on a role or IAM user.' },
  change: { label: 'Radar change', severity: true, more: '#/', hint: 'What Radar pings: a new caller entered a role, a role gained permissions, first denied calls, and so on.' },
  'key-age': { label: 'Access key past its rotation age', more: '#/identities?type=users&flag=oldKey', hint: 'An active access key older than the rotation age set in Configuration.' },
  'console-no-mfa': { label: 'Console password without MFA', more: '#/identities?type=users&flag=noMfa', hint: 'An IAM user who can sign in to the console with no MFA device.' },
  'scan-failed': { label: 'Scan failed', more: '#/operations/scans', hint: 'A scan job that failed for good (no retry left).' },
};
export const CHANGE_KINDS = { 'new-caller': 'New caller entered a role', grew: 'Role gained permissions', denied: 'First denied calls', 'new-role': 'Role created', unidentified: 'New event name not identified', dead: 'Role went idle (90 days)', cleaned: 'Role trimmed' };
const SEVERITIES = ['high', 'medium', 'low'];
const atLeast = (min) => SEVERITIES.slice(0, SEVERITIES.indexOf(min) + 1);
// Radar changes have their own scale: high, warn, info, good
const CHANGE_SEV = { high: ['high'], medium: ['high', 'warn'], low: ['high', 'warn', 'info', 'good'] };
const CHANGE_TO = { high: 'high', warn: 'medium', info: 'low', good: 'low' };
const MAX_ITEMS = 50;          // listed in one message; the rest are counted
const RETRY_AFTER = "interval '2 minutes'";
const LOCK = 727010;

// ---------- where messages go ----------
const BLOCKED_HOSTS = /^(localhost|.*\.localhost|metadata|metadata\.google\.internal|instance-data)$/i;
// URL() has already turned decimal, octal and IPv4-mapped forms into the canonical ones checked here
const isLoopbackOrLinkLocal = (h) => /^(127\.|0\.|169\.254\.)/.test(h) || /^\[(::1?|fe[89ab][0-9a-f]:.*|::ffff:(7f[0-9a-f]{2}|a9fe|0{1,4}):.*)\]$/i.test(h);
/**
 * Why a URL cannot be used, or null. https only (http is accepted outside production, for local testing).
 * A Slack destination must be a Slack webhook. In production, loopback, link-local (the cloud metadata service) and
 * metadata host names are refused; private addresses are allowed, so an internal automation can receive alerts.
 */
export function urlProblem(raw, kind) {
  let u;
  try { u = new URL(String(raw).trim()); } catch { return 'Paste the full URL, starting with https://.'; }
  const dev = config.env !== 'production';
  if (u.protocol !== 'https:' && !(dev && u.protocol === 'http:')) return 'Use an https:// URL.';
  if (u.username || u.password) return 'A URL with a user name or password before the host is not accepted.';
  if (kind === 'slack' && u.hostname !== 'hooks.slack.com') return 'A Slack webhook URL starts with https://hooks.slack.com/. Create one with an Incoming Webhook (or a Workflow webhook) in Slack.';
  if (!dev && (BLOCKED_HOSTS.test(u.hostname) || isLoopbackOrLinkLocal(u.hostname))) return 'This address points at the server itself or at the cloud metadata service.';
  return null;
}
/** What the page shows instead of the URL: host and the last four characters. */
const urlHint = (raw) => { const u = new URL(raw); const tail = (u.pathname + u.search).slice(-4); return `${u.host}/…${tail}`; };

const Name = z.string().trim().min(1, 'Give it a name.').max(80);
export const DestinationIn = z.object({ name: Name, kind: z.enum(['slack', 'webhook']), url: z.string().trim().max(2000) });
export const DestinationPatch = z.object({ name: Name.optional(), url: z.string().trim().max(2000).optional() });
export const RuleIn = z.object({
  name: Name,
  trigger: z.enum(Object.keys(TRIGGERS)),
  minSeverity: z.enum(SEVERITIES).default('high'),
  changeKinds: z.array(z.enum(Object.keys(CHANGE_KINDS))).max(10).default([]),
  environments: z.array(z.string().trim().min(1).max(40)).max(20).default([]),
  destinationId: z.string().uuid(),
  mode: z.enum(['instant', 'daily']).default('instant'),
  enabled: z.boolean().default(true),
});
export const RulePatch = RuleIn.omit({ trigger: true }).partial();

export class AlertError extends Error { constructor(status, message, field) { super(message); this.status = status; this.field = field; } }

const destView = (d) => ({ id: d.id, name: d.name, kind: d.kind, urlHint: d.url_hint, createdAt: d.created_at, updatedAt: d.updated_at, rules: d.rules ?? 0 });
const ruleView = (r) => ({ id: r.id, name: r.name, trigger: r.trigger, minSeverity: r.min_severity, changeKinds: r.change_kinds, environments: r.environments,
  destinationId: r.destination_id, destinationName: r.destination_name, mode: r.mode, enabled: r.enabled, since: r.since, lastDigestDay: r.last_digest_day,
  createdAt: r.created_at, updatedAt: r.updated_at, waiting: r.waiting ?? 0, lastSentAt: r.last_sent_at ?? null });

/** Everything the Alerts page shows. URLs are never returned. */
export async function alertsView() {
  const [d, r, del] = await Promise.all([
    query(`SELECT d.*, (SELECT count(*)::int FROM alert_rules r WHERE r.destination_id = d.id) AS rules FROM alert_destinations d ORDER BY d.name`),
    query(`SELECT r.*, d.name AS destination_name,
                  (SELECT count(*)::int FROM alert_hits h WHERE h.rule_id = r.id AND h.delivery_id IS NULL) AS waiting,
                  (SELECT max(x.sent_at) FROM alert_deliveries x WHERE x.rule_id = r.id AND x.status = 'sent') AS last_sent_at
             FROM alert_rules r JOIN alert_destinations d ON d.id = r.destination_id ORDER BY r.created_at`),
    query(`SELECT id, rule_id, rule_name, destination_name, kind, status, attempts, items, http_status, error, created_at, sent_at,
                  payload->'items'->0->>'title' AS first_title FROM alert_deliveries ORDER BY created_at DESC LIMIT 50`),
  ]);
  return {
    destinations: d.rows.map(destView), rules: r.rows.map(ruleView),
    deliveries: del.rows.map((x) => ({ id: x.id, ruleId: x.rule_id, ruleName: x.rule_name, destinationName: x.destination_name, kind: x.kind, status: x.status,
      attempts: x.attempts, items: x.items, httpStatus: x.http_status, error: x.error, createdAt: x.created_at, sentAt: x.sent_at, firstTitle: x.first_title })),
    triggers: TRIGGERS, changeKinds: CHANGE_KINDS, digestAt: config.alerts.digestAt, tz: config.schedule.tz, keyRules: keyRules(),
  };
}

export async function createDestination(body, userId) {
  const b = DestinationIn.parse(body);
  const bad = urlProblem(b.url, b.kind);
  if (bad) throw new AlertError(400, bad, 'url');
  return destView((await query(`INSERT INTO alert_destinations(name, kind, url_enc, url_hint, created_by) VALUES ($1,$2,$3,$4,$5) RETURNING *`,
    [b.name, b.kind, encrypt(b.url), urlHint(b.url), userId])).rows[0]);
}
export async function updateDestination(id, body) {
  const b = DestinationPatch.parse(body);
  const d = (await query('SELECT * FROM alert_destinations WHERE id=$1', [id])).rows[0];
  if (!d) throw new AlertError(404, 'That destination no longer exists.');
  if (b.url) { const bad = urlProblem(b.url, d.kind); if (bad) throw new AlertError(400, bad, 'url'); }
  return destView((await query(`UPDATE alert_destinations SET name=coalesce($2, name), url_enc=coalesce($3, url_enc), url_hint=coalesce($4, url_hint), updated_at=now() WHERE id=$1 RETURNING *`,
    [id, b.name ?? null, b.url ? encrypt(b.url) : null, b.url ? urlHint(b.url) : null])).rows[0]);
}
export async function deleteDestination(id) {
  const used = (await query('SELECT count(*)::int n FROM alert_rules WHERE destination_id=$1', [id])).rows[0].n;
  if (used) throw new AlertError(409, `${used} rule${used === 1 ? ' sends' : 's send'} here. Point ${used === 1 ? 'it' : 'them'} elsewhere or remove ${used === 1 ? 'it' : 'them'} first.`);
  const d = (await query('DELETE FROM alert_destinations WHERE id=$1 RETURNING name', [id])).rows[0];
  if (!d) throw new AlertError(404, 'That destination no longer exists.');
  return d;
}

const startMark = async (c) => (await c.query('SELECT coalesce(max(id), 0)::bigint AS n FROM changes')).rows[0].n;
async function checkDestination(c, id) {
  if (!(await c.query('SELECT 1 FROM alert_destinations WHERE id=$1', [id])).rowCount) throw new AlertError(400, 'Pick a destination.', 'destinationId');
}
export async function createRule(body, userId) {
  const b = RuleIn.parse(body);
  return tx(async (c) => {
    await checkDestination(c, b.destinationId);
    const r = (await c.query(`INSERT INTO alert_rules(name, trigger, min_severity, change_kinds, environments, destination_id, mode, enabled, since_change_id, created_by)
                               VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING *`,
      [b.name, b.trigger, b.minSeverity, b.changeKinds, b.environments, b.destinationId, b.mode, b.enabled, await startMark(c), userId])).rows[0];
    return ruleView(r);
  });
}
export async function updateRule(id, body) {
  const b = RulePatch.parse(body);
  return tx(async (c) => {
    const prev = (await c.query('SELECT * FROM alert_rules WHERE id=$1 FOR UPDATE', [id])).rows[0];
    if (!prev) throw new AlertError(404, 'That rule no longer exists.');
    if (b.destinationId) await checkDestination(c, b.destinationId);
    // switched back on: start from now, as a new rule would; what happened while it was off is not posted
    const restart = b.enabled === true && !prev.enabled;
    const r = (await c.query(`UPDATE alert_rules SET name=coalesce($2,name), min_severity=coalesce($3,min_severity), change_kinds=coalesce($4,change_kinds),
        environments=coalesce($5,environments), destination_id=coalesce($6,destination_id), mode=coalesce($7,mode), enabled=coalesce($8,enabled),
        since=CASE WHEN $9 THEN now() ELSE since END, since_change_id=CASE WHEN $9 THEN $10 ELSE since_change_id END, updated_at=now()
      WHERE id=$1 RETURNING *`,
      [id, b.name ?? null, b.minSeverity ?? null, b.changeKinds ?? null, b.environments ?? null, b.destinationId ?? null, b.mode ?? null, b.enabled ?? null, restart, restart ? await startMark(c) : 0])).rows[0];
    if (restart) await c.query('DELETE FROM alert_hits WHERE rule_id=$1 AND delivery_id IS NULL', [id]);
    return ruleView(r);
  });
}
export async function deleteRule(id) {
  const r = (await query('DELETE FROM alert_rules WHERE id=$1 RETURNING name', [id])).rows[0];
  if (!r) throw new AlertError(404, 'That rule no longer exists.');
  return r;
}

// ---------- what each trigger matches ----------
const link = (hash) => `${config.publicUrl}/${hash}`;
const envSql = (n) => `(cardinality($${n}::text[]) = 0 OR a.environment = ANY($${n}::text[]))`;
const days = (d) => Math.floor((Date.now() - new Date(d).getTime()) / 864e5);

/** Matches for one rule: [{ dedupe, item }]. `state` triggers return everything true now; the others only what is new. */
const SOURCES = {
  async finding(r) {
    const rows = (await query(`SELECT f.id, f.title, f.severity, f.created_at, r.id AS role_id, r.name AS role_name, r.kind AS role_kind, a.name AS account_name, a.environment
        FROM flags f JOIN roles r ON r.id = f.role_id JOIN cloud_accounts a ON a.id = r.account_id
       WHERE f.status = 'open' AND r.deleted_at IS NULL AND f.created_at >= $1 AND f.severity = ANY($2) AND ${envSql(3)}
         AND NOT EXISTS (SELECT 1 FROM alert_hits h WHERE h.rule_id = $4 AND h.dedupe = 'flag:' || f.id)
       ORDER BY f.created_at LIMIT 2000`, [r.since, atLeast(r.min_severity), r.environments, r.id])).rows;
    return rows.map((x) => ({ dedupe: `flag:${x.id}`, item: { title: x.title, subject: x.role_name, subjectKind: x.role_kind === 'iam-user' ? 'IAM user' : 'role',
      account: x.account_name, environment: x.environment, severity: x.severity, url: link(`#/identities/${x.role_id}?tab=findings`), at: x.created_at } }));
  },
  async change(r) {
    const top = await startMark({ query });
    const rows = (await query(`SELECT c.id, c.kind, c.severity, c.title, c.detail, c.at, c.role_id, a.id AS account_id, a.name AS account_name, a.environment
        FROM changes c JOIN cloud_accounts a ON a.id = c.account_id
       WHERE c.id > $1 AND c.id <= $2 AND c.severity = ANY($3) AND (cardinality($4::text[]) = 0 OR c.kind = ANY($4::text[])) AND ${envSql(5)}
       ORDER BY c.id`, [r.since_change_id, top, CHANGE_SEV[r.min_severity], r.change_kinds, r.environments])).rows;
    // move the mark even past changes this rule does not want, so they are not read again
    await query('UPDATE alert_rules SET since_change_id = $2 WHERE id = $1 AND since_change_id < $2', [r.id, top]);
    return rows.map((x) => ({ dedupe: `change:${x.id}`, item: { title: x.title, subject: x.detail || '', account: x.account_name, environment: x.environment,
      severity: CHANGE_TO[x.severity] || 'low', kind: x.kind, url: link(x.role_id ? `#/identities/${x.role_id}` : `#/?accounts=${x.account_id}`), at: x.at } }));
  },
  async 'key-age'(r) {
    const rows = (await query(`SELECT k.key_id, k.created_at, r.id AS role_id, r.name AS user_name, a.name AS account_name, a.environment
        FROM iam_access_keys k JOIN roles r ON r.id = k.role_id JOIN cloud_accounts a ON a.id = r.account_id
       WHERE k.status = 'Active' AND k.deleted_at IS NULL AND r.deleted_at IS NULL AND k.created_at < now() - make_interval(days => $1) AND ${envSql(2)}
       ORDER BY k.created_at`, [keyRules().rotateDays, r.environments])).rows;
    return rows.map((x) => ({ dedupe: `key-age:${x.key_id}`, item: { title: `Access key ${x.key_id} is ${days(x.created_at)} days old`, subject: x.user_name, subjectKind: 'IAM user',
      account: x.account_name, environment: x.environment, severity: 'medium', url: link(`#/identities/${x.role_id}?tab=credentials`), at: x.created_at } }));
  },
  async 'console-no-mfa'(r) {
    const rows = (await query(`SELECT r.id AS role_id, r.name AS user_name, d.password_last_used, a.name AS account_name, a.environment
        FROM iam_user_details d JOIN roles r ON r.id = d.role_id JOIN cloud_accounts a ON a.id = r.account_id
       WHERE d.password_enabled AND jsonb_array_length(d.mfa) = 0 AND r.deleted_at IS NULL AND ${envSql(1)}
       ORDER BY r.name`, [r.environments])).rows;
    return rows.map((x) => ({ dedupe: `nomfa:${x.role_id}`, item: { title: 'Console password without MFA', subject: x.user_name, subjectKind: 'IAM user',
      account: x.account_name, environment: x.environment, severity: 'high', url: link(`#/identities/${x.role_id}?tab=credentials`),
      at: x.password_last_used, detail: x.password_last_used ? `last signed in ${days(x.password_last_used)} days ago` : 'never signed in' } }));
  },
  async 'scan-failed'(r) {
    const rows = (await query(`SELECT j.id, j.kind, j.region, j.last_error, coalesce(j.finished_at, j.heartbeat_at, j.created_at) AS at, a.name AS account_name, a.environment
        FROM scan_jobs j JOIN cloud_accounts a ON a.id = j.account_id
       WHERE j.status IN ('failed', 'dead') AND coalesce(j.finished_at, j.heartbeat_at, j.created_at) >= $1 AND ${envSql(2)}
         AND NOT EXISTS (SELECT 1 FROM alert_hits h WHERE h.rule_id = $3 AND h.dedupe = 'job:' || j.id)
       ORDER BY 5 LIMIT 500`, [r.since, r.environments, r.id])).rows;
    return rows.map((x) => ({ dedupe: `job:${x.id}`, item: { title: `${x.kind}${x.region && x.region !== '*' ? ` ${x.region}` : ''} job failed`, subject: (x.last_error || 'no error recorded').split('\n')[0].slice(0, 200),
      account: x.account_name, environment: x.environment, severity: 'high', url: link('#/operations/scans'), at: x.at } }));
  },
};
const STATE = new Set(['key-age', 'console-no-mfa']);

/** Records new matches for one rule. A condition that no longer holds is forgotten, so it can fire again later. Returns how many are new. */
export async function collect(rule) {
  const found = await SOURCES[rule.trigger](rule);
  if (STATE.has(rule.trigger)) {
    await query('DELETE FROM alert_hits WHERE rule_id = $1 AND NOT (dedupe = ANY($2::text[]))', [rule.id, found.map((f) => f.dedupe)]);
  }
  if (!found.length) return 0;
  const r = await query(`INSERT INTO alert_hits(rule_id, dedupe, item) SELECT $1, d, i FROM unnest($2::text[], $3::jsonb[]) AS t(d, i) ON CONFLICT DO NOTHING`,
    [rule.id, found.map((f) => f.dedupe), found.map((f) => JSON.stringify(f.item))]);
  return r.rowCount;
}

// ---------- messages ----------
/** Puts every match not sent yet into one message. Returns the delivery id, or null when there is nothing to send. */
export async function flush(rule, kind = rule.mode) {
  return tx(async (c) => {
    const hits = (await c.query(`SELECT dedupe, item FROM alert_hits WHERE rule_id = $1 AND delivery_id IS NULL ORDER BY found_at, dedupe FOR UPDATE SKIP LOCKED`, [rule.id])).rows;
    if (!hits.length) return null;
    const dest = (await c.query('SELECT name FROM alert_destinations WHERE id = $1', [rule.destination_id])).rows[0];
    const t = TRIGGERS[rule.trigger];
    const payload = { rule: { id: rule.id, name: rule.name, trigger: rule.trigger, label: t.label }, kind, count: hits.length,
      items: hits.slice(0, MAX_ITEMS).map((h) => h.item), more: link(t.more) };
    const id = (await c.query(`INSERT INTO alert_deliveries(rule_id, destination_id, rule_name, destination_name, kind, items, payload) VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING id`,
      [rule.id, rule.destination_id, rule.name, dest?.name, kind, hits.length, JSON.stringify(payload)])).rows[0].id;
    await c.query('UPDATE alert_hits SET delivery_id = $3 WHERE rule_id = $1 AND dedupe = ANY($2::text[])', [rule.id, hits.map((h) => h.dedupe), id]);
    return id;
  });
}

const slackEsc = (s) => String(s ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
const slackLink = (url, text) => `<${url}|${slackEsc(text).replace(/\|/g, '/')}>`;
const head = (p) => (p.kind === 'test' ? 'Test message from Curious Monkey'
  : `${p.kind === 'daily' ? 'Daily digest · ' : ''}${p.rule.name} · ${p.count} new`);

/** The body for Slack: one line per match, the most important first, and a link to the rest. */
export function slackBody(p) {
  const lines = p.items.map((i) => `• *${slackEsc(String(i.severity || '').toUpperCase())}* ${slackLink(i.url, i.title)} · ${slackEsc(i.subject)}${i.detail ? ` (${slackEsc(i.detail)})` : ''} · _${slackEsc(i.account)}${i.environment ? `, ${slackEsc(i.environment)}` : ''}_`);
  const more = p.count > p.items.length ? `\n…and ${p.count - p.items.length} more. ${slackLink(p.more, 'See them all')}` : p.more ? `\n${slackLink(p.more, 'Open Curious Monkey')}` : '';
  const text = p.kind === 'test' ? `*${head(p)}*\nThis destination works. Alerts will arrive here.` : `*${slackEsc(head(p))}*\n${lines.join('\n')}${more}`;
  return { text, unfurl_links: false, unfurl_media: false };
}
/** The body for a plain webhook: the same facts as JSON. */
export const webhookBody = (p) => ({ source: 'curious-monkey', kind: p.kind, title: head(p), rule: p.rule || null, count: p.count, items: p.items, more: p.more || null, sentAt: new Date().toISOString() });

/** POSTs one message. No redirects are followed, the response body is never read back, and it gives up after 10 seconds. */
export async function post(dest, payload) {
  const url = decrypt(dest.url_enc);
  const bad = urlProblem(url, dest.kind);
  if (bad) return { ok: false, error: bad };
  try {
    const res = await fetch(url, { method: 'POST', redirect: 'manual', signal: AbortSignal.timeout(config.alerts.timeoutMs),
      headers: { 'content-type': 'application/json', 'user-agent': 'curious-monkey-alerts' }, body: JSON.stringify(dest.kind === 'slack' ? slackBody(payload) : webhookBody(payload)) });
    await res.body?.cancel().catch(() => {});
    if (res.status >= 200 && res.status < 300) return { ok: true, status: res.status };
    return { ok: false, status: res.status, error: res.status >= 300 && res.status < 400 ? `Answered with a redirect (${res.status}); redirects are not followed.` : `Answered ${res.status}.` };
  } catch (e) {
    const why = e.name === 'TimeoutError' ? `No answer within ${config.alerts.timeoutMs / 1000} seconds.` : (e.cause?.code || e.message || 'Could not connect.');
    return { ok: false, error: String(why).slice(0, 300) };
  }
}

/**
 * Sends one delivery if it is due, claiming it first so two processes never send it twice. The first failure leaves it
 * pending for one retry two minutes later; the second (or any failure of a test) marks it failed.
 */
export async function deliver(id) {
  const d = (await query(`UPDATE alert_deliveries SET attempts = attempts + 1, next_attempt_at = now() + ${RETRY_AFTER}
     WHERE id = $1 AND status = 'pending' AND next_attempt_at <= now() RETURNING *`, [id])).rows[0];
  if (!d) return null;
  const dest = d.destination_id && (await query('SELECT * FROM alert_destinations WHERE id = $1', [d.destination_id])).rows[0];
  const r = dest ? await post(dest, d.payload) : { ok: false, error: 'The destination was removed.' };
  const final = r.ok || !dest || d.attempts >= 2 || d.kind === 'test';
  await query(`UPDATE alert_deliveries SET status = $2, http_status = $3, error = $4, sent_at = CASE WHEN $2 = 'sent' THEN now() ELSE sent_at END WHERE id = $1`,
    [id, r.ok ? 'sent' : final ? 'failed' : 'pending', r.status ?? null, r.ok ? null : r.error]);
  return { ...r, final };
}

/** Posts a test message to a destination now and says how it went. Recorded in the delivery log. */
export async function testDestination(id) {
  const d = (await query('SELECT * FROM alert_destinations WHERE id = $1', [id])).rows[0];
  if (!d) throw new AlertError(404, 'That destination no longer exists.');
  const payload = { kind: 'test', count: 0, items: [], more: link('#/admin/alerts') };
  const del = (await query(`INSERT INTO alert_deliveries(destination_id, destination_name, rule_name, kind, items, payload) VALUES ($1,$2,'Test message','test',0,$3) RETURNING id`,
    [d.id, d.name, JSON.stringify(payload)])).rows[0].id;
  return deliver(del);
}

// ---------- the evaluator ----------
function localParts(tz, d) {
  const f = new Intl.DateTimeFormat('en-GB', { timeZone: tz, hour12: false, year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit' });
  const p = Object.fromEntries(f.formatToParts(d).map((x) => [x.type, x.value]));
  return { day: `${p.year}-${p.month}-${p.day}`, hm: `${p.hour}:${p.minute}` };
}

/**
 * One pass: record new matches for every rule that is on, send instant rules' matches, send each daily digest once a
 * day after the digest time, and retry messages that failed once. Only one process runs it at a time.
 * Returns { matched, sent, failed } or null when another process holds the lock.
 */
export async function alertsTick(now = new Date(), { log = () => {} } = {}) {
  const client = await pool.connect();
  try {
    if (!(await client.query('SELECT pg_try_advisory_lock($1) AS ok', [LOCK])).rows[0].ok) return null;
    try {
      const out = { matched: 0, sent: 0, failed: 0 };
      const count = (r) => { if (!r) return; if (r.ok) out.sent++; else if (r.final) out.failed++; };
      // first, messages already due: a retry, or one a crash left unsent
      for (const { id } of (await query(`SELECT id FROM alert_deliveries WHERE status = 'pending' AND next_attempt_at <= now() ORDER BY created_at LIMIT 50`)).rows) count(await deliver(id));
      const { day, hm } = localParts(config.schedule.tz, now);
      for (const rule of (await query('SELECT * FROM alert_rules WHERE enabled ORDER BY created_at')).rows) {
        try {
          out.matched += await collect(rule);
          if (rule.mode === 'instant') count(await deliverIfAny(await flush(rule)));
          else if (hm >= config.alerts.digestAt && (!rule.last_digest_day || localDay(rule.last_digest_day) < day)) {
            count(await deliverIfAny(await flush(rule, 'daily')));
            await query('UPDATE alert_rules SET last_digest_day = $2 WHERE id = $1', [rule.id, day]);
          }
        } catch (e) { log('error', 'alert rule failed', { rule: rule.name, error: e.message }); }
      }
      return out;
    } finally { await client.query('SELECT pg_advisory_unlock($1)', [LOCK]); }
  } finally { client.release(); }
}
const deliverIfAny = (id) => (id ? deliver(id) : null);
const localDay = (d) => (d instanceof Date ? `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}` : String(d).slice(0, 10));
