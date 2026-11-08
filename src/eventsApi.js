// Event history: search the calls the app keeps — every call made by a role session in a connected account
// (assumed roles, Identity Center, OIDC, role chaining), for SESSION_RETENTION_DAYS. IAM users' long-term keys and
// root are counted per day for analysis but not kept call by call, and raw CloudTrail records are never stored.
//
// track_calls has no index on time alone (it would slow every trail read), so a search walks back from the newest
// end in growing slices: sessions overlapping the slice come from the per-account session index, and each
// session's calls from its own (session_id, at) key. It stops as soon as a page is full.
import { query } from './db.js';
import { scopeSql } from './auth/rbac.js';
import { config } from './config.js';

const H = 36e5;
const SLICES = [1, 6, 24, 72, 168, 336, 720, 2160].map((h) => h * H);   // cumulative look-back per step
const RANGES = { '1h': 1, '24h': 24, '7d': 168, '30d': 720 };

// what each search key looks at. Plain words look at all of them.
const FIELDS = {
  action: ['c.action', "c.event_source || ':' || c.event_name"],
  event: ['c.event_name'],
  role: ['r.name'],
  account: ['a.name', 'a.account_id'],
  user: ['s.session_name', 's.caller_arn', 's.source_identity'],
  ip: ['s.source_ip'],
  resource: ["array_to_string(c.resources, ' ')"],
  error: ['c.error_code'],
  id: ['c.event_id'],
  key: ['s.access_key_id'],
  agent: ['s.user_agent'],
};
const ANY = [...new Set(['action', 'event', 'role', 'user', 'ip', 'resource', 'error', 'id'].flatMap((k) => FIELDS[k]))];

/** "role:deploy -action:Describe 10.0.1" → [{ field, value, neg }] */
export function parseSearch(q) {
  const out = [];
  for (const m of String(q || '').matchAll(/(-)?(?:(\w+):)?(?:"([^"]*)"|(\S+))/g)) {
    const neg = !!m[1], key = m[2]?.toLowerCase(), value = (m[3] ?? m[4] ?? '').trim();
    if (!value) continue;
    if (key && !FIELDS[key]) out.push({ field: null, value: `${key}:${value}`, neg });   // not a key: search it as text
    else out.push({ field: key || null, value, neg });
  }
  return out.slice(0, 12);
}
const like = (v) => `%${v.replace(/[\\%_]/g, (c) => `\\${c}`)}%`;

function filters(user, opts, p) {
  const sess = [scopeSql(user, 's.account_id', p)], call = [];
  if (opts.account) { p.push(opts.account); sess.push(`s.account_id = $${p.length}`); }
  else sess.push('s.account_id IN (SELECT id FROM cloud_accounts)');   // lets the planner walk the per-account session index
  if (opts.role) { p.push(opts.role); sess.push(`s.role_id = $${p.length}`); }
  if (opts.session) { p.push(opts.session); sess.push(`s.id = $${p.length}`); }
  if (opts.outcome === 'denied') call.push('c.denied'); else if (opts.outcome === 'allowed') call.push('NOT c.denied');
  for (const t of parseSearch(opts.q)) {
    p.push(like(t.value));
    const cols = t.field ? FIELDS[t.field] : ANY, test = cols.map((c) => `COALESCE(${c}, '') ILIKE $${p.length}`).join(' OR ');
    call.push(t.neg ? `NOT (${test})` : `(${test})`);
  }
  return { sess, call };
}

export function rangeOf(opts, now = Date.now()) {
  const keep = config.scanner.sessionRetentionDays * 24 * H;
  let to = opts.to ? new Date(opts.to).getTime() : now, from = opts.from ? new Date(opts.from).getTime() : now - (RANGES[opts.range] ?? 24) * H;
  if (!Number.isFinite(to) || to > now) to = now;
  if (!Number.isFinite(from)) from = now - 24 * H;
  from = Math.max(from, now - keep);
  return { from, to };
}

/** One page of calls, newest first. `before` is the cursor the previous page returned. */
export async function searchEvents(user, opts = {}) {
  const limit = Math.max(1, Math.min(opts.limit || 100, 5000));
  const { from, to } = rangeOf(opts);
  let end = to, cursor = null;
  if (opts.before) { const [t, id] = String(opts.before).split('|'); const at = Number(t); if (Number.isFinite(at)) { end = Math.min(to, at + 1); cursor = { at: new Date(at).toISOString(), id: id || '' }; } }
  const items = [];
  let scannedTo = end;
  for (let i = 0; i < SLICES.length && items.length < limit && scannedTo > from; i++) {
    const hi = scannedTo, lo = Math.max(from, end - SLICES[i]);
    if (lo >= hi) continue;
    const p = [];
    const { sess, call } = filters(user, opts, p);
    p.push(new Date(lo).toISOString()); const pLo = p.length;
    p.push(new Date(hi).toISOString()); const pHi = p.length;
    p.push(limit - items.length); const pLim = p.length;
    if (cursor) { p.push(cursor.at, cursor.id); call.push(`(c.at, c.event_id) < ($${p.length - 1}::timestamptz, $${p.length})`); }
    const rows = (await query(
      `SELECT c.event_id, c.at, c.action, c.event_source, c.event_name, c.resources, c.denied, c.error_code, c.child_key_id,
              s.id AS session_id, s.access_key_id, s.session_name, s.caller_arn, s.caller_type, s.via, s.source_ip, s.user_agent, s.mfa, s.source_identity,
              r.id AS role_id, r.name AS role_name, a.id AS account_id, a.name AS account_name, a.account_id AS aws_account_id
         FROM track_sessions s JOIN roles r ON r.id = s.role_id JOIN cloud_accounts a ON a.id = s.account_id
         JOIN LATERAL (SELECT * FROM track_calls c WHERE c.session_id = s.id AND c.at >= $${pLo} AND c.at < $${pHi}
                         ${call.length ? `AND ${call.join(' AND ')}` : ''} ORDER BY c.at DESC, c.event_id DESC LIMIT $${pLim}) c ON true
        WHERE ${sess.join(' AND ')} AND s.started_at < $${pHi} AND COALESCE(s.last_call_at, s.started_at) >= $${pLo}
        ORDER BY c.at DESC, c.event_id DESC LIMIT $${pLim}`, p)).rows;
    items.push(...rows);
    scannedTo = lo;
  }
  const last = items[items.length - 1];
  const more = items.length >= limit || scannedTo > from;
  return {
    items: items.map((x) => ({ ...x, at: new Date(x.at).toISOString() })),
    next: more && last ? `${new Date(last.at).getTime()}|${last.event_id}` : more ? `${scannedTo}|` : null,
    searched: { from: new Date(scannedTo).toISOString(), to: new Date(end).toISOString() },
    range: { from: new Date(from).toISOString(), to: new Date(to).toISOString() },
    retentionDays: config.scanner.sessionRetentionDays,
  };
}

const csvCell = (v) => { const s = v == null ? '' : Array.isArray(v) ? v.join(' ') : String(v); return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s; };
export function eventsCsv(items) {
  const cols = ['at', 'aws_account_id', 'account_name', 'role_name', 'session_name', 'caller_arn', 'source_ip', 'event_source', 'event_name', 'action', 'resources', 'denied', 'error_code', 'event_id', 'access_key_id', 'user_agent'];
  return [cols.join(','), ...items.map((x) => cols.map((c) => csvCell(x[c])).join(','))].join('\n') + '\n';
}
