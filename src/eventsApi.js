// Event history: search the calls the app keeps — every call made by a role session in a connected account
// (assumed roles, Identity Center, OIDC, role chaining), for SESSION_RETENTION_DAYS. IAM users' long-term keys and
// root are counted per day for analysis but not kept call by call, and raw CloudTrail records are never stored.
//
// track_calls has no index on time alone (it would slow every trail read). A search is planned from two small
// tables written as calls arrive (migration 023):
//   call_hourly    says how many calls match the search in each hour, and for which roles, before any call is read.
//                  The search reads just far enough back to fill the page, and skips hours with no match entirely.
//   session_hours  says which sessions made a call in those hours; only their calls are read, by (session_id, at).
// Hours not in the rollups yet (calls stored before them, still being counted in the background) are searched the
// older way: sessions overlapping a growing slice, from the per-account session index.
//
// A session's calls all fall within the life of its temporary credentials, which STS caps at 36 hours (12 for
// AssumeRole), and started_at is never later than its first call. So the sessions that can have calls in a slice
// started at most 36 hours before it.
import { read } from './db.js';
import { coveredFrom } from './rollups.js';
import { scopeSql } from './auth/rbac.js';
import { config } from './config.js';

const H = 36e5;
const SLICES = [1, 6, 24, 72, 168, 336, 720, 2160].map((h) => h * H);   // cumulative look-back per step
const RANGES = { '1h': 1, '24h': 24, '7d': 168, '30d': 720 };
export const MAX_SESSION_MS = 36 * H;    // the longest STS temporary credentials live

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
// the same test against call_hourly, for the keys it can answer
const KINDS = { action: ['k.action', "k.event_source || ':' || k.event_name"], event: ['k.event_name'], error: ['k.error_code'] };
const MAX_KINDS = 20000;
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

// How long one search may run before it returns what it has, and the longest any one statement may take.
const BUDGET_MS = Number(process.env.EVENTS_BUDGET_MS || 12_000), STATEMENT_MS = Number(process.env.EVENTS_STATEMENT_MS || 20_000);

/**
 * What the rollups can say about this search. The words that test a call's action, event name or error are looked up
 * in call_kinds (a few thousand rows): `kinds` is the matching keys, or null when no such word was given.
 * `exact`: every test on a call is answered by the rollups, so their counts are the number of matching calls.
 * `where(P)` gives the tests on call_hourly (alias h).
 */
async function rollupPlan(opts) {
  let exact = !opts.session, kinds = null;
  const p = [], tests = [];
  for (const t of parseSearch(opts.q)) {
    const cols = t.field && KINDS[t.field];
    if (!cols) { exact = false; continue; }
    p.push(like(t.value));
    const test = cols.map((c) => `${c} ILIKE $${p.length}`).join(' OR ');
    tests.push(t.neg ? `NOT (${test})` : `(${test})`);
  }
  if (tests.length) {
    kinds = (await read(`SELECT k.k FROM call_kinds k WHERE ${tests.join(' AND ')} LIMIT ${MAX_KINDS + 1}`, p)).rows.map((x) => x.k);
    if (kinds.length > MAX_KINDS) { kinds = null; exact = false; }      // matches nearly everything: no use as a filter
  }
  const where = (P) => [
    ...(opts.role ? [`h.role_id = ${P(opts.role)}`] : []),
    ...(opts.outcome === 'denied' ? ['h.denied'] : opts.outcome === 'allowed' ? ['NOT h.denied'] : []),
    ...(kinds ? [`h.k = ANY(${P(kinds)}::uuid[])`] : []),
  ];
  return { kinds, exact, where };
}

function filters(user, opts, p) {
  const sess = [scopeSql(user, 's.account_id', p)], call = [];
  if (opts.account) { p.push(opts.account); sess.push(`s.account_id = $${p.length}`); }
  else sess.push('s.account_id IN (SELECT id FROM cloud_accounts)');   // lets the planner walk the per-account session index
  if (opts.role) { p.push(opts.role); sess.push(`s.role_id = $${p.length}`); }
  if (opts.session) { p.push(opts.session); sess.push(`s.id = $${p.length}`); }
  call.push(...callTests(opts, p));
  return { sess, call };
}

/** The search terms and outcome as tests on a call (c) and its session, role and account (s, r, a). */
function callTests(opts, p) {
  const call = [];
  if (opts.outcome === 'denied') call.push('c.denied'); else if (opts.outcome === 'allowed') call.push('NOT c.denied');
  for (const t of parseSearch(opts.q)) {
    p.push(like(t.value));
    const cols = t.field ? FIELDS[t.field] : ANY, test = cols.map((c) => `COALESCE(${c}, '') ILIKE $${p.length}`).join(' OR ');
    call.push(t.neg ? `NOT (${test})` : `(${test})`);
  }
  return call;
}

export function rangeOf(opts, now = Date.now()) {
  const keep = config.scanner.sessionRetentionDays * 24 * H;
  let to = opts.to ? new Date(opts.to).getTime() : now, from = opts.from ? new Date(opts.from).getTime() : now - (RANGES[opts.range] ?? 24) * H;
  if (!Number.isFinite(to) || to > now) to = now;
  if (!Number.isFinite(from)) from = now - 24 * H;
  from = Math.max(from, now - keep);
  return { from, to };
}

const COLS = `c.event_id, c.at, c.action, c.event_source, c.event_name, c.resources, c.denied, c.error_code, c.child_key_id,
              s.id AS session_id, s.access_key_id, s.session_name, s.caller_arn, s.caller_type, s.via, s.source_ip, s.user_agent, s.mfa, s.source_identity,
              r.id AS role_id, r.name AS role_name, a.id AS account_id, a.name AS account_name, a.account_id AS aws_account_id`;

/** One page of calls, newest first. `before` is the cursor the previous page returned. */
export async function searchEvents(user, opts = {}) {
  const limit = Math.max(1, Math.min(opts.limit || 100, 5000));
  const { from, to } = rangeOf(opts);
  let end = to, cursor = null;
  if (opts.before) { const [t, id] = String(opts.before).split('|'); const at = Number(t); if (Number.isFinite(at)) { end = Math.min(to, at + 1); cursor = { at: new Date(at).toISOString(), id: id || '' }; } }
  const items = [];
  const st = { scannedTo: end, deadline: Date.now() + BUDGET_MS, partial: false };
  const run = async (sql, p) => {
    try { return (await read(sql, p, { timeoutMs: STATEMENT_MS })).rows; }
    catch (e) { if (e.code !== '57014') throw e; st.partial = true; return null; }   // took too long: return what there is
  };

  // the accounts this search covers, and from when the rollups can answer for them
  const ap = [];
  const accounts = (await read(`SELECT s.id FROM cloud_accounts s WHERE ${scopeSql(user, 's.id', ap)}${opts.account ? ` AND s.id = $${ap.push(opts.account)}` : ''}`, ap)).rows.map((x) => x.id);
  const fastFrom = opts.session ? Infinity : Math.max(from, await coveredFrom(accounts));
  if (accounts.length && fastFrom < end) await viaRollups(user, opts, { accounts, from: fastFrom, end, cursor, limit, items, st, run });
  if (accounts.length && !st.partial && items.length < limit && st.scannedTo > from) await viaSessions(user, opts, { from, end: st.scannedTo, cursor, limit, items, st, run });

  const last = items[items.length - 1];
  const more = items.length >= limit || st.scannedTo > from;
  return {
    items: items.map((x) => ({ ...x, at: new Date(x.at).toISOString() })),
    next: more && last ? `${new Date(last.at).getTime()}|${last.event_id}` : more ? `${st.scannedTo}|` : null,
    searched: { from: new Date(st.scannedTo).toISOString(), to: new Date(end).toISOString() },
    range: { from: new Date(from).toISOString(), to: new Date(to).toISOString() },
    partial: st.partial,
    // older calls still being counted into the rollups: searches before this time take the slower way for now
    indexing: Number.isFinite(fastFrom) && fastFrom > from ? new Date(Math.min(fastFrom, to)).toISOString() : null,
    retentionDays: config.scanner.sessionRetentionDays,
  };
}

/** Planned from the rollups: read back only as far as the page needs, and only sessions of roles with a match. */
async function viaRollups(user, opts, { accounts, from, end, cursor, limit, items, st, run }) {
  const hourOf = (t) => Math.floor(t / H) * H;
  const plan = await rollupPlan(opts);
  if (plan.kinds && !plan.kinds.length) { st.scannedTo = from; return; }      // no call of that kind was ever stored
  // hours with a match are listed a span at a time (a day, then a week, then the rest): most pages fill from the first
  const spans = [...new Set([end - 24 * H, end - 168 * H, from].map((t) => Math.max(from, t)))];
  let split = true;                              // the newest hour may be read in part when it is very busy
  for (const spanFrom of spans) {
    if (items.length >= limit || st.scannedTo <= spanFrom) continue;
    const hp = [accounts, new Date(hourOf(spanFrom)).toISOString(), new Date(st.scannedTo).toISOString()];
    const hours = await run(
      `SELECT h.hour, sum(h.n)::bigint AS n FROM call_hourly h
        WHERE h.account_id = ANY($1) AND h.hour >= $2 AND h.hour < $3 ${plan.where((v) => `$${hp.push(v)}`).map((w) => `AND ${w}`).join(' ')}
        GROUP BY h.hour ORDER BY h.hour DESC`, hp);
    if (!hours) return;
    const list = hours.map((x) => ({ t: new Date(x.hour).getTime(), n: x.n }));
    let i = 0;
    while (items.length < limit && i < list.length) {
      if (Date.now() > st.deadline) { st.partial = true; return; }
      const need = limit - items.length, target = plan.exact ? need : need * 4;
      let j = i, sum = 0;
      while (j < list.length && sum < target) sum += list[j++].n;
      const hi = st.scannedTo;
      let lo = Math.max(spanFrom, list[j - 1].t), whole = true;
      if (j === i + 1 && split && plan.exact && list[i].n > need * 8 && hi - lo > 4 * 60e3) {
        lo = Math.max(lo, Math.floor(hi - Math.max(2 * 60e3, ((hi - lo) * need * 4) / list[i].n))); whole = false;
      }
      split = whole;                              // after a part of an hour, take the rest of it
      if (lo < hi) {
        const p = [accounts, new Date(hourOf(lo)).toISOString(), new Date(hi).toISOString(), new Date(lo).toISOString(), need];
        const tests = plan.where((v) => `$${p.push(v)}`);
        // accounts, role and kind are settled by the rollup; what is left are tests on the call and its session
        const call = callTests(opts, p);
        if (cursor) { p.push(cursor.at, cursor.id); call.push(`(c.at, c.event_id) < ($${p.length - 1}::timestamptz, $${p.length})`); }
        const callSql = call.length ? `AND ${call.join(' AND ')}` : '';
        const needS = /\b[sra]\./.test(callSql);
        const active = tests.length
          ? `SELECT DISTINCT sh.session_id FROM (SELECT DISTINCT h.account_id, h.hour, h.role_id FROM call_hourly h WHERE h.account_id = ANY($1) AND h.hour >= $2 AND h.hour < $3 AND ${tests.join(' AND ')}) hit
               JOIN session_hours sh ON sh.account_id = hit.account_id AND sh.hour = hit.hour AND sh.role_id = hit.role_id`
          : `SELECT DISTINCT sh.session_id FROM session_hours sh WHERE sh.account_id = ANY($1) AND sh.hour >= $2 AND sh.hour < $3`;
        const rows = await run(
          `WITH active AS MATERIALIZED (${active})
           SELECT ${COLS}
             FROM (SELECT c.* FROM active ${needS ? 'JOIN track_sessions s ON s.id = active.session_id JOIN roles r ON r.id = s.role_id JOIN cloud_accounts a ON a.id = s.account_id' : ''}
                     JOIN LATERAL (SELECT * FROM track_calls c WHERE c.session_id = active.session_id AND c.at >= $4 AND c.at < $3 ${callSql}
                                    ORDER BY c.at DESC, c.event_id DESC LIMIT $5) c ON true
                    ORDER BY c.at DESC, c.event_id DESC LIMIT $5) c
             JOIN track_sessions s ON s.id = c.session_id JOIN roles r ON r.id = s.role_id JOIN cloud_accounts a ON a.id = s.account_id
            ORDER BY c.at DESC, c.event_id DESC`, p);
        if (!rows) return;
        items.push(...rows);
        st.scannedTo = lo;
      }
      if (whole) i = j;
    }
    if (items.length < limit) st.scannedTo = spanFrom;     // every hour with a match in this span was read
  }
}

/** The older way, for hours the rollups do not cover yet: sessions overlapping a growing slice. */
async function viaSessions(user, opts, { from, end, cursor, limit, items, st, run }) {
  for (let i = 0; i < SLICES.length && items.length < limit && st.scannedTo > from; i++) {
    if (Date.now() > st.deadline) { st.partial = true; return; }
    const hi = st.scannedTo, lo = Math.max(from, end - SLICES[i]);
    if (lo >= hi) continue;
    const p = [];
    const { sess, call } = filters(user, opts, p);
    p.push(new Date(lo).toISOString()); const pLo = p.length;
    p.push(new Date(hi).toISOString()); const pHi = p.length;
    p.push(limit - items.length); const pLim = p.length;
    p.push(new Date(lo - MAX_SESSION_MS).toISOString()); const pBorn = p.length;
    if (cursor) { p.push(cursor.at, cursor.id); call.push(`(c.at, c.event_id) < ($${p.length - 1}::timestamptz, $${p.length})`); }
    const rows = await run(
      `SELECT ${COLS}
         FROM track_sessions s JOIN roles r ON r.id = s.role_id JOIN cloud_accounts a ON a.id = s.account_id
         JOIN LATERAL (SELECT * FROM track_calls c WHERE c.session_id = s.id AND c.at >= $${pLo} AND c.at < $${pHi}
                         ${call.length ? `AND ${call.join(' AND ')}` : ''} ORDER BY c.at DESC, c.event_id DESC LIMIT $${pLim}) c ON true
        WHERE ${sess.join(' AND ')} AND s.started_at >= $${pBorn} AND s.started_at < $${pHi} AND COALESCE(s.last_call_at, s.started_at) >= $${pLo}
        ORDER BY c.at DESC, c.event_id DESC LIMIT $${pLim}`, p);
    if (!rows) return;
    items.push(...rows);
    st.scannedTo = lo;
  }
}

const csvCell = (v) => { const s = v == null ? '' : Array.isArray(v) ? v.join(' ') : String(v); return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s; };
export function eventsCsv(items) {
  const cols = ['at', 'aws_account_id', 'account_name', 'role_name', 'session_name', 'caller_arn', 'source_ip', 'event_source', 'event_name', 'action', 'resources', 'denied', 'error_code', 'event_id', 'access_key_id', 'user_agent'];
  return [cols.join(','), ...items.map((x) => cols.map((c) => csvCell(x[c])).join(','))].join('\n') + '\n';
}
