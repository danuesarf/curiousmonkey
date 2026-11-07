// Session replay: one role session, the sessions that led to it, and every role it jumped into.
// Sessions are linked by access key: an AssumeRole made with session A's key created session B
// (B.parent_key_id = A.access_key_id). That works across accounts when both are connected.
import { query } from './db.js';
import { inScope } from './auth/rbac.js';

const MAX_HOPS = 12;

const SESSION_COLS = `s.id, s.account_id, s.role_id, s.access_key_id, s.parent_key_id, s.via, s.caller_type, s.caller_arn, s.session_name,
  s.source_ip, s.user_agent, s.mfa, s.source_identity, s.trust, s.start_known, s.started_at, s.last_call_at, s.calls, s.denied,
  r.name AS role_name, r.arn AS role_arn, a.name AS account_name, a.account_id AS aws_account_id, p.display AS principal, p.kind AS principal_kind`;
const FROM = `FROM track_sessions s JOIN roles r ON r.id=s.role_id JOIN cloud_accounts a ON a.id=s.account_id LEFT JOIN principals p ON p.id=s.principal_id`;

/** Sessions to pick from, newest first. A session that started a jump says so. */
export async function listSessions(user, { accountId, roleId, limit = 50 } = {}) {
  const p = [], where = [];
  if (accountId) { p.push(accountId); where.push(`s.account_id=$${p.length}`); }
  if (roleId) { p.push(roleId); where.push(`s.role_id=$${p.length}`); }
  if (user.scope_accounts) { p.push(user.scope_accounts); where.push(`s.account_id = ANY($${p.length}::uuid[])`); }
  p.push(Math.min(limit, 200));
  const r = await query(
    `SELECT ${SESSION_COLS},
       EXISTS (SELECT 1 FROM track_sessions c WHERE c.parent_key_id = s.access_key_id) AS has_jumps,
       (s.parent_key_id IS NOT NULL) AS is_jump
     ${FROM} ${where.length ? `WHERE ${where.join(' AND ')}` : ''}
     ORDER BY s.started_at DESC LIMIT $${p.length}`, p);
  return r.rows.map(publicSession);
}

/**
 * The whole chain around one session: up to the first session (whoever started it all), and down into every
 * session started from any of them. Calls of all of them, in time order, each tagged with its session.
 */
export async function buildTrack(user, sessionId) {
  const start = (await query(`SELECT ${SESSION_COLS} ${FROM} WHERE s.id=$1`, [sessionId])).rows[0];
  if (!start || !inScope(user, start.account_id)) return null;

  const byKey = new Map([[start.access_key_id, start]]);
  // up: the session whose key made this one
  let cur = start;
  for (let i = 0; i < MAX_HOPS && cur.parent_key_id; i++) {
    const parent = (await query(`SELECT ${SESSION_COLS} ${FROM} WHERE s.access_key_id=$1`, [cur.parent_key_id])).rows[0];
    if (!parent || byKey.has(parent.access_key_id)) break;
    byKey.set(parent.access_key_id, parent); cur = parent;
  }
  const root = cur;
  // down: breadth first from the root, so sibling jumps show too
  // (sessions already found on the way up are expanded too, so the start session's own jumps are not skipped)
  let frontier = [root.access_key_id];
  const expanded = new Set();
  for (let i = 0; i < MAX_HOPS && frontier.length; i++) {
    frontier.forEach((k) => expanded.add(k));
    const kids = (await query(`SELECT ${SESSION_COLS} ${FROM} WHERE s.parent_key_id = ANY($1) ORDER BY s.started_at`, [frontier])).rows;
    frontier = [];
    for (const k of kids) {
      if (!byKey.has(k.access_key_id)) byKey.set(k.access_key_id, k);
      if (!expanded.has(k.access_key_id)) frontier.push(k.access_key_id);
    }
  }

  const ordered = [...byKey.values()].sort((a, b) => a.started_at - b.started_at);
  const visible = ordered.filter((s) => inScope(user, s.account_id));
  const index = new Map(visible.map((s, i) => [s.id, i]));
  const keyIndex = new Map(visible.map((s, i) => [s.access_key_id, i]));
  const calls = visible.length ? (await query(
    `SELECT session_id, event_id, at, action, event_source, event_name, resources, denied, error_code, child_key_id
       FROM track_calls WHERE session_id = ANY($1) ORDER BY at, event_id LIMIT 5000`, [visible.map((s) => s.id)])).rows : [];
  return {
    sessionId: start.id,
    origin: { caller: root.principal || root.caller_arn || 'unknown', callerType: root.caller_type, via: root.via, startKnown: root.start_known },
    sessions: visible.map((s, i) => ({ ...publicSession(s), lane: i, parentLane: s.parent_key_id && keyIndex.has(s.parent_key_id) ? keyIndex.get(s.parent_key_id) : null })),
    hidden: ordered.length - visible.length,           // sessions in accounts this user cannot see
    calls: calls.map((c) => ({
      lane: index.get(c.session_id), at: c.at, action: c.action, eventSource: c.event_source, eventName: c.event_name,
      resources: c.resources, denied: c.denied, errorCode: c.error_code,
      jumpTo: c.child_key_id && keyIndex.has(c.child_key_id) ? keyIndex.get(c.child_key_id) : null,
      jumpOutOfView: !!c.child_key_id && !keyIndex.has(c.child_key_id),
    })),
  };
}

function publicSession(s) {
  return {
    id: s.id, accountId: s.account_id, account: s.account_name, awsAccountId: s.aws_account_id, roleId: s.role_id, role: s.role_name, roleArn: s.role_arn,
    principal: s.principal, principalKind: s.principal_kind, via: s.via, callerType: s.caller_type, callerArn: s.caller_arn, sessionName: s.session_name,
    sourceIp: s.source_ip, userAgent: s.user_agent, mfa: s.mfa, sourceIdentity: s.source_identity, trust: s.trust, startKnown: s.start_known,
    startedAt: s.started_at, lastCallAt: s.last_call_at, calls: s.calls, denied: s.denied,
    isJump: s.is_jump ?? !!s.parent_key_id, hasJumps: s.has_jumps ?? false,
  };
}
