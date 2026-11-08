// Writes a batch of parsed events. Everything is worked out in memory first and then written with about a dozen
// set-based statements, whatever the batch size: one round trip per event was the slowest part of a scan.
//
// What gets recorded is the same as before:
//   principals        who entered each role (and the sessions seen without their start)
//   role_sessions     temporary access key -> principal, so later calls are attributed to who started the session
//   track_sessions    / track_calls: session replay, within the retention window
//   activity_daily    calls per role, principal, action and day; activity_resources; passrole_observed
import { config } from '../config.js';
import { matchTrust } from '../analyzer/trust.js';
import { recordNewCaller } from '../radarHistory.js';

const DAY = 864e5;
const CHUNK = 5000;                                     // rows per statement for the big inserts
const J = (v) => JSON.stringify(v);
const chunks = (a, n = CHUNK) => { const out = []; for (let i = 0; i < a.length; i += n) out.push(a.slice(i, i + n)); return out; };

export function principalFrom(e) {
  const c = e.caller;
  if (c.type === 'AWSService' || c.invokedBy) return { key: `svc:${c.invokedBy}`, kind: 'service', display: c.invokedBy };
  if (c.type === 'IAMUser') return { key: `user:${c.arn}`, kind: 'user', display: `${c.arn?.split(':').pop()} (${c.accountId})` };
  if (c.type === 'AssumedRole') { const m = c.arn?.match(/assumed-role\/([^/]+)\//); return { key: `role:${c.accountId}:${m?.[1]}`, kind: 'role', display: `role/${m?.[1]} (${c.accountId})` }; }
  if (c.type === 'SAMLUser' || c.type === 'WebIdentityUser') {
    const who = c.principalId?.split(':').slice(1).join(':') || e.sessionName;
    return { key: `fed:${c.principalId || e.sessionName}`, kind: 'federated', display: who };
  }
  return { key: `other:${c.arn || c.type}`, kind: 'other', display: c.arn || String(c.type) };
}

/** The role an event belongs to: by ARN, or by name when the event had no sessionIssuer. */
export const roleOf = (e, roles) => (e.roleArn ? roles.byArn.get(e.roleArn) : e.roleName ? roles.byName.get(e.roleName) : null) || null;

export async function applyEvents(c, evs, roles, accountId, opts = {}) {
  if (!evs.length) return;
  const keepFrom = Date.now() - config.scanner.sessionRetentionDays * DAY;

  // ---- 1. which principal each temporary key belongs to, as stored before this batch ----
  const keys = new Set();
  for (const e of evs) { if (e.accessKeyId) keys.add(e.accessKeyId); if (e.callerKeyId) keys.add(e.callerKeyId); }
  const keyOwner = new Map();                           // access key -> principal ref: { id } (stored) or { ref } (this batch)
  if (keys.size) {
    for (const part of chunks([...keys])) {
      const r = await c.query(`SELECT access_key_id, principal_id FROM role_sessions WHERE access_key_id = ANY($1)`, [part]);
      for (const x of r.rows) keyOwner.set(x.access_key_id, { id: x.principal_id });
    }
  }

  // ---- 2. work everything out in memory, in the same order as before: assumptions first, then calls ----
  const P = new Map();                                  // 'role|key' -> principal to upsert
  const ensure = (role, p, e, via, caller) => {
    const ref = `${role.id}|${p.key}`;
    let x = P.get(ref);
    if (!x) { x = { ref, role, p, via, caller, first: e.time, last: e.time, firstAt: e.time }; P.set(ref, x); }
    if (e.time < x.first) x.first = e.time; if (e.time > x.last) x.last = e.time;
    return { ref };
  };
  const assumeAgg = new Map();                          // principal ref -> { n, caller, via, ips, mfa, sid, tags }
  const seenAgg = new Map();                            // principal (stored id) -> { first, last }
  const newKeys = new Map();                            // access key -> { role, principal ref, started }
  const sessUpserts = new Map();                        // access key -> full track_sessions row (from an AssumeRole)
  const callRows = [];                                  // track_calls, resolved to sessions later
  const daily = new Map(), resources = new Map(), passed = new Map();
  const pkey = (pr) => pr.id || pr.ref;

  const handleCall = (role, e, { action = e.action, resources: res = e.resources, childKey = null } = {}) => {
    let pr = e.accessKeyId ? keyOwner.get(e.accessKeyId) : null;
    if (!pr) pr = ensure(role, { key: `session:${e.sessionName}`, kind: 'session', display: `session ${e.sessionName}` }, e, 'unknown (started before the window)', {});
    else if (pr.id) { const s = seenAgg.get(pr.id) || { first: e.time, last: e.time }; if (e.time < s.first) s.first = e.time; if (e.time > s.last) s.last = e.time; seenAgg.set(pr.id, s); }
    else { const x = P.get(pr.ref); if (e.time < x.first) x.first = e.time; if (e.time > x.last) x.last = e.time; }
    if (e.time.getTime() >= keepFrom && e.accessKeyId) {
      callRows.push({ key: e.accessKeyId, role, pr, e, action, resources: res || [], childKey });
    }
    if (!action) return;                                // no IAM permission involved (console sign-in)
    const day = e.time.toISOString().slice(0, 10);
    const dk = `${role.id}|${pkey(pr)}|${action}|${day}`;
    const d = daily.get(dk) || { role: role.id, pr, action, day, ok: 0, err: 0, nores: 0 };
    e.denied ? d.err++ : d.ok++; daily.set(dk, d);
    if (!e.denied && !res.length) d.nores++;
    if (e.denied) return;                               // denied calls prove nothing was used
    for (const r of res) {
      const rk = `${role.id}|${action}|${r}`;
      const x = resources.get(rk) || { role: role.id, action, resource: r, last: e.time, n: 0 };
      x.n++; if (e.time > x.last) x.last = e.time; resources.set(rk, x);
    }
    for (const arn of e.passedRoles || []) {
      const svc = e.eventSource.replace(/\.amazonaws\.com$/, '');
      const pk = `${role.id}|${arn}|${svc}`;
      const x = passed.get(pk) || { role: role.id, arn, svc, last: e.time, n: 0 };
      x.n++; if (e.time > x.last) x.last = e.time; passed.set(pk, x);
    }
  };

  for (const e of evs) {
    if (e.type === 'assume') {
      // 1. role chaining: a role session in this account made the AssumeRole. That is a call of its own.
      const callerRole = e.callerRoleArn ? roles.byArn.get(e.callerRoleArn) : e.callerRoleName ? roles.byName.get(e.callerRoleName) : null;
      if (callerRole) {
        handleCall(callerRole, { ...e, accessKeyId: e.callerKeyId, sessionName: e.callerSessionName, eventSource: 'sts.amazonaws.com', passedRoles: [] },
          { action: `sts:${e.eventName}`, resources: e.roleArn ? [e.roleArn] : [], childKey: e.denied ? null : e.accessKeyId });
      }
      // 2. the role being entered
      const role = roles.byArn.get(e.roleArn);
      if (!role || e.denied) continue;                  // a refused AssumeRole is not a use
      const p = principalFrom(e);
      const viaAction = `sts:${e.eventName}`;
      const trust = matchTrust(role.trust_policy, e.caller, viaAction);
      const callerJson = { ...e.caller, trust };
      const pr = ensure(role, p, e, viaAction, callerJson);
      const a = assumeAgg.get(pr.ref) || { n: 0, ips: new Set(), mfa: false, sid: null, tags: new Set() };
      a.n++; a.caller = callerJson; a.via = viaAction;
      if (e.ip) a.ips.add(e.ip);
      if (e.mfa) a.mfa = true;
      if (e.sourceIdentity) a.sid = e.sourceIdentity;
      for (const t of e.sessionTags || []) a.tags.add(t);
      assumeAgg.set(pr.ref, a);
      if (e.accessKeyId) {
        if (!keyOwner.has(e.accessKeyId)) { keyOwner.set(e.accessKeyId, pr); newKeys.set(e.accessKeyId, { role, pr, started: e.time }); }   // the first one wins, as before
        if (e.time.getTime() >= keepFrom) {
          const prev = sessUpserts.get(e.accessKeyId);
          sessUpserts.set(e.accessKeyId, { role, pr, e, viaAction, trust, started: prev && prev.started < e.time ? prev.started : e.time });
        }
      }
      continue;
    }
    const role = roleOf(e, roles);
    if (!role) continue;
    handleCall(role, e);
  }

  // ---- 3. principals: one upsert, then the AssumeRole details and the first/last-seen of stored ones ----
  const plist = [...P.values()];
  const idOf = new Map();                               // ref -> uuid
  for (const part of chunks(plist)) {
    const r = await c.query(
      `INSERT INTO principals(role_id, key, kind, display, via, caller, first_seen, last_seen, sessions_count, source_ips, mfa, source_identity, session_tags)
       SELECT r, k, kd, ds, v, cl::jsonb, f, l, 0, '{}', NULL, NULL, '{}'
         FROM unnest($1::uuid[], $2::text[], $3::text[], $4::text[], $5::text[], $6::text[], $7::timestamptz[], $8::timestamptz[]) AS t(r, k, kd, ds, v, cl, f, l)
       ON CONFLICT (role_id, key) DO UPDATE SET first_seen=LEAST(principals.first_seen, EXCLUDED.first_seen), last_seen=GREATEST(principals.last_seen, EXCLUDED.last_seen)
       RETURNING id, role_id, key, (xmax = 0) AS inserted`,
      [part.map((x) => x.role.id), part.map((x) => x.p.key), part.map((x) => x.p.kind), part.map((x) => x.p.display), part.map((x) => x.via),
       part.map((x) => J(x.caller || {})), part.map((x) => x.first), part.map((x) => x.last)]);
    for (const row of r.rows) {
      const ref = `${row.role_id}|${row.key}`;
      idOf.set(ref, row.id);
      const x = P.get(ref);
      // a caller never seen before, in an account whose history was already complete: ping it
      if (row.inserted && opts.recordNew && x.p.kind !== 'session' && x.firstAt.getTime() > Date.now() - 3 * DAY) {
        await recordNewCaller(c, accountId, x.role, x.p, x.via, x.firstAt);
      }
    }
  }
  const resolve = (pr) => pr.id || idOf.get(pr.ref);

  if (assumeAgg.size) {
    const A = [...assumeAgg.entries()];
    await c.query(
      `UPDATE principals p SET sessions_count = p.sessions_count + u.n, caller = u.cl::jsonb,
         source_ips = (SELECT ARRAY(SELECT DISTINCT unnest(p.source_ips || ARRAY(SELECT jsonb_array_elements_text(u.ips::jsonb))) LIMIT 20)),
         mfa = CASE WHEN u.mfa THEN true ELSE p.mfa END, source_identity = COALESCE(u.sid, p.source_identity),
         session_tags = (SELECT ARRAY(SELECT DISTINCT unnest(p.session_tags || ARRAY(SELECT jsonb_array_elements_text(u.tags::jsonb))) LIMIT 20)), via = u.via
       FROM unnest($1::uuid[], $2::int[], $3::text[], $4::text[], $5::bool[], $6::text[], $7::text[], $8::text[]) AS u(id, n, cl, ips, mfa, sid, tags, via)
       WHERE p.id = u.id`,
      [A.map(([ref]) => idOf.get(ref)), A.map(([, a]) => a.n), A.map(([, a]) => J(a.caller)), A.map(([, a]) => J([...a.ips])), A.map(([, a]) => a.mfa),
       A.map(([, a]) => a.sid), A.map(([, a]) => J([...a.tags])), A.map(([, a]) => a.via)]);
  }
  if (seenAgg.size) {
    const S = [...seenAgg.entries()];
    await c.query(
      `UPDATE principals p SET first_seen = LEAST(p.first_seen, u.f), last_seen = GREATEST(p.last_seen, u.l)
         FROM unnest($1::uuid[], $2::timestamptz[], $3::timestamptz[]) AS u(id, f, l) WHERE p.id = u.id`,
      [S.map(([id]) => id), S.map(([, s]) => s.first), S.map(([, s]) => s.last)]);
  }

  // ---- 4. temporary keys -> principal, for calls in later batches (and other regions) ----
  if (newKeys.size) {
    const K = [...newKeys.entries()];
    await c.query(
      `INSERT INTO role_sessions(access_key_id, role_id, principal_id, started_at)
       SELECT * FROM unnest($1::text[], $2::uuid[], $3::uuid[], $4::timestamptz[]) ON CONFLICT (access_key_id) DO NOTHING`,
      [K.map(([k]) => k), K.map(([, v]) => v.role.id), K.map(([, v]) => resolve(v.pr)), K.map(([, v]) => v.started)]);
  }

  // ---- 5. session replay (retention window only) ----
  if (sessUpserts.size || callRows.length) {
    const sessionId = new Map();                        // access key -> track_sessions.id
    if (sessUpserts.size) {
      const U = [...sessUpserts.entries()];
      const r = await c.query(
        `INSERT INTO track_sessions(account_id, role_id, access_key_id, principal_id, parent_key_id, via, caller_type, caller_arn, session_name, source_ip, user_agent, mfa, source_identity, trust, start_known, started_at)
         SELECT $1::uuid, * FROM unnest($2::uuid[], $3::text[], $4::uuid[], $5::text[], $6::text[], $7::text[], $8::text[], $9::text[], $10::text[], $11::text[], $12::bool[], $13::text[], $14::jsonb[], $15::bool[], $16::timestamptz[])
         ON CONFLICT (access_key_id) DO UPDATE SET principal_id=EXCLUDED.principal_id, parent_key_id=EXCLUDED.parent_key_id, via=EXCLUDED.via,
           caller_type=EXCLUDED.caller_type, caller_arn=EXCLUDED.caller_arn, session_name=EXCLUDED.session_name, source_ip=EXCLUDED.source_ip,
           user_agent=EXCLUDED.user_agent, mfa=EXCLUDED.mfa, source_identity=EXCLUDED.source_identity, trust=EXCLUDED.trust, start_known=true,
           started_at=LEAST(track_sessions.started_at, EXCLUDED.started_at)
         RETURNING id, access_key_id`,
        [accountId, U.map(([, s]) => s.role.id), U.map(([k]) => k), U.map(([, s]) => resolve(s.pr)),
         U.map(([, s]) => (s.e.caller?.type === 'AssumedRole' ? s.e.callerKeyId : null)), U.map(([, s]) => s.viaAction), U.map(([, s]) => s.e.caller?.type || null),
         U.map(([, s]) => s.e.caller?.arn || null), U.map(([, s]) => s.e.sessionName), U.map(([, s]) => s.e.ip), U.map(([, s]) => s.e.userAgent),
         U.map(([, s]) => s.e.mfa ?? null), U.map(([, s]) => s.e.sourceIdentity || null), U.map(([, s]) => J(s.trust || null)), U.map(() => true), U.map(([, s]) => s.started)]);
      for (const x of r.rows) sessionId.set(x.access_key_id, x.id);
    }
    // calls whose session started in an earlier batch, or before the stored history
    const missing = [...new Set(callRows.map((x) => x.key))].filter((k) => !sessionId.has(k));
    for (const part of chunks(missing)) {
      const r = await c.query(`SELECT access_key_id, id FROM track_sessions WHERE access_key_id = ANY($1)`, [part]);
      for (const x of r.rows) sessionId.set(x.access_key_id, x.id);
    }
    const placeholders = new Map();
    for (const x of callRows) if (!sessionId.has(x.key) && !placeholders.has(x.key)) placeholders.set(x.key, x);   // the first (earliest) call starts it
    if (placeholders.size) {
      const H = [...placeholders.values()];
      const r = await c.query(
        `INSERT INTO track_sessions(account_id, role_id, access_key_id, principal_id, via, session_name, source_ip, user_agent, start_known, started_at)
         SELECT $1::uuid, r, k, p, 'started before stored history', sn, ip, ua, false, t
           FROM unnest($2::uuid[], $3::text[], $4::uuid[], $5::text[], $6::text[], $7::text[], $8::timestamptz[]) AS u(r, k, p, sn, ip, ua, t)
         ON CONFLICT (access_key_id) DO UPDATE SET started_at=LEAST(track_sessions.started_at, EXCLUDED.started_at) RETURNING id, access_key_id`,
        [accountId, H.map((x) => x.role.id), H.map((x) => x.key), H.map((x) => resolve(x.pr)), H.map((x) => x.e.sessionName || null), H.map((x) => x.e.ip), H.map((x) => x.e.userAgent), H.map((x) => x.e.time)]);
      for (const x of r.rows) sessionId.set(x.access_key_id, x.id);
    }
    // duplicates were removed before this point, so every row counts; the session tallies are worked out here
    // instead of being sent back by the database
    const tally = new Map();
    for (const part of chunks(callRows)) {
      await c.query(
        `INSERT INTO track_calls(session_id, event_id, at, action, event_source, event_name, resources, denied, error_code, child_key_id)
         SELECT s, ev, t, a, src, nm, CASE WHEN res = '' THEN '{}'::text[] ELSE string_to_array(res, chr(31)) END, d, ec, ck
           FROM unnest($1::uuid[], $2::text[], $3::timestamptz[], $4::text[], $5::text[], $6::text[], $7::text[], $8::bool[], $9::text[], $10::text[]) AS u(s, ev, t, a, src, nm, res, d, ec, ck)
         ON CONFLICT DO NOTHING`,
        [part.map((x) => sessionId.get(x.key)), part.map((x) => x.e.id), part.map((x) => x.e.time), part.map((x) => x.action), part.map((x) => x.e.eventSource || 'sts.amazonaws.com'),
         part.map((x) => x.e.eventName), part.map((x) => x.resources.join('\u001f')), part.map((x) => !!x.e.denied), part.map((x) => x.e.errorCode), part.map((x) => x.childKey || null)]);
    }
    const once = new Set();
    for (const x of callRows) {
      const sid = sessionId.get(x.key), k = `${sid}|${x.e.id}`;
      if (once.has(k)) continue;                       // the same event twice in one session (it cannot be stored twice)
      once.add(k);
      const t = tally.get(sid) || { n: 0, denied: 0, last: x.e.time };
      t.n++; if (x.e.denied) t.denied++; if (x.e.time > t.last) t.last = x.e.time; tally.set(sid, t);
    }
    if (tally.size) {
      const T = [...tally.entries()];
      await c.query(
        `UPDATE track_sessions s SET calls = s.calls + u.n, denied = s.denied + u.d, last_call_at = GREATEST(COALESCE(s.last_call_at, u.l), u.l)
           FROM unnest($1::uuid[], $2::int[], $3::int[], $4::timestamptz[]) AS u(id, n, d, l) WHERE s.id = u.id`,
        [T.map(([id]) => id), T.map(([, t]) => t.n), T.map(([, t]) => t.denied), T.map(([, t]) => t.last)]);
    }
  }

  // ---- 6. activity aggregates ----
  const D = new Map();                                  // re-keyed by stored principal id
  for (const d of daily.values()) {
    const pid = resolve(d.pr);
    const k = `${d.role}|${pid}|${d.action}|${d.day}`;
    const x = D.get(k) || { role: d.role, pid, action: d.action, day: d.day, ok: 0, err: 0, nores: 0 };
    x.ok += d.ok; x.err += d.err; x.nores += d.nores; D.set(k, x);
  }
  for (const part of chunks([...D.values()])) {
    await c.query(
      `INSERT INTO activity_daily(role_id, principal_id, action, day, count, error_count, no_resource_count)
       SELECT * FROM unnest($1::uuid[], $2::uuid[], $3::text[], $4::date[], $5::int[], $6::int[], $7::int[])
       ON CONFLICT (role_id, principal_id, action, day) DO UPDATE SET count=activity_daily.count+EXCLUDED.count, error_count=activity_daily.error_count+EXCLUDED.error_count,
         no_resource_count=activity_daily.no_resource_count+EXCLUDED.no_resource_count`,
      [part.map((x) => x.role), part.map((x) => x.pid), part.map((x) => x.action), part.map((x) => x.day), part.map((x) => x.ok), part.map((x) => x.err), part.map((x) => x.nores)]);
  }
  for (const part of chunks([...resources.values()])) {
    await c.query(
      `INSERT INTO activity_resources(role_id, action, resource, last_seen, count)
       SELECT * FROM unnest($1::uuid[], $2::text[], $3::text[], $4::timestamptz[], $5::int[])
       ON CONFLICT (role_id, action, resource) DO UPDATE SET count=activity_resources.count+EXCLUDED.count, last_seen=GREATEST(activity_resources.last_seen, EXCLUDED.last_seen)`,
      [part.map((x) => x.role), part.map((x) => x.action), part.map((x) => x.resource), part.map((x) => x.last), part.map((x) => x.n)]);
  }
  for (const part of chunks([...passed.values()])) {
    await c.query(
      `INSERT INTO passrole_observed(role_id, passed_role_arn, service, last_seen, count)
       SELECT * FROM unnest($1::uuid[], $2::text[], $3::text[], $4::timestamptz[], $5::int[])
       ON CONFLICT (role_id, passed_role_arn, service) DO UPDATE SET count=passrole_observed.count+EXCLUDED.count, last_seen=GREATEST(passrole_observed.last_seen, EXCLUDED.last_seen)`,
      [part.map((x) => x.role), part.map((x) => x.arn), part.map((x) => x.svc), part.map((x) => x.last), part.map((x) => x.n)]);
  }
}
