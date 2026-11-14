// What changed on one identity, newest first: the History tab. Merges what inventory and analysis record
// (identity_events) with what other tables already know: keys created and deleted, Radar's changes (new callers,
// permissions gained or trimmed, first denied calls), when it was created in AWS, and every decision and approval
// on it from the audit log.
import { query } from './db.js';

const RADAR = { 'new-caller': 'caller', grew: 'permissions', cleaned: 'permissions', denied: 'denied', dead: 'idle' };
const DECIDED = { keep_scoped: 'keep, scoped', keep: 'keep', remove: 'remove', accept: 'accept', investigate: 'investigate' };

/**
 * Up to `limit` entries: { id, at, kind, group, title, detail, by, diff }. `group` is what the tab filters on:
 * policy, access, credentials, risk, review, lifecycle. `diff` is true when the entry has documents to compare
 * (GET /roles/:id/history/:eventId returns them).
 */
export async function identityHistory(role, { limit = 500 } = {}) {
  const [ev, ch, keys, audit] = await Promise.all([
    query(`SELECT id, at, kind, title, detail - 'before' - 'after' AS detail, (detail ? 'before' OR detail ? 'after') AS diff
             FROM identity_events WHERE role_id = $1 ORDER BY at DESC LIMIT $2`, [role.id, limit]),
    query(`SELECT id, at, kind, severity, title, detail FROM changes WHERE role_id = $1 AND kind = ANY($2) ORDER BY at DESC LIMIT $3`, [role.id, Object.keys(RADAR), limit]),
    role.kind === 'iam-user' ? query('SELECT key_id, created_at, deleted_at FROM iam_access_keys WHERE role_id = $1', [role.id]) : { rows: [] },
    query(`SELECT a.id, a.at, a.action, a.actor_email, a.detail, coalesce(f.title, '') AS flag_title, u.name AS actor_name
             FROM audit_log a
             LEFT JOIN flags f ON a.target_type = 'flag' AND f.id::text = a.target_id
             LEFT JOIN users u ON u.id = a.actor_id
            WHERE (a.target_type = 'flag' AND a.target_id IN (SELECT id::text FROM flags WHERE role_id = $1) AND a.action IN ('flag.decide', 'flag.undecide'))
               OR (a.target_type = 'recommendation' AND a.target_id IN (SELECT id::text FROM recommendations WHERE role_id = $1) AND a.action = 'recommendation.approve')
            ORDER BY a.at DESC LIMIT $2`, [role.id, limit]),
  ]);
  const GROUP = { 'policy-added': 'policy', 'policy-removed': 'policy', 'policy-changed': 'policy', 'trust-changed': 'access', 'boundary-changed': 'policy',
    risk: 'risk', 'key-status': 'credentials', password: 'credentials', mfa: 'credentials', deleted: 'lifecycle', restored: 'lifecycle' };
  const out = [
    ...ev.rows.map((e) => ({ id: `e${e.id}`, at: e.at, kind: e.kind, group: GROUP[e.kind], title: e.title, detail: e.detail, diff: e.diff })),
    ...ch.rows.map((c) => ({ id: `c${c.id}`, at: c.at, kind: `radar-${c.kind}`, group: c.kind === 'new-caller' ? 'access' : c.kind === 'denied' ? 'access' : 'policy',
      title: c.kind === 'new-caller' ? 'New caller' : c.title, detail: { text: c.detail, severity: c.severity } })),
    ...keys.rows.flatMap((k) => [
      k.created_at && { id: `k+${k.key_id}`, at: k.created_at, kind: 'key-created', group: 'credentials', title: `Access key ${k.key_id} created`, detail: { key: k.key_id } },
      k.deleted_at && { id: `k-${k.key_id}`, at: k.deleted_at, kind: 'key-deleted', group: 'credentials', title: `Access key ${k.key_id} deleted`, detail: { key: k.key_id, note: 'seen gone at this scan' } },
    ].filter(Boolean)),
    ...audit.rows.map((a) => ({
      id: `a${a.id}`, at: a.at, kind: a.action === 'recommendation.approve' ? 'approval' : a.action === 'flag.undecide' ? 'undecided' : 'decision', group: 'review',
      title: a.action === 'recommendation.approve' ? `Least-privilege policy approved${a.detail?.team ? ` by ${a.detail.team}` : ''}`
        : a.action === 'flag.undecide' ? `Decision cleared on “${a.flag_title || a.detail?.key || 'a finding'}”`
          : `Decided “${DECIDED[a.detail?.decision] || a.detail?.decision}” on “${a.flag_title || a.detail?.key || 'a finding'}”`,
      by: a.actor_name || a.actor_email, detail: { bulk: !!a.detail?.bulk } })),
  ];
  if (role.created_in_aws) out.push({ id: 'created', at: role.created_in_aws, kind: 'created', group: 'lifecycle', title: `Created in AWS`, detail: {} });
  out.sort((x, y) => new Date(y.at) - new Date(x.at));
  return out.slice(0, limit);
}

/** One recorded event with its documents, for the diff. */
export async function historyEvent(roleId, eventId) {
  return (await query('SELECT id, at, kind, title, detail FROM identity_events WHERE role_id = $1 AND id = $2', [roleId, eventId])).rows[0] || null;
}
