import { query } from './db.js';

/** Append-only record of who did what. Failures to write must never break the action itself. */
export async function audit(req, action, target = {}, detail = null) {
  try {
    await query(`INSERT INTO audit_log(actor_id, actor_email, action, target_type, target_id, detail, ip) VALUES ($1,$2,$3,$4,$5,$6,$7)`,
      [req?.user?.id ?? null, req?.user?.email ?? detail?.email ?? null, action, target.type ?? null, target.id ?? null, detail ? JSON.stringify(detail) : null, req?.ip ?? null]);
  } catch (e) { console.error(JSON.stringify({ level: 'error', msg: 'audit write failed', error: e.message })); }
}
