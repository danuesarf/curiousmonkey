// Where each role was (daily snapshots) and what changed that matters (pings).
// Snapshots are only taken once an account's history is fully read: before that, "never called" falls
// as older calls arrive, which would look like a cleanup that never happened.
import { query, tx } from './db.js';

const ADMIN = 15000;
const today = () => new Date().toISOString().slice(0, 10);

/** Compare the account with its last snapshot, record the changes, then take today's snapshot. */
export async function snapshotAndDiff(accountId, day = today()) {
  const roles = (await query(
    `SELECT r.id, r.name, r.granted_count AS granted, r.used_count AS used, r.unused_count AS unused, r.unconfirmed_count AS unconfirmed,
            coalesce(a.calls,0)::bigint AS calls, coalesce(a.denied,0)::bigint AS denied, coalesce(a.active90,false) AS active90
       FROM roles r
       LEFT JOIN (SELECT role_id, sum(count) calls, sum(error_count) denied, bool_or(count > 0 AND day >= current_date - 90) active90
                    FROM activity_daily GROUP BY role_id) a ON a.role_id = r.id
      WHERE r.account_id=$1 AND r.deleted_at IS NULL`, [accountId])).rows;
  const prev = new Map((await query(
    `SELECT DISTINCT ON (role_id) * FROM role_snapshots WHERE account_id=$1 AND day < $2 ORDER BY role_id, day DESC`, [accountId, day])).rows.map((s) => [s.role_id, s]));
  const lastDay = (await query('SELECT max(day) AS d FROM role_snapshots WHERE account_id=$1 AND day < $2', [accountId, day])).rows[0].d;

  const out = [];
  if (lastDay) {                       // nothing to compare against on the first day
    const created = [];
    for (const r of roles) {
      const p = prev.get(r.id);
      if (!p) { created.push(r); continue; }
      const n = (x) => Number(x);
      if (r.granted >= ADMIN && p.granted < ADMIN) {
        out.push({ role: r, kind: 'grew', severity: 'high', title: `${r.name} gained admin-level permissions`, detail: `${n(p.granted).toLocaleString('en-US')} → ${r.granted.toLocaleString('en-US')} permissions`, key: `grew:${r.id}:${day}` });
      } else if (r.granted > p.granted * 1.2 && r.granted - p.granted >= 10) {
        out.push({ role: r, kind: 'grew', severity: 'warn', title: `${r.name} gained permissions`, detail: `${n(p.granted).toLocaleString('en-US')} → ${r.granted.toLocaleString('en-US')} permissions`, key: `grew:${r.id}:${day}` });
      }
      if (r.granted < p.granted * 0.7 && p.granted - r.granted >= 10) {
        out.push({ role: r, kind: 'cleaned', severity: 'good', title: `${r.name} was trimmed`, detail: `${n(p.granted).toLocaleString('en-US')} → ${r.granted.toLocaleString('en-US')} permissions`, key: `cleaned:${r.id}:${day}` });
      }
      if (n(p.denied) === 0 && n(r.denied) > 0) {
        out.push({ role: r, kind: 'denied', severity: 'high', title: `First denied calls from ${r.name}`, detail: `${n(r.denied).toLocaleString('en-US')} denied so far`, key: `denied:${r.id}` });
      }
      if (p.active90 && !r.active90) {
        out.push({ role: r, kind: 'dead', severity: 'info', title: `${r.name} made no calls in 90 days`, detail: `${r.granted.toLocaleString('en-US')} permissions held`, key: `dead:${r.id}:${day}` });
      }
    }
    if (created.length) {
      out.push({ role: created.length === 1 ? created[0] : null, kind: 'new-role', severity: 'info',
        title: created.length === 1 ? `Role created: ${created[0].name}` : `${created.length} roles created`,
        detail: created.slice(0, 5).map((r) => r.name).join(', ') + (created.length > 5 ? '…' : ''), key: `new-role:${accountId}:${day}` });
    }
    const unk = (await query(
      `SELECT u.raw_action, u.count FROM unmapped_events u
        WHERE u.account_id=$1 AND u.first_seen > $2::date
          AND NOT EXISTS (SELECT 1 FROM event_action_map m WHERE m.raw_action=u.raw_action AND m.status='accepted')`, [accountId, lastDay])).rows;
    for (const u of unk) out.push({ role: null, kind: 'unidentified', severity: 'warn', title: 'New event name not identified', detail: u.raw_action, key: `unid:${accountId}:${u.raw_action}` });
  }

  await tx(async (c) => {
    for (const ch of out) {
      await c.query(`INSERT INTO changes(account_id, role_id, kind, severity, title, detail, dedupe) VALUES ($1,$2,$3,$4,$5,$6,$7) ON CONFLICT (dedupe) DO NOTHING`,
        [accountId, ch.role?.id || null, ch.kind, ch.severity, ch.title, ch.detail, ch.key]);
    }
    if (roles.length) {
      await c.query(
        `INSERT INTO role_snapshots(role_id, account_id, day, granted, used, unused, unconfirmed, calls, denied, active90)
         SELECT id, $1, $2, g, u, un, uc, ca, de, ac FROM unnest($3::uuid[], $4::int[], $5::int[], $6::int[], $7::int[], $8::bigint[], $9::bigint[], $10::bool[])
              AS t(id, g, u, un, uc, ca, de, ac)
         ON CONFLICT (role_id, day) DO UPDATE SET granted=EXCLUDED.granted, used=EXCLUDED.used, unused=EXCLUDED.unused, unconfirmed=EXCLUDED.unconfirmed,
           calls=EXCLUDED.calls, denied=EXCLUDED.denied, active90=EXCLUDED.active90`,
        [accountId, day, roles.map((r) => r.id), roles.map((r) => r.granted), roles.map((r) => r.used), roles.map((r) => r.unused), roles.map((r) => r.unconfirmed),
          roles.map((r) => r.calls), roles.map((r) => r.denied), roles.map((r) => r.active90)]);
    }
    await c.query(`DELETE FROM changes WHERE at < now() - interval '120 days'`);
    await c.query(`DELETE FROM role_snapshots WHERE day < current_date - 400`);
  });
  return out.length;
}

/** A caller seen entering a role for the first time, once history is complete: the most important ping. */
export async function recordNewCaller(c, accountId, role, p, via, at) {
  const roleAcct = role.arn?.split(':')[4];
  const callerAcct = p.key.startsWith('role:') ? p.key.split(':')[1] : (p.key.match(/arn:aws:iam::(\d{12})/) || [])[1];
  const external = callerAcct && roleAcct && callerAcct !== roleAcct;
  const severity = p.kind === 'user' || external ? 'high' : 'warn';
  await c.query(`INSERT INTO changes(account_id, role_id, kind, severity, title, detail, dedupe, at) VALUES ($1,$2,'new-caller',$3,$4,$5,$6,$7) ON CONFLICT (dedupe) DO NOTHING`,
    [accountId, role.id, severity, `New caller entered ${role.name}`, `${p.display}${via ? ` · ${via}` : ''}${external ? ' · from another account' : ''}`, `caller:${role.id}:${p.key}`, at]);
}
