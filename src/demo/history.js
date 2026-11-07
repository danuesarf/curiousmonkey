// Demo only: invent the past, so the radar's trails, trends and pings can be seen without waiting a month.
// Each role gets a snapshot for each of the last 35 days, drifting from an invented starting point to where it
// stands today; a few roles drift a lot (outward or inward). A handful of changes are recorded from real roles.
import { query } from '../db.js';
import { snapshotAndDiff } from '../radarHistory.js';

export async function demoHistory() {
  const accounts = (await query('SELECT id, name FROM cloud_accounts')).rows;
  let snaps = 0, changes = 0;
  for (const a of accounts) {
    await snapshotAndDiff(a.id);                     // today, from the real analysis
    const roles = (await query(`SELECT * FROM role_snapshots WHERE account_id=$1 AND day=current_date`, [a.id])).rows;
    let seed = [...a.id].reduce((x, c) => (x * 31 + c.charCodeAt(0)) % 2147483647, 11);
    const rnd = () => { seed = (seed * 16807) % 2147483647; return (seed - 1) / 2147483646; };
    for (const r of roles) {
      const d = rnd();
      const drift = d < 0.12 ? 0.15 + rnd() * 0.2 : d < 0.24 ? -(0.1 + rnd() * 0.2) : (rnd() - 0.5) * 0.04;   // share of granted
      for (let ago = 35; ago >= 1; ago--) {
        const k = ago / 35;
        const unused = Math.max(0, Math.min(r.granted, Math.round(r.unused - drift * k * r.granted)));
        const used = Math.max(0, Math.min(r.granted - unused, Math.round(r.used * (1 - 0.3 * k))));
        await query(`INSERT INTO role_snapshots(role_id, account_id, day, granted, used, unused, unconfirmed, calls, denied, active90)
                     VALUES ($1,$2,current_date - $3::int,$4,$5,$6,$7,$8,$9,$10) ON CONFLICT DO NOTHING`,
          [r.role_id, a.id, ago, r.granted, used, unused, Math.max(0, r.granted - used - unused), Math.round(Number(r.calls) * (1 - k)), 0, r.active90]);
        snaps++;
      }
    }
    const pick = (await query(`SELECT r.id, r.name, r.granted_count FROM roles r WHERE r.account_id=$1 AND r.deleted_at IS NULL ORDER BY r.risk_score DESC, r.name LIMIT 6`, [a.id])).rows;
    const callers = (await query(`SELECT DISTINCT ON (p.role_id) p.role_id, p.display, p.via FROM principals p JOIN roles r ON r.id=p.role_id WHERE r.account_id=$1 AND p.kind <> 'session'`, [a.id])).rows;
    const ev = [
      pick[0] && callers.find((c) => c.role_id === pick[0].id) && ['new-caller', 'high', `New caller entered ${pick[0].name}`, `${callers.find((c) => c.role_id === pick[0].id).display} · first time seen`, pick[0].id, 25],
      pick[1] && ['denied', 'high', `First denied calls from ${pick[1].name}`, '14 denied so far', pick[1].id, 70],
      pick[2] && ['grew', 'warn', `${pick[2].name} gained permissions`, `${Math.round(pick[2].granted_count * 0.6)} → ${pick[2].granted_count} permissions`, pick[2].id, 160],
      pick[3] && ['dead', 'info', `${pick[3].name} made no calls in 90 days`, `${pick[3].granted_count} permissions held`, pick[3].id, 600],
      pick[4] && ['cleaned', 'good', `${pick[4].name} was trimmed`, `${pick[4].granted_count * 9} → ${pick[4].granted_count} permissions`, pick[4].id, 1500],
    ].filter(Boolean);
    // only some accounts change on a given day: pings should stand out, not cover the dish
    const keep = rnd() < 0.35 ? ev.filter(() => rnd() < 0.45).slice(0, 2) : [];
    for (const [kind, sev, title, detail, roleId, minsAgo] of keep) {
      const r = await query(`INSERT INTO changes(account_id, role_id, kind, severity, title, detail, dedupe, at) VALUES ($1,$2,$3,$4,$5,$6,$7, now() - make_interval(mins => $8))
                             ON CONFLICT (dedupe) DO NOTHING RETURNING id`, [a.id, roleId, kind, sev, title, detail, `demo:${kind}:${roleId}`, minsAgo]);
      changes += r.rowCount;
    }
  }
  return `demo history: ${snaps} snapshots, ${changes} changes across ${accounts.length} accounts`;
}
