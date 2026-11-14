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
  const events = await demoIdentityEvents();
  return `demo history: ${snaps} snapshots, ${changes} changes, ${events} identity events across ${accounts.length} accounts`;
}

/**
 * Demo only: a few past changes on the riskiest roles, so the History tab has something to show. Built from each
 * role's real current documents: the "before" is the document with its last statement taken out.
 */
async function demoIdentityEvents() {
  const roles = (await query(`SELECT DISTINCT ON (r.account_id) r.id, r.name, r.trust_policy FROM roles r
                                WHERE r.deleted_at IS NULL AND r.kind <> 'iam-user' ORDER BY r.account_id, r.risk_score DESC, r.name`)).rows;
  let n = 0;
  const add = async (roleId, daysAgo, kind, title, detail) => {
    await query(`INSERT INTO identity_events(role_id, at, kind, title, detail) VALUES ($1, now() - make_interval(days => $2), $3, $4, $5)`, [roleId, daysAgo, kind, title, JSON.stringify(detail)]);
    n++;
  };
  for (const r of roles) {
    if ((await query('SELECT 1 FROM identity_events WHERE role_id=$1 LIMIT 1', [r.id])).rowCount) continue;
    const pol = (await query(`SELECT name, kind, arn, aws_managed, document FROM role_policies WHERE role_id=$1 ORDER BY aws_managed, kind, name`, [r.id])).rows;
    // a policy of their own that grew: "before" has its last statement out, or its first action only
    const own = pol.find((p) => !p.aws_managed && p.document?.Statement);
    if (own) {
      const st = [].concat(own.document.Statement);
      const narrower = (s) => ({ ...s, Action: [].concat(s.Action || 's3:GetObject').slice(0, 1).map((a) => (a === '*' ? 's3:GetObject' : a)) });
      const before = { ...own.document, Statement: st.length > 1 ? st.slice(0, -1) : [narrower(st[0])] };
      await add(r.id, 12, 'policy-changed', `${own.kind === 'inline' ? 'Inline' : 'Managed'} policy ${own.name} changed`, { name: own.name, policyKind: own.kind, arn: own.arn, awsManaged: false, before, after: own.document });
    }
    await add(r.id, 11, 'risk', 'Risk rose: Medium → High', { from: 'Medium', to: 'High', reasons: ['Grants more than it uses'] });
    const managed = pol.find((p) => p.aws_managed);
    if (managed) await add(r.id, 40, 'policy-added', `Managed policy ${managed.name} attached`, { name: managed.name, policyKind: 'managed', arn: managed.arn, awsManaged: true, after: managed.document });
    const st = r.trust_policy?.Statement;
    if (Array.isArray(st) && st.length) {
      await add(r.id, 26, 'trust-changed', 'Trust policy changed', { name: 'Trust policy', before: { ...r.trust_policy, Statement: st.slice(0, 1).map((x) => ({ ...x, Condition: { StringEquals: { 'sts:ExternalId': 'demo-legacy' } } })) }, after: r.trust_policy });
    }
  }
  return n;
}
