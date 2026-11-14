// Manage policy, in the worker. Two jobs, one worker at a time (advisory lock):
//  1. Custom controls about roles and IAM users: each is a query; what matches gets a finding in the Findings inbox
//     (category 'custom'), what no longer matches is resolved. (Custom controls about ways in are the Trust map's.)
//  2. After a built-in control is turned off, on, or given another severity: every account is analysed again from what
//     is stored (no AWS calls), so findings and risk scores follow. The API already moved the open findings it could.
import { query, pool } from './db.js';
import { loadPolicy, matchIdentityRule } from './controls.js';
import { analyzeAccount } from './scanner/analyzeJob.js';

const LOCK = 727013;
const APPLIED = 'policy.applied';                             // app_settings: the built-in overrides the last full analysis used
const overSig = (policy) => [...policy.over].map(([id, o]) => `${id}:${o.severity}:${o.enabled}`).sort().join('|');

/** File the findings of every custom control about identities. Returns what changed. */
export async function syncCustom(policy = null) {
  policy = policy || await loadPolicy();
  const mine = policy.custom.filter((x) => x.target === 'identity');
  let opened = 0, updated = 0, resolved = 0;
  for (const cc of mine) {
    const control = `custom.${cc.id}`;
    const { ids, errors } = await matchIdentityRule(cc.rule);
    if (errors.length) continue;                              // a rule this version cannot read: leave its findings as they are
    const up = await query(
      `INSERT INTO flags(role_id, category, key, title, actions, resources, reason, evidence, suggestion, suggested_resources, severity, control, status, updated_at)
       SELECT r, 'custom', $2, $3, '{}', '{}', $4, $5, $6, '{}', $7, $8, 'open', now() FROM unnest($1::uuid[]) AS x(r)
       ON CONFLICT (role_id, category, key) DO UPDATE SET title=EXCLUDED.title, reason=EXCLUDED.reason, evidence=EXCLUDED.evidence, suggestion=EXCLUDED.suggestion,
         severity=EXCLUDED.severity, control=EXCLUDED.control, status='open', updated_at=now()
         WHERE (flags.title, flags.reason, flags.evidence, coalesce(flags.suggestion, ''), flags.severity, flags.status)
            IS DISTINCT FROM (EXCLUDED.title, EXCLUDED.reason, EXCLUDED.evidence, coalesce(EXCLUDED.suggestion, ''), EXCLUDED.severity, 'open')
       RETURNING (xmax = 0) AS inserted`,
      [ids, cc.id, cc.name, cc.description || 'Matches a custom control of this workspace.', `Rule: ${cc.rule}`.slice(0, 2000), cc.remediation || null, cc.severity, control]);
    opened += up.rows.filter((r) => r.inserted).length; updated += up.rows.filter((r) => !r.inserted).length;
    resolved += (await query(`UPDATE flags SET status='resolved', updated_at=now() WHERE category='custom' AND key=$1 AND status='open' AND NOT (role_id = ANY($2::uuid[]))`, [cc.id, ids])).rowCount;
  }
  // controls removed, turned off, or no longer about identities
  resolved += (await query(`UPDATE flags SET status='resolved', updated_at=now() WHERE category='custom' AND status='open' AND NOT (key = ANY($1::text[]))`, [mine.map((x) => x.id)])).rowCount;
  return { opened, updated, resolved, controls: mine.length };
}

let lastKey = null, lastAt = 0;
/** One pass. Returns what it did, or null when another worker holds the lock. */
export async function policyTick({ log = () => {}, force = false, alive = () => {} } = {}) {
  const client = await pool.connect();
  try {
    if (!(await client.query('SELECT pg_try_advisory_lock($1) AS ok', [LOCK])).rows[0].ok) return null;
    try {
      const policy = await loadPolicy();
      const out = { reanalysed: 0 };
      // built-in controls changed since the last full analysis: analyse every account again
      const want = overSig(policy);
      const applied = (await query('SELECT value FROM app_settings WHERE key = $1', [APPLIED])).rows[0]?.value?.over ?? '';
      if (want !== applied) {
        const accounts = (await query(`SELECT id, name FROM cloud_accounts WHERE status <> 'planned' ORDER BY name`)).rows;
        for (const a of accounts) {
          try { await analyzeAccount(a.id, { alive }); out.reanalysed++; } catch (e) { log('warn', 'policy: account not analysed again', { account: a.name, error: e.message }); }
          // someone changed the policy again meanwhile: stop, the next pass starts over with it
          if (overSig(await loadPolicy()) !== want) { log('info', 'policy changed during re-analysis; starting over next pass'); return out; }
        }
        await query(`INSERT INTO app_settings(key, value, updated_at) VALUES ($1, $2, now()) ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now()`, [APPLIED, JSON.stringify({ over: want })]);
        log('info', 'policy applied: accounts analysed again', { accounts: out.reanalysed });
      }
      // custom controls: when they or the analysis changed, and every ten minutes anyway
      const key = `${policy.sig}|${(await query('SELECT max(analyzed_at) AS t, count(*) AS n FROM roles WHERE deleted_at IS NULL')).rows.map((r) => `${r.t?.getTime?.() ?? ''}:${r.n}`)[0]}`;
      if (force || key !== lastKey || Date.now() - lastAt > 600_000) {
        Object.assign(out, await syncCustom(policy));
        lastKey = key; lastAt = Date.now();
        if (out.opened || out.resolved) log('info', 'custom controls filed', out);
      }
      return out;
    } finally { await client.query('SELECT pg_advisory_unlock($1)', [LOCK]); }
  } finally { client.release(); }
}
