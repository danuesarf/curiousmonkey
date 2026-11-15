// Manage policy, in the worker. Two jobs, one worker at a time (advisory lock):
//  1. Controls that are rules about identities, built-in and custom: what a rule matches gets a finding (AWS: the
//     Findings inbox; Google Cloud: the principal's page); what no longer matches is closed. (Rules about ways in are
//     the Trust map's.)
//  2. After a built-in control is turned off, on, or given another severity: every account is analysed again from what
//     is stored (no AWS calls), so findings and risk scores follow. The API already moved the open findings it could.
import { query, pool } from './db.js';
import { loadPolicy } from './controls.js';
import { matchIdentityRule, loadGcpPrincipals } from './identityRules.js';
import { analyzeAccount } from './scanner/analyzeJob.js';

const LOCK = 727013;
const APPLIED = 'policy.applied';                             // app_settings: the built-in overrides the last full analysis used
// (rules are filed by syncRules, not by the analysis, so a change to one needs no analysis)
const overSig = (policy) => [...policy.over].filter(([id]) => !id.startsWith('rule.')).map(([id, o]) => `${id}:${o.severity}:${o.enabled}`).sort().join('|');

/**
 * File the findings of every control that is a rule about identities, built-in and custom. In AWS a match is a finding
 * in the Findings inbox; in Google Cloud it is added to what the principal's page lists. What no longer matches is closed.
 */
export async function syncRules(policy = null) {
  policy = policy || await loadPolicy();
  const mine = policy.rules.filter((x) => x.target === 'identity');
  const gcp = mine.length ? await loadGcpPrincipals() : [];
  const reasons = new Map();                                  // Google Cloud principal -> what the rules say about it
  let opened = 0, updated = 0, resolved = 0;
  const done = [];
  for (const cc of mine) {
    const m = await matchIdentityRule(cc.rule, gcp);
    if (m.errors.length) continue;                            // a rule this version cannot read: leave its findings as they are
    done.push(cc.id);
    const up = await query(
      `INSERT INTO flags(role_id, category, key, title, actions, resources, reason, evidence, suggestion, suggested_resources, severity, control, status, updated_at)
       SELECT r, $2, $3, $4, '{}', '{}', $5, $6, $7, '{}', $8, $3, 'open', now() FROM unnest($1::uuid[]) AS x(r)
       ON CONFLICT (role_id, category, key) DO UPDATE SET title=EXCLUDED.title, reason=EXCLUDED.reason, evidence=EXCLUDED.evidence, suggestion=EXCLUDED.suggestion,
         severity=EXCLUDED.severity, control=EXCLUDED.control, status='open', updated_at=now()
         WHERE (flags.title, flags.reason, flags.evidence, coalesce(flags.suggestion, ''), flags.severity, flags.status)
            IS DISTINCT FROM (EXCLUDED.title, EXCLUDED.reason, EXCLUDED.evidence, coalesce(EXCLUDED.suggestion, ''), EXCLUDED.severity, 'open')
       RETURNING (xmax = 0) AS inserted`,
      [m.aws, cc.source === 'custom' ? 'custom' : 'rule', cc.id, cc.name, cc.description || 'Matches a rule of this workspace\'s policy.', `Rule: ${cc.rule}`.slice(0, 2000), cc.remediation || null, cc.severity]);
    opened += up.rows.filter((r) => r.inserted).length; updated += up.rows.filter((r) => !r.inserted).length;
    resolved += (await query(`UPDATE flags SET status='resolved', updated_at=now() WHERE category IN ('custom', 'rule') AND key=$1 AND status='open' AND NOT (role_id = ANY($2::uuid[]))`, [cc.id, m.aws])).rowCount;
    for (const id of m.gcp) {
      if (!reasons.has(id)) reasons.set(id, []);
      reasons.get(id).push({ id: cc.id, severity: cc.severity, title: cc.name, detail: cc.description || `Matches the rule: ${cc.rule}`, rule: true });
    }
  }
  // rules removed, turned off, or no longer about identities (those that could not be read keep theirs)
  const unread = mine.filter((x) => !done.includes(x.id)).map((x) => x.id);
  resolved += (await query(`UPDATE flags SET status='resolved', updated_at=now() WHERE category IN ('custom', 'rule') AND status='open' AND NOT (key = ANY($1::text[]))`, [[...done, ...unread]])).rowCount;
  // Google Cloud: only the principals whose rule matches changed are written
  let gcpChanged = 0;
  for (const p of gcp) {
    const had = p.reasons.filter((r) => r.rule), want = reasons.get(p.id) || [];
    const same = (xs) => xs.map((x) => `${x.id}|${x.severity}|${x.title}|${x.detail}`).sort().join('\n');    // jsonb reorders keys
    if (same(had) === same(want)) continue;
    await query('UPDATE gcp_principals SET risk_reasons = $2 WHERE id = $1', [p.id, JSON.stringify([...p.reasons.filter((r) => !r.rule), ...want])]);
    gcpChanged++;
  }
  return { opened, updated, resolved, gcpChanged, rules: mine.length };
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
      const key = `${policy.sig}|${(await query(`SELECT (SELECT max(analyzed_at) FROM roles WHERE deleted_at IS NULL) AS t, (SELECT count(*) FROM roles WHERE deleted_at IS NULL) AS n,
        (SELECT max(analyzed_at) FROM gcp_principals) AS g`)).rows.map((r) => `${r.t?.getTime?.() ?? ''}:${r.n}:${r.g?.getTime?.() ?? ''}`)[0]}`;
      if (force || key !== lastKey || Date.now() - lastAt > 600_000) {
        Object.assign(out, await syncRules(policy));
        lastKey = key; lastAt = Date.now();
        if (out.opened || out.resolved || out.gcpChanged) log('info', 'policy rules filed', out);
      }
      return out;
    } finally { await client.query('SELECT pg_advisory_unlock($1)', [LOCK]); }
  } finally { client.release(); }
}
