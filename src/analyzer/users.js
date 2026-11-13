// What makes an IAM user risky beyond its permissions: its credentials. Long-lived access keys that are old, unused
// or doubled; a console password with no MFA, or one nobody uses. Pure: the analysis passes the stored facts in.
// The two ages are workspace settings (Configuration → Risk thresholds); callers pass them in (keyRules() in config.js).
const DAY = 864e5;
export const DEFAULT_KEY_RULES = { rotateDays: 90, staleDays: 90 };

const age = (d, now) => (d ? Math.floor((now - new Date(d).getTime()) / DAY) : null);

/** Findings for one user, each with the points it adds to the risk score. */
export function userFindings({ details, keys, now = Date.now(), rules = DEFAULT_KEY_RULES }) {
  const { rotateDays, staleDays } = rules;
  const out = [];
  const add = (points, id, text) => out.push({ points, id, text });
  const active = keys.filter((k) => k.status === 'Active' && !k.deleted_at);
  for (const k of active) {
    const a = age(k.created_at, now);
    const used = [k.last_used_at, k.trail_last_seen].filter(Boolean).map((d) => new Date(d).getTime()).sort((x, y) => y - x)[0] || null;
    const idle = used ? age(used, now) : null;
    if (a != null && a > Math.max(365, rotateDays)) add(25, 'key-old', `Access key ${k.key_id} is ${a} days old: rotate it (every ${rotateDays} days), or move the workload to a role`);
    else if (a != null && a > rotateDays) add(15, 'key-old', `Access key ${k.key_id} is ${a} days old: rotate it`);
    if (!used && a != null && a > 14) add(10, 'key-unused', `Access key ${k.key_id} has never been used: deactivate it`);
    else if (idle != null && idle > staleDays) add(10, 'key-unused', `Access key ${k.key_id} unused for ${idle} days: deactivate it`);
  }
  if (active.length > 1) add(5, 'key-two', 'Two active access keys: one should be retired after rotation');
  if (details?.password_enabled) {
    const mfa = (details.mfa || []).length > 0;
    if (!mfa) add(30, 'console-no-mfa', 'Console password without MFA');
    const idle = details.password_last_used ? age(details.password_last_used, now) : null;
    if (idle == null && age(details.password_created, now) > 30) add(10, 'password-unused', 'Console password never used: remove it');
    else if (idle != null && idle > staleDays) add(10, 'password-unused', `Console password unused for ${idle} days: remove it`);
    if (active.length) add(5, 'console-and-keys', 'Both a console password and access keys: one person or one workload, not both');
  }
  return out;
}

/** Fold a user's credential findings into the analysis result: same thresholds as roles (50 High, 25 Medium). */
export function withUserRisk(result, findings) {
  const score = result.riskScore + findings.reduce((n, f) => n + f.points, 0);
  return { ...result, riskScore: score, risk: score >= 50 ? 'High' : score >= 25 ? 'Medium' : 'Low', riskReasons: [...findings.map((f) => f.text), ...result.riskReasons] };
}
