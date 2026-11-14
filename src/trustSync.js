// Files the Trust map's findings where reviewers work (the Findings inbox, decisions, alerts, access reviews), and tells
// the change feed about new ways in and guards taken off. One rule set: the findings are the Trust map's own (trustmap.js),
// worked out with the whole estate in view (which accounts are yours, which Identity Center is the organisation's).
// High and medium findings are filed; low ones (a Bitbucket step wildcard, your own account with MFA) stay on the map.
// Runs in the worker every minute; an advisory lock lets one worker at a time do it, and it only writes when the ways
// in were worked out again since the last run.
import { query, pool } from './db.js';
import { trustIndex, flagKey } from './trustmap.js';

const LOCK = 727011;
const SUGGEST = {
  public: 'Name the principals that need this role, or add a condition such as aws:PrincipalOrgID.',
  'not-principal': 'Replace NotPrincipal with the principals that should get in.',
  'account-root': 'Name the roles that come in (aws:PrincipalArn), or trust them directly instead of the whole account.',
  'external-no-externalid': 'Ask the third party for its ExternalId and require it (sts:ExternalId).',
  'oidc-no-sub': 'Add a :sub condition for the repository, branch, service account or workload that should get in.',
  'oidc-broad-sub': 'Narrow the :sub condition to the repositories and branches (or service accounts) that use this role.',
  'oidc-no-aud': 'Add an :aud condition (sts.amazonaws.com for most providers).',
  'cognito-no-aud': 'Add cognito-identity.amazonaws.com:aud with your identity pool ID.',
  'cognito-guest': 'Keep the role to what an anonymous guest needs, or require amr = authenticated.',
  'cognito-no-amr': 'Add cognito-identity.amazonaws.com:amr = authenticated.',
  'saml-no-aud': 'Add SAML:aud = https://signin.aws.amazon.com/saml.',
  'idc-multiple': 'Check who runs the other Identity Center and remove its AWSSSO provider if it is not yours.',
  'idc-other': 'Check whose Identity Center this is; remove its provider if it is not yours.',
  'iam-user': 'Trust a role instead of an IAM user.',
  'deleted-principal': 'Remove the statement: the identity it named no longer exists.',
  'broad-action': 'Allow sts:AssumeRole (and only the sts: actions needed) instead of sts:* or *.',
};
let lastSynced = 0;

/** One pass. Returns what it wrote, or null when there was nothing new to do. */
export async function trustTick({ log = () => {}, force = false } = {}) {
  const client = await pool.connect();
  try {
    const got = (await client.query('SELECT pg_try_advisory_lock($1) AS ok', [LOCK])).rows[0].ok;
    if (!got) return null;
    try {
      const ix = await trustIndex();
      if (!force && ix.at.getTime() <= lastSynced) return null;
      const out = { ...(await fileFindings(ix)), ...(await feedChanges(ix)) };
      lastSynced = ix.at.getTime();
      if (out.opened || out.resolved || out.changes) log('info', 'trust findings filed', out);
      return out;
    } finally { await client.query('SELECT pg_advisory_unlock($1)', [LOCK]); }
  } finally { client.release(); }
}

async function fileFindings(ix) {
  const rows = [];
  for (const e of ix.edges) {
    if (e.expected) continue;                                 // expected trust: its findings are not filed
    for (const f of e.findings) {
      if (f.severity !== 'high' && f.severity !== 'medium') continue;   // low ones stay on the map, out of the inbox
      rows.push({ role: e.roleId, key: flagKey(e, f.id), title: f.title, severity: f.severity, reason: f.detail || f.title,
        evidence: `${e.source} → ${e.role} (${e.account}), statement ${e.sid || e.statement + 1}: ${e.principal}${e.conditions.length ? ` · ${e.conditions.join('; ')}` : ' · no conditions'}`.slice(0, 2000),
        suggestion: SUGGEST[f.id] || null });
    }
  }
  const cols = (k) => rows.map((r) => r[k]);
  // new or changed findings; an unchanged one is left alone, so alerts and "updated" stay meaningful
  const up = await query(
    `INSERT INTO flags(role_id, category, key, title, actions, resources, reason, evidence, suggestion, suggested_resources, severity, status, updated_at)
     SELECT r, 'trust', k, t, '{}', '{}', re, ev, sg, '{}', sv, 'open', now()
       FROM unnest($1::uuid[], $2::text[], $3::text[], $4::text[], $5::text[], $6::text[], $7::text[]) AS x(r, k, t, re, ev, sg, sv)
     ON CONFLICT (role_id, category, key) DO UPDATE SET title=EXCLUDED.title, reason=EXCLUDED.reason, evidence=EXCLUDED.evidence, suggestion=EXCLUDED.suggestion,
       severity=EXCLUDED.severity, status='open', updated_at=now()
       WHERE (flags.title, flags.reason, flags.evidence, coalesce(flags.suggestion, ''), flags.severity, flags.status)
          IS DISTINCT FROM (EXCLUDED.title, EXCLUDED.reason, EXCLUDED.evidence, coalesce(EXCLUDED.suggestion, ''), EXCLUDED.severity, 'open')
     RETURNING (xmax = 0) AS inserted`,
    [cols('role'), cols('key'), cols('title'), cols('reason'), cols('evidence'), cols('suggestion'), cols('severity')]);
  // gone from the trust policy, or now expected: resolved (a decision stays with it, should it come back)
  const res = await query(
    `UPDATE flags f SET status='resolved', updated_at=now()
      WHERE f.category = 'trust' AND f.status = 'open'
        AND NOT EXISTS (SELECT 1 FROM unnest($1::uuid[], $2::text[]) AS x(r, k) WHERE x.r = f.role_id AND x.k = f.key)`, [cols('role'), cols('key')]);
  return { opened: up.rows.filter((r) => r.inserted).length, updated: up.rows.filter((r) => !r.inserted).length, resolved: res.rowCount };
}

// new ways in and guards taken off in the last two days, once each, as Radar changes (the bell, alerts)
async function feedChanges(ix) {
  const cutoff = Date.now() - 2 * 864e5;
  const rows = [];
  for (const e of ix.edges) {
    const c = e.change;
    if (!c || e.group === 'service' || new Date(c.at).getTime() < cutoff) continue;
    const weakened = c.kind === 'weakened';
    const sev = e.worst === 'high' ? 'high' : e.worst === 'medium' || weakened ? 'warn' : 'info';
    rows.push({ account: e.accountId, role: e.roleId, kind: weakened ? 'trust-weakened' : 'new-trust', severity: sev,
      title: weakened ? `${c.guards.join(', ')} taken off ${e.role}'s trust in ${e.source}` : `${e.source} can now get into ${e.role}`,
      detail: `${e.account} · statement ${e.sid || e.statement + 1} · ${e.principal}${e.conditions.length ? ` · ${e.conditions.join('; ')}` : ' · no conditions'}`.slice(0, 1000),
      dedupe: `trust:${weakened ? 'w' : 'n'}:${e.roleId}:${e.statement}:${e.principal}:${new Date(c.at).toISOString()}`.slice(0, 500), at: c.at });
  }
  if (!rows.length) return { changes: 0 };
  const cols = (k) => rows.map((r) => r[k]);
  const r = await query(
    `INSERT INTO changes(account_id, role_id, kind, severity, title, detail, dedupe, at)
     SELECT * FROM unnest($1::uuid[], $2::uuid[], $3::text[], $4::text[], $5::text[], $6::text[], $7::text[], $8::timestamptz[])
     ON CONFLICT (dedupe) DO NOTHING`,
    [cols('account'), cols('role'), cols('kind'), cols('severity'), cols('title'), cols('detail'), cols('dedupe'), cols('at')]);
  return { changes: r.rowCount };
}
