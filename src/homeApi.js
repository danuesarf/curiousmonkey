// Home: the page after sign-in. It answers "what should I do first?" with a short ranked list, each item opening the
// page that does it, plus the member's queue as counts and the estate at a glance.
//
// The list is worked out here, on the server, so its wording lives in one place: Home shows it to a person, the wall
// view shows the team's version, and the "what to do first" digest (an alert rule, see alerts.js) posts the same list.
//
// Who sees an item depends on what they can do (permissions) and which review team they are on. A team's version (wall,
// digest) is everything that team could act on, with no personal snoozes.
import { query } from './db.js';
import { can, scopeSql } from './auth/rbac.js';
import { historyFor } from './history.js';
import { keyRules } from './config.js';
import { ssoView } from './sso.js';
import { cached, scopeKey } from './cache.js';

export const TIERS = ['blocking', 'urgent', 'hygiene', 'setup'];
export const TIER_LABEL = { blocking: 'Blocking', urgent: 'Urgent', hygiene: 'Hygiene', setup: 'Setup' };
export const TEAM_LABEL = { infrasec: 'Infrastructure Security', infosec: 'Information Security' };
const SNOOZE_DAYS = { setup: 30, default: 7 };
const n = (x) => Number(x || 0);
const plural = (k, one, many = `${one}s`) => (k === 1 ? one : many);
const fmt = (x) => Number(x || 0).toLocaleString('en-US');
const day = (d) => (d ? new Date(d).toLocaleDateString('en-GB', { day: 'numeric', month: 'short', timeZone: 'UTC' }) : '');

/**
 * Who the list is for. A person: their scope, team and permissions. A team (wall view, digest): every account or the
 * ones named, the team (or none: the whole workspace), and every permission (the team could act on all of it).
 */
export const forUser = (user) => ({ scopeUser: user, team: user.team || null, can: (p) => can(user, p), userId: user.id, role: user.role });
export const forTeam = ({ team = null, accounts = null } = {}) => ({ scopeUser: { scope_accounts: accounts?.length ? accounts : null }, team, can: () => true, userId: null, role: 'team' });

// a team's own roles: the ones it reviews, and the ones both teams must
const mineSql = (team, params, col = 'r') => { if (!team) return 'TRUE'; params.push(team); return `(${col}.reviewer_team = $${params.length} OR ${col}.requires_both)`; };

/** Drafts this team (or, without a team, any team) still has to approve: current, passing their checks, on an account whose history is read. */
export async function waitingDrafts(scopeUser, team, completeIds) {
  if (!completeIds.length) return [];
  const p = [completeIds];
  const rows = (await query(`
    SELECT rec.id, rec.created_at, rec.source, rec.summary, (rec.diff->>'removedCount')::int AS removed, (rec.diff->>'granted')::int AS granted,
           r.id AS role_id, r.name AS role_name, r.kind AS role_kind, r.risk, r.reviewer_team, r.requires_both,
           a.id AS account_id, a.name AS account_name, a.environment,
           coalesce((SELECT array_agg(x.team ORDER BY x.team) FROM recommendation_approvals x WHERE x.recommendation_id = rec.id), '{}') AS approved_by
      FROM recommendations rec JOIN roles r ON r.id = rec.role_id JOIN cloud_accounts a ON a.id = r.account_id
     WHERE rec.status = 'draft' AND rec.analysis_hash = r.analysis_hash AND r.deleted_at IS NULL AND r.account_id = ANY($1::uuid[])
       AND NOT EXISTS (SELECT 1 FROM jsonb_array_elements(rec.checks) c WHERE c->>'status' = 'fail')
       AND ${scopeSql(scopeUser, 'r.account_id', p)}
     ORDER BY CASE r.risk WHEN 'High' THEN 0 WHEN 'Medium' THEN 1 ELSE 2 END, rec.created_at`, p)).rows;
  return rows.map((x) => {
    const required = x.requires_both ? ['infrasec', 'infosec'] : [x.reviewer_team].filter(Boolean);
    return { id: x.id, createdAt: x.created_at, source: x.source, summary: x.summary, removed: x.removed ?? null, granted: x.granted ?? null,
      role: { id: x.role_id, name: x.role_name, kind: x.role_kind, risk: x.risk }, account: { id: x.account_id, name: x.account_name, environment: x.environment },
      requiredTeams: required, approvedBy: x.approved_by, waitingFor: required.filter((t) => !x.approved_by.includes(t)) };
  }).filter((d) => d.waitingFor.length && (!team || d.waitingFor.includes(team)));
}

/** Everything the list and the page are built from, for one scope and team. Cached briefly: it is the same for everyone who shares both. */
async function facts(who) {
  const key = `home:${scopeKey(who.scopeUser)}:${who.team || '-'}`;
  return cached(key, async () => {
    const su = who.scopeUser;
    const ap = [];
    const accounts = (await query(`SELECT * FROM cloud_accounts a WHERE ${scopeSql(su, 'a.id', ap)} ORDER BY a.name`, ap)).rows;
    const live = accounts.filter((a) => a.status !== 'planned');
    const hist = await historyFor(live);
    const complete = live.filter((a) => hist.get(a.id).complete);
    const completeIds = complete.map((a) => a.id), liveIds = live.map((a) => a.id);
    const state = !live.length ? 'first-run' : complete.length < live.length ? 'reading' : 'steady';

    const fp = [completeIds]; const fScope = scopeSql(su, 'r.account_id', fp); const fMine = mineSql(who.team, fp);
    const kp = []; const kScope = scopeSql(su, 'r.account_id', kp);
    const [findings, findingsByAcct, drafts, reviews, keys, noMfa, failed, unk, ids, never, members, rulesN, lastReview, decided] = await Promise.all([
      // open findings with no decision, on accounts whose history is read (elsewhere they are provisional)
      query(`SELECT f.severity, count(*)::int n, count(*) FILTER (WHERE ${fMine})::int mine
               FROM flags f JOIN roles r ON r.id = f.role_id LEFT JOIN review_decisions d ON d.flag_id = f.id
              WHERE f.status = 'open' AND d.id IS NULL AND r.deleted_at IS NULL AND r.account_id = ANY($1::uuid[]) AND ${fScope} GROUP BY 1`, fp),
      query(`SELECT a.name, count(*)::int n FROM flags f JOIN roles r ON r.id = f.role_id JOIN cloud_accounts a ON a.id = r.account_id LEFT JOIN review_decisions d ON d.flag_id = f.id
              WHERE f.status = 'open' AND d.id IS NULL AND f.severity = 'high' AND r.deleted_at IS NULL AND r.account_id = ANY($1::uuid[]) AND ${fScope} AND ${fMine}
              GROUP BY a.name ORDER BY 2 DESC, 1 LIMIT 3`, fp),
      waitingDrafts(su, who.team, completeIds),
      query(`SELECT r.id, r.name, r.teams, r.account_ids, r.created_at, coalesce((SELECT array_agg(s.team) FROM access_review_signoffs s WHERE s.review_id = r.id), '{}') AS signed
               FROM access_reviews r WHERE r.status = 'open' ORDER BY r.created_at`),
      query(`SELECT count(*)::int total, count(*) FILTER (WHERE k.created_at < now() - make_interval(days => ${Number(keyRules().rotateDays) | 0}))::int old,
                    max(extract(epoch FROM now() - k.created_at) / 86400)::int oldest_days,
                    (array_agg(r.name ORDER BY k.created_at))[1] AS oldest_user
               FROM iam_access_keys k JOIN roles r ON r.id = k.role_id
              WHERE k.status = 'Active' AND k.deleted_at IS NULL AND r.deleted_at IS NULL AND ${kScope}`, kp),
      query(`SELECT count(*)::int n FROM iam_user_details d JOIN roles r ON r.id = d.role_id
              WHERE d.password_enabled AND jsonb_array_length(coalesce(d.mfa, '[]'::jsonb)) = 0 AND r.deleted_at IS NULL AND ${kScope}`, kp),
      liveIds.length ? query(`SELECT count(*)::int n, (array_agg(a.name ORDER BY s.created_at DESC))[1] AS latest
               FROM scan_runs s JOIN cloud_accounts a ON a.id = s.account_id
              WHERE s.status IN ('failed', 'partial') AND s.created_at > now() - interval '1 day' AND s.account_id = ANY($1::uuid[])
                AND NOT EXISTS (SELECT 1 FROM scan_runs t WHERE t.account_id = s.account_id AND t.status = 'succeeded' AND t.created_at > s.created_at)`, [liveIds]) : { rows: [{ n: 0 }] },
      liveIds.length ? query(`SELECT count(DISTINCT u.raw_action)::int n FROM unmapped_events u LEFT JOIN event_action_map m ON m.raw_action = u.raw_action
              WHERE u.account_id = ANY($1) AND (m.status IS NULL OR m.status = 'suggested' OR (m.status = 'unresolved' AND m.reopen_at IS NOT NULL AND m.reopen_at < now() AND u.last_seen > m.decided_at))`, [liveIds]) : { rows: [{ n: 0 }] },
      query(`SELECT count(*) FILTER (WHERE r.kind <> 'iam-user')::int roles, count(*) FILTER (WHERE r.kind = 'iam-user')::int users
               FROM roles r WHERE r.deleted_at IS NULL AND ${kScope}`, kp),
      // the Radar axis: the median role's never-called share, now and 30 days ago
      liveIds.length ? query(`SELECT
          (SELECT percentile_cont(0.5) WITHIN GROUP (ORDER BY r.unused_count::float8 / r.granted_count) FROM roles r
            WHERE r.deleted_at IS NULL AND r.granted_count > 0 AND r.account_id = ANY($1::uuid[])) AS now,
          (SELECT percentile_cont(0.5) WITHIN GROUP (ORDER BY s.unused::float8 / s.granted) FROM role_snapshots s
            WHERE s.granted > 0 AND s.account_id = ANY($1::uuid[]) AND s.day = (SELECT max(day) FROM role_snapshots WHERE day <= current_date - 30)) AS then`, [liveIds]) : { rows: [{}] },
      query(`SELECT count(*)::int n, count(*) FILTER (WHERE team IS NOT NULL)::int on_team FROM users WHERE NOT disabled`),
      query(`SELECT count(*)::int n FROM alert_rules WHERE enabled`),
      query(`SELECT max(created_at) AS at FROM access_reviews`),
      query(`SELECT EXISTS (SELECT 1 FROM review_decisions) AS any`),
    ]);
    const sev = Object.fromEntries(['high', 'medium', 'low'].map((s) => [s, findings.rows.find((x) => x.severity === s) || { n: 0, mine: 0 }]));
    const inScope = (ids) => !su.scope_accounts || ids.every((id) => su.scope_accounts.includes(id));
    const openReviews = reviews.rows.filter((r) => inScope(r.account_ids));
    const toSign = openReviews.filter((r) => (who.team ? r.teams.includes(who.team) && !r.signed.includes(who.team) : r.teams.some((t) => !r.signed.includes(t))));
    const sso = ssoView();
    const k = keys.rows[0];
    return {
      state,
      accounts: { total: live.length, planned: accounts.length - live.length, complete: complete.length,
        reading: live.filter((a) => !hist.get(a.id).complete).map((a) => ({ id: a.id, name: a.name, environment: a.environment, progress: hist.get(a.id).progress })),
        completeIds },
      findings: { high: sev.high.n, medium: sev.medium.n, low: sev.low.n, mineHigh: sev.high.mine, mineMedium: sev.medium.mine, mine: sev.high.mine + sev.medium.mine + sev.low.mine,
        highByAccount: findingsByAcct.rows },
      drafts,
      reviewsToSign: toSign.map((r) => ({ id: r.id, name: r.name, teams: r.teams, signed: r.signed, createdAt: r.created_at })),
      keys: { active: n(k?.total), old: n(k?.old), oldestDays: k?.oldest_days ?? null, oldestUser: k?.oldest_user ?? null, noMfa: n(noMfa.rows[0]?.n) },
      failedScans: { n: n(failed.rows[0]?.n), latest: failed.rows[0]?.latest || null },
      unidentified: n(unk.rows[0]?.n),
      identities: { roles: n(ids.rows[0]?.roles), users: n(ids.rows[0]?.users) },
      never: { now: never.rows[0]?.now ?? null, then: never.rows[0]?.then ?? null },
      setup: { members: n(members.rows[0].n), onTeam: n(members.rows[0].on_team), alertRules: n(rulesN.rows[0].n), sso: Boolean(sso.enabled && sso.issuer && sso.clientId),
        lastReviewAt: lastReview.rows[0]?.at || null, decided: Boolean(decided.rows[0]?.any) },
    };
  });
}

/** The setup checklist: six steps, in order. */
function setupSteps(f) {
  return [
    { key: 'accounts', title: 'Connect your first AWS account', done: f.accounts.total > 0, href: '#/accounts/new', perm: 'accounts' },
    { key: 'history', title: 'Let it read the history', done: f.accounts.total > 0 && f.state === 'steady', href: '#/operations/scans', perm: null },
    { key: 'team', title: 'Invite your team and pick review teams', done: f.setup.members > 1 && f.setup.onTeam > 0, href: '#/admin/members', perm: 'members' },
    { key: 'sso', title: 'Turn on single sign-on', done: f.setup.sso, href: '#/admin/config', perm: 'sso' },
    { key: 'alerts', title: 'Send High findings to Slack', done: f.setup.alertRules > 0, href: '#/admin/alerts', perm: 'settings' },
    { key: 'decide', title: 'Decide your first findings', done: f.setup.decided, href: '#/findings', perm: 'decide' },
  ];
}

/**
 * The ranked list. Each item: { key, tier, count, title, why, meta, href, cta }. Ranked by tier, then by the order
 * below (which is by how much it matters within the tier). Only items `who` can act on.
 */
export function buildActions(f, who) {
  const out = [];
  const add = (perm, a) => { if (!perm || [].concat(perm).some((p) => who.can(p))) out.push(a); };
  const team = who.team ? TEAM_LABEL[who.team] : null;
  const mineQ = who.team ? '&mine=1' : '';
  // while some history is still read, findings links open on the accounts that are done (the rest are previews)
  const onlyRead = f.state === 'reading' && f.accounts.completeIds.length ? `&accounts=${f.accounts.completeIds.join(',')}` : '';

  if (f.state === 'first-run') {
    add('accounts', { key: 'connect', tier: 'blocking', count: 0, title: 'Connect your first AWS account',
      why: 'A read-only role in the account, or the organisation’s CloudTrail bucket for many accounts at once. The page writes the policy for you.',
      meta: null, href: '#/accounts/new', cta: 'Connect an account' });
    return out;
  }
  // ----- blocking -----
  if (f.failedScans.n) add('ops', { key: 'scans-failed', tier: 'blocking', count: f.failedScans.n,
    title: `Fix ${f.failedScans.n} failed ${plural(f.failedScans.n, 'scan')}`,
    why: 'A scan that failed leaves its account’s data behind. Retry it, or read its log for what went wrong.',
    meta: f.failedScans.latest ? `latest: ${f.failedScans.latest}` : null, href: '#/operations/scans', cta: 'Open scans' });
  // ----- while history is read: what needs none of it comes first -----
  if (f.state === 'reading') add('view', { key: 'trust', tier: 'urgent', count: 0, title: 'See every way into your accounts',
    why: 'Trust policies are read already. Check who outside your organisation can assume a role before anything else.',
    meta: null, href: '#/trust', cta: 'Open the Trust map' });
  // ----- urgent: decisions only this person or team can make -----
  const high = who.team ? f.findings.mineHigh : f.findings.high;
  if (high) add('decide', { key: 'findings-high', tier: 'urgent', count: high,
    title: `Decide ${fmt(high)} high ${plural(high, 'finding')}`,
    why: `${team ? `On roles ${team} signs off. ` : ''}Each one waits on a keep, scope or remove.${f.state === 'reading' ? ' Only accounts whose history is read are counted; the rest are still previews.' : ''}`,
    meta: f.findings.highByAccount.map((x) => `${x.name} ${x.n}`).join(' · ') || null, href: `#/findings?severity=high${mineQ}${onlyRead}`, cta: 'Open findings' });
  const drafts = f.drafts;
  // approving needs a review team; a team's own version (wall, digest) always has one or speaks for both
  const approver = who.role === 'team' || Boolean(who.team);
  if (drafts.length && approver) add('approve', { key: 'drafts', tier: 'urgent', count: drafts.length,
    title: `Approve ${drafts.length} least-privilege ${plural(drafts.length, 'draft')}`,
    why: drafts.some((d) => d.approvedBy.length) ? `${drafts.filter((d) => d.approvedBy.length).length} already approved by the other team. They pass the safety checks; ${team ? `${team}’s` : 'your'} approval sends them out.`
      : 'They pass the safety checks and are waiting for a review team’s approval.',
    meta: drafts.slice(0, 3).map((d) => `${d.role.name} in ${d.account.name}${d.removed ? ` −${fmt(d.removed)} actions` : ''}`).join(' · '), href: '#/findings?state=drafts', cta: 'Review drafts' });
  for (const r of approver ? f.reviewsToSign.slice(0, 2) : []) {
    add('approve', { key: `review:${r.id}`, tier: 'urgent', count: 1, title: `Sign off “${r.name}”`,
      why: r.signed.length ? `${r.signed.map((t) => TEAM_LABEL[t] || t).join(' and ')} signed off. The review stays open until ${team || 'every team'} does too.` : 'No team has signed it off yet.',
      meta: `${r.signed.length} of ${r.teams.length} sign-offs · opened ${day(r.createdAt)}`, href: `#/reviews/${r.id}`, cta: 'Open review' });
  }
  // ----- hygiene -----
  const hygiene = ['decide', 'recommend'];
  if (f.keys.old) add(hygiene, { key: 'keys-old', tier: 'hygiene', count: f.keys.old,
    title: `Rotate ${fmt(f.keys.old)} access ${plural(f.keys.old, 'key')} older than ${keyRules().rotateDays} days`,
    why: 'Long-lived keys work from anywhere until deleted. Rotate them, or move the workload to a role.',
    meta: f.keys.oldestUser ? `oldest: ${f.keys.oldestUser} · ${fmt(f.keys.oldestDays)} days` : null, href: '#/identities?type=users&flag=oldKey', cta: 'Show the keys' });
  if (f.keys.noMfa) add(hygiene, { key: 'no-mfa', tier: 'hygiene', count: f.keys.noMfa,
    title: `${fmt(f.keys.noMfa)} IAM ${plural(f.keys.noMfa, 'user')} can sign in to the console without MFA`,
    why: 'A password alone is enough to get in. Add an MFA device, or remove the console password.',
    meta: null, href: '#/identities?type=users&flag=noMfa', cta: 'Show the users' });
  if (f.unidentified) add(hygiene, { key: 'unidentified', tier: 'hygiene', count: f.unidentified,
    title: `Identify ${fmt(f.unidentified)} event ${plural(f.unidentified, 'name')}`,
    why: 'Calls under names not yet mapped to an IAM action. Until they are, the permissions they need cannot be confirmed.',
    meta: null, href: '#/unidentified', cta: 'Identify them' });
  const medium = who.team ? f.findings.mineMedium : f.findings.medium;
  if (medium) add('decide', { key: 'findings-medium', tier: 'hygiene', count: medium,
    title: `Decide ${fmt(medium)} medium ${plural(medium, 'finding')}`, why: 'Less urgent, but each one is still a permission nobody has confirmed is needed.',
    meta: null, href: `#/findings?severity=medium${mineQ}${onlyRead}`, cta: 'Open findings' });
  // ----- setup -----
  if (f.setup.members < 2 || !f.setup.onTeam) add('members', { key: 'setup-team', tier: 'setup', count: 0, title: 'Invite your team and pick review teams',
    why: 'Approvals need a member of each review team. Do it now so nothing waits.', meta: `${f.setup.members} ${plural(f.setup.members, 'member')} · ${f.setup.onTeam} on a review team`,
    href: '#/admin/members', cta: 'Invite' });
  if (!f.setup.alertRules) add('settings', { key: 'setup-alerts', tier: 'setup', count: 0, title: 'Send High findings to Slack',
    why: 'Nobody is told when a High finding appears; someone has to open the app. One rule fixes that.', meta: null, href: '#/admin/alerts', cta: 'Set up alerts' });
  if (!f.setup.sso) add('sso', { key: 'setup-sso', tier: 'setup', count: 0, title: 'Turn on single sign-on',
    why: 'Members sign in with your identity provider, and its groups decide their roles here.', meta: null, href: '#/admin/config', cta: 'Set up SSO' });
  if (f.state === 'steady' && (!f.setup.lastReviewAt || Date.now() - new Date(f.setup.lastReviewAt) > 90 * 864e5)) add('decide', { key: 'setup-review', tier: 'setup', count: 0,
    title: 'Run an access review', why: 'A frozen snapshot of who can do what, with every decision, signed off by each review team. None in the last 90 days.',
    meta: f.setup.lastReviewAt ? `last one ${day(f.setup.lastReviewAt)}` : null, href: '#/reviews', cta: 'Start a review' });
  return out.sort((a, b) => TIERS.indexOf(a.tier) - TIERS.indexOf(b.tier));     // stable: the order above holds within a tier
}

/** Home for one member: the list without what they put off, their queue, the estate, and the setup checklist. */
export async function homeFor(user) {
  const who = forUser(user);
  const f = await facts(who);
  const snoozed = new Set((await query('SELECT action_key FROM home_snoozes WHERE user_id = $1 AND until > now()', [user.id])).rows.map((r) => r.action_key));
  const all = buildActions(f, who);
  const actions = all.filter((a) => !snoozed.has(a.key));
  const steps = setupSteps(f);
  return {
    ...page(f, who),
    actions, snoozed: all.length - actions.length,
    setup: { steps: steps.map(({ perm, ...s }) => ({ ...s, canDo: !perm || who.can(perm) })), done: steps.filter((s) => s.done).length, total: steps.length, hidden: Boolean(user.home_setup_hidden) },
    // an auditor acts on nothing here; what they look for is evidence
    evidence: user.role === 'auditor' ? await evidence(user) : null,
  };
}

/** The team's version, for the wall view: no snoozes, no setup checklist. */
export async function homeForTeam({ team = null, accounts = null, setup = false } = {}) {
  const who = forTeam({ team, accounts });
  const f = await facts(who);
  return { ...page(f, who), actions: buildActions(f, who).filter((a) => setup || a.tier !== 'setup') };
}

function page(f, who) {
  const approver = (who.role === 'team' || Boolean(who.team)) && who.can('approve');
  return {
    state: f.state, team: who.team,
    accounts: f.accounts,
    queue: { findingsMine: who.team ? f.findings.mine : f.findings.high + f.findings.medium + f.findings.low, drafts: approver ? f.drafts.length : 0, reviewsToSign: approver ? f.reviewsToSign.length : 0,
      unidentified: f.unidentified, failedScans: f.failedScans.n },
    estate: { identities: f.identities, findings: { high: f.findings.high, medium: f.findings.medium, low: f.findings.low },
      never: f.never.now, never30: f.never.now != null && f.never.then != null ? f.never.now - f.never.then : null, keys: { active: f.keys.active, old: f.keys.old }, rotateDays: keyRules().rotateDays },
  };
}

async function evidence(user) {
  const rows = (await query(`SELECT r.id, r.name, r.status, r.account_ids, r.created_at, (SELECT max(signed_at) FROM access_review_signoffs s WHERE s.review_id = r.id) AS signed_at
                               FROM access_reviews r ORDER BY r.created_at DESC LIMIT 20`)).rows
    .filter((r) => !user.scope_accounts || r.account_ids.every((id) => user.scope_accounts.includes(id)));
  const signed = rows.find((r) => r.status === 'signed');
  return { latestSigned: signed ? { id: signed.id, name: signed.name, signedAt: signed.signed_at } : null, open: rows.filter((r) => r.status === 'open').length };
}

/** "Not now": hide an item for this person for a while (setup items for longer). */
export async function snooze(user, key, days) {
  const d = Math.max(1, Math.min(90, Number(days) || (String(key).startsWith('setup-') ? SNOOZE_DAYS.setup : SNOOZE_DAYS.default)));
  await query(`INSERT INTO home_snoozes(user_id, action_key, until) VALUES ($1, $2, now() + make_interval(days => $3))
               ON CONFLICT (user_id, action_key) DO UPDATE SET until = EXCLUDED.until`, [user.id, String(key).slice(0, 80), d]);
  return { key, days: d };
}
export async function unsnoozeAll(user) { await query('DELETE FROM home_snoozes WHERE user_id = $1', [user.id]); }
export async function setSetupHidden(user, hidden) { await query('UPDATE users SET home_setup_hidden = $2 WHERE id = $1', [user.id, Boolean(hidden)]); }

/** The digest's message items: the team's list as alert items (title, subject, url), at most `max`, of the tiers asked for. */
export async function todoItems({ team = null, accounts = null, tiers = TIERS, max = 5, link = (h) => h } = {}) {
  const list = (await homeForTeam({ team, accounts, setup: tiers.includes('setup') })).actions.filter((a) => tiers.includes(a.tier));
  return { total: list.length, items: list.slice(0, max).map((a) => ({ title: a.title, subject: a.meta || a.why, severity: TIER_LABEL[a.tier], tier: a.tier, count: a.count, url: link(a.href) })) };
}
