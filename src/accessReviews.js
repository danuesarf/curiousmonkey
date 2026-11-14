// Access reviews: evidence for a periodic user access review. Creating one freezes, in one consistent read, every
// role and IAM user in the chosen accounts: risk, permissions held and used, who used it in the period and how often,
// access keys and console sign-in, and every finding with its decision. Each review team then signs it off.
// Nothing in a review changes after it is taken; a new scan does not touch it.
import { z } from 'zod';
import { query, tx } from './db.js';
import { TEAMS, inScope } from './auth/rbac.js';
import { historyFor } from './history.js';
import { keyRules } from './config.js';
import { toCsv } from './csv.js';

const DAY = 864e5;
const day = (d) => new Date(d).toISOString().slice(0, 10);
const daysAgo = (d, now) => (d ? Math.floor((now - new Date(d).getTime()) / DAY) : null);

export class ReviewError extends Error { constructor(status, message, field) { super(message); this.status = status; this.field = field; } }

export const ReviewIn = z.object({
  name: z.string().trim().min(1, 'Give the review a name.').max(120),
  accounts: z.array(z.string().uuid()).min(1, 'Pick at least one account.').max(500),
  from: z.string().regex(/^\d{4}-\d{2}-\d{2}$/, 'Pick a start date.'),
  to: z.string().regex(/^\d{4}-\d{2}-\d{2}$/, 'Pick an end date.'),
  teams: z.array(z.enum(TEAMS)).min(1, 'At least one team signs off.').default([...TEAMS]),
});

/** A member sees a review only if they can see every account in it. */
const visible = (user, r) => r.account_ids.every((id) => inScope(user, id));

/** Takes the snapshot and stores the review. Returns its id. */
export async function createReview(user, body) {
  const b = ReviewIn.parse(body);
  const from = new Date(`${b.from}T00:00:00Z`), to = new Date(`${b.to}T00:00:00Z`), today = new Date(`${day(Date.now())}T00:00:00Z`);
  if (Number.isNaN(+from) || Number.isNaN(+to)) throw new ReviewError(400, 'Pick real dates.', 'from');
  if (to < from) throw new ReviewError(400, 'The period ends before it starts.', 'to');
  // `to` is a date on the person's calendar: east of UTC it is already tomorrow there, so allow one day
  if (to > new Date(+today + DAY)) throw new ReviewError(400, 'The period cannot end in the future.', 'to');
  if ((to - from) / DAY > 366) throw new ReviewError(400, 'A review covers at most a year.', 'from');
  const ids = [...new Set(b.accounts)];
  if (!ids.every((id) => inScope(user, id))) throw new ReviewError(404, 'One of these accounts does not exist.', 'accounts');
  const accounts = (await query(`SELECT * FROM cloud_accounts WHERE id = ANY($1::uuid[]) AND status <> 'planned' ORDER BY name`, [ids])).rows;
  if (accounts.length !== ids.length) throw new ReviewError(400, 'Pick connected accounts: a planned one has nothing to review yet.', 'accounts');
  const hist = await historyFor(accounts);
  const now = Date.now(), rules = keyRules();
  const end = new Date(+to + DAY);                                   // the period includes its last day

  return tx(async (c) => {
    // every read below sees the database at one moment
    await c.query('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ');
    const [roles, calls, callers, details, keys, flags] = await Promise.all([
      c.query(`SELECT r.id, r.account_id, r.name, r.arn, r.kind, r.permission_set, r.risk, r.risk_score, r.risk_reasons, r.reviewer_team, r.requires_both,
                      r.granted_count, r.used_count, r.unused_count, r.unconfirmed_count, r.created_in_aws, r.last_used_at, r.last_activity_at, r.analyzed_at
                 FROM roles r WHERE r.account_id = ANY($1::uuid[]) AND r.deleted_at IS NULL
                ORDER BY r.account_id, r.risk_score DESC NULLS LAST, r.name`, [ids]),
      c.query(`SELECT x.role_id, sum(x.count)::bigint AS calls, sum(x.error_count)::bigint AS denied, count(DISTINCT x.day)::int AS days
                 FROM activity_daily x JOIN roles r ON r.id = x.role_id
                WHERE r.account_id = ANY($1::uuid[]) AND x.day >= $2::date AND x.day < $3::date GROUP BY x.role_id`, [ids, day(from), day(end)]),
      c.query(`SELECT p.role_id, p.display, p.kind, p.via, p.sessions_count, p.first_seen, p.last_seen, p.mfa
                 FROM principals p JOIN roles r ON r.id = p.role_id
                WHERE r.account_id = ANY($1::uuid[]) AND p.last_seen >= $2 AND (p.first_seen IS NULL OR p.first_seen < $3)
                ORDER BY p.role_id, p.last_seen DESC`, [ids, from, end]),
      c.query(`SELECT d.* FROM iam_user_details d JOIN roles r ON r.id = d.role_id WHERE r.account_id = ANY($1::uuid[])`, [ids]),
      c.query(`SELECT k.* FROM iam_access_keys k JOIN roles r ON r.id = k.role_id WHERE r.account_id = ANY($1::uuid[]) AND k.deleted_at IS NULL ORDER BY k.created_at`, [ids]),
      c.query(`SELECT f.role_id, f.title, f.severity, f.category, f.created_at, d.decision, d.note, d.team AS decided_team, d.decided_at, u.name AS decided_by
                 FROM flags f JOIN roles r ON r.id = f.role_id LEFT JOIN review_decisions d ON d.flag_id = f.id LEFT JOIN users u ON u.id = d.decided_by
                WHERE r.account_id = ANY($1::uuid[]) AND f.status = 'open' AND r.deleted_at IS NULL
                ORDER BY f.role_id, CASE f.severity WHEN 'high' THEN 0 WHEN 'medium' THEN 1 ELSE 2 END, f.title`, [ids]),
    ]);
    const group = (rows) => { const m = new Map(); for (const x of rows) { if (!m.has(x.role_id)) m.set(x.role_id, []); m.get(x.role_id).push(x); } return m; };
    const callsBy = new Map(calls.rows.map((x) => [x.role_id, x])), callersBy = group(callers.rows), keysBy = group(keys.rows), flagsBy = group(flags.rows);
    const detailBy = new Map(details.rows.map((d) => [d.role_id, d]));
    const acct = new Map(accounts.map((a) => [a.id, a]));

    const items = roles.rows.map((r, n) => {
      const a = acct.get(r.account_id), used = callsBy.get(r.id), who = callersBy.get(r.id) || [], fl = flagsBy.get(r.id) || [];
      const isUser = r.kind === 'iam-user', d = detailBy.get(r.id);
      const ks = (keysBy.get(r.id) || []).map((k) => {
        const last = [k.last_used_at, k.trail_last_seen].filter(Boolean).sort((x, y) => new Date(y) - new Date(x))[0] || null;
        const age = daysAgo(k.created_at, now);
        return { id: k.key_id, status: k.status, created: k.created_at, ageDays: age, lastUsed: last, rotate: k.status === 'Active' && age != null && age > rules.rotateDays };
      });
      const data = {
        name: r.name, arn: r.arn, kind: r.kind, permissionSet: r.permission_set, account: a.name, awsAccountId: a.account_id, environment: a.environment,
        risk: r.risk, riskScore: r.risk_score, why: (r.risk_reasons || []).slice(0, 5), reviewerTeam: r.requires_both ? 'both' : r.reviewer_team,
        permissions: { granted: r.granted_count, used: r.used_count, unused: r.unused_count, unconfirmed: r.unconfirmed_count },
        createdInAws: r.created_in_aws, lastUsedIam: r.last_used_at, lastCall: r.last_activity_at, analyzedAt: r.analyzed_at,
        period: { calls: Number(used?.calls || 0), denied: Number(used?.denied || 0), activeDays: used?.days || 0 },
        callers: who.slice(0, 15).map((p) => ({ name: p.display, kind: p.kind, via: p.via, sessions: p.sessions_count, firstSeen: p.first_seen, lastSeen: p.last_seen, mfa: p.mfa })),
        moreCallers: Math.max(0, who.length - 15),
        findings: fl.map((f) => ({ title: f.title, severity: f.severity, category: f.category, found: f.created_at, decision: f.decision || null, note: f.note || null,
          decidedBy: f.decided_by || null, decidedTeam: f.decided_team || null, decidedAt: f.decided_at || null })),
        ...(isUser ? { user: { consolePassword: !!d?.password_enabled, passwordLastUsed: d?.password_last_used || null, mfa: (d?.mfa || []).map((m) => m.type), groups: d?.groups || [], keys: ks } } : {}),
      };
      return { n, accountId: r.account_id, kind: r.kind, risk: r.risk, name: r.name, calls: data.period.calls, open: fl.length, undecided: fl.filter((f) => !f.decision).length, data };
    });

    const users = items.filter((i) => i.kind === 'iam-user');
    const activeKeys = users.flatMap((i) => i.data.user.keys.filter((k) => k.status === 'Active'));
    const totals = {
      identities: items.length, roles: items.length - users.length, users: users.length,
      high: items.filter((i) => i.risk === 'High').length, medium: items.filter((i) => i.risk === 'Medium').length, low: items.filter((i) => i.risk === 'Low').length,
      unusedInPeriod: items.filter((i) => !i.calls).length, findings: items.reduce((s, i) => s + i.open, 0), undecided: items.reduce((s, i) => s + i.undecided, 0),
      activeKeys: activeKeys.length, keysToRotate: activeKeys.filter((k) => k.rotate).length,
      consoleWithoutMfa: users.filter((i) => i.data.user.consolePassword && !i.data.user.mfa.length).length,
    };
    const snapshot = {
      takenAt: new Date(now).toISOString(), keyRules: rules,
      accounts: accounts.map((a) => {
        const h = hist.get(a.id) || {};
        const mine = items.filter((i) => i.accountId === a.id);
        return { id: a.id, name: a.name, awsAccountId: a.account_id, environment: a.environment, historyComplete: !!h.complete, historyFrom: h.backTo || null, historyTo: h.readUpTo || null,
          identities: mine.length, high: mine.filter((i) => i.risk === 'High').length, undecided: mine.reduce((s, i) => s + i.undecided, 0) };
      }),
      totals,
    };
    const review = (await c.query(`INSERT INTO access_reviews(name, period_from, period_to, account_ids, teams, snapshot, created_by, created_by_name)
                                   VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING id`,
      [b.name, b.from, b.to, ids, [...new Set(b.teams)], JSON.stringify(snapshot), user.id, user.name])).rows[0];
    const CH = 1000;
    for (let i = 0; i < items.length; i += CH) {
      const s = items.slice(i, i + CH);
      await c.query(`INSERT INTO access_review_items(review_id, n, account_id, kind, risk, name, calls, open_findings, undecided, data)
                     SELECT $1, * FROM unnest($2::int[], $3::uuid[], $4::text[], $5::text[], $6::text[], $7::bigint[], $8::int[], $9::int[], $10::jsonb[])`,
      [review.id, s.map((x) => x.n), s.map((x) => x.accountId), s.map((x) => x.kind), s.map((x) => x.risk), s.map((x) => x.name), s.map((x) => x.calls),
        s.map((x) => x.open), s.map((x) => x.undecided), s.map((x) => JSON.stringify(x.data))]);
    }
    return { id: review.id, totals };
  });
}

const head = (r, signoffs) => ({
  id: r.id, name: r.name, from: day(r.period_from), to: day(r.period_to), teams: r.teams, status: r.status, createdAt: r.created_at, createdBy: r.created_by_name,
  accounts: r.snapshot.accounts, totals: r.snapshot.totals, takenAt: r.snapshot.takenAt, keyRules: r.snapshot.keyRules,
  signoffs: (signoffs || []).map((s) => ({ team: s.team, by: s.user_name, email: s.user_email, note: s.note, at: s.signed_at })),
});
async function load(user, id) {
  const r = (await query('SELECT * FROM access_reviews WHERE id = $1', [id])).rows[0];
  if (!r || !visible(user, r)) throw new ReviewError(404, 'That review does not exist.');
  return r;
}
const signoffsOf = async (ids) => {
  const rows = ids.length ? (await query('SELECT * FROM access_review_signoffs WHERE review_id = ANY($1::uuid[]) ORDER BY signed_at', [ids])).rows : [];
  const m = new Map(); for (const s of rows) { if (!m.has(s.review_id)) m.set(s.review_id, []); m.get(s.review_id).push(s); }
  return m;
};

/** Every review the member can see, newest first, without its identities. */
export async function listReviews(user) {
  const rows = (await query('SELECT * FROM access_reviews ORDER BY created_at DESC LIMIT 200')).rows.filter((r) => visible(user, r));
  const so = await signoffsOf(rows.map((r) => r.id));
  return rows.map((r) => head(r, so.get(r.id)));
}
export async function getReview(user, id) {
  const r = await load(user, id);
  return head(r, (await signoffsOf([r.id])).get(r.id));
}

/** One page of a review's identities. Filters: q, account, kind (roles|users), risk, unused (no calls in the period), undecided. `all` returns every one (for printing). */
export async function reviewItems(user, id, q) {
  const r = await load(user, id);
  const p = [r.id], where = ['review_id = $1'];
  const add = (sql, v) => { p.push(v); where.push(sql.replaceAll('?', `$${p.length}`)); };
  if (q.q) add("(name ILIKE ? OR data->>'arn' ILIKE ?)", `%${String(q.q).slice(0, 100).replace(/[\\%_]/g, (ch) => `\\${ch}`)}%`);
  if (q.account && z.string().uuid().safeParse(q.account).success) add('account_id = ?', q.account);
  if (q.kind === 'users') where.push("kind = 'iam-user'"); if (q.kind === 'roles') where.push("kind <> 'iam-user'");
  if (['High', 'Medium', 'Low'].includes(q.risk)) add('risk = ?', q.risk);
  if (q.unused === '1') where.push('calls = 0');
  if (q.undecided === '1') where.push('undecided > 0');
  const all = q.all === '1', limit = all ? 50000 : Math.min(Math.max(Number(q.limit) || 50, 1), 200), page = Math.max(Number(q.page) || 1, 1);
  const rows = (await query(`SELECT n, account_id, data, count(*) OVER()::int AS total FROM access_review_items WHERE ${where.join(' AND ')} ORDER BY n LIMIT ${limit} OFFSET ${all ? 0 : (page - 1) * limit}`, p)).rows;
  return { items: rows.map((x) => ({ n: x.n, accountId: x.account_id, ...x.data })), total: rows[0]?.total ?? 0, page, limit };
}

/** A review team signs the review off. Once every team listed on it has, the review is signed. */
export async function signOff(user, id, body) {
  const { note } = z.object({ note: z.string().trim().max(1000).optional() }).parse(body || {});
  const r = await load(user, id);
  if (!user.team) throw new ReviewError(403, 'Only a member of a review team can sign off. Ask an owner to set your team on the Members page.');
  if (!r.teams.includes(user.team)) throw new ReviewError(403, 'Your team is not asked to sign this review off.');
  return tx(async (c) => {
    const ins = await c.query(`INSERT INTO access_review_signoffs(review_id, team, user_id, user_name, user_email, note) VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT DO NOTHING`,
      [r.id, user.team, user.id, user.name, user.email, note || null]);
    if (!ins.rowCount) throw new ReviewError(409, 'Your team has already signed this review off.');
    const n = (await c.query('SELECT count(*)::int n FROM access_review_signoffs WHERE review_id = $1', [r.id])).rows[0].n;
    if (n >= r.teams.length) await c.query(`UPDATE access_reviews SET status = 'signed' WHERE id = $1`, [r.id]);
    return { team: user.team, signed: n >= r.teams.length };
  });
}

/** Removes a review nobody has signed off yet. A signed-off one is evidence and stays. */
export async function deleteReview(user, id) {
  const r = await load(user, id);
  if ((await query('SELECT 1 FROM access_review_signoffs WHERE review_id = $1 LIMIT 1', [r.id])).rowCount) throw new ReviewError(409, 'A review someone has signed off is kept as evidence and cannot be removed.');
  await query('DELETE FROM access_reviews WHERE id = $1', [r.id]);
  return r;
}

const DECIDED = { keep_scoped: 'keep, scoped', keep: 'keep', remove: 'remove', accept: 'accept', investigate: 'investigate' };
/** The review as spreadsheets: `identities` (one line per role or IAM user) or `decisions` (one line per finding). */
export async function reviewCsv(user, id, which) {
  const r = await getReview(user, id);
  const { items } = await reviewItems(user, id, { all: '1' });
  if (which === 'decisions') {
    const lines = items.flatMap((i) => i.findings.map((f) => ({ i, f })));
    return toCsv([
      ['Account', ({ i }) => i.account], ['Account ID', ({ i }) => i.awsAccountId], ['Identity', ({ i }) => i.name], ['Kind', ({ i }) => i.kind], ['ARN', ({ i }) => i.arn],
      ['Finding', ({ f }) => f.title], ['Severity', ({ f }) => f.severity], ['Found', ({ f }) => f.found], ['Decision', ({ f }) => DECIDED[f.decision] || 'not decided'],
      ['Note', ({ f }) => f.note], ['Decided by', ({ f }) => f.decidedBy], ['Team', ({ f }) => f.decidedTeam], ['Decided at', ({ f }) => f.decidedAt],
    ], lines);
  }
  return toCsv([
    ['Review', () => r.name], ['Period from', () => r.from], ['Period to', () => r.to],
    ['Account', (i) => i.account], ['Account ID', (i) => i.awsAccountId], ['Environment', (i) => i.environment], ['Identity', (i) => i.name], ['Kind', (i) => i.kind], ['ARN', (i) => i.arn],
    ['Risk', (i) => i.risk], ['Why', (i) => i.why], ['Reviewer team', (i) => i.reviewerTeam],
    ['Permissions granted', (i) => i.permissions.granted], ['Used', (i) => i.permissions.used], ['Unused', (i) => i.permissions.unused], ['Cannot be verified', (i) => i.permissions.unconfirmed],
    ['Calls in period', (i) => i.period.calls], ['Denied in period', (i) => i.period.denied], ['Active days in period', (i) => i.period.activeDays],
    ['Callers in period', (i) => [...i.callers.map((c) => c.name), ...(i.moreCallers ? [`+${i.moreCallers} more`] : [])]], ['Last call seen', (i) => i.lastCall],
    ['Console password', (i) => (i.user ? (i.user.consolePassword ? 'yes' : 'no') : '')], ['MFA', (i) => (i.user ? i.user.mfa.join('; ') || 'none' : '')],
    ['Active access keys', (i) => (i.user ? i.user.keys.filter((k) => k.status === 'Active').map((k) => `${k.id} (${k.ageDays} days)`) : '')],
    ['Open findings', (i) => i.findings.length], ['Not decided', (i) => i.findings.filter((f) => !f.decision).length],
  ], items);
}
