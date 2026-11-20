// Specific trust: a draft trust policy for a role that trusts a whole account (Principal "arn:aws:iam::<account>:root"
// or a bare account ID), built from who actually came in. Every caller seen in the history read is named: a role by its
// real ARN (path included: an IAM Identity Center role lives under /aws-reserved/sso.amazonaws.com/<region>/), a user
// by its ARN, an identity CloudTrail named only by its unique ID by that ID. The draft keeps the account as the
// principal and adds aws:PrincipalArn (what AWS recommends for cross-account trust: it keeps working when a role is
// recreated), or names the identities in Principal. It never adds access: every caller kept is re-checked against
// the draft, and other conditions (sts:ExternalId, MFA…) stay as they were. Nothing is changed in AWS.
import { query, tx } from '../db.js';
import { normalizeStatements, docHash, arr } from '../analyzer/policy.js';
import { accountComplete } from '../history.js';
import { config } from '../config.js';
import { Refusal } from './index.js';

const ACCT = /^\d{12}$/;
const rootAccount = (p) => (ACCT.test(p) ? p : String(p).match(/^arn:aws[a-z-]*:iam::(\d{12}):root$/)?.[1] || null);
const POSITIVE = /^(StringEquals|StringLike|ArnEquals|ArnLike)(IfExists)?$/i;
const glob = (pattern, value) => new RegExp(`^${String(pattern).replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*').replace(/\?/g, '.')}$`, 'i').test(value);
const QUIET_DAYS = 60;
export const SIZE_DEFAULT = 2048, SIZE_MAX = 4096;   // IAM's trust policy length quota: 2,048 by default, raisable to 4,096

/** The whole-account principals in a trust policy, and the statements they are in. */
export function rootPrincipals(trust) {
  const out = [];
  for (const st of normalizeStatements(trust || {})) {
    if (st.effect !== 'Allow' || !st.principal || st.principal === '*') continue;
    for (const p of arr(st.principal.AWS)) { const a = rootAccount(String(p)); if (a) out.push({ statement: st.index, sid: st.sid, account: a, raw: String(p) }); }
  }
  return out;
}

/**
 * Who came in from these accounts, named as precisely as the stored data allows.
 * kind: role (arn known, or guessed when the role's account is not scanned: `pathKnown` false), user, unnamed (only a
 * unique ID: kept with aws:userid), merged (recorded before callers were kept by account: cannot be placed).
 */
export async function resolveCallers(role, accounts) {
  if (!accounts.length) return [];
  const rows = (await query(
    `SELECT key, kind, display, via, first_seen, last_seen, sessions_count, session_tags, source_identity, mfa
       FROM principals WHERE role_id = $1 AND kind <> 'session'
        AND (key = 'other:AWSAccount' OR ${accounts.map((_, i) => `key LIKE 'role:' || $${i + 2} || ':%' OR key LIKE 'user:arn:aws%:iam::' || $${i + 2} || ':%' OR key LIKE 'acct:' || $${i + 2} || ':%'`).join(' OR ')})
      ORDER BY last_seen DESC NULLS LAST`, [role.id, ...accounts])).rows;
  // the roles and users Curious Monkey has read, for their real ARNs (with paths) and to name unique IDs
  const names = rows.filter((r) => r.key.startsWith('role:')).map((r) => r.key.split(':'));
  const ids = rows.filter((r) => r.key.startsWith('acct:')).map((r) => r.key.split(':')[2]).filter((x) => /^A[IR]OA/.test(x));
  const known = names.length || ids.length ? (await query(
    `SELECT r.name, r.arn, r.kind, r.aws_id, a.account_id FROM roles r JOIN cloud_accounts a ON a.id = r.account_id
      WHERE r.deleted_at IS NULL AND ((a.account_id, r.name) IN (SELECT * FROM unnest($1::text[], $2::text[])) OR r.aws_id = ANY($3))`,
    [names.map((n) => n[1]), names.map((n) => n.slice(2).join(':')), ids])).rows : [];
  const scanned = new Set((await query(`SELECT account_id FROM cloud_accounts WHERE status <> 'planned' AND account_id = ANY($1)`, [accounts])).rows.map((x) => x.account_id));
  const byName = new Map(known.filter((k) => k.kind !== 'iam-user').map((k) => [`${k.account_id}:${k.name}`, k]));
  const byId = new Map(known.filter((k) => k.aws_id).map((k) => [k.aws_id, k]));
  return rows.map((r) => {
    const base = { key: r.key, display: r.display, sessions: r.sessions_count, firstSeen: r.first_seen, lastSeen: r.last_seen, via: r.via,
      tags: (r.session_tags || []).length > 0, sourceIdentity: !!r.source_identity, mfa: r.mfa };
    if (r.key === 'other:AWSAccount') return { ...base, kind: 'merged', account: null };
    const [, a, ...rest] = r.key.split(':');
    if (r.key.startsWith('role:')) {
      const k = byName.get(`${a}:${rest.join(':')}`);
      return { ...base, kind: 'role', account: a, name: rest.join(':'), arn: k?.arn || `arn:aws:iam::${a}:role/${rest.join(':')}`, pathKnown: !!k,
        ...(k ? {} : { pathWhy: scanned.has(a) ? 'not-found' : 'not-scanned' }) };
    }
    if (r.key.startsWith('user:')) { const arn = r.key.slice(5); return { ...base, kind: 'user', account: arn.match(/::(\d{12}):/)?.[1], name: arn.split('/').pop(), arn, pathKnown: true }; }
    const id = rest[0];
    const k = byId.get(id);
    if (k) return { ...base, kind: k.kind === 'iam-user' ? 'user' : 'role', account: a, name: k.name, arn: k.arn, pathKnown: true, namedFromId: id };
    return { ...base, kind: 'unnamed', account: a, uid: id };
  });
}

// ------------------------------------------------------------------ the draft (no I/O)
/** Does `doc` let this caller in? Only the keys the draft writes are evaluated; every other condition is as it was. */
export function allows(doc, caller, action = 'sts:AssumeRole') {
  const arn = caller.arn || null;
  // aws:userid is "<role ID>:<session name>" for a role session, the user ID for an IAM user
  const userid = caller.uid ? (/^AIDA/.test(caller.uid) ? caller.uid : `${caller.uid}:session`) : null;
  for (const st of normalizeStatements(doc)) {
    if (st.effect !== 'Allow' || !st.actions.some((a) => glob(a, action))) continue;
    const ps = st.principal === '*' ? ['*'] : arr(st.principal?.AWS).map(String);
    const inP = ps.some((p) => p === '*' || rootAccount(p) === caller.account || (arn && p === arn));
    if (!inP) continue;
    let ok = true;
    for (const [op, kv] of Object.entries(st.conditions || {})) {
      if (!POSITIVE.test(op)) continue;
      for (const [k, v] of Object.entries(kv)) {
        const vals = arr(v).map(String);
        if (/^aws:PrincipalArn$/i.test(k)) ok = ok && !!arn && vals.some((x) => (/like/i.test(op) ? glob(x, arn) : x === arn));
        else if (/^aws:userid$/i.test(k)) ok = ok && !!userid && vals.some((x) => (/like/i.test(op) ? glob(x, userid) : x === userid));
        else if (/^aws:PrincipalAccount$/i.test(k)) ok = ok && vals.includes(caller.account);
      }
    }
    if (ok) return true;
  }
  return false;
}

const sidOf = (sid, suffix) => `${String(sid || 'Trust').replace(/[^A-Za-z0-9]/g, '')}${suffix}`.slice(0, 100);
const actionsFor = (st, callers) => {
  if (!st.actions.some((a) => a === '*' || /^sts:\*$/i.test(a))) return null;
  const out = new Set(callers.map((c) => c.via).filter((v) => /^sts:/.test(v)));
  if (!out.size) out.add('sts:AssumeRole');
  if (callers.some((c) => c.tags)) out.add('sts:TagSession');
  if (callers.some((c) => c.sourceIdentity)) out.add('sts:SetSourceIdentity');
  return [...out].sort();
};

/**
 * The draft. input: { role: { name, accountId, trust, lastUsedAt }, callers (from resolveCallers), exclude (keys),
 * style ('condition' | 'principal'), complete (history read), windowDays }.
 * Returns { after, changes, accounts, checks, summary }.
 */
export function buildTrustDraft({ role, callers, exclude = [], style = 'condition', complete = true, windowDays = null, now = Date.now() }) {
  const before = role.trust || {};
  const list = arr(before.Statement).map((s) => JSON.parse(JSON.stringify(s)));
  const sts = normalizeStatements(before);
  const out = [], changes = [], accounts = [];
  const skip = new Set(exclude);
  for (const st of sts) {
    const doc = list[st.index];
    const roots = st.effect === 'Allow' && st.principal && st.principal !== '*' ? arr(st.principal.AWS).map(String).filter(rootAccount) : [];
    if (!roots.length) { out.push(doc); continue; }
    const label = st.sid ? `statement ${st.sid}` : `statement ${st.index + 1}`;
    const narrowed = Object.entries(st.conditions || {}).some(([op, kv]) => POSITIVE.test(op) && Object.keys(kv).some((k) => /^aws:(PrincipalArn|userid)$/i.test(k)));
    if (narrowed) { out.push(doc); changes.push({ statement: label, kind: 'keep', text: 'Already narrowed by aws:PrincipalArn or aws:userid: left as it is.' }); continue; }

    const added = [];
    for (const raw of roots) {
      const a = rootAccount(raw);
      const mine = callers.filter((c) => c.account === a);
      const kept = mine.filter((c) => !skip.has(c.key)), dropped = mine.filter((c) => skip.has(c.key));
      const named = kept.filter((c) => c.kind === 'role' || c.kind === 'user'), unnamed = kept.filter((c) => c.kind === 'unnamed');
      const acc = { account: a, statement: label, principal: raw, kept: kept.length, dropped: dropped.length, outcome: null };
      accounts.push(acc);
      // the account principal comes out of the original statement; what replaces it is added beside it
      const left = arr(doc.Principal.AWS).filter((p) => String(p) !== raw);
      if (left.length) doc.Principal.AWS = left.length === 1 ? left[0] : left; else delete doc.Principal.AWS;

      if (!kept.length) {
        const usedPerIam = role.lastUsedAt && (!windowDays || now - new Date(role.lastUsedAt) >= windowDays * 864e5);
        if (dropped.length) { acc.outcome = 'removed'; changes.push({ statement: label, kind: 'remove', text: `Remove ${raw}: every identity that came in from it was left out (${dropped.map((c) => c.name || c.uid || c.key).join(', ')}).` }); continue; }
        if (complete && !usedPerIam) { acc.outcome = 'removed'; changes.push({ statement: label, kind: 'remove', text: `Remove ${raw}: nothing came in from ${a} in ${windowDays ? `the ${windowDays} days read` : 'the history read'}.` }); continue; }
        // not enough history to say: keep it as it was
        doc.Principal.AWS = doc.Principal.AWS ? [...arr(doc.Principal.AWS), raw] : raw;
        acc.outcome = 'kept';
        changes.push({ statement: label, kind: 'keep', text: `Kept ${raw}: nobody seen from ${a}, but ${!complete ? 'the history is still being read' : `IAM says the role was used ${String(role.lastUsedAt).slice(0, 10)}, before the history read`}.` });
        continue;
      }
      const actions = actionsFor(st, kept);
      const make = (suffix, principal, cond) => {
        const s = { ...(st.sid || suffix ? { Sid: sidOf(st.sid, suffix) } : {}), Effect: 'Allow', Principal: { AWS: principal.length === 1 ? principal[0] : principal }, Action: actions || doc.Action };
        const c = JSON.parse(JSON.stringify(doc.Condition || {}));
        for (const [op, kv] of Object.entries(cond)) c[op] = { ...(c[op] || {}), ...kv };
        if (Object.keys(c).length) s.Condition = c;
        return s;
      };
      const tag = roots.length > 1 ? a.slice(-4) : '';
      const arns = [...new Set(named.map((c) => c.arn))].sort();
      const guessed = named.filter((c) => !c.pathKnown);
      if (named.length) {
        if (style === 'principal' && !guessed.length) {
          added.push(make(`${tag}Named`, arns, {}));
          changes.push({ statement: label, kind: 'narrow', text: `Replace ${raw} with the ${named.length === 1 ? 'identity' : `${named.length} identities`} that came in, named in Principal: ${named.map((c) => c.name).join(', ')}.` });
        } else {
          // ArnLike when a role's path is not known (its account is not scanned): role/<name> and role/*/<name>
          const values = guessed.length ? [...new Set(named.flatMap((c) => (c.pathKnown ? [c.arn] : [c.arn, c.arn.replace(/:role\//, ':role/*/')])))].sort() : arns;
          added.push(make(`${tag}Named`, [`arn:aws:iam::${a}:root`], { [guessed.length ? 'ArnLike' : 'ArnEquals']: { 'aws:PrincipalArn': values.length === 1 ? values[0] : values } }));
          changes.push({ statement: label, kind: 'narrow', text: `Keep ${a} as the principal and allow only the ${named.length === 1 ? 'identity' : `${named.length} identities`} that came in (aws:PrincipalArn): ${named.map((c) => c.name).join(', ')}.`
            + (style === 'principal' && guessed.length ? ' Named in a condition, not in Principal: the path of a role in an account that is not scanned is not known.' : '') });
        }
      }
      if (unnamed.length) {
        added.push(make(`${tag}ById`, [`arn:aws:iam::${a}:root`], { StringLike: { 'aws:userid': unnamed.map((c) => (/^AIDA/.test(c.uid) ? c.uid : `${c.uid}:*`)).sort() } }));
        changes.push({ statement: label, kind: 'narrow', text: `Allow ${unnamed.length === 1 ? 'the identity' : `the ${unnamed.length} identities`} CloudTrail named only by unique ID (aws:userid ${unnamed.map((c) => c.uid).join(', ')}).` });
      }
      if (actions) changes.push({ statement: label, kind: 'narrow', text: `Actions ${st.actions.join(', ')} → ${actions.join(', ')}: what the callers used.` });
      if (dropped.length) changes.push({ statement: label, kind: 'remove', text: `Leave out ${dropped.map((c) => c.name || c.uid || c.key).join(', ')}: ${dropped.length === 1 ? 'it loses' : 'they lose'} access.` });
      acc.outcome = 'narrowed';
    }
    const hasPrincipal = doc.Principal && Object.values(doc.Principal).some((v) => arr(v).length);
    if (hasPrincipal) out.push(doc, ...added);
    else out.push(...added);
  }
  const after = { ...before, Statement: out };
  if (!after.Version) after.Version = '2012-10-17';

  // ---- checks
  const keptCallers = callers.filter((c) => !skip.has(c.key) && c.kind !== 'merged' && accounts.some((x) => x.account === c.account));
  const blocked = keptCallers.filter((c) => !allows(after, c, /^sts:/.test(c.via) ? c.via : 'sts:AssumeRole'));
  const stillRoot = rootPrincipals(after).filter((r) => {
    const st = normalizeStatements(after)[r.statement];
    return !Object.entries(st.conditions || {}).some(([op, kv]) => POSITIVE.test(op) && Object.keys(kv).some((k) => /^aws:(PrincipalArn|userid)$/i.test(k)));
  });
  const size = JSON.stringify(after).length;
  const unnamed = keptCallers.filter((c) => c.kind === 'unnamed'), merged = callers.filter((c) => c.kind === 'merged');
  const guessed = keptCallers.filter((c) => c.kind === 'role' && !c.pathKnown);
  const quiet = keptCallers.filter((c) => c.lastSeen && now - new Date(c.lastSeen) > QUIET_DAYS * 864e5);
  const dropped = callers.filter((c) => skip.has(c.key));
  const checks = [
    blocked.length ? { id: 'callers-kept', label: `${blocked.length} caller${blocked.length === 1 ? '' : 's'} kept in would be refused`, status: 'fail', detail: blocked.map((c) => c.name || c.uid).join(', ') }
      : { id: 'callers-kept', label: `Every caller kept in still gets in (${keptCallers.length})`, status: 'pass', detail: null },
    stillRoot.length ? { id: 'root-left', label: `${stillRoot.length} whole-account principal${stillRoot.length === 1 ? '' : 's'} left`, status: 'warn', detail: `${stillRoot.map((r) => r.raw).join(', ')}: not enough history to name who uses ${stillRoot.length === 1 ? 'it' : 'them'}.` }
      : { id: 'root-left', label: 'No whole-account principal left unnarrowed', status: 'pass', detail: null },
    { id: 'conditions-kept', label: 'Existing conditions kept (sts:ExternalId, MFA, tags…)', status: 'pass', detail: null },
    dropped.length ? { id: 'left-out', label: `${dropped.length} caller${dropped.length === 1 ? '' : 's'} left out by you`, status: 'warn', detail: `${dropped.map((c) => c.name || c.uid || c.key).join(', ')} will be refused after this is applied.` }
      : { id: 'left-out', label: 'Nobody seen is left out', status: 'pass', detail: null },
    unnamed.length ? { id: 'unnamed', label: `${unnamed.length} caller${unnamed.length === 1 ? '' : 's'} allowed by unique ID`, status: 'warn', detail: `CloudTrail in this account names ${unnamed.length === 1 ? 'it' : 'them'} only by ID (${unnamed.map((c) => c.uid).join(', ')}). The aws:userid condition works, but a recreated role gets a new ID. Onboard or rescan ${[...new Set(unnamed.map((c) => c.account))].join(', ')} to name ${unnamed.length === 1 ? 'it' : 'them'}.` }
      : { id: 'unnamed', label: 'Every caller is named by ARN', status: 'pass', detail: null },
    guessed.length ? { id: 'path', label: `${guessed.length} role path${guessed.length === 1 ? '' : 's'} not known`, status: 'warn',
      detail: `${guessed.map((c) => `${c.name} (${c.pathWhy === 'not-found' ? `not in ${c.account}'s inventory: deleted, or renamed since` : `${c.account} is not scanned`})`).join(', ')}. ArnLike allows the name at any path; rescan or onboard the account to pin the exact ARN.` }
      : { id: 'path', label: 'Role ARNs read from IAM, paths included', status: 'pass', detail: null },
    merged.length ? { id: 'merged', label: 'Older sign-ins not tied to an account', status: 'warn', detail: `${merged.reduce((n, c) => n + c.sessions, 0)} session(s) were recorded before callers were kept by account. If they came from a trusted account, that identity is not in the draft.` } : null,
    quiet.length ? { id: 'quiet', label: `${quiet.length} caller${quiet.length === 1 ? '' : 's'} not seen for ${QUIET_DAYS}+ days`, status: 'warn', detail: `${quiet.map((c) => c.name || c.uid).join(', ')}. Kept in; leave ${quiet.length === 1 ? 'it' : 'them'} out if no longer needed.` } : null,
    !complete ? { id: 'history', label: 'History still being read', status: 'warn', detail: 'Callers in the unread part are not in the draft. Approval waits for the read to finish.' }
      : { id: 'history', label: `Built from ${windowDays ? `${windowDays} days of` : 'the whole'} CloudTrail history read`, status: 'pass', detail: null },
    size > SIZE_MAX ? { id: 'size', label: `${size} characters: over IAM's 4,096 limit`, status: 'fail', detail: 'Use the condition style, or leave out callers.' }
      : size > SIZE_DEFAULT ? { id: 'size', label: `${size} characters: over IAM's default 2,048`, status: 'warn', detail: 'Ask AWS to raise the "Role trust policy length" quota (up to 4,096), or leave out callers.' }
      : { id: 'size', label: `${size} characters, within IAM's 2,048 limit`, status: 'pass', detail: null },
  ].filter(Boolean);
  if (!out.length) checks.unshift({ id: 'empty', label: 'Nobody would be let in', status: 'fail', detail: 'Every statement would be removed, and IAM refuses an empty trust policy. If nobody needs the role, delete it instead.' });
  const narrowedN = accounts.filter((a) => a.outcome === 'narrowed').length, removedN = accounts.filter((a) => a.outcome === 'removed').length;
  const summary = !accounts.length ? 'This role trusts no whole account.'
    : [narrowedN && `${narrowedN} whole-account principal${narrowedN === 1 ? '' : 's'} narrowed to the ${keptCallers.length} identit${keptCallers.length === 1 ? 'y' : 'ies'} seen coming in`,
      removedN && `${removedN} removed (nobody came in)`].filter(Boolean).join('; ') + '.';
  return { after, changes, accounts, checks, summary };
}

// ------------------------------------------------------------------ stored drafts and approval
async function contextFor(roleId) {
  const role = (await query(`SELECT r.*, a.name AS account_name, a.account_id AS aws_account_id FROM roles r JOIN cloud_accounts a ON a.id = r.account_id WHERE r.id = $1 AND r.deleted_at IS NULL`, [roleId])).rows[0];
  if (!role) throw new Refusal('role not found', 404);
  const roots = rootPrincipals(role.trust_policy);
  const callers = await resolveCallers(role, [...new Set(roots.map((r) => r.account))]);
  const days = (await query('SELECT EXTRACT(EPOCH FROM (max(last_event_time) - min(first_event_time))) / 86400 AS d FROM scan_checkpoints WHERE account_id = $1', [role.account_id])).rows[0]?.d;
  return { role, roots, callers, complete: await accountComplete(role.account_id), windowDays: days ? Math.round(Number(days)) : null };
}

export async function draftTrust(roleId, { exclude = [], style = 'condition', userId = null } = {}) {
  const ctx = await contextFor(roleId);
  if (ctx.role.kind === 'service-linked' || /^\/aws-reserved\//.test(ctx.role.path || '') || /:role\/aws-reserved\//.test(ctx.role.arn)) throw new Refusal('AWS manages this role\'s trust policy. It is reported only.', 409);
  if (ctx.role.kind === 'iam-user') throw new Refusal('IAM users have no trust policy.', 409);
  if (!ctx.roots.length) throw new Refusal('This role trusts no whole account (no :root or bare account ID in its trust policy).', 409);
  const known = new Set(ctx.callers.map((c) => c.key));
  const ex = exclude.filter((k) => known.has(k));
  const d = buildTrustDraft({ role: { name: ctx.role.name, trust: ctx.role.trust_policy, lastUsedAt: ctx.role.last_used_at }, callers: ctx.callers, exclude: ex, style, complete: ctx.complete, windowDays: ctx.windowDays });
  return tx(async (c) => {
    await c.query(`UPDATE trust_recommendations SET status = 'superseded' WHERE role_id = $1 AND status = 'draft'`, [roleId]);
    return (await c.query(
      `INSERT INTO trust_recommendations(role_id, style, before, policy, changes, accounts, callers, excluded, checks, summary, trust_hash, created_by)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) RETURNING *`,
      [roleId, style, JSON.stringify(ctx.role.trust_policy), JSON.stringify(d.after), JSON.stringify(d.changes), JSON.stringify(d.accounts), JSON.stringify(ctx.callers),
       ex, JSON.stringify(d.checks), d.summary, docHash(ctx.role.trust_policy || {}), userId])).rows[0];
  });
}

/** The latest draft, whether the role moved on since (trust changed, someone new came in), approvals, and who is seen now. */
export async function latestTrustDraft(roleId) {
  const ctx = await contextFor(roleId);
  const rec = (await query(`SELECT * FROM trust_recommendations WHERE role_id = $1 AND status <> 'superseded' ORDER BY created_at DESC LIMIT 1`, [roleId])).rows[0];
  const base = { roots: ctx.roots, callers: ctx.callers, complete: ctx.complete, windowDays: ctx.windowDays };
  if (!rec) return { ...base, draft: null };
  const drafted = new Set(rec.callers.map((c) => c.key));
  const newCallers = ctx.callers.filter((c) => !drafted.has(c.key));
  const approvals = (await query(`SELECT a.team, a.approved_at, u.name FROM trust_recommendation_approvals a LEFT JOIN users u ON u.id = a.user_id WHERE a.recommendation_id = $1`, [rec.id])).rows;
  const required = ctx.role.requires_both ? ['infrasec', 'infosec'] : [ctx.role.reviewer_team];
  const changed = rec.trust_hash !== docHash(ctx.role.trust_policy || {});
  return { ...base, draft: { ...rec, stale: changed || newCallers.length > 0, staleWhy: changed ? 'trust' : newCallers.length ? 'callers' : null, newCallers, approvals, requiredTeams: required } };
}

export async function approveTrust(id, user) {
  const rec = (await query('SELECT * FROM trust_recommendations WHERE id = $1', [id])).rows[0];
  if (!rec) throw new Refusal('draft not found', 404);
  if (rec.status !== 'draft') throw new Refusal(`This draft is ${rec.status}`, 409);
  const latest = (await latestTrustDraft(rec.role_id)).draft;
  if (latest?.id !== rec.id) throw new Refusal('A newer draft exists.', 409);
  if (latest.stale) throw new Refusal(latest.staleWhy === 'trust' ? 'The trust policy changed after this draft was made. Draft it again.' : 'Someone new came in after this draft was made. Draft it again so they are in it (or left out on purpose).', 409);
  if (rec.checks.some((c) => c.status === 'fail')) throw new Refusal('This draft fails a safety check and cannot be approved.', 409);
  const role = (await query('SELECT * FROM roles WHERE id = $1', [rec.role_id])).rows[0];
  if (!(await accountComplete(role.account_id))) throw new Refusal('CloudTrail history for this account is still being read, so this draft is a preview. Approval opens when the read is complete.', 409);
  if (!user.team) throw new Refusal('Only members of Infrastructure Security or Information Security can approve', 403);
  const required = role.requires_both ? ['infrasec', 'infosec'] : [role.reviewer_team];
  if (!required.includes(user.team)) throw new Refusal(`This role is reviewed by ${required.join(' and ')}; you are on ${user.team}`, 403);
  return tx(async (c) => {
    await c.query(`INSERT INTO trust_recommendation_approvals(recommendation_id, user_id, team) VALUES ($1,$2,$3) ON CONFLICT (recommendation_id, team) DO NOTHING`, [id, user.id, user.team]);
    const got = (await c.query('SELECT team FROM trust_recommendation_approvals WHERE recommendation_id = $1', [id])).rows.map((r) => r.team);
    const done = required.every((t) => got.includes(t));
    if (done) await c.query(`UPDATE trust_recommendations SET status = 'approved' WHERE id = $1`, [id]);
    return { approved: done, waitingFor: required.filter((t) => !got.includes(t)) };
  });
}

export async function notifyTrustApproved(id) {
  if (!config.approvalWebhookUrl) return;
  const r = (await query(`SELECT t.id, t.policy, ro.arn, ro.name FROM trust_recommendations t JOIN roles ro ON ro.id = t.role_id WHERE t.id = $1`, [id])).rows[0];
  await fetch(config.approvalWebhookUrl, { method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ event: 'trust-recommendation.approved', recommendationId: r.id, role: { arn: r.arn, name: r.name }, trustPolicy: r.policy }) })
    .catch((e) => console.error(JSON.stringify({ level: 'warn', msg: 'approval webhook failed', error: e.message })));
}

export function trustExport(role, rec, format) {
  const doc = JSON.stringify(rec.policy, null, 2);
  if (format === 'cli') {
    return [`# Curious Monkey specific-trust draft for ${role.name} (${rec.status}). Review before applying.`,
      `cat > trust-${role.name}.json <<'EOF'`, doc, 'EOF', `aws iam update-assume-role-policy --role-name ${role.name} --policy-document file://trust-${role.name}.json`].join('\n');
  }
  if (format === 'terraform') {
    const id = role.name.replace(/[^A-Za-z0-9_]/g, '_');
    return [`# Curious Monkey specific-trust draft for ${role.name} (${rec.status}). Review before applying.`,
      `# Set it as assume_role_policy on the existing aws_iam_role "${role.name}".`, `locals {`, `  ${id}_assume_role_policy = jsonencode(${doc.replace(/\n/g, '\n  ')})`, '}', '', `# resource "aws_iam_role" "${id}" { assume_role_policy = local.${id}_assume_role_policy ... }`].join('\n');
  }
  return { role: role.name, arn: role.arn, approved: rec.status === 'approved', trustPolicy: rec.policy };
}
