import { getGateway } from '../aws/gateway.js';
import { query, tx } from '../db.js';
import { docHash } from '../analyzer/policy.js';

export const roleKind = (name, path) =>
  path.includes('/aws-service-role/') || name.startsWith('AWSServiceRoleFor') ? 'service-linked'
  : name.startsWith('AWSReservedSSO_') ? 'identity-center' : 'custom';

export const loadContext = async (accountId) => {
  const account = (await query('SELECT * FROM cloud_accounts WHERE id=$1', [accountId])).rows[0];
  const workspace = (await query('SELECT * FROM workspace')).rows[0];
  if (!account || !workspace) throw Object.assign(new Error('account or workspace missing'), { retryable: false });
  return { account, workspace, gw: await getGateway(account, workspace) };
};

async function limited(items, n, fn) {
  const out = []; let i = 0;
  await Promise.all(Array.from({ length: Math.min(n, items.length) }, async () => {
    while (i < items.length) { const k = i++; out[k] = await fn(items[k], k); }
  }));
  return out;
}

// a managed policy document: AWS-managed ones are cached for a week (they are the same in every account)
async function managedDoc(gw, a) {
  const cached = a.awsManaged ? (await query(
    `SELECT document FROM managed_policy_cache WHERE arn=$1 AND fetched_at > now() - interval '7 days' ORDER BY fetched_at DESC LIMIT 1`, [a.arn])).rows[0] : null;
  if (cached) return { ...a, document: cached.document };
  const m = await gw.getManagedPolicy(a.arn);
  await query(`INSERT INTO managed_policy_cache(arn, version_id, document) VALUES ($1,$2,$3) ON CONFLICT (arn, version_id) DO UPDATE SET fetched_at=now()`,
    [a.arn, m.versionId, JSON.stringify(m.document)]);
  return { ...a, document: m.document };
}
/** Records one change on an identity (History tab). */
const event = (c, roleId, kind, title, detail = {}) =>
  c.query('INSERT INTO identity_events(role_id, kind, title, detail) VALUES ($1,$2,$3,$4)', [roleId, kind, title, JSON.stringify(detail)]);
const POLICY_KIND = { inline: 'Inline policy', managed: 'Managed policy', group: 'Group policy' };

/**
 * Saves an identity's policies. With `record`, what differs from the stored set is written to its history:
 * a policy added, removed, or whose document changed (an AWS managed one changes when AWS publishes a version).
 */
async function savePolicies(c, roleId, docs, { record = false } = {}) {
  if (record) {
    const prev = new Map((await c.query('SELECT kind, name, arn, aws_managed, doc_hash, document FROM role_policies WHERE role_id=$1', [roleId])).rows.map((p) => [`${p.kind}:${p.name}`, p]));
    const next = new Map(docs.map((d) => [`${d.kind}:${d.name}`, d]));
    for (const [k, d] of next) {
      const p = prev.get(k), label = `${POLICY_KIND[d.kind] || 'Policy'} ${d.name}`;
      const base = { name: d.name, policyKind: d.kind, arn: d.arn, awsManaged: !!d.aws };
      if (!p) await event(c, roleId, 'policy-added', `${label} ${d.kind === 'inline' ? 'added' : 'attached'}`, { ...base, after: d.document });
      else if (p.doc_hash !== docHash(d.document)) {
        await event(c, roleId, 'policy-changed', d.aws ? `AWS updated the managed policy ${d.name}` : `${label} changed`, { ...base, before: p.document, after: d.document });
      }
    }
    for (const [k, p] of prev) {
      if (!next.has(k)) await event(c, roleId, 'policy-removed', `${POLICY_KIND[p.kind] || 'Policy'} ${p.name} ${p.kind === 'inline' ? 'deleted' : 'detached'}`,
        { name: p.name, policyKind: p.kind, arn: p.arn, awsManaged: p.aws_managed, before: p.document });
    }
  }
  await c.query(`DELETE FROM role_policies WHERE role_id=$1 AND NOT (kind||':'||name = ANY($2))`, [roleId, docs.map((d) => `${d.kind}:${d.name}`)]);
  for (const d of docs) {
    const hash = docHash(d.document);
    await c.query(
      `INSERT INTO role_policies(role_id, kind, name, arn, aws_managed, document, doc_hash) VALUES ($1,$2,$3,$4,$5,$6,$7)
       ON CONFLICT (role_id, kind, name) DO UPDATE SET arn=EXCLUDED.arn, aws_managed=EXCLUDED.aws_managed, document=EXCLUDED.document, doc_hash=EXCLUDED.doc_hash`,
      [roleId, d.kind, d.name, d.arn, d.aws, JSON.stringify(d.document), hash]);
    await c.query(`INSERT INTO policy_history(role_id, kind, name, doc_hash, document) VALUES ($1,$2,$3,$4,$5) ON CONFLICT DO NOTHING`,
      [roleId, d.kind, d.name, hash, JSON.stringify(d.document)]);
  }
}

/**
 * IAM users, stored as roles of kind 'iam-user' so everything that analyses roles analyses them. Returns the ARNs
 * seen, or null when the scanner role cannot list users (created before it could): stored users are then kept.
 */
const USER_READS = 'iam:ListUsers, iam:GetUser, iam:ListAccessKeys, iam:GetAccessKeyLastUsed, iam:ListMFADevices, iam:GetLoginProfile, iam:ListGroupsForUser and the user and group policy reads';
export async function inventoryUsers(ctx, account, gw) {
  if (!gw.listUsers) return null;
  let users;
  // IAM users are optional: a scanner role without the user reads (any of them), or any other failure here, skips users
  // with a warning and never fails the scan. Users already stored are kept (null: nothing is marked deleted).
  const skip = (e) => {
    const denied = /AccessDenied|not authorized/i.test(`${e.name} ${e.message}`);
    const action = String(e.message).match(/perform: (\S+)/)?.[1];
    ctx.log(denied
      ? `IAM users skipped: the scanner role cannot ${action ? `call ${action}` : 'read them'}. Add ${USER_READS} to it; roles are scanned as usual and stored users are kept.`
      : `IAM users skipped: ${e.message}. Roles are scanned as usual and stored users are kept.`, null, 'warn');
    return null;
  };
  try { users = await gw.listUsers(); } catch (e) { return skip(e); }
  await ctx.progress({ phase: 'users', total: users.length, done: 0 });
  let done = 0;
  try { await limited(users, 4, async (u) => {
    const [detail, pol] = await Promise.all([gw.getUserDetail(u.name), gw.getUserPolicies(u.name)]);
    const docs = [...pol.inline.map((p) => ({ kind: 'inline', name: p.name, arn: null, aws: false, document: p.document }))];
    for (const a of pol.attached) { const m = await managedDoc(gw, a); docs.push({ kind: 'managed', name: m.name, arn: m.arn, aws: m.awsManaged, document: m.document }); }
    for (const g of pol.groups || []) {
      for (const p of g.inline) docs.push({ kind: 'group', name: `${g.group}/${p.name}`, arn: null, aws: false, document: p.document });
      for (const a of g.attached) { const m = await managedDoc(gw, a); docs.push({ kind: 'group', name: `${g.group}/${m.name}`, arn: m.arn, aws: m.awsManaged, document: m.document }); }
    }
    const lastKey = detail.keys.map((k) => k.lastUsed).filter(Boolean).sort((a, b) => new Date(b) - new Date(a))[0] || null;
    const lastUsed = [lastKey, u.passwordLastUsed].filter(Boolean).sort((a, b) => new Date(b) - new Date(a))[0] || null;
    const lastRegion = lastKey ? detail.keys.find((k) => k.lastUsed === lastKey)?.region || null : null;
    await tx(async (c) => {
      // what was stored before, to record what changed (nothing is recorded the first time a user is seen)
      const prev = (await c.query(`SELECT r.id, r.deleted_at, d.password_enabled, d.mfa FROM roles r LEFT JOIN iam_user_details d ON d.role_id = r.id
                                    WHERE r.account_id=$1 AND r.arn=$2 FOR UPDATE OF r`, [account.id, u.arn])).rows[0];
      const prevKeys = prev ? new Map((await c.query('SELECT key_id, status FROM iam_access_keys WHERE role_id=$1 AND deleted_at IS NULL', [prev.id])).rows.map((k) => [k.key_id, k.status])) : new Map();
      const row = (await c.query(
        `INSERT INTO roles(account_id, arn, name, path, kind, trust_policy, tags, created_in_aws, last_used_at, last_used_region, inline_count, attached_count, aws_id, deleted_at)
         VALUES ($1,$2,$3,$4,'iam-user',NULL,$5,$6,$7,$8,$9,$10,$11,NULL)
         ON CONFLICT (account_id, arn) DO UPDATE SET tags=EXCLUDED.tags, kind='iam-user', last_used_at=EXCLUDED.last_used_at, last_used_region=EXCLUDED.last_used_region,
           inline_count=EXCLUDED.inline_count, attached_count=EXCLUDED.attached_count, aws_id=COALESCE(EXCLUDED.aws_id, roles.aws_id), deleted_at=NULL
         RETURNING id`,
        [account.id, u.arn, u.name, u.path || '/', JSON.stringify(detail.tags || {}), u.createDate, lastUsed, lastRegion,
         docs.filter((d) => d.kind === 'inline').length, docs.filter((d) => d.kind !== 'inline').length, u.userId || null])).rows[0];
      await savePolicies(c, row.id, docs, { record: !!prev });
      if (prev) {
        if (prev.deleted_at) await event(c, row.id, 'restored', 'IAM user seen again after it was gone');
        if (prev.password_enabled != null && prev.password_enabled !== !!detail.password) await event(c, row.id, 'password', detail.password ? 'Console password created' : 'Console password removed');
        const was = (prev.mfa || []).map((m) => m.serial), now = (detail.mfa || []).map((m) => m.serial);
        for (const s of now.filter((x) => !was.includes(x))) await event(c, row.id, 'mfa', 'MFA device added', { serial: s });
        for (const s of was.filter((x) => !now.includes(x))) await event(c, row.id, 'mfa', 'MFA device removed', { serial: s });
        for (const k of detail.keys) {
          const before = prevKeys.get(k.id);
          if (before && k.status && before !== k.status) await event(c, row.id, 'key-status', `Access key ${k.id} ${k.status === 'Inactive' ? 'deactivated' : 'activated'}`, { key: k.id, from: before, to: k.status });
        }
      }
      await c.query(
        `INSERT INTO iam_user_details(role_id, user_id, password_enabled, password_created, password_last_used, mfa, groups, updated_at) VALUES ($1,$2,$3,$4,$5,$6,$7,now())
         ON CONFLICT (role_id) DO UPDATE SET user_id=EXCLUDED.user_id, password_enabled=EXCLUDED.password_enabled, password_created=EXCLUDED.password_created,
           password_last_used=EXCLUDED.password_last_used, mfa=EXCLUDED.mfa, groups=EXCLUDED.groups, updated_at=now()`,
        [row.id, u.userId || null, !!detail.password, detail.password?.created || null, u.passwordLastUsed || null, JSON.stringify(detail.mfa || []), detail.groups || []]);
      for (const k of detail.keys) await c.query(
        `INSERT INTO iam_access_keys(role_id, key_id, status, created_at, last_used_at, last_used_service, last_used_region, deleted_at) VALUES ($1,$2,$3,$4,$5,$6,$7,NULL)
         ON CONFLICT (role_id, key_id) DO UPDATE SET status=EXCLUDED.status, created_at=EXCLUDED.created_at, last_used_at=EXCLUDED.last_used_at,
           last_used_service=EXCLUDED.last_used_service, last_used_region=EXCLUDED.last_used_region, deleted_at=NULL`,
        [row.id, k.id, k.status, k.created, k.lastUsed, k.service, k.region]);
      await c.query(`UPDATE iam_access_keys SET deleted_at=now(), status='Deleted' WHERE role_id=$1 AND deleted_at IS NULL AND NOT (key_id = ANY($2))`, [row.id, detail.keys.map((k) => k.id)]);
    });
    await ctx.progress({ done: ++done });
  }); } catch (e) { return skip(e); }
  return users.map((u) => u.arn);
}

/** Marks identities no longer in AWS as gone (their history is kept) and records it. */
async function markGone(accountId, kindSql, seen, title) {
  const gone = (await query(`UPDATE roles SET deleted_at=now() WHERE account_id=$1 AND ${kindSql} AND deleted_at IS NULL AND NOT (arn = ANY($2)) RETURNING id`, [accountId, seen])).rows;
  if (gone.length) await query(`INSERT INTO identity_events(role_id, kind, title) SELECT id, 'deleted', $2 FROM unnest($1::uuid[]) AS id`, [gone.map((g) => g.id), title]);
}

/**
 * Roles with their trust policy, boundary and policies. For a role already stored, what changed is written to its
 * history. Returns the ARNs seen.
 */
export async function inventoryRoles(ctx, account, gw) {
  const roles = await gw.listRoles();
  await ctx.progress({ phase: 'inventory', total: roles.length, done: 0 });
  const seen = [];
  let done = 0;
  await limited(roles, 4, async (r) => {
    const detail = await gw.getRoleDetail(r.name);
    const pol = await gw.getRolePolicies(r.name);
    const managed = [];
    for (const a of pol.attached) managed.push(await managedDoc(gw, a));
    const kind = roleKind(r.name, r.path);
    await tx(async (c) => {
      const prev = (await c.query('SELECT id, trust_policy, boundary_arn, deleted_at FROM roles WHERE account_id=$1 AND arn=$2 FOR UPDATE', [account.id, r.arn])).rows[0];
      const row = (await c.query(
        `INSERT INTO roles(account_id, arn, name, path, kind, permission_set, trust_policy, boundary_arn, tags, created_in_aws,
                           last_used_at, last_used_region, inline_count, attached_count, aws_id, deleted_at)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,NULL)
         ON CONFLICT (account_id, arn) DO UPDATE SET trust_policy=EXCLUDED.trust_policy, boundary_arn=EXCLUDED.boundary_arn, tags=EXCLUDED.tags,
           kind=EXCLUDED.kind, permission_set=EXCLUDED.permission_set, last_used_at=EXCLUDED.last_used_at, last_used_region=EXCLUDED.last_used_region,
           inline_count=EXCLUDED.inline_count, attached_count=EXCLUDED.attached_count, aws_id=COALESCE(EXCLUDED.aws_id, roles.aws_id), deleted_at=NULL
         RETURNING id`,
        [account.id, r.arn, r.name, r.path, kind, kind === 'identity-center' ? r.name.split('_')[1] : null, JSON.stringify(r.trustPolicy),
         r.boundaryArn, JSON.stringify(detail.tags), r.createDate, detail.lastUsedAt, detail.lastUsedRegion, pol.inline.length, pol.attached.length, r.awsId || null])).rows[0];
      if (prev) {
        if (prev.deleted_at) await event(c, row.id, 'restored', 'Role seen again after it was gone');
        if (prev.trust_policy && docHash(prev.trust_policy) !== docHash(r.trustPolicy)) {
          await event(c, row.id, 'trust-changed', 'Trust policy changed', { name: 'Trust policy', before: prev.trust_policy, after: r.trustPolicy });
        }
        if ((prev.boundary_arn || null) !== (r.boundaryArn || null)) {
          await event(c, row.id, 'boundary-changed', r.boundaryArn ? (prev.boundary_arn ? 'Permission boundary replaced' : 'Permission boundary set') : 'Permission boundary removed',
            { from: prev.boundary_arn || null, to: r.boundaryArn || null });
        }
      }
      const docs = [
        ...pol.inline.map((p) => ({ kind: 'inline', name: p.name, arn: null, aws: false, document: p.document })),
        ...managed.map((p) => ({ kind: 'managed', name: p.name, arn: p.arn, aws: p.awsManaged, document: p.document })),
      ];
      await savePolicies(c, row.id, docs, { record: !!prev });
    });
    seen.push(r.arn);
    await ctx.progress({ done: ++done });
  });
  return seen;
}

export async function runInventory(ctx) {
  let account, gw;
  try {
    ({ account, gw } = await loadContext(ctx.job.account_id));
    const verified = await gw.verify();
    if (verified.accountId !== account.account_id) {
      throw Object.assign(new Error(`role belongs to account ${verified.accountId}, expected ${account.account_id}`), { retryable: false });
    }
  } catch (e) {
    // Show the reason on the account itself so the person onboarding it can fix the trust policy or ExternalId.
    if (e.name === 'CredentialsProviderError' || /Could not load credentials/i.test(e.message)) {
      e.message = 'The worker has no AWS credentials to start from. Give the worker an instance, task or pod role, put keys in its .env, or store keys on this account (Edit account).';
    }
    if (e.retryable === false || /AccessDenied|not authorized|ExternalId|InvalidClientTokenId|SignatureDoesNotMatch|no AWS credentials/i.test(`${e.name} ${e.message}`)) {
      await query(`UPDATE cloud_accounts SET status='error', status_detail=$2 WHERE id=$1`,
        [ctx.job.account_id, JSON.stringify({ message: String(e.message).slice(0, 400), at: new Date().toISOString() })]);
      e.retryable = false;
    }
    throw e;
  }
  const seen = await inventoryRoles(ctx, account, gw);
  // roles that disappeared keep their history but stop being analysed
  await markGone(account.id, "kind <> 'iam-user'", seen, 'Role deleted in AWS');
  const userArns = await inventoryUsers(ctx, account, gw);
  if (userArns) await markGone(account.id, "kind = 'iam-user'", userArns, 'IAM user deleted in AWS');


  // SAML providers and who issues for them: tells IAM Identity Center instances apart. A scanner role created before
  // iam:ListSAMLProviders / iam:GetSAMLProvider were part of its policy cannot read them: keep what is stored and say so.
  if (gw.listSamlProviders) {
    try {
      const providers = await gw.listSamlProviders();
      await tx(async (c) => {
        await c.query('DELETE FROM saml_providers WHERE account_id=$1 AND NOT (arn = ANY($2))', [account.id, providers.map((p) => p.arn)]);
        for (const p of providers) await c.query(
          `INSERT INTO saml_providers(account_id, arn, name, issuer, created_at, seen_at) VALUES ($1,$2,$3,$4,$5,now())
           ON CONFLICT (account_id, arn) DO UPDATE SET name=EXCLUDED.name, issuer=EXCLUDED.issuer, created_at=EXCLUDED.created_at, seen_at=now()`,
          [account.id, p.arn, p.name, p.issuer, p.createdAt]);
      });
    } catch (e) {
      if (!/AccessDenied|not authorized/i.test(`${e.name} ${e.message}`)) throw e;
      ctx.log('cannot read SAML providers: add iam:ListSAMLProviders and iam:GetSAMLProvider to the scanner role so IAM Identity Center instances can be told apart', null, 'warn');
    }
  }

  // buckets and other resources that have data events turned on
  const found =await gw.discoverDataEvents().catch((e) => { ctx.log(`data event discovery failed: ${e.message}`, null, 'warn'); return []; });
  await tx(async (c) => {
    await c.query('DELETE FROM data_event_sources WHERE account_id=$1', [account.id]);
    for (const f of found) {
      await c.query(
        `INSERT INTO data_event_sources(account_id, source_name, source_type, resource_type, arn_patterns, read_write, readable)
         VALUES ($1,$2,$3,$4,$5,$6,$7) ON CONFLICT DO NOTHING`,
        [account.id, f.name, f.type, f.resourceType, f.arnPatterns, f.readWrite,
         account.event_source === 's3' && !!f.bucket && f.bucket === account.s3_bucket]);   // readable: we ingest this trail's files
    }
  });
  await query(`UPDATE cloud_accounts SET status='connected', status_detail=NULL WHERE id=$1`, [account.id]);
  return { roles: seen.length, users: userArns ? userArns.length : null, dataEventSources: found.length };
}
