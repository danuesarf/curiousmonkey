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
    if (e.retryable === false || /AccessDenied|not authorized|ExternalId|InvalidClientTokenId/i.test(`${e.name} ${e.message}`)) {
      await query(`UPDATE cloud_accounts SET status='error', status_detail=$2 WHERE id=$1`,
        [ctx.job.account_id, JSON.stringify({ message: String(e.message).slice(0, 400), at: new Date().toISOString() })]);
      e.retryable = false;
    }
    throw e;
  }
  const roles = await gw.listRoles();
  await ctx.progress({ phase: 'inventory', total: roles.length, done: 0 });
  const seen = [];
  let done = 0;
  await limited(roles, 4, async (r) => {
    const detail = await gw.getRoleDetail(r.name);
    const pol = await gw.getRolePolicies(r.name);
    const managed = [];
    for (const a of pol.attached) {
      const cached = a.awsManaged ? (await query(
        `SELECT document FROM managed_policy_cache WHERE arn=$1 AND fetched_at > now() - interval '7 days' ORDER BY fetched_at DESC LIMIT 1`, [a.arn])).rows[0] : null;
      if (cached) { managed.push({ ...a, document: cached.document }); continue; }
      const m = await gw.getManagedPolicy(a.arn);
      await query(`INSERT INTO managed_policy_cache(arn, version_id, document) VALUES ($1,$2,$3) ON CONFLICT (arn, version_id) DO UPDATE SET fetched_at=now()`,
        [a.arn, m.versionId, JSON.stringify(m.document)]);
      managed.push({ ...a, document: m.document });
    }
    const kind = roleKind(r.name, r.path);
    await tx(async (c) => {
      const row = (await c.query(
        `INSERT INTO roles(account_id, arn, name, path, kind, permission_set, trust_policy, boundary_arn, tags, created_in_aws,
                           last_used_at, last_used_region, inline_count, attached_count, deleted_at)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,NULL)
         ON CONFLICT (account_id, arn) DO UPDATE SET trust_policy=EXCLUDED.trust_policy, boundary_arn=EXCLUDED.boundary_arn, tags=EXCLUDED.tags,
           kind=EXCLUDED.kind, permission_set=EXCLUDED.permission_set, last_used_at=EXCLUDED.last_used_at, last_used_region=EXCLUDED.last_used_region,
           inline_count=EXCLUDED.inline_count, attached_count=EXCLUDED.attached_count, deleted_at=NULL
         RETURNING id`,
        [account.id, r.arn, r.name, r.path, kind, kind === 'identity-center' ? r.name.split('_')[1] : null, JSON.stringify(r.trustPolicy),
         r.boundaryArn, JSON.stringify(detail.tags), r.createDate, detail.lastUsedAt, detail.lastUsedRegion, pol.inline.length, pol.attached.length])).rows[0];
      const docs = [
        ...pol.inline.map((p) => ({ kind: 'inline', name: p.name, arn: null, aws: false, document: p.document })),
        ...managed.map((p) => ({ kind: 'managed', name: p.name, arn: p.arn, aws: p.awsManaged, document: p.document })),
      ];
      await c.query(`DELETE FROM role_policies WHERE role_id=$1 AND NOT (kind||':'||name = ANY($2))`, [row.id, docs.map((d) => `${d.kind}:${d.name}`)]);
      for (const d of docs) {
        const hash = docHash(d.document);
        await c.query(
          `INSERT INTO role_policies(role_id, kind, name, arn, aws_managed, document, doc_hash) VALUES ($1,$2,$3,$4,$5,$6,$7)
           ON CONFLICT (role_id, kind, name) DO UPDATE SET arn=EXCLUDED.arn, aws_managed=EXCLUDED.aws_managed, document=EXCLUDED.document, doc_hash=EXCLUDED.doc_hash`,
          [row.id, d.kind, d.name, d.arn, d.aws, JSON.stringify(d.document), hash]);
        await c.query(`INSERT INTO policy_history(role_id, kind, name, doc_hash, document) VALUES ($1,$2,$3,$4,$5) ON CONFLICT DO NOTHING`,
          [row.id, d.kind, d.name, hash, JSON.stringify(d.document)]);
      }
    });
    seen.push(r.arn);
    await ctx.progress({ done: ++done });
  });
  // roles that disappeared keep their history but stop being analysed
  await query(`UPDATE roles SET deleted_at=now() WHERE account_id=$1 AND deleted_at IS NULL AND NOT (arn = ANY($2))`, [account.id, seen]);

  // buckets and other resources that have data events turned on
  const found = await gw.discoverDataEvents().catch((e) => { ctx.log(`data event discovery failed: ${e.message}`, null, 'warn'); return []; });
  await tx(async (c) => {
    await c.query('DELETE FROM data_event_sources WHERE account_id=$1', [account.id]);
    for (const f of found) {
      await c.query(
        `INSERT INTO data_event_sources(account_id, source_name, source_type, resource_type, arn_patterns, read_write, readable)
         VALUES ($1,$2,$3,$4,$5,$6,false) ON CONFLICT DO NOTHING`,
        [account.id, f.name, f.type, f.resourceType, f.arnPatterns, f.readWrite]);
    }
  });
  await query(`UPDATE cloud_accounts SET status='connected', status_detail=NULL WHERE id=$1`, [account.id]);
  return { roles: roles.length, dataEventSources: found.length };
}
