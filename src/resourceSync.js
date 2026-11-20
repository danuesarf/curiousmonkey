// Resource access: storing what the scanner read, and keeping the analysis current.
// The scanner reads each service's resources with the account's inventory (inventoryResources). What a policy means
// also depends on the estate: an account onboarded later is no longer "outside", and a control given another
// severity or turned off changes the findings. resourceTick works everything out again when any of that changes;
// an advisory lock lets one worker at a time do it.
import { query, tx, pool } from './db.js';
import { analyzeResource, worstOf, SERVICES } from './analyzer/resourcePolicy.js';
import { docHash } from './analyzer/policy.js';
import { loadPolicy } from './controls.js';
import { knownVendor } from './trustmap.js';
import { config } from './config.js';
import { loadOwnership } from './gcp/ownership.js';
import { analyzeGcpResource } from './gcp/resources.js';

export const RESOURCE_SERVICES = Object.keys(SERVICES);
const LOCK = 727013;
const VERSION = 3;              // bump when the analysis itself changes, so stored results are worked out again
const CHUNK = 500;
const READS = {
  s3: 's3:ListAllMyBuckets, s3:GetBucketPolicy, s3:GetBucketPublicAccessBlock, s3:GetBucketLocation and s3:GetAccountPublicAccessBlock',
  kms: 'kms:ListKeys, kms:ListAliases, kms:DescribeKey and kms:GetKeyPolicy',
  dynamodb: 'dynamodb:ListTables and dynamodb:GetResourcePolicy',
  sqs: 'sqs:ListQueues and sqs:GetQueueAttributes',
  sns: 'sns:ListTopics and sns:GetTopicAttributes',
  secretsmanager: 'secretsmanager:ListSecrets and secretsmanager:GetResourcePolicy',
  lambda: 'lambda:ListFunctions and lambda:GetPolicy',
  ecr: 'ecr:DescribeRepositories and ecr:GetRepositoryPolicy',
};
const denied = (e) => /AccessDenied|not authorized|UnauthorizedOperation|AuthorizationError|don't have permissions/i.test(`${e.name} ${e.message}`);

/** Which accounts are yours, your organisations, known vendors; the workspace's policy; and a signature of all of it. */
export async function estateFor() {
  const [accounts, org, policy, gproj, seen] = await Promise.all([
    query('SELECT account_id, name, aws_org_id FROM cloud_accounts').then((r) => r.rows),
    query('SELECT account_id, name FROM org_accounts').then((r) => r.rows).catch(() => []),
    loadPolicy(),
    query(`SELECT p.connection_id, p.project_id, c.status_detail->>'domain' AS domain FROM gcp_projects p JOIN gcp_connections c ON c.id = p.connection_id`).then((r) => r.rows).catch(() => []),
    query(`SELECT md5(string_agg(project_id || ':' || coalesce(organization, ''), ',' ORDER BY project_id)) AS h FROM gcp_seen_projects`).then((r) => r.rows[0]?.h || '', () => ''),
  ]);
  const estate = { connected: new Map(accounts.map((a) => [a.account_id, a.name])), org: new Map(org.map((x) => [x.account_id, x.name])),
    orgIds: new Set(accounts.map((a) => a.aws_org_id).filter(Boolean)), vendor: knownVendor };
  const sig = docHash({ v: VERSION, c: [...estate.connected.keys()].sort(), o: [...estate.org.keys()].sort(), i: [...estate.orgIds].sort(), p: policy.sig,
    g: gproj.map((x) => `${x.connection_id}:${x.project_id}:${x.domain || ''}`).sort(),
    // whose projects and domains are yours (Configuration, and the projects the readers can see)
    w: [config.gcp.ownProjects || [], config.gcp.ownDomains || [], seen] });
  return { estate, policy, sig };
}

const cols = (rows, k) => rows.map((r) => r[k]);
const json = (v) => JSON.stringify(v);

/**
 * Saves analyses: each resource's exposure, grants and worst finding, its findings (opened, updated, resolved), and,
 * for `feed` items (a policy that changed, a resource that appeared on a later scan), the change feed.
 * A decision stays with a finding while its grant (actions and conditions) stays the same.
 */
async function saveAnalyses(c, items) {
  if (!items.length) return { opened: 0, resolved: 0, changes: 0 };
  for (let i = 0; i < items.length; i += CHUNK) {
    const part = items.slice(i, i + CHUNK);
    await c.query(
      `UPDATE resources r SET exposure = x.e, grants = x.g::jsonb, worst = x.w
         FROM unnest($1::uuid[], $2::text[], $3::text[], $4::text[]) AS x(id, e, g, w)
        WHERE r.id = x.id AND (r.exposure, r.grants, r.worst) IS DISTINCT FROM (x.e, x.g::jsonb, x.w)`,
      [cols(part, 'id'), cols(part, 'exposure'), part.map((x) => json(x.grants)), part.map((x) => worstOf(x.findings))]);
  }
  const rows = items.flatMap((x) => x.findings.map((f) => ({ ...f, resource: x.id, account: x.accountId, feed: !!x.feed, resourceName: x.name, service: x.service })));
  let opened = 0, changes = 0;
  const feed = [];
  for (let i = 0; i < rows.length; i += CHUNK) {
    const part = rows.slice(i, i + CHUNK);
    const r = await c.query(
      `INSERT INTO resource_findings(resource_id, key, control, severity, title, detail, suggestion, principal, principal_account, statement, sid, actions, conditions, status, updated_at)
       SELECT x.r, x.k, x.ct, x.sv, x.t, x.d, x.sg, x.p, x.pa, x.st, x.sid, ARRAY(SELECT jsonb_array_elements_text(x.ac::jsonb)), ARRAY(SELECT jsonb_array_elements_text(x.co::jsonb)), 'open', now()
         FROM unnest($1::uuid[], $2::text[], $3::text[], $4::text[], $5::text[], $6::text[], $7::text[], $8::text[], $9::text[], $10::int[], $11::text[], $12::text[], $13::text[])
              AS x(r, k, ct, sv, t, d, sg, p, pa, st, sid, ac, co)
       ON CONFLICT (resource_id, key) DO UPDATE SET control = EXCLUDED.control, severity = EXCLUDED.severity, title = EXCLUDED.title, detail = EXCLUDED.detail,
         suggestion = EXCLUDED.suggestion, principal = EXCLUDED.principal, principal_account = EXCLUDED.principal_account, statement = EXCLUDED.statement, sid = EXCLUDED.sid,
         actions = EXCLUDED.actions, conditions = EXCLUDED.conditions, status = 'open', resolved_at = NULL, updated_at = now(),
         decision   = CASE WHEN (resource_findings.actions, resource_findings.conditions) IS DISTINCT FROM (EXCLUDED.actions, EXCLUDED.conditions) THEN NULL ELSE resource_findings.decision END,
         note       = CASE WHEN (resource_findings.actions, resource_findings.conditions) IS DISTINCT FROM (EXCLUDED.actions, EXCLUDED.conditions) THEN NULL ELSE resource_findings.note END,
         decided_by = CASE WHEN (resource_findings.actions, resource_findings.conditions) IS DISTINCT FROM (EXCLUDED.actions, EXCLUDED.conditions) THEN NULL ELSE resource_findings.decided_by END,
         decided_at = CASE WHEN (resource_findings.actions, resource_findings.conditions) IS DISTINCT FROM (EXCLUDED.actions, EXCLUDED.conditions) THEN NULL ELSE resource_findings.decided_at END
       WHERE (resource_findings.control, resource_findings.severity, resource_findings.title, resource_findings.detail, coalesce(resource_findings.suggestion, ''), resource_findings.status,
              resource_findings.actions, resource_findings.conditions)
          IS DISTINCT FROM (EXCLUDED.control, EXCLUDED.severity, EXCLUDED.title, EXCLUDED.detail, coalesce(EXCLUDED.suggestion, ''), 'open', EXCLUDED.actions, EXCLUDED.conditions)
       RETURNING (xmax = 0) AS inserted, resource_id, key`,
      [cols(part, 'resource'), cols(part, 'key'), cols(part, 'control'), cols(part, 'severity'), cols(part, 'title'), cols(part, 'detail'), cols(part, 'suggestion'),
       cols(part, 'principal'), cols(part, 'principalAccount'), cols(part, 'statement'), cols(part, 'sid'), part.map((f) => json(f.actions)), part.map((f) => json(f.conditions))]);
    const fresh = new Set(r.rows.filter((x) => x.inserted).map((x) => `${x.resource_id}|${x.key}`));
    opened += fresh.size;
    for (const f of part) if (f.feed && fresh.has(`${f.resource}|${f.key}`)) feed.push(f);
  }
  const res = await c.query(
    `UPDATE resource_findings f SET status = 'resolved', resolved_at = now(), updated_at = now()
      WHERE f.resource_id = ANY($1::uuid[]) AND f.status = 'open'
        AND NOT EXISTS (SELECT 1 FROM unnest($2::uuid[], $3::text[]) AS x(r, k) WHERE x.r = f.resource_id AND x.k = f.key)`,
    [cols(items, 'id'), cols(rows, 'resource'), cols(rows, 'key')]);

  // the change feed (Radar's bell, alerts): a resource opened to anyone, or shared outside the estate
  const ch = feed.filter((f) => f.account && (f.control === 'res.public' || f.control === 'res.external-account') && f.severity !== 'low').map((f) => {
    const pub = f.control === 'res.public', label = SERVICES[f.service]?.label || f.service;
    return { account: f.account, kind: pub ? 'resource-public' : 'resource-shared', severity: f.severity === 'high' ? 'high' : 'warn',
      title: pub ? `${label} ${f.resourceName} opened to anyone` : `${label} ${f.resourceName} shared with ${f.principalAccount || f.principal}`,
      detail: `${f.detail}`.slice(0, 1000), dedupe: `res:${f.resource}:${f.key}:${new Date().toISOString().slice(0, 10)}`.slice(0, 500) };
  });
  if (ch.length) {
    changes = (await c.query(
      `INSERT INTO changes(account_id, role_id, kind, severity, title, detail, dedupe)
       SELECT a, NULL, k, s, t, d, dd FROM unnest($1::uuid[], $2::text[], $3::text[], $4::text[], $5::text[], $6::text[]) AS x(a, k, s, t, d, dd)
       ON CONFLICT (dedupe) DO NOTHING`,
      [cols(ch, 'account'), cols(ch, 'kind'), cols(ch, 'severity'), cols(ch, 'title'), cols(ch, 'detail'), cols(ch, 'dedupe')])).rowCount;
  }
  return { opened, resolved: res.rowCount, changes };
}

/**
 * Scanner step: every service's resources and their policies. Each service is optional: a scanner role that may not
 * list it (created before these reads were in its policy) skips it with a warning, and what is stored for it stays.
 */
export async function inventoryResources(ctx, account, gw) {
  if (!gw.listResources) return null;
  if (gw.organizationId) {
    try {
      const id = await gw.organizationId();
      await query('UPDATE cloud_accounts SET aws_org_id = $2 WHERE id = $1 AND aws_org_id IS DISTINCT FROM $2', [account.id, id]);
    } catch (e) {
      if (/AWSOrganizationsNotInUse/i.test(`${e.name} ${e.message}`)) await query('UPDATE cloud_accounts SET aws_org_id = NULL WHERE id = $1', [account.id]);
      else if (!denied(e)) ctx.log(`organisation not read: ${e.message}`, null, 'warn');
    }
  }
  const { estate, policy } = await estateFor();
  const counts = {}, skipped = [];
  let done = 0, opened = 0, changes = 0;
  await ctx.progress({ phase: 'resources', total: RESOURCE_SERVICES.length, done: 0 });
  for (const svc of RESOURCE_SERVICES) {
    let items;
    try { items = await gw.listResources(svc); }
    catch (e) {
      skipped.push(svc);
      ctx.log(denied(e)
        ? `${SERVICES[svc].short} resource policies skipped: the scanner role cannot list them. Add ${READS[svc]} to it (Accounts → Edit shows the policy); what is stored stays.`
        : `${SERVICES[svc].short} resource policies not read: ${e.message}. What is stored stays.`, null, 'warn');
      await ctx.progress({ done: ++done });
      continue;
    }
    const r = await tx(async (c) => {
      const prev = new Map((await c.query('SELECT id, arn, doc_hash, deleted_at FROM resources WHERE account_id = $1 AND service = $2', [account.id, svc])).rows.map((x) => [x.arn, x]));
      const hadAny = prev.size > 0;
      const saved = [];
      for (let i = 0; i < items.length; i += CHUNK) {
        const part = items.slice(i, i + CHUNK).map((x) => ({ ...x, hash: x.policy ? docHash(x.policy) : null, extra: { ...(x.extra || {}), ...(x.unreadable ? { unreadable: x.unreadable } : {}) } }));
        const rows = (await c.query(
          `INSERT INTO resources(account_id, service, arn, name, region, policy, doc_hash, extra, seen_at, policy_changed_at, deleted_at)
           SELECT $1, $2, x.arn, x.name, x.region, x.p::jsonb, x.h, x.e::jsonb, now(), CASE WHEN x.h IS NULL THEN NULL ELSE now() END, NULL
             FROM unnest($3::text[], $4::text[], $5::text[], $6::text[], $7::text[], $8::text[]) AS x(arn, name, region, p, h, e)
           ON CONFLICT (account_id, arn) DO UPDATE SET name = EXCLUDED.name, region = EXCLUDED.region, policy = EXCLUDED.policy, extra = EXCLUDED.extra, seen_at = now(), deleted_at = NULL,
             policy_changed_at = CASE WHEN resources.doc_hash IS DISTINCT FROM EXCLUDED.doc_hash THEN now() ELSE resources.policy_changed_at END, doc_hash = EXCLUDED.doc_hash
           RETURNING id, arn`,
          [account.id, svc, cols(part, 'arn'), cols(part, 'name'), cols(part, 'region'), part.map((x) => (x.policy ? json(x.policy) : null)), cols(part, 'hash'), part.map((x) => json(x.extra))])).rows;
        const ids = new Map(rows.map((x) => [x.arn, x.id]));
        for (const x of part) {
          const before = prev.get(x.arn);
          const a = analyzeResource({ ...x, accountId: account.account_id }, estate, policy);
          saved.push({ id: ids.get(x.arn), accountId: account.id, name: x.name, service: svc, ...a,
            feed: before ? before.doc_hash !== x.hash || !!before.deleted_at : hadAny });
        }
      }
      // gone from AWS: kept for the record, its findings closed
      const gone = (await c.query(`UPDATE resources SET deleted_at = now() WHERE account_id = $1 AND service = $2 AND deleted_at IS NULL AND NOT (arn = ANY($3)) RETURNING id`,
        [account.id, svc, items.map((x) => x.arn)])).rows.map((x) => x.id);
      if (gone.length) await c.query(`UPDATE resource_findings SET status = 'resolved', resolved_at = now(), updated_at = now() WHERE resource_id = ANY($1) AND status = 'open'`, [gone]);
      return saveAnalyses(c, saved);
    });
    counts[svc] = items.length; opened += r.opened; changes += r.changes;
    await ctx.progress({ done: ++done });
  }
  return { resources: counts, skipped, findingsOpened: opened, changes };
}

// ------------------------------------------------------------------ Google Cloud
/**
 * What a Google Cloud resource policy means depends on: the organisation's domain, which projects are this
 * connection's (and which another connection's), the AWS accounts behind federated identities, and what each role allows.
 */
async function gcpEstate(connId, { domain, providers, roleDefs } = {}) {
  const [projects, conn, prov, accounts] = await Promise.all([
    query('SELECT connection_id, project_id FROM gcp_projects').then((r) => r.rows),
    domain === undefined ? query(`SELECT status_detail->>'domain' AS domain FROM gcp_connections WHERE id = $1`, [connId]).then((r) => r.rows[0]?.domain || null) : domain,
    providers ? Promise.resolve(providers) : query('SELECT * FROM gcp_wif_providers WHERE connection_id = $1', [connId]).then((r) => r.rows),
    query('SELECT account_id, name FROM cloud_accounts').then((r) => r.rows),
  ]);
  return { domain: conn, own: await loadOwnership({ domains: [conn] }), providers: prov, roleDefs: roleDefs || null, awsAccounts: new Map(accounts.map((a) => [a.account_id, a.name])),
    projects: new Set(projects.filter((p) => p.connection_id === connId).map((p) => p.project_id)),
    otherProjects: new Set(projects.filter((p) => p.connection_id !== connId).map((p) => p.project_id)) };
}
async function roleDefsFor(resources) {
  const roles = [...new Set(resources.flatMap((r) => (r.policy?.bindings || []).map((b) => b.role)))];
  if (!roles.length) return new Map();
  return new Map((await query('SELECT name, permissions FROM gcp_role_defs WHERE name = ANY($1)', [roles])).rows.map((r) => [r.name, r.permissions]));
}

/**
 * Google Cloud scan step: the connection's resources with resource-level IAM policies, analysed and stored. The
 * connection's resources are replaced: one gone from the read is kept for the record, its findings closed.
 */
export async function saveGcpResources(conn, items, info = {}) {
  const { policy } = await estateFor();
  const estate = await gcpEstate(conn.id, { domain: info.domain ?? undefined, providers: info.providers, roleDefs: info.roleDefs || await roleDefsFor(items) });
  return tx(async (c) => {
    const saved = [];
    for (let i = 0; i < items.length; i += CHUNK) {
      const part = items.slice(i, i + CHUNK).map((x) => ({ ...x, hash: x.policy ? docHash(x.policy) : null }));
      const rows = (await c.query(
        `INSERT INTO resources(cloud, account_id, gcp_connection_id, project_id, service, arn, name, region, policy, doc_hash, extra, seen_at, policy_changed_at, deleted_at)
         SELECT 'gcp', NULL, $1, x.pr, x.s, x.arn, x.name, x.region, x.p::jsonb, x.h, x.e::jsonb, now(), CASE WHEN x.h IS NULL THEN NULL ELSE now() END, NULL
           FROM unnest($2::text[], $3::text[], $4::text[], $5::text[], $6::text[], $7::text[], $8::text[], $9::text[]) AS x(pr, s, arn, name, region, p, h, e)
         ON CONFLICT (gcp_connection_id, arn) WHERE gcp_connection_id IS NOT NULL DO UPDATE SET project_id = EXCLUDED.project_id, service = EXCLUDED.service, name = EXCLUDED.name,
           region = EXCLUDED.region, policy = EXCLUDED.policy, extra = EXCLUDED.extra, seen_at = now(), deleted_at = NULL,
           policy_changed_at = CASE WHEN resources.doc_hash IS DISTINCT FROM EXCLUDED.doc_hash THEN now() ELSE resources.policy_changed_at END, doc_hash = EXCLUDED.doc_hash
         RETURNING id, arn`,
        [conn.id, cols(part, 'project_id'), cols(part, 'service'), cols(part, 'arn'), cols(part, 'name'), cols(part, 'region'), part.map((x) => (x.policy ? json(x.policy) : null)), cols(part, 'hash'),
          part.map((x) => json({ ...(x.extra || {}), type: x.type }))])).rows;
      const ids = new Map(rows.map((x) => [x.arn, x.id]));
      for (const x of part) saved.push({ id: ids.get(x.arn), accountId: null, name: x.name, service: x.service, feed: false, ...analyzeGcpResource(x, estate, policy) });
    }
    const gone = (await c.query(`UPDATE resources SET deleted_at = now() WHERE gcp_connection_id = $1 AND deleted_at IS NULL AND NOT (arn = ANY($2)) RETURNING id`, [conn.id, items.map((x) => x.arn)])).rows.map((x) => x.id);
    if (gone.length) await c.query(`UPDATE resource_findings SET status = 'resolved', resolved_at = now(), updated_at = now() WHERE resource_id = ANY($1) AND status = 'open'`, [gone]);
    const r = await saveAnalyses(c, saved);
    return { stored: items.length, removed: gone.length, findingsOpened: r.opened };
  });
}

/** Works out every stored resource again when the estate or the policy changed since the last time. */
export async function resourceTick({ log = () => {}, force = false } = {}) {
  const client = await pool.connect();
  try {
    if (!(await client.query('SELECT pg_try_advisory_lock($1) AS ok', [LOCK])).rows[0].ok) return null;
    try {
      const { estate, policy, sig } = await estateFor();
      const stored = (await query('SELECT sig FROM resource_analysis WHERE id')).rows[0]?.sig;
      if (!force && stored === sig) return null;
      const out = { resources: 0, opened: 0, resolved: 0 };
      const gEstates = new Map();
      let after = '00000000-0000-0000-0000-000000000000';
      for (;;) {
        const page = (await query(
          `SELECT r.id, r.cloud, r.account_id, r.gcp_connection_id, r.project_id, r.service, r.arn, r.name, r.policy, r.extra, a.account_id AS aws_account_id
             FROM resources r LEFT JOIN cloud_accounts a ON a.id = r.account_id
            WHERE r.deleted_at IS NULL AND r.id > $1 ORDER BY r.id LIMIT $2`, [after, CHUNK])).rows;
        if (!page.length) break;
        after = page[page.length - 1].id;
        // Google Cloud resources: their connection's estate and the role definitions they name
        const gcpRows = page.filter((x) => x.cloud === 'gcp');
        const defs = gcpRows.length ? await roleDefsFor(gcpRows) : null;
        for (const id of new Set(gcpRows.map((x) => x.gcp_connection_id))) if (!gEstates.has(id)) gEstates.set(id, await gcpEstate(id));
        const items = page.map((x) => ({ id: x.id, accountId: x.account_id, name: x.name, service: x.service, feed: false,
          ...(x.cloud === 'gcp'
            ? analyzeGcpResource({ service: x.service, arn: x.arn, name: x.name, project_id: x.project_id, policy: x.policy, extra: x.extra }, { ...gEstates.get(x.gcp_connection_id), roleDefs: defs }, policy)
            : analyzeResource({ service: x.service, arn: x.arn, name: x.name, accountId: x.aws_account_id, policy: x.policy, extra: x.extra }, estate, policy)) }));
        const r = await tx((c) => saveAnalyses(c, items));
        out.resources += page.length; out.opened += r.opened; out.resolved += r.resolved;
      }
      await query(`INSERT INTO resource_analysis(id, sig, at) VALUES (true, $1, now()) ON CONFLICT (id) DO UPDATE SET sig = EXCLUDED.sig, at = now()`, [sig]);
      if (out.opened || out.resolved) log('info', 'resource access worked out again', out);
      return out;
    } finally { await client.query('SELECT pg_advisory_unlock($1)', [LOCK]); }
  } finally { client.release(); }
}
