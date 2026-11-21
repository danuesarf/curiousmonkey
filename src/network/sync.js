// The Networking extension's background work: read each AWS account's and each Google Cloud project's networking
// once a day (or at once after the extension is turned on, or a "Read now"), store it, work out findings, exposure
// and the map again across everything (src/network/analyze.js), and file the findings. One owner at a time per
// worker, under an advisory lock, so replicas share the work.
import { query, tx, pool } from '../db.js';
import { getGateway } from '../aws/gateway.js';
import { gcpGateway } from '../gcp/scan.js';
import { normalizeGcpProject } from './gcpReader.js';
import { analyzeNetwork } from './analyze.js';
import { isEnabled } from '../extensions.js';
import { knownVendor } from '../trustmap.js';
import { loadPolicy } from '../controls.js';
import { loadOwnership } from '../gcp/ownership.js';

const EVERY_HOURS = 24;
const LOCK = 731_000_001;
const json = (v) => JSON.stringify(v);

/** Replace what is stored for one owner (an AWS account, or a Google Cloud project) with a fresh read. */
export async function saveNetwork({ cloud, owner, accountId = null, gcpConnectionId = null, items = [], skipped = [], error = null }) {
  await tx(async (c) => {
    if (!error) {
      // when each object was first seen, kept across reads; a new one in an owner read before is new now, and what was
      // there at the first read has no date (it was there before we looked)
      const before = new Map((await c.query('SELECT type, native_id, first_seen FROM net_items WHERE cloud = $1 AND owner = $2', [cloud, owner])).rows.map((r) => [`${r.type}|${r.native_id}`, r.first_seen]));
      const readBefore = before.size > 0 || (await c.query('SELECT 1 FROM net_reads WHERE cloud = $1 AND owner = $2 AND error IS NULL', [cloud, owner])).rows.length > 0;
      await c.query('DELETE FROM net_items WHERE cloud = $1 AND owner = $2', [cloud, owner]);
      // the same object can come twice (a peering is seen from both accounts only once per owner, but be safe)
      const seen = new Set(), rows = items.filter((i) => { const k = `${i.type}|${i.id}`; if (seen.has(k)) return false; seen.add(k); return true; });
      const now = new Date(), firstSeen = (x) => { const k = `${x.type}|${x.id}`; return before.has(k) ? before.get(k) : readBefore ? now : null; };
      for (let i = 0; i < rows.length; i += 500) {
        const part = rows.slice(i, i + 500);
        await c.query(`INSERT INTO net_items(cloud, owner, account_id, gcp_connection_id, region, type, native_id, name, vpc, data, first_seen)
          SELECT $1, $2, $3, $4, x.region, x.type, x.id, x.name, x.vpc, x.data::jsonb, x.first_seen
            FROM unnest($5::text[], $6::text[], $7::text[], $8::text[], $9::text[], $10::text[], $11::timestamptz[]) AS x(region, type, id, name, vpc, data, first_seen)`,
        [cloud, owner, accountId, gcpConnectionId, part.map((x) => x.region), part.map((x) => x.type), part.map((x) => x.id), part.map((x) => x.name), part.map((x) => x.vpc), part.map((x) => json(x.data)), part.map(firstSeen)]);
      }
    }
    const counts = {}; for (const i of items) counts[i.type] = (counts[i.type] || 0) + 1;
    await c.query(`INSERT INTO net_reads(cloud, owner, read_at, counts, skipped, error) VALUES ($1, $2, now(), $3, $4, $5)
      ON CONFLICT (cloud, owner) DO UPDATE SET read_at = now(), counts = CASE WHEN EXCLUDED.error IS NULL THEN EXCLUDED.counts ELSE net_reads.counts END, skipped = EXCLUDED.skipped, error = EXCLUDED.error`,
    [cloud, owner, json(counts), skipped, error]);
  });
}

/** What the analyzer needs to know about the estate. */
export async function networkEstate() {
  const [accts, org, projects, own] = await Promise.all([
    query('SELECT id, account_id, name FROM cloud_accounts').then((r) => r.rows),
    query('SELECT account_id, name FROM org_accounts').then((r) => r.rows).catch(() => []),
    query('SELECT DISTINCT ON (project_id) project_id, name, connection_id FROM gcp_projects ORDER BY project_id').then((r) => r.rows).catch(() => []),
    loadOwnership().catch(() => null),
  ]);
  return {
    awsAccounts: new Map(accts.map((a) => [a.account_id, { id: a.id, name: a.name }])), orgAccounts: new Map(org.map((x) => [x.account_id, x.name])), vendor: knownVendor,
    gcpProjects: new Map(projects.map((p) => [p.project_id, { name: p.name, connection: p.connection_id }])),
    ownProject: (p) => !!own?.project(p),
  };
}

export async function loadItems() {
  return (await query(`SELECT cloud, owner, account_id, region, type, native_id AS id, name, vpc, data, first_seen AS "firstSeen" FROM net_items`)).rows;
}

/** Everything worked out again: findings filed (opened, updated, resolved). Returns the analysis for callers that want it. */
export async function analyzeAndFile() {
  const { loadUsage } = await import('./flows.js');
  const [items, estate, policy, usage] = await Promise.all([loadItems(), networkEstate(), loadPolicy(), loadUsage()]);
  const r = analyzeNetwork(items, estate, policy, usage);
  const acct = (f) => (f.cloud === 'aws' ? estate.awsAccounts.get(f.owner)?.id || null : null);
  const fs = r.findings;
  await tx(async (c) => {
    for (let i = 0; i < fs.length; i += 300) {
      const p = fs.slice(i, i + 300);
      await c.query(`INSERT INTO net_findings(key, control, severity, cloud, owner, account_id, item_type, native_id, item_name, vpc, title, detail, suggestion, status, updated_at)
        SELECT x.k, x.ct, x.sv, x.cl, x.ow, x.ac, x.it, x.ni, x.nm, x.vp, x.t, x.d, x.sg, 'open', now()
          FROM unnest($1::text[], $2::text[], $3::text[], $4::text[], $5::text[], $6::uuid[], $7::text[], $8::text[], $9::text[], $10::text[], $11::text[], $12::text[], $13::text[])
            AS x(k, ct, sv, cl, ow, ac, it, ni, nm, vp, t, d, sg)
        ON CONFLICT (key) DO UPDATE SET control = EXCLUDED.control, severity = EXCLUDED.severity, account_id = EXCLUDED.account_id, item_name = EXCLUDED.item_name, vpc = EXCLUDED.vpc,
          title = EXCLUDED.title, detail = EXCLUDED.detail, suggestion = EXCLUDED.suggestion, status = 'open', resolved_at = NULL, updated_at = now(),
          decision = CASE WHEN net_findings.status = 'resolved' THEN NULL ELSE net_findings.decision END
        WHERE (net_findings.severity, net_findings.title, net_findings.detail, net_findings.status, coalesce(net_findings.suggestion, '')) IS DISTINCT FROM (EXCLUDED.severity, EXCLUDED.title, EXCLUDED.detail, 'open', coalesce(EXCLUDED.suggestion, ''))`,
      [p.map((f) => f.key), p.map((f) => f.control), p.map((f) => f.severity), p.map((f) => f.cloud), p.map((f) => f.owner), p.map(acct), p.map((f) => f.itemType), p.map((f) => f.nativeId),
        p.map((f) => f.itemName), p.map((f) => f.vpc), p.map((f) => f.title), p.map((f) => f.detail), p.map((f) => f.suggestion || null)]);
    }
    // held: findings whose evidence is not at hand right now (flow logs not read lately) stay as they are
    await c.query(`UPDATE net_findings SET status = 'resolved', resolved_at = now(), updated_at = now() WHERE status = 'open' AND NOT (key = ANY($1::text[]))`, [[...fs.map((f) => f.key), ...(r.held || [])]]);
  });
  return r;
}

/** Read one AWS account's networking. */
export async function readAwsNetwork(account, { gw } = {}) {
  const workspace = (await query('SELECT * FROM workspace')).rows[0];
  gw ||= await getGateway(account, workspace);
  try {
    const r = await gw.listNetwork();
    await saveNetwork({ cloud: 'aws', owner: account.account_id, accountId: account.id, items: r.items, skipped: r.skipped });
    return { items: r.items.length, skipped: r.skipped };
  } catch (e) {
    await saveNetwork({ cloud: 'aws', owner: account.account_id, accountId: account.id, error: String(e.message).slice(0, 500) });
    return { error: e.message };
  }
}

/** Read a Google Cloud connection's projects' networking, one project at a time. */
export async function readGcpNetwork(conn, { gw = gcpGateway(conn) } = {}) {
  const projects = (await query('SELECT project_id FROM gcp_projects WHERE connection_id = $1 ORDER BY project_id', [conn.id])).rows.map((r) => r.project_id);
  // a project no longer in this connection (taken out, or deleted in Google Cloud): its networking goes with it
  await query(`DELETE FROM net_items WHERE cloud = 'gcp' AND gcp_connection_id = $1 AND NOT (owner = ANY($2))`, [conn.id, projects]);
  const out = { projects: 0, items: 0, errors: 0 };
  for (const p of projects) {
    try {
      const r = await gw.network(p);
      const items = normalizeGcpProject(p, r.raw || {});
      await saveNetwork({ cloud: 'gcp', owner: p, gcpConnectionId: conn.id, items, skipped: r.skipped || [] });
      out.projects++; out.items += items.length;
    } catch (e) {
      out.errors++;
      await saveNetwork({ cloud: 'gcp', owner: p, gcpConnectionId: conn.id, error: String(e.message).slice(0, 500) });
    }
  }
  return out;
}

/**
 * Forget owners that are gone: the networking of Google Cloud projects no longer in any connection, and when each AWS
 * account or project no longer connected was read (an AWS account's networking is deleted with the account; a project
 * that moved to another connection leaves this one's when it is read). → how many owners were forgotten.
 */
export async function forgetGone() {
  const items = (await query(`DELETE FROM net_items i WHERE i.cloud = 'gcp' AND NOT EXISTS (SELECT 1 FROM gcp_projects p WHERE p.project_id = i.owner) RETURNING owner`).catch(() => ({ rows: [] }))).rows;
  const reads = (await query(`DELETE FROM net_reads r WHERE (r.cloud = 'aws' AND NOT EXISTS (SELECT 1 FROM cloud_accounts a WHERE a.account_id = r.owner))
    OR (r.cloud = 'gcp' AND NOT EXISTS (SELECT 1 FROM gcp_projects p WHERE p.project_id = r.owner)) RETURNING owner`).catch(() => ({ rows: [] }))).rows;
  return new Set([...items, ...reads].map((r) => r.owner)).size;
}

/** Ask for a fresh read of everything (after the extension is turned on, or "Read now"). */
// The request is a time stamp, not a flag: the worker clears only the request it served, so one made while a read
// is under way is served by the next pass. When each owner was last read is left alone, so the page keeps saying
// when it really was.
export async function requestNetworkRead() {
  const at = `to_char(clock_timestamp() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"')`;
  await query(`INSERT INTO extensions(key, settings) VALUES ('networking', jsonb_build_object('readNow', ${at}))
    ON CONFLICT (key) DO UPDATE SET settings = extensions.settings || jsonb_build_object('readNow', ${at})`);
}
/** When a read was asked for and not yet done, or null. */
export async function pendingNetworkRead() {
  const v = (await query(`SELECT settings->>'readNow' AS v FROM extensions WHERE key = 'networking'`)).rows[0]?.v;
  if (!v) return null;
  const t = new Date(v);   // a request from before this was a time stamp is just `true`
  return (Number.isNaN(t.getTime()) ? new Date() : t).toISOString();
}

/**
 * Worker step: when the extension is on, read every AWS account and Google Cloud connection whose networking is
 * older than a day (or never read), then work everything out again. One worker at a time (advisory lock).
 */
export async function networkTick({ log = () => {}, awsGw = null, gcpGw = null } = {}) {
  if (!(await isEnabled('networking'))) return null;
  const client = await pool.connect();
  try {
    if (!(await client.query('SELECT pg_try_advisory_lock($1) AS ok', [LOCK])).rows[0].ok) return null;
    try {
      const now = (await query(`SELECT settings->>'readNow' AS now FROM extensions WHERE key = 'networking'`)).rows[0]?.now || null;
      // an account or project that is gone: its networking was deleted with it, and so is when it was read
      const gone = await forgetGone();
      const stale = `(SELECT read_at FROM net_reads r WHERE r.cloud = $1 AND r.owner = $2) IS NULL OR (SELECT read_at FROM net_reads r WHERE r.cloud = $1 AND r.owner = $2) < now() - make_interval(hours => ${EVERY_HOURS})`;
      const accounts = (await query(`SELECT * FROM cloud_accounts WHERE status <> 'planned' ORDER BY name`)).rows;
      const out = { aws: 0, gcp: 0, errors: 0 };
      for (const a of accounts) {
        if (!now && !(await query(`SELECT ${stale} AS due`, ['aws', a.account_id])).rows[0].due) continue;
        const r = await readAwsNetwork(a, { gw: awsGw ? awsGw(a) : undefined });
        if (r.error) { out.errors++; log('warn', 'network not read', { account: a.name, error: r.error }); } else out.aws++;
      }
      const conns = (await query(`SELECT * FROM gcp_connections ORDER BY name`).catch(() => ({ rows: [] }))).rows;
      for (const c of conns) {
        const projects = (await query('SELECT project_id FROM gcp_projects WHERE connection_id = $1', [c.id])).rows;
        let due = !!now;
        for (const p of projects) if (!due) due = (await query(`SELECT ${stale} AS due`, ['gcp', p.project_id])).rows[0].due;
        if (!due) continue;
        const r = await readGcpNetwork(c, { gw: gcpGw ? gcpGw(c) : gcpGateway(c) });
        out.gcp += r.projects; out.errors += r.errors;
      }
      if (now) await query(`UPDATE extensions SET settings = settings - 'readNow' WHERE key = 'networking' AND settings->>'readNow' = $1`, [now]);
      // a net.* control changed on the Policy page: findings filed again from what is stored, with no new read
      const policy = await loadPolicy();
      const sig = [...(policy.over || new Map())].filter(([id]) => id.startsWith('net.')).map(([id, o]) => `${id}:${o.severity}:${o.enabled}`).sort().join('|');
      const was = (await query(`SELECT settings->>'policySig' AS s FROM extensions WHERE key = 'networking'`)).rows[0]?.s ?? '';
      if (sig !== was) await query(`UPDATE extensions SET settings = settings || jsonb_build_object('policySig', $1::text) WHERE key = 'networking'`, [sig]);
      if (!out.aws && !out.gcp && !now && sig === was && !gone) return null;
      const r = await analyzeAndFile();
      const res = { ...out, findings: r.findings.length, exposures: r.exposures.filter((e) => e.ports.length).length };
      log('info', 'networking read', res);
      return res;
    } finally { await client.query('SELECT pg_advisory_unlock($1)', [LOCK]); }
  } finally { client.release(); }
}
