// Google Cloud projects as the app shows them: one row per project (the first connection that reads it), with the
// environment it lands in (set by hand, from its env label, or the connection's default).
import { query } from '../db.js';
import { isEnvironment, resolveEnvironment, environmentOf } from '../environments.js';

export async function gcpProjects() {
  const r = await query(`SELECT p.*, c.environment AS default_env, c.name AS connection_name FROM gcp_projects p JOIN gcp_connections c ON c.id = p.connection_id ORDER BY p.project_id`);
  const seen = new Set();
  return r.rows.filter((p) => !seen.has(p.project_id) && seen.add(p.project_id)).map((p) => {
    const label = p.labels?.env || p.labels?.environment || p.labels?.stage || null;
    const fromLabel = label && isEnvironment(resolveEnvironment(label)) ? resolveEnvironment(label) : null;
    return { projectId: p.project_id, number: p.number, name: p.name || p.project_id, connection: p.connection_id, connectionName: p.connection_name, parent: p.parent,
      environment: environmentOf(p.environment || fromLabel || p.default_env), environmentSource: p.environment ? 'set' : fromLabel ? 'label' : 'connection', labels: p.labels };
  });
}

/**
 * The folders and organization above each project whose IAM policy no connection could read: roles granted there
 * are missing. Refused by one connection but read by another (an organization connected besides its projects) is
 * read. Map project ID -> ['folders/123', 'organizations/456'], nearest first; only projects with something missing.
 */
export async function unreadAbove() {
  const [conns, projects] = await Promise.all([
    query(`SELECT status_detail FROM gcp_connections WHERE status_detail IS NOT NULL`),
    query(`SELECT DISTINCT project_id, ancestors FROM gcp_projects`),
  ]);
  const read = new Set(), refused = new Set();
  for (const { status_detail: d } of conns.rows) {
    for (const r of d?.above?.read || []) read.add(r);
    // a scan from before the read was noted: what it skipped
    for (const r of d?.above?.refused || (d?.skipped || []).filter((x) => /^(folders|organizations)\//.test(x))) refused.add(r);
  }
  const out = new Map();
  for (const p of projects.rows) {
    const missing = (p.ancestors || []).filter((a) => refused.has(a) && !read.has(a));
    if (missing.length && !out.has(p.project_id)) out.set(p.project_id, missing);
  }
  return out;
}
/** 'folders/123' -> 'folder 123', 'organizations/456' -> 'the organization (456)' */
export const aboveLabel = (r) => (String(r).startsWith('folders/') ? `folder ${r.split('/')[1]}` : `the organization (${String(r).split('/')[1]})`);

/** How a principal's ways in add up, by kind (wif, gke, token, actAs, key...), and the AWS identities among them. */
export function summarizeSources(list) {
  const by = {};
  for (const s of list || []) by[s.via] = (by[s.via] || 0) + 1;
  const aws = (list || []).filter((s) => s.origin?.cloud === 'aws').map((s) => s.origin.label);
  return { ...by, aws: [...new Set(aws)] };
}
