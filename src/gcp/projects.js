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

/** How a principal's ways in add up, by kind (wif, gke, token, actAs, key...), and the AWS identities among them. */
export function summarizeSources(list) {
  const by = {};
  for (const s of list || []) by[s.via] = (by[s.via] || 0) + 1;
  const aws = (list || []).filter((s) => s.origin?.cloud === 'aws').map((s) => s.origin.label);
  return { ...by, aws: [...new Set(aws)] };
}
