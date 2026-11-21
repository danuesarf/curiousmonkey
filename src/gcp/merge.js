// One identity, one picture, however Google Cloud is connected.
//
// With a connection per project (or an organization and a project inside it), an identity's roles are spread over
// the connections: its own project's connection reads the roles granted there, another project's connection the roles
// granted on that project or on a folder above it. Each connection's analysis sees only its share, and the pages show
// one copy of each identity, so a service account looked as if it held only the roles of whichever connection was
// read last: a role granted on a folder (read by the connection of a project under it) went missing from the service
// account's own project, from Space and from its page.
//
// After a scan, every identity is analysed again over everything every connection read (each policy once, each
// project once with its longest ancestry), and every copy of it gets the whole picture: all its roles, the projects
// they reach, who can become it, its keys, its risk.
import { analyzeGcp } from './analyze.js';
import { loadPolicy } from '../controls.js';
import { config } from '../config.js';

const CHUNK = 400;
const bindingKey = (b) => `${b.resource}|${b.role}|${b.member}|${b.condition ? JSON.stringify(b.condition) : ''}`;

/**
 * Re-analyse every Google Cloud identity across all connections and write the result to every copy. `c` is a
 * database client (the scan's transaction). Nothing to do with one connection, unless `force` (one is left after
 * another was removed: its identities may still hold what the removed one read). Returns how many identities were
 * joined from more than one connection.
 */
export async function mergeConnections(c, { domains = [], keyRotateDays = config.risk.keyRotateDays, force = false } = {}) {
  const conns = (await c.query(`SELECT c.id, c.status_detail->>'domain' AS domain FROM gcp_connections c WHERE EXISTS (SELECT 1 FROM gcp_principals p WHERE p.connection_id = c.id)`)).rows;
  if (conns.length < (force ? 1 : 2)) return { connections: conns.length, identities: 0, joined: 0 };

  const projects = new Map();
  for (const p of (await c.query('SELECT project_id, ancestors FROM gcp_projects')).rows) {
    const had = projects.get(p.project_id);
    if (!had || (p.ancestors || []).length > had.ancestors.length) projects.set(p.project_id, { project_id: p.project_id, ancestors: p.ancestors || [] });
  }
  const bindings = new Map();
  for (const b of (await c.query('SELECT resource, resource_type, project_id, role, member, condition FROM gcp_bindings')).rows) if (!bindings.has(bindingKey(b))) bindings.set(bindingKey(b), b);
  // a service account as its own project's connection listed it (its keys, unique ID, name)
  const serviceAccounts = (await c.query(`SELECT DISTINCT ON (p.email) p.email, p.project_id, p.unique_id, p.display_name, p.disabled, p.keys
                                            FROM gcp_principals p JOIN gcp_projects pr ON pr.connection_id = p.connection_id AND pr.project_id = p.project_id
                                           WHERE p.kind = 'serviceAccount' AND p.email IS NOT NULL ORDER BY p.email, p.analyzed_at DESC`)).rows;
  const providers = (await c.query('SELECT DISTINCT ON (name) * FROM gcp_wif_providers ORDER BY name')).rows;
  const roleNames = [...new Set([...bindings.values()].map((b) => b.role))];
  const roleDefs = new Map((await c.query('SELECT name, permissions FROM gcp_role_defs WHERE name = ANY($1)', [roleNames])).rows.map((r) => [r.name, r.permissions || []]));
  const copies = new Map((await c.query('SELECT member, count(*)::int AS n FROM gcp_principals GROUP BY member')).rows.map((r) => [r.member, r.n]));

  const result = analyzeGcp({
    org: { domain: null, domains: [...new Set([...conns.map((x) => x.domain), ...domains, ...(config.gcp.ownDomains || [])].filter(Boolean))] },
    projects: [...projects.values()], bindings: [...bindings.values()], roleDefs, serviceAccounts, providers, keyRotateDays, policy: await loadPolicy(),
  });
  const saBy = new Map(serviceAccounts.map((s) => [s.email, s]));
  const items = [];
  for (const x of result.values()) {
    if (!copies.has(x.member)) continue;                        // nothing stored for it (cannot happen; kept safe)
    const sa = x.kind === 'serviceAccount' ? saBy.get(x.email) : null;
    items.push({ member: x.member, roles: x.roles, permissions: x.permissions, reach: x.reach, sources: x.sources, origin: x.origin || null, risk: x.risk, risk_score: x.risk_score,
      risk_reasons: x.reasons, managed_by: x.managed ? 'google' : null,
      project_id: sa?.project_id ?? null, unique_id: sa?.unique_id ?? null, display_name: sa?.display_name ?? null, disabled: sa ? !!sa.disabled : null, keys: sa ? sa.keys : null });
  }
  for (let i = 0; i < items.length; i += CHUNK) {
    await c.query(`UPDATE gcp_principals p SET roles = u.roles, permissions = u.permissions, reach = ARRAY(SELECT jsonb_array_elements_text(u.reach)), sources = u.sources, origin = u.origin,
                          risk = u.risk, risk_score = u.risk_score, risk_reasons = u.risk_reasons, managed_by = u.managed_by,
                          project_id = coalesce(u.project_id, p.project_id), unique_id = coalesce(u.unique_id, p.unique_id), display_name = coalesce(u.display_name, p.display_name),
                          disabled = coalesce(u.disabled, p.disabled), keys = coalesce(u.keys, p.keys)
                     FROM jsonb_to_recordset($1::jsonb) AS u(member text, roles jsonb, permissions int, reach jsonb, sources jsonb, origin jsonb, risk text, risk_score int, risk_reasons jsonb,
                                                             managed_by text, project_id text, unique_id text, display_name text, disabled boolean, keys jsonb)
                    WHERE p.member = u.member`, [JSON.stringify(items.slice(i, i + CHUNK))]);
  }
  return { connections: conns.length, identities: items.length, joined: items.filter((x) => copies.get(x.member) > 1).length };
}
