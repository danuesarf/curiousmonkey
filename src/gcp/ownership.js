// Whose is a Google Cloud project, and whose is a domain: the rule every Google Cloud view uses to tell your own
// identities from outsiders.
//
// A project is
//   read   - a connection reads it (its IAM is known)
//   yours  - not read, but yours: a connection's reader can see it under one of your organizations, or it is on the
//            workspace's list of your projects (Configuration: project IDs, `*` wildcards, or project numbers)
//   null   - neither: someone else's, as far as this tool can tell
// A service account names its project in its email (name@PROJECT.iam.gserviceaccount.com, PROJECT@appspot...) or by
// number (NUMBER-compute@developer...); numbers are matched through the projects that are read or seen.
// Your domains are the organizations' (read by the scan) and the workspace's list (Configuration). With none known,
// nobody can be told to be outside your domain: the views say so instead of guessing.
import { query } from '../db.js';
import { config } from '../config.js';

const glob = (p) => new RegExp(`^${String(p).toLowerCase().replace(/[.+?^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '[a-z0-9-]*')}$`);

/** A pure ownership object, from what is known (the tests build one directly). */
export function makeOwnership({ read = [], seen = [], organizations = [], patterns = [], domains = [] } = {}) {
  const readIds = new Set(read.map((p) => p.project_id));
  const orgs = new Set(organizations.filter(Boolean));
  const numbers = new Map([...read, ...seen].filter((p) => p.number).map((p) => [String(p.number), p.project_id]));
  const seenOurs = new Set(seen.filter((p) => p.organization && orgs.has(p.organization)).map((p) => p.project_id));
  const res = patterns.map((p) => String(p).trim()).filter(Boolean).map(glob);
  const doms = [...new Set(domains.map((d) => String(d || '').trim().toLowerCase()).filter(Boolean))];
  const idOf = (x) => (x == null ? null : /^\d+$/.test(String(x)) ? numbers.get(String(x)) || null : String(x));
  return {
    read: readIds, organizations: orgs, domains: doms, idOf,
    /** 'read', 'yours' or null, for a project ID or number */
    project(x) {
      if (x == null || x === '') return null;
      const id = idOf(x);
      if (id && readIds.has(id)) return 'read';
      if (id && seenOurs.has(id)) return 'yours';
      return res.some((r) => r.test(String(x).toLowerCase()) || (id && r.test(id))) ? 'yours' : null;
    },
    /** whether an email or domain is in one of your domains (or a subdomain); null when no domain is known */
    inDomain(emailOrDomain) {
      if (!doms.length) return null;
      const s = String(emailOrDomain || '').toLowerCase(), d = s.includes('@') ? s.split('@')[1] : s;
      return doms.some((x) => d === x || d.endsWith(`.${x}`));
    },
  };
}

/** What every connection knows, and the workspace's lists. */
export async function loadOwnership({ domains: extra = [] } = {}) {
  const [read, seen, conns] = await Promise.all([
    query('SELECT DISTINCT project_id, number, ancestors FROM gcp_projects').then((r) => r.rows),
    query('SELECT DISTINCT project_id, number, organization FROM gcp_seen_projects').then((r) => r.rows, (e) => { if (e.code === '42P01') return []; throw e; }),
    query(`SELECT scope_type, scope_id, status_detail->>'domain' AS domain FROM gcp_connections`).then((r) => r.rows),
  ]);
  // your organizations: the ones a connection is on, and the ones the projects it reads sit under
  const organizations = [...conns.filter((c) => c.scope_type === 'organization').map((c) => `organizations/${c.scope_id}`),
    ...read.flatMap((p) => (p.ancestors || []).filter((a) => a.startsWith('organizations/')))];
  return makeOwnership({ read, seen, organizations, patterns: config.gcp.ownProjects || [], domains: [...conns.map((c) => c.domain), ...(config.gcp.ownDomains || []), ...extra] });
}

/** The project a service account belongs to, from its email: an ID, a number, or null (a Google-owned domain). */
export function projectOfServiceAccount(email) {
  const e = String(email || '').toLowerCase();
  return e.match(/@([a-z0-9-]+)\.iam\.gserviceaccount\.com$/)?.[1] || e.match(/^([a-z0-9-]+)@appspot\.gserviceaccount\.com$/)?.[1]
    || e.match(/^(\d+)-compute@developer\.gserviceaccount\.com$/)?.[1] || null;
}
