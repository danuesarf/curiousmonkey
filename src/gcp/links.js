// The paths between the two clouds.
//   AWS -> Google Cloud: a workload identity pool with an AWS provider, and a binding that lets the federated
//     identity (an AWS account, or one role in it) become a service account or hold roles itself.
//   Google Cloud -> AWS: an AWS role whose trust policy accepts accounts.google.com tokens for a service account,
//     named by its numeric unique ID in accounts.google.com:sub / :aud / :oaud.
import { query } from '../db.js';

import { googleTrustsOf } from './analyze.js';
export { googleTrustsOf };

/**
 * Every cross-cloud path visible to the caller. `awsScope`: null for everything, or the AWS account uuids a scoped
 * member may see (their Google Cloud side is then hidden: GCP data is not scoped by account).
 */
export async function crossLinks({ awsScope = null } = {}) {
  const [accounts, gcp, googleRoles] = await Promise.all([
    query(`SELECT id, account_id, name, environment FROM cloud_accounts WHERE provider='aws'`),
    query(`SELECT p.id, p.member, p.kind, p.email, p.project_id, p.unique_id, p.sources, p.origin, p.roles, p.reach, p.risk, p.connection_id FROM gcp_principals p
           WHERE p.kind IN ('serviceAccount','federated')`),
    query(`SELECT r.id, r.name, r.arn, r.account_id, r.trust_policy, r.risk FROM roles r WHERE r.deleted_at IS NULL AND r.trust_policy::text LIKE '%accounts.google.com%'`),
  ]);
  const byAwsId = new Map(accounts.rows.map((a) => [a.account_id, a]));
  const visible = (uuid) => !awsScope || awsScope.includes(uuid);
  const roleIds = new Map();
  const needRoles = new Set();
  const awsToGcp = [];
  for (const p of gcp.rows) {
    // a federated identity is a path of its own only where it holds roles itself; one that may only become a
    // service account is drawn as that service account's way in
    const direct = p.kind === 'federated' && p.origin && p.roles.some((r) => r.resourceType !== 'serviceAccount');
    if (p.kind === 'federated' && !direct) continue;
    const origins = direct ? [{ origin: p.origin, via: 'direct', role: p.roles.map((r) => r.role).join(', ') }]
      : p.sources.filter((s) => s.via === 'wif' && s.origin?.cloud === 'aws').map((s) => ({ origin: s.origin, via: 'impersonate', role: s.role }));
    for (const { origin, via, role } of origins) {
      if (origin.cloud !== 'aws') continue;
      for (const acct of origin.awsAccountId ? [origin.awsAccountId] : origin.awsAccountIds || []) {
        const a = byAwsId.get(acct);
        if (a && !visible(a.id)) continue;
        if (awsScope && !a) continue;
        if (a && origin.awsRole) needRoles.add(`${a.id}|${origin.awsRole}`);
        awsToGcp.push({ awsAccountId: acct, awsAccount: a?.id || null, awsAccountName: a?.name || null, awsRole: origin.awsRole || null, gcpPrincipal: p.id, gcpMember: p.member, gcpEmail: p.email,
          gcpProject: p.project_id || (via === 'direct' ? p.reach[0] : null), via, grant: role, broad: !!origin.broad, label: origin.label, pool: origin.pool, conditions: (origin.providers || []).map((x) => x.condition).filter(Boolean) });
      }
    }
  }
  if (needRoles.size) {
    const keys = [...needRoles].map((k) => k.split('|'));
    const r = await query(`SELECT id, name, account_id FROM roles WHERE deleted_at IS NULL AND (account_id, name) IN (SELECT * FROM unnest($1::uuid[], $2::text[]))`, [keys.map((k) => k[0]), keys.map((k) => k[1])]);
    for (const x of r.rows) roleIds.set(`${x.account_id}|${x.name}`, x.id);
  }
  for (const l of awsToGcp) l.awsRoleId = l.awsAccount && l.awsRole ? roleIds.get(`${l.awsAccount}|${l.awsRole}`) || null : null;

  const byUnique = new Map(gcp.rows.filter((p) => p.unique_id).map((p) => [p.unique_id, p]));
  const gcpToAws = [];
  for (const r of googleRoles.rows) {
    if (!visible(r.account_id)) continue;
    const acct = accounts.rows.find((a) => a.id === r.account_id);
    for (const t of googleTrustsOf(r.trust_policy)) {
      for (const id of t.ids) {
        const p = byUnique.get(id);
        gcpToAws.push({ awsRoleId: r.id, awsRole: r.name, awsAccount: r.account_id, awsAccountName: acct?.name || null, awsAccountId: acct?.account_id || null, uniqueId: id,
          gcpPrincipal: p?.id || null, gcpMember: p?.member || null, gcpEmail: p?.email || null, gcpProject: p?.project_id || null, statement: t.statement, known: !!p });
      }
      if (t.any) gcpToAws.push({ awsRoleId: r.id, awsRole: r.name, awsAccount: r.account_id, awsAccountName: acct?.name || null, awsAccountId: acct?.account_id || null, uniqueId: null, any: true, statement: t.statement, known: false });
    }
  }
  return { awsToGcp: awsScope ? awsToGcp.filter((l) => l.awsAccount) : awsToGcp, gcpToAws };
}
