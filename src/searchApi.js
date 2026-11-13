// Search for the command palette: roles, IAM users, access keys, accounts and Google Cloud identities by name or ID,
// a few of each, only in the accounts the member can see.
import { query } from './db.js';
import { scopeSql } from './auth/rbac.js';

const PER_TYPE = 5;
const like = (q) => `%${q.replace(/[\\%_]/g, (c) => `\\${c}`)}%`;
// an exact name first, then names that start with the text, then the riskiest
const rank = (col, n) => `(lower(${col}) = lower($${n})) DESC, (lower(${col}) LIKE lower($${n}) || '%') DESC`;

export async function search(user, text) {
  const q = String(text || '').trim().slice(0, 100);
  if (q.length < 2) return { q, roles: [], users: [], keys: [], accounts: [], gcp: [] };
  const identities = (isUser) => {
    const p = [like(q), q];
    return query(`SELECT r.id, r.name, r.kind, r.risk, a.name AS account_name, a.account_id AS aws_account_id
                    FROM roles r JOIN cloud_accounts a ON a.id = r.account_id
                   WHERE r.deleted_at IS NULL AND r.kind ${isUser ? '=' : '<>'} 'iam-user' AND (r.name ILIKE $1 OR r.arn ILIKE $1) AND ${scopeSql(user, 'r.account_id', p)}
                   ORDER BY ${rank('r.name', 2)}, r.risk_score DESC NULLS LAST, r.name LIMIT ${PER_TYPE}`, p);
  };
  const kp = [like(q)], ap = [like(q), q];
  const [roles, users, keys, accounts, gcp] = await Promise.all([
    identities(false), identities(true),
    // a key ID is only worth matching once enough of it is typed (every one starts with AKIA)
    q.length >= 4 ? query(`SELECT k.key_id, k.status, k.deleted_at, r.id AS user_id, r.name AS user_name, r.risk, a.name AS account_name
                             FROM iam_access_keys k JOIN roles r ON r.id = k.role_id JOIN cloud_accounts a ON a.id = r.account_id
                            WHERE r.deleted_at IS NULL AND k.key_id ILIKE $1 AND ${scopeSql(user, 'r.account_id', kp)}
                            ORDER BY (k.deleted_at IS NULL) DESC, k.key_id LIMIT ${PER_TYPE}`, kp) : { rows: [] },
    query(`SELECT a.id, a.name, a.account_id AS aws_account_id, a.environment, a.status FROM cloud_accounts a
            WHERE (a.name ILIKE $1 OR a.account_id LIKE $1) AND ${scopeSql(user, 'a.id', ap)} ORDER BY ${rank('a.name', 2)}, a.name LIMIT ${PER_TYPE}`, ap),
    // Google Cloud is not shown to members limited to some AWS accounts
    user.scope_accounts ? { rows: [] } : query(`SELECT id, kind, coalesce(email, display_name, member) AS name, project_id, risk FROM gcp_principals
            WHERE (email ILIKE $1 OR display_name ILIKE $1 OR member ILIKE $1 OR unique_id = $2) ORDER BY ${rank('coalesce(email, display_name, member)', 2)}, risk_score DESC, member LIMIT ${PER_TYPE}`, [like(q), q]),
  ]);
  return {
    q,
    roles: roles.rows.map((r) => ({ id: r.id, name: r.name, kind: r.kind, risk: r.risk, account: r.account_name, awsAccountId: r.aws_account_id })),
    users: users.rows.map((r) => ({ id: r.id, name: r.name, risk: r.risk, account: r.account_name, awsAccountId: r.aws_account_id })),
    keys: keys.rows.map((k) => ({ id: k.key_id, status: k.deleted_at ? 'Deleted' : k.status, userId: k.user_id, user: k.user_name, risk: k.risk, account: k.account_name })),
    accounts: accounts.rows.map((a) => ({ id: a.id, name: a.name, awsAccountId: a.aws_account_id, environment: a.environment, status: a.status })),
    gcp: gcp.rows.map((g) => ({ id: g.id, name: g.name, kind: g.kind, project: g.project_id, risk: g.risk })),
  };
}
