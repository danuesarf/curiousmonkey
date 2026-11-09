// Builders for INSERT / UPDATE column lists. Values always go as $n parameters; column names come from code, and are
// checked against an allowlist here so that a future change cannot turn a request field into SQL.
const ACCOUNT_COLUMNS = new Set(['account_id', 'name', 'environment', 'ou', 'note', 'regions', 'excluded_regions', 'event_source', 'lookback_days',
  's3_bucket', 's3_prefix', 's3_org_id', 's3_region', 'auth_mode', 'base_identity', 'role_arn', 'trust_principal', 'credentials_enc',
  'credentials_hint', 'status', 'status_detail', 'onboarded_at', 'updated_at', 'created_by']);

function checked(cols, allowed) {
  const keys = Object.keys(cols);
  for (const k of keys) if (!allowed.has(k) || !/^[a-z][a-z0-9_]*$/.test(k)) throw new Error(`not an allowed column: ${k}`);
  return keys;
}
/** `SET a=$2, b=$3` (numbering from `first`) and the values in the same order. */
export function setClause(cols, first = 2, allowed = ACCOUNT_COLUMNS) {
  const keys = checked(cols, allowed);
  return { sql: keys.map((k, i) => `"${k}"=$${i + first}`).join(', '), values: keys.map((k) => cols[k]) };
}
/** `("a","b") VALUES ($1,$2)` and the values. */
export function insertParts(cols, allowed = ACCOUNT_COLUMNS) {
  const keys = checked(cols, allowed);
  return { sql: `(${keys.map((k) => `"${k}"`).join(',')}) VALUES (${keys.map((_, i) => `$${i + 1}`).join(',')})`, values: keys.map((k) => cols[k]) };
}
