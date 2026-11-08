// CloudTrail S3 layout: <prefix>/AWSLogs/[<org-id>/]<account>/CloudTrail/<region>/YYYY/MM/DD/<account>_CloudTrail_<region>_YYYYMMDDTHHmmZ_<id>.json.gz
const pad = (n) => String(n).padStart(2, '0');
export function trailRegionsPrefix(account) {
  const base = account.s3_prefix ? `${account.s3_prefix.replace(/^\/+|\/+$/g, '')}/` : '';
  const org = account.s3_org_id ? `${account.s3_org_id}/` : '';
  return `${base}AWSLogs/${org}${account.account_id}/CloudTrail/`;
}
export function trailDayPrefix(account, region, day) {
  const base = account.s3_prefix ? `${account.s3_prefix.replace(/^\/+|\/+$/g, '')}/` : '';
  const org = account.s3_org_id ? `${account.s3_org_id}/` : '';
  return `${base}AWSLogs/${org}${account.account_id}/CloudTrail/${region}/${day.getUTCFullYear()}/${pad(day.getUTCMonth() + 1)}/${pad(day.getUTCDate())}/`;
}
/** Publish time from the file name, in ms. null if the name does not follow the pattern. */
export function fileTimeFromKey(key) {
  const m = key.match(/_(\d{4})(\d{2})(\d{2})T(\d{2})(\d{2})Z_/);
  return m ? Date.UTC(+m[1], +m[2] - 1, +m[3], +m[4], +m[5]) : null;
}
