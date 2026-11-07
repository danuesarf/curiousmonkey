// Credentials a worker uses for one account.
//   assume_role + system : default AWS chain (env/.env, instance/task/pod role) -> sts:AssumeRole into the scanner role
//   assume_role + stored : keys saved on the account (encrypted)               -> sts:AssumeRole into the scanner role
//   access_key           : keys of a dedicated read-only IAM user, used directly
import { encrypt, decrypt } from '../auth/crypto.js';

export function sealCredentials({ accessKeyId, secretAccessKey, sessionToken }) {
  return {
    enc: encrypt(JSON.stringify({ accessKeyId, secretAccessKey, sessionToken: sessionToken || undefined })),
    hint: `${accessKeyId.slice(0, 4)}…${accessKeyId.slice(-4)}${sessionToken ? ' (temporary)' : ''}`,
  };
}
export function storedCredentials(account) {
  if (!account.credentials_enc) return null;
  return JSON.parse(decrypt(account.credentials_enc));
}
/** Base credentials for the SDK. `undefined` means "use the default provider chain". */
export function baseCredentials(account) {
  if (account.auth_mode === 'access_key' || account.base_identity === 'stored') {
    const c = storedCredentials(account);
    if (!c) throw Object.assign(new Error('This account is set to use stored access keys, but none are saved. Edit the account and add them.'), { retryable: false });
    return c;
  }
  return undefined;
}
/** A session ARN cannot be a trust-policy principal; the role behind it can. */
export function principalFromCallerArn(arn) {
  const m = arn?.match(/^arn:(aws[\w-]*):sts::(\d{12}):assumed-role\/([^/]+)\//);
  if (m) return `arn:${m[1]}:iam::${m[2]}:role/${m[3]}`;
  return arn || null;
}

const REFRESH_BEFORE_MS = 5 * 60e3;
/**
 * Credentials for the scanner role that renew themselves. Scans can run for hours, longer than one role session,
 * so every SDK call asks this provider, which re-assumes the role 5 minutes before the session ends.
 * Concurrent callers share one AssumeRole call.
 */
export function refreshingRoleCredentials({ assume, now = () => Date.now() }) {
  let current = null, pending = null;
  return async () => {
    if (current && current.expiration.getTime() - now() > REFRESH_BEFORE_MS) return current;
    if (!pending) {
      pending = assume()
        .then((c) => { current = c; return c; })
        .catch((e) => {
          if (/ExpiredToken|security token included in the request is expired/i.test(`${e.name} ${e.message}`)) {
            throw Object.assign(new Error('The credentials used to assume the scanner role have expired. They are temporary keys (in the worker’s .env, or saved on this account). Replace them with long-lived keys or give the worker a role, then retry the scan.'),
              { name: 'BaseCredentialsExpired', retryable: false });
          }
          throw e;
        })
        .finally(() => { pending = null; });
    }
    return pending;
  };
}
