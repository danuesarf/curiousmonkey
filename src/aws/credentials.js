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
