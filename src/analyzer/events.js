// Parse one CloudTrail record (the JSON inside a LookupEvents result) into what the scanner needs.
import { mapEvent, isDenied } from './actionNames.js';

const ROLE_ARN_RE = /arn:aws[a-z-]*:iam::\d{12}:role\/[\w+=,.@\/-]+/g;
const ASSUME = new Set(['AssumeRole', 'AssumeRoleWithSAML', 'AssumeRoleWithWebIdentity']);

/** Role ARN of the session behind an event (sessionIssuer is the role itself, with its path). */
export function issuerRoleArn(rec) {
  const ui = rec.userIdentity;
  if (ui?.type !== 'AssumedRole') return null;
  return ui.sessionContext?.sessionIssuer?.arn || null;
}

/** Some events carry an AssumedRole identity without sessionContext. The role name is still in the session ARN. */
export function issuerRoleName(rec) {
  const ui = rec.userIdentity;
  if (ui?.type !== 'AssumedRole') return null;
  return ui.arn?.match(/:assumed-role\/([^/]+)\//)?.[1] || null;
}

export function parseEvent(rec) {
  const base = {
    id: rec.eventID, time: new Date(rec.eventTime), region: rec.awsRegion,
    ip: rec.sourceIPAddress || null, userAgent: rec.userAgent || null,
    errorCode: rec.errorCode || null, denied: isDenied(rec.errorCode),
  };
  if (rec.eventSource === 'sts.amazonaws.com' && ASSUME.has(rec.eventName)) {
    const ui = rec.userIdentity || {};
    return {
      ...base, type: 'assume', eventName: rec.eventName, roleArn: rec.requestParameters?.roleArn || null,
      sessionName: rec.requestParameters?.roleSessionName || null,
      accessKeyId: rec.responseElements?.credentials?.accessKeyId || null,
      callerKeyId: ui.accessKeyId || null, callerRoleArn: issuerRoleArn(rec), callerRoleName: issuerRoleArn(rec) ? null : issuerRoleName(rec),
      callerSessionName: ui.type === 'AssumedRole' ? ui.arn?.split('/').pop() || null : null,
      caller: { type: ui.type, arn: ui.arn || ui.sessionContext?.sessionIssuer?.arn || null, principalId: ui.principalId,
        accountId: ui.accountId, invokedBy: ui.invokedBy || null, userName: ui.userName || null },
      mfa: rec.additionalEventData?.MFAAuthenticated === 'true' || ui.sessionContext?.attributes?.mfaAuthenticated === 'true',
      sourceIdentity: rec.requestParameters?.sourceIdentity || null,
      sessionTags: (rec.requestParameters?.tags || []).map((t) => `${t.key}=${t.value}`),
      eventSource: rec.eventSource,
    };
  }
  const roleArn = issuerRoleArn(rec);
  const roleName = roleArn ? null : issuerRoleName(rec);
  if (!roleArn && !roleName) return { ...base, type: 'ignore', why: 'not-role', eventSource: rec.eventSource };
  const m = mapEvent(rec.eventSource, rec.eventName);
  const resources = (rec.resources || []).map((r) => r.ARN).filter(Boolean);
  return {
    ...base, type: 'api', roleArn, roleName, action: m.action, mapped: m.mapped, noPermission: !!m.none,
    identityType: rec.userIdentity?.type, paramKeys: Object.keys(rec.requestParameters || {}).slice(0, 12),
    eventSource: rec.eventSource, eventName: rec.eventName,
    accessKeyId: rec.userIdentity?.accessKeyId || null,
    sessionName: rec.userIdentity?.arn?.split('/').pop() || null,
    resources, passedRoles: findPassedRoles(rec, roleArn),
  };
}

/** CloudTrail never logs iam:PassRole itself, but the role ARN shows up in the request that used it. */
export function findPassedRoles(rec, callerRoleArn) {
  const text = JSON.stringify(rec.requestParameters || {});
  const found = new Set(text.match(ROLE_ARN_RE) || []);
  found.delete(callerRoleArn);
  return [...found];
}

export const servicePrincipalOf = (eventSource) => eventSource.replace(/\.amazonaws\.com(\.cn)?$/, '');
