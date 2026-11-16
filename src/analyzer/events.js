// Parse one CloudTrail record (the JSON inside a LookupEvents result) into what the scanner needs.
import { mapEvent, isDenied } from './actionNames.js';

const ROLE_ARN_RE = /arn:aws[a-z-]*:iam::\d{12}:role\/[\w+=,.@\/-]+/g;
// EC2 takes an instance profile, not a role: { arn } or just { name }. The profile is what CloudTrail shows.
const PROFILE_ARN_RE = /arn:aws[a-z-]*:iam::\d{12}:instance-profile\/[\w+=,.@\/-]+/g;
const ASSUME = new Set(['AssumeRole', 'AssumeRoleWithSAML', 'AssumeRoleWithWebIdentity']);

/** Role ARN of the session behind an event (sessionIssuer is the role itself, with its path). */
export function issuerRoleArn(rec) {
  const ui = rec.userIdentity;
  if (ui?.type !== 'AssumedRole') return null;
  return ui.sessionContext?.sessionIssuer?.arn || null;
}

function sessionCreatedOf(rec) {
  const t = rec.userIdentity?.sessionContext?.attributes?.creationDate;
  const d = t ? new Date(t) : null;
  return d && !Number.isNaN(d.getTime()) ? d : null;
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
  // an IAM user calling with its own credentials (an access key, or a console session): attributed to the user
  const userArn = !roleArn && !roleName && rec.userIdentity?.type === 'IAMUser' ? rec.userIdentity.arn || null : null;
  if (!roleArn && !roleName && !userArn) return { ...base, type: 'ignore', why: 'not-role', eventSource: rec.eventSource };
  if (userArn) {
    const m = mapEvent(rec.eventSource, rec.eventName);
    return { ...base, type: 'api', roleArn: userArn, roleName: null, userCall: true, action: m.action, mapped: m.mapped, noPermission: !!m.none,
      identityType: 'IAMUser', paramKeys: Object.keys(rec.requestParameters || {}).slice(0, 12), eventSource: rec.eventSource, eventName: rec.eventName,
      accessKeyId: rec.userIdentity.accessKeyId || null, console: !!rec.userIdentity.sessionContext || !/^AKIA/.test(rec.userIdentity.accessKeyId || ''),
      sessionName: null, resources: (rec.resources || []).map((r) => r.ARN).filter(Boolean), passedRoles: findPassedRoles(rec, null) };
  }
  const m = mapEvent(rec.eventSource, rec.eventName);
  const resources = (rec.resources || []).map((r) => r.ARN).filter(Boolean);
  return {
    ...base, type: 'api', roleArn, roleName, action: m.action, mapped: m.mapped, noPermission: !!m.none,
    identityType: rec.userIdentity?.type, paramKeys: Object.keys(rec.requestParameters || {}).slice(0, 12),
    eventSource: rec.eventSource, eventName: rec.eventName,
    accessKeyId: rec.userIdentity?.accessKeyId || null,
    sessionName: rec.userIdentity?.arn?.split('/').pop() || null,
    // when the session's credentials were first issued. The console swaps in new keys during one sign-in; they keep
    // this time, which is how they are tied back to the sign-in (see applyEvents).
    sessionCreated: sessionCreatedOf(rec),
    resources, passedRoles: findPassedRoles(rec, roleArn),
  };
}

// Services that never take a passed role: a role ARN in their requests is the role being read, changed or analyzed.
const NO_PASS_SOURCES = new Set(['iam.amazonaws.com', 'sts.amazonaws.com']);
// A field that hands a role to a service is named for it: role, roleArn, executionRoleArn, serviceRole, iamRoles,
// accessRole, nodeRole, iamInstanceProfile... Fields such as principalArn, resourceArn or arn only name a role.
const PASS_KEY = /role|instanceprofile/i;
// A policy or document that sits under such a field lists roles; it does not pass them.
const NOT_PASS_KEY = /policy|document|principal|trust/i;

/**
 * CloudTrail never logs iam:PassRole itself, but the role ARN shows up in the request that used it.
 * Only role ARNs under a field that hands the role to the service count (RunInstances iamInstanceProfile,
 * RegisterTaskDefinition taskRoleArn, CreateFunction role, StartPolicyGeneration cloudTrailDetails.accessRole...).
 * A role ARN anywhere else (GetRole, GenerateServiceLastAccessedDetails, Access Analyzer's principalArn) is a role
 * this one looked at, not one it passed.
 */
export function findPassedRoles(rec, callerRoleArn) {
  if (NO_PASS_SOURCES.has(rec.eventSource)) return [];
  const found = new Set();
  const acct = rec.recipientAccountId || rec.userIdentity?.accountId;
  const partition = (rec.userIdentity?.arn || '').split(':')[1] || 'aws';
  // passing: under a field that hands a role over. inProfile: directly inside an instance-profile field.
  const walk = (v, passing, inProfile) => {
    if (v == null) return;
    if (Array.isArray(v)) { for (const x of v) walk(x, passing, inProfile); return; }
    if (typeof v === 'string') {
      if (!passing) return;
      for (const a of v.match(ROLE_ARN_RE) || []) found.add(a);
      for (const a of v.match(PROFILE_ARN_RE) || []) found.add(a);
      return;
    }
    if (typeof v !== 'object') return;
    for (const [k, x] of Object.entries(v)) {
      if (NOT_PASS_KEY.test(k)) continue;
      // an instance profile given by name only ({ iamInstanceProfile: { name } })
      if (inProfile && k === 'name' && typeof x === 'string' && /^[\w+=,.@-]+$/.test(x) && /^\d{12}$/.test(acct || '')) {
        found.add(`arn:${partition}:iam::${acct}:instance-profile/${x}`);
        continue;
      }
      walk(x, passing || PASS_KEY.test(k), /instanceprofile/i.test(k));
    }
  };
  walk(rec.requestParameters, false, false);
  found.delete(callerRoleArn);
  return [...found];
}

export const servicePrincipalOf = (eventSource) => eventSource.replace(/\.amazonaws\.com(\.cn)?$/, '');
