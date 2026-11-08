// Roles x permissions. "Scope" (which accounts) is separate and applies to everything but workspace-level actions.
export const ROLES = ['owner', 'admin', 'reviewer', 'account_owner', 'auditor'];
export const TEAMS = ['infrasec', 'infosec'];

export const PERMS = {
  owner:         ['view', 'scan', 'accounts', 'decide', 'recommend', 'approve', 'export', 'members', 'audit', 'ops', 'sso', 'settings'],
  admin:         ['view', 'scan', 'accounts', 'decide', 'recommend', 'export', 'members', 'audit', 'ops', 'settings'],
  reviewer:      ['view', 'scan', 'decide', 'recommend', 'approve', 'export', 'ops'],
  account_owner: ['view', 'scan', 'recommend', 'export'],
  auditor:       ['view', 'audit', 'ops'],
};
// Approving also needs a review team (checked in the recommender); owners and reviewers must belong to one.

export const can = (user, perm) => Boolean(user && !user.disabled && PERMS[user.role]?.includes(perm));
export const inScope = (user, accountId) => !user.scope_accounts || user.scope_accounts.includes(accountId);
export const scopeSql = (user, col, params) => {
  if (!user.scope_accounts) return 'TRUE';
  params.push(user.scope_accounts);
  return `${col} = ANY($${params.length}::uuid[])`;
};
