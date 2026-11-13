// Admin: members, the audit log and the configuration, as tabs of one page. A tab shows only to someone who may use it.
import { h, pageTabs } from '../lib.js';
import { session } from '../main.js';
import { membersPage } from './members.js';
import { auditPage } from './audit.js';
import { settingsPage } from './settings.js';

const TABS = [['members', 'Members', 'members', membersPage], ['audit', 'Audit log', 'audit', auditPage], ['config', 'Configuration', 'settings', settingsPage]];
/** The Admin tabs this person may open. */
export const adminTabs = (user) => TABS.filter(([, , perm]) => user?.permissions.includes(perm));

export async function adminPage(ctx, tab) {
  const mine = adminTabs(session.user);
  const [key, label, , page] = mine.find((t) => t[0] === tab) || mine[0] || [];
  if (!page) return h('div', { class: 'empty' }, 'Nothing here.');
  ctx.setCrumbs('Admin', label);
  return h('div', { class: 'stack-lg' }, pageTabs('Admin', mine.map(([k, l]) => [k, l, `#/admin/${k}`]), key), await page(ctx));
}
