// Operations: the scans, the workers that run them and the database under them, as three tabs of one page.
import { h, pageTabs } from '../lib.js';
import { opsPage } from './ops.js';
import { workersPage, databasePage } from './workers.js';

const TABS = [['scans', 'Scans', opsPage], ['workers', 'Workers', workersPage], ['database', 'Database', databasePage]];

export async function operationsPage(ctx, tab) {
  const [key, label, page] = TABS.find((t) => t[0] === tab) || TABS[0];
  ctx.setCrumbs('Operations', label);
  return h('div', { class: 'stack-lg' }, pageTabs('Operations', TABS.map(([k, l]) => [k, l, `#/operations/${k}`]), key), await page(ctx));
}
