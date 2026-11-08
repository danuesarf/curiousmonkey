import { runInventory } from './inventory.js';
import { runEvents } from './events.js';
import { runTrailEvents } from './trailReader.js';
import { runAdvisor } from './advisor.js';
import { runAnalyze } from './analyzeJob.js';
import { query } from '../db.js';

// S3 trails are read by one account-wide reader; Event History region by region.
async function events(ctx) {
  const src = (await query('SELECT event_source FROM cloud_accounts WHERE id=$1', [ctx.job.account_id])).rows[0]?.event_source;
  return src === 's3' ? runTrailEvents(ctx) : runEvents(ctx);
}

export const handlers = { inventory: runInventory, events, advisor: runAdvisor, analyze: runAnalyze };
