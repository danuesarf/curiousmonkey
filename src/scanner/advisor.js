import { query } from '../db.js';
import { loadContext } from './inventory.js';

// IAM Access Advisor keeps its own, longer record of which services a role touched. We use it to say
// "this service was used, we just can't see which action" instead of wrongly calling it unused.
export async function runAdvisor(ctx) {
  const { account, gw } = await loadContext(ctx.job.account_id);
  const roles = (await query(
    `SELECT r.id, r.arn FROM roles r WHERE r.account_id=$1 AND r.deleted_at IS NULL
        AND NOT EXISTS (SELECT 1 FROM advisor_services a WHERE a.role_id=r.id AND a.refreshed_at > now() - interval '20 hours')`, [account.id])).rows;
  let done = 0, failed = 0;
  const queue = [...roles];
  await Promise.all(Array.from({ length: 3 }, async () => {
    while (queue.length) {
      const r = queue.shift();
      ctx.alive();
      try {
        const rows = await gw.getAdvisor(r.arn);
        await query('DELETE FROM advisor_services WHERE role_id=$1', [r.id]);
        for (const a of rows) await query(
          `INSERT INTO advisor_services(role_id, service_namespace, last_authenticated) VALUES ($1,$2,$3)`, [r.id, a.service, a.lastAuthenticated]);
      } catch (e) {
        failed++;
        await ctx.log(`advisor failed for ${r.arn}: ${e.message}`, null, 'warn');
        if (e.retryable === false) continue;
      }
      await ctx.progress({ phase: 'advisor', done: ++done, total: roles.length });
    }
  }));
  if (failed && failed === roles.length) throw new Error('Access Advisor failed for every role');
  return { roles: roles.length, failed };
}
