// Small operator CLI.
//   node src/cli.js demo   add two demo accounts (AWS_MODE=demo) and queue their first scans
//   node src/cli.js scan   queue a scan for every connected account (the worker does the work)
//   node src/cli.js demo-history   (demo only) invent 35 days of past snapshots and a few changes, so the radar's
//                                  trails, trends and pings have something to show without waiting a month
import { pool, closePool } from './db.js';
import { migrate } from './migrate.js';
import { enqueueRun } from './queue.js';
import { config } from './config.js';

const cmd = process.argv[2];
const DEMO = [['111111111111', 'payments-prod', 'production'], ['222222222222', 'data-platform-stg', 'staging']];

async function main() {
  await migrate(() => {});
  if (cmd === 'demo') {
    if (config.awsMode !== 'demo') throw new Error('Set AWS_MODE=demo first. The demo accounts are fake and cannot be scanned with real AWS.');
    await pool.query(`INSERT INTO workspace(name, slug, external_id) VALUES ('Demo workspace','demo','cm-demo-external-id') ON CONFLICT (id) DO NOTHING`);
    for (const [id, name, env] of DEMO) {
      const r = await pool.query(
        `INSERT INTO cloud_accounts(account_id, name, environment, role_arn, regions, status)
         VALUES ($1,$2,$3,'arn:aws:iam::'||$1||':role/CuriousMonkeyScanner','{ap-southeast-3,us-east-1}','connected')
         ON CONFLICT (account_id) DO NOTHING RETURNING id`, [id, name, env]);
      if (r.rows[0]) { await enqueueRun(r.rows[0].id, { trigger: 'manual' }); console.log(`queued first scan for ${name}`); }
      else console.log(`${name} already exists`);
    }
    console.log('Start a worker (npm run worker) and open the portal. Sign up first: the first person becomes the owner.');
  } else if (cmd === 'scan') {
    const { rows } = await pool.query(`SELECT id, name FROM cloud_accounts WHERE status='connected'`);
    for (const a of rows) { await enqueueRun(a.id, { trigger: 'manual' }); console.log(`queued ${a.name}`); }
    if (!rows.length) console.log('No connected accounts.');
  } else if (cmd === 'demo-history') {
    if (config.awsMode !== 'demo') throw new Error('demo-history only runs with AWS_MODE=demo: it invents history.');
    const { demoHistory } = await import('./demo/history.js');
    console.log(await demoHistory());
  } else {
    console.log('usage: node src/cli.js demo|scan|demo-history');
    process.exitCode = 1;
  }
}
main().catch((e) => { console.error(e.message); process.exitCode = 1; }).finally(closePool);
