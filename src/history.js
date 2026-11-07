// How much of each account's CloudTrail history has been read. Until all of it is, results are provisional:
// used counts can only go up and "never called" can only go down, so nothing is approved on them.
import { query } from './db.js';
import { config } from './config.js';
import { lookbackFor } from './scanner/events.js';

const DAY = 864e5, MIN = 60e3;
const SLACK = DAY;
const CATCH_UP_SLACK = 12 * 60 * MIN; // two 6-hour slices          // a day of tolerance at the old end, so a horizon that moves daily never reopens it

/**
 * Pure: account + its checkpoints -> { progress 0..100, complete, readUpTo, backTo, regions }.
 * A region counts from where its stored history starts (or the horizon) to the newest event read.
 */
export function historyState(account, checkpoints, now = Date.now()) {
  const horizon = now - lookbackFor(account) * DAY;
  const end = now - config.scanner.deliveryLagMinutes * MIN;
  const span = Math.max(end - horizon, 1);
  const regions = account.regions.map((region) => {
    const cp = checkpoints.find((c) => c.region === region);
    if (!cp) return { region, progress: 0, complete: false, first: null, last: null };
    const first = new Date(cp.first_event_time || cp.last_event_time).getTime();
    const last = new Date(cp.last_event_time).getTime();
    const covered = Math.max(0, Math.min(last, end) - Math.max(first, horizon));
    const backDone = first <= horizon + SLACK;
    // caught up = the read position reached the present when caught_up_at was stamped. A stamp with the read position
    // well behind it is stale (e.g. backfilled by a migration while a read was mid-way) and does not count.
    const stamp = cp.caught_up_at ? new Date(cp.caught_up_at).getTime() : null;
    const caughtUp = stamp != null && last >= stamp - config.scanner.deliveryLagMinutes * MIN - CATCH_UP_SLACK;
    const complete = backDone && caughtUp;
    return { region, progress: complete ? 100 : Math.min(99, (covered / span) * 100), complete, first: new Date(first), last: new Date(last), gap: !!cp.gap_detected };
  });
  const complete = regions.length > 0 && regions.every((r) => r.complete);
  const progress = complete ? 100 : Math.floor(regions.reduce((s, r) => s + r.progress, 0) / Math.max(regions.length, 1));
  const lasts = regions.filter((r) => r.last).map((r) => r.last.getTime());
  const firsts = regions.filter((r) => r.first).map((r) => r.first.getTime());
  return {
    progress, complete,
    readUpTo: lasts.length ? new Date(Math.min(...lasts)) : null,
    backTo: firsts.length ? new Date(Math.max(...firsts)) : null,
    regions: regions.map((r) => ({ ...r, progress: Math.floor(r.progress) })),
  };
}

/** History state for these accounts (rows of cloud_accounts), keyed by id. */
export async function historyFor(accounts) {
  if (!accounts.length) return new Map();
  const cps = (await query('SELECT * FROM scan_checkpoints WHERE account_id = ANY($1)', [accounts.map((a) => a.id)])).rows;
  return new Map(accounts.map((a) => [a.id, historyState(a, cps.filter((c) => c.account_id === a.id))]));
}

export async function accountComplete(accountId) {
  const a = (await query('SELECT * FROM cloud_accounts WHERE id=$1', [accountId])).rows[0];
  if (!a) return false;
  return (await historyFor([a])).get(a.id).complete;
}
