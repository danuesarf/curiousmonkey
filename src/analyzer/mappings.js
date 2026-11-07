// Translate stored activity keys to IAM actions, using accepted event mappings.
// Activity is stored under the raw key of an unmapped event (e.g. "cloudfront:GetThing2031"), so accepting a
// mapping later credits history already stored, without reading CloudTrail again.
import { query } from '../db.js';
import { actionInfo } from './catalog.js';

export async function loadMappings() {
  const r = await query(`SELECT raw_action, action FROM event_action_map WHERE status='accepted'`);
  return new Map(r.rows.map((x) => [x.raw_action, x.action]));
}

/**
 * key -> { action }        a known action (as is, or through a mapping)
 * key -> { none: true }    mapped to "no permission"
 * key -> { unmapped: svc } still unknown
 */
export function translate(key, maps) {
  if (actionInfo(key)) return { action: actionInfo(key).action };
  if (maps.has(key)) { const a = maps.get(key); return a ? { action: actionInfo(a)?.action || a } : { none: true }; }
  return { unmapped: key.split(':')[0].toLowerCase() };
}
