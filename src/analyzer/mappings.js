// Translate stored activity keys to IAM actions, using accepted event mappings.
// Activity is stored under the raw key of an unmapped event (e.g. "cloudfront:GetThing2031"), so accepting a
// mapping later credits history already stored, without reading CloudTrail again.
import { query } from '../db.js';
import { actionInfo } from './catalog.js';
import { mapEvent } from './actionNames.js';

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

/**
 * Event names stored as unidentified before Curious Monkey learned their mapping (a built-in alias added in a later
 * version) are settled here: recorded as accepted mappings with source "builtin", so history is credited at the next
 * analysis exactly as if a reviewer had typed them. A reviewer's own decision is never overwritten.
 */
export async function applyBuiltins() {
  const rows = (await query(
    `SELECT DISTINCT u.raw_action, u.event_source, u.event_name FROM unmapped_events u
      LEFT JOIN event_action_map m ON m.raw_action=u.raw_action WHERE m.raw_action IS NULL OR (m.status='suggested')`)).rows;
  let n = 0;
  for (const r of rows) {
    const m = mapEvent(r.event_source, r.event_name);
    if (!m.mapped || !m.action) continue;
    await query(`INSERT INTO event_action_map(raw_action, event_source, event_name, action, status, source, note, decided_at)
                 VALUES ($1,$2,$3,$4,'accepted','builtin','Known CloudTrail-to-IAM name difference',now())
                 ON CONFLICT (raw_action) DO UPDATE SET action=EXCLUDED.action, status='accepted', source='builtin', note=EXCLUDED.note, decided_at=now()
                 WHERE event_action_map.status='suggested'`, [r.raw_action, r.event_source, r.event_name, m.action]);
    n++;
  }
  return n;
}
