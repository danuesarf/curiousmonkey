// Manage policy. Every rule the tool checks is a control: the built-in ones are listed here (the catalogue), and a
// workspace can give one another severity or turn it off (control_overrides), and write its own (custom_controls).
// The places that make findings ask this module what applies: the analyser, the IAM user checks, the Trust map, the
// Google Cloud analysis, and the worker job that files custom controls (policySync.js).
import { z } from 'zod';
import { query } from './db.js';
import { scopeSql } from './auth/rbac.js';
import { toCsv } from './csv.js';
import { compileIdentityRule } from './identityRules.js';

import { BUILTIN, BY_ID, DOMAINS, SEVERITIES, INBOX, TRUST } from './controlCatalog.js';

export * from './controlCatalog.js';

// ---------------------------------------------------------------- what applies now
/** The workspace's policy: overrides of built-in controls and its enabled custom controls. Read before each analysis. */
export async function loadPolicy() {
  let o = [], cu = [];
  try {
    [o, cu] = await Promise.all([
      query('SELECT control_id, severity, enabled, updated_at FROM control_overrides').then((r) => r.rows),
      query('SELECT id, name, description, target, rule, severity, remediation, enabled, updated_at FROM custom_controls ORDER BY created_at').then((r) => r.rows),
    ]);
  } catch (e) { if (e.code !== '42P01') throw e; }          // before migrations
  const over = new Map(o.filter((x) => BY_ID.has(x.control_id)).map((x) => [x.control_id, { severity: x.severity, enabled: x.enabled }]));
  const sig = [...o.map((x) => `${x.control_id}:${x.severity}:${x.enabled}`).sort(), ...cu.map((x) => `${x.id}:${new Date(x.updated_at).getTime()}`)].join('|');
  // the controls that are rules, built-in and custom, as they apply now
  const rules = [
    ...BUILTIN.filter((b) => b.rule).flatMap((b) => { const ov = over.get(b.id); return (ov ? ov.enabled : !b.off)
      ? [{ id: b.id, source: 'builtin', name: b.name, description: b.what, target: b.target, rule: b.rule, severity: ov?.severity || b.severity, remediation: b.fix }] : []; }),
    ...cu.filter((x) => x.enabled).map((x) => ({ id: `custom.${x.id}`, source: 'custom', name: x.name, description: x.description, target: x.target, rule: x.rule, severity: x.severity, remediation: x.remediation })),
  ];
  return { over, rules, sig };
}

// ---------------------------------------------------------------- the catalogue, with the workspace's changes
export class ControlError extends Error { constructor(status, message, field) { super(message); this.status = status; this.field = field; } }

/**
 * Every control: built-in and custom, with its severity now, whether the workspace changed it, and its open findings.
 * `q` filters: words (name, description, id, rule), and domain:, severity:, source:builtin|custom, state:on|off|changed.
 */
export async function listControls(user, q = '') {
  const sp = [];
  const [over, custom, counts] = await Promise.all([
    query('SELECT o.*, u.name AS by FROM control_overrides o LEFT JOIN users u ON u.id = o.updated_by'),
    query('SELECT c.*, u.name AS by FROM custom_controls c LEFT JOIN users u ON u.id = c.updated_by ORDER BY lower(c.name)'),
    query(`SELECT f.control, count(*)::int n, count(*) FILTER (WHERE d.id IS NULL)::int undecided
             FROM flags f JOIN roles r ON r.id = f.role_id LEFT JOIN review_decisions d ON d.flag_id = f.id
            WHERE f.status = 'open' AND f.control IS NOT NULL AND r.deleted_at IS NULL AND ${scopeSql(user, 'r.account_id', sp)} GROUP BY 1`, sp),
  ]);
  const ov = new Map(over.rows.map((x) => [x.control_id, x])), n = new Map(counts.rows.map((x) => [x.control, x]));
  const filed = (id, where) => (String(where).startsWith(INBOX) || where === TRUST || id.startsWith('custom.') ? { open: n.get(id)?.n ?? 0, undecided: n.get(id)?.undecided ?? 0 } : { open: null, undecided: null });
  const items = [
    ...BUILTIN.map((b) => {
      const o = ov.get(b.id);
      const changed = !!o && (o.enabled !== !b.off || !!o.severity);
      return { id: b.id, source: 'builtin', domain: b.domain, name: b.name, what: b.what, fix: b.fix, where: b.where, target: b.target || null, rule: b.rule || null,
        clouds: b.target === 'identity' ? compileIdentityRule(b.rule).clouds : null, defaultEnabled: !b.off,
        defaultSeverity: b.severity, varies: b.varies, severity: o?.severity || b.severity, enabled: o ? o.enabled : !b.off, changed,
        note: changed ? o.note : null, updatedBy: changed ? o.by : null, updatedAt: changed ? o.updated_at : null, ...filed(b.id, b.where) };
    }),
    ...custom.rows.map((x) => ({ id: `custom.${x.id}`, source: 'custom', domain: 'custom', name: x.name, what: x.description, fix: x.remediation,
      where: x.target === 'way-in' ? TRUST : INBOX, target: x.target, rule: x.rule, clouds: x.target === 'identity' ? compileIdentityRule(x.rule).clouds : null, defaultEnabled: true, defaultSeverity: x.severity, varies: null, severity: x.severity, enabled: x.enabled, changed: false,
      note: null, updatedBy: x.by, updatedAt: x.updated_at, ...filed(`custom.${x.id}`) })),
  ];
  const terms = [...String(q || '').matchAll(/(\w+)[:=](\S+)|"([^"]*)"|(\S+)/g)].map((m) => (m[1] ? [m[1].toLowerCase(), m[2].toLowerCase()] : ['text', (m[3] ?? m[4]).toLowerCase()]));
  const hit = (x, [k, v]) => {
    const vs = v.split(',');
    if (k === 'domain') return vs.includes(x.domain);
    if (k === 'severity') return vs.includes(x.severity || 'varies');
    if (k === 'source') return vs.includes(x.source);
    if (k === 'state') return vs.some((s) => (s === 'on' ? x.enabled : s === 'off' ? !x.enabled : s === 'changed' ? x.changed || x.source === 'custom' : false));
    if (k === 'target') return vs.some((s) => x.target === s || (s === 'identities' && x.target === 'identity') || (s === 'rule' && !!x.rule));
    if (k === 'cloud') return vs.some((s) => (x.clouds || []).includes(s) || (s === 'gcp' && x.domain === 'gcp') || (s === 'aws' && !x.clouds && x.domain !== 'gcp'));
    if (k === 'findings') return vs.some((s) => (s === 'yes' ? x.open > 0 : s === 'no' ? !x.open : false));
    return [x.id, x.name, x.what, x.rule, x.fix].some((t) => String(t || '').toLowerCase().includes(k === 'text' ? v : `${k}:${v}`));
  };
  const shown = items.filter((x) => terms.every((t) => hit(x, t)));
  return { items: shown, total: items.length, domains: DOMAINS,
    summary: { builtin: BUILTIN.length, custom: custom.rows.length, changed: items.filter((x) => x.changed).length, off: items.filter((x) => !x.enabled).length, rules: items.filter((x) => x.rule).length } };
}

export function controlsCsv(items) {
  return toCsv([
    ['ID', (x) => x.id], ['Domain', (x) => DOMAINS[x.domain]], ['Control', (x) => x.name], ['What it checks', (x) => x.what], ['Source', (x) => x.source],
    ['Severity', (x) => x.severity || 'varies'], ['Built-in severity', (x) => (x.source === 'custom' ? '' : x.defaultSeverity || `varies: ${x.varies}`)], ['On', (x) => (x.enabled ? 'yes' : 'no')],
    ['Changed here', (x) => (x.changed ? 'yes' : 'no')], ['Why', (x) => x.note], ['Applies to', (x) => (x.target === 'way-in' ? 'ways in' : x.target === 'identity' ? `identities (${(x.clouds || []).join(', ')})` : '')],
    ['Rule', (x) => x.rule], ['Open findings', (x) => x.open], ['Shows in', (x) => x.where], ['How to fix', (x) => x.fix], ['Changed by', (x) => x.updatedBy], ['Changed at', (x) => x.updatedAt],
  ], items);
}

export const OverrideIn = z.object({
  severity: z.enum(SEVERITIES).nullable().optional(),       // null: back to the built-in severity
  enabled: z.boolean().optional(),
  note: z.string().trim().max(500).nullable().optional(),
});
/** Change a built-in control. Open findings follow at once where that is one statement; the rest on the next analysis. */
export async function setOverride(user, id, body) {
  const b = BY_ID.get(id);
  if (!b) throw new ControlError(404, 'No such control.');
  const patch = OverrideIn.parse(body);
  const cur = (await query('SELECT * FROM control_overrides WHERE control_id = $1', [id])).rows[0];
  const on = !b.off;                                         // whether it is on as shipped
  const next = { severity: patch.severity !== undefined ? patch.severity : cur?.severity ?? null, enabled: patch.enabled ?? cur?.enabled ?? on, note: patch.note !== undefined ? patch.note : cur?.note ?? null };
  const before = { severity: cur?.severity ?? null, enabled: cur?.enabled ?? on };
  if (next.enabled === on && !next.severity) await query('DELETE FROM control_overrides WHERE control_id = $1', [id]);
  else await query(`INSERT INTO control_overrides(control_id, severity, enabled, note, updated_by, updated_at) VALUES ($1,$2,$3,$4,$5, now())
    ON CONFLICT (control_id) DO UPDATE SET severity = EXCLUDED.severity, enabled = EXCLUDED.enabled, note = EXCLUDED.note, updated_by = EXCLUDED.updated_by, updated_at = now()`,
  [id, next.severity, next.enabled, next.note, user.id]);
  // open findings follow now; a severity that goes back to "varies", and a control turned on again, need the next analysis
  let touched = 0;
  if (!next.enabled) touched = (await query(`UPDATE flags SET status = 'resolved', updated_at = now() WHERE control = $1 AND status = 'open'`, [id])).rowCount;
  else if (next.severity || b.severity) touched = (await query(`UPDATE flags SET severity = $2, updated_at = now() WHERE control = $1 AND status = 'open' AND severity <> $2`, [id, next.severity || b.severity])).rowCount;
  return { id, before, after: { severity: next.severity, enabled: next.enabled }, findingsChanged: touched };
}

export const CustomIn = z.object({
  name: z.string().trim().min(3).max(120),
  description: z.string().trim().max(1000).nullable().optional(),
  target: z.enum(['identity', 'way-in']),
  rule: z.string().trim().min(1).max(2000),
  severity: z.enum(SEVERITIES),
  remediation: z.string().trim().max(1000).nullable().optional(),
  enabled: z.boolean().default(true),
});
const customId = (id) => { const u = z.string().uuid().safeParse(String(id).replace(/^custom\./, '')); if (!u.success) throw new ControlError(404, 'No such control.'); return u.data; };

/** Create or change a custom control. `checkRule(target, rule)` returns the rule's errors (the routes pass it in). */
export async function saveCustom(user, id, body, checkRule) {
  const b = CustomIn.parse(body);
  const errors = await checkRule(b.target, b.rule);
  if (errors.length) throw new ControlError(400, errors[0], 'rule');
  try {
    if (!id) {
      const n = (await query('SELECT count(*)::int n FROM custom_controls')).rows[0].n;
      if (n >= 200) throw new ControlError(400, 'There are 200 custom controls; remove one first.');
      const r = (await query(`INSERT INTO custom_controls(name, description, target, rule, severity, remediation, enabled, created_by, updated_by)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$8) RETURNING id`, [b.name, b.description || null, b.target, b.rule, b.severity, b.remediation || null, b.enabled, user.id])).rows[0];
      return { id: `custom.${r.id}`, created: true, ...b };
    }
    const uid = customId(id);
    const old = (await query('SELECT target FROM custom_controls WHERE id = $1', [uid])).rows[0];
    if (!old) throw new ControlError(404, 'No such control.');
    if (old.target !== b.target) throw new ControlError(400, 'What a control applies to cannot change; make a new one.', 'target');
    await query(`UPDATE custom_controls SET name=$2, description=$3, rule=$4, severity=$5, remediation=$6, enabled=$7, updated_by=$8, updated_at=now() WHERE id=$1`,
      [uid, b.name, b.description || null, b.rule, b.severity, b.remediation || null, b.enabled, user.id]);
    return { id: `custom.${uid}`, created: false, ...b };
  } catch (e) {
    if (e.code === '23505') throw new ControlError(409, 'A custom control already has that name.', 'name');
    throw e;
  }
}
export async function deleteCustom(id) {
  const uid = customId(id);
  const r = (await query('DELETE FROM custom_controls WHERE id = $1 RETURNING name', [uid])).rows[0];
  if (!r) throw new ControlError(404, 'No such control.');
  const f = await query(`UPDATE flags SET status = 'resolved', updated_at = now() WHERE control = $1 AND status = 'open'`, [`custom.${uid}`]);
  return { name: r.name, findingsResolved: f.rowCount };
}

// ---------------------------------------------------------------- the policy as a file: export, and import elsewhere
const PolicyFile = z.object({
  kind: z.literal('curious-monkey-policy'),
  version: z.literal(1),
  overrides: z.array(z.object({ id: z.string().max(80), severity: z.enum(SEVERITIES).nullable().optional(), enabled: z.boolean().optional(), note: z.string().max(500).nullable().optional() })).max(500).default([]),
  custom: z.array(z.object({ name: z.string(), description: z.string().nullable().optional(), target: z.enum(['identity', 'way-in']), rule: z.string(), severity: z.enum(SEVERITIES),
    remediation: z.string().nullable().optional(), enabled: z.boolean().default(true) })).max(200).default([]),
}).passthrough();

/** What this workspace changed and added, as a document another workspace can import. */
export async function exportPolicy() {
  const [o, cu] = await Promise.all([
    query('SELECT control_id, severity, enabled, note FROM control_overrides ORDER BY control_id'),
    query('SELECT name, description, target, rule, severity, remediation, enabled FROM custom_controls ORDER BY lower(name)'),
  ]);
  return { kind: 'curious-monkey-policy', version: 1, exportedAt: new Date().toISOString(),
    overrides: o.rows.filter((x) => BY_ID.has(x.control_id)).map((x) => ({ id: x.control_id, severity: x.severity, enabled: x.enabled, note: x.note })),
    custom: cu.rows };
}

/**
 * Bring a policy file in. With `dryRun` nothing is written: the answer says what would happen. Custom controls are
 * matched by name (created, or updated when the name exists); `replace` also removes custom controls and resets
 * built-in changes the file does not hold. A rule that cannot be read, or a control this version does not have, is skipped.
 */
export async function importPolicy(user, doc, { dryRun = false, replace = false } = {}, checkRule) {
  const parsed = PolicyFile.safeParse(doc);
  if (!parsed.success) { const i = parsed.error.issues[0]; throw new ControlError(400, `This is not a policy file (${i.path.join('.') || 'the file'}: ${i.message}).`); }
  const file = parsed.data;
  const plan = { overrides: [], custom: [], skipped: [], removed: [], reset: [] };
  const have = new Map((await query('SELECT id, name, target FROM custom_controls')).rows.map((x) => [x.name.toLowerCase(), x]));
  const haveOver = (await query('SELECT control_id FROM control_overrides')).rows.map((x) => x.control_id);
  for (const o of file.overrides) {
    if (!BY_ID.has(o.id)) plan.skipped.push({ what: o.id, why: 'no such built-in control in this version' });
    else plan.overrides.push(o);
  }
  const seen = new Set();
  for (const cu of file.custom) {
    const body = CustomIn.safeParse(cu);
    const key = String(cu.name || '').trim().toLowerCase();
    if (!body.success) { plan.skipped.push({ what: cu.name || '(no name)', why: body.error.issues[0].message }); continue; }
    if (seen.has(key)) { plan.skipped.push({ what: cu.name, why: 'the name is in the file twice' }); continue; }
    const errors = await checkRule(body.data.target, body.data.rule);
    if (errors.length) { plan.skipped.push({ what: cu.name, why: errors[0] }); continue; }
    const old = have.get(key);
    if (old && old.target !== body.data.target) { plan.skipped.push({ what: cu.name, why: 'a control with this name applies to something else here' }); continue; }
    seen.add(key);
    plan.custom.push({ ...body.data, action: old ? 'update' : 'create', id: old ? `custom.${old.id}` : null });
  }
  if (replace) {
    plan.removed = [...have.values()].filter((x) => !seen.has(x.name.toLowerCase())).map((x) => ({ id: `custom.${x.id}`, name: x.name }));
    plan.reset = haveOver.filter((id) => !plan.overrides.some((o) => o.id === id));
  }
  const summary = { overrides: plan.overrides.length, created: plan.custom.filter((x) => x.action === 'create').length, updated: plan.custom.filter((x) => x.action === 'update').length,
    removed: plan.removed.length, reset: plan.reset.length, skipped: plan.skipped };
  if (dryRun) {
    return { dryRun: true, ...summary, names: { create: plan.custom.filter((x) => x.action === 'create').map((x) => x.name), update: plan.custom.filter((x) => x.action === 'update').map((x) => x.name), remove: plan.removed.map((x) => x.name) } };
  }
  for (const id of plan.reset) await setOverride(user, id, { severity: null, enabled: !BY_ID.get(id).off, note: null });
  for (const o of plan.overrides) await setOverride(user, o.id, { severity: o.severity ?? null, enabled: o.enabled ?? !BY_ID.get(o.id).off, note: o.note ?? null });
  for (const x of plan.removed) await deleteCustom(x.id);
  for (const { action, id, ...body } of plan.custom) await saveCustom(user, action === 'update' ? id : null, body, async () => []);
  return { dryRun: false, ...summary };
}
