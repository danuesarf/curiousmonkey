// Environments an account can belong to: their names, colours and order (east to west in Space, top to bottom in
// lists). An owner or admin edits the list on the Configuration page. The id stays fixed once made, so renaming an
// environment does not touch accounts; removing one that accounts still use needs somewhere to move them.
import { z } from 'zod';
import { query, tx } from './db.js';

export const DEFAULT_ENVIRONMENTS = [
  { id: 'production', name: 'Production', color: '#c68405' },
  { id: 'shared', name: 'Shared', color: '#676815' },
  { id: 'staging', name: 'Staging', color: '#4b95f0' },
  { id: 'development', name: 'Development', color: '#37ac78' },
  { id: 'sandbox', name: 'Sandbox', color: '#a947a3' },
];
export const MAX_ENVIRONMENTS = 12;
const KEY = 'environments';

const Env = z.object({
  id: z.string().trim().toLowerCase().regex(/^[a-z][a-z0-9-]{0,39}$/, 'An id is lower case letters, digits and dashes, starting with a letter.').optional(),
  name: z.string().trim().min(1, 'Give every environment a name.').max(40),
  color: z.string().trim().regex(/^#[0-9a-f]{6}$/i, 'Use a colour such as #4b95f0.'),
});
const Saved = z.array(Env.required({ id: true })).min(1).max(MAX_ENVIRONMENTS);

let list = DEFAULT_ENVIRONMENTS;

/** Read the saved list (or the defaults). A missing table before migrations is not an error. */
export async function refreshEnvironments() {
  try {
    const row = (await query('SELECT value FROM app_settings WHERE key=$1', [KEY])).rows[0];
    const ok = row && Saved.safeParse(row.value);
    list = ok?.success ? ok.data : DEFAULT_ENVIRONMENTS;
  } catch (e) { if (e.code !== '42P01') throw e; }
  return list;
}

export const environments = () => list;
export const environmentIds = () => list.map((e) => e.id);
export const isEnvironment = (id) => list.some((e) => e.id === id);
/** What someone typed (an id or a name, any case) as an id; unknown input is returned lower-cased, to be refused. */
export const resolveEnvironment = (v) => { const x = String(v ?? '').trim().toLowerCase(); return list.find((e) => e.id === x || e.name.toLowerCase() === x)?.id || x; };
export const defaultEnvironment = () => list[0].id;
/** An account's environment as the maps should treat it: unknown values fall to the first environment. */
export const environmentOf = (id) => (isEnvironment(id) ? id : list[0].id);

const slug = (s) => s.toLowerCase().normalize('NFKD').replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').replace(/^(\d)/, 'env-$1').slice(0, 40) || 'env';

/**
 * Replace the list. New entries get an id from their name. `reassign` says where the accounts of a removed
 * environment go: { removedId: keptId }. Without it, removing an environment in use is refused with the counts.
 */
export async function saveEnvironments(input, reassign = {}, userId = null) {
  const parsed = z.array(Env).min(1, 'Keep at least one environment.').max(MAX_ENVIRONMENTS, `At most ${MAX_ENVIRONMENTS} environments.`).parse(input);
  const taken = new Set(parsed.filter((e) => e.id).map((e) => e.id));
  if (taken.size !== parsed.filter((e) => e.id).length) throw Object.assign(new Error('Two environments have the same id.'), { status: 400 });
  const next = parsed.map((e) => {
    if (e.id) return { id: e.id, name: e.name, color: e.color.toLowerCase() };
    let id = slug(e.name), n = 2; const base = id;
    while (taken.has(id)) id = `${base}-${n++}`.slice(0, 40);
    taken.add(id);
    return { id, name: e.name, color: e.color.toLowerCase() };
  });
  const names = new Set(next.map((e) => e.name.toLowerCase()));
  if (names.size !== next.length) throw Object.assign(new Error('Two environments have the same name.'), { status: 400 });

  const keep = new Set(next.map((e) => e.id));
  return tx(async (c) => {
    // accounts whose environment is going away, by environment
    const used = (await c.query(`SELECT environment, count(*)::int AS n FROM cloud_accounts WHERE NOT (environment = ANY($1)) GROUP BY 1`, [[...keep]])).rows;
    const missing = used.filter((u) => !keep.has(reassign[u.environment]));
    if (missing.length) {
      throw Object.assign(new Error(`Accounts still use ${missing.map((u) => `${u.environment} (${u.n})`).join(', ')}. Choose where to move them.`),
        { status: 409, code: 'environment_in_use', inUse: Object.fromEntries(missing.map((u) => [u.environment, u.n])) });
    }
    const moved = {};
    for (const u of used) {
      await c.query('UPDATE cloud_accounts SET environment=$2, updated_at=now() WHERE environment=$1', [u.environment, reassign[u.environment]]);
      moved[u.environment] = { to: reassign[u.environment], accounts: u.n };
    }
    await c.query(`INSERT INTO app_settings(key, value, updated_by, updated_at) VALUES ($1,$2,$3,now())
                   ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value, updated_by=EXCLUDED.updated_by, updated_at=now()`, [KEY, JSON.stringify(next), userId]);
    list = next;
    return { environments: next, moved };
  });
}

/** Each environment with how many accounts are in it. */
export async function environmentsWithCounts() {
  await refreshEnvironments();
  const counts = new Map((await query('SELECT environment, count(*)::int AS n FROM cloud_accounts GROUP BY 1')).rows.map((r) => [r.environment, r.n]));
  return list.map((e) => ({ ...e, accounts: counts.get(e.id) || 0 }));
}
