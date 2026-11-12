// A small in-memory cache for pages that are expensive to work out and fine to show a few seconds old (Space, the
// first page of Events). An answer younger than freshMs is returned as is. An older one is still returned at once,
// and worked out again in the background. Answers people looked at recently are kept warm on a timer, so opening
// the page again is instant. Each API process keeps its own; nothing is shared, so no Redis is needed.
const FRESH_MS = Number(process.env.CACHE_FRESH_MS ?? 20_000);
const STALE_MS = Number(process.env.CACHE_STALE_MS ?? 30 * 60_000);
const WARM_FOR_MS = 15 * 60_000;      // keep refreshing an answer this long after it was last asked for
const MAX = 300;
const store = new Map();              // key -> { value, at, used, fn, pending }

function refresh(key, e) {
  if (!e.pending) {
    e.pending = Promise.resolve().then(e.fn).then((v) => { e.value = v; e.at = Date.now(); e.failed = false; return v; })
      .catch((err) => { e.failed = true; if (e.value === undefined) store.delete(key); throw err; })
      .finally(() => { e.pending = null; });
    e.pending.catch(() => {});        // background refreshes report nothing; the next request tries again
  }
  return e.pending;
}

/** The cached answer for `key`, working it out with `fn` when there is none. freshMs <= 0 turns caching off. */
export async function cached(key, fn, { freshMs = FRESH_MS, staleMs = STALE_MS } = {}) {
  if (freshMs <= 0) return fn();
  const now = Date.now();
  let e = store.get(key);
  if (!e) {
    if (store.size >= MAX) { const oldest = [...store].sort((a, b) => a[1].used - b[1].used)[0]; store.delete(oldest[0]); }
    e = { value: undefined, at: 0, used: now, fn, pending: null }; store.set(key, e);
  }
  e.used = now; e.fn = fn;
  if (e.value !== undefined && now - e.at < staleMs) { if (now - e.at >= freshMs) refresh(key, e); return e.value; }
  return refresh(key, e);
}

/** Who can see what decides the answer: all accounts, or the viewer's own set. */
export const scopeKey = (user) => (user?.scope_accounts ? [...user.scope_accounts].sort().join(',') : '*');

export const clearCache = () => store.clear();

// keep recently used answers warm, one at a time
let warming = false;
if (FRESH_MS > 0) setInterval(async () => {
  if (warming) return; warming = true;
  try {
    const now = Date.now();
    for (const [key, e] of store) {
      if (now - e.used > STALE_MS) { store.delete(key); continue; }
      if (e.warm && now - e.used < WARM_FOR_MS && now - e.at >= FRESH_MS) await refresh(key, e).catch(() => {});
    }
  } finally { warming = false; }
}, Math.max(5000, FRESH_MS)).unref();

/** Like cached(), and kept warm in the background for a while after each use. */
export function cachedWarm(key, fn, opts) {
  const p = cached(key, fn, opts);
  const e = store.get(key); if (e) e.warm = true;
  return p;
}
