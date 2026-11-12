// The API's small cache: fresh answers as they are, older ones at once while a new one is worked out behind.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { cached, clearCache, scopeKey } from '../src/cache.js';

const wait = (ms) => new Promise((r) => setTimeout(r, ms));

test('fresh is reused; stale is returned at once and replaced in the background; too old waits for a new one', async () => {
  clearCache();
  let n = 0;
  const fn = async () => { await wait(20); return ++n; };
  const o = { freshMs: 60, staleMs: 400 };
  assert.equal(await cached('a', fn, o), 1);
  assert.equal(await cached('a', fn, o), 1);            // fresh: not worked out again
  const [x, y] = await Promise.all([cached('b', fn, o), cached('b', fn, o)]);
  assert.equal(x, y);                                    // two askers at once share one answer
  await wait(80);
  const t = Date.now();
  assert.equal(await cached('a', fn, o), 1);            // stale: the old answer, without waiting
  assert.ok(Date.now() - t < 15);
  await wait(40);
  assert.equal(await cached('a', fn, o), 3);            // the refresh has landed
  await wait(450);
  assert.equal(await cached('a', fn, o), 4);            // too old to show: waits
  assert.equal(await cached('a', fn, { freshMs: 0 }), 5);   // caching off
});

test('a failure is not remembered, and viewers with different scopes do not share answers', async () => {
  clearCache();
  await assert.rejects(cached('c', async () => { throw new Error('down'); }, { freshMs: 60, staleMs: 400 }), /down/);
  assert.equal(await cached('c', async () => 'ok', { freshMs: 60, staleMs: 400 }), 'ok');
  assert.equal(scopeKey({ scope_accounts: null }), '*');
  assert.equal(scopeKey({ scope_accounts: ['b', 'a'] }), 'a,b');
});
