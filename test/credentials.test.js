// Role sessions renew themselves during long scans; expired base keys fail clearly and are not retried.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { refreshingRoleCredentials } from '../src/aws/credentials.js';
import { classifyError } from '../src/queue.js';

const HOUR = 3600e3;
function fakeSts(clock) {
  let n = 0;
  return { calls: () => n, assume: async () => { n++; await new Promise((r) => setTimeout(r, 5)); return { accessKeyId: `ASIA${n}`, secretAccessKey: 's', sessionToken: 't', expiration: new Date(clock.t + HOUR) }; } };
}

test('a scan longer than one role session keeps getting valid credentials', async () => {
  const clock = { t: Date.UTC(2026, 10, 7) };
  const sts = fakeSts(clock);
  const creds = refreshingRoleCredentials({ assume: sts.assume, now: () => clock.t });
  assert.equal((await creds()).accessKeyId, 'ASIA1');
  clock.t += 50 * 60e3;                                    // 50 min in: still 10 min left, reused
  assert.equal((await creds()).accessKeyId, 'ASIA1');
  clock.t += 6 * 60e3;                                     // 4 min left: renewed before it can expire
  assert.equal((await creds()).accessKeyId, 'ASIA2');
  for (let h = 0; h < 6; h++) { clock.t += 58 * 60e3; const c = await creds(); assert.ok(c.expiration.getTime() - clock.t > 5 * 60e3); }
  assert.equal(sts.calls(), 8);                            // about one AssumeRole per hour over 7 hours
});

test('many parallel calls share one AssumeRole', async () => {
  const clock = { t: 0 };
  const sts = fakeSts(clock);
  const creds = refreshingRoleCredentials({ assume: sts.assume, now: () => clock.t });
  const all = await Promise.all(Array.from({ length: 20 }, () => creds()));
  assert.equal(sts.calls(), 1); assert.ok(all.every((c) => c.accessKeyId === 'ASIA1'));
});

test('expired base keys fail at once with a clear reason; an expired role session is retried', async () => {
  const creds = refreshingRoleCredentials({ assume: async () => { throw Object.assign(new Error('The security token included in the request is expired'), { name: 'ExpiredTokenException' }); } });
  const e = await creds().catch((x) => x);
  assert.equal(e.retryable, false); assert.match(e.message, /temporary keys/);
  assert.equal(classifyError(e), false);
  assert.equal(classifyError(Object.assign(new Error('The security token included in the request is expired'), { name: 'ExpiredTokenException' })), true);
  assert.equal(classifyError(Object.assign(new Error('not authorized'), { name: 'AccessDenied' })), false);
});
