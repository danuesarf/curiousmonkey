// Secrets at rest (AES-256-GCM) and the database TLS settings.
import { test } from 'node:test';
import assert from 'node:assert/strict';

const { encrypt, decrypt } = await import('../src/auth/crypto.js');

test('encrypted values round-trip and carry a full 16-byte tag', () => {
  const blob = encrypt('aws-secret-for-the-test');
  assert.equal(decrypt(blob), 'aws-secret-for-the-test');
  assert.equal(Buffer.from(blob.split('.')[2], 'base64').length, 16);
});

test('a truncated or altered tag is refused, not accepted', () => {
  const [v, iv, tag, enc] = encrypt('x').split('.');
  const short = Buffer.from(tag, 'base64').subarray(0, 4).toString('base64');     // a 4-byte tag is guessable
  assert.throws(() => decrypt([v, iv, short, enc].join('.')), /malformed/);
  const flipped = Buffer.from(tag, 'base64'); flipped[0] ^= 1;
  assert.throws(() => decrypt([v, iv, flipped.toString('base64'), enc].join('.')));
  assert.throws(() => decrypt('v2.a.b.c'), /malformed/);
});

test('database TLS verifies the server certificate unless explicitly told not to', async () => {
  const { sslOptionsFor } = await import('../src/db.js');
  assert.equal(sslOptionsFor({ ssl: false, env: {} }), undefined);
  assert.deepEqual(sslOptionsFor({ ssl: true, env: {} }), { rejectUnauthorized: true });
  assert.deepEqual(sslOptionsFor({ ssl: true, env: { DATABASE_SSL_INSECURE: 'true' }, warn: () => {} }), { rejectUnauthorized: false });
});
