import { test } from 'node:test';
import assert from 'node:assert/strict';
import { gzipSync } from 'node:zlib';
import { Readable } from 'node:stream';
import { streamRecords } from '../src/aws/trailStream.js';

const recs = Array.from({ length: 2500 }, (_, i) => ({
  eventID: `e${i}`, eventTime: '2026-08-13T01:00:00Z', eventName: 'GetObject',
  requestParameters: { key: `a "quoted" {brace} [bracket] \\ back\\slash ${i}`, nested: { list: [1, { x: '}' }], empty: {} } },
  userAgent: 'aws-cli/2 é ü 日本',
}));
const file = gzipSync(Buffer.from(JSON.stringify({ Records: recs })));

test('streams every record of a gzipped CloudTrail file, across awkward chunk boundaries', async () => {
  for (const size of [1, 7, 333, 65536]) {
    const chunks = []; for (let i = 0; i < file.length; i += size) chunks.push(file.subarray(i, i + size));
    const got = [];
    const n = await streamRecords(Readable.from(chunks), (r) => got.push(r));
    assert.equal(n, recs.length, `chunk ${size}`);
    assert.deepEqual(got[0], recs[0]); assert.deepEqual(got.at(-1), recs.at(-1));
  }
});

test('an empty or record-less file yields nothing; a corrupt one rejects', async () => {
  assert.equal(await streamRecords(Readable.from([gzipSync(Buffer.from('{"Records":[]}'))]), () => {}), 0);
  await assert.rejects(streamRecords(Readable.from([Buffer.from('not gzip')]), () => {}));
});

test('parser threads return exactly what parsing on the main thread does, small pooled buffers included', async () => {
  process.env.TRAIL_PARSERS = '2';
  const { decodeInline, decodeTrailFile, closeDecoders } = await import('../src/scanner/decode.js');
  const small = gzipSync(Buffer.from(JSON.stringify({ Records: recs.slice(0, 3) })));       // < 4 KB: Node hands out a slice of a shared pool
  const pooled = Buffer.from(small);
  const [a, b, c] = await Promise.all([decodeTrailFile(Buffer.from(file)), decodeTrailFile(pooled), decodeTrailFile(Buffer.from(file))]);
  const ref = await decodeInline(file);
  assert.equal(a.length, recs.length);
  assert.deepEqual(a, ref); assert.deepEqual(c, ref);
  assert.deepEqual(b, await decodeInline(small));
  assert.equal(pooled.length, small.length);                                                 // the caller's buffer is not detached
  await assert.rejects(decodeTrailFile(Buffer.from('not gzip')));
  assert.equal((await decodeTrailFile(Buffer.from(file))).length, recs.length);              // still working after an error
  await closeDecoders();
  delete process.env.TRAIL_PARSERS;
});
