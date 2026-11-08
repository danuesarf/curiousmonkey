// Parser thread: gzipped CloudTrail file in, parsed events out.
import { parentPort } from 'node:worker_threads';
import { decodeInline } from './decode.js';

parentPort.on('message', async ({ id, buf }) => {
  try { parentPort.postMessage({ id, events: await decodeInline(Buffer.from(buf)) }); }
  catch (e) { parentPort.postMessage({ id, error: { message: e.message, name: e.name } }); }
});
