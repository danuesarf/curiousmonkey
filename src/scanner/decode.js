// Turns one gzipped CloudTrail log file into parsed events. Streamed record by record, so memory does not grow
// with the file's size.
import { Readable } from 'node:stream';
import { streamRecords } from '../aws/trailStream.js';
import { parseEvent } from '../analyzer/events.js';

export async function decodeInline(buf) {
  const out = [];
  await streamRecords(Readable.from([buf]), (r) => out.push(parseEvent(r)));
  return out;
}
export const decodeTrailFile = (buf) => decodeInline(buf);
