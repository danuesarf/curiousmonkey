// Reads a gzipped CloudTrail log file ({"Records":[{...},{...}]}) one record at a time.
// A busy account's file can be tens of MB of JSON; parsing it whole (and several at once) runs the heap out.
// Here only the record being parsed is held as a string, so memory stays flat whatever the file size.
import { createGunzip } from 'node:zlib';
import { StringDecoder } from 'node:string_decoder';

/** Calls onRecord(obj) for each element of the top-level "Records" array. Resolves with the count. */
export function streamRecords(readable, onRecord) {
  return new Promise((resolve, reject) => {
    const gz = createGunzip();
    const dec = new StringDecoder('utf8');
    let depth = 0, inStr = false, esc = false, start = -1, buf = '', n = 0;
    const scan = (text) => {
      // buf holds the unfinished record (from its '{'), so scanning resumes where it stopped
      let i = buf.length;
      buf += text;
      for (; i < buf.length; i++) {
        const ch = buf.charCodeAt(i);
        if (inStr) { if (esc) esc = false; else if (ch === 92) esc = true; else if (ch === 34) inStr = false; continue; }
        if (ch === 34) { inStr = true; continue; }
        if (ch === 123 || ch === 91) {                     // { [
          depth++;
          if (depth === 3 && ch === 123) start = i;        // {"Records":[ {record} ]}: a record opens at depth 3
        } else if (ch === 125 || ch === 93) {              // } ]
          if (depth === 3 && ch === 125 && start >= 0) {
            onRecord(JSON.parse(buf.slice(start, i + 1))); n++;
            buf = buf.slice(i + 1); i = -1; start = -1;   // drop what has been parsed
          }
          depth--;
        }
      }
      if (start < 0) buf = '';                             // between records: nothing to keep
      else if (start > 0) { buf = buf.slice(start); start = 0; }
    };
    gz.on('data', (chunk) => { try { scan(dec.write(chunk)); } catch (e) { gz.destroy(e); } });
    gz.on('end', () => { try { scan(dec.end()); resolve(n); } catch (e) { reject(e); } });
    gz.on('error', reject);
    readable.on('error', reject);
    readable.pipe(gz);
  });
}
