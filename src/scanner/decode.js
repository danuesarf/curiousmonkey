// Turns one gzipped CloudTrail log file into parsed events. Streamed record by record, so memory does not grow
// with the file's size. Unzipping and JSON parsing are the CPU-heavy part of reading a trail, so files are decoded
// on a pool of threads (one per spare core); the main thread only downloads and writes.
import os from 'node:os';
import { Readable } from 'node:stream';
import { Worker } from 'node:worker_threads';
import { streamRecords } from '../aws/trailStream.js';
import { parseEvent } from '../analyzer/events.js';

export async function decodeInline(buf) {
  const out = [];
  await streamRecords(Readable.from([buf]), (r) => out.push(parseEvent(r)));
  return out;
}

/**
 * Parser threads to run: TRAIL_PARSERS, else one per core beyond the two the writer and Postgres need.
 * On a 2-core machine threads do not help (measured: the hand-over costs what the parse saves), so parsing stays
 * on the main thread there. 0 = parse inline.
 */
export function parserCount() {
  if (process.env.TRAIL_PARSERS != null && process.env.TRAIL_PARSERS !== '') return Math.max(0, Number(process.env.TRAIL_PARSERS) || 0);
  const cores = os.availableParallelism?.() ?? os.cpus().length;
  return cores >= 4 ? Math.min(8, cores - 2) : 0;
}

class Pool {
  constructor(size) {
    this.size = size; this.threads = []; this.queue = []; this.pending = new Map(); this.seq = 0;
    for (let i = 0; i < size; i++) this.spawn();
  }
  spawn() {
    const w = new Worker(new URL('./decodeThread.js', import.meta.url), { resourceLimits: { maxOldGenerationSizeMb: Number(process.env.TRAIL_PARSER_HEAP_MB || 384) } });
    const t = { w, busy: null };
    w.unref();
    w.on('message', ({ id, events, error }) => {
      const p = this.pending.get(id); this.pending.delete(id); t.busy = null;
      if (p) error ? p.reject(Object.assign(new Error(error.message), { name: error.name })) : p.resolve(events);
      this.next();
    });
    const died = (err) => {                            // out of memory or a crash: fail its file, replace the thread
      const id = t.busy; t.busy = null;
      if (id != null && this.pending.has(id)) { this.pending.get(id).reject(Object.assign(err instanceof Error ? err : new Error(`parser thread exited (${err})`), { retryable: true })); this.pending.delete(id); }
      this.threads = this.threads.filter((x) => x !== t);
      if (!this.closed) { this.spawn(); this.next(); }
    };
    w.on('error', died);
    w.on('exit', (code) => { if (code !== 0 || t.busy != null) died(code); });
    this.threads.push(t);
  }
  run(buf) {
    // a pooled Buffer shares its ArrayBuffer with others: copy it so it can be transferred
    const ab = buf.byteOffset === 0 && buf.byteLength === buf.buffer.byteLength ? buf.buffer : buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength);
    return new Promise((resolve, reject) => { const id = ++this.seq; this.pending.set(id, { resolve, reject }); this.queue.push({ id, ab }); this.next(); });
  }
  next() {
    for (const t of this.threads) {
      if (t.busy != null || !this.queue.length) continue;
      const job = this.queue.shift(); t.busy = job.id;
      t.w.postMessage({ id: job.id, buf: job.ab }, [job.ab]);
    }
  }
  async close() { this.closed = true; await Promise.all(this.threads.map((t) => t.w.terminate())); this.threads = []; }
}

let pool = null;
export function decodeTrailFile(buf) {
  const n = parserCount();
  if (!n) return decodeInline(buf);
  if (!pool || pool.size !== n) { pool?.close(); pool = new Pool(n); }
  return pool.run(buf);
}
export async function closeDecoders() { if (pool) { await pool.close(); pool = null; } }
