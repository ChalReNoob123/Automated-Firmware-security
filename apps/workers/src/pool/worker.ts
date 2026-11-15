// Worker entry — compiled to dist/pool/worker.js and spawned by ../pool.js via
// new URL('./pool/worker.js', import.meta.url). Runs serializable engine jobs
// off the main thread; results (or per-job errors) post back as JSON. A job
// that throws must never kill the worker — only infrastructure failures do.
import { parentPort } from 'node:worker_threads';
import { runJob, type PoolJob, type PoolResult } from './jobs.js';

const port = parentPort;
if (!port) throw new Error('pool/worker.js must run under worker_threads');

port.on('message', (m: { id: number; job: PoolJob }) => {
  try {
    const result: PoolResult = runJob(m.job);
    port.postMessage({ id: m.id, ok: true, value: result });
  } catch (e) {
    port.postMessage({ id: m.id, ok: false, error: String(e).slice(0, 300) });
  }
});
