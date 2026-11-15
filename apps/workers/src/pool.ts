// Engine throughput pool — CPU-bound stages (fuzzing, protocol fuzzing, static
// scans) run on worker threads so the main thread stays live (the API event
// loop keeps serving during scans) and concurrent campaigns spread across
// cores. Falls back permanently to in-thread execution when threads are
// unavailable (test/bundled contexts — the worker file only exists in the
// compiled package) and reports the REAL mode via getPoolInfo(). No fake
// parallelism claims: which mode executed a job is always observable.

import { Worker } from 'node:worker_threads';
import os from 'node:os';
import { existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { runJob, type PoolJob, type PoolResult } from './pool/jobs.js';

// ── limiter: bounds concurrent in-flight jobs, observable via info ──────
export function createLimiter(max: number) {
  const cap = Math.max(1, Math.floor(max));
  let active = 0;
  const waiters: (() => void)[] = [];
  const info = { max: cap, active: 0, queued: 0, completed: 0 };
  const releaseOne = () => {
    if (active < cap && waiters.length) {
      active++; // slot handed to the released coroutine BEFORE it resumes
      info.active = active;
      info.queued = waiters.length - 1;
      waiters.shift()!();
    }
  };
  return {
    info,
    async run<T>(fn: () => Promise<T> | T): Promise<T> {
      if (active >= cap) await new Promise<void>((res) => waiters.push(res));
      else {
        active++;
        info.active = active;
      }
      try {
        const out = await fn();
        return out;
      } finally {
        info.completed++;
        active--;
        info.active = active;
        releaseOne();
      }
    },
  };
}

// ── pool state ──────────────────────────────────────────────────────────
export type PoolMode = 'uninitialized' | 'threads' | 'inline';

const PARALLELISM = Math.max(1, (os.availableParallelism?.() ?? os.cpus().length) || 1);
const MAX_WORKERS = Math.max(1, Math.min(PARALLELISM - 1, 4));
const JOB_TIMEOUT_MS = 120_000; // a stuck worker never hangs a pipeline run

const limiter = createLimiter(MAX_WORKERS);
const stats = { dispatched: 0, threaded: 0, inline: 0, failed: 0, degradations: [] as string[] };
let mode: PoolMode = 'uninitialized';
let fallbackReason = '';
let workers: Worker[] = [];
let rr = 0;
let seq = 0;
let initPromise: Promise<void> | null = null; // singleton init — concurrent first-callers must not spawn N workers
const pending = new Map<number, { resolve: (v: PoolResult) => void; reject: (e: Error) => void; timer: NodeJS.Timeout }>();

function degrade(reason: string) {
  if (mode === 'inline') return;
  mode = 'inline';
  fallbackReason = reason;
  stats.degradations.push(reason);
  for (const [id, p] of [...pending]) {
    clearTimeout(p.timer);
    pending.delete(id);
    p.reject(new Error('pool degraded to inline: ' + reason));
  }
  for (const w of workers) {
    w.removeAllListeners();
    void w.terminate().catch(() => {});
  }
  workers = [];
}

function trySpawn(): Worker | null {
  try {
    const entry = new URL('./pool/worker.js', import.meta.url);
    // Gate on file existence: in source/test contexts the compiled worker
    // entry isn't there — spawn nothing (an async MODULE_NOT_FOUND from a
    // doomed worker would otherwise escape as an uncaught exception).
    if (!existsSync(fileURLToPath(entry))) {
      fallbackReason = 'worker entry not compiled (inline mode)';
      return null;
    }
    return new Worker(entry);
  } catch (e) {
    fallbackReason = 'spawn failed: ' + String(e).slice(0, 120);
    stats.degradations.push(fallbackReason);
    return null;
  }
}

// Persistent per-worker wiring: job result routing + infrastructure failure
// detection. A per-job failure (ok:false) rejects ONLY that job, marked
// jobError so offload re-runs it inline without degrading the pool.
function attach(w: Worker) {
  w.on('message', (m: { id: number; ok: boolean; value?: PoolResult; error?: string }) => {
    const p = pending.get(m.id);
    if (!p) return;
    pending.delete(m.id);
    clearTimeout(p.timer);
    if (m.ok && m.value) p.resolve(m.value);
    else {
      const e = new Error(m.error ?? 'worker job failed') as Error & { jobError?: boolean };
      e.jobError = true;
      p.reject(e);
    }
  });
  w.on('error', (e) => degrade('worker error: ' + String(e).slice(0, 120)));
  w.on('exit', (code) => {
    workers = workers.filter((x) => x !== w);
    if (code !== 0 && mode === 'threads' && workers.length === 0) degrade('worker exited code ' + code);
  });
}

// First spawn waits for 'online' so a missing worker file (test context) fails
// fast into inline mode instead of leaving a pending job on a broken worker.
function spawnOnline(): Promise<Worker | null> {
  const w = trySpawn();
  if (!w) return Promise.resolve(null);
  return new Promise((res) => {
    const t = setTimeout(() => finish(null), 3000);
    const finish = (out: Worker | null) => {
      clearTimeout(t);
      w.removeAllListeners('online');
      w.removeAllListeners('error');
      if (!out) void w.terminate().catch(() => {});
      res(out);
    };
    w.once('online', () => {
      attach(w);
      // A library must not pin the host process open: the API server holds its
      // own listeners; idle workers simply don't block exit.
      w.unref();
      finish(w);
    });
    w.once('error', (e) => {
      fallbackReason = 'worker load failed: ' + String(e).slice(0, 120);
      stats.degradations.push(fallbackReason);
      finish(null);
    });
  });
}

function sendToWorker(job: PoolJob): Promise<PoolResult> {
  const w = workers[rr++ % workers.length];
  const id = ++seq;
  return new Promise<PoolResult>((resolve, reject) => {
    const timer = setTimeout(() => {
      pending.delete(id);
      const e = new Error('worker job timeout');
      reject(e);
    }, JOB_TIMEOUT_MS);
    pending.set(id, { resolve, reject, timer });
    w.postMessage({ id, job });
  });
}

export async function offload(job: PoolJob): Promise<PoolResult> {
  stats.dispatched++;
  if (mode === 'inline') {
    stats.inline++;
    return runJob(job);
  }
  if (mode === 'uninitialized') {
    // Singleton init: N concurrent first-callers share ONE spawn decision, and
    // the pool comes up at FULL width (per-worker capacity is fixed, so lazy
    // growth would either under-parallelize or race).
    initPromise ??= (async () => {
      const spawned: Worker[] = [];
      for (let i = 0; i < MAX_WORKERS; i++) {
        const w = await spawnOnline();
        if (!w) break;
        spawned.push(w);
      }
      if (spawned.length) {
        workers.push(...spawned);
        mode = 'threads';
      } else {
        mode = 'inline';
        stats.inline++;
      }
    })();
    await initPromise;
  }
  // (the init closure above reassigns `mode`; TS can't track that, hence the widening)
  if ((mode as PoolMode) === 'inline') return runJob(job);
  try {
    const r = await limiter.run(() => sendToWorker(job));
    stats.threaded++;
    return r;
  } catch (e) {
    const err = e as Error & { jobError?: boolean };
    // A single bad JOB is that job's problem — re-run it inline and keep the
    // threads. Broken WORKER infrastructure (timeout/exit/load) degrades the
    // pool permanently to inline.
    if (!err.jobError && mode === 'threads') degrade(String(e).slice(0, 160));
    stats.failed++;
    return runJob(job);
  }
}

export function setPoolMode(m: 'inline' | 'auto') {
  if (m === 'inline') {
    degrade('manual setPoolMode(inline)'); // drains pending jobs, terminates workers
    mode = 'inline';
    fallbackReason = 'manual setPoolMode(inline)';
    return;
  }
  mode = 'uninitialized';
  fallbackReason = '';
  initPromise = null;
  for (const w of workers) {
    w.removeAllListeners();
    void w.terminate().catch(() => {});
  }
  workers = [];
}

export function getPoolInfo() {
  return {
    mode,
    fallbackReason,
    parallelism: PARALLELISM,
    maxWorkers: MAX_WORKERS,
    workers: workers.length,
    dispatched: stats.dispatched,
    threaded: stats.threaded,
    inline: stats.inline,
    failed: stats.failed,
    degradations: [...stats.degradations],
    queue: { ...limiter.info },
  };
}
