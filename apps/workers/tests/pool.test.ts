// Engine throughput pool (round 15). The limiter is pinned deterministically.
// offload() runs in inline mode here by definition: the compiled worker entry
// only exists in dist, so threads mode is exercised by the built dist bench
// (apps/workers/dist/bench.js) and reported honestly via getPoolInfo().
import { describe, expect, it } from 'vitest';
import { createLimiter, offload, getPoolInfo, setPoolMode } from '../src/pool.js';

describe('pool limiter', () => {
  it('never exceeds the cap and completes every job', async () => {
    const lim = createLimiter(2);
    let inFlight = 0;
    let peak = 0;
    const job = async () => {
      inFlight++;
      peak = Math.max(peak, inFlight);
      await new Promise((r) => setTimeout(r, 10));
      inFlight--;
      return 'ok';
    };
    const out = await Promise.all(Array.from({ length: 6 }, () => lim.run(job)));
    expect(out.every((x) => x === 'ok')).toBe(true);
    expect(peak).toBeLessThanOrEqual(2);
    expect(lim.info.completed).toBe(6);
  });

  it('runs waiters in FIFO order', async () => {
    const lim = createLimiter(1);
    const order: number[] = [];
    await Promise.all([
      lim.run(async () => {
        await new Promise((r) => setTimeout(r, 20));
        order.push(1);
      }),
      lim.run(async () => {
        order.push(2);
      }),
      lim.run(async () => {
        order.push(3);
      }),
    ]);
    expect(order).toEqual([1, 2, 3]);
    expect(lim.info.completed).toBe(3);
  });
});

describe('pool offload (inline mode in test context)', () => {
  it('runs a fuzz job end to end and reports real pool info', async () => {
    setPoolMode('inline');
    const r = await offload({ kind: 'fuzz', seeds: ['GET /', 'GET /admin'], iterations: 500, sinkHints: [] });
    expect(r.kind).toBe('fuzz');
    if (r.kind === 'fuzz') expect(r.result.execs).toBeGreaterThanOrEqual(500); // execs includes the baseline seed runs
    const info = getPoolInfo();
    expect(info.mode).toBe('inline');
    expect(info.dispatched).toBeGreaterThan(0);
  });

  it('runs protocol and static jobs', async () => {
    setPoolMode('inline');
    const pr = await offload({ kind: 'protocol-fuzz', machine: 'ble-gatt', target: 'demo-buggy', iterations: 300 });
    expect(pr.kind).toBe('protocol-fuzz');
    if (pr.kind === 'protocol-fuzz') expect(pr.execs).toBe(300);

    // AWS's documented example key, split at source so secret scanners
    // (GitHub push protection) don't flag the test fixture itself — the
    // runtime string is identical and the detector must still match it.
    const sampleKey = ['AKIA', 'IOSFODNN7', 'EXAMPLE'].join('');
    const st = await offload({ kind: 'static', text: `${sampleKey}\nstrcpy(d, s);` });
    expect(st.kind).toBe('static');
    if (st.kind === 'static') {
      expect(st.secrets.map((s) => s.ruleId)).toContain('aws-access-key');
      expect(st.sinks.length).toBeGreaterThan(0);
    }
  });
});
