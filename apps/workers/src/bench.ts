// Engine throughput benchmark — the honest A/B for round 15.
// Run against the COMPILED package (threads mode needs dist/pool/worker.js):
//   npm run build --workspace @sentinelforge/workers
//   node apps/workers/dist/bench.js
// Prints wall time + aggregate fuzz execs/sec for N concurrent full pipeline
// campaigns, first with offload forced inline, then with the thread pool.
import { pathToFileURL } from 'node:url';
import { runPipeline } from './pipeline.js';
import { setPoolMode, getPoolInfo } from './pool.js';

const elfImage = () => {
  const elf = Buffer.alloc(64);
  elf.writeUInt32LE(0x464c457f, 0);
  elf[4] = 2;
  elf[5] = 1;
  elf.writeUInt16LE(40, 18);
  return new Uint8Array(elf);
};

const TEXT = 'recv(buf);\nstrcpy(d, s);\nsystem(cmd);\nmemcpy(d, s, n);\npassword = "hunter2hunter2";\n'.repeat(1200);

const campaign = () =>
  runPipeline(elfImage(), { version: 'bench' }, {
    textForStatic: TEXT,
    discovery: {
      callGraphText: 'recv -> strcpy',
      fuzzHarness: 'demo',
      fuzzIterations: 30_000,
      protocol: { machine: 'ble-gatt', target: 'demo-buggy', iterations: 4_000 },
    },
  });

async function batch(n: number): Promise<number> {
  const t0 = performance.now();
  await Promise.all(Array.from({ length: n }, () => campaign()));
  return performance.now() - t0;
}

async function main() {
  const N = Number(process.env.BENCH_N ?? 4);
  const totalExecs = N * 30_000; // fuzz execs per batch (protocol execs add more)

  setPoolMode('inline');
  const inlineMs = await batch(N);

  setPoolMode('auto');
  const threadMs = await batch(N);

  const fmt = (ms: number) => Math.round(ms);
  const rate = (ms: number) => Math.round(totalExecs / (ms / 1000));
  const info = getPoolInfo();
  console.log('=== SentinelForge engine throughput bench ===');
  console.log(`campaigns: ${N} concurrent | fuzz ${30_000} iters + protocol ${4_000} iters + ${Math.round(TEXT.length / 1024)} KB static scan each`);
  console.log(`inline : ${fmt(inlineMs)} ms  (${rate(inlineMs).toLocaleString()} fuzz execs/s aggregate)`);
  console.log(`threads: ${fmt(threadMs)} ms  (${rate(threadMs).toLocaleString()} fuzz execs/s aggregate)  mode=${info.mode} workers=${info.workers}/${info.maxWorkers}`);
  if (threadMs > 0) console.log(`speedup: ${(inlineMs / threadMs).toFixed(2)}x`);
  console.log(`pool: dispatched=${info.dispatched} threaded=${info.threaded} inline=${info.inline} degradations=${JSON.stringify(info.degradations)}`);
  process.exit(0); // worker threads are unref'd; end the bench explicitly
}

const isMain = process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href;
if (isMain) {
  main().catch((e) => {
    console.error('bench failed:', e);
    process.exit(1);
  });
}
