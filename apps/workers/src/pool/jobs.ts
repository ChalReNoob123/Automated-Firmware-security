// Serializable engine jobs + the in-thread implementations. Shared by the
// worker entry (threads mode) and pool.ts (inline fallback) so both modes run
// BYTE-IDENTICAL stage code. Job payloads are plain JSON so they cross
// worker-thread boundaries; the heavy functions they map to live in this
// package and are deterministic (fuzz's seeded PRNG), so a job produces the
// same result whichever mode executed it.

import { demoHarness, fuzz, type FuzzResult } from '../stages/fuzz.js';
import { BLE_GATT, MODBUS, MQTT, buggyGattTarget, fuzzProtocol, strictTarget, type ProtoFinding } from '../stages/protocol.js';
import { scanSecrets, scanSinks, type SecretFinding, type SinkHit } from '../stages/static.js';

export type PoolJob =
  | { kind: 'fuzz'; seeds: string[]; iterations: number; sinkHints: string[] }
  | { kind: 'protocol-fuzz'; machine: 'ble-gatt' | 'mqtt' | 'modbus'; target: 'demo-buggy' | 'reference'; iterations: number }
  | { kind: 'static'; text: string };

export type PoolResult =
  | { kind: 'fuzz'; result: FuzzResult; ms: number }
  | { kind: 'protocol-fuzz'; execs: number; findings: ProtoFinding[]; pairsHit: string[]; ms: number }
  | { kind: 'static'; secrets: SecretFinding[]; sinks: SinkHit[]; ms: number };

const MACHINES = { 'ble-gatt': BLE_GATT, mqtt: MQTT, modbus: MODBUS } as const;

export function runJob(job: PoolJob): PoolResult {
  const t0 = performance.now();
  if (job.kind === 'fuzz') {
    const result = fuzz(demoHarness, {
      seeds: job.seeds.map((s) => Buffer.from(s, 'latin1')),
      iterations: job.iterations,
      sinkHints: job.sinkHints,
    });
    return { kind: 'fuzz', result, ms: performance.now() - t0 };
  }
  if (job.kind === 'protocol-fuzz') {
    const machine = MACHINES[job.machine];
    const target = job.target === 'demo-buggy' ? buggyGattTarget(machine) : strictTarget(machine);
    const pr = fuzzProtocol(machine, target, { iterations: job.iterations });
    return { kind: 'protocol-fuzz', execs: pr.execs, findings: pr.findings, pairsHit: pr.pairsHit, ms: performance.now() - t0 };
  }
  return {
    kind: 'static',
    secrets: job.text ? scanSecrets(job.text) : [],
    sinks: job.text ? scanSinks(job.text) : [],
    ms: performance.now() - t0,
  };
}
