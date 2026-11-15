// Resumable pipeline orchestrator — Temporal-style sequencing without the Temporal
// dependency yet (Module 2 runs stages in-process; the containerized/K8s + Temporal
// wiring is the documented follow-up). State is kept per runId so a crashed campaign
// resumes from the last done stage instead of re-acquiring.
import { randomUUID } from 'node:crypto';
import { publish } from './bus.js';
import { acquire, type FirmwareRecord } from './stages/acquisition.js';
import { planUnpack } from './stages/unpack.js';
import { scanSecrets, scanSinks } from './stages/static.js';
import { buildSbom, buildVex, inferComponents, type Stage4Result } from './stages/sbom.js';
import { verifyRootOfTrust, type RoTEvidence, type RoTReport } from './stages/rootOfTrust.js';
import { startSession, type BootSession, type EmulatorConfig } from './stages/emulator.js';
import { parseCallGraph, traceTaint, type TaintPath } from './stages/taint.js';
import { type FuzzResult } from './stages/fuzz.js';
import { correlate, type ScoredFinding } from './stages/consensus.js';
import { verifyPatch, type PatchReport } from './stages/patchVerify.js';
import { parseElf, carveGzip, type ElfInfo, type GzipMember } from './stages/binary.js';
import { type ProtoFinding } from './stages/protocol.js';
import { offload, getPoolInfo } from './pool.js';

export type PipelineStage = 'acquisition' | 'unpack' | 'static' | 'sbom' | 'root-of-trust' | 'discovery' | 'network' | 'report';

export const PIPELINE_ORDER: PipelineStage[] = [
  'acquisition',
  'unpack',
  'static',
  'sbom',
  'root-of-trust',
  'discovery',
  'network',
  'report',
];

export type StageStatus = 'pending' | 'running' | 'done' | 'failed' | 'skipped';

// Round 15 — real throughput observability: every run records its wall time,
// per-stage durations, and engine throughput (fuzz execs/sec), plus how the
// CPU-bound jobs actually executed (worker threads vs inline fallback).
export type RunMetrics = {
  wallMs: number;
  stageMs: Partial<Record<PipelineStage, number>>;
  jobsDispatched: number; // CPU jobs sent through the pool (any mode)
  poolMode: string; // 'threads' | 'inline' | 'uninitialized' — real mode used
  staticTextBytes: number;
  fuzzExecsPerSec: number | null; // fuzz throughput when the fuzz job ran
  protocolExecs: number | null;
  findingsCount: number;
};

export type RunState = {
  runId: string;
  firmware: FirmwareRecord;
  stages: Record<PipelineStage, StageStatus>;
  metrics: RunMetrics;
  artifacts: { sbom?: Stage4Result['sbom']; vex?: Stage4Result['vex']; binary?: { elf?: ElfInfo | { valid: false; reason: string }; gzipMembers?: GzipMember[] } };
  findings: { secrets: ReturnType<typeof scanSecrets>; sinks: ReturnType<typeof scanSinks> };
  taintPaths: TaintPath[];
  fuzz: FuzzResult | null;
  protocolFindings: ProtoFinding[];
  consensus: ScoredFinding[]; // consensus-scored, priority-ordered — the analyst queue
  patchVerdict: PatchReport | null; // set when a prior build is supplied for comparison
  rotReport: RoTReport | null;
  emulator: BootSession | null; // live twin backing discovery + N-day re-runs (Module 4)
  handoff: string | null; // what the next module (discovery) receives
  updatedAt: string;
};

const runs = new Map<string, RunState>();

export function getRun(runId: string): RunState | undefined {
  return runs.get(runId);
}

export type DiscoveryOpts = {
  callGraphText?: string; // `caller -> callee` edges (Ghidra export in prod)
  fuzzIterations?: number; // fuzz the demo harness; prod targets plug in via workers API
  fuzzHarness?: 'demo'; // explicit opt-in only — never fabricate crashes silently
  fuzzSeeds?: string[];
  protocol?: { machine: 'ble-gatt' | 'mqtt' | 'modbus'; iterations?: number; target?: 'demo-buggy' | 'reference' };
};

export type PatchCompareOpts = {
  oldRaw: Uint8Array;
  newRaw: Uint8Array;
  oldText?: string;
  newText?: string;
  vulnSink?: string;
  oldVersion?: string;
  newVersion?: string;
};

export async function runPipeline(
  raw: Uint8Array,
  meta: { version: string; id?: string; orgId?: string },
  opts: {
    resumeFrom?: PipelineStage;
    textForStatic?: string;
    rotEvidence?: RoTEvidence;
    emulatorConfig?: EmulatorConfig;
    discovery?: DiscoveryOpts;
    patchCompare?: PatchCompareOpts;
  } = {}
): Promise<RunState> {
  const runId = randomUUID();
  const firmware = acquire(raw, meta);
  const startedAt = performance.now();
  const metrics: RunMetrics = {
    wallMs: 0,
    stageMs: {},
    jobsDispatched: 0,
    poolMode: 'unknown',
    staticTextBytes: 0,
    fuzzExecsPerSec: null,
    protocolExecs: null,
    findingsCount: 0,
  };
  const state: RunState = {
    runId,
    firmware,
    stages: Object.fromEntries(PIPELINE_ORDER.map((s) => [s, 'pending'])) as Record<PipelineStage, StageStatus>,
    metrics,
    artifacts: {},
    findings: { secrets: [], sinks: [] },
    taintPaths: [],
    fuzz: null,
    protocolFindings: [],
    consensus: [],
    patchVerdict: null,
    rotReport: null,
    emulator: null,
    handoff: null,
    updatedAt: new Date().toISOString(),
  };
  runs.set(runId, state);

  const done = (s: PipelineStage, status: StageStatus = 'done', data?: unknown) => {
    state.stages[s] = status;
    state.updatedAt = new Date().toISOString();
    publish({ type: status === 'done' ? 'stage.done' : 'stage.failed', firmwareId: firmware.id, runId, stage: s, ...(data !== undefined ? { data } : {}) });
  };

  // Stage wrapper: status transitions + per-stage duration + optional payload
  // on the done event. Stage bodies write to DISJOINT parts of the run state,
  // so tiers below can safely run concurrently.
  const runStage = async (s: PipelineStage, fn: () => Promise<unknown> | unknown): Promise<void> => {
    state.stages[s] = 'running';
    publish({ type: 'stage.started', firmwareId: firmware.id, runId, stage: s });
    const t0 = performance.now();
    const data = await fn();
    metrics.stageMs[s] = Math.round((performance.now() - t0) * 1000) / 1000; // µs-resolution
    done(s, 'done', data);
  };

  const order: PipelineStage[] = ['acquisition', 'unpack', 'static', 'sbom'];
  const startAt = opts.resumeFrom ? order.indexOf(opts.resumeFrom) : 0;

  // unpack computes the layout once; sbom reuses it instead of re-planning the
  // same bytes (the duplicate planUnpack call was pure wasted work). Resume
  // runs that skip unpack recompute it exactly as before.
  let plan: ReturnType<typeof planUnpack> | null = null;

  try {
    // acquisition
    if (startAt <= 0) {
      state.stages.acquisition = 'running';
      publish({ type: 'stage.started', firmwareId: firmware.id, runId, stage: 'acquisition' });
      done('acquisition');
    }
    // unpack
    if (startAt <= 1) {
      await runStage('unpack', () => {
        plan = planUnpack(raw); // plan recorded; containerized worker executes extraction
        // Real parsing where the pure-TS decoders reach: ELF headers + gzip members.
        const kinds = new Set(plan.hits.map((h) => h.kind));
        const binary: NonNullable<typeof state.artifacts.binary> = {};
        if (kinds.has('elf')) binary.elf = parseElf(raw);
        if (kinds.has('gzip')) binary.gzipMembers = carveGzip(raw);
        if (Object.keys(binary).length) state.artifacts.binary = binary;
        return { planHits: plan.hits.length };
      });
    }
    if (startAt <= 2) {
      // TIER 1 — independent analyses run concurrently (worker threads in the
      // compiled package; inline interleaving otherwise): static/secrets scan,
      // sbom/vex build, root-of-trust verification, patch comparison.
      const tier1: Promise<void>[] = [];
      tier1.push(
        runStage('static', async () => {
          const text = opts.textForStatic ?? '';
          metrics.staticTextBytes = text.length;
          if (text) {
            metrics.jobsDispatched++;
            const r = await offload({ kind: 'static', text });
            if (r.kind === 'static') {
              state.findings.secrets = r.secrets;
              state.findings.sinks = r.sinks;
            }
          } else {
            state.findings.secrets = [];
            state.findings.sinks = [];
          }
          return { secrets: state.findings.secrets.length, sinks: state.findings.sinks.length };
        }),
      );
      tier1.push(
        runStage('sbom', () => {
          const hits = (plan ?? planUnpack(raw)).hits;
          const sbom = buildSbom(firmware, inferComponents(hits));
          const vex = buildVex([]);
          state.artifacts.sbom = sbom;
          state.artifacts.vex = vex;
          return { components: sbom.components.length };
        }),
      );
      if (opts.rotEvidence)
        tier1.push(
          runStage('root-of-trust', () => {
            state.rotReport = verifyRootOfTrust(opts.rotEvidence!);
            return { passed: state.rotReport.passed };
          }),
        );
      if (opts.patchCompare)
        tier1.push(
          runStage('report', () => {
            state.patchVerdict = verifyPatch(opts.patchCompare!);
            return { patch: state.patchVerdict.verdict };
          }),
        );
      await Promise.all(tier1);
    } else {
      // resume directly into sbom (resumeFrom = 'sbom' re-runs it)
      await runStage('sbom', () => {
        const hits = (plan ?? planUnpack(raw)).hits;
        const sbom = buildSbom(firmware, inferComponents(hits));
        const vex = buildVex([]);
        state.artifacts.sbom = sbom;
        state.artifacts.vex = vex;
        return { components: sbom.components.length };
      });
    }

    // live twin (Module 4) — boot the emulator when a config is supplied so the
    // discovery engine (Module 5) inherits a running session with snapshot support
    if (opts.emulatorConfig) {
      state.emulator = startSession(opts.emulatorConfig);
      publish({ type: 'stage.started', firmwareId: firmware.id, runId, stage: 'discovery', data: { emulator: state.emulator.id } });
    }

    // discovery (Modules 5–6) — taint first (its sinks steer the fuzzer), then
    // fuzz and protocol fuzz CONCURRENTLY (both CPU jobs go through the pool),
    // then consensus over everything.
    if (opts.discovery) {
      const d = opts.discovery;
      await runStage('discovery', async () => {
        if (d.callGraphText) state.taintPaths = traceTaint(parseCallGraph(d.callGraphText));
        const sub: Promise<void>[] = [];
        if (d.fuzzHarness === 'demo') {
          sub.push(
            (async () => {
              metrics.jobsDispatched++;
              const r = await offload({
                kind: 'fuzz',
                seeds: d.fuzzSeeds ?? ['GET /', 'GET /admin'],
                iterations: d.fuzzIterations ?? 2000,
                sinkHints: state.taintPaths.map((t) => t.sink),
              });
              if (r.kind === 'fuzz') {
                state.fuzz = r.result;
                metrics.fuzzExecsPerSec = r.ms > 0 ? Math.round((r.result.execs / r.ms) * 1000) : null;
              }
            })(),
          );
        }
        if (d.protocol) {
          const proto = d.protocol;
          sub.push(
            (async () => {
              metrics.jobsDispatched++;
              const r = await offload({ kind: 'protocol-fuzz', machine: proto.machine, target: proto.target ?? 'reference', iterations: proto.iterations ?? 2000 });
              if (r.kind === 'protocol-fuzz') {
                state.protocolFindings = r.findings;
                metrics.protocolExecs = r.execs;
              }
            })(),
          );
        }
        await Promise.all(sub);
        state.consensus = correlate({
          taintPaths: state.taintPaths,
          fuzzCrashes: (state.fuzz?.crashes ?? []).map((c) => ({ reason: c.reason, inputHex: c.inputHex })),
          sinks: state.findings.sinks,
          secrets: state.findings.secrets,
          snapshotRef: state.emulator?.snapshots.at(-1)?.id ?? null,
        });
        return {
          taintPaths: state.taintPaths.length,
          fuzzExecs: state.fuzz?.execs ?? 0,
          protocolFindings: state.protocolFindings.length,
          consensus: state.consensus.length,
        };
      });
    }

    // hand-off (Module 7+ owns graph/report — pipeline just sequences them per spec §5)
    state.handoff =
      `report ← ${state.consensus.length} consensus finding(s), ${state.protocolFindings.length} protocol finding(s)` +
      (state.rotReport ? `; rot=${state.rotReport.passed ? 'pass' : 'FAIL'}` : ' (rot pending)') +
      (state.patchVerdict ? `; patch=${state.patchVerdict.verdict}` : '');
    publish({ type: 'handoff.discovery', firmwareId: firmware.id, runId, data: { findings: state.consensus.length } });
  } catch (e) {
    const cur = (Object.entries(state.stages).find(([, v]) => v === 'running')?.[0] ?? 'acquisition') as PipelineStage;
    done(cur, 'failed');
    throw e;
  } finally {
    metrics.wallMs = Math.round((performance.now() - startedAt) * 10) / 10;
    metrics.poolMode = getPoolInfo().mode;
    metrics.findingsCount = state.consensus.length;
    state.metrics = metrics;
    state.updatedAt = new Date().toISOString();
    publish({ type: 'pipeline.metrics', firmwareId: firmware.id, runId, data: metrics });
  }
  return state;
}
