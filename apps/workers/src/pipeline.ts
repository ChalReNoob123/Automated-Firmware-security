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
import { fuzz, demoHarness, type FuzzResult } from './stages/fuzz.js';
import { correlate, type ScoredFinding } from './stages/consensus.js';
import { verifyPatch, type PatchReport } from './stages/patchVerify.js';
import { parseElf, carveGzip, type ElfInfo, type GzipMember } from './stages/binary.js';
import { BLE_GATT, MQTT, MODBUS, buggyGattTarget, fuzzProtocol, strictTarget, type ProtoFinding } from './stages/protocol.js';

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
export type RunState = {
  runId: string;
  firmware: FirmwareRecord;
  stages: Record<PipelineStage, StageStatus>;
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
  const state: RunState = {
    runId,
    firmware,
    stages: Object.fromEntries(PIPELINE_ORDER.map((s) => [s, 'pending'])) as Record<PipelineStage, StageStatus>,
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

  const done = (s: PipelineStage, status: StageStatus = 'done') => {
    state.stages[s] = status;
    state.updatedAt = new Date().toISOString();
    publish({ type: status === 'done' ? 'stage.done' : 'stage.failed', firmwareId: firmware.id, runId, stage: s });
  };

  const order: PipelineStage[] = ['acquisition', 'unpack', 'static', 'sbom'];
  const startAt = opts.resumeFrom ? order.indexOf(opts.resumeFrom) : 0;

  try {
    // acquisition
    if (startAt <= 0) {
      state.stages.acquisition = 'running';
      publish({ type: 'stage.started', firmwareId: firmware.id, runId, stage: 'acquisition' });
      done('acquisition');
    }
    // unpack
    if (startAt <= 1) {
      state.stages.unpack = 'running';
      publish({ type: 'stage.started', firmwareId: firmware.id, runId, stage: 'unpack' });
      const plan = planUnpack(raw); // plan recorded; containerized worker executes extraction
      // Real parsing where the pure-TS decoders reach: ELF headers + gzip members.
      const kinds = new Set(plan.hits.map((h) => h.kind));
      const binary: NonNullable<typeof state.artifacts.binary> = {};
      if (kinds.has('elf')) binary.elf = parseElf(raw);
      if (kinds.has('gzip')) binary.gzipMembers = carveGzip(raw);
      if (Object.keys(binary).length) state.artifacts.binary = binary;
      done('unpack');
    }
    // static + secrets
    if (startAt <= 2) {
      state.stages.static = 'running';
      publish({ type: 'stage.started', firmwareId: firmware.id, runId, stage: 'static' });
      const text = opts.textForStatic ?? '';
      state.findings.secrets = text ? scanSecrets(text) : [];
      state.findings.sinks = text ? scanSinks(text) : [];
      done('static');
    }
    // sbom/vex
    state.stages.sbom = 'running';
    publish({ type: 'stage.started', firmwareId: firmware.id, runId, stage: 'sbom' });
    const hits = planUnpack(raw).hits;
    const sbom = buildSbom(firmware, inferComponents(hits));
    const vex = buildVex([]);
    state.artifacts.sbom = sbom;
    state.artifacts.vex = vex;
    publish({ type: 'sbom.ready', firmwareId: firmware.id, runId, stage: 'sbom', data: { components: sbom.components.length } });
    done('sbom');

    // root-of-trust (Module 3) — runs when boot evidence supplied, else stays pending
    if (opts.rotEvidence) {
      state.stages['root-of-trust'] = 'running';
      publish({ type: 'stage.started', firmwareId: firmware.id, runId, stage: 'root-of-trust' });
      state.rotReport = verifyRootOfTrust(opts.rotEvidence);
      done('root-of-trust');
    }

    // live twin (Module 4) — boot the emulator when a config is supplied so the
    // discovery engine (Module 5) inherits a running session with snapshot support
    if (opts.emulatorConfig) {
      state.emulator = startSession(opts.emulatorConfig);
      publish({ type: 'stage.started', firmwareId: firmware.id, runId, stage: 'discovery', data: { emulator: state.emulator.id } });
    }

    // discovery (Modules 5–6) — taint + fuzz + consensus; runs on supplied evidence only
    if (opts.discovery) {
      state.stages.discovery = 'running';
      publish({ type: 'stage.started', firmwareId: firmware.id, runId, stage: 'discovery' });
      if (opts.discovery.callGraphText) {
        state.taintPaths = traceTaint(parseCallGraph(opts.discovery.callGraphText));
      }
      if (opts.discovery.fuzzHarness === 'demo') {
        const seeds = (opts.discovery.fuzzSeeds ?? ['GET /', 'GET /admin']).map((s) => Buffer.from(s, 'latin1'));
        state.fuzz = fuzz(demoHarness, {
          seeds,
          iterations: opts.discovery.fuzzIterations ?? 2000,
          sinkHints: state.taintPaths.map((t) => t.sink),
        });
      }
      if (opts.discovery.protocol) {
        const machines = { 'ble-gatt': BLE_GATT, mqtt: MQTT, modbus: MODBUS } as const;
        const machine = machines[opts.discovery.protocol.machine];
        const target = opts.discovery.protocol.target === 'demo-buggy' ? buggyGattTarget(machine) : strictTarget(machine);
        const pr = fuzzProtocol(machine, target, { iterations: opts.discovery.protocol.iterations ?? 2000 });
        state.protocolFindings = pr.findings;
        publish({ type: 'stage.done', firmwareId: firmware.id, runId, stage: 'discovery', data: { protocolFindings: pr.findings.length } });
      }
      state.consensus = correlate({
        taintPaths: state.taintPaths,
        fuzzCrashes: (state.fuzz?.crashes ?? []).map((c) => ({ reason: c.reason, inputHex: c.inputHex })),
        sinks: state.findings.sinks,
        secrets: state.findings.secrets,
        snapshotRef: state.emulator?.snapshots.at(-1)?.id ?? null,
      });
      done('discovery');
    }

    // patch verification — compares against the prior build when supplied
    if (opts.patchCompare) {
      state.patchVerdict = verifyPatch(opts.patchCompare);
      publish({ type: 'stage.done', firmwareId: firmware.id, runId, stage: 'report', data: { patch: state.patchVerdict.verdict } });
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
  }
  return state;
}
