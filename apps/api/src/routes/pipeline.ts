import { Router } from 'express';
import { z } from 'zod';
import { randomUUID } from 'node:crypto';
import { requireAuth } from '../middleware/rbac.js';
import { requireAttestation } from './devices.js';
import { getFirmware, getRunDoc, nextAnalysisRunSeq, persistAnalysisRun, putRun } from '../store.js';
import { priorityOf, runPipeline, type RunMetrics } from '@sentinelforge/workers';

const router = Router();

type QueuedRun = {
  runId: string;
  firmwareId: string;
  version: string;
  status: 'queued' | 'running' | 'done' | 'failed';
  createdAt: string;
  /** position in the analysis sequence, taken when the run is created */
  seq?: number;
  /** a newer run already applied its verdicts, so this one wrote nothing */
  superseded?: boolean;
  finishedAt?: string;
  // Executions are labeled: 'demo' = the deterministic synthetic image the
  // workers suite pins (real engine work, NOT a real customer firmware);
  // 'upload' = bytes a caller actually uploaded through POST /v1/firmware.
  source?: 'demo' | 'upload';
  profile?: 'demo';
  firmwareSha256?: string;
  stageStatus?: Record<string, string>;
  metrics?: RunMetrics;
  findingsCount?: number;
  // persisted rows produced by this run, so the UI can open their evidence
  findings?: { id: string; title: string; confidence: string; priority: number }[];
  /** analysis verdicts from an earlier run that this run no longer produces */
  removed?: string[];
  artifacts?: {
    elf?: { valid: boolean; machine?: string; bits?: number; endian?: string };
    gzipMembers?: number;
    components?: number;
    sha256?: string;
  };
  error?: string;
};
type Authed = { user: { org: string } };
const orgOf = (req: { user?: unknown }) => (req as unknown as { user?: { org?: string } }).user?.org ?? '';

// Deterministic synthetic image — same shape the workers tests pin (ELF header).
const demoImage = () => {
  const elf = Buffer.alloc(64);
  elf.writeUInt32LE(0x464c457f, 0);
  elf[4] = 2;
  elf[5] = 1;
  elf.writeUInt16LE(40, 18);
  return new Uint8Array(elf);
};
const DEMO_TEXT = 'recv(buf);\nstrcpy(d, s);\nsystem(cmd);\nmemcpy(d, s, n);\npassword = "hunter2hunter2";\n'.repeat(400);

// Throughput ledger per org (in-memory until Supabase wiring; honest about it).
export type RunSummary = {
  runId: string;
  wallMs: number;
  fuzzExecsPerSec: number | null;
  protocolExecs: number | null;
  findingsCount: number;
  poolMode: string;
  finishedAt: string;
};
const metricLog = new Map<string, RunSummary[]>();
const rememberMetric = (org: string, runId: string, m: RunMetrics) => {
  const list = metricLog.get(org) ?? [];
  list.unshift({
    runId,
    wallMs: m.wallMs,
    fuzzExecsPerSec: m.fuzzExecsPerSec,
    protocolExecs: m.protocolExecs,
    findingsCount: m.findingsCount,
    poolMode: m.poolMode,
    finishedAt: new Date().toISOString(),
  });
  metricLog.set(org, list.slice(0, 20));
};

// Actually execute a queued demo run with the pooled engine. Fire-and-forget:
// the 202 says "queued" honestly, and the run doc transitions queued → running
// → done/failed as the engine works. In-flight guard prevents double-executes.
const inFlight = new Set<string>();
async function executeQueuedDemo(org: string, run: QueuedRun) {
  if (inFlight.has(run.runId)) return;
  inFlight.add(run.runId);
  try {
    await putRun(org, run.runId, { ...run, status: 'running', profile: 'demo' });
    const state = await runPipeline(demoImage(), { version: run.version, id: run.firmwareId }, {
      textForStatic: DEMO_TEXT,
      discovery: {
        callGraphText: 'recv -> strcpy',
        fuzzHarness: 'demo',
        fuzzIterations: 20_000,
        protocol: { machine: 'ble-gatt', target: 'demo-buggy', iterations: 4_000 },
      },
    });
    const done: QueuedRun = {
      ...run,
      status: 'done',
      finishedAt: new Date().toISOString(),
      profile: 'demo',
      stageStatus: state.stages,
      metrics: state.metrics,
      findingsCount: state.consensus.length,
    };
    await putRun(org, run.runId, done);
    rememberMetric(org, run.runId, state.metrics);
  } catch (e) {
    await putRun(org, run.runId, { ...run, status: 'failed', finishedAt: new Date().toISOString(), profile: 'demo', error: String(e).slice(0, 200) }).catch(() => {});
  } finally {
    inFlight.delete(run.runId);
  }
}

// Real image execution (round 33): acquisition → unpack → strings-based static
// → SBOM over the uploaded bytes, then every consensus finding is PERSISTED
// into the findings queue so its evidence page can open it. Discovery/fuzz stay
// off for uploads on purpose: they need a call graph or the demo harness, and
// spraying a demo harness at a real image would manufacture the exact
// false positives this product claims to eliminate. Stages that cannot run are
// reported as not-run rather than faked.
async function executeQueuedUpload(org: string, run: QueuedRun, data: Uint8Array) {
  if (inFlight.has(run.runId)) return;
  inFlight.add(run.runId);
  try {
    await putRun(org, run.runId, { ...run, status: 'running' });
    const state = await runPipeline(data, { id: run.firmwareId, version: run.version });
    // Ordering comes from the sequence, not the clock. One transaction writes this
    // run's verdicts and prunes the ones it no longer produces; a run whose
    // sequence is already behind the image's applied sequence writes nothing.
    const runSeq = run.seq ?? (await nextAnalysisRunSeq());
    const write = await persistAnalysisRun(
      org,
      run.firmwareId,
      { seq: runSeq, startedAt: run.createdAt },
      state.consensus.map((c) => ({
        title: c.title,
        confidence: c.confidence,
        engines: c.engines as string[],
        why: c.why.join('; '),
        ...(c.snapshotRef ? { snapshotRef: c.snapshotRef } : {}),
        ...(c.epss != null ? { epss: c.epss } : {}),
        ...(c.ssvc ? { ssvc: c.ssvc } : {}),
      }))
    );
    if (!write.applied) {
      await putRun(org, run.runId, {
        ...run,
        seq: runSeq,
        status: 'done',
        superseded: true,
        finishedAt: new Date().toISOString(),
        findingsCount: 0,
        findings: [],
        note: 'a newer analysis of this image already applied its verdicts — this run wrote nothing',
      });
      return;
    }
    const created: NonNullable<QueuedRun['findings']> = write.rows.map((row) => ({
      id: row.id,
      title: row.title,
      confidence: row.confidence,
      priority: priorityOf({
        engines: row.corroborating_engines,
        epss: row.epss ?? undefined,
        ssvc: (['Track', 'Track*', 'Attend', 'Act'] as const).includes(row.ssvc as never)
          ? (row.ssvc as 'Track' | 'Track*' | 'Attend' | 'Act')
          : undefined,
      }),
    }));
    const elf = state.artifacts.binary?.elf;
    const done: QueuedRun = {
      ...run,
      seq: runSeq,
      status: 'done',
      finishedAt: new Date().toISOString(),
      stageStatus: state.stages,
      metrics: state.metrics,
      findingsCount: created.length,
      findings: created,
      ...(write.removed.length ? { removed: write.removed } : {}),
      firmwareSha256: state.firmware.sha256,
      artifacts: {
        elf: elf && elf.valid ? { valid: true, machine: elf.machine, bits: elf.bits, endian: elf.endian } : { valid: false },
        gzipMembers: state.artifacts.binary?.gzipMembers?.length ?? 0,
        components: state.artifacts.sbom?.components.length ?? 0,
        sha256: state.firmware.sha256,
      },
    };
    await putRun(org, run.runId, done);
    rememberMetric(org, run.runId, state.metrics);
  } catch (e) {
    await putRun(org, run.runId, { ...run, status: 'failed', finishedAt: new Date().toISOString(), source: 'upload', error: String(e).slice(0, 200) }).catch(() => {});
  } finally {
    inFlight.delete(run.runId);
  }
}

// POST /v1/pipeline/runs — enqueue a firmware analysis run (persisted run record).
// Gated by BOTH auth and the attestation row (no test without logged authorization).
// profile:'demo' additionally launches the pooled engine on the labeled
// synthetic image so throughput is real, measured, and pollable.
router.post('/runs', requireAuth, requireAttestation, async (req, res) => {
  const p = z
    .object({
      firmwareId: z.string().min(1).max(64).optional(),
      version: z.string().min(1).max(64).optional(),
      profile: z.enum(['demo']).optional(),
    })
    .safeParse(req.body);
  if (!p.success) return res.status(400).json({ error: p.error.issues[0]?.message ?? 'firmwareId or profile:demo required' });
  const org = orgOf(req);
  const runId = randomUUID();

  if (p.data.profile === 'demo') {
    const run: QueuedRun = {
      runId,
      firmwareId: p.data.firmwareId ?? 'demo-hub',
      version: p.data.version ?? 'r15',
      status: 'queued',
      createdAt: new Date().toISOString(),
      source: 'demo',
      profile: 'demo',
    };
    await putRun(org, runId, run);
    void executeQueuedDemo(org, run);
    return res.status(202).json({
      runId,
      status: 'queued',
      source: 'demo',
      note: 'pooled engine executing the demo profile; poll GET /runs/:id for live stage status + throughput metrics',
    });
  }

  if (!p.data.firmwareId) {
    return res.status(400).json({ error: 'firmwareId required — upload the image at POST /v1/firmware first' });
  }
  const fw = await getFirmware(p.data.firmwareId, org);
  if (!fw) return res.status(404).json({ error: 'firmware not found in your org — upload it at POST /v1/firmware' });
  // Position in the global analysis order, taken once when the run is created.
  const seq = await nextAnalysisRunSeq();
  const run: QueuedRun = {
    runId,
    firmwareId: fw.record.id,
    version: p.data.version ?? fw.record.version,
    status: 'queued',
    createdAt: new Date().toISOString(),
    seq,
    source: 'upload',
    firmwareSha256: fw.record.sha256,
  };
  await putRun(org, runId, run);
  void executeQueuedUpload(org, run, fw.data);
  res.status(202).json({
    runId,
    status: 'queued',
    source: 'upload',
    firmwareId: run.firmwareId,
    sha256: fw.record.sha256,
    note: 'acquisition → unpack → strings-based static → SBOM over the uploaded image; poll GET /runs/:id',
  });
});

router.get('/runs/:id', requireAuth, async (req, res) => {
  const id = Array.isArray(req.params.id) ? req.params.id[0] : req.params.id;
  const run = await getRunDoc<QueuedRun>(orgOf(req as unknown as Authed), id);
  if (!run) return res.status(404).json({ error: 'run not found' });
  res.json(run);
});

// GET /v1/pipeline/metrics — engine throughput ledger for this org: completed
// runs with wall time, fuzz execs/sec, protocol execs, pool mode actually used.
router.get('/metrics', requireAuth, async (req, res) => {
  const runs = metricLog.get(orgOf(req as unknown as Authed)) ?? [];
  const walls = runs.map((r) => r.wallMs);
  const bestExecs = runs.reduce<number | null>((b, r) => (r.fuzzExecsPerSec != null && (b == null || r.fuzzExecsPerSec > b) ? r.fuzzExecsPerSec : b), null);
  res.json({
    runs: runs.length,
    avgWallMs: walls.length ? Math.round(walls.reduce((a, b) => a + b, 0)) : null,
    bestFuzzExecsPerSec: bestExecs,
    poolMode: runs[0]?.poolMode ?? null,
    recent: runs.slice(0, 5),
  });
});

export default router;
