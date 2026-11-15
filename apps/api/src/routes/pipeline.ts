import { Router } from 'express';
import { z } from 'zod';
import { randomUUID } from 'node:crypto';
import { requireAuth } from '../middleware/rbac.js';
import { requireAttestation } from './devices.js';
import { getRunDoc, putRun } from '../store.js';
import { runPipeline, type RunMetrics } from '@sentinelforge/workers';

const router = Router();

type QueuedRun = {
  runId: string;
  firmwareId: string;
  version: string;
  status: 'queued' | 'running' | 'done' | 'failed';
  createdAt: string;
  finishedAt?: string;
  // Executions are labeled: 'demo' = the deterministic synthetic image the
  // workers suite pins (real engine work, NOT a real customer firmware).
  // Real firmware arrives via device acquisition (Module 1) in prod wiring.
  profile?: 'demo';
  stageStatus?: Record<string, string>;
  metrics?: RunMetrics;
  findingsCount?: number;
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

// POST /v1/pipeline/runs — enqueue a firmware analysis run (persisted run record).
// Gated by BOTH auth and the attestation row (no test without logged authorization).
// profile:'demo' additionally launches the pooled engine on the labeled
// synthetic image so throughput is real, measured, and pollable.
router.post('/runs', requireAuth, requireAttestation, async (req, res) => {
  const p = z
    .object({ firmwareId: z.string().min(1).max(128), version: z.string().min(1).max(64), profile: z.enum(['demo']).optional() })
    .safeParse(req.body);
  if (!p.success) return res.status(400).json({ error: p.error.issues[0]?.message ?? 'firmwareId + version required' });
  const runId = randomUUID();
  const run: QueuedRun = { runId, firmwareId: p.data.firmwareId, version: p.data.version, status: 'queued', createdAt: new Date().toISOString() };
  await putRun(orgOf(req), runId, run);
  if (p.data.profile === 'demo') void executeQueuedDemo(orgOf(req), run);
  res.status(202).json({
    runId,
    status: 'queued',
    note: p.data.profile === 'demo' ? 'pooled engine executing the demo profile; poll GET /runs/:id for live stage status + throughput metrics' : 'workers pick this up (Module 2); resumable via runId',
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
