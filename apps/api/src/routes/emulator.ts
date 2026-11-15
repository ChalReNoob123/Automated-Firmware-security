import { Router, type Request } from 'express';
import { z } from 'zod';
import { createHash, randomUUID } from 'node:crypto';
import { requireAuth } from '../middleware/rbac.js';
import { requireAttestation } from './devices.js';
import { audit } from '../db.js';
import { getSessionDoc, putSession } from '../store.js';

// Control-plane resource layer for emulator sessions (spec §6).
// Execution semantics (dry-run/QEMU, snapshot hashing, replay compare) live in
// @sentinelforge/workers stages/emulator.ts; this router owns HTTP validation,
// auth + attestation gating, and audit. The two converge onto shared session
// state when the Temporal worker pool lands (Module 5).
const router = Router();

type Snapshot = { id: string; stateHash: string; inputTrace: string[]; createdAt: string; note?: string };
type Crash = { id: string; reason: string; snapshotId: string | null; inputTrace: string[]; at: string };
type Session = {
  id: string;
  arch: string;
  memoryMb: number;
  backend: 'dry-run';
  status: 'ready' | 'crashed' | 'stopped';
  bootLog: string[];
  inputTrace: string[];
  snapshots: Snapshot[];
  crashes: Crash[];
};

const sessions = {
  async get(orgId: string, id: string) {
    return getSessionDoc<Session>(orgId, id);
  },
  async set(orgId: string, s: Session) {
    await putSession(orgId, s.id, s);
  },
};
// Prototype store cap: eviction lives in the store layer (pg: unbounded table,
// memory: oldest-first past 200 — see store.ts). Listing is intentionally absent:
// sessions are addressed by id from pipeline runs, never enumerated.
const orgOf = (req: Request) => (req as unknown as { user?: { org?: string } }).user?.org ?? '';
const paramId = (req: Request) => {
  const id = req.params.id as string | string[] | undefined;
  return Array.isArray(id) ? id[0] : (id ?? '');
};
const hashState = (s: Session) => createHash('sha256').update(JSON.stringify({ bootLog: s.bootLog, inputTrace: s.inputTrace })).digest('hex');

const createSchema = z.object({
  arch: z.enum(['arm', 'aarch64', 'mips', 'mipsel', 'x86', 'x86_64', 'riscv64']),
  memoryMb: z.number().int().min(64).max(8192).default(256),
  kernelArgs: z.string().max(512).optional(),
});

// POST /v1/emulator/sessions — boot a twin. Gated: testing needs logged authorization.
router.post('/sessions', requireAuth, requireAttestation, async (req, res) => {
  const p = createSchema.safeParse(req.body);
  if (!p.success) return res.status(400).json({ error: p.error.issues[0]?.message });
  const s: Session = {
    id: `emu_${randomUUID().slice(0, 8)}`,
    arch: p.data.arch,
    memoryMb: p.data.memoryMb,
    backend: 'dry-run',
    status: 'ready',
    bootLog: [`Linux version 5.10.0-forge (${p.data.arch}) #1 SMP PREEMPT`, 'Starting init: /sbin/init …', 'login: '],
    inputTrace: [],
    snapshots: [],
    crashes: [],
  };
  await sessions.set(orgOf(req), s);
  await audit('emulator_boot', { ip: req.ip });
  res.status(201).json(s);
});

router.get('/sessions/:id', requireAuth, async (req, res) => {
  const s = await sessions.get(orgOf(req), paramId(req));
  if (!s) return res.status(404).json({ error: 'session not found' });
  res.json(s);
});

// POST …/input — feed console input (a test action → attestation required)
router.post('/sessions/:id/input', requireAuth, requireAttestation, async (req, res) => {
  const s = await sessions.get(orgOf(req), paramId(req));
  if (!s) return res.status(404).json({ error: 'session not found' });
  if (s.status === 'stopped') return res.status(409).json({ error: 'session stopped' });
  const p = z.object({ input: z.string().min(1).max(4096) }).safeParse(req.body);
  if (!p.success) return res.status(400).json({ error: 'input required' });
  s.inputTrace.push(p.data.input);
  s.bootLog.push(`> ${p.data.input}`);
  if (s.status === 'crashed') s.status = 'ready';
  await sessions.set(orgOf(req), s);
  res.json(s);
});

// POST …/snapshots — capture reproducible state
router.post('/sessions/:id/snapshots', requireAuth, async (req, res) => {
  const s = await sessions.get(orgOf(req), paramId(req));
  if (!s) return res.status(404).json({ error: 'session not found' });
  if (s.status === 'stopped') return res.status(409).json({ error: 'session stopped' });
  const note = typeof req.body?.note === 'string' ? req.body.note.slice(0, 200) : undefined;
  const snap: Snapshot = {
    id: `snap_${randomUUID().slice(0, 8)}`,
    stateHash: hashState(s),
    inputTrace: [...s.inputTrace],
    createdAt: new Date().toISOString(),
    ...(note ? { note } : {}),
  };
  s.snapshots.push(snap);
  await sessions.set(orgOf(req), s);
  res.status(201).json(snap);
});

// POST …/replay — step-by-step replay of a snapshot's input trace
router.post('/sessions/:id/replay', requireAuth, async (req, res) => {
  const s = await sessions.get(orgOf(req), paramId(req));
  if (!s) return res.status(404).json({ error: 'session not found' });
  const p = z.object({ snapshotId: z.string().min(1) }).safeParse(req.body);
  if (!p.success) return res.status(400).json({ error: 'snapshotId required' });
  const snap = s.snapshots.find((x) => x.id === p.data.snapshotId);
  if (!snap) return res.status(404).json({ error: 'snapshot not found' });
  const postSnap = s.inputTrace.length - snap.inputTrace.length;
  const recomputed = createHash('sha256')
    .update(JSON.stringify({ bootLog: s.bootLog.slice(0, s.bootLog.length - postSnap), inputTrace: snap.inputTrace }))
    .digest('hex');
  const match = JSON.stringify(s.inputTrace.slice(0, snap.inputTrace.length)) === JSON.stringify(snap.inputTrace) && recomputed === snap.stateHash;
  res.json({ match, steps: snap.inputTrace.length, detail: match ? `reproduced ${snap.inputTrace.length} steps → ${snap.stateHash.slice(0, 12)}…` : 'diverged since snapshot' });
});

// POST …/crash — record anomaly with auto-snapshot repro bundle
router.post('/sessions/:id/crash', requireAuth, requireAttestation, async (req, res) => {
  const s = await sessions.get(orgOf(req), paramId(req));
  if (!s) return res.status(404).json({ error: 'session not found' });
  const p = z.object({ reason: z.string().min(1).max(512) }).safeParse(req.body);
  if (!p.success) return res.status(400).json({ error: 'reason required' });
  const snap: Snapshot = {
    id: `snap_${randomUUID().slice(0, 8)}`,
    stateHash: hashState(s),
    inputTrace: [...s.inputTrace],
    createdAt: new Date().toISOString(),
    note: `auto-snapshot at crash: ${p.data.reason}`,
  };
  s.snapshots.push(snap);
  s.status = 'crashed';
  const crash: Crash = { id: `crash_${randomUUID().slice(0, 8)}`, reason: p.data.reason, snapshotId: snap.id, inputTrace: [...s.inputTrace], at: new Date().toISOString() };
  s.crashes.push(crash);
  await sessions.set(orgOf(req), s);
  res.status(201).json(crash);
});

export default router;
