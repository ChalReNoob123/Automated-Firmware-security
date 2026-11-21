import { Router, type Request } from 'express';
import { z } from 'zod';
import { requireAuth } from '../middleware/rbac.js';
import { requireAttestation } from './devices.js';
import { audit } from '../db.js';
import { getFirmware, getSessionDoc, putSession } from '../store.js';
import {
  bootDeadlineFrom,
  buildTwin,
  failStaleBoot,
  feedInput,
  launchTwin,
  recordCrash,
  replay,
  takeSnapshot,
  willLaunch,
  type TwinImage,
  type TwinSession,
} from '@sentinelforge/workers';

// Control plane for emulator sessions (spec §6).
//
// Round 36: this router no longer owns any session semantics. Booting, image
// binding, hashing, snapshots, replay and crashes all live in the workers'
// stages/emulator.ts; the router validates HTTP, enforces auth + attestation,
// persists org-scoped docs, and audits. There used to be a near-copy of the
// whole model here, and the copies drifted.
const router = Router();

type Session = TwinSession;

const sessions = {
  async get(orgId: string, id: string) {
    return getSessionDoc<Session>(orgId, id);
  },
  async set(orgId: string, s: Session) {
    await putSession(orgId, s.id, s);
  },
};
// Every read settles an expired boot. A `booting` row whose deadline passed has
// no live launch behind it any more (an API restart is the usual cause), so it is
// reported as `failed` with the reason, never returned as booting forever. The
// transition is persisted so the next reader sees the same answer.
const loadSession = async (orgId: string, id: string) => {
  const s = await sessions.get(orgId, id);
  if (s && failStaleBoot(s)) await sessions.set(orgId, s);
  return s;
};

// Prototype store cap: eviction lives in the store layer (pg: unbounded table,
// memory: oldest-first past 200 — see store.ts). Listing is intentionally absent:
// sessions are addressed by id from pipeline runs, never enumerated.
const orgOf = (req: Request) => (req as unknown as { user?: { org?: string } }).user?.org ?? '';
const subOf = (req: Request) => (req as unknown as { user?: { sub?: string } }).user?.sub ?? '';
const paramId = (req: Request) => {
  const id = req.params.id as string | string[] | undefined;
  return Array.isArray(id) ? id[0] : (id ?? '');
};
const auditEmu = (req: Request, event: string) =>
  audit(event, { userId: subOf(req), orgId: orgOf(req), ip: req.ip });

const createSchema = z.object({
  // arch is optional when an image is supplied — the ELF header is the better
  // source of truth, and it is what the session records.
  arch: z.enum(['arm', 'aarch64', 'mips', 'mipsel', 'x86', 'x86_64', 'riscv64']).optional(),
  memoryMb: z.number().int().min(64).max(8192).default(256),
  kernelArgs: z.string().max(512).optional(),
  firmwareId: z.string().min(1).max(64).optional(),
});

// POST /v1/emulator/sessions — boot a twin. Gated: testing needs logged authorization.
//
// ASYNCHRONOUS boot: when a real launch is going to happen, the session is
// persisted as `booting` and returned immediately; the qemu run continues in the
// background and the GET endpoint shows the captured console when it lands. A
// slow or hung boot therefore costs one session row, not an 8-second HTTP hang.
router.post('/sessions', requireAuth, requireAttestation, async (req, res) => {
  const p = createSchema.safeParse(req.body);
  if (!p.success) return res.status(400).json({ error: p.error.issues[0]?.message });

  let image: TwinImage | undefined;
  if (p.data.firmwareId) {
    const fw = await getFirmware(p.data.firmwareId, orgOf(req));
    if (!fw) {
      return res.status(404).json({ error: 'firmware not found in your org — upload it at POST /v1/firmware' });
    }
    image = {
      firmwareId: fw.record.id,
      version: fw.record.version,
      sha256: fw.record.sha256,
      bytes: fw.record.bytes,
      data: fw.data,
    };
  }

  const s = buildTwin({
    ...(p.data.arch ? { arch: p.data.arch } : {}),
    memoryMb: p.data.memoryMb,
    ...(p.data.kernelArgs ? { kernelArgs: p.data.kernelArgs } : {}),
    ...(image ? { image } : {}),
  });

  const org = orgOf(req);
  const launching = !!image && willLaunch(s);

  if (launching && image) {
    s.status = 'booting';
    s.bootDeadline = bootDeadlineFrom();
    await sessions.set(org, s);
    await auditEmu(req, 'emulator_boot_async');
    res.status(201).json(s);
    // Fire-and-forget with an explicit terminal write: the client polls GET.
    void launchTwin(s, image)
      .then((updated) => sessions.set(org, updated))
      .catch(async (e) => {
        s.status = 'ready';
        s.launchError = (e as Error).message;
        await sessions.set(org, s).catch(() => {});
      });
    return;
  }

  // No launch will happen: run the (spawn-free) launcher once so the session
  // records WHY it did not execute instead of leaving the field silent.
  if (image) await launchTwin(s, image);
  await sessions.set(org, s);
  await auditEmu(req, 'emulator_boot');
  res.status(201).json(s);
});

router.get('/sessions/:id', requireAuth, async (req, res) => {
  const s = await loadSession(orgOf(req), paramId(req));
  if (!s) return res.status(404).json({ error: 'session not found' });
  res.json(s);
});

// POST …/input — feed console input (a test action → attestation required)
router.post('/sessions/:id/input', requireAuth, requireAttestation, async (req, res) => {
  const s = await loadSession(orgOf(req), paramId(req));
  if (!s) return res.status(404).json({ error: 'session not found' });
  const p = z.object({ input: z.string().min(1).max(4096) }).safeParse(req.body);
  if (!p.success) return res.status(400).json({ error: 'input required' });
  try {
    feedInput(s, p.data.input);
  } catch (e) {
    return res.status(409).json({ error: (e as Error).message });
  }
  await sessions.set(orgOf(req), s);
  await auditEmu(req, 'emulator_input');
  res.json(s);
});

// POST …/snapshots — capture reproducible state.
router.post('/sessions/:id/snapshots', requireAuth, requireAttestation, async (req, res) => {
  const s = await loadSession(orgOf(req), paramId(req));
  if (!s) return res.status(404).json({ error: 'session not found' });
  const note = typeof req.body?.note === 'string' ? req.body.note.slice(0, 200) : undefined;
  try {
    const snap = takeSnapshot(s, note);
    await sessions.set(orgOf(req), s);
    await auditEmu(req, 'emulator_snapshot');
    res.status(201).json(snap);
  } catch (e) {
    res.status(409).json({ error: (e as Error).message });
  }
});

// POST …/replay — step-by-step replay of a snapshot's input trace.
router.post('/sessions/:id/replay', requireAuth, requireAttestation, async (req, res) => {
  const s = await loadSession(orgOf(req), paramId(req));
  if (!s) return res.status(404).json({ error: 'session not found' });
  const p = z.object({ snapshotId: z.string().min(1) }).safeParse(req.body);
  if (!p.success) return res.status(400).json({ error: 'snapshotId required' });
  try {
    const result = replay(s, p.data.snapshotId);
    await auditEmu(req, 'emulator_replay');
    res.json(result);
  } catch (e) {
    res.status(404).json({ error: (e as Error).message });
  }
});

// POST …/crash — record an anomaly with an auto-snapshot repro bundle.
router.post('/sessions/:id/crash', requireAuth, requireAttestation, async (req, res) => {
  const s = await loadSession(orgOf(req), paramId(req));
  if (!s) return res.status(404).json({ error: 'session not found' });
  const p = z.object({ reason: z.string().min(1).max(512) }).safeParse(req.body);
  if (!p.success) return res.status(400).json({ error: 'reason required' });
  const crash = recordCrash(s, p.data.reason);
  await sessions.set(orgOf(req), s);
  await auditEmu(req, 'emulator_crash');
  res.status(201).json(crash);
});

export default router;
