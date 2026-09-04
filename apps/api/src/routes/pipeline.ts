import { Router } from 'express';
import { z } from 'zod';
import { randomUUID } from 'node:crypto';
import { requireAuth } from '../middleware/rbac.js';
import { requireAttestation } from './devices.js';
import { getRunDoc, putRun } from '../store.js';

const router = Router();

type QueuedRun = { runId: string; firmwareId: string; version: string; status: 'queued' | 'running' | 'done'; createdAt: string };

// POST /v1/pipeline/runs — enqueue a firmware analysis run (persisted run record).
// Gated by BOTH auth and the attestation row (no test without logged authorization).
router.post('/runs', requireAuth, requireAttestation, async (req, res) => {
  const p = z.object({ firmwareId: z.string().min(1).max(128), version: z.string().min(1).max(64) }).safeParse(req.body);
  if (!p.success) return res.status(400).json({ error: p.error.issues[0]?.message ?? 'firmwareId + version required' });
  const runId = randomUUID();
  await putRun(runId, { runId, firmwareId: p.data.firmwareId, version: p.data.version, status: 'queued', createdAt: new Date().toISOString() });
  res.status(202).json({ runId, status: 'queued', note: 'workers pick this up (Module 2); resumable via runId' });
});

router.get('/runs/:id', requireAuth, async (req, res) => {
  const id = Array.isArray(req.params.id) ? req.params.id[0] : req.params.id;
  const run = await getRunDoc<QueuedRun>(id);
  if (!run) return res.status(404).json({ error: 'run not found' });
  res.json(run);
});

export default router;
