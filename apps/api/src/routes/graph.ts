import { Router } from 'express';
import { z } from 'zod';
import { buildAttackGraph, layoutForce, shortestPaths, demoSample } from '@sentinelforge/graph-service';
import { requireAuth } from '../middleware/rbac.js';

const router = Router();

const taintPathSchema = z.object({ source: z.string().min(1).max(128), sink: z.string().min(1).max(128), path: z.array(z.string().min(1).max(128)).min(2).max(64) });

// POST /v1/graph/build — build + lay out + rank the attack graph from discovery evidence.
// Round-24 audit: this is a COMPUTE surface — the caller supplies the evidence
// in the body and the result returns to the caller; no org data is read and
// nothing persists. (A dead `store.upsert` write to a module-global unscoped
// store was removed: no read path existed, and an unkeyed global write is a
// future-IDOR trap. Persist graphs only WITH an org key when a read path lands.)
router.post('/build', requireAuth, (req, res) => {
  const p = z
    .object({ taintPaths: z.array(taintPathSchema).min(1).max(200), secrets: z.array(z.object({ ruleId: z.string().max(128) })).max(200).optional() })
    .safeParse(req.body);
  if (!p.success) return res.status(400).json({ error: p.error.issues[0]?.message });
  const graph = layoutForce(buildAttackGraph(p.data));
  const paths = shortestPaths(graph);
  res.status(201).json({ graph, paths });
});

// GET /v1/graph/demo — aggregate sample (no auth; non-sensitive canned evidence for first paint)
router.get('/demo', (_req, res) => {
  res.json(demoSample());
});

export default router;
