import { Router } from 'express';
import { z } from 'zod';
import { matchSbom, verdictFor, demoAdvisories, parseNvd, type CveAdvisory } from '@sentinelforge/workers';
import { requireAuth } from '../middleware/rbac.js';
import { feedStatus, pollNvd } from '../intel.js';

// Predictive N-day radar (spec): the moment a CVE is published against an SBOM
// component, return an exploitability verdict + twin re-run descriptor.
const router = Router();

const sbomSchema = z.object({ name: z.string().min(1), version: z.string().min(1), purl: z.string().optional() });
const advisorySchema = z.object({
  id: z.string().regex(/^CVE-\d{4}-.+$/i),
  published: z.string().default(new Date().toISOString()),
  summary: z.string().default(''),
  affected: z.array(z.object({ name: z.string(), purl: z.string().optional(), versionEnd: z.string().optional(), versionEndType: z.enum(['excluding', 'including']).optional() })).min(1),
  hasPoc: z.boolean().optional(),
  epss: z.number().min(0).max(1).optional(),
});

// POST /v1/radar/check — match advisories against an SBOM, verdicts back.
router.post('/check', requireAuth, (req, res) => {
  const p = z
    .object({ firmwareRef: z.string().min(1).max(128), sbom: z.array(sbomSchema).min(1).max(500), advisories: z.array(advisorySchema).min(1).max(100) })
    .safeParse(req.body);
  if (!p.success) return res.status(400).json({ error: p.error.issues[0]?.message });
  const out = p.data.advisories.map((a) => {
    const adv = a as CveAdvisory;
    return { verdict: verdictFor(matchSbom(p.data.sbom, adv), adv, p.data.firmwareRef), matches: matchSbom(p.data.sbom, adv) };
  });
  res.json({ checked: out.length, results: out });
});

// POST /v1/radar/ingest-nvd — map raw NVD 2.0 items to advisories (parser check).
router.post('/ingest-nvd', requireAuth, (req, res) => {
  const p = z.object({ items: z.array(z.record(z.string(), z.unknown())).min(1) }).safeParse(req.body);
  if (!p.success) return res.status(400).json({ error: 'items[] required' });
  try {
    res.json({ advisories: parseNvd(p.data.items as Parameters<typeof parseNvd>[0]) });
  } catch (e) {
    res.status(400).json({ error: 'NVD parse failed: ' + (e as Error).message });
  }
});

// GET /v1/radar/demo — canned feed + verdicts against the demo SBOM (public sample).
router.get('/demo', (_req, res) => {
  const sbom = [
    { name: 'httpd', version: '1.9', purl: 'pkg:generic/httpd@1.9' },
    { name: 'tls-mini', version: '1.4.2' },
  ];
  res.json({
    sbom,
    results: demoAdvisories().map((adv) => ({ verdict: verdictFor(matchSbom(sbom, adv), adv, 'fw-demo'), matches: matchSbom(sbom, adv) })),
  });
});

// POST /v1/radar/poll — pull NVD modifications since an ISO timestamp (or 24h).
router.post('/poll', requireAuth, async (req, res) => {
  const since = typeof req.body?.since === 'string' ? req.body.since : undefined;
  try {
    const { advisories, total } = await pollNvd(since);
    res.json({ total, advisories: advisories.slice(0, 50), status: feedStatus() });
  } catch (e) {
    res.status(502).json({ error: 'NVD poll failed: ' + (e as Error).message, status: feedStatus() });
  }
});

router.get('/feed/status', requireAuth, (_req, res) => {
  res.json(feedStatus());
});

export default router;
