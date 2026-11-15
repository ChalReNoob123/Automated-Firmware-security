import { Router } from 'express';
import { requireAuth } from '../middleware/rbac.js';
import { listFindings } from '../store.js';
import { familiesOf, priorityOf, type SsvcDecision } from '@sentinelforge/workers';

// SSVC values we accept (anything else scores 0 via the guard below).
const SSVC_VALUES: readonly SsvcDecision[] = ['Track', 'Track*', 'Attend', 'Act'];
const asSsvc = (v: string | null): SsvcDecision | undefined =>
  (SSVC_VALUES as readonly string[]).includes(v ?? '') ? (v as SsvcDecision) : undefined;

// Detector calibration — the "is our output trustworthy?" endpoint.
// Reports confidence distribution, corroboration rate (share of findings confirmed
// by INDEPENDENT engine families), engine/family coverage and priority spread.
const router = Router();

router.get('/', requireAuth, async (req, res) => {
  const org = (req as unknown as { user: { org: string } }).user.org;
  const findings = await listFindings(org, { limit: 500 });

  const byConfidence = { Confirmed: 0, Likely: 0, Unconfirmed: 0 };
  const byFamily = new Map<string, number>();
  const byEngine = new Map<string, number>();
  let corroborated = 0;
  let prioritySum = 0;

  for (const f of findings) {
    byConfidence[f.confidence] = (byConfidence[f.confidence] ?? 0) + 1;
    const fams = familiesOf(f.corroborating_engines ?? []);
    for (const fam of fams) byFamily.set(fam, (byFamily.get(fam) ?? 0) + 1);
    for (const e of f.corroborating_engines ?? []) byEngine.set(e, (byEngine.get(e) ?? 0) + 1);
    if (fams.length >= 2) corroborated++;
    // Round 14: this was the THIRD inline priority definition (confidence base
    // + EPSS, no SSVC term) and had drifted from the engine — the calibration
    // endpoint's averagePriority silently disagreed with the pipeline and the
    // dashboard. Reuse the engine's priorityOf so every surface shares one
    // definition (worker tests pin the constants).
    prioritySum += priorityOf({
      engines: f.corroborating_engines ?? [],
      epss: f.epss ?? undefined,
      ssvc: asSsvc(f.ssvc),
    });
  }

  const total = findings.length;
  res.json({
    total,
    byConfidence,
    corroborationRate: total ? +(corroborated / total).toFixed(3) : 0,
    averagePriority: total ? Math.round(prioritySum / total) : 0,
    byFamily: Object.fromEntries([...byFamily.entries()].sort((a, b) => b[1] - a[1])),
    byEngine: Object.fromEntries([...byEngine.entries()].sort((a, b) => b[1] - a[1])),
    policy: {
      confirmed: 'requires ≥2 INDEPENDENT engine families (static-analysis / symbolic / dynamic / protocol / heuristic)',
      likely: 'single family, multiple tools, or one strong engine',
      unconfirmed: 'single engine — needs triage',
    },
  });
});

export default router;
