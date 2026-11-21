import { Router } from 'express';
import { z } from 'zod';
import { requireAuth, requirePerm } from '../middleware/rbac.js';
import { audit } from '../db.js';
import { createFinding, deleteFinding, getFinding, listFindings, type FindingRow, type NewFinding } from '../store.js';
import { sanitizeMultiline, sanitizeText } from '../sanitize.js';
import { priorityOf } from '@sentinelforge/workers';

// Findings — the analyst queue, persisted per org.
// Write needs triage rights (Analyst+); read is any signed-in role.
const router = Router();

type Authed = { user: { sub: string; org: string } };

// Every finding response carries the ENGINE-COMPUTED priority (workers
// priorityOf) so the dashboard/reports never rank from a mirrored constant —
// one definition, computed once, consumed everywhere.
const withPriority = (row: FindingRow) => ({
  ...row,
  priority: priorityOf({ engines: row.corroborating_engines ?? [], epss: row.epss ?? undefined, ssvc: (['Track', 'Track*', 'Attend', 'Act'] as const).includes(row.ssvc as never) ? (row.ssvc as 'Track' | 'Track*' | 'Attend' | 'Act') : undefined }),
});

const findingSchema = z.object({
  title: z.string().min(3).max(256),
  firmwareId: z.string().max(64).optional(),
  emb3d: z.string().max(128).optional(),
  cvss: z.number().min(0).max(10).optional(),
  epss: z.number().min(0).max(1).optional(),
  ssvc: z.enum(['Track', 'Track*', 'Attend', 'Act']).optional(),
  confidence: z.enum(['Confirmed', 'Likely', 'Unconfirmed']).default('Unconfirmed'),
  engines: z.array(z.string().max(32)).max(12).default([]),
  why: z.string().max(2000).optional(),
  snapshotRef: z.string().max(128).optional(),
});

router.get('/', requireAuth, async (req, res) => {
  const u = (req as unknown as Authed).user;
  const confidence = typeof req.query.confidence === 'string' ? req.query.confidence : undefined;
  if (confidence && !['Confirmed', 'Likely', 'Unconfirmed'].includes(confidence))
    return res.status(400).json({ error: 'confidence: Confirmed|Likely|Unconfirmed' });
  res.json({ findings: (await listFindings(u.org, { ...(confidence ? { confidence } : {}), limit: 100 })).map(withPriority) });
});

router.post('/', requireAuth, requirePerm('triage:write'), async (req, res) => {
  const p = findingSchema.safeParse(req.body);
  if (!p.success) return res.status(400).json({ error: p.error.issues[0]?.message });
  const u = (req as unknown as Authed).user;
  const row = await createFinding({
    orgId: u.org,
    firmwareId: p.data.firmwareId,
    title: sanitizeText(p.data.title, 256),
    emb3d: p.data.emb3d ? sanitizeText(p.data.emb3d, 128) : undefined,
    cvss: p.data.cvss,
    epss: p.data.epss,
    ssvc: p.data.ssvc,
    confidence: p.data.confidence,
    engines: p.data.engines.map((e) => sanitizeText(e, 32)),
    why: p.data.why ? sanitizeMultiline(p.data.why, 2000) : undefined,
    snapshotRef: p.data.snapshotRef ? sanitizeText(p.data.snapshotRef, 128) : undefined,
  });
  await audit('finding_created', { userId: u.sub, orgId: u.org, ip: req.ip });
  res.status(201).json(withPriority(row));
});

// GET /v1/findings/:id — the evidence chain behind one verdict. Read is any
// signed-in role (same rule as the list), and the org check happens in the
// store so a foreign id returns 404 rather than leaking existence.
router.get('/:id', requireAuth, async (req, res) => {
  const u = (req as unknown as Authed).user;
  const id = Array.isArray(req.params.id) ? req.params.id[0] : req.params.id;
  const row = await getFinding(id ?? '', u.org);
  if (!row) return res.status(404).json({ error: 'finding not found' });
  res.json(withPriority(row));
});

router.delete('/:id', requireAuth, requirePerm('triage:write'), async (req, res) => {
  const u = (req as unknown as Authed).user;
  const id = Array.isArray(req.params.id) ? req.params.id[0] : req.params.id;
  if (!(await deleteFinding(id ?? '', u.org))) return res.status(404).json({ error: 'finding not found' });
  res.json({ success: true });
});

// POST /v1/findings/demo — seeds a representative queue for previews and UI dev.
// Same validation as real creates; clearly labeled sample rows.
router.post('/demo', requireAuth, requirePerm('triage:write'), async (req, res) => {
  const u = (req as unknown as Authed).user;
  const samples: (Omit<NewFinding, 'orgId'> & { confidence: 'Confirmed' | 'Likely' | 'Unconfirmed' })[] = [
    { title: 'Tainted input reaches strcpy via recv → parse_query', emb3d: 'EMB3D: memory-unsafe input handling', cvss: 9.1, epss: 0.72, ssvc: 'Act', confidence: 'Confirmed', engines: ['taint', 'fuzz', 'static'], why: 'taint path recv → parse_query → strcpy; fuzzer crash at strcpy; static sink present' },
    { title: 'GATT write accepted pre-pairing (auth bypass)', emb3d: 'EMB3D: improper access control', cvss: 8.2, epss: 0.31, ssvc: 'Attend', confidence: 'Confirmed', engines: ['protocol-fuzz', 'emulator'], why: 'differential oracle: reference rejects, target accepts into authenticated' },
    { title: 'Hardcoded AWS key in OTA image', emb3d: 'EMB3D: hardcoded credentials', cvss: 7.4, ssvc: 'Attend', confidence: 'Likely', engines: ['secrets', 'static'], why: "secret rule 'aws-access-key' matched; corroborated by static string analysis — same family, weaker evidence (Likely, not Confirmed)" },
    { title: 'UART console enabled in production bootargs', emb3d: 'EMB3D: improper access control', cvss: 6.8, confidence: 'Unconfirmed', engines: ['root-of-trust'], why: 'console=ttyS0 in boot config; single engine, no corroboration — needs triage' },
    { title: 'Suspicious outbound burst to unlisted resolver', emb3d: 'EMB3D: covert channel', confidence: 'Unconfirmed', engines: ['heuristic'], why: 'single-engine anomaly — needs triage' },
  ];
  const rows = [];
  for (const s of samples) rows.push(withPriority(await createFinding({ ...s, orgId: u.org })));
  await audit('findings_seeded', { userId: u.sub, orgId: u.org, ip: req.ip });
  res.status(201).json({ seeded: rows.length, findings: rows });
});

export default router;
