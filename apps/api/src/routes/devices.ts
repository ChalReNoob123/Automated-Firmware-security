import { Router, type Request, type Response, type NextFunction } from 'express';
import { z } from 'zod';
import { audit } from '../db.js';
import { requireAuth, requirePerm } from '../middleware/rbac.js';
import { createAttestation, createDevice, findAttestation, listDevices } from '../store.js';
import { sanitizeText } from '../sanitize.js';

const router = Router();

type Authed = { user: { sub: string; org: string } };

// POST /v1/devices — register USB/WiFi/BLE/Zigbee/Z-Wave/UART/JTAG target (real row).
router.post('/devices', requireAuth, requirePerm('scan:run'), async (req, res) => {
  const p = z
    .object({
      name: z.string().min(1).max(128),
      transport: z.enum(['usb', 'wifi', 'ble', 'zigbee', 'zwave', 'uart', 'jtag']),
      fingerprint: z.string().max(256).optional(),
    })
    .safeParse(req.body);
  if (!p.success) return res.status(400).json({ error: p.error.issues[0]?.message ?? 'name + transport required' });
  const u = (req as unknown as Authed).user;
  const d = await createDevice({ orgId: u.org, name: sanitizeText(p.data.name, 128), transport: p.data.transport, fingerprint: p.data.fingerprint ? sanitizeText(p.data.fingerprint, 256) : undefined });
  await audit('device_registered', { userId: u.sub, orgId: u.org, ip: req.ip });
  res.status(201).json(d);
});

router.get('/devices', requireAuth, async (req, res) => {
  const u = (req as unknown as Authed).user;
  res.json({ devices: await listDevices(u.org) });
});

// POST /v1/attestations — MANDATORY logged authorization gate (spec §3).
router.post('/attestations', requireAuth, requirePerm('attest:sign'), async (req, res) => {
  const p = z
    .object({ deviceId: z.string().min(1).max(64), scope: z.string().min(1).max(256), legalBasis: z.string().min(4).max(512) })
    .safeParse(req.body);
  if (!p.success) return res.status(400).json({ error: p.error.issues[0]?.message ?? 'deviceId, scope, legalBasis required' });
  const u = (req as unknown as Authed).user;
  try {
    const a = await createAttestation({ orgId: u.org, deviceId: p.data.deviceId, userId: u.sub, scope: sanitizeText(p.data.scope, 256), legalBasis: sanitizeText(p.data.legalBasis, 512) });
    await audit('attestation_signed', { userId: u.sub, orgId: u.org, ip: req.ip });
    res.status(201).json(a);
  } catch (e) {
    res.status(404).json({ error: (e as Error).message });
  }
});

// Gate middleware: the attestation header must name a REAL row in the caller's org.
// Forged or cross-org ids fail closed — this is what makes the gate a gate.
export async function requireAttestation(req: Request, res: Response, next: NextFunction) {
  const raw = req.headers['x-attestation-id'];
  const attId = Array.isArray(raw) ? raw[0] : raw;
  const u = (req as unknown as Authed).user;
  if (!attId || !u) return res.status(403).json({ error: 'Authorization attestation required before any test' });
  const row = await findAttestation(attId, u.org);
  if (!row) return res.status(403).json({ error: 'Unknown or foreign attestation — attest this device first' });
  (req as unknown as { attestation?: unknown }).attestation = row;
  next();
}

export default router;
