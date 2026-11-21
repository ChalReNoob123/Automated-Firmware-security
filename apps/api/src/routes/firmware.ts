import { Router, raw } from 'express';
import { z } from 'zod';
import { acquire } from '@sentinelforge/workers';
import { firmwareEncryptionConfigured } from '../firmwareCrypto.js';
import { requireAuth } from '../middleware/rbac.js';
import { requireAttestation } from './devices.js';
import { audit } from '../db.js';
import { listDevices, listFirmware, putFirmware } from '../store.js';

// Firmware intake (round 33) — the missing first link.
//
// Before this route the product could not accept a target image at all: the
// pipeline only ever ran a 64-byte synthetic ELF, so "analysis of the target
// device" was structurally impossible. The body is RAW BYTES, not JSON —
// base64-in-JSON would inflate a 6 MB image by a third and blow the JSON body
// limit. The parser is route-scoped so the global 12 MB JSON limit is unchanged.
//
// Gating is the same doctrine as every other test action: auth + a real
// attestation row in the caller's org. The image may optionally be linked to a
// registered device, and that link is what makes the run attributable to a
// specific target rather than "some bytes".
const router = Router();

const bytesOnly = raw({
  type: ['application/octet-stream', 'application/x-firmware', 'binary/octet-stream'],
  limit: '16mb',
});

const querySchema = z.object({
  version: z.string().min(1).max(64).optional(),
  deviceId: z.string().min(1).max(64).optional(),
});

// GET /v1/firmware — metadata only (no bytes), for the emulator's image picker.
router.get('/', requireAuth, async (req, res) => {
  const u = (req as unknown as { user: { org: string } }).user;
  const rows = await listFirmware(u.org);
  res.json({ firmware: rows.map((r) => ({ id: r.id, version: r.version, sha256: r.sha256, bytes: r.bytes, deviceId: r.device_id, encryptedAtRest: r.encrypted_at_rest, createdAt: r.created_at })) });
});

// POST /v1/firmware?version=1.4.2&deviceId=<uuid>
// Body: the image. Content-Type: application/octet-stream.
router.post('/', requireAuth, requireAttestation, bytesOnly, async (req, res) => {
  const u = (req as unknown as { user: { org: string; sub: string } }).user;
  const body = req.body as unknown;
  if (!Buffer.isBuffer(body) || body.length === 0) {
    return res.status(400).json({
      error: 'send the image as raw bytes with Content-Type: application/octet-stream',
    });
  }
  const q = querySchema.safeParse(req.query ?? {});
  if (!q.success) return res.status(400).json({ error: q.error.issues[0]?.message ?? 'bad query' });

  const version = q.data.version ?? 'unspecified';
  let deviceId: string | null = null;
  if (q.data.deviceId) {
    const devices = await listDevices(u.org);
    if (!devices.some((d) => d.id === q.data.deviceId)) {
      return res.status(404).json({ error: 'device not found in your org' });
    }
    deviceId = q.data.deviceId;
  }

  // acquire() hashes with sha256 and rejects empty images — the same function
  // the pipeline calls, so the hash on the upload and the hash on the run agree.
  const meta = acquire(new Uint8Array(body), { version, orgId: u.org });
  const record = await putFirmware({
    orgId: u.org,
    deviceId,
    version,
    sha256: meta.sha256,
    bytes: meta.bytes,
    data: new Uint8Array(body),
  });
  await audit('firmware_uploaded', { userId: u.sub, orgId: u.org, ip: req.ip });

  res.status(201).json({
    id: record.id,
    sha256: record.sha256,
    bytes: record.bytes,
    version: record.version,
    deviceId: record.device_id,
    encryptedAtRest: record.encrypted_at_rest,
    note: record.encrypted_at_rest
      ? 'stored org-scoped, encrypted at rest; run it with POST /v1/pipeline/runs { firmwareId }'
      : 'stored org-scoped but NOT encrypted — set FIRMWARE_ENC_KEY (32 bytes, hex or base64) to seal blobs at rest',
  });
});

export default router;
