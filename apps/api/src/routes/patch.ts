import { Router } from 'express';
import { z } from 'zod';
import { verifyPatch } from '@sentinelforge/workers';
import { requireAuth } from '../middleware/rbac.js';
import { requireAttestation } from './devices.js';

// Automated patch verification (spec): prove the vulnerable path is gone.
// Gated — comparing builds is analysis work, not public readout.
const router = Router();

const hexBytes = (hex: string): Uint8Array => {
  if (!/^[0-9a-fA-F]*$/.test(hex) || hex.length % 2 !== 0 || hex.length === 0 || hex.length > 32 * 1024 * 1024)
    throw new Error('hex: even-length hex string, non-empty, ≤16MB image');
  return new Uint8Array(Buffer.from(hex, 'hex'));
};

router.post('/verify', requireAuth, requireAttestation, (req, res) => {
  const p = z
    .object({
      oldHex: z.string().min(2),
      newHex: z.string().min(2),
      oldText: z.string().max(2_000_000).optional(),
      newText: z.string().max(2_000_000).optional(),
      vulnSink: z.string().max(64).optional(),
      oldVersion: z.string().max(64).optional(),
      newVersion: z.string().max(64).optional(),
    })
    .safeParse(req.body);
  if (!p.success) return res.status(400).json({ error: p.error.issues[0]?.message });
  try {
    res.json(
      verifyPatch({
        oldRaw: hexBytes(p.data.oldHex),
        newRaw: hexBytes(p.data.newHex),
        ...(p.data.oldText ? { oldText: p.data.oldText } : {}),
        ...(p.data.newText ? { newText: p.data.newText } : {}),
        ...(p.data.vulnSink ? { vulnSink: p.data.vulnSink } : {}),
        ...(p.data.oldVersion ? { oldVersion: p.data.oldVersion } : {}),
        ...(p.data.newVersion ? { newVersion: p.data.newVersion } : {}),
      })
    );
  } catch (e) {
    res.status(400).json({ error: (e as Error).message });
  }
});

export default router;
