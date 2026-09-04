import { createHash, randomUUID } from 'node:crypto';
import { z } from 'zod';

// Stage 1 — Acquisition. Validates intake, hashes, records at-rest encryption intent.
// Mirrors packages/db `firmware` table (sha256 UNIQUE per org).
const intakeSchema = z.object({
  id: z.string().min(1).optional(),
  version: z.string().min(1).max(64),
  orgId: z.string().min(1).optional(),
});

export type FirmwareRecord = {
  id: string;
  orgId: string | null;
  version: string;
  sha256: string;
  bytes: number;
  encryptedAtRest: true; // non-functional requirement: firmware images encrypted at rest/in transit
  acquiredAt: string;
};

export function acquire(raw: Uint8Array, meta: { version: string; id?: string; orgId?: string }): FirmwareRecord {
  const parsed = intakeSchema.parse(meta);
  if (raw.length === 0) throw new Error('empty firmware image');
  const sha256 = createHash('sha256').update(raw).digest('hex');
  return {
    id: parsed.id ?? `fw_${randomUUID().slice(0, 8)}`,
    orgId: parsed.orgId ?? null,
    version: parsed.version,
    sha256,
    bytes: raw.length,
    encryptedAtRest: true,
    acquiredAt: new Date().toISOString(),
  };
}
