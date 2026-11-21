import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';

// Firmware blobs at rest (round 34).
//
// The API used to report `encryptedAtRest: true` because the schema's default
// was TRUE — while the blob table stored the image in the clear. This module
// makes the claim true or makes it false; it never lies.
//
// AES-256-GCM with a random 12-byte IV per image. The stored form is
//   "SFENC1" || iv || authTag || ciphertext
// so a blob is self-describing: plaintext rows written before this change (or
// while no key was configured) are still readable, and a keyed row can never be
// silently treated as plaintext because the magic prefix would fail to parse.
//
// Key source: FIRMWARE_ENC_KEY, either 64 hex characters or base64 for 32 bytes.
// With no key the upload still succeeds, but the row is stored plaintext AND
// reports encryptedAtRest:false — an honest downgrade instead of a false badge.
const MAGIC = Buffer.from('SFENC1', 'latin1');
const IV_LEN = 12;
const TAG_LEN = 16;

function key(): Buffer | null {
  const raw = (process.env.FIRMWARE_ENC_KEY ?? '').trim();
  if (!raw) return null;
  const buf = /^[0-9a-f]{64}$/i.test(raw) ? Buffer.from(raw, 'hex') : Buffer.from(raw, 'base64');
  return buf.length === 32 ? buf : null;
}

export const firmwareEncryptionConfigured = () => key() !== null;

export function sealFirmware(bytes: Uint8Array): { data: Uint8Array; encrypted: boolean } {
  const k = key();
  if (!k) return { data: bytes, encrypted: false };
  const iv = randomBytes(IV_LEN);
  const cipher = createCipheriv('aes-256-gcm', k, iv);
  const ciphertext = Buffer.concat([cipher.update(Buffer.from(bytes)), cipher.final()]);
  return { data: Buffer.concat([MAGIC, iv, cipher.getAuthTag(), ciphertext]), encrypted: true };
}

export function openFirmware(stored: Uint8Array): Uint8Array {
  const buf = Buffer.from(stored.buffer, stored.byteOffset, stored.byteLength);
  const isSealed = buf.length >= MAGIC.length + IV_LEN + TAG_LEN && buf.subarray(0, MAGIC.length).equals(MAGIC);
  if (!isSealed) return new Uint8Array(buf);
  const k = key();
  if (!k) throw new Error('firmware blob is encrypted but FIRMWARE_ENC_KEY is not configured');
  const iv = buf.subarray(MAGIC.length, MAGIC.length + IV_LEN);
  const tag = buf.subarray(MAGIC.length + IV_LEN, MAGIC.length + IV_LEN + TAG_LEN);
  const ciphertext = buf.subarray(MAGIC.length + IV_LEN + TAG_LEN);
  const decipher = createDecipheriv('aes-256-gcm', k, iv);
  decipher.setAuthTag(tag);
  return new Uint8Array(Buffer.concat([decipher.update(ciphertext), decipher.final()]));
}
