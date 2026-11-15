import { Router } from 'express';
import { detectNativeTools } from '@sentinelforge/workers';
import { usingPostgres } from '../store.js';

const router = Router();

// Toolchain probing runs execFileSync per binary/arch — under concurrent load it
// serializes the event loop (measured ~650ms/request, 26s for a 40-burst on dev
// Windows). Cache for 60s: installs that happen mid-process still propagate
// within a minute, and the endpoint stops being a cheap CPU amplification.
let nativeCache: { caps: ReturnType<typeof detectNativeTools>; at: number } | null = null;
const NATIVE_TTL_MS = 60_000;
const native = () => {
  if (!nativeCache || Date.now() - nativeCache.at > NATIVE_TTL_MS) {
    nativeCache = { caps: detectNativeTools(), at: Date.now() };
  }
  return nativeCache.caps;
};

// GET /v1/capabilities — what this instance can actually do: native toolchain
// presence, persistence backend, engine list. The UI and agents adapt to this.
router.get('/', (_req, res) => {
  res.json({
    native: native(),
    persistence: usingPostgres() ? 'postgres' : 'memory (dev fallback)',
    engines: ['acquisition', 'unpack+elf+gzip', 'static+secrets', 'sbom+vex', 'root-of-trust', 'emulator', 'taint', 'fuzz', 'consensus', 'nday', 'patch-verify'],
  });
});

export default router;
