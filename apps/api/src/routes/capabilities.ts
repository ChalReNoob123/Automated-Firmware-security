import { Router } from 'express';
import { detectNativeTools } from '@sentinelforge/workers';
import { usingPostgres } from '../store.js';

const router = Router();

// GET /v1/capabilities — what this instance can actually do: native toolchain
// presence, persistence backend, engine list. The UI and agents adapt to this.
router.get('/', (_req, res) => {
  res.json({
    native: detectNativeTools(),
    persistence: usingPostgres() ? 'postgres' : 'memory (dev fallback)',
    engines: ['acquisition', 'unpack+elf+gzip', 'static+secrets', 'sbom+vex', 'root-of-trust', 'emulator', 'taint', 'fuzz', 'consensus', 'nday', 'patch-verify'],
  });
});

export default router;
