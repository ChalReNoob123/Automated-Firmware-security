import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import dotenv from 'dotenv';
import crypto from 'node:crypto';
import rateLimit from 'express-rate-limit';
import authRoutes from './routes/auth.js';
import deviceRoutes, { requireAttestation } from './routes/devices.js';
import pipelineRoutes from './routes/pipeline.js';
import emulatorRoutes from './routes/emulator.js';
import graphRoutes from './routes/graph.js';
import copilotRoutes from './routes/copilot.js';
import radarRoutes from './routes/radar.js';
import patchRoutes from './routes/patch.js';
import capabilitiesRoutes from './routes/capabilities.js';
import systemRoutes from './routes/system.js';
import findingsRoutes from './routes/findings.js';
import qualityRoutes from './routes/quality.js';
import { requireAuth } from './middleware/rbac.js';
import { hasForbiddenKeys, hasExcessiveDepth } from './sanitize.js';
import { dbHealth } from './store.js';

dotenv.config();

export const app = express();
app.use(helmet());
// Content Security Policy — strict, no inline scripts, only same-origin resources.
// Set directly via middleware to avoid type conflicts with helmet's CSP types.
app.use((_req, res, next) => {
  res.setHeader(
    'Content-Security-Policy',
    "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; connect-src 'self'; font-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none';",
  );
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=()');
  next();
});
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS ?? 'http://localhost:3005,http://localhost:3006,http://localhost:4173,http://localhost:5173,http://127.0.0.1:3005')
  .split(',')
  .map((s) => s.trim())
  .filter(Boolean);
app.use(
  cors({
    origin: (origin, cb) => {
      if (!origin || ALLOWED_ORIGINS.includes(origin)) return cb(null, true);
      return cb(new Error('CORS: origin not allowed'));
    },
    // Round 29: PATCH + DELETE join the list — the preflight is what the
    // browser actually consults (supertest never sends one, so the live E2E
    // caught this gap: "Failed to fetch" on the role change). Every method a
    // route implements must appear here or its preflight dies silently.
    methods: ['GET', 'POST', 'PATCH', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'x-attestation-id'],
    credentials: true, // refresh cookie flows on same-site origins (ports ignored)
  })
);
app.use(express.json({ limit: '12mb' }));

// Prototype-pollution guard: reject bodies carrying __proto__/constructor/prototype
// at any depth (zod strips unknown keys, this protects any future merge path).
app.use((req, _res, next) => {
  if (req.body && typeof req.body === 'object') {
    if (hasForbiddenKeys(req.body)) {
      return _res.status(400).json({ error: 'forbidden keys in payload' });
    }
    if (hasExcessiveDepth(req.body)) {
      return _res.status(400).json({ error: 'payload nesting too deep' });
    }
  }
  next();
});

// Observability: every response carries X-Request-Id; one log line per request
// with latency. Feed these to any log shipper — no agent required.
app.use((req, res, next) => {
  const id = (req.headers['x-request-id'] as string) || crypto.randomUUID().slice(0, 8);
  (req as unknown as { reqId: string }).reqId = id;
  res.setHeader('x-request-id', id);
  const start = Date.now();
  res.on('finish', () => {
    console.log(`[${id}] ${req.method} ${req.path} ${res.statusCode} ${Date.now() - start}ms`);
  });
  next();
});

// Brute-force shield on the auth surface (mirrors SentinelGrid's authLimiter).
// 429 bodies are JSON so the web forms render a real message instead of
// "HTTP 429" (their fetch reads the `error` field). Budget is env-tunable:
// production keeps 60/15m per IP; dev/test defaults to 400 because a dev box
// shares one IP between the UI, agents and test batteries — the drain that
// made the workspace-claim form return 429 mid-testing.
const json429 = (msg: string) => ({ error: msg });
const rl = (windowMs: number, limit: number, msg: string) =>
  rateLimit({ windowMs, limit, standardHeaders: 'draft-8', legacyHeaders: false, message: json429(msg) });
const isProd = process.env.NODE_ENV === 'production';
const authLimiter = rl(15 * 60 * 1000, Number(process.env.AUTH_RATE_LIMIT ?? (isProd ? 60 : 400)), 'Too many auth requests from this network — pause a moment and try again.');
app.use('/v1/auth', authLimiter);
// Chat runs fuzz campaigns inline — cap it so one client can't pin the event loop.
const copilotLimiter = rl(60 * 1000, 30, 'Chat is rate limited (30/min) — try again shortly.');
app.use('/v1/copilot', copilotLimiter);
// General analysis API rate limit — 100 req/min per IP for read-heavy endpoints.
const analysisLimiter = rl(60 * 1000, 100, 'Analysis API rate limited (100/min) — slow down.');
app.use('/v1/graph', analysisLimiter);
app.use('/v1/radar', analysisLimiter);
app.use('/v1/capabilities', analysisLimiter);
// System probe (native USB enumeration) spawns a child process per cache miss —
// stricter than reads, looser than the UI's 12s poll needs (30/min ≈ 5 tabs).
const systemLimiter = rl(60 * 1000, 30, 'System probe rate limited (30/min) — slow down.');
app.use('/v1/system', systemLimiter);
// Mutation endpoints are stricter — 100 req/min per IP for write-heavy endpoints.
const mutationLimiter = rl(60 * 1000, isProd ? 100 : 300, 'Mutation rate limited — pause and retry.');
app.use('/v1/pipeline', mutationLimiter);
app.use('/v1/emulator', mutationLimiter);
app.use('/v1/patch', mutationLimiter);
app.use('/v1/findings', mutationLimiter);

// Minimal cookie parser (avoids extra dep; production can swap to cookie-parser).
// Splits each pair on the FIRST '=' only — values like base64 padding or JWT
// fragments containing '=' must survive intact.
app.use((req, _res, next) => {
  const h = req.headers.cookie ?? '';
  (req as unknown as { cookies: Record<string, string> }).cookies = Object.fromEntries(
    h
      .split(';')
      .map((c) => c.trim())
      .filter(Boolean)
      .map((c) => {
        const eq = c.indexOf('=');
        return eq === -1 ? [c, ''] : [c.slice(0, eq), c.slice(eq + 1)];
      })
  );
  next();
});

// Health — used by K8s probes + web status panel
app.get('/health', (_req, res) => res.json({ ok: true, service: 'sentinelforge-api', ts: new Date().toISOString() }));

// Readiness — verifies the persistence backend is reachable (probes must fail fast
// when the database is down, not serve 500s).
app.get('/ready', async (_req, res) => {
  try {
    const db = await dbHealth();
    res.json({ ready: true, persistence: db.postgres ? 'postgres' : 'memory', ts: new Date().toISOString() });
  } catch (e) {
    res.status(503).json({ ready: false, error: (e as Error).message });
  }
});

// Module 1: Auth/RBAC + attestation gate (public discovery route registered BEFORE routers)
app.get('/v1/modules', (_req, res) =>
  res.json({
    modules: [
      'auth-rbac',
      'pipeline-acquisition-sbom',
      'root-of-trust',
      'emulator',
      'discovery-fuzz-symbolic',
      'consensus',
      'attack-graph',
      'mcp-copilot',
      'n-day-radar',
      'patch-verify',
      'fleet-dashboard',
      'reporting',
      'federated-learning',
    ],
  })
);
app.use('/v1/auth', authRoutes);
app.use('/v1', deviceRoutes);
app.use('/v1/pipeline', pipelineRoutes);
app.use('/v1/emulator', emulatorRoutes);
app.use('/v1/graph', graphRoutes);
app.use('/v1/copilot', copilotRoutes);
app.use('/v1/radar', radarRoutes);
app.use('/v1/patch', patchRoutes);
app.use('/v1/capabilities', capabilitiesRoutes);
app.use('/v1/system', systemRoutes);
app.use('/v1/findings', findingsRoutes);
app.use('/v1/quality', qualityRoutes);

// Example gated pipeline entry — every future analysis route uses requireAttestation.
// NOTE: requireAuth must run first — requireAttestation scopes the lookup to req.user.org.
app.post('/v1/pipeline/run', requireAuth, requireAttestation, (_req, res) =>
  res.status(202).json({ status: 'queued', note: 'Module 2 workers pick this up' })
);

// JSON error boundary (CORS denials, zod throws, body-parser errors) — never leak HTML/stack.
app.use((req: express.Request, res: express.Response) => {
  res.status(404).json({ error: `Not found: ${req.method} ${req.path}` });
});
app.use((err: unknown, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
  const msg = err instanceof Error ? err.message : 'Internal server error';
  const status = (err as { status?: number } | null)?.status;
  const type = (err as { type?: string } | null)?.type;
  if (type === 'entity.too.large' || status === 413) return res.status(413).json({ error: 'Payload exceeds the body limit' });
  if (typeof status === 'number' && status >= 400 && status < 500) return res.status(status).json({ error: msg });
  if (msg.startsWith('CORS')) return res.status(403).json({ error: msg });
  if (err instanceof SyntaxError && 'body' in (err as unknown as Record<string, unknown>)) return res.status(400).json({ error: 'malformed JSON body' });
  return res.status(500).json({ error: 'Internal server error' });
});
