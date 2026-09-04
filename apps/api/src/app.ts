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

dotenv.config();

export const app = express();
app.use(helmet());
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
    methods: ['GET', 'POST', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'x-attestation-id'],
    credentials: true, // refresh cookie flows on same-site origins (ports ignored)
  })
);
app.use(express.json({ limit: '50mb' }));

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
const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 60, standardHeaders: 'draft-8', legacyHeaders: false });
app.use('/v1/auth', authLimiter);
// Chat runs fuzz campaigns inline — cap it so one client can't pin the event loop.
const copilotLimiter = rateLimit({ windowMs: 60 * 1000, limit: 30, standardHeaders: 'draft-8', legacyHeaders: false });
app.use('/v1/copilot', copilotLimiter);

// Minimal cookie parser (avoids extra dep; production can swap to cookie-parser)
app.use((req, _res, next) => {
  const h = req.headers.cookie ?? '';
  (req as unknown as { cookies: Record<string, string> }).cookies = Object.fromEntries(
    h
      .split(';')
      .map((c) => c.trim().split('='))
      .filter((p) => p.length === 2) as [string, string][]
  );
  next();
});

// Health — used by K8s probes + web status panel
app.get('/health', (_req, res) => res.json({ ok: true, service: 'sentinelforge-api', ts: new Date().toISOString() }));

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

// Example gated pipeline entry — every future analysis route uses requireAttestation
app.post('/v1/pipeline/run', requireAttestation, (_req, res) =>
  res.status(202).json({ status: 'queued', note: 'Module 2 workers pick this up' })
);

// JSON error boundary (CORS denials, zod throws, body-parser errors) — never leak HTML/stack.
app.use((req: express.Request, res: express.Response) => {
  res.status(404).json({ error: `Not found: ${req.method} ${req.path}` });
});
app.use((err: unknown, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
  const msg = err instanceof Error ? err.message : 'Internal server error';
  if (msg.startsWith('CORS')) return res.status(403).json({ error: msg });
  if (err instanceof SyntaxError && 'body' in (err as unknown as Record<string, unknown>)) return res.status(400).json({ error: 'malformed JSON body' });
  return res.status(500).json({ error: 'Internal server error' });
});
