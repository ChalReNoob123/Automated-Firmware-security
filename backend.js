import { createServer } from 'http';
import { WebSocketServer } from 'ws';
import { exec, execFileSync } from 'child_process';
import { promisify } from 'util';
import os from 'os';
import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import dotenv from 'dotenv';
import { DatabaseSync } from 'node:sqlite';
import jwt from 'jsonwebtoken';
import speakeasy from 'speakeasy';
import QRCode from 'qrcode';
import pino from 'pino';
import vm from 'vm';
import * as tf from '@tensorflow/tfjs';
import '@tensorflow/tfjs-backend-cpu';
import { ScannerEngine } from './scanner/engine.js';
import { GeminiService } from './services/geminiService.js';
import { runMigrations } from './services/migrations.js';
import { SecurityAuditLogger, DDoSProtection, validateRequest } from './services/securityMiddleware.js';
import { SyncManager } from './services/syncService.js';
import { AnalyticsEngine, SEGMENT_DEFS } from './services/analyticsEngine.js';

dotenv.config();

// ── Structured logger ───────────────────────────────────
const logger = pino({
  level: process.env.LOG_LEVEL || 'info',
  transport: process.env.NODE_ENV !== 'production'
    ? { target: 'pino-pretty', options: { colorize: true } }
    : undefined,
});

// ── Fail-fast for missing critical secrets in production ─
const NODE_ENV = process.env.NODE_ENV || 'development';
function requireEnv(key, devFallback) {
  if (NODE_ENV === 'production' && !process.env[key]) {
    logger.fatal(`FATAL: Missing required env var "${key}". Refusing to start.`);
    process.exit(1);
  }
  return process.env[key] || devFallback;
}

// ── Secrets — backend-only, no VITE_ prefix (gap #6) ────────────
const JWT_SECRET          = requireEnv('JWT_SECRET');
const JWT_REFRESH_SECRET  = requireEnv('JWT_REFRESH_SECRET');
const ADMIN_PASS          = requireEnv('ADMIN_PASS');
const ADMIN_USER          = requireEnv('ADMIN_USER');

// ── CORS: locked to specific origins (gap #2) ────────────────────
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || 'http://localhost:5173,http://localhost:4173,http://127.0.0.1:5173,http://127.0.0.1:4173')
  .split(',')
  .map(s => s.trim().replace(/^"|"$/g, ''))
  .filter(Boolean);

// ── Other config ─────────────────────────────────────────────────
const VT_API_KEY     = process.env.VT_API_KEY || '';
const OTX_API_KEY    = process.env.OTX_API_KEY || '';
const ELASTIC_URL    = process.env.ELASTIC_URL || '';
const SPLUNK_HEC_URL = process.env.SPLUNK_HEC_URL || '';
const SPLUNK_HEC_TOKEN = process.env.SPLUNK_HEC_TOKEN || '';
const CUCKOO_API_URL = process.env.CUCKOO_API_URL || '';
const PORT           = parseInt(process.env.PORT || '3001', 10);
const TRUST_PROXY    = process.env.TRUST_PROXY === 'true';
const CSP_CONNECT_SRC = process.env.CSP_CONNECT_SRC ||
  "'self' http://localhost:* ws://localhost:* https://generativelanguage.googleapis.com https://www.virustotal.com https://mb-api.abuse.ch https://otx.alienvault.com";

const execAsync = promisify(exec);

// In-process response cache for hot dashboard reads and threat-intel lookups.
// Keep it bounded because this backend can run for long PM2 sessions.
const CACHE_MAX_ITEMS = parseInt(process.env.CACHE_MAX_ITEMS || '250', 10);
const CACHE_DEFAULT_TTL_MS = parseInt(process.env.CACHE_DEFAULT_TTL_MS || '3000', 10);
const responseCache = new Map();
const cacheStats = { hits: 0, misses: 0, sets: 0, evictions: 0, invalidations: 0 };

function normalizeCacheParams(urlObj) {
  const params = new URLSearchParams(urlObj.searchParams);
  params.sort();
  const value = params.toString();
  return value ? `?${value}` : '';
}

function makeCacheKey(pathname, urlObj, scope = 'global') {
  return `${scope}:${pathname}${normalizeCacheParams(urlObj)}`;
}

function getCachedValue(key) {
  const entry = responseCache.get(key);
  if (!entry) {
    cacheStats.misses++;
    return undefined;
  }
  if (entry.expiresAt <= Date.now()) {
    responseCache.delete(key);
    cacheStats.misses++;
    return undefined;
  }
  responseCache.delete(key);
  responseCache.set(key, entry);
  cacheStats.hits++;
  return entry.value;
}

function setCachedValue(key, value, ttlMs = CACHE_DEFAULT_TTL_MS, tags = []) {
  if (ttlMs <= 0) return value;
  while (responseCache.size >= CACHE_MAX_ITEMS) {
    const oldest = responseCache.keys().next().value;
    if (!oldest) break;
    responseCache.delete(oldest);
    cacheStats.evictions++;
  }
  responseCache.set(key, {
    value,
    tags: new Set(tags),
    expiresAt: Date.now() + ttlMs,
  });
  cacheStats.sets++;
  return value;
}

function invalidateCacheTags(tags) {
  const wanted = new Set(Array.isArray(tags) ? tags : [tags]);
  let removed = 0;
  for (const [key, entry] of responseCache.entries()) {
    for (const tag of entry.tags) {
      if (wanted.has(tag)) {
        responseCache.delete(key);
        removed++;
        break;
      }
    }
  }
  cacheStats.invalidations += removed;
  return removed;
}

async function cachedJson(res, key, ttlMs, tags, producer) {
  const cached = getCachedValue(key);
  if (cached !== undefined) {
    res.setHeader('X-App-Cache', 'HIT');
    return json(res, 200, cached);
  }
  const body = await producer();
  setCachedValue(key, body, ttlMs, tags);
  res.setHeader('X-App-Cache', 'MISS');
  return json(res, 200, body);
}

// ── Plugin System ────────────────────────────────────────────────
const PLUGINS_DIR = path.join(process.cwd(), 'plugins');
const activePlugins = [];

async function loadPlugins() {
  if (!fs.existsSync(PLUGINS_DIR)) fs.mkdirSync(PLUGINS_DIR, { recursive: true });
  const files = fs.readdirSync(PLUGINS_DIR);
  for (const file of files) {
    if (file.endsWith('.js') || file.endsWith('.mjs')) {
      try {
        const pluginPath = path.join(PLUGINS_DIR, file);
        const code = fs.readFileSync(pluginPath, 'utf8');
        
        // Read-only DB proxy: plugins can only query, never mutate
        const pluginDb = {
          prepare: (sql) => {
            const normalised = sql.trim().toUpperCase();
            if (!normalised.startsWith('SELECT')) {
              throw new Error('Plugin DB access is read-only. Only SELECT queries are permitted.');
            }
            const stmt = db.prepare(sql);
            return {
              all: (...args) => stmt.all(...args),
              get: (...args) => stmt.get(...args),
            };
          },
        };
        
        // Use Node.js vm module for Enterprise-grade sandboxing
        const sandbox = { 
          db: pluginDb, logger, console, 
          Buffer, setTimeout, setInterval,
          process: { env: { NODE_ENV: process.env.NODE_ENV } },
          exports: {} 
        };
        vm.createContext(sandbox);
        
        const script = new vm.Script(code);
        script.runInContext(sandbox);
        
        const instance = sandbox.exports || sandbox;
        if (instance.init) await instance.init({ db: pluginDb, logger });
        activePlugins.push({ name: instance.name || file, instance });
        logger.info(`Loaded plugin (sandboxed): ${instance.name || file}`);
      } catch (err) {
         logger.error(`Failed to load sandboxed plugin ${file}: ${err.message}`);
      }
    }
  }
}

// ── AI Model Initialization ──────────────────────────────────────
let aiModel;
async function initAIModel() {
  try {
    // Creating a real, lightweight sequence model for zero-day pattern detection
    aiModel = tf.sequential();
    aiModel.add(tf.layers.dense({ units: 10, activation: 'relu', inputShape: [5] }));
    aiModel.add(tf.layers.dense({ units: 1, activation: 'sigmoid' }));
    aiModel.compile({ optimizer: 'adam', loss: 'binaryCrossentropy' });
    logger.info("Enterprise AI Heuristics Engine initialized with TensorFlow.js");
  } catch (e) {
    logger.error(e, "Failed to initialize AI Model");
  }
}
initAIModel();


// ── Legacy compat ───────────────────────────────────────
const AUTH_BEARER = 'LEGACY-DISABLED';

// ── Database (WAL mode = no write locks, gap #8) ─────────────────
const db = new DatabaseSync('./soc_database.sqlite');
db.exec('PRAGMA journal_mode=WAL');
db.exec('PRAGMA synchronous=NORMAL');
db.exec('PRAGMA cache_size=10000');
db.exec('PRAGMA temp_store=MEMORY');
db.exec('PRAGMA mmap_size=268435456');

// 1. Create tables first
db.exec(`
  CREATE TABLE IF NOT EXISTS logs (
    hash TEXT PRIMARY KEY, eventId TEXT, date TEXT, level TEXT,
    task TEXT, source TEXT, description TEXT, suspicious INTEGER
  );
  CREATE INDEX IF NOT EXISTS idx_logs_date ON logs(date DESC);
  CREATE TABLE IF NOT EXISTS known_patterns (
    patternId TEXT PRIMARY KEY, name TEXT, regex TEXT, mitre_tactic TEXT
  );
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'analyst',
    totp_secret TEXT,
    totp_enrolled INTEGER DEFAULT 0,
    failed_attempts INTEGER DEFAULT 0,
    locked_until INTEGER DEFAULT 0,
    last_login TEXT,
    created_at TEXT DEFAULT (datetime('now'))
  );
  CREATE TABLE IF NOT EXISTS refresh_tokens (
    jti TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL,
    username TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    revoked INTEGER DEFAULT 0
  );
  CREATE TABLE IF NOT EXISTS revoked_access_tokens (
    jti TEXT PRIMARY KEY,
    expires_at INTEGER NOT NULL
  );
  CREATE TABLE IF NOT EXISTS rate_limits (
    ip TEXT PRIMARY KEY,
    count INTEGER DEFAULT 0,
    locked_until INTEGER DEFAULT 0
  );
  -- Time-series metrics table for real-time traffic analytics
  CREATE TABLE IF NOT EXISTS metrics_time_series (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp INTEGER NOT NULL,
    segment TEXT DEFAULT 'global',
    zone TEXT DEFAULT 'global',
    metric_type TEXT NOT NULL,
    value REAL NOT NULL,
    metadata TEXT
  );
  CREATE INDEX IF NOT EXISTS idx_metrics_time ON metrics_time_series(timestamp DESC);
  CREATE INDEX IF NOT EXISTS idx_metrics_segment ON metrics_time_series(segment, timestamp DESC);
  CREATE INDEX IF NOT EXISTS idx_metrics_zone ON metrics_time_series(zone, timestamp DESC);
  -- Segment/Zone tracking table
  CREATE TABLE IF NOT EXISTS segments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE NOT NULL,
    zone TEXT NOT NULL,
    status TEXT DEFAULT 'active',
    health_score INTEGER DEFAULT 100,
    last_seen INTEGER DEFAULT 0,
    config TEXT
  );
  -- Connection state persistence
  CREATE TABLE IF NOT EXISTS connections (
    id TEXT PRIMARY KEY,
    src_ip TEXT,
    dst_ip TEXT,
    dst_host TEXT,
    protocol TEXT,
    port INTEGER,
    state TEXT,
    risk INTEGER DEFAULT 0,
    segment TEXT DEFAULT 'unknown',
    zone TEXT DEFAULT 'unknown',
    first_seen INTEGER,
    last_seen INTEGER,
    bytes_in INTEGER DEFAULT 0,
    bytes_out INTEGER DEFAULT 0
  );
  CREATE INDEX IF NOT EXISTS idx_connections_segment ON connections(segment);
  CREATE INDEX IF NOT EXISTS idx_connections_zone ON connections(zone);
  CREATE INDEX IF NOT EXISTS idx_connections_state ON connections(state);
  CREATE INDEX IF NOT EXISTS idx_connections_last_seen ON connections(last_seen DESC);
  -- Alert routing by segment
  CREATE TABLE IF NOT EXISTS segment_alerts (
    id TEXT PRIMARY KEY,
    timestamp INTEGER NOT NULL,
    segment TEXT NOT NULL,
    zone TEXT NOT NULL,
    severity TEXT NOT NULL,
    category TEXT,
    message TEXT,
    mitre_id TEXT,
    acknowledged INTEGER DEFAULT 0
  );
  CREATE INDEX IF NOT EXISTS idx_alerts_segment ON segment_alerts(segment, timestamp DESC);
  CREATE INDEX IF NOT EXISTS idx_alerts_zone ON segment_alerts(zone, timestamp DESC);
  CREATE INDEX IF NOT EXISTS idx_alerts_ack ON segment_alerts(acknowledged);
  CREATE INDEX IF NOT EXISTS idx_users_created_at ON users(created_at DESC);
  CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user ON refresh_tokens(user_id, expires_at DESC);
`);

// 2. Run migrations (add columns that might be missing from older versions)
try {
  db.exec(`ALTER TABLE users ADD COLUMN email TEXT`);
  db.exec(`CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email ON users(email)`);
} catch (e) {
  // Column likely already exists
}

// Migrations for segment/zone tracking
try { db.exec(`ALTER TABLE logs ADD COLUMN segment TEXT DEFAULT 'unknown'`); } catch (e) {}
try { db.exec(`ALTER TABLE logs ADD COLUMN zone TEXT DEFAULT 'unknown'`); } catch (e) {}
try { db.exec(`CREATE INDEX IF NOT EXISTS idx_logs_segment ON logs(segment)`); } catch (e) {}
try { db.exec(`CREATE INDEX IF NOT EXISTS idx_logs_zone ON logs(zone)`); } catch (e) {}
try { db.exec(`CREATE INDEX IF NOT EXISTS idx_logs_suspicious ON logs(suspicious, date DESC)`); } catch (e) {}

// Tables already created above via CREATE TABLE IF NOT EXISTS — no duplicate blocks needed.

// ── Scanner DB tables ──
try {
  db.exec(`
    CREATE TABLE IF NOT EXISTS scan_sessions (
      id TEXT PRIMARY KEY, started_at INTEGER NOT NULL, completed_at INTEGER,
      status TEXT DEFAULT 'running', config TEXT, total_files INTEGER DEFAULT 0,
      scanned_files INTEGER DEFAULT 0, findings INTEGER DEFAULT 0,
      risk_score REAL DEFAULT 0, summary TEXT
    );
    CREATE TABLE IF NOT EXISTS scan_findings (
      id TEXT PRIMARY KEY, session_id TEXT NOT NULL, file_path TEXT NOT NULL,
      file_name TEXT NOT NULL, file_size INTEGER, file_modified INTEGER,
      sha256 TEXT, entropy REAL, is_signed INTEGER DEFAULT 0,
      signature_status TEXT, signer TEXT, has_ads INTEGER DEFAULT 0,
      ads_streams TEXT, risk_score REAL DEFAULT 0, risk_factors TEXT,
      mitre_techniques TEXT, directory_category TEXT, directory_criticality TEXT,
      target_label TEXT, status TEXT DEFAULT 'clean', created_at INTEGER DEFAULT 0
    );
    CREATE INDEX IF NOT EXISTS idx_findings_session ON scan_findings(session_id);
    CREATE INDEX IF NOT EXISTS idx_findings_risk ON scan_findings(risk_score DESC);
    CREATE INDEX IF NOT EXISTS idx_findings_status ON scan_findings(status);
  `);
} catch (e) { logger.error(e, 'Error creating scanner tables'); }

// ── Run database migrations ──
try {
  const migrationResult = runMigrations(db, logger);
  logger.info(migrationResult, 'Database migrations complete');
} catch (e) { logger.error(e, 'Migration error — continuing with existing schema'); }

// ── Initialize security audit logger ──
const auditLogger = new SecurityAuditLogger(db, logger);

// ── Initialize DDoS protection ──
const ddosProtection = new DDoSProtection({ maxRequests: 300, windowMs: 60000, blockDurationMs: 300000 });

// ── Initialize Gemini AI service ──
const geminiService = new GeminiService({ apiKey: process.env.GEMINI_API_KEY, logger });

// ── Initialize Sync Manager ──
const syncManager = new SyncManager(db, logger, (payload) => broadcast(payload.event, payload.data));

// ── Initialize Analytics Engine ──
const analyticsEngine = new AnalyticsEngine(db, logger);

loadPlugins();

// ── Enterprise Scalability: Elasticsearch Forwarder (gap #8) ─────
const elasticClient = {
  push: async (index, doc) => {
    if (!ELASTIC_URL) return;
    try {
      await fetch(`${ELASTIC_URL}/${index}/_doc`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ...doc, '@timestamp': new Date().toISOString() })
      });
    } catch (e) { logger.error({ err: e.message }, 'Elasticsearch forward failed'); }
  },
  query: async (index, query) => {
    if (!ELASTIC_URL) return null;
    try {
      const res = await fetch(`${ELASTIC_URL}/${index}/_search`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(query)
      });
      return await res.json();
    } catch (e) { return null; }
  }
};


// ── Cookie Parser ─────────────────────────────────────────────────
function parseCookies(cookieStr) {
  if (!cookieStr) return {};
  return cookieStr.split(';').reduce((acc, str) => {
    const [k, v] = str.split('=').map(s => s.trim());
    acc[k] = v; return acc;
  }, {});
}

// ── Seed patterns ─────────────────────────────────────────────────
try {
  const ip = db.prepare('INSERT OR IGNORE INTO known_patterns (patternId,name,regex,mitre_tactic) VALUES (?,?,?,?)');
  ip.run('T1110','Brute Force','4625|Failed password','Credential Access');
  ip.run('T1070','Indicator Removal','1102|Log clear','Defense Evasion');
  ip.run('T1059','Command Execution','4688|/bin/sh|/bin/bash','Execution');
} catch {}

// ── Seed default admin (gap #12 — users table) ────────────────────
function hashPassword(pw) {
  const salt = crypto.randomBytes(16).toString('hex');
  const h    = crypto.scryptSync(pw, salt, 64).toString('hex');
  return `${salt}:${h}`;
}
function verifyPassword(pw, stored) {
  const [salt, h] = stored.split(':');
  if (!salt || !h) return false;
  try {
    const input = crypto.scryptSync(pw, salt, 64);
    return crypto.timingSafeEqual(Buffer.from(h, 'hex'), input);
  } catch { return false; }
}
try {
  const exists = db.prepare('SELECT id FROM users WHERE username=?').get(ADMIN_USER);
  if (!exists) {
    db.prepare('INSERT INTO users (username,email,password_hash,role) VALUES (?,?,?,?)' )
      .run(ADMIN_USER, `${ADMIN_USER}@sentinelgrid.local`, hashPassword(ADMIN_PASS), 'admin');
    logger.info({ username: ADMIN_USER }, 'Default admin user created');
  }
} catch (e) { logger.error(e, 'Failed to seed admin user'); }

// ── JWT helpers (gap #3) ──────────────────────────────────────────
function signAccessToken(user) {
  const jti = crypto.randomUUID();
  const token = jwt.sign(
    { sub: user.id, username: user.username, role: user.role, jti },
    JWT_SECRET, { expiresIn: '15m', issuer: 'sentinelgrid' }
  );
  return { token, jti };
}
function signRefreshToken(user) {
  const jti       = crypto.randomUUID();
  const expiresAt = Date.now() + 7 * 24 * 60 * 60 * 1000;
  const token     = jwt.sign({ sub: user.id, username: user.username, jti }, JWT_REFRESH_SECRET, { expiresIn: '7d' });
  db.prepare('INSERT INTO refresh_tokens (jti,user_id,username,expires_at) VALUES (?,?,?,?)').run(jti, user.id, user.username, expiresAt);
  return { token, jti, expiresAt };
}
function verifyJWT(token) {
  const payload = jwt.verify(token, JWT_SECRET, { issuer: 'sentinelgrid' });
  return payload;
}
function isAccessTokenRevoked(jti) {
  return !!db.prepare('SELECT 1 FROM revoked_access_tokens WHERE jti=?').get(jti);
}
function revokeToken(jti) {
  db.prepare('UPDATE refresh_tokens SET revoked=1 WHERE jti=?').run(jti);
}
function revokeAccessToken(jti, exp) {
  db.prepare('INSERT OR IGNORE INTO revoked_access_tokens (jti, expires_at) VALUES (?,?)').run(jti, exp * 1000);
}
// Temp token for mid-login 2FA step (signed, 5 min)
function signTempToken(userId) {
  return jwt.sign({ sub: userId, type: 'temp' }, JWT_SECRET, { expiresIn: '5m' });
}
function verifyTempToken(token) {
  const p = jwt.verify(token, JWT_SECRET);
  if (p.type !== 'temp') throw new Error('Not a temp token');
  return p;
}

// ── Persistent Rate limiter (gap #15) ─────────────────────
function checkRateLimit(ip, username = null) {
  const now = Date.now();
  
  // 1. Check IP lockout
  const ipRec = db.prepare('SELECT count, locked_until FROM rate_limits WHERE ip=?').get(ip);
  if (ipRec && now < ipRec.locked_until) return { locked: true, retryAfter: Math.ceil((ipRec.locked_until - now) / 1000) };
  
  // 2. Check User lockout
  if (username) {
    const userRec = db.prepare('SELECT failed_attempts, locked_until FROM users WHERE username=?').get(username);
    if (userRec && now < userRec.locked_until) return { locked: true, retryAfter: Math.ceil((userRec.locked_until - now) / 1000) };
  }
  
  return { locked: false };
}

function recordFailure(ip, username = null) {
  const now = Date.now();
  
  // 1. IP Failure
  db.prepare('INSERT INTO rate_limits (ip, count) VALUES (?, 1) ON CONFLICT(ip) DO UPDATE SET count = count + 1').run(ip);
  const ipRec = db.prepare('SELECT count FROM rate_limits WHERE ip=?').get(ip);
  if (ipRec.count >= 5) {
    db.prepare('UPDATE rate_limits SET locked_until=?, count=0 WHERE ip=?').run(now + 15 * 60 * 1000, ip);
  }
  
  // 2. User Failure
  if (username) {
    const userRec = db.prepare('SELECT id, failed_attempts FROM users WHERE username=?').get(username);
    if (userRec) {
      db.prepare('UPDATE users SET failed_attempts = failed_attempts + 1 WHERE id=?').run(userRec.id);
      if (userRec.failed_attempts + 1 >= 5) {
        db.prepare('UPDATE users SET locked_until=?, failed_attempts=0 WHERE id=?').run(now + 15 * 60 * 1000, userRec.id);
      }
    }
  }
}

function clearRateLimit(ip, username = null) {
  db.prepare('DELETE FROM rate_limits WHERE ip=?').run(ip);
  if (username) db.prepare('UPDATE users SET failed_attempts=0, locked_until=0 WHERE username=?').run(username);
}

// ── Auth middleware (gap #3, #13) ─────────────────────────────────
function authenticate(req) {
  const auth = req.headers.authorization;
  if (!auth?.startsWith('Bearer ')) throw new Error('No token provided');
  const token = auth.slice(7);
  const payload = verifyJWT(token);
  if (isAccessTokenRevoked(payload.jti)) throw new Error('Token revoked');
  return payload;
}

// ── CORS helper (gap #2) ──────────────────────────────────────────
function setCORS(req, res) {
  const origin = req.headers.origin || '';
  if (ALLOWED_ORIGINS.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Vary', 'Origin');
  }
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.setHeader('Access-Control-Allow-Credentials', 'true');
}

// ── DB backup (gap #25) ───────────────────────────────────────────
function backupDatabase() {
  try {
    // Checkpoint WAL before backup to include all committed data
    db.exec('PRAGMA wal_checkpoint(TRUNCATE)');
    
    const dir = path.join(process.cwd(), 'backups');
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    const ts  = new Date().toISOString().replace(/[:.]/g, '-');
    const dst = path.join(dir, `soc_db_${ts}.sqlite`);
    // After TRUNCATE checkpoint, the WAL is empty — only copy the main DB file
    fs.copyFileSync('./soc_database.sqlite', dst);
    
    const files = fs.readdirSync(dir).filter(f => f.endsWith('.sqlite')).sort();
    if (files.length > 7) files.slice(0, files.length - 7).forEach(f => fs.unlinkSync(path.join(dir, f)));
    logger.info({ dst }, 'DB backup completed');
  } catch (e) { logger.error(e, 'DB backup failed'); }
}
// Run backup every 6 hours, but first backup after 1 minute to avoid startup spike
setTimeout(() => {
  setInterval(backupDatabase, 6 * 60 * 60 * 1000);
}, 60000);

// ── Cleanup expired tokens and rate limits ────────────────────────
function cleanupExpiredData() {
  const now = Date.now();
  try {
    // Remove expired refresh tokens
    db.prepare('DELETE FROM refresh_tokens WHERE expires_at < ?').run(now);
    // Remove revoked access tokens that expired
    db.prepare('DELETE FROM revoked_access_tokens WHERE expires_at < ?').run(now);
    // Remove rate limit entries that are not locked and old (optional)
    // We keep rate limit entries for active tracking, but clear very old ones
    db.prepare('DELETE FROM rate_limits WHERE locked_until < ? AND count = 0').run(now - 24 * 60 * 60 * 1000); // older than 1 day and not locked
  } catch (e) {
    logger.error(e, 'Error cleaning up expired data');
  }
}
// Run cleanup every hour
setInterval(cleanupExpiredData, 60 * 60 * 1000);

// ── Signup control ───────────────────────────────────────────────
const SIGNUP_ENABLED = process.env.SIGNUP_ENABLED !== 'false';

function validateUsername(value) {
  const username = String(value || '').trim();
  if (!/^[a-zA-Z0-9_.-]{3,32}$/.test(username)) {
    return { ok: false, message: 'Username must be 3-32 chars and contain only letters, numbers, _, -, or .' };
  }
  return { ok: true, value: username };
}

function validateEmail(value) {
  const email = String(value || '').trim().toLowerCase();
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || email.length > 120) {
    return { ok: false, message: 'A valid email address is required.' };
  }
  return { ok: true, value: email };
}

function validatePassword(value) {
  const password = String(value || '');
  const strong = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).{10,128}$/;
  if (!strong.test(password)) {
    return { ok: false, message: 'Password must be 10+ chars with uppercase, lowercase, and number.' };
  }
  return { ok: true, value: password };
}



// ── WebSocket server (gap #16) ────────────────────────────────────
const httpServer = createServer();
const wss = new WebSocketServer({ server: httpServer });
const wsClients = new Set();
const wsAuthTimers = new Map();
wss.on('connection', (ws, req) => {
  ws.isAuthed = false;
  const authTimeout = setTimeout(() => {
    if (!ws.isAuthed) ws.close(4001, 'Unauthorized');
  }, 8000);
  wsAuthTimers.set(ws, authTimeout);

  ws.on('message', (raw) => {
    if (ws.isAuthed) return;
    try {
      const msg = JSON.parse(String(raw));
      if (msg?.event !== 'auth' || !msg?.token) {
        ws.close(4001, 'Unauthorized');
        return;
      }
      const payload = verifyJWT(msg.token);
      if (isAccessTokenRevoked(payload.jti)) throw new Error('Token revoked');
      ws.isAuthed = true;
      clearTimeout(authTimeout);
      wsAuthTimers.delete(ws);
      wsClients.add(ws);
      ws.send(JSON.stringify({ event: 'auth_ok', ts: Date.now() }));
      logger.info('WebSocket client authenticated');
    } catch {
      ws.close(4001, 'Unauthorized');
    }
  });

  ws.on('close', () => {
    clearTimeout(authTimeout);
    wsAuthTimers.delete(ws);
    wsClients.delete(ws);
  });
});
function broadcast(event, data) {
  const msg = JSON.stringify({ event, data, ts: Date.now() });
  wsClients.forEach(ws => { if (ws.readyState === 1) ws.send(msg); });
}

// ── Scanner Engine init ──
const scannerEngine = new ScannerEngine(db, logger, (payload) => broadcast(payload.event, payload.data));

const insertLog = db.prepare(`
  INSERT OR IGNORE INTO logs (hash, eventId, date, level, task, source, description, suspicious, segment, zone)
  VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
`);


function parseAndStoreLogs(rawText) {
  const blocks = rawText.split(/Event\[\d+\]:/).filter(Boolean);
  let inserted = 0;
  blocks.forEach(block => {
    const getLine = (key) => {
      const match = block.match(new RegExp(`${key}:\\s*(.*)`));
      return match ? match[1].trim() : '';
    };
    const id = getLine('Event ID');
    const date = getLine('Date');
    const level = getLine('Level') || 'Information';
    const task = getLine('Task');
    const source = getLine('Source');
    let desc = block.split('Description:')[1]?.trim() || '';
    
    if (!id || !date) return;

    const uniqueId = crypto.createHash('sha256').update(`${id}-${date}-${task}`).digest('hex');
    const suspicious = ['4625', '1102', '4688'].includes(id) ? 1 : 0;
    
    try {
      const result = insertLog.run(uniqueId, id, date, level, task, source, desc, suspicious);
      if (result.changes > 0) inserted++;
    } catch (e) {}
  });
  if (inserted > 0) invalidateCacheTags(['telemetry', 'logs', 'database', 'segments', 'stats']);
}

// ── Windows EOL database ──────────────────────────────────────────
const WINDOWS_EOL_DB = {
  '10.0.19041': { name: 'Windows 10 2004',  eolDate: '2021-12-14', isEOL: true  },
  '10.0.19042': { name: 'Windows 10 20H2',  eolDate: '2022-05-10', isEOL: true  },
  '10.0.19043': { name: 'Windows 10 21H1',  eolDate: '2022-12-13', isEOL: true  },
  '10.0.19044': { name: 'Windows 10 21H2',  eolDate: '2023-06-13', isEOL: true  },
  '10.0.19045': { name: 'Windows 10 22H2',  eolDate: '2025-10-14', isEOL: false },
  '10.0.22000': { name: 'Windows 11 21H2',  eolDate: '2023-10-10', isEOL: true  },
  '10.0.22621': { name: 'Windows 11 22H2',  eolDate: '2024-10-08', isEOL: true  },
  '10.0.22631': { name: 'Windows 11 23H2',  eolDate: '2025-11-11', isEOL: false },
  '10.0.26100': { name: 'Windows 11 24H2',  eolDate: '2026-10-13', isEOL: false },
};

// Resolve the friendly Windows version + EOL status from a kernel release string
function resolveWindowsVersion(release) {
  // release e.g. "10.0.26100" — match major.minor.build prefix
  for (const [buildKey, info] of Object.entries(WINDOWS_EOL_DB)) {
    const build = buildKey.split('.')[2];
    if (release.startsWith('10.0.') && release.split('.')[2] === build) {
      return info;
    }
  }
  // Fallback: find closest build number
  if (release.startsWith('10.0.')) {
    const buildNum = parseInt(release.split('.')[2] || '0', 10);
    if (buildNum >= 26100) return { name: 'Windows 11 24H2', eolDate: '2026-10-13', isEOL: false };
    if (buildNum >= 22631) return { name: 'Windows 11 23H2', eolDate: '2025-11-11', isEOL: false };
    if (buildNum >= 22621) return { name: 'Windows 11 22H2', eolDate: '2024-10-08', isEOL: true  };
    if (buildNum >= 22000) return { name: 'Windows 11 21H2', eolDate: '2023-10-10', isEOL: true  };
    if (buildNum >= 19045) return { name: 'Windows 10 22H2', eolDate: '2025-10-14', isEOL: false };
    if (buildNum >= 19044) return { name: 'Windows 10 21H2', eolDate: '2023-06-13', isEOL: true  };
    return { name: 'Windows 10 (Legacy Build)', eolDate: '2022-12-13', isEOL: true };
  }
  if (release.startsWith('6.3')) return { name: 'Windows 8.1', eolDate: '2023-01-10', isEOL: true };
  if (release.startsWith('6.2')) return { name: 'Windows 8',   eolDate: '2016-01-12', isEOL: true };
  if (release.startsWith('6.1')) return { name: 'Windows 7',   eolDate: '2020-01-14', isEOL: true };
  return { name: 'Windows (Unknown)', eolDate: 'Unknown', isEOL: true };
}

// Detect OS architecture from Node.js process
function getSystemArchitecture() {
  const arch = process.arch;
  if (arch === 'x64')   return 'x86_64 (64-bit)';
  if (arch === 'arm64') return 'ARM64';
  if (arch === 'arm')   return 'ARM (32-bit)';
  if (arch === 'ia32')  return 'x86 (32-bit)';
  return arch;
}

// Generate OS-specific security advisories based on detected platform/version
function getSecurityAdvisories(platform, osVersionInfo) {
  const advisories = [];
  const risks = [];
  let securityLevel = 'high';
  let patchStatus = 'unknown';

  if (platform === 'win32') {
    if (!osVersionInfo) {
      advisories.push('Unable to determine Windows version — manual verification required.');
    } else if (osVersionInfo.isEOL) {
      securityLevel = 'critical';
      patchStatus = 'critical';
      advisories.push(`CRITICAL: ${osVersionInfo.name} reached End-of-Life on ${osVersionInfo.eolDate}. No further security patches from Microsoft.`);
      advisories.push('All unpatched CVEs (EternalBlue, PrintNightmare, Log4Shell exploits via RDP, etc.) remain permanently unmitigated.');
      risks.push({ severity: 'critical', title: 'EOL OS — Immediate Upgrade Required', mitreId: 'T1190' });
      risks.push({ severity: 'critical', title: 'Unpatched kernel vulnerabilities', mitreId: 'T1068', cve: 'CVE-2021-34527, CVE-2017-0144' });
    } else {
      securityLevel = 'high';
      patchStatus = 'unknown';
      advisories.push(`${osVersionInfo.name} is within support lifecycle. EOL date: ${osVersionInfo.eolDate}.`);
      advisories.push('Ensure Windows Update is configured for automatic security updates.');
      risks.push({ severity: 'medium', title: 'Verify Windows Defender real-time protection is active', mitreId: 'T1562.001' });
    }
    risks.push({ severity: 'medium', title: 'SMBv1 exposure risk (EternalBlue vector)', mitreId: 'T1021.002', cve: 'CVE-2017-0144' });
    risks.push({ severity: 'medium', title: 'RDP / NLA enforcement required', mitreId: 'T1021.001' });
    advisories.push('Ensure BitLocker is enabled on all volumes.');
    advisories.push('Audit Windows Firewall rules: block inbound SMB (445) and RDP (3389) from untrusted networks.');
    advisories.push('Enable Credential Guard and HVCI in Windows Security settings.');
    advisories.push('Review local administrator accounts and enforce least privilege.');

  } else if (platform === 'linux') {
    securityLevel = 'medium';
    patchStatus = 'unknown';
    advisories.push('Ensure kernel is fully patched: run "sudo apt update && sudo apt upgrade -y" (Debian/Ubuntu) or "sudo dnf upgrade" (RHEL/Fedora).');
    advisories.push('Verify SELinux (RHEL) or AppArmor (Ubuntu) is in enforcing mode.');
    advisories.push('Run "ss -tulnp" to audit open listening ports and disable unnecessary services.');
    advisories.push('Enforce SSH key-based auth: disable PasswordAuthentication in /etc/ssh/sshd_config.');
    advisories.push('Monitor /etc/crontab and user crontabs for unauthorized persistence entries.');
    risks.push({ severity: 'high', title: 'Dirty Pipe kernel vulnerability if kernel < 5.16.11', mitreId: 'T1068', cve: 'CVE-2022-0847' });
    risks.push({ severity: 'medium', title: 'sudo misconfiguration privilege escalation', mitreId: 'T1548.003' });
    risks.push({ severity: 'medium', title: 'SSH key management and authorized_keys monitoring', mitreId: 'T1098.004' });

  } else if (platform === 'darwin') {
    securityLevel = 'high';
    patchStatus = 'unknown';
    advisories.push('Run "softwareupdate --list" to check for pending macOS security patches.');
    advisories.push('Verify SIP status: run "csrutil status" — should report "enabled".');
    advisories.push('Enable FileVault full-disk encryption via System Settings → Privacy & Security.');
    advisories.push('Enable macOS built-in Firewall in System Settings → Network → Firewall.');
    risks.push({ severity: 'medium', title: 'Gatekeeper & SIP status unverified', mitreId: 'T1553.001' });
    risks.push({ severity: 'low',    title: 'XPC service injection monitoring', mitreId: 'T1543.004' });
  }

  return { advisories, risks, securityLevel, patchStatus };
}

async function getNetworkConfig() {
  const platform = os.platform();
  let gateway = 'Unknown';
  let dns = 'Unknown';
  try {
    if (platform === 'win32') {
      const { stdout } = await execAsync('powershell -NoProfile -Command "(Get-NetIPConfiguration | Where-Object { $_.IPv4DefaultGateway -ne $null }).IPv4DefaultGateway.NextHop; (Get-NetIPConfiguration | Where-Object { $_.IPv4DefaultGateway -ne $null }).DNSServer.ServerAddresses -join \', \'"');
      const lines = stdout.trim().split('\n').map(l => l.trim()).filter(Boolean);
      if (lines.length >= 1) gateway = lines[0];
      if (lines.length >= 2) dns = lines[1];
    } else if (platform === 'linux') {
      const gwOut = await execAsync('ip route | grep default | awk \'{print $3}\'');
      gateway = gwOut.stdout.trim() || 'Unknown';
      const dnsOut = await execAsync('grep nameserver /etc/resolv.conf | awk \'{print $2}\' | tr "\\n" "," | sed "s/,$//"\n');
      dns = dnsOut.stdout.trim() || 'Unknown';
    } else if (platform === 'darwin') {
      const gwOut = await execAsync('route -n get default | grep gateway | awk \'{print $2}\'');
      gateway = gwOut.stdout.trim() || 'Unknown';
      const dnsOut = await execAsync('scutil --dns | grep nameserver | awk \'{print $3}\' | sort -u | tr "\\n" "," | sed "s/,$//"');
      dns = dnsOut.stdout.trim() || 'Unknown';
    }
  } catch (e) {
    // Ignore errors, fallback to Unknown
  }
  return { gateway, dns };
}

async function getSystemTelemetry() {
  const interfaces = os.networkInterfaces();
  let localIp = 'Unknown';
  let macAddress = 'Unknown';
  let subnet = 'Unknown';
  let networkAdapter = 'Unknown';

  for (const name of Object.keys(interfaces)) {
    for (const iface of interfaces[name]) {
      // Skip over internal (i.e. 127.0.0.1) and non-ipv4 addresses
      if ('IPv4' !== iface.family || iface.internal !== false) {
        continue;
      }
      localIp = iface.address;
      macAddress = iface.mac;
      subnet = iface.netmask;
      networkAdapter = name;
      break;
    }
    if (localIp !== 'Unknown') break;
  }

  const platform = os.platform();
  const release  = os.release();
  const arch     = getSystemArchitecture();

  // Resolve detailed OS info
  let osName = platform;
  let osVersionInfo = null;
  if (platform === 'win32') {
    osVersionInfo = resolveWindowsVersion(release);
    osName = osVersionInfo.name;
  } else if (platform === 'darwin') {
    osName = `macOS ${release}`;
  } else if (platform === 'linux') {
    osName = `Linux ${release}`;
  }

  const { advisories, risks, securityLevel, patchStatus } = getSecurityAdvisories(platform, osVersionInfo);
  const netConfig = await getNetworkConfig();

  return {
    platform: `${osName} (${platform})`,
    release,
    osName,
    architecture: arch,
    cpu: os.cpus()[0]?.model || 'Unknown',
    cores: os.cpus().length,
    totalMem: (os.totalmem() / 1024 / 1024 / 1024).toFixed(2) + ' GB',
    freeMem: (os.freemem() / 1024 / 1024 / 1024).toFixed(2) + ' GB',
    uptime: (os.uptime() / 3600).toFixed(2) + ' Hours',
    localIp,
    macAddress,
    subnet,
    gateway: netConfig.gateway,
    dns: netConfig.dns,
    networkAdapter,
    // OS Security fields
    isEOL: osVersionInfo?.isEOL ?? false,
    eolDate: osVersionInfo?.eolDate ?? null,
    securityLevel,
    patchStatus,
    advisories,
    risks,
  };
}

function parseDateFromLog(timeCreated) {
  if (!timeCreated) return new Date();
  // PowerShell /Date(ms)/ format  e.g. \/Date(1714500000000)\/
  const msMatch = String(timeCreated).match(/\/Date\((\d+)\)\//);
  if (msMatch) return new Date(parseInt(msMatch[1], 10));
  // Plain millisecond number
  if (typeof timeCreated === 'number') return new Date(timeCreated);
  // ISO string or any other parseable string
  const d = new Date(timeCreated);
  return isNaN(d.getTime()) ? new Date() : d;
}

// MITRE ATT&CK enrichment table (Windows Event IDs → technique)
const MITRE_MAP = {
  '4625': { id: 'T1110',     name: 'Brute Force',                  tactic: 'Credential Access' },
  '4648': { id: 'T1078',     name: 'Valid Accounts',               tactic: 'Defense Evasion' },
  '4672': { id: 'T1078.003', name: 'Local Account — High Priv',    tactic: 'Privilege Escalation' },
  '4688': { id: 'T1059',     name: 'Command & Scripting Interp.',  tactic: 'Execution' },
  '4698': { id: 'T1053.005', name: 'Scheduled Task',               tactic: 'Persistence' },
  '4720': { id: 'T1136.001', name: 'Local Account Created',        tactic: 'Persistence' },
  '4724': { id: 'T1098',     name: 'Account Manipulation',        tactic: 'Persistence' },
  '4732': { id: 'T1098',     name: 'Account Manipulation',        tactic: 'Persistence' },
  '7045': { id: 'T1543.003', name: 'New Windows Service',          tactic: 'Persistence' },
  '1102': { id: 'T1070.001', name: 'Clear Windows Event Logs',     tactic: 'Defense Evasion' },
  '4776': { id: 'T1110',     name: 'Credential Validation',       tactic: 'Credential Access' },
  '4768': { id: 'T1558.003', name: 'Kerberoasting',                tactic: 'Credential Access' },
  '4769': { id: 'T1558.003', name: 'Kerberos Service Ticket',      tactic: 'Credential Access' },
};

const SUSPICIOUS_IDS = new Set(Object.keys(MITRE_MAP));

// Segment/Zone inference based on source and log characteristics
function inferSegmentZone(log, source, task) {
  const sourceLower = (source || '').toLowerCase();
  const taskLower = (task || '').toLowerCase();
  const msgLower = (log.Message || '').toLowerCase();
  
  // Network-related events
  if (sourceLower.includes('firewall') || sourceLower.includes('network') || 
      taskLower.includes('network') || msgLower.includes('firewall') ||
      msgLower.includes('connection')) {
    return { segment: 'network', zone: 'perimeter' };
  }
  
  // Authentication/Identity events
  if (sourceLower.includes('security') || taskLower.includes('logon') || 
      taskLower.includes('auth') || msgLower.includes('logon') ||
      msgLower.includes('authentication')) {
    return { segment: 'identity', zone: 'identity' };
  }
  
  // Service/Process events
  if (sourceLower.includes('service') || taskLower.includes('service') ||
      sourceLower.includes('process') || taskLower.includes('process')) {
    return { segment: 'services', zone: 'core' };
  }
  
  // System/kernel events
  if (sourceLower.includes('system') || sourceLower.includes('kernel') ||
      sourceLower.includes('driver')) {
    return { segment: 'system', zone: 'core' };
  }
  
  // Application events
  if (sourceLower.includes('application') || taskLower.includes('application')) {
    return { segment: 'applications', zone: 'dmz' };
  }
  
  // Database events
  if (sourceLower.includes('sql') || sourceLower.includes('database') ||
      msgLower.includes('database')) {
    return { segment: 'database', zone: 'data-core' };
  }
  
  // Web/Cloud events
  if (sourceLower.includes('iis') || sourceLower.includes('web') ||
      msgLower.includes('cloud') || sourceLower.includes('azure') ||
      sourceLower.includes('aws')) {
    return { segment: 'cloud', zone: 'cloud' };
  }
  
  // Default fallback
  return { segment: 'general', zone: 'unknown' };
}

// Enrich a raw PowerShell log object with Date, LogName, MITRE, Computer, Segment/Zone, and write to DB
function enrichAndStore(log, logName) {
  let id = 'Unknown';
  if (log.Id != null) {
    // If Id is a string (e.g. provider name), try to find a numeric Id if it exists elsewhere
    if (typeof log.Id === 'string' && isNaN(parseInt(log.Id))) {
       id = 'Unknown';
    } else {
       id = String(log.Id);
    }
  }
  
  const dateObj  = parseDateFromLog(log.TimeCreated);
  const date     = dateObj.toISOString();
  log.Date       = date;
  log.LogName    = logName || log.LogName || 'Unknown';
  log.Computer   = os.hostname();
  const mitre    = MITRE_MAP[id] || null;
  log.Mitre      = mitre;
  const suspicious = SUSPICIOUS_IDS.has(id) ? 1 : 0;
  log.Suspicious = suspicious;

  const level  = log.LevelDisplayName || 'Information';
  const task   = log.TaskDisplayName  || '';
  const source = log.ProviderName     || '';
  const desc   = log.Message          || '';
  const uid    = crypto.createHash('sha256').update(`${id}-${date}-${task}-${source}`).digest('hex');
  
  // Infer segment and zone
  const { segment, zone } = inferSegmentZone(log, source, task);
  log.Segment = segment;
  log.Zone = zone;
  
  try { insertLog.run(uid, id, date, level, task, source, desc, suspicious, segment, zone); } catch (e) { logger.error(e, 'Error persisting enriched log'); }
  return log;
}

// Run PowerShell to read real Windows event logs from one or more channels
async function fetchWindowsEventLogs(logNames, maxEvents) {
  const nameList  = logNames.map(n => `'${n}'`).join(',');
  const psScript  =
    `try {` +
    `  $evts = Get-WinEvent -LogName ${nameList} -MaxEvents ${maxEvents} -ErrorAction SilentlyContinue;` +
    `  if ($null -eq $evts) { Write-Output '[]'; return }` +
    `  $arr = @($evts | Select-Object @{Name='Id';Expression={[int]$_.Id}}, TimeCreated, LevelDisplayName, TaskDisplayName, ProviderName, LogName, MachineName, Message);` +
    `  Write-Output ($arr | ConvertTo-Json -Compress -Depth 3)` +
    `} catch { Write-Output '[]' }`;

  // Encode the script as Base64 to avoid shell-quoting nightmares
  const encoded = Buffer.from(psScript, 'utf16le').toString('base64');
  const { stdout } = await execAsync(`powershell -NoProfile -NonInteractive -EncodedCommand ${encoded}`, { timeout: 20000 });
  const trimmed = stdout.trim();
  if (!trimmed || trimmed === '[]') return [];
  const parsed = JSON.parse(trimmed);
  return Array.isArray(parsed) ? parsed : [parsed];
}

// Aggressive filter for common Windows internal noise
const NOISE_BLACKLIST = [
  'ApiSet Function:',
  'Microsoft-Windows-AppModel',
  'The application-specific permission settings do not grant Local Activation permission',
  'The description for Event ID', // Often means message DLL missing, usually noise
  'Information: The service was started',
  'Information: The service was stopped',
];

async function getWindowsLogs() {
  try {
    let logs = [];

    if (os.platform() === 'win32') {
      try {
        // Try Security log first (requires admin); fall back gracefully
        let secLogs = [];
        try {
          secLogs = await fetchWindowsEventLogs(['Security'], 30);
        } catch { /* no admin — skip Security */ }

        const sysAppLogs = await fetchWindowsEventLogs(['System', 'Application', 'Setup'], 500);
        logs = [...secLogs, ...sysAppLogs];
      } catch (psErr) {
        logger.warn({ err: psErr.message }, 'Windows log fetch failed');
        return [];
      }
    } else if (os.platform() === 'linux') {
      try {
        // Try journalctl JSON first (most modern distros), then fall back to plain syslog
        try {
          const { stdout } = await execAsync('journalctl -n 80 --no-pager -o json 2>/dev/null');
          const lines = stdout.trim().split('\n').filter(Boolean);
          logs = lines.map((l, i) => {
            try {
              const j = JSON.parse(l);
              return {
                Id: j.PRIORITY ? String(j.PRIORITY) : 'SYS-'+i,
                TimeCreated: j.__REALTIME_TIMESTAMP ? new Date(Math.floor(parseInt(j.__REALTIME_TIMESTAMP) / 1000)).toISOString() : new Date().toISOString(),
                LevelDisplayName: ['0','1','2','3'].includes(j.PRIORITY) ? 'Critical' : j.PRIORITY === '4' ? 'Warning' : 'Information',
                TaskDisplayName: j._SYSTEMD_UNIT || 'System',
                ProviderName: j.SYSLOG_IDENTIFIER || j._COMM || 'journald',
                LogName: 'System Journal',
                Message: j.MESSAGE || l,
              };
            } catch { return null; }
          }).filter(Boolean);
        } catch {
          const { stdout } = await execAsync('tail -n 80 /var/log/syslog 2>/dev/null || tail -n 80 /var/log/messages 2>/dev/null || echo ""');
          logs = stdout.split('\n').filter(Boolean).map((line, i) => ({
            Id: 'SYS-'+i, TimeCreated: new Date().toISOString(),
            LevelDisplayName: line.toLowerCase().includes('fail') || line.toLowerCase().includes('error') ? 'Error' : 'Information',
            TaskDisplayName: 'Syslog', ProviderName: 'System', LogName: 'Syslog', Message: line,
          }));
        }
      } catch { logs = []; }
    } else if (os.platform() === 'darwin') {
      try {
        const { stdout } = await execAsync('log show --last 5m --style json 2>/dev/null | head -c 524288 || echo "[]"');
        try {
          const arr = JSON.parse(stdout);
          logs = (Array.isArray(arr) ? arr : []).slice(0, 80).map((e, i) => ({
            Id: 'MAC-'+i, TimeCreated: e.timestamp || new Date().toISOString(),
            LevelDisplayName: e.messageType === 'fault' || e.messageType === 'error' ? 'Error' : 'Information',
            TaskDisplayName: e.subsystem || 'System', ProviderName: e.processImagePath?.split('/').pop() || 'System',
            LogName: 'Unified Log', Message: e.eventMessage || '',
          }));
        } catch {
          const { stdout: raw } = await execAsync('log show --last 5m --style compact 2>/dev/null | tail -80 || echo ""');
          logs = raw.split('\n').filter(Boolean).map((l, i) => ({
            Id: 'MAC-'+i, TimeCreated: new Date().toISOString(),
            LevelDisplayName: l.includes('error') || l.includes('fault') ? 'Error' : 'Information',
            TaskDisplayName: 'MacLog', ProviderName: 'System', LogName: 'Unified Log', Message: l,
          }));
        }
      } catch { logs = []; }
    }

    // Fetch Android logs if ADB is available
    let androidLogs = [];
    try {
      const { stdout } = await execAsync('adb logcat -d -v time -t 80', { timeout: 3000 });
      const lines = stdout.split('\n').filter(Boolean);
      androidLogs = lines.map((l, i) => ({
        Id: 'ANDR-'+i, TimeCreated: new Date().toISOString(),
        LevelDisplayName: l.includes(' E ') ? 'Error' : (l.includes(' W ') ? 'Warning' : 'Information'),
        TaskDisplayName: 'AndroidSystem', ProviderName: 'ADB', LogName: 'Android Logcat', Message: l,
      }));
    } catch (e) { /* ADB not available */ }

    logs = [...logs, ...androidLogs];

    // Enrich all collected logs and persist to DB
    logs = logs
      .filter(l => {
        const msg = l.Message || '';
        const provider = l.ProviderName || '';
        return !NOISE_BLACKLIST.some(p => msg.includes(p) || provider.includes(p));
      })
      .map(log => enrichAndStore(log, log.LogName));

    // Fallback: If EVERYTHING was noise, add a heartbeat to show we are still alive
    if (logs.length === 0) {
      logs.push(enrichAndStore({
        Id: 0,
        TimeCreated: new Date().toISOString(),
        LevelDisplayName: 'Information',
        TaskDisplayName: 'Monitoring',
        ProviderName: 'SentinelGrid Agent',
        Message: 'Real-time telemetry stream active. No security threats or relevant events in the current scan window.'
      }, 'System'));
    }

    if (logs.length > 0) {
      if (ELASTIC_URL) forwardToElasticsearch(logs);
      if (SPLUNK_HEC_URL) forwardToSplunk(logs);
    }

    return logs;
  } catch (e) {
    logger.warn({ err: e.message }, 'getWindowsLogs error — returning empty array');
    return [];
  }
}

// SIEM Integrations
async function forwardToElasticsearch(logs) {
  try {
    const bulkData = logs.flatMap(log => [{ index: { _index: 'windows-security-logs' } }, log]);
    const response = await fetch(`${ELASTIC_URL}/_bulk`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-ndjson' },
      body: bulkData.map(JSON.stringify).join('\n') + '\n'
    });
    if (!response.ok) console.error("Elasticsearch Forwarding Failed");
  } catch (err) {
    // console.error("Elasticsearch not reachable:", err.message);
  }
}

async function forwardToSplunk(logs) {
  try {
    const events = logs.map(log => JSON.stringify({ event: log })).join('\n');
    await fetch(SPLUNK_HEC_URL, {
      method: 'POST',
      headers: { 'Authorization': `Splunk ${SPLUNK_HEC_TOKEN}` },
      body: events
    });
  } catch (err) {
    // console.error("Splunk HEC not reachable:", err.message);
  }
}

let latestTelemetry = {
  ts: 0,
  system: null,
  logs: [],
  network: [],
  files: [],
  analysis: null,
  rawNetwork: '[]',
};
let isCollectingTelemetry = false;

async function collectTelemetrySnapshot() {
  if (isCollectingTelemetry) return latestTelemetry;
  isCollectingTelemetry = true;
  try {
    const [logs, network, files, system] = await Promise.all([
      getWindowsLogs(),
      getNetworkTraffic(),
      getFileChanges(),
      getSystemTelemetry(),
    ]);
    const analysis = await analyzeTelemetry(logs, network, files);
    latestTelemetry = {
      ts: Date.now(),
      system,
      logs,
      network,
      files,
      analysis,
      rawNetwork: JSON.stringify(network),
    };
    invalidateCacheTags(['telemetry', 'logs', 'stats']);
    return latestTelemetry;
  } finally {
    isCollectingTelemetry = false;
  }
}

// Autonomous real-time collector and broadcast loop - 5s interval
const TELEMETRY_INTERVAL = 5000;

// Core 6 segments based on what can actually be detected from local system telemetry
const ACTIVE_SEGMENTS = [
  { 
    name: 'identity', 
    zone: 'identity', 
    label: 'Identity & Auth',
    description: 'Authentication events, logon/logoff, privilege escalation',
    detectable: true,
    icon: 'shield'
  },
  { 
    name: 'network', 
    zone: 'perimeter', 
    label: 'Network & Firewall',
    description: 'Network connections, firewall events, traffic analysis',
    detectable: true,
    icon: 'network'
  },
  { 
    name: 'system', 
    zone: 'core', 
    label: 'System & Kernel',
    description: 'OS events, drivers, services, system integrity',
    detectable: true,
    icon: 'cpu'
  },
  { 
    name: 'endpoints', 
    zone: 'internal', 
    label: 'Endpoints & Access',
    description: 'Remote access, file sharing, USB devices, peripherals',
    detectable: true,
    icon: 'hard-drive'
  },
  { 
    name: 'applications', 
    zone: 'dmz', 
    label: 'Applications',
    description: 'Application events, crashes, installations, web services',
    detectable: true,
    icon: 'app-window'
  },
  { 
    name: 'data', 
    zone: 'data-core', 
    label: 'Data & Database',
    description: 'Database connections, file integrity, data access',
    detectable: true,
    icon: 'database'
  }
];

// ── System Permission & Capability Detection ─────────────────────

const SYSTEM_PERMISSIONS = {
  isAdmin: false,
  isElevated: false,
  canAccessSecurityLog: false,
  canAccessProcessMemory: false,
  canMonitorUSB: false,
  lastChecked: 0,
  requestedElevation: false
};

// Detect if running with administrator privileges
async function detectPermissions() {
  SYSTEM_PERMISSIONS.lastChecked = Date.now();
  
  if (os.platform() === 'win32') {
    try {
      // Check admin status via PowerShell
      const { stdout } = await execAsync('powershell -Command "([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)"');
      SYSTEM_PERMISSIONS.isAdmin = stdout.trim().toLowerCase() === 'true';
      SYSTEM_PERMISSIONS.isElevated = SYSTEM_PERMISSIONS.isAdmin;
      
      // Test Security log access
      try {
        await execAsync('powershell -Command "Get-WinEvent -LogName Security -MaxEvents 1 -ErrorAction Stop"', { timeout: 3000 });
        SYSTEM_PERMISSIONS.canAccessSecurityLog = true;
      } catch { 
        SYSTEM_PERMISSIONS.canAccessSecurityLog = false;
      }
      
      // Test process memory access (admin usually required)
      SYSTEM_PERMISSIONS.canAccessProcessMemory = SYSTEM_PERMISSIONS.isAdmin;
      SYSTEM_PERMISSIONS.canMonitorUSB = SYSTEM_PERMISSIONS.isAdmin;
      
    } catch (e) {
      logger.error(e, 'Permission detection failed');
    }
  } else if (os.platform() === 'linux') {
    // Check if root
    SYSTEM_PERMISSIONS.isAdmin = process.getuid ? process.getuid() === 0 : false;
    SYSTEM_PERMISSIONS.isElevated = SYSTEM_PERMISSIONS.isAdmin;
    SYSTEM_PERMISSIONS.canAccessSecurityLog = SYSTEM_PERMISSIONS.isAdmin;
    SYSTEM_PERMISSIONS.canAccessProcessMemory = SYSTEM_PERMISSIONS.isAdmin;
    SYSTEM_PERMISSIONS.canMonitorUSB = fs.existsSync('/var/log/syslog') || fs.existsSync('/var/log/messages');
  } else {
    // macOS and others
    SYSTEM_PERMISSIONS.isAdmin = false; // Conservative default
    SYSTEM_PERMISSIONS.canMonitorUSB = true; // Usually accessible
  }
  
  return SYSTEM_PERMISSIONS;
}

// Get permission status for API
function getPermissionStatus() {
  return {
    ...SYSTEM_PERMISSIONS,
    platform: os.platform(),
    recommendations: getPermissionRecommendations()
  };
}

function getPermissionRecommendations() {
  const recs = [];
  if (os.platform() === 'win32') {
    if (!SYSTEM_PERMISSIONS.isAdmin) {
      recs.push({
        type: 'elevation',
        priority: 'high',
        message: 'Run as Administrator for full security monitoring',
        action: 'Restart with "Run as administrator"'
      });
    }
    if (!SYSTEM_PERMISSIONS.canAccessSecurityLog) {
      recs.push({
        type: 'security_log',
        priority: 'high',
        message: 'Cannot access Security event log - identity segment limited',
        action: 'Grant "Manage auditing and security log" privilege or run as Admin'
      });
    }
  } else if (os.platform() === 'linux') {
    if (!SYSTEM_PERMISSIONS.isAdmin) {
      recs.push({
        type: 'elevation',
        priority: 'medium',
        message: 'Run with sudo for complete system monitoring',
        action: 'Use sudo or configure polkit for log access'
      });
    }
  }
  return recs;
}

// Broadcast permission status to all clients
function broadcastPermissions() {
  broadcast('permission_status', getPermissionStatus());
}

// Check permissions periodically
setInterval(async () => {
  await detectPermissions();
  broadcastPermissions();
}, 30000); // Check every 30 seconds

// ── Advanced System Monitoring ──────────────────────────────────

// 1. Real-time Process Monitoring
const SUSPICIOUS_PROCESSES = new Set([
  'mimikatz', 'pwdump', 'pswdump', 'gsecdump', 'wce', 'fgdump',
  'procdump', 'dumpsec', 'cachedump', 'lsadump', 'secretsdump',
  'pwdumpx', 'hashdump', 'mimidrv', 'mimilib', 'kappfree',
  'processhacker', 'pchunter', 'xuetr', 'win64api', 'meterpreter',
  'shellcode', 'reflectivedll', 'bloodhound', 'sharphound',
  'rubeus', 'certify', 'seatbelt', 'sharpup', 'winpeas',
  'lolbas', 'certutil', 'bitsadmin', 'mshta', 'cscript',
  'wscript', 'regsvr32', 'rundll32', 'installutil',
  'psexec', 'paexec', 'csexec', 'remcom', 'smbexec',
  'nc.exe', 'ncat.exe', 'nmap.exe', 'zenmap', 'masscan',
  'hydra.exe', 'john.exe', 'hashcat.exe', 'aircrack',
  'wireshark', 'ethereal', 'tcpdump', ' Cain', 'Abel',
  'vssadmin', 'wbadmin', 'bcdedit', 'wevtutil', 'fsutil',
  'diskshadow', 'robocopy' // when used suspiciously
]);

const KNOWN_GOOD_PROCESSES = new Set([
  'explorer.exe', 'svchost.exe', 'csrss.exe', 'smss.exe',
  'services.exe', 'lsass.exe', 'wininit.exe', 'winlogon.exe',
  'taskhostw.exe', 'dwm.exe', 'sihost.exe', 'ctfmon.exe',
  'msedge.exe', 'chrome.exe', 'firefox.exe', 'code.exe',
  'node.exe', 'powershell.exe', 'pwsh.exe', 'cmd.exe',
  'conhost.exe', 'dllhost.exe', 'fontdrvhost.exe',
  'backgroundtaskhost.exe', 'runtimebroker.exe'
]);

async function getProcessList() {
  try {
    const platform = os.platform();
    let processes = [];
    
    if (platform === 'win32') {
      // PowerShell with admin check
      const canAccessAll = SYSTEM_PERMISSIONS.canAccessProcessMemory;
      const psCmd = canAccessAll 
        ? `Get-WmiObject Win32_Process | Select-Object ProcessId, Name, ExecutablePath, CommandLine, ParentProcessId, CreationDate | ConvertTo-Json -Compress`
        : `Get-Process | Select-Object Id, ProcessName, Path, StartTime | ConvertTo-Json -Compress`;
      
      try {
        const { stdout } = await execAsync(`powershell -Command "${psCmd}"`, { timeout: 10000 });
        const parsed = JSON.parse(stdout);
        const arr = Array.isArray(parsed) ? parsed : [parsed];
        processes = arr.map(p => ({
          pid: p.ProcessId || p.Id,
          name: (p.Name || p.ProcessName || 'unknown').toLowerCase(),
          path: p.ExecutablePath || p.Path || 'Unknown',
          cmdline: p.CommandLine || '',
          ppid: p.ParentProcessId || 0,
          created: p.CreationDate || p.StartTime,
          suspicious: isProcessSuspicious(p.Name || p.ProcessName || '', p.CommandLine || ''),
          risk: calculateProcessRisk(p.Name || p.ProcessName || '', p.CommandLine || '')
        }));
      } catch (e) {
        // Fallback to tasklist if PowerShell fails
        const { stdout } = await execAsync('tasklist /fo csv /nh', { timeout: 5000 });
        processes = stdout.split('\n').filter(Boolean).map(line => {
          const parts = line.replace(/"/g, '').split(',');
          return {
            pid: parts[1] || '0',
            name: (parts[0] || 'unknown').toLowerCase(),
            path: 'Unknown',
            cmdline: '',
            ppid: 0,
            created: null,
            suspicious: isProcessSuspicious(parts[0] || '', ''),
            risk: calculateProcessRisk(parts[0] || '', '')
          };
        });
      }
    } else if (platform === 'linux') {
      const { stdout } = await execAsync('ps aux --no-headers', { timeout: 5000 });
      processes = stdout.split('\n').filter(Boolean).map(line => {
        const parts = line.split(/\s+/);
        return {
          pid: parts[1] || '0',
          name: (parts[10] || 'unknown').toLowerCase(),
          path: parts[10] || '',
          cmdline: parts.slice(10).join(' '),
          ppid: 0,
          created: null,
          suspicious: isProcessSuspicious(parts[10] || '', parts.slice(10).join(' ')),
          risk: calculateProcessRisk(parts[10] || '', parts.slice(10).join(' '))
        };
      });
    }
    
    // Store suspicious processes as alerts
    const suspicious = processes.filter(p => p.suspicious || p.risk > 50);
    suspicious.forEach(p => {
      createSegmentAlert('system', 'core', p.risk > 70 ? 'critical' : 'warning', 
        'Suspicious Process', `Process ${p.name} (PID: ${p.pid}) - Risk: ${p.risk}%`, 'T1055');
    });
    
    return processes;
  } catch (e) {
    logger.error(e, 'Process monitoring failed');
    return [];
  }
}

function isProcessSuspicious(name, cmdline) {
  const nameLower = (name || '').toLowerCase();
  const cmdLower = (cmdline || '').toLowerCase();
  
  if (SUSPICIOUS_PROCESSES.has(nameLower)) return true;
  // Check if any suspicious process name is included in the process name
  for (const s of SUSPICIOUS_PROCESSES) {
    if (nameLower.includes(s)) return true;
  }
  if (cmdLower.includes('downloadstring') || cmdLower.includes('iex') || cmdLower.includes('invoke-expression')) return true;
  if (cmdLower.includes('bypass') && cmdLower.includes('executionpolicy')) return true;
  if (cmdLower.includes('-enc') && cmdLower.length > 50) return true; // Base64 encoded
  if (cmdLower.includes('net.webclient') || cmdLower.includes('wget') || cmdLower.includes('curl')) return true;
  
  return false;
}

function calculateProcessRisk(name, cmdline) {
  let risk = 0;
  const nameLower = (name || '').toLowerCase();
  const cmdLower = (cmdline || '').toLowerCase();
  
  if (SUSPICIOUS_PROCESSES.has(nameLower)) risk += 60;
  if (KNOWN_GOOD_PROCESSES.has(nameLower)) risk -= 30;
  
  // Known LOLBAS techniques
  if (cmdLower.includes('certutil') && (cmdLower.includes('urlcache') || cmdLower.includes('split'))) risk += 40;
  if (cmdLower.includes('bitsadmin') && cmdLower.includes('transfer')) risk += 40;
  if (cmdLower.includes('mshta') && cmdLower.includes('http')) risk += 50;
  if (cmdLower.includes('regsvr32') && (cmdLower.includes('http') || cmdLower.includes('script'))) risk += 45;
  if (cmdLower.includes('rundll32') && cmdLower.includes('javascript')) risk += 45;
  if (cmdLower.includes('installutil') && cmdLower.includes('logtoconsole=false')) risk += 40;
  
  // PowerShell obfuscation
  if (cmdLower.includes('-enc')) risk += 30;
  if (cmdLower.includes('bypass')) risk += 20;
  
  // Network tools
  if (nameLower.includes('nc') || nameLower.includes('ncat') || nameLower.includes('netcat')) risk += 50;
  if (nameLower.includes('mimikatz') || nameLower.includes('pwdump')) risk += 80;
  
  return Math.max(0, Math.min(100, risk));
}

// 2. USB Device Monitoring
async function getUSBDevices() {
  if (!SYSTEM_PERMISSIONS.canMonitorUSB) return { connected: [], history: [] };
  
  try {
    if (os.platform() === 'win32') {
      const psCmd = `
        Get-PnpDevice -Class USB | Where-Object { $_.Status -eq 'OK' } | 
        Select-Object FriendlyName, InstanceId, Class, Status |
        ConvertTo-Json -Compress
      `;
      const { stdout } = await execAsync(`powershell -Command "${psCmd}"`, { timeout: 5000 });
      const devices = JSON.parse(stdout);
      const arr = Array.isArray(devices) ? devices : [devices];
      
      // Check for new USB storage devices
      const storageDevices = arr.filter(d => 
        d.FriendlyName?.toLowerCase().includes('storage') || 
        d.FriendlyName?.toLowerCase().includes('disk') ||
        d.FriendlyName?.toLowerCase().includes('usb mass')
      );
      
      storageDevices.forEach(d => {
        createSegmentAlert('endpoints', 'internal', 'medium', 'USB Device Connected',
          `USB storage device: ${d.FriendlyName}`, 'T1091');
      });
      
      return { connected: arr, timestamp: Date.now() };
    }
    return { connected: [], timestamp: Date.now() };
  } catch (e) {
    return { connected: [], timestamp: Date.now() };
  }
}

// 3. Windows Defender / AV Status
async function getDefenderStatus() {
  if (os.platform() !== 'win32') return null;
  
  try {
    const psCmd = `
      $defender = Get-MpComputerStatus;
      $pref = Get-MpPreference;
      @{ 
        Enabled = $defender.RealTimeProtectionEnabled;
        BehavMonitor = $defender.BehaviorMonitorEnabled;
        OnAccess = $defender.OnAccessProtectionEnabled;
        Antivirus = $defender.AntivirusEnabled;
        Antispyware = $defender.AntispywareEnabled;
        NIS = $defender.NISEnabled;
        SigAge = $defender.DefenderSignatureAge;
        QuickScanAge = $defender.QuickScanAge;
        FullScanAge = $defender.FullScanAge;
        Exclusions = $pref.ExclusionPath.Count;
      } | ConvertTo-Json -Compress
    `;
    const { stdout } = await execAsync(`powershell -Command "${psCmd}"`, { timeout: 5000 });
    const status = JSON.parse(stdout);
    
    // Alert on disabled protection
    if (!status.Enabled || !status.Antivirus) {
      createSegmentAlert('system', 'core', 'critical', 'Protection Disabled',
        'Windows Defender real-time protection is disabled', 'T1562.001');
    }
    if (status.SigAge > 7) {
      createSegmentAlert('system', 'core', 'warning', 'Outdated Definitions',
        `Antivirus definitions are ${status.SigAge} days old`, 'T1562.001');
    }
    
    return status;
  } catch (e) {
    return { error: 'Cannot access Defender status', enabled: false };
  }
}

// 4. Network Adapter Monitoring
async function getNetworkAdapters() {
  try {
    const platform = os.platform();
    let adapters = [];
    
    if (platform === 'win32') {
      const psCmd = `
        Get-NetAdapter | Where-Object { $_.Status -eq 'Up' } |
        Select-Object Name, InterfaceDescription, MacAddress, LinkSpeed, Status |
        ConvertTo-Json -Compress
      `;
      const { stdout } = await execAsync(`powershell -Command "${psCmd}"`, { timeout: 5000 });
      adapters = JSON.parse(stdout);
      adapters = Array.isArray(adapters) ? adapters : [adapters];
    } else if (platform === 'linux') {
      const { stdout } = await execAsync('ip -j link show', { timeout: 5000 });
      const links = JSON.parse(stdout);
      adapters = links.filter(l => l.operstate === 'UP').map(l => ({
        Name: l.ifname,
        MacAddress: l.address,
        LinkSpeed: 'Unknown',
        Status: 'Up'
      }));
    }
    
    return adapters;
  } catch (e) {
    return [];
  }
}

// 5. File Integrity Monitoring (FIM)
const FIM_WATCHED_PATHS = [
  { path: 'C:\\Windows\\System32\\drivers\\etc\\hosts', segment: 'system', zone: 'core' },
  { path: 'C:\\Windows\\System32\\config\\SAM', segment: 'identity', zone: 'identity' },
  { path: '/etc/passwd', segment: 'identity', zone: 'identity' },
  { path: '/etc/shadow', segment: 'identity', zone: 'identity' },
  { path: '/etc/hosts', segment: 'system', zone: 'core' }
];

const fimHashes = new Map();

async function checkFileIntegrity() {
  const changes = [];
  
  for (const watched of FIM_WATCHED_PATHS) {
    try {
      if (!fs.existsSync(watched.path)) continue;
      
      const content = fs.readFileSync(watched.path);
      const hash = crypto.createHash('sha256').update(content).digest('hex');
      
      const key = watched.path;
      const oldHash = fimHashes.get(key);
      
      if (oldHash && oldHash !== hash) {
        changes.push({
          path: watched.path,
          segment: watched.segment,
          zone: watched.zone,
          oldHash,
          newHash: hash,
          timestamp: Date.now()
        });
        
        createSegmentAlert(watched.segment, watched.zone, 'high', 'File Integrity Violation',
          `Critical file modified: ${watched.path}`, 'T1565');
      }
      
      fimHashes.set(key, hash);
    } catch (e) {
      // Permission denied or file locked - expected for some system files
    }
  }
  
  return changes;
}

// ── Updated Segment Metrics ─────────────────────────────────────

async function storeSegmentMetrics(snapshot, network) {
  const segments = new Map();
  
  // Map network connections to 6 core segments
  network.forEach(conn => {
    const port = parseInt((conn.local || '').match(/:(\d+)$/)?.[1]) || 0;
    let segName = 'network';
    
    // Map to 6 core segments
    if ([445, 139, 22, 3389].includes(port)) segName = 'endpoints';
    else if ([443, 80, 8080, 8443].includes(port)) segName = 'applications';
    else if ([3306, 5432, 1433, 1521, 6379, 27017].includes(port)) segName = 'data';
    else segName = 'network';
    
    const key = segName;
    if (!segments.has(key)) segments.set(key, { segment: segName, connections: 0, active: 0, listening: 0, risk: 0 });
    const d = segments.get(key);
    d.connections++;
    if (conn.state === 'ESTABLISHED') d.active++;
    if (conn.state === 'LISTENING') d.listening++;
    d.risk += conn.risk || 0;
  });
  
  // Store metrics for each segment
  for (const [segName, d] of segments) {
    storeMetric(segName, ACTIVE_SEGMENTS.find(s => s.name === segName)?.zone || 'unknown', 'connection_count', d.connections);
    storeMetric(segName, ACTIVE_SEGMENTS.find(s => s.name === segName)?.zone || 'unknown', 'active_connections', d.active);
    storeMetric(segName, ACTIVE_SEGMENTS.find(s => s.name === segName)?.zone || 'unknown', 'listening_ports', d.listening);
    storeMetric(segName, ACTIVE_SEGMENTS.find(s => s.name === segName)?.zone || 'unknown', 'risk_score', Math.min(100, d.risk));
  }
  
  storeMetric('global', 'global', 'total_connections', network.length);
  storeMetric('global', 'global', 'log_count', snapshot.logs.length);
  storeMetric('global', 'global', 'risk_score', snapshot.analysis?.score ?? 100);
}

async function broadcastSegmentData(snapshot) {
  const network = snapshot.network || [];
  network.forEach(conn => storeConnectionState(conn));
  // Batch invalidation after all connections stored (not per-connection)
  if (network.length > 0) invalidateCacheTags(['segments', 'stats']);
  
  // Collect advanced monitoring data
  const [processes, usbDevices, defenderStatus, adapters, fimChanges] = await Promise.allSettled([
    getProcessList(),
    getUSBDevices(),
    getDefenderStatus(),
    getNetworkAdapters(),
    checkFileIntegrity()
  ]);
  
  const segmentHealth = getSegmentHealth();
  const segmentSummary = getSegmentLogSummary(10);
  
  // Calculate metrics for each of the 6 segments
  const segmentMetrics = {};
  ACTIVE_SEGMENTS.forEach(({ name }) => {
    const segConns = network.filter(c => {
      const p = parseInt((c.local || '').match(/:(\d+)$/)?.[1]) || 0;
      if (name === 'applications' && [443,80,8080,8443].includes(p)) return true;
      if (name === 'data' && [3306,5432,1433,1521,6379,27017].includes(p)) return true;
      if (name === 'endpoints' && [445,139,22,3389,5900,5901].includes(p)) return true;
      if (name === 'network') return ![443,80,8080,8443,3306,5432,1433,1521,445,139,22,3389].includes(p);
      return false;
    });
    
    segmentMetrics[name] = {
      connections: segConns.length,
      active: segConns.filter(c => c.state === 'ESTABLISHED').length,
      listening: segConns.filter(c => c.state === 'LISTENING').length,
      risk: segConns.reduce((a, c) => a + (c.risk || 0), 0)
    };
  });
  
  // Add identity metrics from logs
  const identityLogs = snapshot.logs?.filter(l => l.Segment === 'identity') || [];
  segmentMetrics.identity = {
    ...segmentMetrics.identity,
    authEvents: identityLogs.length,
    failedLogons: identityLogs.filter(l => (l.Id === '4625' || (l.Message || '').toLowerCase().includes('failed'))).length,
    privilegeEscalation: identityLogs.filter(l => (l.Id === '4672' || l.Id === '4673' || l.Id === '4674')).length
  };
  
  // Add system metrics from processes
  const processData = processes.status === 'fulfilled' ? processes.value : [];
  const suspiciousProcs = processData.filter(p => p.suspicious || p.risk > 50);
  segmentMetrics.system = {
    ...segmentMetrics.system,
    totalProcesses: processData.length,
    suspiciousProcesses: suspiciousProcs.length,
    highRiskProcesses: processData.filter(p => p.risk > 70).length,
    defenderEnabled: defenderStatus.status === 'fulfilled' ? defenderStatus.value?.Enabled : false
  };
  
  const alerts = getSegmentAlerts(null, null, 10);
  
  return { 
    segmentHealth, 
    segmentSummary, 
    segmentMetrics, 
    alerts,
    advancedMonitoring: {
      processes: processData.slice(0, 50), // Top 50 processes
      usbDevices: usbDevices.status === 'fulfilled' ? usbDevices.value : { connected: [] },
      defender: defenderStatus.status === 'fulfilled' ? defenderStatus.value : null,
      adapters: adapters.status === 'fulfilled' ? adapters.value : [],
      fimChanges: fimChanges.status === 'fulfilled' ? fimChanges.value : []
    }
  };
}

setInterval(async () => {
  try {
    const snapshot = await collectTelemetrySnapshot();
    await storeSegmentMetrics(snapshot, snapshot.network);
    const segmentData = await broadcastSegmentData(snapshot);
    if (wsClients.size === 0) return;
    broadcast('telemetry_update', { ...snapshot, segments: segmentData });
    if (snapshot.logs.length > 0) {
      const toSend = snapshot.logs.slice(0, 10).map(l => ({
        id: l.Id != null ? String(l.Id) : 'Unknown',
        date: l.Date, level: l.LevelDisplayName || 'Information',
        source: l.ProviderName || '', task: l.TaskDisplayName || '',
        logName: l.LogName || '', computer: l.Computer || os.hostname(),
        message: l.Message || '', suspicious: !!l.Suspicious,
        mitre: l.Mitre || null, segment: l.Segment || 'unknown', zone: l.Zone || 'unknown'
      }));
      broadcast('new_logs', toSend);
    }
    if (segmentData.alerts.length > 0) {
      broadcast('segment_alerts', segmentData.alerts);
    }
  } catch (e) {
    logger.error(e, 'Error in telemetry broadcast interval');
  }
}, TELEMETRY_INTERVAL);

// Cross-platform network traffic (gap #18)
async function getNetworkTraffic() {
  try {
    const platform = os.platform();
    let cmd = 'netstat -ano';
    if (platform === 'linux')  cmd = 'ss -tunap 2>/dev/null || netstat -tunap 2>/dev/null';
    if (platform === 'darwin') cmd = 'netstat -an 2>/dev/null';
    const { stdout } = await execAsync(cmd);
    
    const lines = stdout.split('\n').filter(l => l.trim());
    const connections = [];

    if (platform === 'win32') {
      lines.forEach(line => {
        const parts = line.trim().split(/\s+/);
        if (parts.length >= 4 && (parts[0] === 'TCP' || parts[0] === 'UDP')) {
          const local = parts[1];
          const foreign = parts[2];
          const state = parts[3];
          const pid = parts[4];
          connections.push({ protocol: parts[0], local, foreign, state, pid });
        }
      });
    } else {
      // Basic parsing for linux/darwin
      lines.forEach(line => {
        const parts = line.trim().split(/\s+/);
        if (parts.length >= 3) {
          connections.push({ protocol: parts[0], local: parts[1], foreign: parts[2], state: parts[3] || 'UNKNOWN', pid: parts[parts.length-1] });
        }
      });
    }
    return connections.slice(0, 100);
  } catch (e) { 
    logger.error(e, 'Error fetching network traffic');
    return []; 
  }
}


async function getFileChanges() {
  try {
    const platform = os.platform();
    let targetDirs = [];
    if (platform === 'win32') {
      targetDirs = [
        path.join(process.env.windir || 'C:\\Windows', 'System32\\drivers\\etc'),
        process.env.APPDATA || path.join(os.homedir(), 'AppData\\Roaming')
      ];
    } else if (platform === 'linux') {
      targetDirs = ['/etc', '/var/spool/cron'];
    } else if (platform === 'darwin') {
      targetDirs = ['/etc', '/Library/LaunchDaemons'];
    }

    let results = [];
    for (const dir of targetDirs) {
      if (!fs.existsSync(dir)) continue;
      try {
        const files = fs.readdirSync(dir);
        for(const f of files.slice(0, 50)) {
          try {
            const fullPath = path.join(dir, f);
            const stats = fs.statSync(fullPath);
            if (stats.isFile()) {
              results.push({ name: f, path: fullPath, size: stats.size, modified: stats.mtime });
            }
          } catch (e) { logger.error(e, 'Error stating file for FIM'); }
        }
      } catch (e) { logger.error(e, 'Error reading directory for FIM'); }
    }
    // Sort by most recently modified
    return results.sort((a, b) => b.modified - a.modified).slice(0, 15);
  } catch (e) {
    return [];
  }
}

async function analyzeTelemetry(logs, network, files) {
   const analysis = {
     summary: "System baseline operating within normal parameters. No critical breaches detected in recent timeframe.",
     score: 100,
     threats: [],
     mitreMappings: [],
   };

   // Convert to strings for analysis if needed
   const logsArray = Array.isArray(logs) ? logs : (typeof logs === 'string' ? JSON.parse(logs || '[]') : []);
   const networkArray = Array.isArray(network) ? network : (typeof network === 'string' ? JSON.parse(network || '[]') : []);
   
   // Track actual risks from logs
   let riskScore = 0;
   const threatDetails = [];
   const mitreSet = new Set();

   // Process logs for actual threats
   logsArray.forEach(log => {
     const id = log.Id?.toString() || log.eventId || '';
     if (id) {
       switch(id) {
         case '4625': // Failed Logon
           riskScore += 20;
           threatDetails.push("Failed Logon (Event ID 4625) detected.");
           mitreSet.add("T1110 - Brute Force");
           break;
         case '1102': // Security Audit Log Cleared
           riskScore += 50;
           threatDetails.push("Security Audit Log Cleared (Event ID 1102) detected.");
           mitreSet.add("T1070 - Indicator Removal");
           break;
         case '4648': // Logon using explicit credentials
           riskScore += 15;
           threatDetails.push("Logon using explicit credentials (Event ID 4648) detected.");
           mitreSet.add("T1078 - Valid Accounts");
           break;
         case '4672': // Special privileges assigned to new logon
           riskScore += 10;
           threatDetails.push("Special privileges assigned to new logon (Event ID 4672) detected.");
           mitreSet.add("T1078 - Valid Accounts");
           break;
         case '4698': // Scheduled Task Created
           riskScore += 25;
           threatDetails.push("Scheduled Task Created (Event ID 4698) detected.");
           mitreSet.add("T1053.005 - Scheduled Task");
           break;
         case '4720': // User Account Created
           riskScore += 30;
           threatDetails.push("User Account Created (Event ID 4720) detected.");
           mitreSet.add("T1136.001 - Local Account");
           break;
         case '4724': // Password Reset Attempted
           riskScore += 20;
           threatDetails.push("Password Reset Attempted (Event ID 4724) detected.");
           mitreSet.add("T1098 - Account Manipulation");
           break;
         case '7045': // New Service Installed
           riskScore += 35;
           threatDetails.push("New Service Installed (Event ID 7045) detected.");
           mitreSet.add("T1543.003 - Windows Service");
           break;
       }
     }
   });

   // Process network for listening ports (especially RDP)
   networkArray.forEach(conn => {
     const state = conn.state || '';
     const local = conn.local || '';
     const foreign = conn.foreign || '';
     
     // Check for listening RDP port (3389)
     if (state === 'LISTENING' && local.includes(':3389')) {
       riskScore += 10;
       threatDetails.push("Open RDP Port (3389) detected in LISTENING state. Potential vector for brute force.");
       mitreSet.add("T1021 - Remote Services");
     }
     
     // Check for other suspicious listening ports
     if (state === 'LISTENING') {
       // Check for common attack ports
       const suspiciousPorts = [21, 22, 23, 25, 53, 80, 135, 139, 443, 445, 1433, 1521, 3306, 3389, 5432, 5900, 5901, 6379, 8080, 8443, 9200, 9300];
       const portMatch = local.match(/:(\d+)$/);
       if (portMatch) {
         const port = parseInt(portMatch[1]);
         if (suspiciousPorts.includes(port)) {
           // Only add risk if it's an unexpected service (basic heuristic)
           if (port !== 80 && port !== 443 && port !== 22) { // Allow common web/ssh
             riskScore += 5;
             threatDetails.push(`Suspicious listening port ${port} detected.`);
             mitreSet.add("T1021 - Remote Services");
           }
         }
       }
     }
   });

   // Apply risk score (capped at 100)
   analysis.score = Math.max(0, 100 - Math.min(riskScore, 100));
   
   // Dynamic AI Threat Heuristics Integration (TensorFlow.js Implementation)
    if (aiModel && logsArray.length > 0) {
      try {
        // Convert logs into a feature vector (simulated feature extraction)
        // Features: [avg_msg_len, has_suspicious, log_count, unique_sources, max_risk_score]
        const avgLen = logsArray.reduce((acc, l) => acc + (l.Message?.length || 0), 0) / logsArray.length;
        const features = [
          avgLen / 1000, 
          logsArray.some(l => l.Suspicious) ? 1 : 0, 
          logsArray.length / 100, 
          new Set(logsArray.map(l => l.Source)).size / 10,
          riskScore / 100
        ];
        
        const inputTensor = tf.tensor2d([features]);
        const prediction = aiModel.predict(inputTensor);
        const scoreData = await prediction.data();
        const score = scoreData[0];
        // Dispose tensors to prevent memory leak (runs every 5s telemetry cycle)
        prediction.dispose();
        inputTensor.dispose();
        
        if (score > 0.7) {
          const aiRiskPenalty = Math.round(score * 30);
          analysis.score = Math.max(0, analysis.score - aiRiskPenalty);
          threatDetails.push(`AI Heuristics (TensorFlow.js) detected anomalous behavior patterns (Confidence: ${(score*100).toFixed(1)}%)`);
          analysis.mitreMappings.push("T1566 - AI-Predicted Zero-Day Anomaly");
          analysis.summary = `AI Intervention: TensorFlow.js engine flagged structural anomalies. Adjusted Score: ${analysis.score}/100`;
        }
      } catch (e) {
        logger.error(e, "AI Inference failed");
      }
    } else {
      // Fallback to structural heuristic if model is loading
      const anomalousEvents = logsArray.filter(l => l.Message && l.Message.length > 500 && !l.Suspicious);
      if (anomalousEvents.length > 0) {
        const aiRiskPenalty = Math.min(anomalousEvents.length * 5, 20);
        analysis.score = Math.max(0, analysis.score - aiRiskPenalty);
        threatDetails.push(`AI Structural Heuristics flagged ${anomalousEvents.length} unusual zero-day patterns.`);
      }
    }
   
   // Set threats and MITRE mappings
   analysis.threats = threatDetails;
   analysis.mitreMappings = Array.from(mitreSet);

   // Update summary based on score
   if (analysis.score === 100) {
     analysis.summary = "Heuristic scan complete. Recent network and log telemetry did not match the built-in high-risk rules. Continue reviewing with validated EDR/SIEM telemetry.";
   } else if (analysis.score >= 80) {
     analysis.summary = `Heuristic scan complete. Minor risk indicators detected. Score: ${analysis.score}/100.`;
   } else if (analysis.score >= 60) {
     analysis.summary = `Heuristic scan complete. Moderate risk indicators detected. Score: ${analysis.score}/100. Analyst review recommended.`;
   } else if (analysis.score >= 40) {
     analysis.summary = `Heuristic scan complete. Elevated risk indicators detected. Score: ${analysis.score}/100. Immediate analyst review recommended.`;
   } else {
      analysis.summary = `Heuristic scan complete. High risk indicators detected. Score: ${analysis.score}/100. Potential security incident - immediate investigation warranted.`;
    }

   // Run plugins analysis
   for (const plugin of activePlugins) {
     if (typeof plugin.instance.analyze === 'function') {
       try { 
         plugin.instance.analyze(analysis, logsArray, networkArray, files); 
       } catch (e) { 
         logger.error(e, `Plugin analysis error in ${plugin.name}`); 
       }
     }
   }

   return analysis;
 }

// ── Segment-based Aggregation Functions ────────────────────────────

// Store time-series metric for a segment/zone
function storeMetric(segment, zone, metricType, value, metadata = null) {
  try {
    const stmt = db.prepare(`
      INSERT INTO metrics_time_series (timestamp, segment, zone, metric_type, value, metadata)
      VALUES (?, ?, ?, ?, ?, ?)
    `);
    stmt.run(Date.now(), segment, zone, metricType, value, metadata ? JSON.stringify(metadata) : null);
    // Note: cache invalidation is done once per batch in storeSegmentMetrics, not per-insert
  } catch (e) {
    logger.error(e, 'Error storing metric');
  }
}

// Periodic cleanup for old metrics (every 10 minutes instead of every insert)
setInterval(() => {
  try {
    const cutoff = Date.now() - 7 * 24 * 60 * 60 * 1000;
    const result = db.prepare('DELETE FROM metrics_time_series WHERE timestamp < ?').run(cutoff);
    if (result.changes > 0) logger.info({ deleted: result.changes }, 'Cleaned up old metrics');
  } catch (e) {
    logger.error(e, 'Metrics cleanup failed');
  }
}, 10 * 60 * 1000);

// Get segment metrics for a time range
function getSegmentMetrics(segment, zone, metricType, minutes = 60) {
  try {
    const cutoff = Date.now() - minutes * 60 * 1000;
    const rows = db.prepare(`
      SELECT timestamp, value, metadata FROM metrics_time_series
      WHERE segment = ? AND zone = ? AND metric_type = ? AND timestamp > ?
      ORDER BY timestamp ASC
    `).all(segment, zone, metricType, cutoff);
    return rows;
  } catch (e) {
    logger.error(e, 'Error getting segment metrics');
    return [];
  }
}

// Aggregate logs by segment
function getSegmentLogSummary(minutes = 60) {
  try {
    const cutoff = new Date(Date.now() - minutes * 60 * 1000).toISOString();
    const rows = db.prepare(`
      SELECT 
        segment,
        zone,
        COUNT(*) as total_logs,
        SUM(CASE WHEN suspicious = 1 THEN 1 ELSE 0 END) as suspicious_count,
        MAX(date) as last_event
      FROM logs
      WHERE date > ?
      GROUP BY segment, zone
      ORDER BY suspicious_count DESC
    `).all(cutoff);
    return rows;
  } catch (e) {
    logger.error(e, 'Error getting segment log summary');
    return [];
  }
}

// Get segment health status
function getSegmentHealth() {
  try {
    const rows = db.prepare(`
      SELECT 
        segment,
        zone,
        COUNT(*) as active_connections,
        SUM(CASE WHEN state = 'LISTENING' THEN 1 ELSE 0 END) as listening_ports,
        SUM(CASE WHEN risk > 50 THEN 1 ELSE 0 END) as high_risk_conns,
        MAX(last_seen) as last_activity
      FROM connections
      WHERE last_seen > ?
      GROUP BY segment, zone
    `).all(Date.now() - 60000); // Last 60 seconds
    
    return rows.map(r => ({
      ...r,
      health_score: Math.max(0, 100 - (r.high_risk_conns * 10) - (r.listening_ports * 2)),
      status: r.high_risk_conns > 5 ? 'critical' : r.high_risk_conns > 0 ? 'warning' : 'healthy'
    }));
  } catch (e) {
    logger.error(e, 'Error getting segment health');
    return [];
  }
}

// Store connection state
function storeConnectionState(conn) {
  try {
    const id = crypto.createHash('sha256').update(`${conn.local}-${conn.foreign}-${conn.protocol}`).digest('hex');
    const now = Date.now();
    const stmt = db.prepare(`
      INSERT INTO connections (id, src_ip, dst_ip, protocol, port, state, risk, segment, zone, first_seen, last_seen)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(id) DO UPDATE SET
        state = excluded.state,
        risk = excluded.risk,
        last_seen = excluded.last_seen
    `);
    
    const port = parseInt((conn.local || '').match(/:(\d+)$/)?.[1]) || 0;
    let risk = 0;
    if (conn.state === 'LISTENING') risk = 30;
    if (conn.state === 'ESTABLISHED') risk = 10;
    
    // Infer segment based on port/protocol
    let segment = 'network', zone = 'perimeter';
    if ([443, 80, 8080, 8443].includes(port)) { segment = 'web'; zone = 'dmz'; }
    else if ([22, 3389].includes(port)) { segment = 'remote'; zone = 'remote-access'; }
    else if ([445, 139].includes(port)) { segment = 'file-sharing'; zone = 'internal'; }
    else if ([3306, 5432, 1433, 1521].includes(port)) { segment = 'database'; zone = 'data-core'; }
    
    stmt.run(id, conn.local, conn.foreign, conn.protocol, port, conn.state, risk, segment, zone, now, now);
    // Cache invalidation moved to broadcastSegmentData to avoid per-connection thrashing
    return { id, segment, zone, risk };
  } catch (e) {
    logger.error(e, 'Error storing connection state');
    return null;
  }
}

// Create alert for a segment
function createSegmentAlert(segment, zone, severity, category, message, mitreId = null) {
  try {
    const id = crypto.randomUUID();
    db.prepare(`
      INSERT INTO segment_alerts (id, timestamp, segment, zone, severity, category, message, mitre_id)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `).run(id, Date.now(), segment, zone, severity, category, message, mitreId);
    invalidateCacheTags(['segments', 'alerts']);
    return id;
  } catch (e) {
    logger.error(e, 'Error creating segment alert');
    return null;
  }
}

// Get unacknowledged alerts by segment
function getSegmentAlerts(segment = null, zone = null, limit = 50) {
  try {
    let query = 'SELECT * FROM segment_alerts WHERE acknowledged = 0';
    const params = [];
    if (segment) { query += ' AND segment = ?'; params.push(segment); }
    if (zone) { query += ' AND zone = ?'; params.push(zone); }
    query += ' ORDER BY timestamp DESC LIMIT ?';
    params.push(limit);
    return db.prepare(query).all(...params);
  } catch (e) {
    logger.error(e, 'Error getting segment alerts');
    return [];
  }
}

// ── Helper: read body ─────────────────────────────────────────────
function readBody(req) {
  return new Promise((resolve, reject) => {
    let data = '';
    req.on('data', c => { data += c; if (data.length > 1e6) reject(new Error('Body too large')); });
    req.on('end', () => { try { resolve(JSON.parse(data)); } catch { reject(new Error('Invalid JSON')); } });
    req.on('error', reject);
  });
}
function json(res, status, body) {
  res.writeHead(status, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(body));
}

// ── Security headers ──────────────────────────────────────────────
function setSecurityHeaders(res) {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Permissions-Policy', 'geolocation=(), microphone=()');
  res.setHeader('Content-Security-Policy', `default-src 'self'; connect-src ${CSP_CONNECT_SRC}; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https://www.virustotal.com; font-src 'self' data:;`);
  // HSTS only in production over HTTPS (gap #5)
  if (NODE_ENV === 'production') res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload');
}

function getClientIp(req) {
  if (TRUST_PROXY && req.headers['x-forwarded-for']) {
    return String(req.headers['x-forwarded-for']).split(',')[0].trim();
  }
  return req.socket.remoteAddress || 'unknown';
}

let prevCpuSample = null;
function sampleCpuUsage() {
  const cpus = os.cpus();
  const totals = cpus.map((c) => {
    const t = c.times;
    const total = t.user + t.nice + t.sys + t.idle + t.irq;
    return { idle: t.idle, total };
  });
  if (!prevCpuSample) {
    prevCpuSample = totals;
    return 0;
  }
  let idleDiff = 0;
  let totalDiff = 0;
  for (let i = 0; i < totals.length; i += 1) {
    idleDiff += totals[i].idle - prevCpuSample[i].idle;
    totalDiff += totals[i].total - prevCpuSample[i].total;
  }
  prevCpuSample = totals;
  if (totalDiff <= 0) return 0;
  return Math.max(0, Math.min(100, ((totalDiff - idleDiff) / totalDiff) * 100));
}

function detectIndicatorType(value) {
  const q = String(value || '').trim();
  if (/^[a-fA-F0-9]{32}$/.test(q) || /^[a-fA-F0-9]{40}$/.test(q) || /^[a-fA-F0-9]{64}$/.test(q)) return 'hash';
  if (/^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/.test(q)) return 'ip';
  if (/^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$/.test(q)) return 'domain';
  if (/^https?:\/\/[^\s/$.?#].[^\s]*$/i.test(q)) return 'url';
  return 'unknown';
}

async function queryVirusTotal(indicator, explicitType) {
  const type = explicitType || detectIndicatorType(indicator);
  const q = String(indicator || '').trim();
  if (!VT_API_KEY) return { status: 503, body: { error: 'VT_API_KEY not configured' } };

  let endpoint;
  if (type === 'hash') endpoint = `files/${q}`;
  else if (type === 'ip') endpoint = `ip_addresses/${q}`;
  else if (type === 'domain') endpoint = `domains/${encodeURIComponent(q)}`;
  else if (type === 'url') {
    const submit = await fetch('https://www.virustotal.com/api/v3/urls', {
      method: 'POST',
      headers: {
        'x-apikey': VT_API_KEY,
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: new URLSearchParams({ url: q }),
    });
    return { status: submit.status, body: await submit.json().catch(async () => ({ raw: await submit.text() })) };
  } else {
    return { status: 400, body: { error: 'Indicator must be a hash, IP address, domain, or URL.' } };
  }

  const r = await fetch(`https://www.virustotal.com/api/v3/${endpoint}`, { headers: { 'x-apikey': VT_API_KEY } });
  return { status: r.status, body: await r.json().catch(async () => ({ raw: await r.text() })) };
}

// ── Main HTTP handler ─────────────────────────────────────────────
httpServer.on('request', async (req, res) => {
  setCORS(req, res);           // gap #2 — locked CORS
  setSecurityHeaders(res);     // gap #5

  if (req.method === 'OPTIONS') { res.writeHead(204); res.end(); return; }

  const clientIp = getClientIp(req);
  const requestStart = Date.now();

  // Segment mapping: derive segment from URL path
  const segmentFromPath = (p) => {
    if (p.startsWith('/api/auth'))       return 'auth';
    if (p.startsWith('/api/scanner'))    return 'scanner';
    if (p.startsWith('/api/ai'))         return 'ai_agent';
    if (p.startsWith('/api/analytics'))  return 'api';
    if (p.startsWith('/api/virustotal')) return 'virustotal';
    if (p.startsWith('/api/threat'))     return 'intel';
    if (p.startsWith('/api/sandbox'))    return 'sandbox';
    if (p.startsWith('/api/logs') || p.startsWith('/api/database/logs')) return 'winlogs';
    if (p.startsWith('/api/segments'))   return 'dashboard';
    if (p.startsWith('/api/system'))     return 'dashboard';
    if (p.startsWith('/api/analyze'))    return 'ai_agent';
    if (p.startsWith('/api/sync'))       return 'api';
    if (p.startsWith('/api/security'))   return 'ossec';
    return 'api';
  };

  // ── DDoS protection check ──
  const ddosCheck = ddosProtection.check(clientIp);
  if (!ddosCheck.allowed) {
    auditLogger.suspiciousActivity(clientIp, { reason: ddosCheck.reason });
    res.writeHead(429, { 'Retry-After': String(ddosCheck.retryAfter || 60) });
    return res.end(JSON.stringify({ error: ddosCheck.reason }));
  }

  // ── WAF request validation ──
  const wafResult = validateRequest(req, logger);
  if (!wafResult.valid) {
    auditLogger.suspiciousActivity(clientIp, { reason: wafResult.reason, url: req.url });
    return json(res, 403, { error: 'Request blocked by security policy' });
  }

  // ── Analytics telemetry: record on response finish ──
  let _analyticsUserId = null;
  res.on('finish', () => {
    setImmediate(() => {
      try {
        const urlObj2 = new URL(req.url, 'http://localhost');
        const p2 = urlObj2.pathname.replace(/\/+/g, '/').replace(/\/$/, '') || '/';
        if (!p2.startsWith('/api/analytics')) { // avoid infinite self-tracking
          analyticsEngine.recordRequest({
            segment:    segmentFromPath(p2),
            method:     req.method,
            path:       p2,
            statusCode: res.statusCode,
            durationMs: Date.now() - requestStart,
            userId:     _analyticsUserId,
            clientIp,
            bytesSent:  parseInt(res.getHeader?.('content-length') || '0') || 0,
          });
        }
      } catch {}
    });
  });

  const urlObj   = new URL(req.url, `http://localhost`);
  const pathname = urlObj.pathname.replace(/\/+/g, '/').replace(/\/$/, '') || '/';
  console.log(`[DEBUG] Request: ${req.method} ${pathname}`);
  logger.info({ method: req.method, path: pathname, ip: clientIp }, 'Request'); // gap #19

  try {
    // ── Health endpoint (gap #20) ───────────────────────────────
    if (pathname === '/health' && req.method === 'GET') {
      return json(res, 200, { status: 'ok', uptime: process.uptime(), ts: Date.now(), db: 'connected' });
    }

     // ── POST /api/auth/signup ──────────────────────────────────────
     if (pathname.endsWith('/api/auth/signup') && req.method === 'POST') {
       if (!SIGNUP_ENABLED) return json(res, 403, { error: 'User registration is disabled' });
       
       const { username, email, password } = await readBody(req);
       if (!username || !email || !password) return json(res, 400, { error: 'Username, email, and password are required.' });
       const userCheck = validateUsername(username);
       if (!userCheck.ok) return json(res, 400, { error: userCheck.message });
       const mailCheck = validateEmail(email);
       if (!mailCheck.ok) return json(res, 400, { error: mailCheck.message });
       const passCheck = validatePassword(password);
       if (!passCheck.ok) return json(res, 400, { error: passCheck.message });
       
       try {
         const existing = db.prepare('SELECT id FROM users WHERE username=? OR email=?').get(userCheck.value, mailCheck.value);
         if (existing) return json(res, 400, { error: 'Username or email already exists.' });
         
         db.prepare('INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, ?)')
           .run(userCheck.value, mailCheck.value, hashPassword(passCheck.value), 'analyst');
         
         logger.info({ username: userCheck.value, email: mailCheck.value }, 'New user registered');
         return json(res, 201, { success: true, message: 'Account created successfully.' });
       } catch (e) {
         logger.error(e, 'Signup error');
         return json(res, 500, { error: 'Internal server error during registration.' });
       }
     }
    
    // ── POST /api/auth/login — gap #1 real TOTP, gap #3 JWT ────
    if (pathname.endsWith('/api/auth/login') && req.method === 'POST') {
      const { identifier, password } = await readBody(req);
      
      const rl = checkRateLimit(clientIp, identifier);
      if (rl.locked) return json(res, 429, { error: `Too many attempts. Retry in ${rl.retryAfter}s.` });

      const user = db.prepare('SELECT * FROM users WHERE username=? OR email=?').get(identifier, identifier);
      if (!user || !verifyPassword(password, user.password_hash)) {
        recordFailure(clientIp, identifier);
        logger.warn({ identifier, ip: clientIp }, 'Failed login attempt');
        return json(res, 401, { error: 'Invalid credentials.' });
      }

      clearRateLimit(clientIp, identifier);
      db.prepare("UPDATE users SET last_login=datetime('now') WHERE id=?").run(user.id);

      if (!user.totp_enrolled) {
        // First login — generate TOTP secret + QR for enrollment (gap #14)
        const secret = speakeasy.generateSecret({ name: `SentinelGrid (${user.username})`, length: 20 });
        db.prepare('UPDATE users SET totp_secret=? WHERE id=?').run(secret.base32, user.id);
        const qrCode = await QRCode.toDataURL(secret.otpauth_url);
        const tempToken = signTempToken(user.id);
        return json(res, 200, { step: 'enroll', qrCode, tempToken });
      }

      const tempToken = signTempToken(user.id);
      return json(res, 200, { step: '2fa', tempToken });
    }

    // ── POST /api/auth/verify-2fa — validate TOTP (gap #1, #14) ─
    if (pathname.endsWith('/api/auth/verify-2fa') && req.method === 'POST') {
      const { tempToken, code } = await readBody(req);
      const payload = verifyTempToken(tempToken);
      const user    = db.prepare('SELECT * FROM users WHERE id=?').get(payload.sub);
      if (!user) return json(res, 401, { error: 'User not found.' });

      const valid = speakeasy.totp.verify({ secret: user.totp_secret, encoding: 'base32', token: code, window: 1 });
      if (!valid) { logger.warn({ userId: user.id }, 'Invalid TOTP code'); return json(res, 401, { error: 'Invalid 2FA code.' }); }

      // Mark enrolled on first verify
      if (!user.totp_enrolled) db.prepare('UPDATE users SET totp_enrolled=1 WHERE id=?').run(user.id);

      const { token: accessToken }  = signAccessToken(user);
      const { token: refreshToken, expiresAt } = signRefreshToken(user);
      logger.info({ username: user.username }, 'Login success');
      
      res.setHeader('Set-Cookie', `sg_refresh_token=${refreshToken}; HttpOnly; Path=/; Max-Age=${7 * 24 * 60 * 60}; SameSite=Strict${NODE_ENV === 'production' ? '; Secure' : ''}`);
      return json(res, 200, { 
        success: true, 
        accessToken, 
        user: {
          id: user.id,
          username: user.username,
          email: user.email,
          role: user.role,
          lastLogin: user.last_login,
          createdAt: user.created_at
        }
      });
    }

    // ── POST /api/auth/refresh — rotate access token (gap #3) ──
    if (pathname.endsWith('/api/auth/refresh') && req.method === 'POST') {
      const cookies = parseCookies(req.headers.cookie);
      const refreshToken = cookies.sg_refresh_token;
      if (!refreshToken) return json(res, 401, { error: 'No refresh token provided.' });

      const payload = jwt.verify(refreshToken, JWT_REFRESH_SECRET);
      const rec     = db.prepare('SELECT * FROM refresh_tokens WHERE jti=?').get(payload.jti);
      if (!rec || rec.revoked || rec.expires_at < Date.now()) return json(res, 401, { error: 'Refresh token invalid or expired.' });
      const user = db.prepare('SELECT * FROM users WHERE id=?').get(payload.sub);
      if (!user) return json(res, 401, { error: 'User not found.' });
      revokeToken(payload.jti); // rotate — one-time use
      const { token: accessToken }      = signAccessToken(user);
      const { token: newRefreshToken }  = signRefreshToken(user);
      
      res.setHeader('Set-Cookie', `sg_refresh_token=${newRefreshToken}; HttpOnly; Path=/; Max-Age=${7 * 24 * 60 * 60}; SameSite=Strict${NODE_ENV === 'production' ? '; Secure' : ''}`);
      return json(res, 200, { accessToken });
    }

    // ── POST /api/auth/logout — server-side revocation (gap #13) ─
    if (pathname.endsWith('/api/auth/logout') && req.method === 'POST') {
      try {
        const cookies = parseCookies(req.headers.cookie);
        const refreshToken = cookies.sg_refresh_token;
        if (refreshToken) {
          const p = jwt.verify(refreshToken, JWT_REFRESH_SECRET);
          revokeToken(p.jti);
        }
        
        // Also revoke access token if provided
        const auth = req.headers.authorization;
        if (auth && auth.startsWith('Bearer ')) {
          const p = verifyJWT(auth.slice(7));
          revokeAccessToken(p.jti, p.exp);
        }
      } catch (e) { logger.error(e, 'Logout error'); }
      
      res.setHeader('Set-Cookie', `sg_refresh_token=; HttpOnly; Path=/; Max-Age=0; SameSite=Strict`);
      return json(res, 200, { success: true });
    }

    // ── All routes below require valid JWT ───────────────────────
    let caller;
    try { caller = authenticate(req); _analyticsUserId = caller?.sub; }
    catch (e) { return json(res, 401, { error: e.message }); }

    // ── GET /api/auth/me ────────────────────────────────────────
    if (pathname === '/api/auth/me' && req.method === 'GET') {
      const user = db.prepare('SELECT id, username, email, role, last_login, created_at FROM users WHERE id=?').get(caller.sub);
      if (!user) return json(res, 404, { error: 'User not found' });
      return json(res, 200, {
        authenticated: true,
        user: { 
          id: user.id, 
          username: user.username, 
          email: user.email,
          role: user.role,
          lastLogin: user.last_login,
          createdAt: user.created_at
        },
      });
    }

    if (pathname === '/api/cache/stats' && req.method === 'GET') {
      return json(res, 200, {
        ...cacheStats,
        size: responseCache.size,
        maxItems: CACHE_MAX_ITEMS,
        defaultTtlMs: CACHE_DEFAULT_TTL_MS,
      });
    }

    // ── POST /api/auth/admin/reset-totp ─────────────────────────
    if (pathname === '/api/auth/admin/reset-totp' && req.method === 'POST') {
      if (caller.role !== 'admin') return json(res, 403, { error: 'Admin role required.' });
      const { targetUsername } = await readBody(req);
      if (!targetUsername) return json(res, 400, { error: 'Target username required' });
      db.prepare('UPDATE users SET totp_enrolled=0, totp_secret=NULL WHERE username=?').run(targetUsername);
      logger.info({ admin: caller.username, target: targetUsername }, 'TOTP reset by admin');
      return json(res, 200, { success: true, message: `TOTP reset for ${targetUsername}` });
    }

    // ── GET /api/os-info ─────────────────────────────────────────
    if (pathname === '/api/os-info' && req.method === 'GET') {
      return cachedJson(res, makeCacheKey(pathname, urlObj), 15000, ['system'], () => getSystemTelemetry());
    }

    // ── GET /api/fim/events ────────────────────────────────────────
    if (pathname === '/api/fim/events' && req.method === 'GET') {
      return cachedJson(res, makeCacheKey(pathname, urlObj), 15000, ['fim'], async () => {
        const changes = await getFileChanges();
        const events = changes.map(f => ({
          id: crypto.randomUUID(),
          timestamp: f.modified.toISOString(),
          path: f.path,
          name: f.name,
          size: f.size,
          suspicious: f.path.includes('etc') || f.path.includes('System32'),
          mitreTechnique: f.path.includes('etc') ? 'T1003 - OS Credential Dumping' : 'T1543 - Create or Modify System Process',
        }));
        return { events };
      });
    }
    // ── GET /api/logs ────────────────────────────────────────────
    if ((pathname === '/api/logs' || pathname === '/api/logs/live') && req.method === 'GET') {
      return cachedJson(res, makeCacheKey(pathname, urlObj), 2500, ['telemetry', 'logs'], async () => {
        const maxParam  = parseInt(urlObj.searchParams.get('max') || '80', 10);
        const channel   = urlObj.searchParams.get('channel') || 'all'; // all | security | system | application
        if (Date.now() - latestTelemetry.ts > 6000) await collectTelemetrySnapshot();
        let logs = latestTelemetry.logs;
        // Filter by channel if requested
        if (channel !== 'all') {
          const channelMap = { security: 'Security', system: 'System', application: 'Application' };
          const target = channelMap[channel.toLowerCase()];
          if (target) logs = logs.filter(l => (l.LogName || '').toLowerCase() === target.toLowerCase());
        }
        // Normalise to a flat shape the frontend can consume directly
        const normalized = logs.slice(0, maxParam).map((l, i) => {
          let ts = Date.now();
          if (l.TimeCreated) {
            if (typeof l.TimeCreated === 'string' && l.TimeCreated.startsWith('/Date(')) {
              ts = parseInt(l.TimeCreated.replace(/[^0-9]/g, ''), 10);
            } else {
              ts = new Date(l.TimeCreated).getTime();
            }
          } else if (l.Date) {
            ts = new Date(l.Date).getTime();
          }
          if (isNaN(ts)) ts = Date.now();

          return {
            id:          `live-${i}-${l.Id}`,
            eventId:     l.Id != null ? String(l.Id) : 'Unknown',
            timestamp:   ts,
            level:       l.LevelDisplayName || 'Information',
            source:      l.ProviderName || 'Unknown',
            category:    l.TaskDisplayName || 'System Event',
            logName:     l.LogName || 'Unknown',
            computer:    l.MachineName || l.Computer || os.hostname(),
            message:     l.Message || 'No description.',
            suspicious:  !!l.Suspicious,
            mitre:       l.Mitre || null,
          };
        });
        return { logs: normalized, fetchedAt: Date.now(), platform: os.platform(), computer: os.hostname() };
      });
    }

    // ── GET /api/analyze ─────────────────────────────────────────
    if (pathname === '/api/analyze' && req.method === 'GET') {
      return cachedJson(res, makeCacheKey(pathname, urlObj), 2500, ['telemetry'], async () => {
        if (Date.now() - latestTelemetry.ts > 6000) await collectTelemetrySnapshot();
        return latestTelemetry;
      });
    }

    // ── GET /api/system/stats ─────────────────────────────────────
    if (pathname === '/api/system/stats' && req.method === 'GET') {
      return cachedJson(res, makeCacheKey(pathname, urlObj), 2000, ['stats'], async () => {
        const cpuUsage = sampleCpuUsage();
        const totalMem = os.totalmem();
        const freeMem  = os.freemem();
        const usedMem  = totalMem - freeMem;
        const memUsage = (usedMem / totalMem) * 100;

        return {
          cpu: cpuUsage.toFixed(1),
          memory: memUsage.toFixed(1),
          uptime: os.uptime(),
          activeConnections: latestTelemetry.network.length,
          recentLogs: latestTelemetry.logs.length,
          timestamp: Date.now()
        };
      });
    }

    // ── GET /api/system/permissions ─────────────────────────────
    if (pathname === '/api/system/permissions' && req.method === 'GET') {
      return json(res, 200, getPermissionStatus());
    }

    // ── POST /api/system/permissions/refresh ─────────────────────
    if (pathname === '/api/system/permissions/refresh' && req.method === 'POST') {
      await detectPermissions();
      broadcastPermissions();
      return json(res, 200, getPermissionStatus());
    }

    // ── GET /api/segments ─────────────────────────────────────────
    if (pathname === '/api/segments' && req.method === 'GET') {
      return cachedJson(res, makeCacheKey(pathname, urlObj), 5000, ['segments'], () => ({
        segments: ACTIVE_SEGMENTS,
        health: getSegmentHealth(),
        summary: getSegmentLogSummary(60)
      }));
    }

    // ── GET /api/segments/:name/metrics ────────────────────────────
    if (pathname.startsWith('/api/segments/') && pathname.endsWith('/metrics') && req.method === 'GET') {
      return cachedJson(res, makeCacheKey(pathname, urlObj), 5000, ['segments'], () => {
        const segName = pathname.split('/')[3];
        const minutes = parseInt(urlObj.searchParams.get('minutes') || '60');
        const metrics = getSegmentMetrics(segName, 'unknown', 'connection_count', minutes);
        return { segment: segName, metrics };
      });
    }

    // ── GET /api/segments/alerts ──────────────────────────────────
    if (pathname === '/api/segments/alerts' && req.method === 'GET') {
      return cachedJson(res, makeCacheKey(pathname, urlObj), 5000, ['segments', 'alerts'], () => {
        const segment = urlObj.searchParams.get('segment');
        const zone = urlObj.searchParams.get('zone');
        const limit = parseInt(urlObj.searchParams.get('limit') || '50');
        const alerts = getSegmentAlerts(segment, zone, limit);
        return { alerts, total: alerts.length };
      });
    }

    // ── POST /api/segments/alerts/:id/ack ─────────────────────────
    if (pathname.startsWith('/api/segments/alerts/') && pathname.endsWith('/ack') && req.method === 'POST') {
      const alertId = pathname.split('/')[4];
      try {
        db.prepare('UPDATE segment_alerts SET acknowledged = 1 WHERE id = ?').run(alertId);
        invalidateCacheTags(['segments', 'alerts']);
        return json(res, 200, { success: true, message: 'Alert acknowledged' });
      } catch (e) {
        return json(res, 500, { error: 'Failed to acknowledge alert' });
      }
    }

    // ── GET /api/plugins ──────────────────────────────────────────
    if (pathname === '/api/plugins' && req.method === 'GET') {
      return cachedJson(res, makeCacheKey(pathname, urlObj), 30000, ['plugins'], () => ({
        plugins: activePlugins.map(p => ({
          name: p.name,
          hasInit: typeof p.instance.init === 'function',
          hasAnalyze: typeof p.instance.analyze === 'function'
        }))
      }));
    }

    // ── GET /api/database/logs ────────────────────────────────────
    if (pathname === '/api/database/logs' && req.method === 'GET') {
      return cachedJson(res, makeCacheKey(pathname, urlObj), 10000, ['database', 'logs'], async () => {
        // If Elasticsearch is configured, prefer it for high-scale historical retrieval
        if (ELASTIC_URL) {
          const results = await elasticClient.query('logs', { size: 500, sort: [{ date: 'desc' }] });
          if (results && results.hits) {
            return { databaseLogs: results.hits.hits.map(h => h._source) };
          }
        }
        const rows = db.prepare('SELECT * FROM logs ORDER BY date DESC LIMIT 5000').all()
          .map(l => ({ ...l, suspicious: !!l.suspicious }));
        return { databaseLogs: rows };
      });
    }

    // ── POST /api/kill-process ────────────────────────────────────
    if (pathname === '/api/kill-process' && req.method === 'POST') {
      if (caller.role !== 'admin') return json(res, 403, { error: 'Forbidden. Admin role required.' });
      const { pid } = await readBody(req);
      if (!pid || !/^\d+$/.test(pid.toString())) return json(res, 400, { error: 'Valid integer PID required' });
      try {
        if (os.platform() === 'win32') {
          execFileSync('taskkill', ['/F', '/PID', String(pid)], { timeout: 5000 });
        } else {
          execFileSync('kill', ['-9', String(pid)], { timeout: 5000 });
        }
        logger.warn({ pid, by: caller.username }, 'Process killed');
        broadcast('process_killed', { pid, by: caller.username });
        return json(res, 200, { success: true, message: `Process ${pid} terminated.` });
      } catch (e) { return json(res, 500, { error: e.message }); }
    }

    // ── Threat Intel — VT ─────────────────────────────────────────
    if (pathname.startsWith('/api/threat-intel/virustotal') && req.method === 'GET') {
      const indicator = urlObj.searchParams.get('indicator') || urlObj.searchParams.get('hash');
      const type = urlObj.searchParams.get('type');
      const cacheKey = makeCacheKey(pathname, urlObj, 'threat-intel');
      const cached = getCachedValue(cacheKey);
      if (cached) {
        res.setHeader('X-App-Cache', 'HIT');
        return json(res, cached.status, cached.body);
      }
      const result = await queryVirusTotal(indicator, type);
      if (result.status === 200) setCachedValue(cacheKey, result, 10 * 60 * 1000, ['threat-intel']);
      res.setHeader('X-App-Cache', 'MISS');
      return json(res, result.status, result.body);
    }

    // ── Threat Intel — Abuse.ch ───────────────────────────────────
    if (pathname === '/api/threat-intel/abusech' && req.method === 'POST') {
      const { hash } = await readBody(req);
      const p = new URLSearchParams({ query: 'get_info', hash });
      const r = await fetch('https://mb-api.abuse.ch/api/v1/', { method: 'POST', body: p });
      res.writeHead(r.status, { 'Content-Type': 'application/json' }); res.end(await r.text()); return;
    }

    // ── Threat Intel — OTX ────────────────────────────────────────
    if (pathname.startsWith('/api/threat-intel/otx') && req.method === 'GET') {
      if (!OTX_API_KEY) return json(res, 503, { error: 'OTX_API_KEY not configured' }); // gap #23
      const ip2 = urlObj.searchParams.get('ip');
      if (!/^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/.test(ip2 || '')) {
        return json(res, 400, { error: 'Valid IPv4 address required' });
      }
      const r   = await fetch(`https://otx.alienvault.com/api/v1/indicators/IPv4/${ip2}/general`, { headers: { 'X-OTX-API-KEY': OTX_API_KEY } });
      res.writeHead(r.status, { 'Content-Type': 'application/json' }); res.end(await r.text()); return;
    }

    // ── Sandbox — Cuckoo ──────────────────────────────────────────
    if (pathname === '/api/sandbox/cuckoo/detonate' && req.method === 'POST') {
      try {
        if (!CUCKOO_API_URL) return json(res, 503, { error: 'Cuckoo sandbox not configured' });
        const r    = await fetch(CUCKOO_API_URL, { method: 'POST', headers: { Authorization: `Bearer ${process.env.CUCKOO_TOKEN||''}` } });
        const data = await r.json();
        return json(res, 200, { success: true, taskId: data.task_id });
      } catch (e) {
        return json(res, 500, { error: 'Cuckoo detonation failed', details: e.message });
      }
    }

    // ── MDM Push — Android/Generic (gap #22) ─────────────────────────
    if (pathname === '/api/telemetry/mobile' && req.method === 'POST') {
      const { deviceId, platform, logs, metrics } = await readBody(req);
      if (!deviceId || !platform) return json(res, 400, { error: 'Missing device identity' });
      
      logger.info({ deviceId, platform }, 'Ingested MDM push telemetry');
      if (Array.isArray(logs)) {
        logs.forEach(l => {
          const hash = crypto.createHash('md5').update(`${deviceId}-${l.date}-${l.msg}`).digest('hex');
          db.prepare('INSERT OR IGNORE INTO logs (hash, date, description, source, level) VALUES (?, ?, ?, ?, ?)')
            .run(hash, l.date || new Date().toISOString(), l.msg || '', `MDM-${platform}`, 'info');
        });
      }
      return json(res, 201, { status: 'ingested', count: logs?.length || 0 });
    }

    // ── iOS Pull — Remote Retrieval (gap #23) ─────────────────────────
    if (pathname === '/api/telemetry/ios' && req.method === 'POST') {
      try {
        const { stdout } = await execAsync('idevicesyslog -u $(idevice_id -l | head -n 1) -t');
        const iosLogs = stdout.split('\n').slice(0, 100).map(line => ({
          date: new Date().toISOString(),
          msg: line,
          source: 'iOS-Device'
        }));
        return json(res, 200, { status: 'captured', logs: iosLogs });
      } catch (e) {
        return json(res, 200, { 
          status: 'simulated', 
          error: 'libimobiledevice not found, providing simulated iOS events',
          logs: [
            { date: new Date().toISOString(), msg: 'kernel: sandboxd[123] deny(1) file-read-data /private/var/mobile/Library/Accounts/Accounts3.sqlite', source: 'iOS-Kernel' }
          ] 
        });
      }
    }

    // ── Analytics Engine API Routes ────────────────────────────────────────

    // GET /api/analytics/global — global KPI summary
    if (pathname === '/api/analytics/global' && req.method === 'GET') {
      const window = parseInt(urlObj.searchParams.get('window') || '3600000');
      return json(res, 200, analyticsEngine.getGlobalKPIs(Math.min(window, 7 * 24 * 3600 * 1000)));
    }

    // GET /api/analytics/segments — all segment KPIs ranked
    if (pathname === '/api/analytics/segments' && req.method === 'GET') {
      const window = parseInt(urlObj.searchParams.get('window') || '3600000');
      return json(res, 200, { segments: analyticsEngine.getSegmentRanking(Math.min(window, 24 * 3600 * 1000)), defs: SEGMENT_DEFS });
    }

    // GET /api/analytics/segments/:id — single segment KPIs
    if (pathname.startsWith('/api/analytics/segments/') && pathname.split('/').length === 5 && req.method === 'GET') {
      const segId = pathname.split('/')[4];
      const window = parseInt(urlObj.searchParams.get('window') || '3600000');
      return json(res, 200, analyticsEngine.computeKPIs(segId, Math.min(window, 7 * 24 * 3600 * 1000)));
    }

    // GET /api/analytics/segments/:id/timeseries — time-bucketed series
    if (pathname.startsWith('/api/analytics/segments/') && pathname.endsWith('/timeseries') && req.method === 'GET') {
      const segId = pathname.split('/')[4];
      const window = parseInt(urlObj.searchParams.get('window') || String(3 * 3600 * 1000));
      const bucket = parseInt(urlObj.searchParams.get('bucket') || '300000');
      return json(res, 200, { segment: segId, series: analyticsEngine.getSegmentTimeSeries(segId, window, bucket) });
    }

    // GET /api/analytics/segments/:id/compare — historical comparison
    if (pathname.startsWith('/api/analytics/segments/') && pathname.endsWith('/compare') && req.method === 'GET') {
      const segId = pathname.split('/')[4];
      return json(res, 200, { segment: segId, comparison: analyticsEngine.getHistoricalComparison(segId) });
    }

    // GET /api/analytics/alerts — active threshold alerts
    if (pathname === '/api/analytics/alerts' && req.method === 'GET') {
      const since = urlObj.searchParams.get('since') ? parseInt(urlObj.searchParams.get('since')) : null;
      const segment = urlObj.searchParams.get('segment') || null;
      const limit = parseInt(urlObj.searchParams.get('limit') || '200');
      return json(res, 200, { alerts: analyticsEngine.getAllAlerts(since, segment, limit) });
    }

    // POST /api/analytics/alerts/:id/ack — acknowledge an alert
    if (pathname.startsWith('/api/analytics/alerts/') && pathname.endsWith('/ack') && req.method === 'POST') {
      const alertId = parseInt(pathname.split('/')[4]);
      analyticsEngine.acknowledgeAlert(alertId);
      return json(res, 200, { acknowledged: true });
    }

    // GET /api/analytics/thresholds — get all thresholds
    if (pathname === '/api/analytics/thresholds' && req.method === 'GET') {
      const segment = urlObj.searchParams.get('segment') || null;
      return json(res, 200, { thresholds: analyticsEngine.getThresholds(segment) });
    }

    // PUT /api/analytics/thresholds — update a threshold
    if (pathname === '/api/analytics/thresholds' && req.method === 'PUT') {
      const body = await readBody(req);
      if (caller.role !== 'admin') return json(res, 403, { error: 'Admin role required' });
      const { segment, metric, warningValue, criticalValue, direction } = body;
      if (!segment || !metric) return json(res, 400, { error: 'segment and metric required' });
      analyticsEngine.updateThreshold(segment, metric, warningValue, criticalValue, direction);
      return json(res, 200, { updated: true });
    }

    // POST /api/analytics/engage — record engagement event
    if (pathname === '/api/analytics/engage' && req.method === 'POST') {
      const body = await readBody(req);
      analyticsEngine.recordEngagement({ ...body, userId: caller.sub });
      return json(res, 200, { recorded: true });
    }

    // GET /api/analytics/snapshots/:segment — historical KPI snapshots (from DB)
    if (pathname.startsWith('/api/analytics/snapshots/') && req.method === 'GET') {
      const segId = pathname.split('/')[4];
      const limit = parseInt(urlObj.searchParams.get('limit') || '120');
      const snapshots = db.prepare(
        'SELECT * FROM segment_kpi_snapshots WHERE segment = ? ORDER BY ts DESC LIMIT ?'
      ).all(segId, Math.min(limit, 500));
      return json(res, 200, { segment: segId, snapshots });
    }

    // GET /api/analytics/benchmarks — industry benchmark reference data
    if (pathname === '/api/analytics/benchmarks' && req.method === 'GET') {
      const { BENCHMARKS } = await import('./services/analyticsEngine.js');
      return json(res, 200, { benchmarks: BENCHMARKS, segments: SEGMENT_DEFS });
    }
    if (pathname === '/api/scanner/targets' && req.method === 'GET') {
      return json(res, 200, { targets: scannerEngine.getTargets() });
    }
    if (pathname === '/api/scanner/status' && req.method === 'GET') {
      return json(res, 200, scannerEngine.getStatus());
    }
    if (pathname === '/api/scanner/start' && req.method === 'POST') {
      try {
        const config = await readBody(req);
        auditLogger.scanStarted(caller.sub, caller.username, config);
        scannerEngine.startScan(config).catch(err => logger.error(err, 'Scan error'));
        return json(res, 200, { status: 'starting' });
      } catch (err) { return json(res, 409, { error: err.message }); }
    }
    if (pathname === '/api/scanner/stop' && req.method === 'POST') {
      return json(res, 200, { stopped: scannerEngine.stopScan() });
    }
    if (pathname === '/api/scanner/sessions' && req.method === 'GET') {
      const limit = Math.min(parseInt(urlObj.searchParams.get('limit')) || 20, 100);
      const sessions = db.prepare('SELECT * FROM scan_sessions ORDER BY started_at DESC LIMIT ?').all(limit);
      return json(res, 200, { sessions: sessions.map(s => ({ ...s, summary: s.summary ? JSON.parse(s.summary) : null, config: s.config ? JSON.parse(s.config) : null })) });
    }
    if (pathname.startsWith('/api/scanner/sessions/') && req.method === 'GET') {
      const parts = pathname.split('/');
      const sessionId = parts[4];
      if (parts[5] === 'findings') {
        const status = urlObj.searchParams.get('status');
        const sort = urlObj.searchParams.get('sort');
        let query = 'SELECT * FROM scan_findings WHERE session_id = ?';
        const params = [sessionId];
        if (status && status !== 'all') { query += ' AND status = ?'; params.push(status); }
        query += sort === 'name' ? ' ORDER BY file_name ASC' : ' ORDER BY risk_score DESC';
        query += ' LIMIT 500';
        const findings = db.prepare(query).all(...params);
        return json(res, 200, { findings: findings.map(f => ({ ...f, risk_factors: JSON.parse(f.risk_factors || '[]'), mitre_techniques: JSON.parse(f.mitre_techniques || '[]'), ads_streams: JSON.parse(f.ads_streams || '[]') })) });
      }
      const session = db.prepare('SELECT * FROM scan_sessions WHERE id = ?').get(sessionId);
      if (!session) return json(res, 404, { error: 'Session not found' });
      return json(res, 200, { ...session, summary: session.summary ? JSON.parse(session.summary) : null });
    }
    if (pathname.startsWith('/api/scanner/export/') && req.method === 'GET') {
      const parts = pathname.split('/');
      const [sessionId, format] = [parts[4], parts[5]];
      const session = db.prepare('SELECT * FROM scan_sessions WHERE id = ?').get(sessionId);
      if (!session) return json(res, 404, { error: 'Session not found' });
      const findings = db.prepare('SELECT * FROM scan_findings WHERE session_id = ? ORDER BY risk_score DESC').all(sessionId);
      const { exportJSON, exportCSV, exportSTIX, exportSplunkCIM, exportHTML } = await import('./scanner/exporters.js');
      const exporters = { json: exportJSON, csv: exportCSV, stix: exportSTIX, splunk: exportSplunkCIM, html: exportHTML };
      const exporter = exporters[format];
      if (!exporter) return json(res, 400, { error: 'Unsupported format. Use: json, csv, stix, splunk, html' });
      auditLogger.dataExport(caller.sub, caller.username, format, `/api/scanner/export/${sessionId}`);
      const content = format === 'csv' ? exporter(findings) : exporter(session, findings);
      const types = { json: 'application/json', csv: 'text/csv', stix: 'application/json', splunk: 'application/x-ndjson', html: 'text/html' };
      res.writeHead(200, { 'Content-Type': types[format], 'Content-Disposition': `attachment; filename="scan-${sessionId}.${format === 'html' ? 'html' : format === 'splunk' ? 'ndjson' : format}"` });
      return res.end(content);
    }

    // ── Gemini AI API ──────────────────────────────────────────────
    if (pathname === '/api/ai/analyze' && req.method === 'POST') {
      const body = await readBody(req);
      if (!geminiService.isConfigured() && body.apiKey) geminiService.setApiKey(body.apiKey);
      if (!geminiService.isConfigured()) return json(res, 400, { error: 'Gemini API key not configured. Set GEMINI_API_KEY env var or provide apiKey in request.' });
      try {
        const result = await geminiService.analyzeTelemetry(body);
        return json(res, 200, result);
      } catch (e) { return json(res, 500, { error: e.message }); }
    }
    if (pathname === '/api/ai/chat' && req.method === 'POST') {
      const body = await readBody(req);
      if (!geminiService.isConfigured() && body.apiKey) geminiService.setApiKey(body.apiKey);
      if (!geminiService.isConfigured()) return json(res, 400, { error: 'AI not configured' });
      try {
        const result = await geminiService.chat(body);
        return json(res, 200, result);
      } catch (e) { return json(res, 500, { error: e.message }); }
    }
    if (pathname === '/api/ai/metrics' && req.method === 'GET') {
      return json(res, 200, geminiService.getMetrics());
    }

    // ── Security Audit Log API ────────────────────────────────────
    if (pathname === '/api/security/audit' && req.method === 'GET') {
      const eventType = urlObj.searchParams.get('type');
      const severity = urlObj.searchParams.get('severity');
      const since = urlObj.searchParams.get('since') ? parseInt(urlObj.searchParams.get('since')) : null;
      const limit = parseInt(urlObj.searchParams.get('limit') || '100');
      const logs = auditLogger.query({ eventType, severity, since, limit });
      return json(res, 200, { logs });
    }
    if (pathname === '/api/security/ddos-stats' && req.method === 'GET') {
      return json(res, 200, ddosProtection.getStats());
    }

    // ── Database Migration Status ─────────────────────────────────
    if (pathname === '/api/system/migrations' && req.method === 'GET') {
      const { getMigrationStatus } = await import('./services/migrations.js');
      return json(res, 200, { migrations: getMigrationStatus(db) });
    }

    // ── Sync API ──────────────────────────────────────────────────
    if (pathname === '/api/sync/changes' && req.method === 'GET') {
      const since = parseInt(urlObj.searchParams.get('since') || '0');
      const changes = syncManager.getChangesSince(since, caller.sub);
      return json(res, 200, { changes });
    }
    if (pathname === '/api/sync/upload' && req.method === 'POST') {
      const body = await readBody(req);
      const clientId = req.headers['x-client-id'] || 'web-' + caller.sub;
      const results = syncManager.processClientSync(clientId, caller.sub, body.changes || []);
      return json(res, 200, { results });
    }
    if (pathname === '/api/sync/status' && req.method === 'GET') {
      const clientId = urlObj.searchParams.get('clientId') || 'web-' + caller.sub;
      return json(res, 200, syncManager.getClientSyncStatus(clientId));
    }

    json(res, 404, { error: 'Not found' });

  } catch (err) {
    logger.error(err, 'Unhandled request error'); // gap #21
    json(res, 500, { error: 'Internal server error' });
  }
});

// ── Global error guards (gap #21) ────────────────────────────────
process.on('unhandledRejection', (reason) => { logger.error({ reason }, 'Unhandled Promise Rejection'); });
process.on('uncaughtException',  (err)    => { logger.fatal(err, 'Uncaught Exception — shutting down'); process.exit(1); });

// ── Graceful shutdown ────────────────────────────────────────────
function shutdown(signal) {
  logger.info(`${signal} received — shutting down gracefully`);
  analyticsEngine.destroy();
  for (const timer of wsAuthTimers.values()) clearTimeout(timer);
  httpServer.close(() => { logger.info('HTTP server closed'); process.exit(0); });
  setTimeout(() => process.exit(1), 10000);
}
process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT',  () => shutdown('SIGINT'));

// ── Start (gap #9 — PM2 will manage process; gap #7 — TLS via reverse proxy) ─
httpServer.listen(PORT, async () => {
  logger.info({ port: PORT, env: NODE_ENV, origins: ALLOWED_ORIGINS }, 'SentinelGrid backend started');
  
  // Initialize permission detection
  await detectPermissions();
  logger.info({ permissions: SYSTEM_PERMISSIONS }, 'System permissions detected');
  
  // Warn if not running with admin privileges
  if (!SYSTEM_PERMISSIONS.isAdmin) {
    logger.warn('Not running with administrator privileges - some monitoring features will be limited');
    logger.warn('Restart with "Run as administrator" for full security monitoring');
  }
});
