/**
 * Security Middleware — Enterprise-grade request protection layer.
 * Provides: request validation, security audit logging, reCAPTCHA verification,
 * enhanced rate limiting, DDoS protection, and incident tracking.
 */
import crypto from 'crypto';

// ── Request Validation Middleware ──
const DANGEROUS_PATTERNS = [
  /(\b(union|select|insert|update|delete|drop|alter|create|exec)\b.*\b(from|into|table|database|where)\b)/i,
  /<script[\s>]/i,
  /javascript:/i,
  /on(error|load|click|mouseover)=/i,
  /\.\.\//g,
  /\0/g,
];

export function validateRequest(req, logger) {
  const url = req.url || '';
  const body = req._body || '';
  const combined = url + (typeof body === 'string' ? body : JSON.stringify(body || ''));

  for (const pattern of DANGEROUS_PATTERNS) {
    if (pattern.test(combined)) {
      logger?.warn({ ip: getClientIp(req), pattern: pattern.source, url }, 'Request blocked by WAF');
      return { valid: false, reason: 'Potentially malicious request content detected' };
    }
  }

  // Content-Length validation
  const contentLength = parseInt(req.headers['content-length'] || '0', 10);
  if (contentLength > 10 * 1024 * 1024) { // 10MB max
    return { valid: false, reason: 'Request body too large' };
  }

  return { valid: true };
}

// ── Security Audit Logger ──
export class SecurityAuditLogger {
  constructor(db, logger) {
    this.db = db;
    this.logger = logger;
    this._ensureTable();
  }

  _ensureTable() {
    try {
      this.db.exec(`
        CREATE TABLE IF NOT EXISTS security_audit_log (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          timestamp INTEGER NOT NULL DEFAULT (unixepoch() * 1000),
          event_type TEXT NOT NULL,
          severity TEXT NOT NULL DEFAULT 'info',
          actor_id INTEGER, actor_username TEXT, actor_ip TEXT,
          resource TEXT, action TEXT, outcome TEXT DEFAULT 'success',
          details TEXT, session_id TEXT, user_agent TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON security_audit_log(timestamp DESC);
      `);
    } catch { /* table may already exist */ }

    this._insertStmt = this.db.prepare(`
      INSERT INTO security_audit_log (timestamp, event_type, severity, actor_id, actor_username, actor_ip, resource, action, outcome, details, session_id, user_agent)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);
  }

  log(event) {
    const ts = Date.now();
    try {
      this._insertStmt.run(
        ts, event.type, event.severity || 'info',
        event.actorId || null, event.actorUsername || null, event.actorIp || null,
        event.resource || null, event.action || null, event.outcome || 'success',
        event.details ? JSON.stringify(event.details) : null,
        event.sessionId || null, event.userAgent || null
      );
    } catch (e) {
      this.logger?.error(e, 'Failed to write audit log');
    }

    // Also log to structured logger for SIEM forwarding
    this.logger?.info({
      audit: true, eventType: event.type, severity: event.severity,
      actor: event.actorUsername, ip: event.actorIp, resource: event.resource,
      action: event.action, outcome: event.outcome,
    }, `AUDIT: ${event.type}`);
  }

  // Pre-built event loggers
  loginSuccess(user, ip, userAgent) {
    this.log({ type: 'auth.login.success', severity: 'info', actorId: user.id, actorUsername: user.username, actorIp: ip, action: 'login', resource: '/api/auth/login', outcome: 'success', userAgent });
  }

  loginFailure(identifier, ip, reason, userAgent) {
    this.log({ type: 'auth.login.failure', severity: 'warning', actorUsername: identifier, actorIp: ip, action: 'login', resource: '/api/auth/login', outcome: 'failure', details: { reason }, userAgent });
  }

  accountLocked(identifier, ip) {
    this.log({ type: 'auth.account.locked', severity: 'high', actorUsername: identifier, actorIp: ip, action: 'lockout', outcome: 'enforced' });
  }

  tokenRefresh(userId, username, ip) {
    this.log({ type: 'auth.token.refresh', severity: 'info', actorId: userId, actorUsername: username, actorIp: ip, action: 'refresh' });
  }

  accessDenied(userId, username, ip, resource) {
    this.log({ type: 'authz.denied', severity: 'warning', actorId: userId, actorUsername: username, actorIp: ip, resource, action: 'access', outcome: 'denied' });
  }

  suspiciousActivity(ip, details) {
    this.log({ type: 'security.suspicious', severity: 'high', actorIp: ip, action: 'detect', details });
  }

  scanStarted(userId, username, config) {
    this.log({ type: 'scanner.started', severity: 'info', actorId: userId, actorUsername: username, action: 'scan', details: config });
  }

  dataExport(userId, username, format, resource) {
    this.log({ type: 'data.export', severity: 'info', actorId: userId, actorUsername: username, action: 'export', resource, details: { format } });
  }

  /** Query audit logs with filters */
  query({ eventType, severity, actorId, since, limit = 100 } = {}) {
    let sql = 'SELECT * FROM security_audit_log WHERE 1=1';
    const params = [];
    if (eventType) { sql += ' AND event_type LIKE ?'; params.push(`${eventType}%`); }
    if (severity) { sql += ' AND severity = ?'; params.push(severity); }
    if (actorId) { sql += ' AND actor_id = ?'; params.push(actorId); }
    if (since) { sql += ' AND timestamp >= ?'; params.push(since); }
    sql += ' ORDER BY timestamp DESC LIMIT ?';
    params.push(Math.min(limit, 500));
    return this.db.prepare(sql).all(...params);
  }
}

// ── Enhanced DDoS Protection ──
export class DDoSProtection {
  constructor(options = {}) {
    this.windowMs = options.windowMs || 60000;
    this.maxRequests = options.maxRequests || 200;
    this.blockDurationMs = options.blockDurationMs || 300000; // 5 minutes
    this.requests = new Map();  // ip -> { count, windowStart }
    this.blocked = new Map();   // ip -> unblockAt
    this.suspiciousPatterns = new Map(); // ip -> pattern count

    // Periodic cleanup
    setInterval(() => this._cleanup(), 60000);
  }

  check(ip) {
    // Check if blocked
    const unblockAt = this.blocked.get(ip);
    if (unblockAt) {
      if (Date.now() < unblockAt) return { allowed: false, reason: 'IP temporarily blocked', retryAfter: Math.ceil((unblockAt - Date.now()) / 1000) };
      this.blocked.delete(ip);
    }

    const now = Date.now();
    let entry = this.requests.get(ip);
    if (!entry || now - entry.windowStart > this.windowMs) {
      entry = { count: 0, windowStart: now };
      this.requests.set(ip, entry);
    }
    entry.count++;

    if (entry.count > this.maxRequests) {
      this.blocked.set(ip, now + this.blockDurationMs);
      return { allowed: false, reason: 'Rate limit exceeded — temporarily blocked', retryAfter: Math.ceil(this.blockDurationMs / 1000) };
    }

    return { allowed: true, remaining: this.maxRequests - entry.count };
  }

  _cleanup() {
    const now = Date.now();
    for (const [ip, entry] of this.requests) {
      if (now - entry.windowStart > this.windowMs * 2) this.requests.delete(ip);
    }
    for (const [ip, unblock] of this.blocked) {
      if (now > unblock) this.blocked.delete(ip);
    }
  }

  getStats() {
    return { trackedIPs: this.requests.size, blockedIPs: this.blocked.size, blockedList: [...this.blocked.keys()] };
  }
}

// ── reCAPTCHA Verification ──
export async function verifyRecaptcha(token, secretKey, expectedAction = null) {
  if (!secretKey) return { success: true, score: 1.0, reason: 'reCAPTCHA not configured — skipping' };

  try {
    const res = await fetch('https://www.google.com/recaptcha/api/siteverify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: `secret=${encodeURIComponent(secretKey)}&response=${encodeURIComponent(token)}`,
    });
    const data = await res.json();

    if (!data.success) return { success: false, score: 0, reason: 'reCAPTCHA verification failed', errors: data['error-codes'] };
    if (expectedAction && data.action !== expectedAction) return { success: false, score: data.score, reason: 'Action mismatch' };
    if (data.score !== undefined && data.score < 0.5) return { success: false, score: data.score, reason: 'Low reCAPTCHA score — likely bot' };

    return { success: true, score: data.score || 1.0 };
  } catch (err) {
    return { success: false, score: 0, reason: `reCAPTCHA error: ${err.message}` };
  }
}

// ── Request Fingerprinting ──
export function fingerprintRequest(req) {
  const parts = [
    req.headers['user-agent'] || '',
    req.headers['accept-language'] || '',
    req.headers['accept-encoding'] || '',
    req.socket?.remoteAddress || '',
  ];
  return crypto.createHash('sha256').update(parts.join('|')).digest('hex').slice(0, 16);
}

function getClientIp(req) {
  return req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.socket?.remoteAddress || 'unknown';
}
