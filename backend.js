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

dotenv.config();

// ── Structured logger (gap #19) ───────────────────────────────────
const logger = pino({
  level: process.env.LOG_LEVEL || 'info',
  transport: process.env.NODE_ENV !== 'production'
    ? { target: 'pino-pretty', options: { colorize: true } }
    : undefined,
});

// ── Fail-fast for missing critical secrets in production (gap #4) ─
const NODE_ENV = process.env.NODE_ENV || 'development';
function requireEnv(key, devFallback) {
  if (NODE_ENV === 'production' && !process.env[key]) {
    logger.fatal(`FATAL: Missing required env var "${key}". Refusing to start.`);
    process.exit(1);
  }
  return process.env[key] || devFallback;
}

// ── Secrets — backend-only, no VITE_ prefix (gap #6) ────────────
const JWT_SECRET          = requireEnv('JWT_SECRET', 'dev-jwt-secret-CHANGE-IN-PRODUCTION-min-32-chars!!');
const JWT_REFRESH_SECRET  = requireEnv('JWT_REFRESH_SECRET', 'dev-refresh-secret-CHANGE-IN-PRODUCTION!!');
const ADMIN_PASS          = requireEnv('ADMIN_PASS', 'Sentinel2026!');
const ADMIN_USER          = requireEnv('ADMIN_USER', 'admin');

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

// ── Legacy compat (removed in next cleanup) ───────────────────────
const AUTH_BEARER = 'LEGACY-DISABLED';

// ── Database (WAL mode = no write locks, gap #8) ─────────────────
const db = new DatabaseSync('./soc_database.sqlite');
db.exec('PRAGMA journal_mode=WAL');
db.exec('PRAGMA synchronous=NORMAL');
db.exec('PRAGMA cache_size=10000');
db.exec('PRAGMA foreign_keys=ON');
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
`);

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
    db.prepare('INSERT INTO users (username,password_hash,role) VALUES (?,?,?)' )
      .run(ADMIN_USER, hashPassword(ADMIN_PASS), 'admin');
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
    const dir = path.join(process.cwd(), 'backups');
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    const ts  = new Date().toISOString().replace(/[:.]/g, '-');
    const dst = path.join(dir, `soc_db_${ts}.sqlite`);
    fs.copyFileSync('./soc_database.sqlite', dst);
    const files = fs.readdirSync(dir).filter(f => f.endsWith('.sqlite')).sort();
    if (files.length > 7) files.slice(0, files.length - 7).forEach(f => fs.unlinkSync(path.join(dir, f)));
    logger.info({ dst }, 'DB backup completed');
  } catch (e) { logger.error(e, 'DB backup failed'); }
}
setInterval(backupDatabase, 6 * 60 * 60 * 1000); // every 6 hours

// ── WebSocket server (gap #16) ────────────────────────────────────
const httpServer = createServer();
const wss = new WebSocketServer({ server: httpServer });
const wsClients = new Set();
wss.on('connection', (ws, req) => {
  const url   = new URL(req.url, `http://localhost`);
  const token = url.searchParams.get('token');
  try {
    const payload = verifyJWT(token);
    if (isAccessTokenRevoked(payload.jti)) throw new Error('Token revoked');
    wsClients.add(ws);
    logger.info('WebSocket client connected');
    ws.on('close', () => wsClients.delete(ws));
  } catch {
    ws.close(4001, 'Unauthorized');
  }
});
function broadcast(event, data) {
  const msg = JSON.stringify({ event, data, ts: Date.now() });
  wsClients.forEach(ws => { if (ws.readyState === 1) ws.send(msg); });
}

const insertLog = db.prepare(`
  INSERT OR IGNORE INTO logs (hash, eventId, date, level, task, source, description, suspicious)
  VALUES (?, ?, ?, ?, ?, ?, ?, ?)
`);


function parseAndStoreLogs(rawText) {
  const blocks = rawText.split(/Event\[\d+\]:/).filter(Boolean);
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

    const uniqueId = crypto.createHash('md5').update(`${id}-${date}-${task}`).digest('hex');
    const suspicious = ['4625', '1102', '4688'].includes(id) ? 1 : 0;
    
    try {
      insertLog.run(uniqueId, id, date, level, task, source, desc, suspicious);
    } catch (e) {}
  });
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

// Enrich a raw PowerShell log object with Date, LogName, MITRE, Computer, and write to DB
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
  const uid    = crypto.createHash('md5').update(`${id}-${date}-${task}-${source}`).digest('hex');
  try { insertLog.run(uid, id, date, level, task, source, desc, suspicious); } catch {}
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

// Autonomous real-time agent: collect and broadcast new logs every 15 s
setInterval(async () => {
  try {
    const freshLogs = await getWindowsLogs();
    if (freshLogs.length > 0) {
      // Only broadcast the newest events (≤10) to avoid flooding
      const toSend = freshLogs.slice(0, 10).map(l => ({
        id:        l.Id != null ? String(l.Id) : 'Unknown',
        date:      l.Date,
        level:     l.LevelDisplayName || 'Information',
        source:    l.ProviderName || '',
        task:      l.TaskDisplayName  || '',
        logName:   l.LogName || '',
        computer:  l.Computer || os.hostname(),
        message:   l.Message  || '',
        suspicious: !!l.Suspicious,
        mitre:     l.Mitre || null,
      }));
      broadcast('new_logs', toSend);
    }
  } catch {}
}, 15000);

// Cross-platform network traffic (gap #18)
async function getNetworkTraffic() {
  try {
    const platform = os.platform();
    let cmd = 'netstat -ano';
    if (platform === 'linux')  cmd = 'ss -tulnp 2>/dev/null || netstat -tulnp 2>/dev/null';
    if (platform === 'darwin') cmd = 'netstat -an 2>/dev/null';
    const { stdout } = await execAsync(cmd);
    return stdout.split('\n').filter(l => l.trim()).slice(0, 50).join('\n');
  } catch (e) { return 'Error fetching network traffic.'; }
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
          } catch (e) {}
        }
      } catch (e) {}
    }
    // Sort by most recently modified
    return results.sort((a, b) => b.modified - a.modified).slice(0, 15);
  } catch (e) {
    return [];
  }
}

function analyzeTelemetry(logs, network, files) {
  const analysis = {
    summary: "System baseline operating within normal parameters. No critical breaches detected in recent timeframe.",
    score: 100,
    threats: [],
    mitreMappings: [],
  };

  const logsString = typeof logs === 'string' ? logs : JSON.stringify(logs);

  if (network.includes("LISTENING")) {
    const listeningPorts = (network.match(/:(\d+)\s+.*LISTENING/g) || []).map(p => p.split(':')[1].split(' ')[0]);
    if (listeningPorts.includes("3389")) {
      analysis.score -= 10;
      analysis.threats.push("Open RDP Port (3389) detected in LISTENING state. Potential vector for brute force.");
      analysis.mitreMappings.push("T1021 - Remote Services");
    }
  }

  const rules = [
    { id: "4625", desc: "Failed Logon", mitre: "T1110 - Brute Force", weight: 20 },
    { id: "1102", desc: "Security Audit Log Cleared", mitre: "T1070 - Indicator Removal", weight: 50 },
    { id: "4648", desc: "Logon using explicit credentials", mitre: "T1078 - Valid Accounts", weight: 15 },
    { id: "4672", desc: "Special privileges assigned to new logon", mitre: "T1078 - Valid Accounts", weight: 10 },
    { id: "4698", desc: "Scheduled Task Created", mitre: "T1053.005 - Scheduled Task", weight: 25 },
    { id: "4720", desc: "User Account Created", mitre: "T1136.001 - Local Account", weight: 30 },
    { id: "4724", desc: "Password Reset Attempted", mitre: "T1098 - Account Manipulation", weight: 20 },
    { id: "7045", desc: "New Service Installed", mitre: "T1543.003 - Windows Service", weight: 35 }
  ];

  for (const rule of rules) {
    if (logsString.includes(rule.id)) {
      analysis.score -= rule.weight;
      analysis.threats.push(`${rule.desc} (Event ID ${rule.id}) detected.`);
      if (!analysis.mitreMappings.includes(rule.mitre)) analysis.mitreMappings.push(rule.mitre);
    }
  }

  analysis.score = Math.max(0, analysis.score);

  if (analysis.score === 100) {
    analysis.summary = "Heuristic scan complete. Recent network and log telemetry did not match the built-in high-risk rules. Continue reviewing with validated EDR/SIEM telemetry.";
  } else {
    analysis.summary = `Heuristic scan complete. Risk score reduced to ${analysis.score}/100 due to matched indicators. Analyst review recommended.`;
  }

  return analysis;
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
  res.setHeader('Content-Security-Policy', `default-src 'self'; connect-src ${CSP_CONNECT_SRC}; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https://www.virustotal.com; font-src 'self' data:;`);
  // HSTS only in production over HTTPS (gap #5)
  if (NODE_ENV === 'production') res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload');
}

function getClientIp(req) {
  if (TRUST_PROXY && req.headers['x-forwarded-for']) {
    return String(req.headers['x-forwarded-for']).split(',')[0].trim();
  }
  return req.socket.remoteAddress || 'unknown';
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
  const urlObj   = new URL(req.url, `http://localhost`);
  const pathname = urlObj.pathname;

  logger.info({ method: req.method, path: pathname, ip: clientIp }, 'Request'); // gap #19

  try {
    // ── Health endpoint (gap #20) ───────────────────────────────
    if (pathname === '/health' && req.method === 'GET') {
      return json(res, 200, { status: 'ok', uptime: process.uptime(), ts: Date.now(), db: 'connected' });
    }

    // ── POST /api/auth/login — gap #1 real TOTP, gap #3 JWT ────
    if (pathname === '/api/auth/login' && req.method === 'POST') {
      const { username, password } = await readBody(req);
      
      const rl = checkRateLimit(clientIp, username);
      if (rl.locked) return json(res, 429, { error: `Too many attempts. Retry in ${rl.retryAfter}s.` });

      const user = db.prepare('SELECT * FROM users WHERE username=?').get(username);
      if (!user || !verifyPassword(password, user.password_hash)) {
        recordFailure(clientIp, username);
        logger.warn({ username, ip: clientIp }, 'Failed login attempt');
        return json(res, 401, { error: 'Invalid credentials.' });
      }

      clearRateLimit(clientIp, username);
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
    if (pathname === '/api/auth/verify-2fa' && req.method === 'POST') {
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
      return json(res, 200, { success: true, accessToken, role: user.role });
    }

    // ── POST /api/auth/refresh — rotate access token (gap #3) ──
    if (pathname === '/api/auth/refresh' && req.method === 'POST') {
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
    if (pathname === '/api/auth/logout' && req.method === 'POST') {
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
      } catch {}
      
      res.setHeader('Set-Cookie', `sg_refresh_token=; HttpOnly; Path=/; Max-Age=0; SameSite=Strict`);
      return json(res, 200, { success: true });
    }

    // ── All routes below require valid JWT ───────────────────────
    let caller;
    try { caller = authenticate(req); }
    catch (e) { return json(res, 401, { error: e.message }); }

    // ── GET /api/auth/me ────────────────────────────────────────
    if (pathname === '/api/auth/me' && req.method === 'GET') {
      return json(res, 200, {
        authenticated: true,
        user: { id: caller.sub, username: caller.username, role: caller.role },
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
      return json(res, 200, await getSystemTelemetry());
    }

    // ── GET /api/logs/live — dedicated real-device log endpoint ──
    if (pathname === '/api/logs/live' && req.method === 'GET') {
      const maxParam  = parseInt(urlObj.searchParams.get('max') || '80', 10);
      const channel   = urlObj.searchParams.get('channel') || 'all'; // all | security | system | application
      let logs = await getWindowsLogs();
      // Filter by channel if requested
      if (channel !== 'all') {
        const channelMap = { security: 'Security', system: 'System', application: 'Application' };
        const target = channelMap[channel.toLowerCase()];
        if (target) logs = logs.filter(l => (l.LogName || '').toLowerCase() === target.toLowerCase());
      }
      // Normalise to a flat shape the frontend can consume directly
      const normalized = logs.slice(0, maxParam).map((l, i) => ({
        id:          `live-${i}-${l.Id}`,
        eventId:     l.Id != null ? String(l.Id) : 'Unknown',
        timestamp:   new Date(l.Date || Date.now()).getTime(),
        level:       l.LevelDisplayName || 'Information',
        source:      l.ProviderName || 'Unknown',
        category:    l.TaskDisplayName || 'System Event',
        logName:     l.LogName || 'Unknown',
        computer:    l.Computer || os.hostname(),
        message:     l.Message || 'No description.',
        suspicious:  !!l.Suspicious,
        mitre:       l.Mitre || null,
      }));
      return json(res, 200, { logs: normalized, fetchedAt: Date.now(), platform: os.platform(), computer: os.hostname() });
    }

    // ── GET /api/analyze ─────────────────────────────────────────
    if (pathname === '/api/analyze' && req.method === 'GET') {
      const [logs, network, files, system] = await Promise.all([getWindowsLogs(), getNetworkTraffic(), getFileChanges(), getSystemTelemetry()]);
      const analysis = analyzeTelemetry(logs, network, files);
      return json(res, 200, { system, logs, network, files, analysis });
    }

    // ── GET /api/database/logs ────────────────────────────────────
    if (pathname === '/api/database/logs' && req.method === 'GET') {
      const rows = db.prepare('SELECT * FROM logs ORDER BY date DESC LIMIT 5000').all()
        .map(l => ({ ...l, suspicious: !!l.suspicious }));
      return json(res, 200, { databaseLogs: rows });
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
      const result = await queryVirusTotal(indicator, type);
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
  httpServer.close(() => { logger.info('HTTP server closed'); process.exit(0); });
  setTimeout(() => process.exit(1), 10000);
}
process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT',  () => shutdown('SIGINT'));

// ── Start (gap #9 — PM2 will manage process; gap #7 — TLS via reverse proxy) ─
httpServer.listen(PORT, () => {
  logger.info({ port: PORT, env: NODE_ENV, origins: ALLOWED_ORIGINS }, 'SentinelGrid backend started');
});
