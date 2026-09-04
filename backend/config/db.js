import { DatabaseSync } from 'node:sqlite';
import path from 'path';
import bcrypt from 'bcryptjs';

const isTestRuntime = process.env.VITEST === 'true' || process.env.NODE_ENV === 'test';
const coreDbPath = isTestRuntime ? ':memory:' : path.resolve(process.cwd(), 'soc_database.sqlite');
const threatDbPath = isTestRuntime ? ':memory:' : path.resolve(process.cwd(), 'threat_ledger.sqlite');
const metricsDbPath = isTestRuntime ? ':memory:' : path.resolve(process.cwd(), 'sandbox_metrics.sqlite');

const coreDb = new DatabaseSync(coreDbPath);
const threatDb = new DatabaseSync(threatDbPath);
const metricsDb = new DatabaseSync(metricsDbPath);

// Tune performance parameters for WAL mode on all shards
[coreDb, threatDb, metricsDb].forEach((shard) => {
  shard.exec(isTestRuntime ? 'PRAGMA journal_mode=MEMORY' : 'PRAGMA journal_mode=WAL');
  shard.exec('PRAGMA synchronous=NORMAL');
  shard.exec('PRAGMA busy_timeout=5000');
  shard.exec('PRAGMA cache_size=10000');
  shard.exec('PRAGMA temp_store=MEMORY');
  shard.exec('PRAGMA mmap_size=268435456');
});

// Create tables on their respective shards
// Core shard: authentication, user logs, rate limits
coreDb.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'analyst',
    totp_secret TEXT,
    totp_enrolled INTEGER DEFAULT 0,
    failed_attempts INTEGER DEFAULT 0,
    locked_until INTEGER DEFAULT 0,
    last_login TEXT,
    created_at TEXT DEFAULT (datetime('now'))
  );
  CREATE INDEX IF NOT EXISTS idx_users_created_at ON users(created_at DESC);

  CREATE TABLE IF NOT EXISTS refresh_tokens (
    jti TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL,
    username TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    revoked INTEGER DEFAULT 0
  );
  CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user ON refresh_tokens(user_id, expires_at DESC);

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

// Threat Ledger shard: alert logs, known signatures, SIEM/SOAR triggers
threatDb.exec(`
  CREATE TABLE IF NOT EXISTS logs (
    hash TEXT PRIMARY KEY, eventId TEXT, date TEXT, level TEXT,
    task TEXT, source TEXT, description TEXT, suspicious INTEGER,
    segment TEXT DEFAULT 'unknown', zone TEXT DEFAULT 'unknown',
    mitre TEXT
  );
  CREATE INDEX IF NOT EXISTS idx_logs_date ON logs(date DESC);
  CREATE INDEX IF NOT EXISTS idx_logs_segment ON logs(segment);
  CREATE INDEX IF NOT EXISTS idx_logs_zone ON logs(zone);
  CREATE INDEX IF NOT EXISTS idx_logs_suspicious ON logs(suspicious, date DESC);

  CREATE TABLE IF NOT EXISTS known_patterns (
    patternId TEXT PRIMARY KEY, name TEXT, regex TEXT, mitre_tactic TEXT
  );

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
`);

// Sandbox Metrics shard: time-series parameters, device telemetry, network flows, hypervisor states
metricsDb.exec(`
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

  CREATE TABLE IF NOT EXISTS segments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE NOT NULL,
    zone TEXT NOT NULL,
    status TEXT DEFAULT 'active',
    health_score INTEGER DEFAULT 100,
    last_seen INTEGER DEFAULT 0,
    config TEXT
  );

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
`);

if (isTestRuntime) {
  const passwordHash = bcrypt.hashSync('admin123', 4);
  coreDb.prepare('INSERT OR IGNORE INTO users (id, username, email, password_hash, role) VALUES (?, ?, ?, ?, ?)')
    .run(1, 'admin', 'admin@sentinelgrid.local', passwordHash, 'admin');
  coreDb.prepare('INSERT OR IGNORE INTO users (id, username, email, password_hash, role) VALUES (?, ?, ?, ?, ?)')
    .run(2, 'analyst', 'analyst@sentinelgrid.local', passwordHash, 'analyst');
}

// Router function to select database shard based on SQL string
function getShardForSql(sql) {
  const sqlLower = sql.toLowerCase();
  
  // Threat Ledger Tables
  if (sqlLower.includes('logs') || sqlLower.includes('known_patterns') || sqlLower.includes('segment_alerts')) {
    return threatDb;
  }
  
  // Sandbox Metrics Tables
  if (sqlLower.includes('metrics_time_series') || sqlLower.includes('connections') || sqlLower.includes('segments')) {
    return metricsDb;
  }
  
  // Fallback to Core Shard (users, refresh_tokens, revoked_access_tokens, rate_limits)
  return coreDb;
}

// Transaction coordination handler
function executeAcrossAllShards(method, ...args) {
  return [coreDb, threatDb, metricsDb].map(shard => shard[method](...args));
}

// Transparent Proxy wrapper to act as standard DatabaseSync instance
const db = new Proxy(coreDb, {
  get(target, prop, receiver) {
    if (prop === 'prepare') {
      return function (sql, ...args) {
        const shard = getShardForSql(sql);
        return shard.prepare(sql, ...args);
      };
    }
    if (prop === 'exec') {
      return function (sql, ...args) {
        const sqlLower = sql.toLowerCase();
        // Route transaction operations to all shards
        if (sqlLower.includes('transaction') || sqlLower.includes('commit') || sqlLower.includes('rollback')) {
          executeAcrossAllShards('exec', sql, ...args);
          return;
        }
        const shard = getShardForSql(sql);
        return shard.exec(sql, ...args);
      };
    }
    // Forward other property lookups (like close)
    return Reflect.get(target, prop, receiver);
  }
});

export { threatDb, metricsDb, coreDb };
export default db;
