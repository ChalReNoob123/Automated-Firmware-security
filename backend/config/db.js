import { DatabaseSync } from 'node:sqlite';
import path from 'path';

const dbPath = path.resolve(process.cwd(), 'soc_database.sqlite');
const db = new DatabaseSync(dbPath);

// Performance tuning
db.exec('PRAGMA journal_mode=WAL');
db.exec('PRAGMA synchronous=NORMAL');
db.exec('PRAGMA busy_timeout=5000');
db.exec('PRAGMA cache_size=10000');
db.exec('PRAGMA temp_store=MEMORY');
db.exec('PRAGMA mmap_size=268435456');

// Initial Schema
db.exec(`
  CREATE TABLE IF NOT EXISTS logs (
    hash TEXT PRIMARY KEY, eventId TEXT, date TEXT, level TEXT,
    task TEXT, source TEXT, description TEXT, suspicious INTEGER,
    segment TEXT DEFAULT 'unknown', zone TEXT DEFAULT 'unknown'
  );
  CREATE INDEX IF NOT EXISTS idx_logs_date ON logs(date DESC);
  CREATE INDEX IF NOT EXISTS idx_logs_segment ON logs(segment);
  CREATE INDEX IF NOT EXISTS idx_logs_zone ON logs(zone);
  CREATE INDEX IF NOT EXISTS idx_logs_suspicious ON logs(suspicious, date DESC);

  CREATE TABLE IF NOT EXISTS known_patterns (
    patternId TEXT PRIMARY KEY, name TEXT, regex TEXT, mitre_tactic TEXT
  );

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

export default db;
