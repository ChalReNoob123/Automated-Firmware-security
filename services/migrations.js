/**
 * Database Migration System — Append-only, versioned schema migrations.
 * Tracks applied migrations in a `_migrations` table and applies them in order.
 * Each migration is idempotent (uses IF NOT EXISTS / IF EXISTS guards).
 */

/** Migration definitions — add new migrations at the bottom, never modify existing ones */
const MIGRATIONS = [
  {
    version: 1,
    name: 'initial_schema',
    description: 'Core tables for users, logs, metrics, segments, connections, alerts, refresh tokens',
    up: `
      -- This migration is a no-op since the tables were already created in backend.js inline.
      -- It exists to establish the migration baseline.
      SELECT 1;
    `,
  },
  {
    version: 2,
    name: 'scanner_tables',
    description: 'System scanner session and findings tables with indexes',
    up: `
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
    `,
  },
  {
    version: 3,
    name: 'security_audit_log',
    description: 'Append-only security audit log for compliance and forensics',
    up: `
      CREATE TABLE IF NOT EXISTS security_audit_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp INTEGER NOT NULL DEFAULT (unixepoch() * 1000),
        event_type TEXT NOT NULL,
        severity TEXT NOT NULL DEFAULT 'info',
        actor_id INTEGER,
        actor_username TEXT,
        actor_ip TEXT,
        resource TEXT,
        action TEXT,
        outcome TEXT DEFAULT 'success',
        details TEXT,
        session_id TEXT,
        user_agent TEXT
      );
      CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON security_audit_log(timestamp DESC);
      CREATE INDEX IF NOT EXISTS idx_audit_event ON security_audit_log(event_type);
      CREATE INDEX IF NOT EXISTS idx_audit_actor ON security_audit_log(actor_id);
    `,
  },
  {
    version: 4,
    name: 'oauth_providers',
    description: 'OAuth provider configuration and linked accounts',
    up: `
      CREATE TABLE IF NOT EXISTS oauth_accounts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        provider TEXT NOT NULL,
        provider_user_id TEXT NOT NULL,
        provider_email TEXT,
        access_token_enc TEXT,
        refresh_token_enc TEXT,
        token_expires_at INTEGER,
        profile_data TEXT,
        linked_at INTEGER NOT NULL DEFAULT (unixepoch() * 1000),
        last_used INTEGER,
        UNIQUE(provider, provider_user_id),
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
      );
      CREATE INDEX IF NOT EXISTS idx_oauth_user ON oauth_accounts(user_id);
      CREATE INDEX IF NOT EXISTS idx_oauth_provider ON oauth_accounts(provider, provider_user_id);
    `,
  },
  {
    version: 5,
    name: 'session_management',
    description: 'Active session tracking for multi-device management',
    up: `
      CREATE TABLE IF NOT EXISTS active_sessions (
        id TEXT PRIMARY KEY,
        user_id INTEGER NOT NULL,
        device_info TEXT,
        ip_address TEXT,
        user_agent TEXT,
        created_at INTEGER NOT NULL DEFAULT (unixepoch() * 1000),
        last_active INTEGER NOT NULL DEFAULT (unixepoch() * 1000),
        expires_at INTEGER NOT NULL,
        revoked INTEGER DEFAULT 0,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
      );
      CREATE INDEX IF NOT EXISTS idx_sessions_user ON active_sessions(user_id);
      CREATE INDEX IF NOT EXISTS idx_sessions_expires ON active_sessions(expires_at);
    `,
  },
  {
    version: 6,
    name: 'ml_model_registry',
    description: 'On-device ML model version tracking and A/B test assignments',
    up: `
      CREATE TABLE IF NOT EXISTS ml_models (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        version TEXT NOT NULL,
        description TEXT,
        model_type TEXT NOT NULL DEFAULT 'tensorflow',
        file_path TEXT,
        file_size INTEGER,
        accuracy REAL,
        status TEXT DEFAULT 'active',
        config TEXT,
        created_at INTEGER NOT NULL DEFAULT (unixepoch() * 1000),
        deployed_at INTEGER,
        UNIQUE(name, version)
      );
      CREATE TABLE IF NOT EXISTS ml_predictions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        model_id TEXT NOT NULL,
        input_hash TEXT,
        prediction TEXT,
        confidence REAL,
        latency_ms INTEGER,
        created_at INTEGER NOT NULL DEFAULT (unixepoch() * 1000),
        FOREIGN KEY (model_id) REFERENCES ml_models(id)
      );
      CREATE INDEX IF NOT EXISTS idx_ml_predictions_model ON ml_predictions(model_id);
      CREATE INDEX IF NOT EXISTS idx_ml_predictions_ts ON ml_predictions(created_at DESC);
    `,
  },
];

/**
 * Run all pending migrations on the given database.
 * @param {object} db - better-sqlite3/node:sqlite DatabaseSync instance
 * @param {object} logger - pino or console logger
 * @returns {{ applied: number, current: number }}
 */
export function runMigrations(db, logger) {
  // Ensure migration tracking table exists
  db.exec(`
    CREATE TABLE IF NOT EXISTS _migrations (
      version INTEGER PRIMARY KEY,
      name TEXT NOT NULL,
      description TEXT,
      applied_at INTEGER NOT NULL DEFAULT (unixepoch() * 1000),
      checksum TEXT
    );
  `);

  const applied = db.prepare('SELECT MAX(version) as v FROM _migrations').get();
  const currentVersion = applied?.v || 0;
  let appliedCount = 0;

  for (const migration of MIGRATIONS) {
    if (migration.version <= currentVersion) continue;

    logger.info({ version: migration.version, name: migration.name }, `Applying migration v${migration.version}: ${migration.name}`);

    try {
      db.exec(migration.up);
      db.prepare('INSERT INTO _migrations (version, name, description, applied_at) VALUES (?, ?, ?, ?)')
        .run(migration.version, migration.name, migration.description, Date.now());
      appliedCount++;
      logger.info({ version: migration.version }, `Migration v${migration.version} applied successfully`);
    } catch (err) {
      logger.error({ version: migration.version, error: err.message }, `Migration v${migration.version} FAILED`);
      throw err; // Stop on first failure
    }
  }

  const finalVersion = currentVersion + appliedCount;
  if (appliedCount > 0) {
    logger.info({ applied: appliedCount, current: finalVersion }, 'All migrations applied');
  } else {
    logger.info({ current: finalVersion }, 'Database schema is up to date');
  }

  return { applied: appliedCount, current: finalVersion };
}

/** List all migrations and their status */
export function getMigrationStatus(db) {
  db.exec(`CREATE TABLE IF NOT EXISTS _migrations (version INTEGER PRIMARY KEY, name TEXT NOT NULL, description TEXT, applied_at INTEGER NOT NULL DEFAULT (unixepoch() * 1000), checksum TEXT);`);
  const applied = db.prepare('SELECT * FROM _migrations ORDER BY version').all();
  const appliedVersions = new Set(applied.map(m => m.version));
  return MIGRATIONS.map(m => ({
    version: m.version,
    name: m.name,
    description: m.description,
    applied: appliedVersions.has(m.version),
    appliedAt: applied.find(a => a.version === m.version)?.applied_at || null,
  }));
}
