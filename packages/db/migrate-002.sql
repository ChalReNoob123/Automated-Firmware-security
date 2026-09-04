-- SentinelForge migration 002 — real auth + persistent runtime state.
-- Run after schema.sql (Supabase SQL editor or psql). Idempotent.

-- Users: login identity, lockout counters, TOTP enrollment
ALTER TABLE users ADD COLUMN IF NOT EXISTS username CITEXT UNIQUE;
ALTER TABLE users ADD COLUMN IF NOT EXISTS failed_attempts INT NOT NULL DEFAULT 0;
ALTER TABLE users ADD COLUMN IF NOT EXISTS locked_until BIGINT NOT NULL DEFAULT 0;
ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_enrolled BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE users ADD COLUMN IF NOT EXISTS last_login TIMESTAMPTZ;

-- Refresh-token rotation log (revoked instead of deleted → auditable)
CREATE TABLE IF NOT EXISTS refresh_tokens (
  jti TEXT PRIMARY KEY,
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  expires_at BIGINT NOT NULL,
  revoked BOOLEAN NOT NULL DEFAULT FALSE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS refresh_tokens_user ON refresh_tokens(user_id);

-- Access-token denylist (logout / role change); sweep expired rows on a schedule
CREATE TABLE IF NOT EXISTS revoked_access_tokens (
  jti TEXT PRIMARY KEY,
  expires_at BIGINT NOT NULL
);

-- Emulator sessions (replaces the in-memory Map; JSONB keeps the TS shape as-is)
CREATE TABLE IF NOT EXISTS emulator_sessions (
  id TEXT PRIMARY KEY,
  data JSONB NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Pipeline run queue (replaces the in-memory Map)
CREATE TABLE IF NOT EXISTS pipeline_runs (
  id TEXT PRIMARY KEY,
  data JSONB NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
