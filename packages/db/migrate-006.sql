-- SentinelForge migration 006 — TOTP recovery codes (round 22). Idempotent.
-- Single-use login factors for a lost authenticator. Codes are stored
-- SHA-256-hashed of the NORMALIZED code (uppercase, dashes stripped);
-- plaintext is returned exactly once and never stored or retrievable.
-- A successful recovery login sets users.totp_enrolled = false (handled by
-- the API) so the next login re-enrolls a fresh authenticator.
CREATE TABLE IF NOT EXISTS recovery_codes (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  code_hash TEXT NOT NULL,
  used_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS recovery_codes_user ON recovery_codes(user_id);
