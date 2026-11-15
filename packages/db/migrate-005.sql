-- SentinelForge migration 005 — Account Security Center (round 20). Idempotent.
-- Distinguish WHY a refresh token is dead: replaying a ROTATED-OUT token is
-- the theft signal (family kill, as before); replaying an OWNER-REVOKED token
-- is the expected behavior of a revoked device (quiet 401, no family kill —
-- otherwise revoking one device would sign out the whole account).
ALTER TABLE refresh_tokens ADD COLUMN IF NOT EXISTS reason TEXT;
