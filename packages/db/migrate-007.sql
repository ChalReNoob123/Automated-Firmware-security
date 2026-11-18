-- SentinelForge migration 007 — team management (round 29).
-- Run after 006 (Supabase SQL editor or psql). Idempotent.
-- Audit rows can now name the TARGET of an action (role change / member
-- removal), not just the actor — forensics needs both sides of the pair.
ALTER TABLE auth_audit ADD COLUMN IF NOT EXISTS target_id UUID REFERENCES users(id) ON DELETE SET NULL;
