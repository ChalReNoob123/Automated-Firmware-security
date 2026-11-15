-- SentinelForge migration 004 — tenant isolation for runtime state.
-- Emulator sessions and pipeline runs were addressable by id alone, which allowed
-- cross-tenant reads (IDOR). org_id is now mandatory on both tables.
ALTER TABLE emulator_sessions ADD COLUMN IF NOT EXISTS org_id TEXT NOT NULL DEFAULT '';
ALTER TABLE pipeline_runs ADD COLUMN IF NOT EXISTS org_id TEXT NOT NULL DEFAULT '';
CREATE INDEX IF NOT EXISTS emulator_sessions_org ON emulator_sessions(org_id);
CREATE INDEX IF NOT EXISTS pipeline_runs_org ON pipeline_runs(org_id);
