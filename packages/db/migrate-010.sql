-- SentinelForge migration 010 — finding provenance.
--
-- Re-running analysis must drop verdicts the new run no longer produces, but it
-- must never delete a finding an analyst filed by hand. `source` records where a
-- row came from: 'analysis' rows are owned by the engine and reconciled per run;
-- 'manual' rows are left alone.
--
-- Existing rows default to 'manual' — the safe choice. Historical pipeline rows
-- are therefore never auto-deleted by the first re-run after this migration.
ALTER TABLE findings ADD COLUMN IF NOT EXISTS source TEXT NOT NULL DEFAULT 'manual';
CREATE INDEX IF NOT EXISTS findings_fw_source ON findings(firmware_id, source);
