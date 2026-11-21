-- SentinelForge migration 011 — concurrent-run-safe finding reconciliation.
--
-- A run prunes the analysis findings it no longer produces, but its keep list
-- only knows its own verdicts. Two runs on the same image therefore deleted each
-- other's rows during reconcile. Each analysis upsert now records the start time
-- of the run that produced it, and the prune skips anything stamped by a run that
-- started later, so a concurrent run's findings survive.
--
-- Rows written before this migration have no stamp; they are treated as stale for
-- any run (the same behaviour as before), which is what the next completed
-- analysis is expected to reconcile.
--
-- No index on the new column: the clarify by (org, firmware) is already served by
-- findings_fw_source and findings_fw_conf, and this only filters the handful of
-- rows for one image.

ALTER TABLE findings ADD COLUMN IF NOT EXISTS analysis_run_at TIMESTAMPTZ;
