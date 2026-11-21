-- SentinelForge migration 012 — analysis run ordering comes from a sequence.
--
-- 011 stamped each analysis finding with the start time of the run that produced
-- it, so a concurrent run's rows survived a prune. A timestamp is the wrong
-- ordering key though: two API instances can disagree about the clock, and a run
-- that finishes after a newer one has pruned could still write rows stamped with
-- its older time, re-creating findings the newer run had dropped.
--
-- Ordering is now monotonic and shared by the whole database:
--   * a run takes its value from `analysis_run_seq` when it is created;
--   * every analysis finding records `analysis_run_seq` — the run that produced it;
--   * a firmware row records `applied_run_seq` — the newest sequence whose
--     verdicts were applied.
--
-- That gives three guarantees the timestamps could not:
--   1. a prune removes only analysis rows with a LOWER sequence than the run
--      pruning them, so a concurrent run's findings always survive;
--   2. an upsert from a lower sequence cannot overwrite a newer verdict;
--   3. a run whose sequence is at or below the firmware's applied sequence skips
--      persistence entirely, so a late-finishing older run cannot re-create
--      findings a newer run pruned.
--
-- `analysis_run_at` stays as informational provenance for the evidence timeline;
-- nothing orders by it any more.

CREATE SEQUENCE IF NOT EXISTS analysis_run_seq;

ALTER TABLE findings ADD COLUMN IF NOT EXISTS analysis_run_seq BIGINT;

-- Backfill existing analysis rows in their old timestamp order, so the first
-- prune after the upgrade behaves the way the previous code did.
WITH ordered AS (
  SELECT id, row_number() OVER (ORDER BY analysis_run_at NULLS FIRST, created_at, id) AS seq
  FROM findings
)
UPDATE findings f
   SET analysis_run_seq = o.seq
  FROM ordered o
 WHERE f.id = o.id
   AND f.analysis_run_seq IS NULL;

ALTER TABLE firmware ADD COLUMN IF NOT EXISTS applied_run_seq BIGINT NOT NULL DEFAULT 0;

-- Continue ABOVE everything already used. is_called = true makes the next
-- nextval() return value + 1, and re-running this file can only move the counter
-- forward, never back.
SELECT setval(
  'analysis_run_seq',
  GREATEST(
    (SELECT last_value FROM analysis_run_seq),
    COALESCE((SELECT max(analysis_run_seq) FROM findings), 0),
    COALESCE((SELECT max(applied_run_seq) FROM firmware), 0)
  ),
  true
);
