-- SentinelForge migration 003 — findings usable without a firmware row.
-- API-reported findings (attack sims, manual triage) often have no analyzed
-- firmware record yet; the link stays optional, analysis fills it later.
ALTER TABLE findings ALTER COLUMN firmware_id DROP NOT NULL;
