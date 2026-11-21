-- SentinelForge migration 009 — one finding per (org, firmware, title).
--
-- Re-running analysis on an unchanged image used to insert a second copy of
-- every finding. The application now upserts by (org_id, firmware_id, title);
-- this index makes that guarantee hold under concurrent runs too.
--
-- Clear any duplicates first (keep the oldest row so existing links stay valid),
-- otherwise the unique index cannot be created on an affected database.
DELETE FROM findings f
USING findings g
WHERE f.id <> g.id
  AND f.org_id = g.org_id
  AND f.firmware_id = g.firmware_id
  AND f.title = g.title
  AND f.firmware_id IS NOT NULL
  AND f.created_at > g.created_at;

CREATE UNIQUE INDEX IF NOT EXISTS findings_org_fw_title
  ON findings (org_id, firmware_id, title)
  WHERE firmware_id IS NOT NULL;

-- Rows uploaded before encryption existed carry encrypted_at_rest=true from the
-- schema default while their blob is plaintext. Correct the flag: a blob is
-- sealed only when it starts with the 'SFENC1' magic written by the API.
UPDATE firmware f
   SET encrypted_at_rest = (substring(b.data from 1 for 6) = '\x5346454e4331'::bytea)
  FROM firmware_blobs b
 WHERE b.firmware_id = f.id;
