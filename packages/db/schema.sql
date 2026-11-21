-- SentinelForge v3 — Module 1 Postgres schema
-- Roles: Owner / Admin / Analyst / Viewer / Auditor (RBAC)
-- Includes: orgs, users, auth audit, devices, attestation gate, firmware, SBOM refs, findings with consensus badges.

CREATE EXTENSION IF NOT EXISTS "pgcrypto";
CREATE EXTENSION IF NOT EXISTS "citext"; -- required by users.email (Supabase: enable in SQL editor, runs fine)

DO $$ BEGIN CREATE TYPE org_role AS ENUM ('Owner','Admin','Analyst','Viewer','Auditor'); EXCEPTION WHEN duplicate_object THEN NULL; END $$;
DO $$ BEGIN CREATE TYPE confidence AS ENUM ('Confirmed','Likely','Unconfirmed'); EXCEPTION WHEN duplicate_object THEN NULL; END $$;

CREATE TABLE IF NOT EXISTS orgs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS users (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
  email CITEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  role org_role NOT NULL DEFAULT 'Analyst',
  totp_secret TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS auth_audit (
  id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  org_id UUID REFERENCES orgs(id) ON DELETE SET NULL,
  user_id UUID REFERENCES users(id) ON DELETE SET NULL,
  event TEXT NOT NULL, -- login, logout, refresh, totp_fail, sso, lockout
  ip INET,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS auth_audit_org_ts ON auth_audit(org_id, created_at DESC);

-- Module 3 device connection: mandatory logged authorization-attestation gate before any test.
CREATE TABLE IF NOT EXISTS devices (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  transport TEXT NOT NULL, -- usb, wifi, ble, zigbee, zwave, uart, jtag
  fingerprint TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS attestations (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
  device_id UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  user_id UUID NOT NULL REFERENCES users(id),
  scope TEXT NOT NULL,       -- e.g. 'firmware-extract,emulate,fuzz'
  legal_basis TEXT NOT NULL, -- ownership / written permission ref
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS firmware (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
  device_id UUID REFERENCES devices(id) ON DELETE SET NULL,
  version TEXT NOT NULL,
  sha256 CHAR(64) NOT NULL,
  bytes BIGINT NOT NULL DEFAULT 0,
  -- Set from what actually happened to the bytes: true only when the blob was
  -- sealed with AES-256-GCM (FIRMWARE_ENC_KEY configured), never assumed.
  encrypted_at_rest BOOLEAN NOT NULL DEFAULT FALSE,
  -- Newest analysis sequence whose verdicts were applied to this image. A run
  -- whose sequence is lower finishing later writes nothing, so it cannot
  -- re-create findings a newer run already pruned (see migrate-012).
  applied_run_seq BIGINT NOT NULL DEFAULT 0,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE(org_id, sha256)
);

-- The uploaded image itself, split out so list queries never drag megabytes.
CREATE TABLE IF NOT EXISTS firmware_blobs (
  firmware_id UUID PRIMARY KEY REFERENCES firmware(id) ON DELETE CASCADE,
  data BYTEA NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Analysis run ordering. Runs take a value here when they are created, every
-- analysis finding records the value of the run that produced it, and
-- reconciliation compares those values instead of wall-clock timestamps. A
-- sequence is global to the database, so two API instances cannot disagree
-- about which run is newer (see migrate-012).
CREATE SEQUENCE IF NOT EXISTS analysis_run_seq;

CREATE TABLE IF NOT EXISTS findings (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
  firmware_id UUID NOT NULL REFERENCES firmware(id) ON DELETE CASCADE,
  title TEXT NOT NULL,
  emb3d TEXT,                 -- MITRE EMB3D tag
  cvss_v4 NUMERIC(3,1),
  epss NUMERIC(5,4),
  ssvc TEXT,
  confidence confidence NOT NULL DEFAULT 'Unconfirmed',
  corroborating_engines TEXT[] NOT NULL DEFAULT '{}', -- e.g. '{symbolic,fuzz}'
  why_flagged TEXT,           -- explainability trace
  snapshot_ref TEXT,          -- emulator snapshot + input trace for repro
  -- 'analysis' rows are owned by the engine and reconciled each run;
  -- 'manual' rows belong to an analyst and are never auto-deleted
  source TEXT NOT NULL DEFAULT 'manual',
  -- start time of the run that produced this row — informational, shown on the
  -- evidence timeline. Ordering no longer uses it: clocks drift across API
  -- instances, and a late run could resurrect findings a newer run pruned.
  analysis_run_at TIMESTAMPTZ,
  -- position of the producing run in analysis_run_seq — THE reconcile ordering
  -- key. Pruning removes only lower values, and an older run cannot overwrite a
  -- newer verdict.
  analysis_run_seq BIGINT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS findings_fw_conf ON findings(firmware_id, confidence);
-- One finding per (org, firmware, title): a re-run updates the verdict in place
-- instead of appending duplicates, and concurrent runs cannot both insert.
CREATE UNIQUE INDEX IF NOT EXISTS findings_org_fw_title
  ON findings (org_id, firmware_id, title)
  WHERE firmware_id IS NOT NULL;
