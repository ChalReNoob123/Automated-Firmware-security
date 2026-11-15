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
  encrypted_at_rest BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE(org_id, sha256)
);

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
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS findings_fw_conf ON findings(firmware_id, confidence);
