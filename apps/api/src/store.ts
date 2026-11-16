import bcrypt from 'bcryptjs';
import { createHash, randomUUID, timingSafeEqual } from 'node:crypto';
import { pool, query } from './db.js';
import type { Role } from './auth.js';

// Persistence with a memory fallback: every function runs against Postgres when
// DATABASE_URL is set, otherwise against in-process Maps (dev/test). Callers never
// branch — the swap is transparent, and Supabase is just a DATABASE_URL away.

export type UserRow = {
  id: string;
  org_id: string;
  email: string;
  username: string;
  password_hash: string;
  role: Role;
  totp_secret: string | null;
  totp_enrolled: boolean;
  failed_attempts: number;
  locked_until: number;
  last_login: string | null;
};

const mem = {
  orgs: new Map<string, { id: string; name: string }>(),
  users: new Map<string, UserRow>(),
  refresh: new Map<string, RefreshRecord>(),
  recovery: new Map<string, RecoveryRow>(),
  revokedAccess: new Map<string, number>(),
  devices: new Map<string, DeviceRow>(),
  attestations: new Map<string, AttestationRow>(),
  sessions: new Map<string, { data: unknown; updated: number }>(),
  runs: new Map<string, { data: unknown; updated: number }>(),
};

export const hashPassword = (pw: string) => bcrypt.hash(pw, 12);
export const verifyPassword = (pw: string, hash: string) => bcrypt.compare(pw, hash);

export async function createOrg(name: string): Promise<{ id: string }> {
  if (pool) {
    const r = await pool.query(`INSERT INTO orgs (name) VALUES ($1) RETURNING id`, [name]);
    return { id: r.rows[0].id };
  }
  const id = randomUUID();
  mem.orgs.set(id, { id, name });
  return { id };
}

export async function findUserByIdentifier(identifier: string): Promise<UserRow | undefined> {
  const needle = identifier.toLowerCase();
  if (pool) {
    const r = await pool.query(`SELECT * FROM users WHERE lower(username)=$1 OR lower(email)=$1 LIMIT 1`, [needle]);
    return r.rows[0] as UserRow | undefined;
  }
  return [...mem.users.values()].find((u) => u.username.toLowerCase() === needle || u.email.toLowerCase() === needle);
}

export async function findUserById(id: string): Promise<UserRow | undefined> {
  if (pool) {
    const r = await pool.query(`SELECT * FROM users WHERE id=$1`, [id]);
    return r.rows[0] as UserRow | undefined;
  }
  return mem.users.get(id);
}

export async function createUser(input: { orgId: string; email: string; username: string; passwordHash: string; role: Role }): Promise<UserRow> {
  if (pool) {
    const r = await pool.query(
      `INSERT INTO users (org_id, email, username, password_hash, role) VALUES ($1,$2,$3,$4,$5) RETURNING *`,
      [input.orgId, input.email, input.username, input.passwordHash, input.role]
    );
    return r.rows[0] as UserRow;
  }
  const u: UserRow = {
    id: randomUUID(),
    org_id: input.orgId,
    email: input.email,
    username: input.username,
    password_hash: input.passwordHash,
    role: input.role,
    totp_secret: null,
    totp_enrolled: false,
    failed_attempts: 0,
    locked_until: 0,
    last_login: null,
  };
  mem.users.set(u.id, u);
  return u;
}

export async function updateUser(id: string, patch: Partial<UserRow>): Promise<void> {
  if (pool) {
    const keys = Object.keys(patch) as (keyof UserRow)[];
    if (!keys.length) return;
    const sets = keys.map((k, i) => `${k}=$${i + 2}`).join(', ');
    await pool.query(`UPDATE users SET ${sets} WHERE id=$1`, [id, ...keys.map((k) => patch[k])]);
    return;
  }
  const u = mem.users.get(id);
  if (u) mem.users.set(id, { ...u, ...patch });
}

export async function storeRefresh(jti: string, userId: string, expiresAt: number): Promise<void> {
  if (pool) {
    await pool.query(`INSERT INTO refresh_tokens (jti, user_id, expires_at) VALUES ($1,$2,$3)`, [jti, userId, expiresAt]);
    return;
  }
  mem.refresh.set(jti, { user_id: userId, expires_at: expiresAt, revoked: false, created_at: Date.now() });
}

// Why a token is dead — the refresh route treats the two VERY differently:
//   'rotated' → normal rotation; replaying it is the THEFT signal (family kill)
//   'revoked' → owner action (device revoke / logout / password rotation);
//               replaying it is expected from a revoked device → quiet 401
export type RefreshReason = 'rotated' | 'revoked';
export type RefreshRecord = { user_id: string; expires_at: number; revoked: boolean; created_at: number; reason?: RefreshReason };

export async function findRefresh(jti: string): Promise<RefreshRecord | undefined> {
  if (pool) {
    const r = await pool.query(`SELECT user_id, expires_at, revoked, created_at, reason FROM refresh_tokens WHERE jti=$1`, [jti]);
    if (!r.rows[0]) return undefined;
    const row = r.rows[0];
    return {
      user_id: row.user_id,
      expires_at: Number(row.expires_at),
      revoked: row.revoked,
      created_at: row.created_at ? new Date(row.created_at).getTime() : Date.now(),
      reason: row.reason ?? undefined,
    };
  }
  return mem.refresh.get(jti);
}

export async function revokeRefresh(jti: string, reason: RefreshReason = 'rotated'): Promise<void> {
  if (pool) {
    await pool.query(`UPDATE refresh_tokens SET revoked=TRUE, reason=$2 WHERE jti=$1`, [jti, reason]);
    return;
  }
  const r = mem.refresh.get(jti);
  if (r) {
    r.revoked = true;
    r.reason = reason;
  }
}

// Kill every live refresh token for a user (owner action: password rotation,
// revoke-all, re-enrollment). `exceptJti` keeps one session alive (password
// rotation keeps the caller signed in). Returns how many sessions were killed.
export async function revokeAllRefreshForUser(userId: string, exceptJti?: string): Promise<number> {
  if (pool) {
    const r = await pool.query(`UPDATE refresh_tokens SET revoked=TRUE, reason='revoked' WHERE user_id=$1 AND revoked=FALSE AND jti <> COALESCE($2,'')`, [userId, exceptJti ?? '']);
    return r.rowCount ?? 0;
  }
  let n = 0;
  for (const [jti, r] of mem.refresh.entries()) {
    if (r.user_id === userId && !r.revoked && jti !== exceptJti) {
      r.revoked = true;
      r.reason = 'revoked';
      n++;
    }
  }
  return n;
}

// ── Session inventory (Account Security Center) ──
// One row per live refresh token for a user. The jti alone authorizes nothing
// (tokens are signed server-side), so exposing it to the authenticated owner
// is safe and is what makes per-device revocation possible.
export type ActiveRefresh = { jti: string; expires_at: number; created_at: number };

export async function listActiveRefreshForUser(userId: string): Promise<ActiveRefresh[]> {
  if (pool) {
    const r = await pool.query(
      `SELECT jti, expires_at, created_at FROM refresh_tokens WHERE user_id=$1 AND revoked=FALSE AND expires_at > $2 ORDER BY created_at DESC`,
      [userId, Date.now()]
    );
    return r.rows.map((row: { jti: string; expires_at: string | number; created_at: string | Date }) => ({
      jti: row.jti,
      expires_at: Number(row.expires_at),
      created_at: new Date(row.created_at).getTime(),
    }));
  }
  const now = Date.now();
  return [...mem.refresh.entries()]
    .filter(([, r]) => r.user_id === userId && !r.revoked && r.expires_at > now)
    .map(([jti, r]) => ({ jti, expires_at: r.expires_at, created_at: r.created_at }))
    .sort((a, b) => b.created_at - a.created_at);
}

// Revoke exactly one session, only if it belongs to this user (self-scoped —
// the route never accepts a jti across tenants). Owner action → 'revoked'.
export async function revokeRefreshForUser(userId: string, jti: string): Promise<boolean> {
  if (pool) {
    const r = await pool.query(`UPDATE refresh_tokens SET revoked=TRUE, reason='revoked' WHERE jti=$1 AND user_id=$2 AND revoked=FALSE`, [jti, userId]);
    return (r.rowCount ?? 0) > 0;
  }
  const rec = mem.refresh.get(jti);
  if (!rec || rec.user_id !== userId || rec.revoked) return false;
  rec.revoked = true;
  rec.reason = 'revoked';
  return true;
}

// ── TOTP recovery codes (round 22) ──
// Single-use login factors for a LOST authenticator. Stored SHA-256-hashed
// (high-entropy random codes — a slow hash buys nothing against an offline
// crack of a 50-bit random value, and online guessing is bounded by the grind
// cap + IP limiter; bcrypt stays reserved for the password class of secrets).
// Plaintext is returned exactly once (enrollment / regeneration) and is never
// retrievable afterwards. A successful recovery login sets totp_enrolled=false
// so the NEXT login re-enrolls from scratch: password knowledge + one unused
// code always recovers the account.
export type RecoveryRow = { id: string; user_id: string; code_hash: string; used_at: number | null };

export async function replaceRecoveryCodes(userId: string, hashes: string[]): Promise<void> {
  if (pool) {
    await pool.query(`DELETE FROM recovery_codes WHERE user_id=$1`, [userId]);
    for (const h of hashes) await pool.query(`INSERT INTO recovery_codes (user_id, code_hash) VALUES ($1,$2)`, [userId, h]);
    return;
  }
  for (const [id, r] of [...mem.recovery]) if (r.user_id === userId) mem.recovery.delete(id);
  for (const h of hashes) {
    const id = randomUUID();
    mem.recovery.set(id, { id, user_id: userId, code_hash: h, used_at: null });
  }
}

export async function countUnusedRecoveryCodes(userId: string): Promise<number> {
  if (pool) {
    const r = await pool.query(`SELECT COUNT(*)::int AS n FROM recovery_codes WHERE user_id=$1 AND used_at IS NULL`, [userId]);
    return r.rows[0]?.n ?? 0;
  }
  let n = 0;
  for (const r of mem.recovery.values()) if (r.user_id === userId && r.used_at === null) n++;
  return n;
}

// SHA-256 of the NORMALIZED code (uppercase, dashes stripped) — callers must
// normalize input the same way before calling.
const digest = (normalized: string) => createHash('sha256').update(normalized, 'utf8').digest();

function hashMatches(storedHex: string, normalized: string): boolean {
  const a = Buffer.from(storedHex, 'hex');
  const b = digest(normalized);
  return a.length === b.length && timingSafeEqual(a, b);
}

// Compare against every unused code; the first match is consumed. Returns
// whether it matched and how many unused codes remain (the consuming attempt
// is counted out of that number).
export async function useRecoveryCode(userId: string, normalized: string): Promise<{ used: boolean; remaining: number }> {
  if (pool) {
    const r = await pool.query(`SELECT id, code_hash FROM recovery_codes WHERE user_id=$1 AND used_at IS NULL`, [userId]);
    const rows = r.rows as Array<{ id: string; code_hash: string }>;
    for (const row of rows) {
      if (hashMatches(row.code_hash, normalized)) {
        await pool.query(`UPDATE recovery_codes SET used_at=now() WHERE id=$1`, [row.id]);
        return { used: true, remaining: Math.max(0, rows.length - 1) };
      }
    }
    return { used: false, remaining: rows.length };
  }
  const unused = [...mem.recovery.values()].filter((r) => r.user_id === userId && r.used_at === null);
  for (const r of unused) {
    if (hashMatches(r.code_hash, normalized)) {
      r.used_at = Date.now();
      return { used: true, remaining: unused.length - 1 };
    }
  }
  return { used: false, remaining: unused.length };
}

export async function revokeAccess(jti: string, expiresAtMs: number): Promise<void> {
  if (pool) {
    await pool.query(`INSERT INTO revoked_access_tokens (jti, expires_at) VALUES ($1,$2) ON CONFLICT DO NOTHING`, [jti, expiresAtMs]);
    return;
  }
  mem.revokedAccess.set(jti, expiresAtMs);
}

export async function isAccessRevoked(jti: string): Promise<boolean> {
  if (pool) {
    const r = await pool.query(`SELECT 1 FROM revoked_access_tokens WHERE jti=$1`, [jti]);
    return r.rowCount !== 0;
  }
  return mem.revokedAccess.has(jti);
}

export function usingPostgres(): boolean {
  return pool !== null;
}

export async function dbHealth(): Promise<{ postgres: boolean }> {
  if (!pool) return { postgres: false };
  await query(`SELECT 1`);
  return { postgres: true };
}

// ── Devices / attestations (real rows, real UUIDs) ──
export type DeviceRow = { id: string; org_id: string; name: string; transport: string; fingerprint: string | null; created_at: string };
export type AttestationRow = { id: string; org_id: string; device_id: string; user_id: string; scope: string; legal_basis: string; created_at: string };

export async function createDevice(input: { orgId: string; name: string; transport: string; fingerprint?: string }): Promise<DeviceRow> {
  if (pool) {
    const r = await pool.query(
      `INSERT INTO devices (org_id, name, transport, fingerprint) VALUES ($1,$2,$3,$4) RETURNING id, org_id, name, transport, fingerprint, created_at`,
      [input.orgId, input.name, input.transport, input.fingerprint ?? null]
    );
    return r.rows[0];
  }
  const d: DeviceRow = { id: randomUUID(), org_id: input.orgId, name: input.name, transport: input.transport, fingerprint: input.fingerprint ?? null, created_at: new Date().toISOString() };
  mem.devices.set(d.id, d);
  return d;
}

export async function listDevices(orgId: string): Promise<DeviceRow[]> {
  if (pool) {
    const r = await pool.query(`SELECT id, org_id, name, transport, fingerprint, created_at FROM devices WHERE org_id=$1 ORDER BY created_at DESC LIMIT 200`, [orgId]);
    return r.rows;
  }
  return [...mem.devices.values()].filter((d) => d.org_id === orgId);
}

export async function createAttestation(input: { orgId: string; deviceId: string; userId: string; scope: string; legalBasis: string }): Promise<AttestationRow> {
  if (pool) {
    const dev = await pool.query(`SELECT id FROM devices WHERE id=$1 AND org_id=$2`, [input.deviceId, input.orgId]);
    if (dev.rowCount === 0) throw new Error('device not found in your org');
    const r = await pool.query(
      `INSERT INTO attestations (org_id, device_id, user_id, scope, legal_basis) VALUES ($1,$2,$3,$4,$5) RETURNING id, org_id, device_id, user_id, scope, legal_basis, created_at`,
      [input.orgId, input.deviceId, input.userId, input.scope, input.legalBasis]
    );
    return r.rows[0];
  }
  if (!mem.devices.has(input.deviceId)) throw new Error('device not found in your org');
  const a: AttestationRow = { id: randomUUID(), org_id: input.orgId, device_id: input.deviceId, user_id: input.userId, scope: input.scope, legal_basis: input.legalBasis, created_at: new Date().toISOString() };
  mem.attestations.set(a.id, a);
  return a;
}

// The gate: an attestation id is valid only if the row exists in the caller's org.
export async function findAttestation(id: string, orgId: string): Promise<AttestationRow | undefined> {
  if (pool) {
    const r = await pool.query(`SELECT * FROM attestations WHERE id=$1 AND org_id=$2`, [id, orgId]);
    return r.rows[0];
  }
  const a = mem.attestations.get(id);
  return a?.org_id === orgId ? a : undefined;
}

// ── JSONB document stores: emulator sessions + pipeline runs ──
// TENANT-SCOPED: every read/write filters by org_id. A session/run id alone is
// NOT an authorization proof — without this, any signed-in org could read
// another tenant's twin (cross-tenant IDOR, now regression-tested).
async function docPut(table: 'emulator_sessions' | 'pipeline_runs', map: Map<string, { data: unknown; updated: number }>, orgId: string, id: string, data: unknown): Promise<void> {
  if (pool) {
    await pool.query(
      `INSERT INTO ${table} (id, org_id, data, updated_at) VALUES ($1,$2,$3,now())
       ON CONFLICT (id) DO UPDATE SET data=$3, org_id=$2, updated_at=now()`,
      [id, orgId, JSON.stringify(data)]
    );
    return;
  }
  map.set(id, { data: { ...(data as Record<string, unknown>), org_id: orgId }, updated: Date.now() });
}

async function docGet<T>(table: 'emulator_sessions' | 'pipeline_runs', map: Map<string, { data: unknown; updated: number }>, orgId: string, id: string): Promise<T | undefined> {
  if (pool) {
    const r = await pool.query(`SELECT data FROM ${table} WHERE id=$1 AND org_id=$2`, [id, orgId]);
    return r.rows[0]?.data as T | undefined;
  }
  const row = map.get(id)?.data as (T & { org_id?: string }) | undefined;
  if (!row || row.org_id !== orgId) return undefined;
  return row;
}

export const putSession = async (orgId: string, id: string, data: unknown) => {
  // Memory fallback is bounded: oldest session evicted past 200 (pg side is
  // unbounded by design — retention policy owns cleanup there).
  if (!pool && !mem.sessions.has(id)) {
    while (mem.sessions.size >= 200) {
      const oldest = mem.sessions.keys().next().value as string | undefined;
      if (!oldest) break;
      mem.sessions.delete(oldest);
    }
  }
  return docPut('emulator_sessions', mem.sessions, orgId, id, data);
};

// ── Findings (analyst queue persistence; mirrors packages/db findings table) ──
export type FindingRow = {
  id: string;
  org_id: string;
  firmware_id: string | null;
  title: string;
  emb3d: string | null;
  cvss_v4: number | null;
  epss: number | null;
  ssvc: string | null;
  confidence: 'Confirmed' | 'Likely' | 'Unconfirmed';
  corroborating_engines: string[];
  why_flagged: string | null;
  snapshot_ref: string | null;
  created_at: string;
};

export type NewFinding = {
  orgId: string;
  firmwareId?: string;
  title: string;
  emb3d?: string;
  cvss?: number;
  epss?: number;
  ssvc?: string;
  confidence: FindingRow['confidence'];
  engines: string[];
  why?: string;
  snapshotRef?: string;
};

const findingMem = new Map<string, FindingRow[]>();

export async function createFinding(f: NewFinding): Promise<FindingRow> {
  if (pool) {
    const r = await pool.query(
      `INSERT INTO findings (org_id, firmware_id, title, emb3d, cvss_v4, epss, ssvc, confidence, corroborating_engines, why_flagged, snapshot_ref)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
       RETURNING id, org_id, firmware_id, title, emb3d, cvss_v4, epss, ssvc, confidence, corroborating_engines, why_flagged, snapshot_ref, created_at`,
      [f.orgId, f.firmwareId ?? null, f.title, f.emb3d ?? null, f.cvss ?? null, f.epss ?? null, f.ssvc ?? null, f.confidence, f.engines, f.why ?? null, f.snapshotRef ?? null]
    );
    return r.rows[0];
  }
  const row: FindingRow = {
    id: randomUUID(), org_id: f.orgId, firmware_id: f.firmwareId ?? null, title: f.title,
    emb3d: f.emb3d ?? null, cvss_v4: f.cvss ?? null, epss: f.epss ?? null, ssvc: f.ssvc ?? null,
    confidence: f.confidence, corroborating_engines: f.engines, why_flagged: f.why ?? null,
    snapshot_ref: f.snapshotRef ?? null, created_at: new Date().toISOString(),
  };
  const list = findingMem.get(f.orgId) ?? [];
  list.unshift(row);
  findingMem.set(f.orgId, list.slice(0, 1000));
  return row;
}

export async function listFindings(orgId: string, opts: { confidence?: string; limit?: number } = {}): Promise<FindingRow[]> {
  const limit = Math.min(Math.max(opts.limit ?? 100, 1), 500);
  if (pool) {
    const r = await pool.query(
      `SELECT id, org_id, firmware_id, title, emb3d, cvss_v4, epss, ssvc, confidence, corroborating_engines, why_flagged, snapshot_ref, created_at
       FROM findings WHERE org_id=$1 ${opts.confidence ? 'AND confidence=$2' : ''} ORDER BY created_at DESC LIMIT $${opts.confidence ? 3 : 2}`,
      opts.confidence ? [orgId, opts.confidence, limit] : [orgId, limit]
    );
    return r.rows;
  }
  const list = findingMem.get(orgId) ?? [];
  return (opts.confidence ? list.filter((f) => f.confidence === opts.confidence) : list).slice(0, limit);
}

export async function deleteFinding(id: string, orgId: string): Promise<boolean> {
  if (pool) {
    const r = await pool.query(`DELETE FROM findings WHERE id=$1 AND org_id=$2`, [id, orgId]);
    return (r.rowCount ?? 0) > 0;
  }
  const list = findingMem.get(orgId) ?? [];
  const next = list.filter((f) => f.id !== id);
  findingMem.set(orgId, next);
  return next.length !== list.length;
}
export const getSessionDoc = <T>(orgId: string, id: string) => docGet<T>('emulator_sessions', mem.sessions, orgId, id);
export const putRun = (orgId: string, id: string, data: unknown) => docPut('pipeline_runs', mem.runs, orgId, id, data);
export const getRunDoc = <T>(orgId: string, id: string) => docGet<T>('pipeline_runs', mem.runs, orgId, id);
