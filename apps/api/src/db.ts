import { Pool } from 'pg';
import dotenv from 'dotenv';

dotenv.config(); // module-load order: pool options must see .env before index.ts body runs

// Production: Postgres (packages/db/schema.sql). Dev without DATABASE_URL: in-memory stub
// so `turbo dev` works before infra is up. All queries go through this module so the
// swap is transparent.
const DATABASE_URL = process.env.DATABASE_URL ?? '';

// Managed Postgres (Supabase/Neon/Render) mandates TLS; localhost dev does not.
// rejectUnauthorized:false matches Supabase pooler certs (shared CA chain).
const needsTLS = DATABASE_URL !== '' && !/localhost|127\.0\.0\.1/.test(DATABASE_URL);

export const pool = DATABASE_URL
  ? new Pool({ connectionString: DATABASE_URL, ...(needsTLS ? { ssl: { rejectUnauthorized: false } } : {}) })
  : null;

type Row = Record<string, unknown>;
const mem: Record<string, Row[]> = { users: [], orgs: [], auth_audit: [], attestations: [], devices: [] };

export async function query<T extends Row = Row>(text: string, params: unknown[] = []): Promise<{ rows: T[] }> {
  if (pool) {
    const r = await pool.query(text, params as unknown[]);
    return { rows: r.rows as T[] };
  }
  // Minimal stub for local dev: support the INSERT/SELECT shapes used by auth + attestation routes
  if (/INSERT INTO auth_audit/i.test(text)) {
    mem.auth_audit.push({
      org_id: params[0],
      user_id: params[1],
      event: params[2],
      ip: params[3],
      created_at: new Date().toISOString(),
    } as Row);
    return { rows: [] };
  }
  if (/FROM auth_audit/i.test(text)) {
    const rows = [...mem.auth_audit]
      .sort((a, b) => String(b.created_at).localeCompare(String(a.created_at)))
      .slice(0, 100);
    return { rows: rows as T[] };
  }
  return { rows: [] };
}

export async function audit(event: string, meta: { orgId?: string; userId?: string; ip?: string }) {
  const at = new Date().toISOString();
  await query(`INSERT INTO auth_audit (org_id, user_id, event, ip) VALUES ($1,$2,$3,$4)`, [
    meta.orgId ?? null,
    meta.userId ?? null,
    event,
    meta.ip ?? null,
  ]);
  // Audit shipping: best-effort POST to AUDIT_WEBHOOK (SIEM/Slack/etc).
  // Fire-and-forget with a short timeout — shipping never blocks auth flows.
  const hook = process.env.AUDIT_WEBHOOK;
  if (hook) {
    void fetch(hook, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      signal: AbortSignal.timeout(5000),
      body: JSON.stringify({ event, orgId: meta.orgId ?? null, userId: meta.userId ?? null, ip: meta.ip ?? null, at }),
    }).catch(() => undefined);
  }
}
