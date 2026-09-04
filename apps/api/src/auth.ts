import crypto from 'node:crypto';
import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';
import { isAccessRevoked } from './store.js';

dotenv.config();

// Short-lived access JWT + rotating refresh tokens, TOTP second step, temp token
// bridging login → 2FA. Revocation consults the persistent store (no more
// process-local denylist — safe across restarts and instances).
const ACCESS_SECRET = process.env.JWT_SECRET ?? 'dev-secret-change-me';
const REFRESH_SECRET = process.env.JWT_REFRESH_SECRET ?? 'dev-refresh-secret-change-me';

if (!process.env.JWT_SECRET && process.env.NODE_ENV === 'production') {
  throw new Error('JWT_SECRET must be set in production');
}

export type Role = 'Owner' | 'Admin' | 'Analyst' | 'Viewer' | 'Auditor';
export type AccessClaims = { sub: string; org: string; role: Role; jti: string };

export function signAccess(user: { id: string; orgId: string; role: Role }) {
  const jti = crypto.randomUUID();
  const token = jwt.sign({ sub: user.id, org: user.orgId, role: user.role, jti }, ACCESS_SECRET, {
    expiresIn: '15m',
    issuer: 'sentinelforge',
  });
  return { token, jti };
}

export function signRefresh(user: { id: string }, days = 7) {
  const jti = crypto.randomUUID();
  const token = jwt.sign({ sub: user.id, jti }, REFRESH_SECRET, { expiresIn: `${days}d` });
  return { token, jti, expiresAt: Date.now() + days * 24 * 60 * 60 * 1000 };
}

export function signTemp(userId: string) {
  return jwt.sign({ sub: userId, type: 'temp' }, ACCESS_SECRET, { expiresIn: '5m' });
}

export async function verifyAccess(token: string): Promise<AccessClaims> {
  const p = jwt.verify(token, ACCESS_SECRET, { issuer: 'sentinelforge' }) as AccessClaims & { type?: string };
  if (await isAccessRevoked(p.jti)) throw new Error('revoked');
  return p;
}

export function verifyRefresh(token: string) {
  return jwt.verify(token, REFRESH_SECRET) as { sub: string; jti: string };
}

export function verifyTemp(token: string) {
  const p = jwt.verify(token, ACCESS_SECRET) as { sub: string; type?: string };
  if (p.type !== 'temp') throw new Error('not-temp');
  return p;
}
