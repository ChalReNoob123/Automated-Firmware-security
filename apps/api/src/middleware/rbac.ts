import type { Request, Response, NextFunction } from 'express';
import { verifyAccess, type Role } from '../auth.js';

// RBAC matrix — spec §2: Owner/Admin/Analyst/Viewer/Auditor. Mirrors SentinelGrid's
// authorize() middleware but extended to 5 IoT-platform roles.
// Round-24 audit: Admin was missing `triage:write` — despite write:all, POST
// /v1/findings (triage) returned 403 for Admins. Admin holds every named perm;
// Owner's '*' remains the only catch-all so later perms don't silently accrue.
const PERMS: Record<Role, string[]> = {
  Owner: ['*'],
  Admin: ['read:all', 'write:all', 'manage:users', 'attest:sign', 'scan:run', 'read:audit', 'triage:write'],
  Analyst: ['read:all', 'scan:run', 'attest:sign', 'triage:write'],
  Viewer: ['read:telemetry', 'read:findings'],
  Auditor: ['read:all', 'read:audit'],
};

export async function requireAuth(req: Request, res: Response, next: NextFunction) {
  const h = req.headers.authorization;
  if (!h?.startsWith('Bearer ')) return res.status(401).json({ error: 'No token' });
  try {
    req.user = await verifyAccess(h.slice(7));
    next();
  } catch (e) {
    return res.status(401).json({ error: 'Unauthorized: ' + (e as Error).message });
  }
}

export function requirePerm(...perms: string[]) {
  return (req: Request, res: Response, next: NextFunction) => {
    const u = req.user as { role: Role } | undefined;
    if (!u) return res.status(401).json({ error: 'Unauthorized' });
    const have = PERMS[u.role] ?? [];
    if (have.includes('*') || perms.every((p) => have.includes(p))) return next();
    return res.status(403).json({ error: 'Forbidden' });
  };
}

declare global {
  // eslint-disable-next-line @typescript-eslint/no-namespace
  namespace Express {
    interface Request {
      user?: unknown;
    }
  }
}
