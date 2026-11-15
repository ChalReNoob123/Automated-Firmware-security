import { Router, type Response } from 'express';
import { z } from 'zod';
import speakeasy from 'speakeasy';
import { audit, query } from '../db.js';
import { signAccess, signRefresh, signTemp, verifyRefresh, verifyTemp } from '../auth.js';
import { requireAuth, requirePerm } from '../middleware/rbac.js';
import {
  createOrg,
  createUser,
  findRefresh,
  findUserById,
  findUserByIdentifier,
  hashPassword,
  revokeAccess,
  revokeRefresh,
  revokeAllRefreshForUser,
  storeRefresh,
  updateUser,
  verifyPassword,
} from '../store.js';

// Real authentication: bcrypt passwords, TOTP enrollment + verification,
// per-account lockout, refresh rotation, persistent revocation.
// (The old demo stub is gone — every step below hits the user store.)
const router = Router();

const LOCKOUT_ATTEMPTS = 5;
const LOCKOUT_MS = 15 * 60 * 1000;

// Per-identifier rate limiting on login — prevents distributed brute-force
// against a specific account from many IPs.
const LOGIN_RATE_LIMIT = new Map<string, { count: number; resetAt: number }>();
const LOGIN_LIMIT = 10;
const LOGIN_WINDOW_MS = 60 * 1000;

// Failed TOTP attempts per user during the temp-token window. The temp token
// is valid 5 minutes; without a cap an attacker holding one could grind the
// 6-digit space at the IP limiter's pace. 5 misses → start over from the
// password step (also resets on successful verify or fresh login).
const TOTP_FAILS = new Map<string, { count: number; resetAt: number }>();
const TOTP_MAX_FAILS = 5;
const TOTP_WINDOW_MS = 5 * 60 * 1000;

function totpFailuresExceeded(userId: string): boolean {
  const now = Date.now();
  const rec = TOTP_FAILS.get(userId);
  if (!rec || now > rec.resetAt) return false;
  return rec.count >= TOTP_MAX_FAILS;
}

function recordTotpFail(userId: string): void {
  const now = Date.now();
  const rec = TOTP_FAILS.get(userId);
  if (!rec || now > rec.resetAt) TOTP_FAILS.set(userId, { count: 1, resetAt: now + TOTP_WINDOW_MS });
  else rec.count++;
}

function clearTotpFails(userId: string): void {
  TOTP_FAILS.delete(userId);
}

function loginRateLimit(identifier: string): boolean {
  const now = Date.now();
  const rec = LOGIN_RATE_LIMIT.get(identifier);
  if (!rec || now > rec.resetAt) {
    LOGIN_RATE_LIMIT.set(identifier, { count: 1, resetAt: now + LOGIN_WINDOW_MS });
    return true;
  }
  if (rec.count >= LOGIN_LIMIT) return false;
  rec.count++;
  return true;
}

// Clean up stale entries periodically.
setInterval(() => {
  const now = Date.now();
  for (const [k, v] of LOGIN_RATE_LIMIT.entries()) {
    if (now > v.resetAt) LOGIN_RATE_LIMIT.delete(k);
  }
}, LOGIN_WINDOW_MS);

const passwordSchema = z
  .string()
  .min(10, 'Password must be at least 10 characters')
  .regex(/[A-Z]/, 'Password must contain an uppercase letter')
  .regex(/[a-z]/, 'Password must contain a lowercase letter')
  .regex(/\d/, 'Password must contain a digit')
  .regex(/[!@#$%^&*()_+\-=[\]{};':"\\|,.<>/?]/, 'Password must contain a special character');

const signupSchema = z.object({
  orgName: z.string().min(2).max(80),
  username: z.string().min(3).max(32).regex(/^[a-zA-Z0-9_.-]+$/, 'Letters, numbers, _ . - only'),
  email: z.string().email(),
  password: passwordSchema,
});
const loginSchema = z.object({ identifier: z.string().min(3).max(128), password: z.string().max(256), rememberMe: z.boolean().optional() });

const COOKIE_NAME = process.env.NODE_ENV === 'production' ? '__Host-sf_refresh' : 'sf_refresh';

const refreshCookie = (res: Response, token: string, days: number) =>
  res.cookie(COOKIE_NAME, token, {
    httpOnly: true,
    path: '/',
    sameSite: 'strict',
    maxAge: days * 24 * 60 * 60 * 1000,
    ...(process.env.NODE_ENV === 'production' ? { secure: true } : {}),
  });

// POST /v1/auth/signup — creates org (caller becomes Owner) + user.
router.post('/signup', async (req, res) => {
  const p = signupSchema.safeParse(req.body);
  if (!p.success) return res.status(400).json({ error: p.error.issues[0]?.message });
  const dupe = await findUserByIdentifier(p.data.username).catch(() => undefined);
  const dupeEmail = await findUserByIdentifier(p.data.email).catch(() => undefined);
  if (dupe || dupeEmail) return res.status(409).json({ error: 'Username or email already registered' });
  const { id: orgId } = await createOrg(p.data.orgName);
  const user = await createUser({
    orgId,
    email: p.data.email,
    username: p.data.username,
    passwordHash: await hashPassword(p.data.password),
    role: 'Owner',
  });
  await audit('signup', { orgId, userId: user.id, ip: req.ip });
  res.status(201).json({ success: true, userId: user.id, orgId });
});

// POST /v1/auth/login — password check (+lockout) → tempToken → TOTP step.
router.post('/login', async (req, res) => {
  const p = loginSchema.safeParse(req.body);
  if (!p.success) return res.status(400).json({ error: 'Invalid credentials shape' });
  // Per-identifier rate limit: prevent distributed brute-force against one account.
  if (!loginRateLimit(p.data.identifier)) {
    await audit('login_rate_limited', { ip: req.ip });
    return res.status(429).json({ error: 'Too many login attempts for this account. Try again later.' });
  }
  const user = await findUserByIdentifier(p.data.identifier);
  if (!user) {
    await audit('login_failed', { ip: req.ip });
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  if (user.locked_until > Date.now()) {
    const mins = Math.ceil((user.locked_until - Date.now()) / 60000);
    await audit('login_locked', { userId: user.id, orgId: user.org_id, ip: req.ip });
    return res.status(403).json({ error: `Account locked after repeated failures. Retry in ${mins} minute(s).` });
  }
  if (!(await verifyPassword(p.data.password, user.password_hash))) {
    const attempts = user.failed_attempts + 1;
    const locked = attempts >= LOCKOUT_ATTEMPTS ? Date.now() + LOCKOUT_MS : 0;
    await updateUser(user.id, { failed_attempts: locked ? 0 : attempts, locked_until: locked });
    await audit(locked ? 'account_locked' : 'login_failed', { userId: user.id, orgId: user.org_id, ip: req.ip });
    // Uniform failure message — the old "N attempt(s) left" reply only fired
    // for EXISTING accounts, which made login an oracle for enumerating
    // registered usernames (confirmed live in the round-19 audit). Lockout
    // stays a distinct message: it can only surface after 5 real attempts.
    return res.status(401).json({
      error: locked ? 'Too many attempts — account locked for 15 minutes.' : 'Invalid credentials',
    });
  }
  await updateUser(user.id, { failed_attempts: 0, locked_until: 0, last_login: new Date().toISOString() });
  await audit('login_success', { userId: user.id, orgId: user.org_id, ip: req.ip });

  if (!user.totp_enrolled) {
    const secret = speakeasy.generateSecret({ name: `SentinelForge (${user.username})`, length: 20 });
    await updateUser(user.id, { totp_secret: secret.base32 });
    return res.json({ step: 'enroll', tempToken: signTemp(user.id), otpauthUrl: secret.otpauth_url, manualKey: secret.base32 });
  }
  res.json({ step: '2fa', tempToken: signTemp(user.id) });
});

// POST /v1/auth/verify-2fa — TOTP check (window 1) → access + rotating HttpOnly refresh.
router.post('/verify-2fa', async (req, res) => {
  const p = z.object({ tempToken: z.string(), code: z.string().length(6).regex(/^\d{6}$/), rememberMe: z.boolean().optional() }).safeParse(req.body);
  if (!p.success) return res.status(400).json({ error: p.error.issues[0]?.message ?? 'tempToken + 6-digit code required' });
  try {
    const t = verifyTemp(p.data.tempToken);
    const user = await findUserById(t.sub);
    if (!user?.totp_secret) throw new Error('no-totp');
    // TOTP grind cap: too many misses inside the temp-token window → refuse
    // until the user restarts from the password step (fresh temp token).
    if (totpFailuresExceeded(user.id)) {
      await audit('2fa_grind_blocked', { userId: user.id, orgId: user.org_id, ip: req.ip });
      return res.status(403).json({ error: 'Too many verification attempts — start again from the password step.' });
    }
    const valid = speakeasy.totp.verify({ secret: user.totp_secret, encoding: 'base32', token: p.data.code, window: 1 });
    if (!valid) {
      recordTotpFail(user.id);
      await audit('2fa_failed', { userId: user.id, orgId: user.org_id, ip: req.ip });
      return res.status(401).json({ error: 'Invalid 2FA code' });
    }
    clearTotpFails(user.id);
    if (!user.totp_enrolled) await updateUser(user.id, { totp_enrolled: true });
    const access = signAccess({ id: user.id, orgId: user.org_id, role: user.role });
    const days = p.data.rememberMe ? 30 : 7;
    const refresh = signRefresh({ id: user.id }, days);
    await storeRefresh(refresh.jti, user.id, refresh.expiresAt);
    refreshCookie(res, refresh.token, days);
    await audit('2fa_success', { userId: user.id, orgId: user.org_id, ip: req.ip });
    res.json({
      success: true,
      accessToken: access.token,
      user: { id: user.id, username: user.username, email: user.email, role: user.role, orgId: user.org_id },
    });
  } catch {
    res.status(401).json({ error: 'Verification failed' });
  }
});

router.post('/refresh', async (req, res) => {
  const tok = (req as unknown as { cookies?: Record<string, string> }).cookies?.[COOKIE_NAME];
  if (!tok) return res.status(401).json({ error: 'No refresh token' });
  try {
    const payload = verifyRefresh(tok);
    const rec = await findRefresh(payload.jti);
    if (!rec) return res.status(401).json({ error: 'Invalid refresh token' });
    if (rec.revoked) {
      // REUSE DETECTED: a rotated-out token was replayed → assume theft, kill the
      // whole family for this user and log it loudly.
      await revokeAllRefreshForUser(rec.user_id);
      await audit('refresh_reuse_detected', { userId: rec.user_id, ip: req.ip });
      return res.status(401).json({ error: 'Refresh token reuse detected — all sessions revoked' });
    }
    if (rec.expires_at < Date.now()) return res.status(401).json({ error: 'Invalid refresh token' });
    const user = await findUserById(payload.sub);
    if (!user) return res.status(401).json({ error: 'User not found' });
    await revokeRefresh(payload.jti);
    const access = signAccess({ id: user.id, orgId: user.org_id, role: user.role });
    // Sliding session: re-issue for the presented token's remaining lifetime
    // (rounded up, 1..30 days). A "remember me for 30 days" login used to
    // silently degrade to 7 days on the first refresh — now the session class
    // survives rotation in both the postgres and memory stores.
    const remainingDays = Math.ceil((rec.expires_at - Date.now()) / 86_400_000);
    const days = Math.max(1, Math.min(30, remainingDays || 7));
    const refresh = signRefresh({ id: user.id }, days);
    await storeRefresh(refresh.jti, user.id, refresh.expiresAt);
    refreshCookie(res, refresh.token, days);
    res.json({ accessToken: access.token });
  } catch {
    res.status(401).json({ error: 'Refresh failed' });
  }
});

router.post('/logout', requireAuth, async (req, res) => {
  const u = (req as unknown as { user: { jti: string; sub: string; exp?: number } }).user;
  const refreshTok = (req as unknown as { cookies?: Record<string, string> }).cookies?.[COOKIE_NAME];
  if (refreshTok) {
    try {
      await revokeRefresh(verifyRefresh(refreshTok).jti);
    } catch {
      /* already invalid */
    }
  }
  await revokeAccess(u.jti, (u.exp ?? Math.floor(Date.now() / 1000) + 900) * 1000);
  await audit('logout', { userId: u.sub, ip: req.ip });
  res.clearCookie(COOKIE_NAME);
  res.json({ success: true });
});

router.get('/me', requireAuth, async (req, res) => {
  const u = (req as unknown as { user: { sub: string } }).user;
  const full = await findUserById(u.sub);
  if (!full) return res.status(404).json({ error: 'User not found' });
  res.json({
    authenticated: true,
    user: { id: full.id, username: full.username, email: full.email, role: full.role, orgId: full.org_id, totpEnrolled: full.totp_enrolled },
  });
});

// SAML SSO hook (spec §2 optional SSO) — stub handshake; real passport-saml wiring is a follow-up.
router.get('/sso/saml', (_req, res) => res.json({ sso: 'saml-stub', next: 'redirect-to-idp' }));

// Audit trail — restricted to roles holding read:audit (Auditor, Admin, Owner).
router.get('/audit', requireAuth, requirePerm('read:audit'), async (req, res) => {
  const u = (req as unknown as { user: { org: string } }).user;
  const r = await query(`SELECT event, ip, created_at FROM auth_audit WHERE org_id=$1 OR org_id IS NULL ORDER BY created_at DESC LIMIT 100`, [u.org]);
  res.json({ events: r.rows });
});

export default router;
