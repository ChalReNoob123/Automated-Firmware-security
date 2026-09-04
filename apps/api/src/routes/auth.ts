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

const refreshCookie = (res: Response, token: string, days: number) =>
  res.cookie('sf_refresh', token, {
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
    return res.status(401).json({
      error: locked ? 'Too many attempts — account locked for 15 minutes.' : `Invalid credentials. ${LOCKOUT_ATTEMPTS - attempts} attempt(s) left.`,
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
    const valid = speakeasy.totp.verify({ secret: user.totp_secret, encoding: 'base32', token: p.data.code, window: 1 });
    if (!valid) {
      await audit('2fa_failed', { userId: user.id, orgId: user.org_id, ip: req.ip });
      return res.status(401).json({ error: 'Invalid 2FA code' });
    }
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
  const tok = (req as unknown as { cookies?: Record<string, string> }).cookies?.['sf_refresh'];
  if (!tok) return res.status(401).json({ error: 'No refresh token' });
  try {
    const payload = verifyRefresh(tok);
    const rec = await findRefresh(payload.jti);
    if (!rec || rec.revoked || rec.expires_at < Date.now()) return res.status(401).json({ error: 'Invalid refresh token' });
    const user = await findUserById(payload.sub);
    if (!user) return res.status(401).json({ error: 'User not found' });
    await revokeRefresh(payload.jti);
    const access = signAccess({ id: user.id, orgId: user.org_id, role: user.role });
    const refresh = signRefresh({ id: user.id });
    await storeRefresh(refresh.jti, user.id, refresh.expiresAt);
    refreshCookie(res, refresh.token, 7);
    res.json({ accessToken: access.token });
  } catch {
    res.status(401).json({ error: 'Refresh failed' });
  }
});

router.post('/logout', requireAuth, async (req, res) => {
  const u = (req as unknown as { user: { jti: string; sub: string; exp?: number } }).user;
  const refreshTok = (req as unknown as { cookies?: Record<string, string> }).cookies?.['sf_refresh'];
  if (refreshTok) {
    try {
      await revokeRefresh(verifyRefresh(refreshTok).jti);
    } catch {
      /* already invalid */
    }
  }
  await revokeAccess(u.jti, (u.exp ?? Math.floor(Date.now() / 1000) + 900) * 1000);
  await audit('logout', { userId: u.sub, ip: req.ip });
  res.clearCookie('sf_refresh');
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
