import { Router, type Response } from 'express';
import { z } from 'zod';
import speakeasy from 'speakeasy';
import { createHash, randomBytes } from 'node:crypto';
import { audit, query } from '../db.js';
import { signAccess, signRefresh, signTemp, verifyRefresh, verifyTemp } from '../auth.js';
import { requireAuth, requirePerm } from '../middleware/rbac.js';
import {
  countUnusedRecoveryCodes,
  createOrg,
  createUser,
  deleteUser,
  findRefresh,
  findUserById,
  findUserByIdentifier,
  hashPassword,
  listActiveRefreshForUser,
  listOrgUsers,
  replaceRecoveryCodes,
  revokeAccess,
  revokeRefresh,
  revokeAllRefreshForUser,
  revokeRefreshForUser,
  storeRefresh,
  updateUser,
  useRecoveryCode,
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

// Sliding per-user failure caps. TOTP: misses inside the 5-minute temp-token
// window (an attacker holding one token must not grind the 6-digit space at
// the IP limiter's pace; 5 misses → start over from the password step, reset
// on success or fresh login). Reauth: wrong-password attempts on the account
// security endpoints — someone holding a stolen ACCESS token must not be able
// to brute-force the password factor through password-change or re-enroll.
function failCap(maxFails: number, windowMs: number) {
  const hits = new Map<string, { count: number; resetAt: number }>();
  return {
    exceeded(id: string): boolean {
      const now = Date.now();
      const rec = hits.get(id);
      if (!rec || now > rec.resetAt) return false;
      return rec.count >= maxFails;
    },
    record(id: string): void {
      const now = Date.now();
      const rec = hits.get(id);
      if (!rec || now > rec.resetAt) hits.set(id, { count: 1, resetAt: now + windowMs });
      else rec.count++;
    },
    clear(id: string): void {
      hits.delete(id);
    },
  };
}

const TOTP_FAILS = failCap(5, 5 * 60 * 1000);
const REAUTH_FAILS = failCap(5, 5 * 60 * 1000);

// ── TOTP recovery codes (round 22) ──
// 10 single-use codes per enrollment. 10 chars from a 32-symbol unambiguous
// alphabet (no 0/O/1/I/L) ≈ 50 bits — online guessing is bounded by the
// shared TOTP grind cap plus the /v1/auth IP limiter, and the store keeps
// only SHA-256 digests of the normalized form. Plaintext is returned exactly
// once (enrollment completion / regeneration) and never again.
const RECOVERY_ALPHABET = '23456789ABCDEFGHJKMNPQRSTUVWXYZ'; // 31 symbols — no 0/O/1/I/L lookalikes
const sha256hex = (normalized: string) => createHash('sha256').update(normalized, 'utf8').digest('hex');
const normalizeRecovery = (raw: string) => raw.toUpperCase().replace(/[^2-9A-Z]/g, '');

function generateRecoveryCodes(count = 10): string[] {
  const codes = new Set<string>();
  while (codes.size < count) {
    let s = '';
    while (s.length < 10) {
      for (const b of randomBytes(16)) {
        if (b < 248) s += RECOVERY_ALPHABET[b % 31]; // 248 = 8×31 → rejection-free, zero modulo bias
        if (s.length === 10) break;
      }
    }
    codes.add(`${s.slice(0, 5)}-${s.slice(5)}`);
  }
  return [...codes];
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
const inviteSchema = z.object({
  email: z.string().email().max(256),
  username: z.string().min(3).max(32).regex(/^[a-zA-Z0-9_.-]+$/, 'Letters, numbers, _ . - only'),
  role: z.enum(['Admin', 'Analyst', 'Viewer', 'Auditor']), // Owner is signup-only — an Admin must never mint a superior
});

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

// POST /v1/auth/verify-2fa — TOTP check (window 1) → access + rotating HttpOnly
// refresh. Round 22: `recoveryCode` may be sent INSTEAD of the 6-digit `code`
// (lost authenticator) — a valid unused recovery code completes the login
// without TOTP, consumes itself, REVOKES every other session, and flips
// totp_enrolled=false so the next login re-enrolls a fresh authenticator.
// Completing a regular enrollment now also issues the user's recovery codes.
router.post('/verify-2fa', async (req, res) => {
  const p = z
    .object({ tempToken: z.string(), code: z.string().length(6).regex(/^\d{6}$/).optional(), recoveryCode: z.string().min(6).max(32).optional(), rememberMe: z.boolean().optional() })
    .refine((d) => !!d.code || !!d.recoveryCode, { message: 'tempToken + 6-digit code required' })
    .safeParse(req.body);
  if (!p.success) return res.status(400).json({ error: p.error.issues[0]?.message ?? 'tempToken + 6-digit code required' });
  try {
    const t = verifyTemp(p.data.tempToken);
    const user = await findUserById(t.sub);
    if (!user?.totp_secret) throw new Error('no-totp');
    // Grind cap (shared with recovery codes): too many misses inside the
    // temp-token window → refuse until the user restarts from the password
    // step (fresh temp token).
    if (TOTP_FAILS.exceeded(user.id)) {
      await audit('2fa_grind_blocked', { userId: user.id, orgId: user.org_id, ip: req.ip });
      return res.status(403).json({ error: 'Too many verification attempts — start again from the password step.' });
    }

    const issueTokens = async (days: number) => {
      const access = signAccess({ id: user!.id, orgId: user!.org_id, role: user!.role });
      const refresh = signRefresh({ id: user!.id }, days);
      await storeRefresh(refresh.jti, user!.id, refresh.expiresAt);
      refreshCookie(res, refresh.token, days);
      return { access, refresh };
    };

    // ── recovery-code path ──
    if (p.data.recoveryCode) {
      const r = await useRecoveryCode(user.id, normalizeRecovery(p.data.recoveryCode));
      if (!r.used) {
        TOTP_FAILS.record(user.id);
        await audit('recovery_code_failed', { userId: user.id, orgId: user.org_id, ip: req.ip });
        return res.status(401).json({ error: 'Invalid recovery code' });
      }
      TOTP_FAILS.clear(user.id);
      // The authenticator is lost/unknown: kill every other session, then
      // force a fresh enrollment on the next login.
      const revokedOtherSessions = await revokeAllRefreshForUser(user.id);
      await updateUser(user.id, { totp_enrolled: false, totp_secret: null });
      const { access, refresh } = await issueTokens(p.data.rememberMe ? 30 : 7);
      await audit('recovery_code_used', { userId: user.id, orgId: user.org_id, ip: req.ip });
      return res.json({
        success: true,
        accessToken: access.token,
        sessionId: refresh.jti,
        usedRecoveryCode: true,
        recoveryRemaining: r.remaining,
        revokedOtherSessions,
        user: { id: user.id, username: user.username, email: user.email, role: user.role, orgId: user.org_id },
      });
    }

    // ── TOTP path ──
    if (!p.data.code) return res.status(400).json({ error: 'tempToken + 6-digit code required' });
    const valid = speakeasy.totp.verify({ secret: user.totp_secret, encoding: 'base32', token: p.data.code, window: 1 });
    if (!valid) {
      TOTP_FAILS.record(user.id);
      await audit('2fa_failed', { userId: user.id, orgId: user.org_id, ip: req.ip });
      return res.status(401).json({ error: 'Invalid 2FA code' });
    }
    TOTP_FAILS.clear(user.id);
    let recoveryCodes: string[] | undefined;
    let recoveryRemaining: number | undefined;
    if (!user.totp_enrolled) {
      // Enrollment completing: the ONE moment the plaintext codes exist.
      await updateUser(user.id, { totp_enrolled: true });
      recoveryCodes = generateRecoveryCodes();
      await replaceRecoveryCodes(user.id, recoveryCodes.map((c) => sha256hex(normalizeRecovery(c))));
      recoveryRemaining = recoveryCodes.length;
    }
    const { access, refresh } = await issueTokens(p.data.rememberMe ? 30 : 7);
    await audit('2fa_success', { userId: user.id, orgId: user.org_id, ip: req.ip });
    res.json({
      success: true,
      accessToken: access.token,
      // The refresh jti lets this device recognize itself in /sessions.
      sessionId: refresh.jti,
      ...(recoveryCodes ? { recoveryCodes, recoveryRemaining } : {}),
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
      if (rec.reason === 'rotated') {
        // THEFT SIGNAL: a rotated-out token was replayed → assume theft, kill
        // the whole family for this user and log it loudly.
        await revokeAllRefreshForUser(rec.user_id);
        await audit('refresh_reuse_detected', { userId: rec.user_id, ip: req.ip });
        return res.status(401).json({ error: 'Refresh token reuse detected — all sessions revoked' });
      }
      // Owner-revoked (device revoked / logged out / password rotation): the
      // legitimate holder replaying it is EXPECTED — quiet death, no family
      // kill, otherwise revoking one device would sign out the whole account.
      await audit('refresh_revoked_replay', { userId: rec.user_id, ip: req.ip });
      return res.status(401).json({ error: 'Session was revoked' });
    }
    if (rec.expires_at < Date.now()) return res.status(401).json({ error: 'Invalid refresh token' });
    const user = await findUserById(payload.sub);
    if (!user) return res.status(401).json({ error: 'User not found' });
    await revokeRefresh(payload.jti, 'rotated');
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
    res.json({ accessToken: access.token, sessionId: refresh.jti });
  } catch {
    res.status(401).json({ error: 'Refresh failed' });
  }
});

router.post('/logout', requireAuth, async (req, res) => {
  const u = (req as unknown as { user: { jti: string; sub: string; exp?: number } }).user;
  const refreshTok = (req as unknown as { cookies?: Record<string, string> }).cookies?.[COOKIE_NAME];
  if (refreshTok) {
    try {
      await revokeRefresh(verifyRefresh(refreshTok).jti, 'revoked');
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

// ── Account Security Center (round 20) ──────────────────────────────────────
// Self-scoped session inventory + per-device revocation, password rotation
// with re-auth, and authenticator re-enrollment. Everything below runs under
// requireAuth and the /v1/auth IP limiter; the reauth endpoints additionally
// carry the per-user REAUTH_FAILS cap (a stolen access token must not enable
// brute-forcing the password factor).
const authed = (req: unknown) => (req as unknown as { user: { sub: string; org: string; jti: string; exp?: number } }).user;

async function currentCookieJti(req: unknown): Promise<string> {
  const tok = (req as unknown as { cookies?: Record<string, string> }).cookies?.[COOKIE_NAME];
  if (!tok) return '';
  try {
    return verifyRefresh(tok).jti;
  } catch {
    return ''; // stale/garbage cookie — simply not "current"
  }
}

// GET /v1/auth/sessions — the caller's live sessions. The jti authorizes
// nothing on its own (refresh tokens are signed; revocation is the only thing
// a bare jti can do), so listing it for its owner is safe and is exactly what
// makes per-device kill possible.
router.get('/sessions', requireAuth, async (req, res) => {
  const u = authed(req);
  const currentJti = await currentCookieJti(req);
  const now = Date.now();
  const sessions = (await listActiveRefreshForUser(u.sub)).map((r) => ({
    id: r.jti,
    current: r.jti === currentJti,
    createdAt: r.created_at,
    expiresAt: r.expires_at,
    expiresDays: Math.max(0, Math.ceil((r.expires_at - now) / 86_400_000)),
  }));
  res.json({ sessions });
});

// POST /v1/auth/sessions/revoke — kill ONE of the caller's sessions. Revoking
// the session this browser holds also acts as a logout (access token denied).
router.post('/sessions/revoke', requireAuth, async (req, res) => {
  const p = z.object({ jti: z.string().min(8).max(128) }).safeParse(req.body);
  if (!p.success) return res.status(400).json({ error: 'jti required' });
  const u = authed(req);
  const ok = await revokeRefreshForUser(u.sub, p.data.jti);
  if (!ok) return res.status(404).json({ error: 'Session not found' });
  const selfRevoked = (await currentCookieJti(req)) === p.data.jti;
  if (selfRevoked) {
    await revokeAccess(u.jti, (u.exp ?? Math.floor(Date.now() / 1000) + 900) * 1000);
    res.clearCookie(COOKIE_NAME);
  }
  await audit('session_revoked', { userId: u.sub, orgId: u.org, ip: req.ip });
  res.json({ success: true, selfRevoked });
});

// POST /v1/auth/sessions/revoke-all — every device out, including this one.
router.post('/sessions/revoke-all', requireAuth, async (req, res) => {
  const u = authed(req);
  const revoked = await revokeAllRefreshForUser(u.sub);
  await revokeAccess(u.jti, (u.exp ?? Math.floor(Date.now() / 1000) + 900) * 1000);
  await audit('sessions_revoked_all', { userId: u.sub, orgId: u.org, ip: req.ip });
  res.clearCookie(COOKIE_NAME);
  res.json({ success: true, revoked });
});

// POST /v1/auth/password — rotate the password. Re-auth with the current
// password first, then every OTHER session dies while the caller's own
// session survives rotation (their cookie keeps working).
router.post('/password', requireAuth, async (req, res) => {
  const p = z.object({ currentPassword: z.string().min(1).max(256), newPassword: passwordSchema }).safeParse(req.body);
  if (!p.success) return res.status(400).json({ error: p.error.issues[0]?.message ?? 'currentPassword + newPassword required' });
  const u = authed(req);
  if (REAUTH_FAILS.exceeded(u.sub)) {
    await audit('password_change_blocked', { userId: u.sub, ip: req.ip });
    return res.status(429).json({ error: 'Too many attempts — try again in a few minutes.' });
  }
  const user = await findUserById(u.sub);
  if (!user) return res.status(404).json({ error: 'User not found' });
  if (!(await verifyPassword(p.data.currentPassword, user.password_hash))) {
    REAUTH_FAILS.record(u.sub);
    await audit('password_change_failed', { userId: user.id, orgId: user.org_id, ip: req.ip });
    return res.status(401).json({ error: 'Current password is incorrect' });
  }
  if (await verifyPassword(p.data.newPassword, user.password_hash)) {
    return res.status(400).json({ error: 'New password must differ from the current password' });
  }
  const revokedOtherSessions = await revokeAllRefreshForUser(user.id, await currentCookieJti(req));
  await updateUser(user.id, { password_hash: await hashPassword(p.data.newPassword), failed_attempts: 0 });
  REAUTH_FAILS.clear(u.sub);
  await audit('password_changed', { userId: user.id, orgId: user.org_id, ip: req.ip });
  res.json({ success: true, revokedOtherSessions });
});

// POST /v1/auth/totp/re-enroll — lost/replaced authenticator. Password re-auth
// (the password is the recovery factor), then a fresh secret + temp token that
// the client completes through the standard /verify-2fa. All other sessions
// are revoked here — a rotated authenticator should not leave old devices
// alive; if the flow is abandoned the next login re-enrolls from scratch
// (login regenerates the secret whenever totp_enrolled is false, so password
// knowledge can always recover the account).
router.post('/totp/re-enroll', requireAuth, async (req, res) => {
  const p = z.object({ password: z.string().min(1).max(256) }).safeParse(req.body);
  if (!p.success) return res.status(400).json({ error: 'password required' });
  const u = authed(req);
  if (REAUTH_FAILS.exceeded(u.sub)) {
    await audit('2fa_reenroll_blocked', { userId: u.sub, ip: req.ip });
    return res.status(429).json({ error: 'Too many attempts — try again in a few minutes.' });
  }
  const user = await findUserById(u.sub);
  if (!user) return res.status(404).json({ error: 'User not found' });
  if (!(await verifyPassword(p.data.password, user.password_hash))) {
    REAUTH_FAILS.record(u.sub);
    await audit('2fa_reenroll_failed', { userId: user.id, orgId: user.org_id, ip: req.ip });
    return res.status(401).json({ error: 'Current password is incorrect' });
  }
  const secret = speakeasy.generateSecret({ name: `SentinelForge (${user.username})`, length: 20 });
  const revokedOtherSessions = await revokeAllRefreshForUser(user.id);
  await updateUser(user.id, { totp_secret: secret.base32, totp_enrolled: false });
  REAUTH_FAILS.clear(u.sub);
  await audit('2fa_reenrolled', { userId: user.id, orgId: user.org_id, ip: req.ip });
  res.json({ tempToken: signTemp(user.id), otpauthUrl: secret.otpauth_url, manualKey: secret.base32, revokedOtherSessions });
});

// ── Recovery-code management (round 22) ─────────────────────────────────────
// GET /v1/auth/recovery-codes — how many single-use codes remain. The codes
// themselves are never retrievable (SHA-256 digests only).
router.get('/recovery-codes', requireAuth, async (req, res) => {
  const u = authed(req);
  res.json({ remaining: await countUnusedRecoveryCodes(u.sub) });
});

// POST /v1/auth/recovery-codes — password re-auth → a FRESH set of 10 codes
// (the old set is invalidated entirely). Plaintext shown exactly once.
router.post('/recovery-codes', requireAuth, async (req, res) => {
  const p = z.object({ password: z.string().min(1).max(256) }).safeParse(req.body);
  if (!p.success) return res.status(400).json({ error: 'password required' });
  const u = authed(req);
  if (REAUTH_FAILS.exceeded(u.sub)) {
    await audit('recovery_regenerate_blocked', { userId: u.sub, ip: req.ip });
    return res.status(429).json({ error: 'Too many attempts — try again in a few minutes.' });
  }
  const user = await findUserById(u.sub);
  if (!user) return res.status(404).json({ error: 'User not found' });
  if (!(await verifyPassword(p.data.password, user.password_hash))) {
    REAUTH_FAILS.record(u.sub);
    await audit('recovery_regenerate_failed', { userId: user.id, orgId: user.org_id, ip: req.ip });
    return res.status(401).json({ error: 'Current password is incorrect' });
  }
  const codes = generateRecoveryCodes();
  await replaceRecoveryCodes(user.id, codes.map((c) => sha256hex(normalizeRecovery(c))));
  REAUTH_FAILS.clear(u.sub);
  await audit('recovery_codes_regenerated', { userId: user.id, orgId: user.org_id, ip: req.ip });
  res.json({ codes, remaining: codes.length });
});

// SAML SSO hook (spec §2 optional SSO) — stub handshake; real passport-saml wiring is a follow-up.
router.get('/sso/saml', (_req, res) => res.json({ sso: 'saml-stub', next: 'redirect-to-idp' }));

// Temp password for invited users: 20 chars, one symbol guaranteed from each
// required class (upper/lower/digit/special), the rest drawn from a mixed set.
// Every index is rejection-sampled (b < 256 - (256 % len)) — zero modulo bias,
// same construction discipline as the round-22 recovery alphabet.
const rejectionIndex = (len: number): number => {
  for (;;) {
    const b = randomBytes(1)[0];
    if (b < 256 - (256 % len)) return b % len;
  }
};
function generateTempPassword(): string {
  const upper = 'ABCDEFGHJKLMNPQRSTUVWXYZ';
  const lower = 'abcdefghijkmnpqrstuvwxyz';
  const digits = '23456789';
  const specials = '!@#$%^&*_-';
  const mixed = upper + lower + digits;
  const chars = [upper, lower, digits, specials].map((set) => set[rejectionIndex(set.length)]);
  while (chars.length < 20) chars.push(mixed[rejectionIndex(mixed.length)]);
  for (let i = chars.length - 1; i > 0; i--) {
    const j = rejectionIndex(i + 1);
    [chars[i], chars[j]] = [chars[j], chars[i]];
  }
  return chars.join('');
}

// POST /v1/auth/invite — Owner/Admin add a teammate to THEIR org with an
// explicit role. Round-24 audit finding: the RBAC matrix was dead code —
// signup hardcodes Owner and no route could mint Admin/Analyst/Viewer/Auditor,
// so `manage:users` was checked by nothing and the 5-role matrix was
// unenforceable and untestable. Owner remains signup-only. The generated temp
// password is returned exactly ONCE; there is no mail transport in this
// prototype (production invites email a one-time link instead — the honest
// gap is documented in SECURITY.md). The invitee enrolls their own TOTP on
// first login like any other account.
router.post('/invite', requireAuth, requirePerm('manage:users'), async (req, res) => {
  const p = inviteSchema.safeParse(req.body);
  if (!p.success) return res.status(400).json({ error: p.error.issues[0]?.message });
  const u = authed(req);
  const email = p.data.email.toLowerCase();
  const dupe = await findUserByIdentifier(p.data.username).catch(() => undefined);
  const dupeEmail = await findUserByIdentifier(email).catch(() => undefined);
  // Same message as signup — existence in ANY org is disclosed only as the
  // combined username-or-email ambiguity, never which.
  if (dupe || dupeEmail) return res.status(409).json({ error: 'Username or email already registered' });
  const tempPassword = generateTempPassword();
  const user = await createUser({
    orgId: u.org,
    email,
    username: p.data.username,
    passwordHash: await hashPassword(tempPassword),
    role: p.data.role,
  });
  await audit('user_invited', { orgId: u.org, userId: u.sub, ip: req.ip });
  res.status(201).json({ userId: user.id, orgId: user.org_id, role: user.role, username: user.username, email: user.email, tempPassword });
});

// Audit trail — restricted to roles holding read:audit (Auditor, Admin, Owner).
// Round-24 audit fix: rows are filtered by the CALLER's org IN JS, not just in
// SQL — the memory fallback behind query() cannot parse WHERE clauses and was
// returning the newest audit rows across ALL orgs in dev (cross-tenant leak on
// the readout). `org_id IS NULL` rows stay visible by design: they are
// anonymous host telemetry (e.g. failed logins for unknown identifiers), not
// tenant data.
router.get('/audit', requireAuth, requirePerm('read:audit'), async (req, res) => {
  const u = (req as unknown as { user: { org: string } }).user;
  // pg: WHERE + LIMIT filter before the JS layer; the memory stub ignores SQL
  // clauses, which is exactly why the JS filter below is the real gate in dev.
  const r = await query(`SELECT event, ip, created_at, org_id FROM auth_audit WHERE org_id=$1 OR org_id IS NULL ORDER BY created_at DESC LIMIT 100`, [u.org]);
  const events = r.rows
    .filter((row) => row.org_id === u.org || row.org_id == null)
    .map(({ event, ip, created_at }) => ({ event, ip, created_at }));
  res.json({ events });
});

// GET /v1/auth/teammates — the caller's org roster for the Security Center's
// Teammates console (round 26). manage:users (Owner, Admin) — the same surface
// that may mint members may read the roster; read:audit is deliberately not
// enough. Tenancy comes from the TOKEN (u.org), never from client input, and
// the response shape is pinned by tests: identity + 2FA state only — never
// password hashes, TOTP secrets, or org-id fields.
router.get('/teammates', requireAuth, requirePerm('manage:users'), async (req, res) => {
  const u = authed(req);
  const rows = await listOrgUsers(u.org);
  res.json({
    orgId: u.org,
    selfId: u.sub,
    members: rows.map((m) => ({
      id: m.id,
      username: m.username,
      email: m.email,
      role: m.role,
      totpEnrolled: m.totp_enrolled,
      lastLogin: m.last_login,
    })),
  });
});

// Round 29 — team management completion: role change + member removal.
// Both are manage:users; both take tenancy from the token; both refuse the
// self-action (no lockout foot-guns) and refuse to touch the Owner row
// (Owner is signup-only and immutable through this API). A cross-org id is
// indistinguishable from an unknown id (uniform 404 — no existence probe).
const roleChangeSchema = z.object({ role: z.enum(['Admin', 'Analyst', 'Viewer', 'Auditor']) });
const teammateId = (req: unknown) => String((req as { params?: { id?: string } }).params?.id ?? '');

// PATCH /v1/auth/teammates/:id — set a teammate's role. Access tokens carry
// the role CLAIM, so the target's refresh tokens are all revoked on change:
// the stale bearer keeps its old perms only until it expires (the standing
// ≤15-min window, same as password rotation — documented in SECURITY.md),
// and the new role is live from their very next login.
router.patch('/teammates/:id', requireAuth, requirePerm('manage:users'), async (req, res) => {
  const p = roleChangeSchema.safeParse(req.body);
  if (!p.success) return res.status(400).json({ error: p.error.issues[0]?.message ?? 'role required' });
  const u = authed(req);
  const target = await findUserById(teammateId(req));
  if (!target || target.org_id !== u.org) return res.status(404).json({ error: 'Teammate not found' });
  if (target.id === u.sub) return res.status(400).json({ error: 'You cannot change your own role' });
  if (target.role === 'Owner') return res.status(403).json({ error: 'The Owner role is fixed — signup-only, never editable' });
  await updateUser(target.id, { role: p.data.role });
  await revokeAllRefreshForUser(target.id);
  await audit('user_role_changed', { orgId: u.org, userId: u.sub, targetId: target.id, ip: req.ip });
  res.json({ id: target.id, role: p.data.role, sessionsRevoked: true });
});

// DELETE /v1/auth/teammates/:id — remove a teammate. The account row goes
// away and every refresh token dies with it: the removed member cannot
// re-authenticate (their password no longer resolves to a user). Their
// unexpired ACCESS bearer still passes signature+jti checks for ≤15 min —
// it 403s on perm-gated routes (old role claim, NOT 401) while identity-
// scoped endpoints (/me) 404 once the row is gone. The standing short-TTL
// window, same model as password rotation — documented in SECURITY.md and
// pinned exactly like that in the tests.
router.delete('/teammates/:id', requireAuth, requirePerm('manage:users'), async (req, res) => {
  const u = authed(req);
  const target = await findUserById(teammateId(req));
  if (!target || target.org_id !== u.org) return res.status(404).json({ error: 'Teammate not found' });
  if (target.id === u.sub) return res.status(400).json({ error: 'You cannot remove your own account here' });
  if (target.role === 'Owner') return res.status(403).json({ error: 'The Owner cannot be removed' });
  await revokeAllRefreshForUser(target.id);
  await deleteUser(target.id);
  await audit('user_removed', { orgId: u.org, userId: u.sub, targetId: target.id, ip: req.ip });
  res.json({ removed: true, id: target.id });
});

export default router;
