'use client';
import { useCallback, useEffect, useRef, useState } from 'react';
import { useRouter } from 'next/navigation';
import { AnimatePresence, motion, useReducedMotion, type MotionProps } from 'framer-motion';
import { Card, glassGlow } from '../components/ui';
import { Reveal } from '../motionKit';
import { apiFetch, getMe, setAccess, setSessionId, API_URL } from '../lib/auth';
import { pwChecks, pwStrong, PW_RULES } from '../lib/pwRules';
import { sfxBlip, sfxDeny, sfxGrant, sfxImpact, sfxShift } from '../audio/sfx';

// Account Security Center (round 20, extended rounds 26 + 29, sensory pass 30).
// Four consoles:
//   PASSWORD     — rotate with re-auth; other sessions die, this one survives
//   SESSIONS     — live device list, per-device revoke, sign-out-everywhere
//   AUTHENTICATOR— re-enroll TOTP via password re-auth + standard verify step
//   TEAMMATES    — org roster + invite console (Owner/Admin only; the round-24
//                  invite endpoint finally gets its UI, plus the round-26
//                  org-scoped roster read), and since round 29 the management
//                  loop closes in place: per-row role change + member removal
//                  (PATCH/DELETE /v1/auth/teammates/:id), never offered for the
//                  caller's own row or the immutable Owner row.
// Round 30 — the console now ACTS like one: list rows rise in and collapse
// out (AnimatePresence + layout reflow, reduced motion → plain fades), a
// sweep of light crosses a row the moment it's minted or its role register
// changes, role chips pop on swap, counts flip, status notes rise (errors
// shake once), and every outcome speaks the round-30 sfx vocabulary
// (grant/shift/impact/deny — no-ops when muted). All ambient framer-motion
// honors prefers-reduced-motion, same as the rest of the fleet.
// All privileged calls go through apiFetch (memory bearer + silent-refresh
// retry); verify-2fa is called directly with credentials:'include' like the
// login form, because it mints the new refresh cookie itself.

type Me = { username: string; email: string; role: string; orgId: string; totpEnrolled?: boolean };
type SessionRow = { id: string; current: boolean; createdAt: number; expiresAt: number; expiresDays: number };
type Teammate = { id: string; username: string; email: string; role: string; totpEnrolled: boolean; lastLogin: string | null };

// Role chip tones for the roster — one hue per RBAC role so a glance reads the
// org's shape (Owner rose, Admin amber, Analyst cyan, Viewer slate, Auditor violet).
const ROLE_TONE: Record<string, { c: string; b: string }> = {
  Owner: { c: '#fda4af', b: 'rgba(244,63,94,0.45)' },
  Admin: { c: '#fcd34d', b: 'rgba(251,191,36,0.45)' },
  Analyst: { c: '#22d3ee', b: 'rgba(34,211,238,0.45)' },
  Viewer: { c: '#94a3b8', b: 'rgba(148,163,184,0.45)' },
  Auditor: { c: '#c4b5fd', b: 'rgba(167,139,250,0.45)' },
};

// Round 30: authority order for the shift cue — a promotion sounds up, a
// demotion sounds down (Owner included only for compare completeness; it is
// never assignable). The RBAC model itself is unchanged: Analyst/Viewer/
// Auditor are parallel duties, this ladder is purely the SOUND's direction.
const ROLE_RANK: Record<string, number> = { Viewer: 0, Auditor: 1, Analyst: 2, Admin: 3, Owner: 4 };
const EASE = [0.22, 1, 0.36, 1] as const; // the fleet's motionKit ease

const post = async (path: string, body: unknown) => {  const r = await fetch(`${API_URL}${path}`, {
    method: 'POST',
    credentials: 'include',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  const j = (await r.json().catch(() => ({}))) as { error?: string };
  if (!r.ok) throw new Error(j.error ?? (r.status === 429 ? 'Too many attempts — pause a moment.' : `HTTP ${r.status}`));
  return j;
};

function CapsLockHint({ on }: { on: boolean }) {
  if (!on) return null;
  return (
    <p role="status" style={{ color: '#fcd34d', fontSize: 12, margin: 0 }}>
      ⚠ Caps Lock is on
    </p>
  );
}

function Hint({ children }: { children: React.ReactNode }) {
  return <p style={{ color: '#64748b', fontSize: 12, margin: 0, lineHeight: 1.55 }}>{children}</p>;
}

// Round 30: every status line announces itself. Confirmations rise into
// place; errors shake once on arrival. The key follows the MESSAGE, so a
// repeated-but-changed error remounts → re-animates AND re-announces
// (role="alert" fires on mount). Reduced motion gets a plain fade.
function Note({ tone, shake, style, children }: { tone: 'ok' | 'err'; shake?: boolean; style?: React.CSSProperties; children: React.ReactNode }) {
  const reduced = useReducedMotion() ?? false;
  const animate = reduced
    ? { opacity: 1 }
    : shake
      ? { opacity: 1, y: 0, x: [0, -5, 5, -4, 4, -2, 2, 0] }
      : { opacity: 1, y: 0 };
  return (
    <motion.p
      role={tone === 'ok' ? 'status' : 'alert'}
      initial={reduced ? { opacity: 0 } : { opacity: 0, y: 8 }}
      animate={animate}
      transition={shake && !reduced ? { duration: 0.4 } : { duration: 0.3 }}
      style={{ fontSize: 13, margin: 0, color: tone === 'ok' ? '#4ade80' : '#f87171', ...style }}
    >
      {children}
    </motion.p>
  );
}

export default function AccountClient() {
  const router = useRouter();
  const [me, setMe] = useState<Me | null | undefined>(undefined);
  const [sessions, setSessions] = useState<SessionRow[] | null>(null);
  const [busy, setBusy] = useState(false);

  // password card state
  const [curPw, setCurPw] = useState('');
  const [newPw, setNewPw] = useState('');
  const [confirmPw, setConfirmPw] = useState('');
  const [caps, setCaps] = useState(false);
  const [pwMsg, setPwMsg] = useState('');
  const [pwErr, setPwErr] = useState('');

  // authenticator card state
  const [enrollStage, setEnrollStage] = useState<'idle' | 'confirm' | 'done'>('idle');
  const [enrollPw, setEnrollPw] = useState('');
  const [enrollCaps, setEnrollCaps] = useState(false);
  const [enroll, setEnroll] = useState<{ tempToken: string; manualKey: string } | null>(null);
  const [code, setCode] = useState('');
  const [enrollMsg, setEnrollMsg] = useState('');
  const [enrollErr, setEnrollErr] = useState('');
  const [copied, setCopied] = useState(false);
  const codeRef = useRef<HTMLInputElement>(null);
  const autoVerified = useRef(false);

  // recovery codes (round 22): remaining count + regenerate flow
  const [recRemaining, setRecRemaining] = useState<number | null>(null);
  const [recStage, setRecStage] = useState<'idle' | 'pw' | 'codes'>('idle');
  const [recPw, setRecPw] = useState('');
  const [recCodes, setRecCodes] = useState<string[]>([]);
  const [recCopied, setRecCopied] = useState(false);
  const [recErr, setRecErr] = useState('');
  const [recCaps, setRecCaps] = useState(false);

  // sessions card state
  const [sessionsErr, setSessionsErr] = useState('');

  // teammates card state (round 26) — Owner/Admin only
  const [team, setTeam] = useState<{ orgId: string; selfId: string; members: Teammate[] } | null>(null);
  const [teamErr, setTeamErr] = useState('');
  const [invUsername, setInvUsername] = useState('');
  const [invEmail, setInvEmail] = useState('');
  const [invRole, setInvRole] = useState<'Admin' | 'Analyst' | 'Viewer' | 'Auditor'>('Analyst');
  const [invTemp, setInvTemp] = useState<{ username: string; tempPassword: string } | null>(null);
  const [invCopied, setInvCopied] = useState(false);
  const [invErr, setInvErr] = useState('');
  // round 29: row actions (role change + removal) — one shared busy flag with
  // the invite form, plus a success note and a verbatim-error line
  const [teamMsg, setTeamMsg] = useState('');
  const [teamActionErr, setTeamActionErr] = useState('');

  // round 30: choreography state
  const reduced = useReducedMotion() ?? false;
  // Row motion shared by both lists: rise in from the left, COLLAPSE out on
  // removal (x-slid + height→0, so siblings reflow through it). Reduced
  // motion strips every transform — opacity only, no layout animation.
  const rowProps = (delay = 0): MotionProps =>
    reduced
      ? {
          initial: { opacity: 0 },
          animate: { opacity: 1 },
          exit: { opacity: 0, transition: { duration: 0.15 } },
          transition: { duration: 0.25, delay },
        }
      : {
          initial: { opacity: 0, x: -14 },
          animate: { opacity: 1, x: 0 },
          exit: { opacity: 0, x: 26, height: 0, transition: { duration: 0.3, ease: EASE } },
          transition: { duration: 0.45, ease: EASE, delay },
        };
  // A sweep of light crosses a roster row the moment its member is minted
  // (cyan) or its role register changes (the new role's hue). Fires once,
  // self-clears; keyed by USERNAME because the invite response carries no id.
  const [flash, setFlash] = useState<{ user: string; color: string } | null>(null);
  const flashTimer = useRef<number | null>(null);
  const fireFlash = (user: string, color: string) => {
    setFlash({ user, color });
    if (flashTimer.current) window.clearTimeout(flashTimer.current);
    flashTimer.current = window.setTimeout(() => setFlash(null), 1100);
  };
  useEffect(() => () => { if (flashTimer.current) window.clearTimeout(flashTimer.current); }, []);

  const refreshSessions = useCallback(async () => {
    try {
      const r = await apiFetch('/v1/auth/sessions');
      if (r.status === 401) {
        setSessionsErr('Session expired — sign in again to view devices.');
        setSessions([]);
        return;
      }
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      const j = (await r.json()) as { sessions: SessionRow[] };
      setSessions(j.sessions);
      setSessionsErr('');
    } catch (e) {
      setSessionsErr((e as Error).message);
    }
  }, []);

  const refreshRecovery = useCallback(async () => {
    try {
      const r = await apiFetch('/v1/auth/recovery-codes');
      if (r.ok) {
        const j = (await r.json()) as { remaining: number };
        setRecRemaining(j.remaining);
      }
    } catch {
      /* the count is informational — ignore failures */
    }
  }, []);

  const refreshTeam = useCallback(async () => {
    try {
      const r = await apiFetch('/v1/auth/teammates');
      if (r.status === 403) {
        setTeam(null); // role changed mid-session — the console simply hides
        return;
      }
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      const j = (await r.json()) as { orgId: string; selfId: string; members: Teammate[] };
      setTeam(j);
      setTeamErr('');
    } catch (e) {
      setTeamErr((e as Error).message);
    }
  }, []);

  useEffect(() => {
    (async () => {
      const u = await getMe();
      setMe(u);
      if (u) {
        void refreshSessions();
        void refreshRecovery();
        if (u.role === 'Owner' || u.role === 'Admin') void refreshTeam();
      }
    })();
  }, [refreshSessions, refreshRecovery, refreshTeam]);

  useEffect(() => {
    if (enrollStage === 'confirm') codeRef.current?.focus();
  }, [enrollStage]);

  const signedOut = () => {
    setAccess(null);
    setSessionId(null);
    router.push('/login');
  };

  // ── password rotation ──
  const changePassword = async () => {
    if (busy) return;
    setBusy(true);
    setPwErr('');
    setPwMsg('');
    try {
      const r = await apiFetch('/v1/auth/password', { method: 'POST', body: JSON.stringify({ currentPassword: curPw, newPassword: newPw }) });
      const j = (await r.json().catch(() => ({}))) as { error?: string; revokedOtherSessions?: number };
      if (!r.ok) throw new Error(j.error ?? `HTTP ${r.status}`);
      sfxGrant();
      setPwMsg(`Password rotated — ${j.revokedOtherSessions ?? 0} other session(s) signed out.`);
      setCurPw('');
      setNewPw('');
      setConfirmPw('');
      void refreshSessions();
    } catch (e) {
      sfxDeny();
      setPwErr((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  // ── sessions ──
  const revoke = async (id: string) => {
    if (busy) return;
    setBusy(true);
    try {
      const r = await apiFetch('/v1/auth/sessions/revoke', { method: 'POST', body: JSON.stringify({ jti: id }) });
      const j = (await r.json().catch(() => ({}))) as { error?: string; selfRevoked?: boolean };
      if (!r.ok) throw new Error(j.error ?? `HTTP ${r.status}`);
      sfxImpact(); // a device just lost its seat — purge reads as a hard cut
      if (j.selfRevoked) {
        signedOut();
        return;
      }
      void refreshSessions();
    } catch (e) {
      sfxDeny();
      setSessionsErr((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  const revokeAll = async () => {
    if (busy) return;
    setBusy(true);
    try {
      await apiFetch('/v1/auth/sessions/revoke-all', { method: 'POST' });
      sfxImpact();
      signedOut();
    } catch (e) {
      sfxDeny();
      setSessionsErr((e as Error).message);
      setBusy(false);
    }
  };

  // ── teammates: invite (round 26) ──
  // The 201 response carries the temp password exactly once — displayed in the
  // card, never stored. 409/400 surface the API's uniform messages verbatim.
  const inviteMember = async () => {
    if (busy) return;
    setBusy(true);
    setInvErr('');
    try {
      const r = await apiFetch('/v1/auth/invite', {
        method: 'POST',
        body: JSON.stringify({ email: invEmail.trim(), username: invUsername.trim(), role: invRole }),
      });
      const j = (await r.json().catch(() => ({}))) as { error?: string; tempPassword?: string; username?: string };
      if (!r.ok) throw new Error(j.error ?? `HTTP ${r.status}`);
      const minted = j.username ?? invUsername.trim();
      sfxGrant();
      setInvTemp({ username: minted, tempPassword: j.tempPassword ?? '' });
      setInvUsername('');
      setInvEmail('');
      await refreshTeam(); // then light the row — it only exists AFTER the refetch
      fireFlash(minted, ROLE_TONE[invRole]?.c ?? '#22d3ee'); // …in the color of the role it arrived with
    } catch (e) {
      sfxDeny();
      setInvErr((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  const copyInvTemp = async () => {
    if (!invTemp) return;
    try {
      await navigator.clipboard.writeText(invTemp.tempPassword);
      setInvCopied(true);
      window.setTimeout(() => setInvCopied(false), 1800);
    } catch {
      /* clipboard blocked — the text is selectable anyway */
    }
  };

  // ── teammates: role change + member removal (round 29) ──
  // The UI never OFFERS the foot-guns the API refuses: no controls on the
  // caller's own row (self-actions 400) or the Owner row (immutable 403).
  // Everything else goes through the real endpoints — a role change revokes
  // the member's refresh tokens server-side, so their NEXT sign-in carries
  // the new role; removal kills the account and every live session. Uniform
  // API messages (404 "Teammate not found", 403 Owner lines) surface verbatim.
  const changeRole = async (m: Teammate, role: string) => {
    if (busy) return;
    setBusy(true);
    setTeamMsg('');
    setTeamActionErr('');
    try {
      const r = await apiFetch(`/v1/auth/teammates/${encodeURIComponent(m.id)}`, {
        method: 'PATCH',
        body: JSON.stringify({ role }),
      });
      const j = (await r.json().catch(() => ({}))) as { error?: string };
      if (!r.ok) throw new Error(j.error ?? `HTTP ${r.status}`);
      sfxShift((ROLE_RANK[role] ?? 0) >= (ROLE_RANK[m.role] ?? 0)); // rising = promotion, falling = demotion
      fireFlash(m.username, ROLE_TONE[role]?.c ?? '#22d3ee'); // the row relights in its NEW register
      setTeamMsg(`${m.username} → ${role}. Their next sign-in carries the new role.`);
      void refreshTeam();
    } catch (e) {
      sfxDeny();
      setTeamActionErr((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  const removeMember = async (m: Teammate) => {
    if (busy) return;
    if (!window.confirm(`Remove ${m.username} from the org? Their sign-ins are revoked immediately and the account cannot log in again.`)) return;
    setBusy(true);
    setTeamMsg('');
    setTeamActionErr('');
    try {
      const r = await apiFetch(`/v1/auth/teammates/${encodeURIComponent(m.id)}`, { method: 'DELETE' });
      const j = (await r.json().catch(() => ({}))) as { error?: string };
      if (!r.ok) throw new Error(j.error ?? `HTTP ${r.status}`);
      sfxImpact(); // the row collapses out under this — a purge, not a fade
      setTeamMsg(`${m.username} removed — all their sessions were revoked.`);
      void refreshTeam();
    } catch (e) {
      sfxDeny();
      setTeamActionErr((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  // ── authenticator re-enrollment ──
  const startReenroll = async () => {
    if (busy || !me) return;
    setBusy(true);
    setEnrollErr('');
    try {
      // round-30 fix: this route runs under requireAuth (bearer only) — the old
      // cookie-only post() reached it with no Authorization header and had
      // ALWAYS failed live with "No token" (the login-page enroll never uses
      // this path). apiFetch attaches the memory-held bearer and silently
      // refreshes once on expiry, like every other authenticated call here.
      const r = await apiFetch('/v1/auth/totp/re-enroll', { method: 'POST', body: JSON.stringify({ password: enrollPw }) });
      const j = (await r.json().catch(() => ({}))) as { error?: string; tempToken: string; manualKey: string; revokedOtherSessions: number };
      if (!r.ok) throw new Error(j.error ?? `HTTP ${r.status}`);
      sfxBlip(700, 1500, 0.07, 0.028); // rising tick — the console awaits a code
      setEnroll({ tempToken: j.tempToken, manualKey: j.manualKey });
      setEnrollStage('confirm');
      setCode('');
      setEnrollMsg(j.revokedOtherSessions > 0 ? `${j.revokedOtherSessions} other session(s) signed out. Add the new key, then confirm.` : 'Add the new key, then confirm below.');
      autoVerified.current = false;
      setMe({ ...me, totpEnrolled: false });
      void refreshSessions();
    } catch (e) {
      sfxDeny();
      setEnrollErr((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  const verifyEnroll = async (explicit?: string) => {
    const c = explicit ?? code;
    if (busy || !enroll || c.length !== 6) return;
    setBusy(true);
    setEnrollErr('');
    try {
      const j = (await post('/v1/auth/verify-2fa', { tempToken: enroll.tempToken, code: c.trim() })) as { accessToken: string; sessionId?: string };
      sfxGrant();
      setAccess(j.accessToken);
      setSessionId(j.sessionId ?? null);
      setEnrollStage('done');
      setEnroll(null);
      setCode('');
      setEnrollMsg('Authenticator updated — this device holds the only live session.');
      setEnrollPw('');
      if (me) setMe({ ...me, totpEnrolled: true });
      void refreshSessions();
    } catch (e) {
      sfxDeny();
      setEnrollErr((e as Error).message);
      autoVerified.current = false; // re-arm so a corrected code auto-fires
    } finally {
      setBusy(false);
    }
  };

  const copyKey = async () => {
    if (!enroll) return;
    try {
      await navigator.clipboard.writeText(enroll.manualKey);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1800);
    } catch {
      /* clipboard blocked — the key is selectable text anyway */
    }
  };

  // ── recovery codes ──
  const regenerateRecovery = async () => {
    if (busy || recStage !== 'pw') return;
    setBusy(true);
    setRecErr('');
    try {
      const r = await apiFetch('/v1/auth/recovery-codes', { method: 'POST', body: JSON.stringify({ password: recPw }) });
      const j = (await r.json().catch(() => ({}))) as { error?: string; codes?: string[]; remaining?: number };
      if (!r.ok) throw new Error(j.error ?? `HTTP ${r.status}`);
      sfxGrant();
      setRecCodes(j.codes ?? []);
      setRecRemaining(j.remaining ?? (j.codes?.length ?? 0));
      setRecStage('codes');
      setRecPw('');
    } catch (e) {
      sfxDeny();
      setRecErr((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  const copyRecCodes = async () => {
    try {
      await navigator.clipboard.writeText(recCodes.join('\n'));
      setRecCopied(true);
      window.setTimeout(() => setRecCopied(false), 1800);
    } catch {
      /* clipboard blocked */
    }
  };

  if (me === undefined) {
    return (
      <p style={{ fontSize: 12, letterSpacing: 2, color: '#64748b', textAlign: 'center', marginTop: 40 }}>○ CHECKING SESSION…</p>
    );
  }

  if (me === null) {
    return (
      <Reveal>
        <Card style={{ maxWidth: 520, margin: '40px auto 0', textAlign: 'center' }}>
          <p className="sf-eyebrow">SF://ACCOUNT · GATED</p>
          <h3 style={{ margin: '8px 0' }}>No live session.</h3>
          <Hint>The security center needs a signed-in identity — memory-held token, HttpOnly refresh.</Hint>
          <div style={{ marginTop: 18 }}>
            <a className="sf-btn sf-btn-accent" href="/login">Sign in</a>
          </div>
        </Card>
      </Reveal>
    );
  }

  const checks = pwChecks(newPw);
  const strong = pwStrong(newPw);
  const match = newPw.length > 0 && newPw === confirmPw;
  const canManage = me.role === 'Owner' || me.role === 'Admin';

  const cardHead = (label: string, status?: React.ReactNode) => (
    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 10, marginBottom: 6 }}>
      <p className="sf-eyebrow" style={{ margin: 0 }}>{label}</p>
      {status}
    </div>
  );

  const field = (props: React.InputHTMLAttributes<HTMLInputElement>) => (
    <input className="sf-input" style={{ width: '100%' }} {...props} />
  );

  return (
    <div style={{ maxWidth: 1040, margin: '34px auto 0', display: 'grid', gap: 18, gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))' }}>
      {/* ── PASSWORD ── */}
      <Reveal delay={0.05}>
        <Card>
          {cardHead('SF://PASSWORD · ROTATE')}
          <Hint>Re-auth with the current password. Every other device is signed out; this one keeps its session.</Hint>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 10, marginTop: 14 }}>
            {field({ name: 'currentPassword', type: 'password', autoComplete: 'current-password', placeholder: 'Current password', 'aria-label': 'Current password', value: curPw, onChange: (e) => setCurPw(e.target.value), onKeyUp: (e) => setCaps(e.getModifierState?.('CapsLock') ?? false) })}
            <CapsLockHint on={caps} />
            {field({ name: 'newPassword', type: 'password', autoComplete: 'new-password', placeholder: 'New password', 'aria-label': 'New password', value: newPw, onChange: (e) => setNewPw(e.target.value) })}
            <ul style={{ listStyle: 'none', margin: 0, padding: 0, display: 'flex', flexWrap: 'wrap', gap: '4px 12px' }}>
              {PW_RULES.map(([label], i) => (
                <li key={label} style={{ fontSize: 11.5, letterSpacing: 0.4, color: checks[i] ? '#6ee7b7' : '#64748b' }}>
                  {checks[i] ? '✓' : '○'} {label}
                </li>
              ))}
            </ul>
            {field({ name: 'confirmPassword', type: 'password', autoComplete: 'new-password', placeholder: 'Confirm new password', 'aria-label': 'Confirm new password', value: confirmPw, onChange: (e) => setConfirmPw(e.target.value) })}
            {confirmPw.length > 0 && !match && <p style={{ color: '#f87171', fontSize: 12, margin: 0 }}>New passwords don't match</p>}
            <button className="sf-btn sf-btn-accent" disabled={busy || !strong || !match || !curPw} onClick={() => void changePassword()}>
              {busy ? 'Rotating…' : 'Rotate password'}
            </button>
            {pwMsg && <Note key={pwMsg} tone="ok">{pwMsg}</Note>}
            {pwErr && <Note key={pwErr} tone="err" shake>{pwErr}</Note>}
          </div>
        </Card>
      </Reveal>

      {/* ── AUTHENTICATOR ── */}
      <Reveal delay={0.12}>
        <Card>
          {cardHead(
            'SF://AUTHENTICATOR · TOTP',
            <span style={{ fontSize: 11, letterSpacing: 1, color: me.totpEnrolled ? '#6ee7b7' : '#fcd34d' }}>
              {me.totpEnrolled ? '● ENROLLED' : '○ NOT ENROLLED'}
            </span>
          )}
          {enrollStage === 'idle' && (
            <>
              <Hint>Lost the phone? One of your single-use recovery codes signs you in from the login page — or re-enroll here with your password. Re-enrollment signs out every other session, and if you abandon the flow your next login simply re-enrolls from scratch.</Hint>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 10, marginTop: 14 }}>
                {field({ name: 'enrollPassword', type: 'password', autoComplete: 'current-password', placeholder: 'Current password', 'aria-label': 'Current password for re-enrollment', value: enrollPw, onChange: (e) => setEnrollPw(e.target.value), onKeyUp: (e) => setEnrollCaps(e.getModifierState?.('CapsLock') ?? false) })}
                <CapsLockHint on={enrollCaps} />
                <button className="sf-btn sf-btn-accent" disabled={busy || !enrollPw} onClick={() => void startReenroll()}>
                  {busy ? 'Working…' : 'Start re-enrollment'}
                </button>
                {enrollErr && <Note key={enrollErr} tone="err" shake>{enrollErr}</Note>}
              </div>
              {/* ── recovery codes ── */}
              <div style={{ borderTop: '1px solid rgba(148,163,184,0.15)', marginTop: 16, paddingTop: 14 }}>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 10 }}>
                  <p style={{ margin: 0, fontSize: 11, letterSpacing: 2, color: '#64748b' }}>
                    RECOVERY CODES · {recRemaining === null ? '…' : `${recRemaining} UNUSED`}
                  </p>
                  {recStage === 'idle' && (
                    <button type="button" className="sf-btn" style={{ fontSize: 11, padding: '3px 10px' }} disabled={busy} onClick={() => { setRecStage('pw'); setRecErr(''); }}>
                      NEW SET
                    </button>
                  )}
                </div>
                {recStage === 'idle' && (
                  <Hint>
                    {recRemaining === 0
                      ? 'No unused codes left — generate a new set (shown once, stored hashed).'
                      : 'Single-use codes for the login page when your authenticator is gone. Stored as hashes; plaintext is shown only when generated.'}
                  </Hint>
                )}
                {recStage === 'pw' && (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 10, marginTop: 10 }}>
                    {field({ name: 'recoveryPassword', type: 'password', autoComplete: 'current-password', placeholder: 'Current password', 'aria-label': 'Current password to regenerate recovery codes', value: recPw, onChange: (e) => setRecPw(e.target.value), onKeyUp: (e) => setRecCaps(e.getModifierState?.('CapsLock') ?? false) })}
                    <CapsLockHint on={recCaps} />
                    <div style={{ display: 'flex', gap: 8 }}>
                      <button className="sf-btn sf-btn-accent" style={{ fontSize: 12 }} disabled={busy || !recPw} onClick={() => void regenerateRecovery()}>
                        {busy ? 'Working…' : 'Generate 10 new codes'}
                      </button>
                      <button className="sf-btn" style={{ fontSize: 12 }} disabled={busy} onClick={() => { setRecStage('idle'); setRecErr(''); setRecPw(''); }}>
                        Cancel
                      </button>
                    </div>
                    {recErr && <Note key={recErr} tone="err" shake>{recErr}</Note>}
                  </div>
                )}
                {recStage === 'codes' && (
                  <div style={{ marginTop: 10 }}>
                    <p style={{ color: '#fcd34d', fontSize: 12.5, margin: '0 0 8px' }}>Shown once — store them in your password manager now.</p>
                    <div className="sf-glass" onPointerMove={glassGlow} style={{ borderRadius: 10, padding: 12, display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 6 }}>
                      {recCodes.map((c) => (
                        <code key={c} style={{ color: '#a5f3fc', fontSize: 12, letterSpacing: 1 }}>{c}</code>
                      ))}
                    </div>
                    <div style={{ display: 'flex', gap: 8, marginTop: 10 }}>
                      <button type="button" className="sf-btn" style={{ fontSize: 12 }} onClick={() => void copyRecCodes()}>
                        {recCopied ? '✓ copied all 10' : 'copy all 10 codes'}
                      </button>
                      <button className="sf-btn" style={{ fontSize: 12 }} onClick={() => setRecStage('idle')}>
                        Done
                      </button>
                    </div>
                  </div>
                )}
              </div>
            </>
          )}
          {enrollStage === 'confirm' && enroll && (
            <div className="sf-glass" onPointerMove={glassGlow} style={{ borderRadius: 12, padding: 14, fontSize: 13, marginTop: 12 }}>
              <b style={{ color: '#fff' }}>Add this key to your authenticator app.</b>
              <p style={{ color: '#94a3b8', margin: '6px 0' }}>{enrollMsg}</p>
              <div style={{ display: 'flex', gap: 8, alignItems: 'stretch' }}>
                <code style={{ flex: 1, wordBreak: 'break-all', background: 'rgba(0,0,0,0.5)', borderRadius: 8, padding: 10, color: '#a5f3fc', fontSize: 12 }}>{enroll.manualKey}</code>
                <button type="button" className="sf-btn" style={{ fontSize: 11.5, padding: '0 12px' }} onClick={() => void copyKey()}>
                  {copied ? '✓ copied' : 'copy'}
                </button>
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 10, marginTop: 12 }}>
                <input
                  ref={codeRef}
                  className="sf-input"
                  name="code"
                  autoComplete="one-time-code"
                  inputMode="numeric"
                  maxLength={6}
                  placeholder="123456"
                  aria-label="Two-factor code"
                  value={code}
                  onChange={(e) => {
                    const v = e.target.value.replace(/\D/g, '');
                    setCode(v);
                    if (v.length === 6 && !autoVerified.current && !busy) {
                      autoVerified.current = true;
                      void verifyEnroll(v); // pass the fresh digits — state hasn't re-rendered yet
                    }
                  }}
                  style={{ letterSpacing: 6, textAlign: 'center', fontSize: 20 }}
                />
                <button className="sf-btn sf-btn-accent" disabled={busy || code.length !== 6} onClick={() => void verifyEnroll()}>
                  {busy ? 'Verifying…' : 'Confirm new authenticator'}
                </button>
                {enrollErr && <Note key={enrollErr} tone="err" shake>{enrollErr}</Note>}
              </div>
            </div>
          )}
          {enrollStage === 'done' && (
            <div style={{ marginTop: '12px' }}>
              <Note key={enrollMsg} tone="ok">{enrollMsg}</Note>
            </div>
          )}
        </Card>
      </Reveal>

      {/* ── TEAMMATES (round 26) — Owner/Admin console ── */}
      {canManage && (
        <Reveal delay={0.18}>
          <Card>
            {cardHead(
              'SF://TEAMMATES · ORG ROSTER',
              team ? (
                // round 30: the count flips when the roster changes shape
                <motion.span
                  key={team.members.length}
                  initial={reduced ? { opacity: 0 } : { opacity: 0, y: -6 }}
                  animate={reduced ? { opacity: 1 } : { opacity: 1, y: 0 }}
                  transition={{ duration: 0.3 }}
                  style={{ fontSize: 11, letterSpacing: 1, color: '#64748b' }}
                >
                  {team.members.length} MEMBERS
                </motion.span>
              ) : (
                <span style={{ fontSize: 11, letterSpacing: 1, color: '#64748b' }}>LOADING…</span>
              )
            )}
            <Hint>
              Everyone in your org. An invite mints the account in THIS org with a one-time temporary password — this prototype has no mail
              transport, so it is shown here exactly once (production emails a one-time link; documented in SECURITY.md). Owner is signup-only:
              no invite can mint a superior.
            </Hint>
            <div style={{ marginTop: 14, display: 'flex', flexDirection: 'column', gap: 8 }}>
              {teamErr && <Note key={teamErr} tone="err" shake>{teamErr}</Note>}
              {team && team.members.length === 0 && !teamErr && <p style={{ color: '#64748b', fontSize: 13, margin: 0 }}>No members yet.</p>}
              {/*
                Round 30: AnimatePresence owns the row lifecycle. OUTER motion
                div = layout only (siblings glide when a row unmounts); INNER
                = the enter/exit choreography (rise in, slide-fade out) — two
                elements so framer's layout transforms and the x-animation
                never write the same transform twice.
              */}
              <AnimatePresence>
                {(team?.members ?? []).map((m) => {
                  const tone = ROLE_TONE[m.role] ?? ROLE_TONE.Viewer;
                  return (
                    <motion.div key={m.id} layout={!reduced} style={{ overflow: 'hidden', borderRadius: 12 }}>
                      <motion.div
                        className="sf-glass"
                        onPointerMove={glassGlow}
                        {...rowProps()}
                        style={{ borderRadius: 12, padding: '12px 14px', display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap', position: 'relative', overflow: 'hidden' }}
                      >
                        {flash?.user === m.username && !reduced && (
                          <motion.span
                            aria-hidden
                            initial={{ x: '-120%' }}
                            animate={{ x: '120%', transition: { duration: 0.85, ease: 'easeInOut' } }}
                            style={{
                              position: 'absolute',
                              inset: 0,
                              borderRadius: 12,
                              pointerEvents: 'none',
                              background: `linear-gradient(105deg, transparent 26%, ${flash.color}1a 44%, ${flash.color}59 50%, ${flash.color}1a 56%, transparent 74%)`,
                            }}
                          />
                        )}
                        <code style={{ color: '#a5f3fc', fontSize: 12.5 }}>{m.username}</code>
                        <span style={{ fontSize: 11, color: '#64748b' }}>{m.email}</span>
                        {/*
                          Round 30: the chip's key follows the ROLE — changing
                          it remounts the chip alone (the row persists), so the
                          swap pops on a spring in the NEW role's hue.
                        */}
                        <motion.span
                          key={m.role}
                          initial={reduced ? { opacity: 0 } : { opacity: 0, scale: 0.55, y: 3 }}
                          animate={reduced ? { opacity: 1 } : { opacity: 1, scale: 1, y: 0 }}
                          transition={reduced ? { duration: 0.15 } : { type: 'spring', stiffness: 520, damping: 22 }}
                          style={{
                            fontSize: 10.5,
                            letterSpacing: 1.2,
                            color: tone.c,
                            border: `1px solid ${tone.b}`,
                            borderRadius: 999,
                            padding: '2px 9px',
                            background: 'rgba(2,6,23,0.4)',
                            display: 'inline-block',
                          }}
                        >
                          {m.role.toUpperCase()}
                        </motion.span>
                        {!m.totpEnrolled && (
                          <span style={{ fontSize: 10.5, letterSpacing: 1.2, color: '#fcd34d', border: '1px solid rgba(251,191,36,0.45)', borderRadius: 999, padding: '2px 9px' }}>
                            2FA PENDING
                          </span>
                        )}
                        {m.id === team?.selfId && (
                          <span
                            style={{
                              fontSize: 10.5,
                              letterSpacing: 1.2,
                              color: '#22d3ee',
                              border: '1px solid rgba(34,211,238,0.4)',
                              borderRadius: 999,
                              padding: '2px 9px',
                              background: 'rgba(34,211,238,0.08)',
                            }}
                          >
                            THIS ACCOUNT
                          </span>
                        )}
                        {m.lastLogin && <span style={{ fontSize: 11, color: '#64748b', marginLeft: 'auto' }}>last {new Date(m.lastLogin).toISOString().slice(0, 10)}</span>}
                        {/*
                          round 29: row actions — deliberately absent for the caller's
                          own row and the Owner row (the API refuses both anyway:
                          self 400, Owner 403; the UI never offers the foot-gun).
                        */}
                        {m.id !== team?.selfId && m.role !== 'Owner' && (
                          <span style={{ display: 'flex', gap: 8, alignItems: 'center', marginLeft: m.lastLogin ? 0 : 'auto' }}>
                            <select
                              className="sf-input"
                              aria-label={`Role for ${m.username}`}
                              value={m.role}
                              disabled={busy}
                              onChange={(e) => void changeRole(m, e.target.value)}
                              style={{ fontSize: 11.5, padding: '4px 8px', color: '#e2e8f0' }}
                            >
                              <option value="Admin">Admin</option>
                              <option value="Analyst">Analyst</option>
                              <option value="Viewer">Viewer</option>
                              <option value="Auditor">Auditor</option>
                            </select>
                            <button
                              type="button"
                              className="sf-btn"
                              disabled={busy}
                              onClick={() => void removeMember(m)}
                              style={{ fontSize: 11.5, padding: '5px 10px', color: '#f87171', borderColor: 'rgba(248,113,113,0.35)' }}
                            >
                              Remove
                            </button>
                          </span>
                        )}
                      </motion.div>
                    </motion.div>
                  );
                })}
              </AnimatePresence>
              {teamMsg && !teamActionErr && <Note key={teamMsg} tone="ok">✓ {teamMsg}</Note>}
              {teamActionErr && <Note key={teamActionErr} tone="err" shake>{teamActionErr}</Note>}
            </div>
            {/* invite form */}
            <div style={{ borderTop: '1px solid rgba(148,163,184,0.15)', marginTop: 16, paddingTop: 14, display: 'flex', flexDirection: 'column', gap: 10 }}>
              <p style={{ margin: 0, fontSize: 11, letterSpacing: 2, color: '#64748b' }}>INVITE A TEAMMATE</p>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10 }}>
                {field({ name: 'inviteUsername', placeholder: 'username', maxLength: 32, 'aria-label': 'New teammate username', value: invUsername, onChange: (e) => setInvUsername(e.target.value) })}
                {field({ name: 'inviteEmail', type: 'email', placeholder: 'email', maxLength: 256, 'aria-label': 'New teammate email', value: invEmail, onChange: (e) => setInvEmail(e.target.value) })}
              </div>
              <div style={{ display: 'flex', gap: 10, alignItems: 'stretch' }}>
                <select
                  className="sf-input"
                  name="inviteRole"
                  aria-label="Role for the new teammate"
                  value={invRole}
                  onChange={(e) => setInvRole(e.target.value as typeof invRole)}
                  style={{ flex: 1, color: '#e2e8f0' }}
                >
                  <option value="Analyst">Analyst — triage + scans</option>
                  <option value="Viewer">Viewer — read only</option>
                  <option value="Auditor">Auditor — audit trail</option>
                  <option value="Admin">Admin — manage users</option>
                </select>
                <button className="sf-btn sf-btn-accent" disabled={busy || !invUsername.trim() || !invEmail.trim()} onClick={() => void inviteMember()}>
                  {busy ? 'Inviting…' : 'Invite'}
                </button>
              </div>
              {invErr && <Note key={invErr} tone="err" shake>{invErr}</Note>}
              {invTemp && (
                <div className="sf-glass" onPointerMove={glassGlow} style={{ borderRadius: 12, padding: 14 }}>
                  <b style={{ color: '#fff', fontSize: 13 }}>Temporary password for {invTemp.username} — shown once.</b>
                  <p style={{ color: '#fcd34d', fontSize: 12, margin: '6px 0' }}>
                    Hand it over through a channel you trust. They enroll their own authenticator on first login, and this password never appears again.
                  </p>
                  <div style={{ display: 'flex', gap: 8, alignItems: 'stretch' }}>
                    <code style={{ flex: 1, wordBreak: 'break-all', background: 'rgba(0,0,0,0.5)', borderRadius: 8, padding: 10, color: '#a5f3fc', fontSize: 12 }}>
                      {invTemp.tempPassword}
                    </code>
                    <button type="button" className="sf-btn" style={{ fontSize: 11.5, padding: '0 12px' }} onClick={() => void copyInvTemp()}>
                      {invCopied ? '✓ copied' : 'copy'}
                    </button>
                  </div>
                  <button className="sf-btn" style={{ fontSize: 11.5, marginTop: 10 }} onClick={() => setInvTemp(null)}>
                    Done
                  </button>
                </div>
              )}
            </div>
          </Card>
        </Reveal>
      )}

      {/* ── SESSIONS ── */}
      <Reveal delay={0.24}>
        <Card style={{ gridColumn: '1 / -1' }}>
          {cardHead(
            'SF://SESSIONS · LIVE DEVICES',
            sessions ? (
              <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6, fontSize: 11, letterSpacing: 1, color: '#64748b' }}>
                {/* same radiating-ring dot the nav uses for API LIVE — green keyframe, already reduced-motion-gated in CSS */}
                <span className="sf-api-dot live" style={{ width: 7, height: 7, borderRadius: '50%', background: '#34d399', boxShadow: '0 0 9px #34d399' }} />
                <motion.span
                  key={sessions.length}
                  initial={reduced ? { opacity: 0 } : { opacity: 0, y: -6 }}
                  animate={reduced ? { opacity: 1 } : { opacity: 1, y: 0 }}
                  transition={{ duration: 0.3 }}
                >
                  {sessions.length} ACTIVE
                </motion.span>
              </span>
            ) : (
              <span style={{ fontSize: 11, letterSpacing: 1, color: '#64748b' }}>LOADING…</span>
            )
          )}
          <Hint>Every browser holding a live refresh cookie for this account. Revoking one cuts its ability to mint new access tokens; its short-lived access token dies naturally within minutes.</Hint>
          <div style={{ marginTop: 14, display: 'flex', flexDirection: 'column', gap: 8 }}>
            {sessionsErr && <Note key={sessionsErr} tone="err" shake>{sessionsErr}</Note>}
            {sessions && sessions.length === 0 && !sessionsErr && <p style={{ color: '#64748b', fontSize: 13, margin: 0 }}>No live sessions.</p>}
            <AnimatePresence>
              {(sessions ?? []).map((s) => (
                <motion.div key={s.id} layout={!reduced} style={{ overflow: 'hidden', borderRadius: 12 }}>
                  <motion.div
                    className="sf-glass"
                    onPointerMove={glassGlow}
                    {...rowProps()}
                    style={{ borderRadius: 12, padding: '12px 14px', display: 'flex', alignItems: 'center', gap: 12, flexWrap: 'wrap' }}
                  >
                    <code style={{ color: '#a5f3fc', fontSize: 12, letterSpacing: 1 }}>{s.id.slice(0, 8)}</code>
                    <span style={{ fontSize: 12, color: '#94a3b8' }}>since {new Date(s.createdAt).toISOString().slice(0, 10)}</span>
                    <span style={{ fontSize: 12, color: '#64748b' }}>expires in {s.expiresDays}d</span>
                    {s.current && (
                      <span style={{ fontSize: 10.5, letterSpacing: 1.2, color: '#22d3ee', border: '1px solid rgba(34,211,238,0.4)', borderRadius: 999, padding: '2px 9px', background: 'rgba(34,211,238,0.08)' }}>
                        THIS DEVICE
                      </span>
                    )}
                    <button
                      className="sf-btn"
                      style={{ marginLeft: 'auto', fontSize: 11, padding: '4px 12px', color: '#f87171', borderColor: 'rgba(248,113,113,0.4)' }}
                      disabled={busy}
                      onClick={() => void revoke(s.id)}
                    >
                      REVOKE
                    </button>
                  </motion.div>
                </motion.div>
              ))}
            </AnimatePresence>
            {sessions && sessions.length > 0 && (
              <button className="sf-btn" style={{ alignSelf: 'flex-start', marginTop: 6, fontSize: 11.5, color: '#f87171', borderColor: 'rgba(248,113,113,0.4)' }} disabled={busy} onClick={() => void revokeAll()}>
                {busy ? 'Working…' : 'SIGN OUT EVERYWHERE'}
              </button>
            )}
          </div>
        </Card>
      </Reveal>
    </div>
  );
}
