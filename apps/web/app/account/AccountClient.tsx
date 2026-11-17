'use client';
import { useCallback, useEffect, useRef, useState } from 'react';
import { useRouter } from 'next/navigation';
import { Card, glassGlow } from '../components/ui';
import { Reveal } from '../motionKit';
import { apiFetch, getMe, setAccess, setSessionId, API_URL } from '../lib/auth';
import { pwChecks, pwStrong, PW_RULES } from '../lib/pwRules';

// Account Security Center (round 20, extended round 26). Four consoles:
//   PASSWORD     — rotate with re-auth; other sessions die, this one survives
//   SESSIONS     — live device list, per-device revoke, sign-out-everywhere
//   AUTHENTICATOR— re-enroll TOTP via password re-auth + standard verify step
//   TEAMMATES    — org roster + invite console (Owner/Admin only; the round-24
//                  invite endpoint finally gets its UI, plus the round-26
//                  org-scoped roster read)
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
      setPwMsg(`Password rotated — ${j.revokedOtherSessions ?? 0} other session(s) signed out.`);
      setCurPw('');
      setNewPw('');
      setConfirmPw('');
      void refreshSessions();
    } catch (e) {
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
      if (j.selfRevoked) {
        signedOut();
        return;
      }
      void refreshSessions();
    } catch (e) {
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
      signedOut();
    } catch (e) {
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
      setInvTemp({ username: j.username ?? invUsername.trim(), tempPassword: j.tempPassword ?? '' });
      setInvUsername('');
      setInvEmail('');
      void refreshTeam();
    } catch (e) {
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

  // ── authenticator re-enrollment ──
  const startReenroll = async () => {
    if (busy || !me) return;
    setBusy(true);
    setEnrollErr('');
    try {
      const j = (await post('/v1/auth/totp/re-enroll', { password: enrollPw })) as { tempToken: string; manualKey: string; revokedOtherSessions: number };
      setEnroll({ tempToken: j.tempToken, manualKey: j.manualKey });
      setEnrollStage('confirm');
      setCode('');
      setEnrollMsg(j.revokedOtherSessions > 0 ? `${j.revokedOtherSessions} other session(s) signed out. Add the new key, then confirm.` : 'Add the new key, then confirm below.');
      autoVerified.current = false;
      setMe({ ...me, totpEnrolled: false });
      void refreshSessions();
    } catch (e) {
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
      setRecCodes(j.codes ?? []);
      setRecRemaining(j.remaining ?? (j.codes?.length ?? 0));
      setRecStage('codes');
      setRecPw('');
    } catch (e) {
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
            {pwMsg && <p role="status" style={{ color: '#6ee7b7', fontSize: 13, margin: 0 }}>{pwMsg}</p>}
            {pwErr && <p role="alert" style={{ color: '#f87171', fontSize: 13, margin: 0 }}>{pwErr}</p>}
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
                {enrollErr && <p role="alert" style={{ color: '#f87171', fontSize: 13, margin: 0 }}>{enrollErr}</p>}
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
                    {recErr && <p role="alert" style={{ color: '#f87171', fontSize: 12.5, margin: 0 }}>{recErr}</p>}
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
                {enrollErr && <p role="alert" style={{ color: '#f87171', fontSize: 13, margin: 0 }}>{enrollErr}</p>}
              </div>
            </div>
          )}
          {enrollStage === 'done' && (
            <p role="status" style={{ color: '#6ee7b7', fontSize: 13, margin: '12px 0 0' }}>{enrollMsg}</p>
          )}
        </Card>
      </Reveal>

      {/* ── TEAMMATES (round 26) — Owner/Admin console ── */}
      {canManage && (
        <Reveal delay={0.18}>
          <Card>
            {cardHead(
              'SF://TEAMMATES · ORG ROSTER',
              <span style={{ fontSize: 11, letterSpacing: 1, color: '#64748b' }}>{team ? `${team.members.length} MEMBERS` : 'LOADING…'}</span>
            )}
            <Hint>
              Everyone in your org. An invite mints the account in THIS org with a one-time temporary password — this prototype has no mail
              transport, so it is shown here exactly once (production emails a one-time link; documented in SECURITY.md). Owner is signup-only:
              no invite can mint a superior.
            </Hint>
            <div style={{ marginTop: 14, display: 'flex', flexDirection: 'column', gap: 8 }}>
              {teamErr && <p role="alert" style={{ color: '#f87171', fontSize: 13, margin: 0 }}>{teamErr}</p>}
              {team && team.members.length === 0 && !teamErr && <p style={{ color: '#64748b', fontSize: 13, margin: 0 }}>No members yet.</p>}
              {(team?.members ?? []).map((m) => {
                const tone = ROLE_TONE[m.role] ?? ROLE_TONE.Viewer;
                return (
                  <div
                    key={m.id}
                    className="sf-glass"
                    onPointerMove={glassGlow}
                    style={{ borderRadius: 12, padding: '12px 14px', display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}
                  >
                    <code style={{ color: '#a5f3fc', fontSize: 12.5 }}>{m.username}</code>
                    <span style={{ fontSize: 11, color: '#64748b' }}>{m.email}</span>
                    <span
                      style={{
                        fontSize: 10.5,
                        letterSpacing: 1.2,
                        color: tone.c,
                        border: `1px solid ${tone.b}`,
                        borderRadius: 999,
                        padding: '2px 9px',
                        background: 'rgba(2,6,23,0.4)',
                      }}
                    >
                      {m.role.toUpperCase()}
                    </span>
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
                  </div>
                );
              })}
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
              {invErr && <p role="alert" style={{ color: '#f87171', fontSize: 12.5, margin: 0 }}>{invErr}</p>}
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
            <span style={{ fontSize: 11, letterSpacing: 1, color: '#64748b' }}>{sessions ? `${sessions.length} ACTIVE` : 'LOADING…'}</span>
          )}
          <Hint>Every browser holding a live refresh cookie for this account. Revoking one cuts its ability to mint new access tokens; its short-lived access token dies naturally within minutes.</Hint>
          <div style={{ marginTop: 14, display: 'flex', flexDirection: 'column', gap: 8 }}>
            {sessionsErr && <p role="alert" style={{ color: '#f87171', fontSize: 13, margin: 0 }}>{sessionsErr}</p>}
            {sessions && sessions.length === 0 && !sessionsErr && <p style={{ color: '#64748b', fontSize: 13, margin: 0 }}>No live sessions.</p>}
            {(sessions ?? []).map((s) => (
              <div
                key={s.id}
                className="sf-glass"
                onPointerMove={glassGlow}
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
              </div>
            ))}
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
