'use client';
import { useEffect, useRef, useState } from 'react';
import { useRouter } from 'next/navigation';
import { motion } from 'framer-motion';
import { Card, glassGlow } from '../components/ui';
import { setAccess, setSessionId, API_URL } from '../lib/auth';
import { PW_RULES, pwChecks, pwStrong } from '../lib/pwRules';

// Shared auth card: signup creates the org + owner, login runs password → TOTP.
// On success the access token lands in MEMORY (lib/auth) and silent refresh via
// the HttpOnly cookie keeps every gated panel working across reloads.
//
// Round-19 audit upgrades: real <form> elements (Enter submits every step,
// password managers autodetect properly), a live password-requirements
// checklist on signup, a "stay signed in for 30 days" choice wired through to
// the API (both login and verify steps — it used to be dead code), auto-verify
// when the 6th TOTP digit lands, a copy button for the enrollment key, and a
// caps-lock warning on the password fields.

function CapsLockHint({ on }: { on: boolean }) {
  if (!on) return null;
  return (
    <p role="status" style={{ color: '#fcd34d', fontSize: 12, margin: 0 }}>
      ⚠ Caps Lock is on
    </p>
  );
}

export default function AuthForm({ mode }: { mode: 'login' | 'signup' }) {
  const router = useRouter();
  const [orgName, setOrgName] = useState('');
  const [username, setUsername] = useState('');
  const [email, setEmail] = useState('');
  const [identifier, setIdentifier] = useState('');
  const [password, setPassword] = useState('');
  const [code, setCode] = useState('');
  const [tempToken, setTempToken] = useState<string | null>(null);
  const [enroll, setEnroll] = useState<{ otpauthUrl: string; manualKey: string } | null>(null);
  const [err, setErr] = useState('');
  const [busy, setBusy] = useState(false);
  const [done, setDone] = useState('');
  const [remember, setRemember] = useState(false);
  const [caps, setCaps] = useState(false);
  const [copied, setCopied] = useState(false);
  const codeRef = useRef<HTMLInputElement>(null);
  const autoVerified = useRef(false); // the 6th digit auto-fires verify exactly once

  useEffect(() => {
    if (tempToken) codeRef.current?.focus();
  }, [tempToken]);

  const post = async (path: string, body: unknown) => {
    // credentials: 'include' is REQUIRED — cross-origin XHR (3005 → 4000)
    // ignores Set-Cookie otherwise, so the HttpOnly refresh cookie never lands
    // and the session dies on the next full page load.
    const r = await fetch(`${API_URL}${path}`, { method: 'POST', credentials: 'include', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
    const j = await r.json().catch(() => ({}));
    if (!r.ok) {
      const api = (j as { error?: string }).error;
      if (api) throw new Error(api);
      if (r.status === 429) throw new Error('Too many attempts — pause a minute and try again.');
      throw new Error(`HTTP ${r.status}`);
    }
    return j;
  };

  const signup = async () => {
    setBusy(true);
    setErr('');
    try {
      await post('/v1/auth/signup', { orgName: orgName.trim(), username: username.trim(), email: email.trim(), password });
      setDone('Workspace created. Now log in with your username + password.');
      setIdentifier(email.trim());
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  const login = async () => {
    if (busy) return;
    setBusy(true);
    setErr('');
    try {
      const j = (await post('/v1/auth/login', { identifier: identifier.trim(), password, rememberMe: remember })) as {
        step: string;
        tempToken: string;
        otpauthUrl?: string;
        manualKey?: string;
      };
      setTempToken(j.tempToken);
      setEnroll(j.step === 'enroll' && j.otpauthUrl && j.manualKey ? { otpauthUrl: j.otpauthUrl, manualKey: j.manualKey } : null);
      setCode('');
      autoVerified.current = false;
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  const verify = async (explicit?: string) => {
    const c = explicit ?? code;
    if (busy || !tempToken || c.length !== 6) return;
    setBusy(true);
    setErr('');
    try {
      const j = (await post('/v1/auth/verify-2fa', { tempToken, code: c.trim(), rememberMe: remember })) as { accessToken: string; sessionId?: string };
      setAccess(j.accessToken);
      setSessionId(j.sessionId ?? null);
      router.push('/');
    } catch (e) {
      setErr((e as Error).message);
      autoVerified.current = false; // allow the next full code to auto-fire again
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

  const checks = pwChecks(password);
  const strong = pwStrong(password);

  return (
    <motion.div initial={{ opacity: 0, y: 24 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.6, ease: [0.22, 1, 0.36, 1] }}>
      <Card style={{ marginTop: 0, maxWidth: 460 }}>
        <h2 style={{ margin: '0 0 4px' }}>{mode === 'login' ? 'Welcome back' : 'Create workspace'}</h2>
        <p style={{ color: '#94a3b8', fontSize: 13.5, margin: '0 0 16px' }}>
          {mode === 'login' ? 'Password, then your 6-digit authenticator code.' : 'One org per workspace — you join as Owner. Passwords need 10+ chars, upper, lower, digit, symbol.'}
        </p>
        {mode === 'signup' ? (
          <form
            style={{ display: 'flex', flexDirection: 'column', gap: 10 }}
            onSubmit={(e) => {
              e.preventDefault();
              if (!busy && strong) void signup();
            }}
          >
            <input className="sf-input" name="orgName" aria-label="Organization name" placeholder="Organization name" value={orgName} onChange={(e) => setOrgName(e.target.value)} />
            <input className="sf-input" name="username" aria-label="Username" autoComplete="username" placeholder="username (letters, numbers, _ . -)" value={username} onChange={(e) => setUsername(e.target.value)} />
            <input className="sf-input" name="email" aria-label="Email" autoComplete="email" placeholder="you@company.com" value={email} onChange={(e) => setEmail(e.target.value)} />
            <input
              className="sf-input"
              name="password"
              aria-label="Password"
              autoComplete="new-password"
              type="password"
              placeholder="Password (10+ chars, mixed)"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              onKeyUp={(e) => setCaps(e.getModifierState?.('CapsLock') ?? false)}
            />
            <CapsLockHint on={caps} />
            {/* live requirements checklist — every rule lights up as it's met */}
            <ul style={{ listStyle: 'none', margin: 0, padding: 0, display: 'flex', flexWrap: 'wrap', gap: '4px 12px' }}>
              {PW_RULES.map(([label], i) => (
                <li key={label} style={{ fontSize: 11.5, letterSpacing: 0.4, color: checks[i] ? '#6ee7b7' : '#64748b' }}>
                  {checks[i] ? '✓' : '○'} {label}
                </li>
              ))}
            </ul>
            <button className="sf-btn sf-btn-accent" type="submit" disabled={busy || !strong}>
              {busy ? 'Creating workspace…' : 'Create workspace'}
            </button>
            {done && (
              <p style={{ color: '#6ee7b7', fontSize: 13 }}>
                {done} <a href="/login" style={{ color: '#22d3ee' }}>Go to login →</a>
              </p>
            )}
          </form>
        ) : tempToken === null ? (
          <form
            style={{ display: 'flex', flexDirection: 'column', gap: 10 }}
            onSubmit={(e) => {
              e.preventDefault();
              void login();
            }}
          >
            <input className="sf-input" name="identifier" aria-label="Email or username" autoComplete="username" placeholder="Email or username" value={identifier} onChange={(e) => setIdentifier(e.target.value)} />
            <input
              className="sf-input"
              name="password"
              aria-label="Password"
              autoComplete="current-password"
              type="password"
              placeholder="Password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              onKeyUp={(e) => setCaps(e.getModifierState?.('CapsLock') ?? false)}
            />
            <CapsLockHint on={caps} />
            <label style={{ display: 'inline-flex', alignItems: 'center', gap: 8, fontSize: 13, color: '#94a3b8', cursor: 'pointer' }}>
              <input type="checkbox" checked={remember} onChange={(e) => setRemember(e.target.checked)} style={{ accentColor: '#22d3ee' }} />
              Stay signed in for 30 days
            </label>
            <button className="sf-btn sf-btn-accent" type="submit" disabled={busy}>
              {busy ? 'Checking password…' : 'Continue'}
            </button>
            <p style={{ fontSize: 13, color: '#94a3b8', margin: 0 }}>
              No workspace yet? <a href="/signup" style={{ color: '#22d3ee' }}>Create one →</a>
            </p>
          </form>
        ) : (
          <form
            style={{ display: 'flex', flexDirection: 'column', gap: 10 }}
            onSubmit={(e) => {
              e.preventDefault();
              void verify();
            }}
          >
            {enroll ? (
              <div className="sf-glass" onPointerMove={glassGlow} style={{ borderRadius: 12, padding: 14, fontSize: 13 }}>
                <b style={{ color: '#fff' }}>First login — enroll your authenticator.</b>
                <p style={{ color: '#94a3b8', margin: '6px 0' }}>
                  Add this key to Google Authenticator / 1Password / Authy (manual entry), then enter the current code below.
                </p>
                <div style={{ display: 'flex', gap: 8, alignItems: 'stretch' }}>
                  <code style={{ flex: 1, wordBreak: 'break-all', background: 'rgba(0,0,0,0.5)', borderRadius: 8, padding: 10, color: '#a5f3fc', fontSize: 12 }}>{enroll.manualKey}</code>
                  <button type="button" className="sf-btn" style={{ fontSize: 11.5, padding: '0 12px' }} onClick={() => void copyKey()}>
                    {copied ? '✓ copied' : 'copy'}
                  </button>
                </div>
              </div>
            ) : (
              <p style={{ fontSize: 13, color: '#94a3b8', margin: 0 }}>Password accepted. Enter the 6-digit code from your authenticator app.</p>
            )}
            <input
              ref={codeRef}
              className="sf-input"
              name="code"
              aria-label="Two-factor code"
              autoComplete="one-time-code"
              placeholder="123456"
              inputMode="numeric"
              maxLength={6}
              value={code}
              onChange={(e) => {
                const v = e.target.value.replace(/\D/g, '');
                setCode(v);
                // auto-verify when the last digit lands (once per attempt —
                // wrong codes re-arm it so a corrected entry still auto-fires)
                if (v.length === 6 && !autoVerified.current && !busy) {
                  autoVerified.current = true;
                  void verify(v); // pass the fresh digits — state hasn't re-rendered yet
                }
              }}
              style={{ letterSpacing: 6, textAlign: 'center', fontSize: 20 }}
            />
            <label style={{ display: 'inline-flex', alignItems: 'center', gap: 8, fontSize: 13, color: '#94a3b8', cursor: 'pointer' }}>
              <input type="checkbox" checked={remember} onChange={(e) => setRemember(e.target.checked)} style={{ accentColor: '#22d3ee' }} />
              Stay signed in for 30 days
            </label>
            <button className="sf-btn sf-btn-accent" type="submit" disabled={busy || code.length !== 6}>
              {busy ? 'Verifying…' : 'Verify + sign in'}
            </button>
            <button className="sf-btn" type="button" onClick={() => { setTempToken(null); setEnroll(null); setCode(''); }} disabled={busy}>
              Back
            </button>
          </form>
        )}
        {err && <p role="alert" style={{ color: '#f87171', fontSize: 13 }}>{err}</p>}
      </Card>
    </motion.div>
  );
}
