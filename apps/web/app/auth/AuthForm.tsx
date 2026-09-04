'use client';
import { useState } from 'react';
import { useRouter } from 'next/navigation';
import { motion } from 'framer-motion';
import { Card } from '../components/ui';
import { setAccess } from '../lib/auth';

// Shared auth card: signup creates the org + owner, login runs password → TOTP.
// On success the access token lands in MEMORY (lib/auth) and silent refresh via
// the HttpOnly cookie keeps every gated panel working across reloads.
const API = process.env.NEXT_PUBLIC_API_URL ?? 'http://localhost:4000';

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

  const post = async (path: string, body: unknown) => {
    const r = await fetch(`${API}${path}`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
    const j = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error((j as { error?: string }).error ?? `HTTP ${r.status}`);
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
    setBusy(true);
    setErr('');
    try {
      const j = (await post('/v1/auth/login', { identifier: identifier.trim(), password })) as {
        step: string;
        tempToken: string;
        otpauthUrl?: string;
        manualKey?: string;
      };
      setTempToken(j.tempToken);
      setEnroll(j.step === 'enroll' && j.otpauthUrl && j.manualKey ? { otpauthUrl: j.otpauthUrl, manualKey: j.manualKey } : null);
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  const verify = async () => {
    setBusy(true);
    setErr('');
    try {
      const j = (await post('/v1/auth/verify-2fa', { tempToken, code: code.trim() })) as { accessToken: string };
      setAccess(j.accessToken);
      router.push('/');
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <motion.div initial={{ opacity: 0, y: 24 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.6, ease: [0.22, 1, 0.36, 1] }}>
      <Card style={{ marginTop: 0, maxWidth: 460 }}>
        <h2 style={{ margin: '0 0 4px' }}>{mode === 'login' ? 'Welcome back' : 'Create workspace'}</h2>
        <p style={{ color: '#94a3b8', fontSize: 13.5, margin: '0 0 16px' }}>
          {mode === 'login' ? 'Password, then your 6-digit authenticator code.' : 'One org per workspace — you join as Owner. Passwords need 10+ chars, upper, lower, digit, symbol.'}
        </p>
        {mode === 'signup' ? (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
            <input className="sf-input" aria-label="Organization name" placeholder="Organization name" value={orgName} onChange={(e) => setOrgName(e.target.value)} />
            <input className="sf-input" aria-label="Username" autoComplete="username" placeholder="username (letters, numbers, _ . -)" value={username} onChange={(e) => setUsername(e.target.value)} />
            <input className="sf-input" aria-label="Email" autoComplete="email" placeholder="you@company.com" value={email} onChange={(e) => setEmail(e.target.value)} />
            <input className="sf-input" aria-label="Password" autoComplete="new-password" type="password" placeholder="Password (10+ chars, mixed)" value={password} onChange={(e) => setPassword(e.target.value)} />
            <button className="sf-btn sf-btn-accent" onClick={signup} disabled={busy}>Create workspace</button>
            {done && <p style={{ color: '#6ee7b7', fontSize: 13 }}>{done} <a href="/login" style={{ color: '#22d3ee' }}>Go to login →</a></p>}
          </div>
        ) : tempToken === null ? (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
            <input className="sf-input" aria-label="Email or username" autoComplete="username" placeholder="Email or username" value={identifier} onChange={(e) => setIdentifier(e.target.value)} />
            <input className="sf-input" aria-label="Password" autoComplete="current-password" type="password" placeholder="Password" value={password} onChange={(e) => setPassword(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && void login()} />
            <button className="sf-btn sf-btn-accent" onClick={login} disabled={busy}>Continue</button>
            <p style={{ fontSize: 13, color: '#94a3b8' }}>No workspace yet? <a href="/signup" style={{ color: '#22d3ee' }}>Create one →</a></p>
          </div>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
            {enroll ? (
              <div className="sf-glass" style={{ borderRadius: 12, padding: 14, fontSize: 13 }}>
                <b style={{ color: '#fff' }}>First login — enroll your authenticator.</b>
                <p style={{ color: '#94a3b8', margin: '6px 0' }}>
                  Add this key to Google Authenticator / 1Password / Authy (manual entry), then enter the current code below.
                </p>
                <code style={{ display: 'block', wordBreak: 'break-all', background: 'rgba(0,0,0,0.5)', borderRadius: 8, padding: 10, color: '#a5f3fc', fontSize: 12 }}>{enroll.manualKey}</code>
              </div>
            ) : (
              <p style={{ fontSize: 13, color: '#94a3b8', margin: 0 }}>Password accepted. Enter the 6-digit code from your authenticator app.</p>
            )}
            <input className="sf-input" aria-label="Two-factor code" autoComplete="one-time-code" placeholder="123456" inputMode="numeric" maxLength={6} value={code} onChange={(e) => setCode(e.target.value.replace(/\D/g, ''))} onKeyDown={(e) => e.key === 'Enter' && void verify()} style={{ letterSpacing: 6, textAlign: 'center', fontSize: 20 }} />
            <button className="sf-btn sf-btn-accent" onClick={verify} disabled={busy || code.length !== 6}>Verify + sign in</button>
            <button className="sf-btn" onClick={() => { setTempToken(null); setEnroll(null); setCode(''); }} disabled={busy}>Back</button>
          </div>
        )}
        {err && <p style={{ color: '#f87171', fontSize: 13 }}>{err}</p>}
      </Card>
    </motion.div>
  );
}
