'use client';
import { useEffect, useRef, useState } from 'react';
import { motion } from 'framer-motion';
import { apiFetch, getAccess } from './lib/auth';

// Emulator console (spec §6): live boot console, snapshot + step-by-step replay,
// crash list with repro bundles. Identity comes from the memory token (silent
// refresh); attestation id persists locally. Same API + gates, cinematic skin.

type Session = {
  id: string;
  arch: string;
  memoryMb: number;
  backend: string;
  status: string;
  bootLog: string[];
  inputTrace: string[];
  snapshots: { id: string; stateHash: string; inputTrace: string[]; createdAt: string; note?: string }[];
  crashes: { id: string; reason: string; snapshotId: string | null; inputTrace: string[]; at: string }[];
};

const STATUS_COLOR: Record<string, string> = { ready: '#34d399', crashed: '#f43f5e', stopped: '#64748b', booting: '#f59e0b' };

export default function EmulatorPanel() {
  const [signedIn, setSignedIn] = useState<boolean | null>(null);
  const [att, setAtt] = useState('');
  const [session, setSession] = useState<Session | null>(null);
  const [arch, setArch] = useState('arm');
  const [input, setInput] = useState('');
  const [replayOut, setReplayOut] = useState('');
  const [err, setErr] = useState('');
  const consoleRef = useRef<HTMLPreElement>(null);

  useEffect(() => {
    setAtt(localStorage.getItem('sf_att') ?? '');
    // Deep-link from attack sim: load its session if we have none yet.
    (async () => {
      const tok = await getAccess();
      setSignedIn(!!tok);
      const last = localStorage.getItem('sf_last_session');
      if (last && tok) {
        try {
          const r = await apiFetch(`/v1/emulator/sessions/${last}`, { method: 'GET' });
          if (r.ok) {
            const j = await r.json();
            if (j?.id) setSession(j);
          }
        } catch {
          /* session expired with the last boot — boot a fresh twin */
        }
      }
    })();
  }, []);
  useEffect(() => {
    consoleRef.current?.scrollTo({ top: 99999 });
  }, [session?.bootLog.length]);

  const save = () => {
    localStorage.setItem('sf_att', att);
  };
  const call = async (path: string, method: string, body?: unknown, gated = false) => {
    setErr('');
    if (!gated && signedIn === false) throw new Error('Sign in at /login first.');
    const tok = await getAccess();
    if (!tok) {
      setSignedIn(false);
      throw new Error('No session — sign in at /login first.');
    }
    setSignedIn(true);
    const attId = att || localStorage.getItem('sf_att') || '';
    const headers: Record<string, string> = {};
    if (gated) {
      if (!attId) throw new Error('Attestation required — register the device at /devices first.');
      headers['x-attestation-id'] = attId;
    }
    const r = await apiFetch(path, { method, headers, body: body ? JSON.stringify(body) : undefined });
    const j = await r.json().catch(() => ({}));
    if (r.status === 401) {
      setSignedIn(false);
      throw new Error('Session expired — sign in at /login, then retry.');
    }
    if (!r.ok) throw new Error((j as { error?: string }).error ?? `HTTP ${r.status}`);
    return j;
  };

  const boot = async () => {
    save();
    setSession(await call('/v1/emulator/sessions', 'POST', { arch, memoryMb: 256 }, true));
  };
  const refresh = async () => {
    if (session) setSession(await call(`/v1/emulator/sessions/${session.id}`, 'GET'));
  };
  const send = async () => {
    if (!session || !input) return;
    setSession(await call(`/v1/emulator/sessions/${session.id}/input`, 'POST', { input }, true));
    setInput('');
  };
  const snap = async () => {
    if (session) setSession(await awaitRefresh(call(`/v1/emulator/sessions/${session.id}/snapshots`, 'POST', {})));
  };
  const awaitRefresh = async <T,>(p: Promise<T>): Promise<Session> => {
    await p;
    return (await call(`/v1/emulator/sessions/${session!.id}`, 'GET')) as Session;
  };
  const replay = async (snapshotId: string) => {
    if (!session) return;
    const r = (await call(`/v1/emulator/sessions/${session.id}/replay`, 'POST', { snapshotId })) as { match: boolean; detail: string };
    setReplayOut(`${snapshotId}: ${r.match ? 'MATCH ✓' : 'DIVERGED ✗'} — ${r.detail}`);
  };

  return (
    <motion.section
      initial={{ opacity: 0, y: 26 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.7, ease: [0.22, 1, 0.36, 1] }}
      className="sf-glass"
      style={{ borderRadius: 20, padding: 24, marginTop: 28 }}
    >
      <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', marginBottom: 14, alignItems: 'center' }}>
        {signedIn === false ? (
          <a className="sf-btn sf-btn-accent" href="/login">Sign in to boot twins</a>
        ) : (
          <span style={{ fontSize: 12, letterSpacing: 2, color: signedIn ? '#6ee7b7' : '#64748b' }}>
            {signedIn ? '● SIGNED IN' : '○ CHECKING SESSION…'}
          </span>
        )}
        <input className="sf-input" placeholder="attestation id" value={att} onChange={(e) => setAtt(e.target.value)} style={{ flex: 1, minWidth: 160 }} />
        <select className="sf-input" value={arch} onChange={(e) => setArch(e.target.value)}>
          {['arm', 'aarch64', 'mips', 'mipsel', 'x86', 'x86_64', 'riscv64'].map((a) => (
            <option key={a} value={a}>{a}</option>
          ))}
        </select>
        <button className="sf-btn sf-btn-accent" onClick={boot}>Boot twin</button>
        <button className="sf-btn" onClick={refresh} disabled={!session}>Refresh</button>
      </div>
      {err && <p style={{ color: '#f87171', fontSize: 13 }}>{err}</p>}
      {session && (
        <>
          <p style={{ color: '#94a3b8', fontSize: 13 }}>
            <code style={{ color: '#a5f3fc' }}>{session.id}</code> · {session.arch} · {session.memoryMb}MB · {session.backend} · status:{' '}
            <b style={{ color: STATUS_COLOR[session.status] ?? '#e2e8f0' }}>{session.status.toUpperCase()}</b>
          </p>
          <pre ref={consoleRef} className="sf-console">{(session.bootLog ?? []).join('\n')}</pre>
          <div style={{ display: 'flex', gap: 8, marginTop: 10 }}>
            <input className="sf-input" placeholder="console input — Enter to send" value={input} onChange={(e) => setInput(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && void send()} style={{ flex: 1 }} />
            <button className="sf-btn" onClick={send}>Send</button>
            <button className="sf-btn" onClick={snap}>Snapshot</button>
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: 16, marginTop: 18 }}>
            <div>
              <h3 style={{ fontSize: 13, letterSpacing: 2, color: '#22d3ee' }}>SNAPSHOTS ({session.snapshots.length})</h3>
              <ul style={{ listStyle: 'none', padding: 0, margin: 0, display: 'flex', flexDirection: 'column', gap: 8 }}>
                {session.snapshots.map((s) => (
                  <li key={s.id} className="sf-glass" style={{ borderRadius: 10, padding: '9px 12px', fontSize: 13 }}>
                    <code style={{ color: '#a5f3fc' }}>{s.id}</code> · {s.inputTrace.length} steps · <code>{s.stateHash.slice(0, 12)}…</code>
                    {s.note ? <div style={{ color: '#94a3b8', fontSize: 12, marginTop: 2 }}>{s.note}</div> : null}
                    <div><button className="sf-btn" style={{ marginTop: 6, padding: '5px 12px', fontSize: 12 }} onClick={() => void replay(s.id)}>Replay steps</button></div>
                  </li>
                ))}
                {session.snapshots.length === 0 && <li style={{ color: '#475569', fontSize: 13 }}>No snapshots yet — capture a baseline before fuzzing.</li>}
              </ul>
              {replayOut && <p style={{ fontSize: 13, color: replayOut.includes('MATCH') ? '#6ee7b7' : '#fca5a5' }}>{replayOut}</p>}
            </div>
            <div>
              <h3 style={{ fontSize: 13, letterSpacing: 2, color: '#f43f5e' }}>CRASHES ({session.crashes.length})</h3>
              <ul style={{ listStyle: 'none', padding: 0, margin: 0, display: 'flex', flexDirection: 'column', gap: 8 }}>
                {session.crashes.map((c) => (
                  <li key={c.id} className="sf-glass" style={{ borderRadius: 10, padding: '9px 12px', fontSize: 13, borderColor: 'rgba(244,63,94,0.3)' }}>
                    <code style={{ color: '#fca5a5' }}>{c.id}</code> · {c.reason}
                    <div style={{ color: '#94a3b8', fontSize: 12, marginTop: 2 }}>repro: snapshot <code>{c.snapshotId}</code> + {c.inputTrace.length} inputs</div>
                  </li>
                ))}
                {session.crashes.length === 0 && <li style={{ color: '#475569', fontSize: 13 }}>Clean boot. Feed it hostile input.</li>}
              </ul>
            </div>
          </div>
        </>
      )}
    </motion.section>
  );
}
