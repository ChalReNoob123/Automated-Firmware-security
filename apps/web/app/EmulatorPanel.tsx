'use client';
import { useEffect, useRef, useState } from 'react';
import { motion } from 'framer-motion';
import { apiFetch, getAccess } from './lib/auth';
import { AttestField, SessionChip } from './components/Gate';
import { Empty, glassGlow } from './components/ui';

// Emulator console (spec §6): live boot console, snapshot + step-by-step replay,
// crash list with repro bundles. Identity comes from the memory token (silent
// refresh); attestation id persists locally. Same API + gates, cinematic skin.

type Session = {
  id: string;
  arch: string;
  memoryMb: number;
  backend: string;
  status: string;
  bootDeadline?: string;
  image?: {
    firmwareId: string;
    version: string;
    sha256: string;
    bytes: number;
    elf: { machine: string; bits: number; endian: string; entry: string; exeType: string } | null;
    banner: string[];
  };
  bootLog: string[];
  inputTrace: string[];
  snapshots: { id: string; stateHash: string; inputTrace: string[]; createdAt: string; note?: string }[];
  crashes: { id: string; reason: string; snapshotId: string | null; inputTrace: string[]; at: string }[];
};

const STATUS_COLOR: Record<string, string> = { ready: '#34d399', crashed: '#f43f5e', stopped: '#64748b', booting: '#f59e0b', failed: '#ef4444' };

export default function EmulatorPanel() {
  const [signedIn, setSignedIn] = useState<boolean | null>(null);
  const [att, setAtt] = useState('');
  const [session, setSession] = useState<Session | null>(null);
  const [arch, setArch] = useState('arm');
  const [firmwares, setFirmwares] = useState<{ id: string; version: string; bytes: number; sha256: string }[]>([]);
  const [firmwareId, setFirmwareId] = useState('');
  const [input, setInput] = useState('');
  const [replayOut, setReplayOut] = useState('');
  const [origin, setOrigin] = useState(''); // finding id when the replay was deep-linked
  const [err, setErr] = useState('');
  const consoleRef = useRef<HTMLPreElement>(null);

  useEffect(() => {
    setAtt(localStorage.getItem('sf_att') ?? '');
    // Deep-links: the attack sim and the finding evidence page both hand us a
    // session id; a finding additionally carries a SNAPSHOT to replay. The
    // query string is read from window (not useSearchParams) so this page keeps
    // rendering without a Suspense boundary around it. Round 33: the evidence
    // page shipped a link that used to land here and do nothing.
    (async () => {
      const tok = await getAccess();
      setSignedIn(!!tok);
      const qs = new URLSearchParams(window.location.search);
      const snap = qs.get('snapshot');
      const fromFinding = qs.get('finding');
      if (fromFinding) setOrigin(fromFinding);
      const last = localStorage.getItem('sf_last_session');
      if (!tok) return;
      // Image picker: what the twin can boot. `?firmware=` preselects one, so
      // the intake panel can hand off to a twin already standing for that image.
      try {
        const fr = await apiFetch('/v1/firmware');
        if (fr.ok) {
          const fj = (await fr.json()) as { firmware?: { id: string; version: string; bytes: number; sha256: string }[] };
          const list = fj.firmware ?? [];
          setFirmwares(list);
          setFirmwareId(qs.get('firmware') ?? list[0]?.id ?? '');
        }
      } catch {
        /* no intake yet — the twin still boots with no image */
      }
      if (!last) {
        if (snap) {
          setReplayOut(
            `Snapshot ${snap} belongs to a twin this browser hasn't opened — open the session that captured it, then replay.`
          );
        }
        return;
      }
      try {
        const r = await apiFetch(`/v1/emulator/sessions/${last}`, { method: 'GET' });
        if (!r.ok) return;
        const j = await r.json();
        if (!j?.id) return;
        setSession(j);
        if (!snap) return;
        const owned = ((j.snapshots ?? []) as { id: string }[]).some((s) => s.id === snap);
        if (!owned) {
          setReplayOut(`Snapshot ${snap} is not in session ${j.id} — it lives in the twin that captured it.`);
          return;
        }
        const rr = await apiFetch(`/v1/emulator/sessions/${j.id}/replay`, {
          method: 'POST',
          headers: { 'x-attestation-id': localStorage.getItem('sf_att') ?? '' },
          body: JSON.stringify({ snapshotId: snap }),
        });
        const out = (await rr.json().catch(() => ({}))) as { match?: boolean; detail?: string; error?: string };
        if (!rr.ok) {
          setReplayOut(`Replay refused (HTTP ${rr.status}) — ${out.error ?? 'attestation required'}`);
        } else {
          setReplayOut(`${snap}: ${out.match ? 'MATCH ✓' : 'DIVERGED ✗'} — ${out.detail ?? ''}`);
        }
      } catch {
        /* session expired with the last boot — boot a fresh twin */
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
    const s = (await call(
      '/v1/emulator/sessions',
      'POST',
      { arch, memoryMb: 256, ...(firmwareId ? { firmwareId } : {}) },
      true
    )) as Session;
    // Round 33: the session used to live only in component state, so a reload
    // lost it and the finding/attack deep-links had nothing to reopen.
    if (s?.id) localStorage.setItem('sf_last_session', s.id);
    setSession(s);
    // Round 36: booting is asynchronous server-side. With a real launch the
    // session arrives as 'booting' and the console lands later — poll it in
    // rather than leaving the panel showing a stale empty terminal.
    if (s?.status === 'booting') {
      // Poll until the boot settles or its server-side deadline passes. A launch
      // that never reports back (API restart mid-boot) is settled by the API as
      // 'failed', so this loop always ends on a real status.
      const until = s.bootDeadline ? Date.parse(s.bootDeadline) + 2000 : Date.now() + 20_000;
      for (let i = 0; i < 240 && Date.now() < until; i++) {
        await new Promise((r) => setTimeout(r, 500));
        try {
          const fresh = (await call(`/v1/emulator/sessions/${s.id}`, 'GET')) as Session;
          setSession(fresh);
          if (fresh.status !== 'booting') break;
        } catch {
          break;
        }
      }
    }
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
      onPointerMove={glassGlow}
      style={{ borderRadius: 20, padding: 24, marginTop: 28 }}
    >
      <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap', marginBottom: 14, alignItems: 'center' }}>
        <SessionChip signedIn={signedIn} cta="Sign in to boot twins" />
        <AttestField att={att} onChange={setAtt} />
        <select className="sf-input" value={arch} onChange={(e) => setArch(e.target.value)}>
          {['arm', 'aarch64', 'mips', 'mipsel', 'x86', 'x86_64', 'riscv64'].map((a) => (
            <option key={a} value={a}>{a}</option>
          ))}
        </select>
        <select
          className="sf-input"
          value={firmwareId}
          onChange={(e) => setFirmwareId(e.target.value)}
          aria-label="firmware image"
          style={{ maxWidth: 260 }}
          title="Twin boots the selected uploaded image; the ELF header overrides the arch box"
        >
          <option value="">No image (dry-run)</option>
          {firmwares.map((f) => (
            <option key={f.id} value={f.id}>
              {f.version} · {Math.max(1, Math.round(f.bytes / 1024))}KB · {f.sha256.slice(0, 6)}
            </option>
          ))}
        </select>
        <button className="sf-btn sf-btn-accent" onClick={boot} disabled={signedIn !== true} title={signedIn !== true ? 'Sign in first — every twin is attributed to a named operator' : undefined}>
          Boot twin
        </button>
        <button className="sf-btn" onClick={refresh} disabled={!session}>Refresh</button>
      </div>
      {err && <p role="alert" style={{ color: '#f87171', fontSize: 13 }}>{err}</p>}
      {!session && signedIn === false && (
        <Empty
          title="Session required — the twin console is auth-gated"
          hint="Sign in at /login, register a device at /devices for an attestation id, then boot. Every twin is attributed to a named operator."
        />
      )}
      {!session && signedIn === null && <Empty title="Waking the console…" hint="Checking for a live session." />}
      {session && (
        <>
          <p style={{ color: '#94a3b8', fontSize: 13 }}>
            <code style={{ color: '#a5f3fc' }}>{session.id}</code> · {session.arch} · {session.memoryMb}MB · {session.backend} · status:{' '}
            {session.image && (
              <span style={{ color: '#a5f3fc' }}>
                {' '}
                · image {session.image.version} · {session.image.sha256.slice(0, 8)}…
                {session.image.elf ? ` (${session.image.elf.machine} ${session.image.elf.bits}-bit)` : ''}
              </span>
            )}
            <b style={{ color: STATUS_COLOR[session.status] ?? '#e2e8f0' }}>{session.status.toUpperCase()}</b>
          </p>
          <div className="uv-term">
            <div className="uv-term-bar">
              <span className="uv-dot uv-dot-r" /><span className="uv-dot uv-dot-y" /><span className="uv-dot uv-dot-g" />
              <span style={{ marginLeft: 6 }}>TWIN — {session.arch} · {session.backend.toUpperCase()}</span>
            </div>
            <pre ref={consoleRef} className="sf-console">{(session.bootLog ?? []).join('\n')}</pre>
          </div>
          <div style={{ display: 'flex', gap: 8, marginTop: 10 }}>
            <input className="sf-input" placeholder="console input — Enter to send" value={input} onChange={(e) => setInput(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && void send()} style={{ flex: 1 }} />
            <button className="sf-btn" onClick={send} disabled={signedIn !== true}>Send</button>
            <button className="sf-btn" onClick={snap} disabled={signedIn !== true}>Snapshot</button>
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: 16, marginTop: 18 }}>
            <div>
              <h3 style={{ fontSize: 13, letterSpacing: 2, color: '#22d3ee' }}>SNAPSHOTS ({session.snapshots.length})</h3>
              <ul style={{ listStyle: 'none', padding: 0, margin: 0, display: 'flex', flexDirection: 'column', gap: 8 }}>
                {session.snapshots.map((s) => (
                  <li key={s.id} className="sf-glass" onPointerMove={glassGlow} style={{ borderRadius: 10, padding: '9px 12px', fontSize: 13 }}>
                    <code style={{ color: '#a5f3fc' }}>{s.id}</code> · {s.inputTrace.length} steps · <code>{s.stateHash.slice(0, 12)}…</code>
                    {s.note ? <div style={{ color: '#94a3b8', fontSize: 12, marginTop: 2 }}>{s.note}</div> : null}
                    <div><button className="sf-btn" style={{ marginTop: 6, padding: '5px 12px', fontSize: 12 }} onClick={() => void replay(s.id)}>Replay steps</button></div>
                  </li>
                ))}
                {session.snapshots.length === 0 && <li style={{ color: '#64748b', fontSize: 13 }}>No snapshots yet — capture a baseline before fuzzing.</li>}
              </ul>
              {replayOut && (
                <p
                  style={{
                    fontSize: 13,
                    color: replayOut.includes('MATCH') ? '#6ee7b7' : replayOut.includes('DIVERGED') ? '#fca5a5' : '#fcd34d',
                  }}
                >
                  {replayOut}
                  {origin && (
                    <>
                      {' · '}
                      <a href={`/findings/${origin}`} style={{ color: '#a5f3fc' }}>
                        back to the finding
                      </a>
                    </>
                  )}
                </p>
              )}
            </div>
            <div>
              <h3 style={{ fontSize: 13, letterSpacing: 2, color: '#f43f5e' }}>CRASHES ({session.crashes.length})</h3>
              <ul style={{ listStyle: 'none', padding: 0, margin: 0, display: 'flex', flexDirection: 'column', gap: 8 }}>
                {session.crashes.map((c) => (
                  <li key={c.id} className="sf-glass" onPointerMove={glassGlow} style={{ borderRadius: 10, padding: '9px 12px', fontSize: 13, borderColor: 'rgba(244,63,94,0.3)' }}>
                    <code style={{ color: '#fca5a5' }}>{c.id}</code> · {c.reason}
                    <div style={{ color: '#94a3b8', fontSize: 12, marginTop: 2 }}>repro: snapshot <code>{c.snapshotId}</code> + {c.inputTrace.length} inputs</div>
                  </li>
                ))}
                {session.crashes.length === 0 && <li style={{ color: '#64748b', fontSize: 13 }}>Clean boot. Feed it hostile input.</li>}
              </ul>
            </div>
          </div>
        </>
      )}
    </motion.section>
  );
}
