'use client';
import { useEffect, useState } from 'react';
import { motion } from 'framer-motion';
import { apiFetch, getAccess } from './lib/auth';

// Security Copilot chat (spec §8): every answer cites the MCP tool that produced
// it. Identity comes from the memory token (silent refresh) — no paste needed.
const LOGIN_HREF = '/login';

type Msg = { role: 'you' | 'copilot'; text: string; cites?: { server: string; tool: string }[]; options?: { label: string; message: string }[] };

export default function CopilotPanel() {
  const [signedIn, setSignedIn] = useState<boolean | null>(null);
  const [input, setInput] = useState('');
  const [msgs, setMsgs] = useState<Msg[]>([
    { role: 'copilot', text: 'Ask about attack paths, taint, fuzz campaigns, EPSS, secure boot, or the pipeline. I answer from live tool output.' },
  ]);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState('');

  useEffect(() => {
    getAccess().then((t) => setSignedIn(!!t));
  }, []);

  const sendText = async (q: string) => {
    if (!q.trim() || busy) return;
    setBusy(true);
    setErr('');
    setInput('');
    setMsgs((m) => [...m, { role: 'you', text: q }]);
    try {
      const r = await apiFetch('/v1/copilot/chat', { method: 'POST', body: JSON.stringify({ message: q }) });
      const j = await r.json().catch(() => ({}));
      if (r.status === 401) {
        setSignedIn(false);
        setErr('');
        setMsgs((m) => [...m, { role: 'copilot', text: 'That needs a signed-in session — grab one at Login, then ask me again.' }]);
        return;
      }
      if (!r.ok) throw new Error((j as { error?: string }).error ?? `HTTP ${r.status}`);
      setSignedIn(true);
      const jj = j as { reply: string; citations?: { server: string; tool: string }[]; clarify?: { label: string; message: string }[] };
      setMsgs((m) => [...m, { role: 'copilot', text: jj.reply, cites: jj.citations, options: jj.clarify }]);
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setBusy(false);
    }
  };
  const send = () => void sendText(input);

  return (
    <motion.section
      initial={{ opacity: 0, y: 26 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.7, ease: [0.22, 1, 0.36, 1] }}
      className="sf-glass"
      style={{ borderRadius: 20, padding: 22, marginTop: 28, maxWidth: 840 }}
    >
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 14 }}>
        {signedIn === false ? (
          <a className="sf-btn sf-btn-accent" href={LOGIN_HREF}>Sign in to chat</a>
        ) : (
          <span style={{ fontSize: 12, letterSpacing: 2, color: signedIn ? '#6ee7b7' : '#64748b' }}>
            {signedIn ? '● SIGNED IN' : '○ CHECKING SESSION…'}
          </span>
        )}
      </div>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 10, minHeight: 220, maxHeight: 440, overflowY: 'auto', marginBottom: 14 }}>
        {msgs.map((m, i) => (
          <motion.div
            key={i}
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.35 }}
            style={{
              alignSelf: m.role === 'you' ? 'flex-end' : 'flex-start',
              background: m.role === 'you' ? 'linear-gradient(100deg, rgba(8,145,178,0.35), rgba(124,58,237,0.35))' : 'rgba(255,255,255,0.05)',
              border: m.role === 'you' ? '1px solid rgba(34,211,238,0.3)' : '1px solid rgba(255,255,255,0.09)',
              borderRadius: 14,
              padding: '10px 14px',
              maxWidth: '88%',
              whiteSpace: 'pre-wrap',
              fontSize: 14,
              lineHeight: 1.6,
            }}
          >
            {m.role === 'copilot' && <div style={{ fontSize: 11, letterSpacing: 2, color: '#22d3ee', marginBottom: 4 }}>◈ COPILOT</div>}
            {m.text}
            {m.cites && m.cites.length > 0 && (
              <div style={{ marginTop: 8, fontSize: 12, color: '#22d3ee' }}>grounded in: {m.cites.map((c) => `${c.server}/${c.tool}`).join(', ')}</div>
            )}
            {m.options && m.options.length > 0 && (
              <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', marginTop: 8 }}>
                {m.options.map((o) => (
                  <button key={o.label} className="sf-btn" style={{ fontSize: 12, padding: '6px 12px' }} onClick={() => void sendText(o.message)} disabled={busy}>
                    {o.label}
                  </button>
                ))}
              </div>
            )}
          </motion.div>
        ))}
        {busy && (
          <div style={{ color: '#94a3b8', fontSize: 13, display: 'flex', gap: 6, alignItems: 'center' }}>
            <span className="sf-typing"><span /><span /><span /></span> consulting tools…
          </div>
        )}
      </div>
      {err && <p style={{ color: '#f87171', fontSize: 13 }}>{err}</p>}
      <div style={{ display: 'flex', gap: 8, marginBottom: 10, flexWrap: 'wrap' }}>
        {['show attack paths', 'trace taint to sinks', 'run a fuzz campaign'].map((s) => (
          <button key={s} className="sf-btn" style={{ fontSize: 12, padding: '6px 12px' }} onClick={() => void sendText(s)} disabled={busy}>{s}</button>
        ))}
      </div>
      <div style={{ display: 'flex', gap: 8 }}>
        <input className="sf-input" placeholder="e.g. show attack paths" value={input} onChange={(e) => setInput(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && void send()} style={{ flex: 1 }} />
        <button className="sf-btn sf-btn-accent" onClick={send} disabled={busy}>Send</button>
      </div>
    </motion.section>
  );
}
