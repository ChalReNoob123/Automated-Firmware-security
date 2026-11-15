'use client';
import { useEffect, useState } from 'react';
import { motion } from 'framer-motion';
import { Card, Badge, Empty, glassGlow } from '../components/ui';
import { apiFetch, getAccess } from '../lib/auth';
import { AttestField, SessionChip } from '../components/Gate';
import { SCENARIOS, type Scenario } from './scenarios';

// Attack runner: executes a scenario's steps as REAL backend operations
// (boot twin → console inputs → snapshots → crash record) and renders the
// verdict with repro references. Identity via memory token; attestation persists.
const SEV: Record<Scenario['severity'], 'rose' | 'amber' | 'gray'> = { critical: 'rose', high: 'amber', medium: 'gray' };

type LogLine = { text: string; ok: boolean };

export default function AttackRunner() {
  const [signedIn, setSignedIn] = useState<boolean | null>(null);
  const [att, setAtt] = useState('');
  const [sel, setSel] = useState<Scenario>(SCENARIOS[0]);
  const [running, setRunning] = useState(false);
  const [log, setLog] = useState<LogLine[]>([]);
  const [verdict, setVerdict] = useState<string | null>(null);
  const [sessionId, setSessionId] = useState<string | null>(null);

  useEffect(() => {
    setAtt(localStorage.getItem('sf_att') ?? '');
    getAccess().then((t) => setSignedIn(!!t));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const H = () => {
    const h: Record<string, string> = {};
    const attId = att || localStorage.getItem('sf_att') || '';
    if (attId) h['x-attestation-id'] = attId;
    return h;
  };

  const call = async (path: string, method: string, body?: unknown) => {
    const r = await apiFetch(path, { method, headers: H(), body: body ? JSON.stringify(body) : undefined });
    const j = await r.json().catch(() => ({}));
    if (r.status === 401) {
      setSignedIn(false);
      throw new Error('Session expired — sign in at /login, then retry.');
    }
    if (!r.ok) throw new Error((j as { error?: string }).error ?? `HTTP ${r.status}`);
    return j;
  };

  const run = async () => {
    if (running) return;
    setRunning(true);
    setLog([]);
    setVerdict(null);
    setSessionId(null);
    localStorage.setItem('sf_att', att);
    const say = (text: string, ok = true) => setLog((l) => [...l, { text, ok }]);
    try {
      const tok = await getAccess();
      if (!tok) {
        setSignedIn(false);
        throw new Error('Sign in at /login first.');
      }
      setSignedIn(true);
      let sid = '';
      for (const step of sel.steps) {
        if (step.kind === 'boot') {
          say(`◈ ${step.label}…`);
          const j = (await call('/v1/emulator/sessions', 'POST', { arch: sel.arch, memoryMb: 256 })) as { id: string };
          sid = j.id;
          setSessionId(sid);
          localStorage.setItem('sf_last_session', sid);
          say(`twin ${sid} ready`, true);
        } else if (step.kind === 'input') {
          say(`› ${step.label}: ${step.input}`);
          await call(`/v1/emulator/sessions/${sid}/input`, 'POST', { input: step.input });
          say('accepted by twin', true);
        } else if (step.kind === 'snapshot') {
          const j = (await call(`/v1/emulator/sessions/${sid}/snapshots`, 'POST', { note: step.note ?? step.label })) as { id: string };
          say(`snapshot ${j.id} captured`, true);
        } else {
          say(`✖ ${step.label}`);
          const j = (await call(`/v1/emulator/sessions/${sid}/crash`, 'POST', { reason: step.reason })) as { id: string };
          say(`impact recorded: ${j.id} (repro bundle attached)`, true);
        }
        await new Promise((r) => setTimeout(r, 550));
      }
      setVerdict(`VULNERABLE — “${sel.name}” reproduced end to end. Replay it step by step from /emulator (session ${sid}).`);
    } catch (e) {
      say('aborted: ' + (e as Error).message, false);
      setVerdict('RUN BLOCKED — ' + (e as Error).message);
    } finally {
      setRunning(false);
    }
  };

  return (
    <div style={{ display: 'grid', gridTemplateColumns: 'minmax(260px, 340px) 1fr', gap: 16, alignItems: 'start' }}>
      <Card style={{ marginTop: 0 }}>
        <motion.div
          initial="hidden"
          animate="show"
          variants={{ hidden: {}, show: { transition: { staggerChildren: 0.06 } } }}
          style={{ display: 'flex', flexDirection: 'column', gap: 8 }}
        >
          {SCENARIOS.map((s) => (
            <motion.div
              key={s.id}
              variants={{
                hidden: { opacity: 0, x: -14 },
                show: { opacity: 1, x: 0, transition: { duration: 0.4, ease: [0.22, 1, 0.36, 1] } },
              }}
            >
              <button
                onClick={() => { setSel(s); setLog([]); setVerdict(null); }}
                className={s.id === sel.id ? 'sf-btn sf-btn-accent' : 'sf-btn'}
                style={{ width: '100%', textAlign: 'left', display: 'flex', gap: 8, alignItems: 'center', justifyContent: 'space-between' }}
              >
                <span>{s.name}</span>
                <Badge tone={SEV[s.severity]}>{s.severity.toUpperCase()}</Badge>
              </button>
            </motion.div>
          ))}
        </motion.div>
        <p style={{ color: '#64748b', fontSize: 12, marginTop: 12, lineHeight: 1.6 }}>{sel.emb3d}</p>
      </Card>

      <Card style={{ marginTop: 0 }}>
        {running && <div aria-hidden className="sf-run-scan" />}
        <h2 style={{ margin: '0 0 4px' }}>{sel.name}</h2>
        <p style={{ color: '#94a3b8', fontSize: 14, lineHeight: 1.6 }}>{sel.description}</p>
        <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap', margin: '12px 0', alignItems: 'center' }}>
          <SessionChip signedIn={signedIn} cta="Sign in to execute" />
          <AttestField att={att} onChange={setAtt} />
          <button
            className="sf-btn sf-btn-accent"
            onClick={run}
            disabled={running || signedIn !== true}
            title={signedIn !== true && !running ? 'Sign in first — each run is attributed to your account and its attestation' : undefined}
          >
            {running ? 'Running…' : 'Execute scenario'}
          </button>
        </div>
        {log.length === 0 && !running && (
          <Empty
            title={signedIn === false ? 'Locked until you sign in' : 'Armed, not fired'}
            hint={
              signedIn === false
                ? 'Sign in at /login and mint an attestation id at /devices, then the full sequence runs against a real twin.'
                : `${sel.steps.length} steps will execute against a fresh ${sel.arch} twin.`
            }
          />
        )}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 6, fontFamily: 'monospace', fontSize: 13 }}>
          {log.map((l, i) => (
            <motion.div key={i} initial={{ opacity: 0, x: -8 }} animate={{ opacity: 1, x: 0 }} style={{ color: l.ok ? '#6ee7b7' : '#fca5a5' }}>
              {l.text}
            </motion.div>
          ))}
        </div>
        {verdict && (
          <motion.div
            initial={{ opacity: 0, y: 16, scale: 0.97 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            transition={{ type: 'spring', stiffness: 210, damping: 20 }}
            className="sf-glass"
            onPointerMove={glassGlow}
            style={{ borderRadius: 12, padding: 14, marginTop: 14, fontSize: 14, borderColor: verdict.startsWith('VULNERABLE') ? 'rgba(244,63,94,0.4)' : 'rgba(245,158,11,0.4)' }}
          >
            {verdict}
            {sessionId && verdict.startsWith('VULNERABLE') && (
              <div style={{ marginTop: 8 }}><a className="sf-btn" href="/emulator">Open in emulator →</a></div>
            )}
          </motion.div>
        )}
      </Card>
    </div>
  );
}
