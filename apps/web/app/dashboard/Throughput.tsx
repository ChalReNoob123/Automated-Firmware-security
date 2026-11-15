'use client';
import { useCallback, useEffect, useRef, useState } from 'react';
import { motion, useReducedMotion } from 'framer-motion';
import { Card, Empty } from '../components/ui';
import { apiFetch } from '../lib/auth';
import { sfxPing } from '../audio/sfx';

// ENGINE THROUGHPUT — live engine ledger from /v1/pipeline/metrics plus a real
// control: launch a labeled demo-profile campaign through the pooled engine
// and watch its wall time, fuzz execs/sec and pool mode land here. Attestation
// comes from the same persisted id the emulator/lab/attack panels use (sf_att);
// without it the button explains exactly what's missing instead of failing
// silently. Reduced motion safe.

type RunSummary = {
  runId: string;
  wallMs: number;
  fuzzExecsPerSec: number | null;
  protocolExecs: number | null;
  findingsCount: number;
  poolMode: string;
  finishedAt: string;
};
type Metrics = {
  runs: number;
  avgWallMs: number | null;
  bestFuzzExecsPerSec: number | null;
  poolMode: string | null;
  recent: RunSummary[];
};
type RunDoc = { runId: string; status: 'queued' | 'running' | 'done' | 'failed'; metrics?: Metrics['recent'][number] & Record<string, unknown>; findingsCount?: number; error?: string };

const fmtRate = (v: number | null) => (v == null ? '—' : v >= 1000 ? `${(v / 1000).toFixed(1)}k/s` : `${v}/s`);

export default function Throughput() {
  const reduced = useReducedMotion() ?? false;
  const [m, setM] = useState<Metrics | null>(null);
  const [note, setNote] = useState('');
  const [busy, setBusy] = useState(false);
  const [liveRun, setLiveRun] = useState<{ id: string; status: string; wallMs?: number } | null>(null);
  const aliveRef = useRef(true);
  useEffect(() => {
    aliveRef.current = true;
    return () => {
      aliveRef.current = false;
    };
  }, []);

  const load = useCallback(async () => {
    const r = await apiFetch('/v1/pipeline/metrics');
    if (r.ok && aliveRef.current) setM(await r.json());
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const runEngine = async () => {
    setBusy(true);
    setNote('');
    try {
      const tok = await apiFetch('/v1/pipeline/runs', {
        method: 'POST',
        headers: { 'x-attestation-id': localStorage.getItem('sf_att') ?? '' },
        body: JSON.stringify({ firmwareId: 'demo-hub', version: 'r15', profile: 'demo' }),
      });
      if (tok.status === 403) {
        setNote('Needs an attestation id — register a device at /devices first (every run is attributed).');
        return;
      }
      if (!tok.ok) throw new Error(`queue HTTP ${tok.status}`);
      const { runId } = (await tok.json()) as { runId: string };
      setLiveRun({ id: runId.slice(0, 8), status: 'queued' });
      // poll the run doc — the engine is executing in-process
      for (let i = 0; i < 60; i++) {
        await new Promise((res) => setTimeout(res, 300));
        const g = await apiFetch(`/v1/pipeline/runs/${runId}`);
        if (!g.ok) continue;
        const doc = (await g.json()) as RunDoc;
        if (doc.status === 'done' || doc.status === 'failed') {
          const wall = typeof doc.metrics?.wallMs === 'number' ? doc.metrics.wallMs : undefined;
          setLiveRun({ id: runId.slice(0, 8), status: doc.status, wallMs: wall });
          if (doc.status === 'done') sfxPing(0.034); // sonar ping — the run surfaced
          break;
        }
        setLiveRun({ id: runId.slice(0, 8), status: doc.status });
      }
      await load();
    } catch (e) {
      setNote((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  const poolChip = m?.poolMode ?? null;
  return (
    <Card style={{ marginTop: 0 }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 12 }}>
        <h3 style={{ margin: 0, fontSize: 14, letterSpacing: 2, color: '#22d3ee', flex: 1 }}>ENGINE THROUGHPUT</h3>
        {poolChip && (
          <span
            style={{
              fontSize: 10,
              letterSpacing: 1.5,
              fontFamily: 'ui-monospace, monospace',
              color: poolChip === 'threads' ? '#6ee7b7' : '#94a3b8',
              border: `1px solid ${poolChip === 'threads' ? 'rgba(110,231,183,0.35)' : 'rgba(148,163,184,0.3)'}`,
              borderRadius: 999,
              padding: '3px 9px',
              background: poolChip === 'threads' ? 'rgba(110,231,183,0.08)' : 'rgba(148,163,184,0.08)',
            }}
            title={poolChip === 'threads' ? 'CPU stages run on worker threads' : 'CPU stages ran in-thread (fallback)'}
          >
            POOL: {poolChip.toUpperCase()}
          </span>
        )}
        <button
          className="sf-btn sf-btn-accent"
          style={{ fontSize: 11, padding: '7px 14px', letterSpacing: 1.5 }}
          onClick={runEngine}
          disabled={busy}
        >
          {busy ? 'RUNNING…' : 'RUN ENGINE'}
        </button>
      </div>

      {m == null ? (
        <Empty title="No engine runs yet" hint="Press RUN ENGINE to launch a labeled demo campaign through the pooled pipeline." />
      ) : (
        <>
          <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap', marginBottom: 12 }}>
            {(
              [
                { label: 'RUNS', v: String(m.runs) },
                { label: 'AVG WALL', v: m.avgWallMs != null ? `${Math.round(m.avgWallMs)}ms` : '—' },
                { label: 'BEST FUZZ RATE', v: fmtRate(m.bestFuzzExecsPerSec) },
              ] as const
            ).map((s) => (
              <motion.div
                key={s.label}
                initial={reduced ? false : { opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.5, ease: [0.22, 1, 0.36, 1] }}
                style={{ flex: '1 1 120px', border: '1px solid rgba(148,163,184,0.14)', borderRadius: 10, padding: '10px 12px', background: 'rgba(15,23,42,0.45)' }}
              >
                <div style={{ fontSize: 9.5, letterSpacing: 2, color: '#64748b', marginBottom: 4 }}>{s.label}</div>
                <div style={{ fontSize: 20, fontWeight: 800, color: '#fff', fontFamily: 'ui-monospace, monospace' }}>{s.v}</div>
              </motion.div>
            ))}
          </div>
          {liveRun && (
            <p style={{ fontSize: 12, color: liveRun.status === 'done' ? '#6ee7b7' : liveRun.status === 'failed' ? '#f87171' : '#7dd3fc', fontFamily: 'ui-monospace, monospace', margin: '0 0 8px' }}>
              {liveRun.status === 'done'
                ? `run ${liveRun.id} done — wall ${liveRun.wallMs != null ? Math.round(liveRun.wallMs) + 'ms' : 'n/a'}`
                : liveRun.status === 'failed'
                  ? `run ${liveRun.id} failed — see the run doc for the error`
                  : `run ${liveRun.id}: ${liveRun.status}…`}
            </p>
          )}
          {note && <p style={{ fontSize: 12, color: '#fcd34d', margin: '0 0 8px' }}>{note}</p>}
          <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
            {m.recent.map((r) => (
              <div
                key={r.runId}
                style={{ display: 'flex', gap: 10, alignItems: 'center', fontSize: 12, fontFamily: 'ui-monospace, monospace', color: '#94a3b8', padding: '7px 10px', borderRadius: 8, background: 'rgba(148,163,184,0.05)' }}
              >
                <span style={{ color: '#22d3ee' }}>{r.runId.slice(0, 8)}</span>
                <span style={{ flex: 1 }}>
                  {Math.round(r.wallMs)}ms · {fmtRate(r.fuzzExecsPerSec)} · {r.findingsCount} findings
                </span>
                <span>{r.poolMode}</span>
              </div>
            ))}
          </div>
        </>
      )}
    </Card>
  );
}
