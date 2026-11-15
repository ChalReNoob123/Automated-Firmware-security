'use client';
import { useEffect, useState } from 'react';
import { motion, useReducedMotion } from 'framer-motion';
import { Badge, Card, Empty, Stat, glassGlow } from '../components/ui';
import { CountUp, Tilt } from '../motionKit';
import { apiFetch, getAccess, API_URL } from '../lib/auth';
import { priority } from '../lib/scoring';
import Throughput from './Throughput';

// Fleet dashboard: findings queue health, confidence mix, priority trend,
// engine coverage, recent activity — all from live API data (findings,
// capabilities, modules, audit). Seeds a demo dataset on empty fleets.
const CONF_COLOR: Record<string, string> = { Confirmed: '#6ee7b7', Likely: '#fcd34d', Unconfirmed: '#94a3b8' };

type Finding = {
  id: string;
  title: string;
  emb3d: string | null;
  cvss_v4: number | null;
  epss: number | null;
  ssvc: string | null;
  confidence: 'Confirmed' | 'Likely' | 'Unconfirmed';
  corroborating_engines: string[];
  why_flagged: string | null;
  snapshot_ref: string | null;
  created_at: string;
  priority?: number | null; // engine-computed by the API (workers priorityOf)
};

function Donut({ parts }: { parts: { label: string; value: number; color: string }[] }) {
  const reduced = useReducedMotion() ?? false;
  const total = Math.max(1, parts.reduce((a, p) => a + p.value, 0));
  let acc = 0;
  const R = 54;
  const C = 2 * Math.PI * R;
  return (
    <div style={{ display: 'flex', gap: 18, alignItems: 'center', flexWrap: 'wrap' }}>
      <motion.div
        initial={reduced ? false : { opacity: 0, scale: 0.85 }}
        animate={{ opacity: 1, scale: 1 }}
        transition={{ duration: 0.55, ease: [0.22, 1, 0.36, 1] }}
        style={{ width: 140, height: 140 }}
      >
        <svg width="140" height="140" viewBox="0 0 140 140">
          <circle cx="70" cy="70" r={R} fill="none" stroke="rgba(255,255,255,0.07)" strokeWidth="16" />
          {parts.map((p, i) => {
            const frac = p.value / total;
            const el = (
              <motion.circle
                key={p.label}
                cx="70"
                cy="70"
                r={R}
                fill="none"
                stroke={p.color}
                strokeWidth="16"
                strokeDasharray={`${frac * C} ${C}`}
                strokeDashoffset={-acc * C}
                strokeLinecap="butt"
                transform="rotate(-90 70 70)"
                initial={reduced ? false : { opacity: 0 }}
                animate={{ opacity: 1 }}
                transition={{ delay: 0.22 + i * 0.14, duration: 0.5 }}
              />
            );
            acc += frac;
            return el;
          })}
          <text x="70" y="76" textAnchor="middle" fill="#fff" fontSize="22" fontWeight="800">{total === 1 && parts.every((p) => p.value === 0) ? 0 : parts.reduce((a, p) => a + p.value, 0)}</text>
        </svg>
      </motion.div>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
        {parts.map((p) => (
          <div key={p.label} style={{ fontSize: 13, color: '#cbd5e1', display: 'flex', gap: 8, alignItems: 'center' }}>
            <span style={{ width: 10, height: 10, borderRadius: 3, background: p.color }} /> {p.label} <b style={{ color: '#fff' }}>{p.value}</b>
          </div>
        ))}
      </div>
    </div>
  );
}

function Trend({ values }: { values: number[] }) {
  const reduced = useReducedMotion() ?? false;
  const W = 560;
  const H = 120;
  const max = Math.max(1, ...values);
  const pts = values.map((v, i) => `${(i / Math.max(1, values.length - 1)) * W},${H - 8 - (v / max) * (H - 24)}`).join(' ');
  const gradId = 'sf-trend-grad';
  return (
    <svg width="100%" height={H} viewBox={`0 0 ${W} ${H}`} preserveAspectRatio="none" style={{ display: 'block' }}>
      <defs>
        <linearGradient id={gradId} x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stopColor="#22d3ee" stopOpacity="0.45" />
          <stop offset="100%" stopColor="#22d3ee" stopOpacity="0.02" />
        </linearGradient>
      </defs>
      {[0.25, 0.5, 0.75].map((f) => (
        <line key={f} x1="0" x2={W} y1={H * f} y2={H * f} stroke="rgba(255,255,255,0.06)" strokeWidth="1" />
      ))}
      {/* area fades in behind, then the line draws itself left→right */}
      <motion.polygon
        points={`0,${H} ${pts} ${W},${H}`}
        fill={`url(#${gradId})`}
        initial={reduced ? false : { opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ delay: 0.65, duration: 0.9 }}
      />
      <motion.polyline
        points={pts}
        fill="none"
        stroke="#22d3ee"
        strokeWidth="2.5"
        strokeLinejoin="round"
        strokeLinecap="round"
        initial={reduced ? false : { pathLength: 0, opacity: 0 }}
        animate={{ pathLength: 1, opacity: 1 }}
        transition={{ duration: 1.35, ease: 'easeOut' }}
      />
    </svg>
  );
}

function Bars({ items }: { items: { label: string; value: number }[] }) {
  const max = Math.max(1, ...items.map((i) => i.value));
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
      {items.map((it) => (
        <div key={it.label}>
          <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 12.5, marginBottom: 4 }}>
            <span style={{ color: '#cbd5e1', fontFamily: 'monospace' }}>{it.label}</span>
            <b style={{ color: '#fff' }}>{it.value}</b>
          </div>
          <div style={{ height: 8, borderRadius: 4, background: 'rgba(255,255,255,0.07)' }}>
            <motion.div
              initial={{ width: 0 }}
              animate={{ width: `${(it.value / max) * 100}%` }}
              transition={{ duration: 0.8, ease: [0.22, 1, 0.36, 1] }}
              style={{ height: '100%', borderRadius: 4, background: 'linear-gradient(90deg,#0891b2,#a855f7)' }}
            />
          </div>
        </div>
      ))}
    </div>
  );
}

export default function Dashboard() {
  const reduced = useReducedMotion() ?? false;
  const [signedIn, setSignedIn] = useState<boolean | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [engines, setEngines] = useState<string[]>([]);
  const [persistence, setPersistence] = useState('');
  const [modules, setModules] = useState<string[]>([]);
  const [err, setErr] = useState('');
  const [busy, setBusy] = useState(false);

  const load = async () => {
    setErr('');
    try {
      const tok = await getAccess();
      if (!tok) {
        setSignedIn(false);
        return;
      }
      setSignedIn(true);
      const [f, caps, mods] = await Promise.all([
        apiFetch('/v1/findings?limit=100').then(async (r) => {
          if (!r.ok) throw new Error(`findings HTTP ${r.status}`);
          return r.json();
        }),
        apiFetch('/v1/capabilities').then((r) => r.json()).catch(() => null),
        fetch(`${API_URL}/v1/modules`).then((r) => r.json()).catch(() => null),
      ]);
      setFindings(f.findings ?? []);
      setEngines(caps?.engines ?? []);
      setPersistence(caps?.persistence ?? '');
      setModules(mods?.modules ?? []);
    } catch (e) {
      setErr((e as Error).message);
    }
  };

  useEffect(() => {
    void load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const seed = async () => {
    setBusy(true);
    try {
      const r = await apiFetch('/v1/findings/demo', { method: 'POST' });
      if (!r.ok) throw new Error(`seed HTTP ${r.status}`);
      await load();
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  const counts = {
    Confirmed: findings.filter((f) => f.confidence === 'Confirmed').length,
    Likely: findings.filter((f) => f.confidence === 'Likely').length,
    Unconfirmed: findings.filter((f) => f.confidence === 'Unconfirmed').length,
  };
  const avgPrio = findings.length ? Math.round(findings.reduce((a, f) => a + priority(f), 0) / findings.length) : 0;
  const top = [...findings].sort((a, b) => priority(b) - priority(a)).slice(0, 6);
  // Priority trend across the queue ordered oldest→newest (cumulative confirmed share).
  const ordered = [...findings].reverse();
  const trend = ordered.length
    ? ordered.map((_, i) => {
        const win = ordered.slice(0, i + 1);
        return Math.round((win.filter((f) => f.confidence === 'Confirmed').length / win.length) * 100);
      })
    : [0];
  const engineFreq = new Map<string, number>();
  findings.forEach((f) => f.corroborating_engines.forEach((e) => engineFreq.set(e, (engineFreq.get(e) ?? 0) + 1)));
  const engineBars = [...engineFreq.entries()].map(([label, value]) => ({ label, value })).sort((a, b) => b.value - a.value).slice(0, 8);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      {signedIn === false ? (
        <Card style={{ marginTop: 0, textAlign: 'center' }}>
          <p style={{ color: '#94a3b8' }}>Sign in to see your fleet posture.</p>
          <a className="sf-btn sf-btn-accent" href="/login">Sign in</a>
        </Card>
      ) : (
        <>
          <motion.div
            initial={reduced ? false : 'hidden'}
            animate="show"
            variants={{ hidden: {}, show: { transition: { staggerChildren: 0.08 } } }}
            style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}
          >
            {(
              [
                { label: 'OPEN FINDINGS', v: <CountUp to={findings.length} />, sub: `${counts.Confirmed} confirmed` },
                { label: 'AVG PRIORITY', v: <CountUp to={avgPrio} />, sub: 'confidence + EPSS weighted' },
                { label: 'ENGINES ACTIVE', v: engines.length ? <CountUp to={engines.length} /> : '—', sub: persistence || 'probing…' },
                { label: 'MODULES', v: modules.length ? <CountUp to={modules.length} /> : '—', sub: 'platform surface' },
              ] as const
            ).map((s) => (
              <motion.div
                key={s.label}
                variants={{
                  hidden: { opacity: 0, y: 20, scale: 0.97 },
                  show: { opacity: 1, y: 0, scale: 1, transition: { duration: 0.5, ease: [0.22, 1, 0.36, 1] } },
                }}
                style={{ flex: '1 1 170px', display: 'flex' }}
              >
                <Tilt style={{ flex: 1, borderRadius: 16 }}>
                  <Stat label={s.label} value={s.v} sub={s.sub} />
                </Tilt>
              </motion.div>
            ))}
          </motion.div>
          {err && <p style={{ color: '#f87171', fontSize: 13 }}>{err}</p>}
          <motion.div
            initial={reduced ? false : { opacity: 0, y: 16 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.35, duration: 0.6, ease: [0.22, 1, 0.36, 1] }}
          >
            <Throughput />
          </motion.div>
          {signedIn && findings.length === 0 && !err && (
            <Card style={{ marginTop: 0, textAlign: 'center' }}>
              <Empty title="Fleet is quiet — suspiciously quiet" hint="Seed the representative queue or file findings from discovery runs." />
              <button className="sf-btn sf-btn-accent" style={{ marginTop: 12 }} onClick={seed} disabled={busy}>
                {busy ? 'Seeding…' : 'Load demo dataset'}
              </button>
            </Card>
          )}
          {findings.length > 0 && (
            <>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: 16 }}>
                <Card style={{ marginTop: 0 }}>
                  <h3 style={{ margin: '0 0 12px', fontSize: 14, letterSpacing: 2, color: '#22d3ee' }}>CONFIDENCE MIX</h3>
                  <Donut
                    parts={[
                      { label: 'Confirmed', value: counts.Confirmed, color: CONF_COLOR.Confirmed },
                      { label: 'Likely', value: counts.Likely, color: CONF_COLOR.Likely },
                      { label: 'Unconfirmed', value: counts.Unconfirmed, color: CONF_COLOR.Unconfirmed },
                    ]}
                  />
                </Card>
                <Card style={{ marginTop: 0 }}>
                  <h3 style={{ margin: '0 0 12px', fontSize: 14, letterSpacing: 2, color: '#a855f7' }}>CONFIRMED SHARE TREND</h3>
                  <Trend values={trend} />
                  <p style={{ fontSize: 12, color: '#64748b', margin: '8px 0 0' }}>Share of confirmed findings as the queue grows — consensus health at a glance.</p>
                </Card>
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: 16 }}>
                <Card style={{ marginTop: 0 }}>
                  <h3 style={{ margin: '0 0 12px', fontSize: 14, letterSpacing: 2, color: '#22d3ee' }}>TOP PRIORITY</h3>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                    {top.map((f) => (
                      <div key={f.id} className="sf-glass" onPointerMove={glassGlow} style={{ borderRadius: 10, padding: '9px 12px', fontSize: 13, display: 'flex', gap: 10, alignItems: 'center' }}>
                        <b style={{ color: '#fff', minWidth: 34 }}>P{priority(f)}</b>
                        <span style={{ flex: 1 }}>{f.title}</span>
                        <Badge tone={f.confidence === 'Confirmed' ? 'green' : f.confidence === 'Likely' ? 'amber' : 'gray'}>{f.confidence.toUpperCase()}</Badge>
                      </div>
                    ))}
                  </div>
                </Card>
                <Card style={{ marginTop: 0 }}>
                  <h3 style={{ margin: '0 0 12px', fontSize: 14, letterSpacing: 2, color: '#a855f7' }}>ENGINE COVERAGE</h3>
                  {engineBars.length ? <Bars items={engineBars} /> : <Empty title="No corroboration yet" hint="Findings gain engines as pipeline stages run." />}
                </Card>
              </div>
            </>
          )}
        </>
      )}
    </div>
  );
}
