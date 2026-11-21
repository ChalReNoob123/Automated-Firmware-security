'use client';
import { useEffect, useRef, useState } from 'react';
import { motion, useReducedMotion } from 'framer-motion';
import { Badge, Card, Empty, Stat, glassGlow } from '../components/ui';
import { CountUp, Tilt } from '../motionKit';
import { apiFetch, getAccess, API_URL } from '../lib/auth';
import { priority } from '../lib/scoring';
import { sfxBlip, sfxPing } from '../audio/sfx';
import Throughput from './Throughput';

// Fleet dashboard: findings queue health, confidence mix, priority trend,
// engine coverage, recent activity — all from live API data (findings,
// capabilities, modules, audit). Seeds a demo dataset on empty fleets.
//
// Round 27 (data-viz motion pass): every chart now lands with choreography —
// donut arcs sweep into place with one console tick each, the trend line
// draws under a scan head and ends in a live beacon, engine bars stagger in
// with count-ups and a periodic sheen, and the ledger rows cascade. Sound is
// programmatic (sfx no-ops while audio is off) and everything is gated on
// prefers-reduced-motion.

const EASE = [0.22, 1, 0.36, 1] as const;
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
  const realTotal = parts.reduce((a, p) => a + p.value, 0);
  let acc = 0;
  const R = 54;
  const C = 2 * Math.PI * R;
  return (
    <div style={{ display: 'flex', gap: 18, alignItems: 'center', flexWrap: 'wrap' }}>
      <motion.div
        initial={reduced ? false : { opacity: 0, scale: 0.85 }}
        animate={{ opacity: 1, scale: 1 }}
        transition={{ duration: 0.55, ease: EASE }}
        style={{ width: 140, height: 140 }}
      >
        <div style={{ width: 140, height: 140, position: 'relative' }}>
          <svg width="140" height="140" viewBox="0 0 140 140">
            {/* slow dotted scan orbit — the ring the arcs live inside (70s/turn) */}
            <motion.g
              animate={reduced ? undefined : { rotate: 360 }}
              transition={reduced ? undefined : { duration: 70, ease: 'linear', repeat: Infinity }}
              style={{ transformOrigin: '70px 70px' }}
            >
              <circle cx="70" cy="70" r={R + 14} fill="none" stroke="rgba(148,163,184,0.25)" strokeWidth="1" strokeDasharray="2 9" />
            </motion.g>
            <circle cx="70" cy="70" r={R} fill="none" stroke="rgba(255,255,255,0.07)" strokeWidth="16" />
            {parts.map((p, i) => {
              const frac = p.value / total;
              const arcCommon = {
                cx: '70',
                cy: '70',
                r: R,
                fill: 'none',
                stroke: p.color,
                strokeWidth: 16,
                strokeLinecap: 'butt' as const,
                transform: 'rotate(-90 70 70)',
              };
              const el = reduced ? (
                <circle key={p.label} {...arcCommon} strokeDasharray={`${frac * C} ${C}`} strokeDashoffset={-acc * C} />
              ) : (
                <motion.circle
                  key={p.label}
                  {...arcCommon}
                  initial={{ opacity: 0, pathLength: 0, pathOffset: acc }}
                  animate={{ opacity: 1, pathLength: frac, pathOffset: acc }}
                  transition={{
                    delay: 0.24 + i * 0.18,
                    duration: 0.75,
                    ease: EASE,
                    // one console tick as each arc lands (no-op with audio off)
                    onComplete: () => {
                      if (p.value > 0) sfxBlip(560 + i * 170, (560 + i * 170) * 1.4, 0.05, 0.02);
                    },
                  }}
                />
              );
              acc += frac;
              return el;
            })}
          </svg>
          {/* center total as HTML overlay — SVG <text> can't host the CountUp span */}
          <div style={{ position: 'absolute', inset: 0, display: 'flex', alignItems: 'center', justifyContent: 'center', pointerEvents: 'none' }}>
            <span className="sf-gradient-text" style={{ fontSize: 26, fontWeight: 800, letterSpacing: -0.5 }}>
              <CountUp to={realTotal} duration={1.1} />
            </span>
          </div>
        </div>
      </motion.div>
      <motion.div
        initial="hidden"
        animate="show"
        variants={{ hidden: {}, show: { transition: { staggerChildren: 0.09, delayChildren: 0.5 } } }}
        style={{ display: 'flex', flexDirection: 'column', gap: 6 }}
      >
        {parts.map((p) => (
          <motion.div
            key={p.label}
            variants={{
              hidden: { opacity: 0, x: 16 },
              show: { opacity: 1, x: 0, transition: { duration: 0.45, ease: EASE } },
            }}
            style={{ fontSize: 13, color: '#cbd5e1', display: 'flex', gap: 8, alignItems: 'center' }}
          >
            <span style={{ width: 10, height: 10, borderRadius: 3, background: p.color }} /> {p.label} <b style={{ color: '#fff' }}>{p.value}</b>
          </motion.div>
        ))}
      </motion.div>
    </div>
  );
}

function Trend({ values }: { values: number[] }) {
  const reduced = useReducedMotion() ?? false;
  const W = 560;
  const H = 120;
  const max = Math.max(1, ...values);
  const xs = values.map((_, i) => (i / Math.max(1, values.length - 1)) * W);
  const ys = values.map((v) => H - 8 - (v / max) * (H - 24));
  const pts = values.map((v, i) => `${xs[i]},${ys[i]}`).join(' ');
  const lastX = xs[xs.length - 1] ?? 0;
  const lastY = ys[ys.length - 1] ?? H - 8;
  // markers only pay off on a readable number of points
  const showMarkers = values.length > 1 && values.length <= 40;
  return (
    <svg width="100%" height={H} viewBox={`0 0 ${W} ${H}`} preserveAspectRatio="none" style={{ display: 'block' }}>
      <defs>
        <linearGradient id="sf-trend-grad" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stopColor="#22d3ee" stopOpacity="0.45" />
          <stop offset="100%" stopColor="#22d3ee" stopOpacity="0.02" />
        </linearGradient>
        <linearGradient id="sf-scan-core" x1="0" y1="0" x2="1" y2="0">
          <stop offset="0%" stopColor="#22d3ee" stopOpacity="0" />
          <stop offset="60%" stopColor="#a5f3fc" stopOpacity="0.85" />
          <stop offset="100%" stopColor="#ffffff" stopOpacity="1" />
        </linearGradient>
        <linearGradient id="sf-scan-halo" x1="0" y1="0" x2="1" y2="0">
          <stop offset="0%" stopColor="#22d3ee" stopOpacity="0" />
          <stop offset="100%" stopColor="#22d3ee" stopOpacity="0.14" />
        </linearGradient>
      </defs>
      {[0.25, 0.5, 0.75].map((f) => (
        <line key={f} x1="0" x2={W} y1={H * f} y2={H * f} stroke="rgba(255,255,255,0.06)" strokeWidth="1" />
      ))}
      {/* area fades in behind, then the line draws itself left→right */}
      <motion.polygon
        points={`0,${H} ${pts} ${W},${H}`}
        fill={`url(#sf-trend-grad)`}
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
      {/* scan head: a vertical light column sweeps left→right in sync with the draw */}
      {!reduced && (
        <motion.g
          initial={{ x: -8, opacity: 1 }}
          animate={{ x: W + 6, opacity: [1, 1, 0] }}
          transition={{ duration: 1.35, ease: 'easeOut', times: [0, 0.94, 1] }}
        >
          <rect x={-9} y={0} width={11} height={H} fill="url(#sf-scan-halo)" />
          <rect x={-1} y={0} width={2.5} height={H} fill="url(#sf-scan-core)" />
        </motion.g>
      )}
      {/* data-point markers pop in after the draw (small queues only) */}
      {showMarkers &&
        xs.map((x, i) => (
          <motion.circle
            key={i}
            cx={x}
            cy={ys[i]}
            r={2.4}
            fill="#67e8f9"
            initial={reduced ? false : { opacity: 0, scale: 0.4 }}
            animate={{ opacity: 1, scale: 1 }}
            transition={reduced ? undefined : { delay: 1.4 + i * 0.035, duration: 0.3, ease: EASE }}
            style={{ transformOrigin: `${x}px ${ys[i]}px` }}
          />
        ))}
      {/* end beacon: the "this is now" dot pulses forever at the newest point */}
      <motion.circle
        cx={lastX}
        cy={lastY}
        r={3.2}
        fill="#22d3ee"
        initial={reduced ? false : { opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ delay: 1.4, duration: 0.3 }}
      />
      {!reduced && (
        <motion.circle
          cx={lastX}
          cy={lastY}
          r={4.5}
          fill="none"
          stroke="#22d3ee"
          strokeWidth="1.4"
          initial={{ opacity: 0 }}
          animate={{ opacity: [0, 0.7, 0.1], scale: [0.5, 1.6, 2.4] }}
          transition={{ delay: 1.6, duration: 1.9, repeat: Infinity, ease: 'easeOut' }}
          style={{ transformOrigin: `${lastX}px ${lastY}px` }}
        />
      )}
    </svg>
  );
}

function Bars({ items }: { items: { label: string; value: number }[] }) {
  const reduced = useReducedMotion() ?? false;
  const max = Math.max(1, ...items.map((i) => i.value));
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
      {items.map((it, i) => (
        <motion.div
          key={it.label}
          initial={reduced ? false : { opacity: 0, x: -12 }}
          animate={{ opacity: 1, x: 0 }}
          transition={reduced ? undefined : { delay: 0.12 + i * 0.07, duration: 0.45, ease: EASE }}
          whileHover={reduced ? undefined : { x: 3 }}
        >
          <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 12.5, marginBottom: 4 }}>
            <span style={{ color: '#cbd5e1', fontFamily: 'monospace' }}>{it.label}</span>
            <b style={{ color: '#fff' }}>
              <CountUp to={it.value} duration={0.9} />
            </b>
          </div>
          <div style={{ height: 8, borderRadius: 4, background: 'rgba(255,255,255,0.07)', overflow: 'hidden' }}>
            <motion.div
              initial={reduced ? false : { width: 0 }}
              animate={{ width: `${(it.value / max) * 100}%` }}
              transition={
                reduced
                  ? undefined
                  : {
                      delay: 0.18 + i * 0.07,
                      duration: 0.8,
                      ease: EASE,
                      // one landing tick per bar, pitch rising down the ranking
                      onComplete: () => sfxBlip(460 + i * 70, (460 + i * 70) * 1.5, 0.045, 0.016),
                    }
              }
              style={{ height: '100%', borderRadius: 4, background: 'linear-gradient(90deg,#0891b2,#a855f7)', position: 'relative', overflow: 'hidden' }}
            >
              {!reduced && (
                <motion.span
                  aria-hidden
                  initial={{ x: '-110%' }}
                  animate={{ x: '420%' }}
                  transition={{ delay: 1.2 + i * 0.07, duration: 1.2, ease: 'easeInOut', repeat: Infinity, repeatDelay: 4.5 }}
                  style={{ position: 'absolute', top: 0, bottom: 0, left: 0, width: '28%', background: 'linear-gradient(90deg, transparent, rgba(255,255,255,0.32), transparent)' }}
                />
              )}
            </motion.div>
          </div>
        </motion.div>
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
  const pinged = useRef(false); // the "data landed" ping fires once per mount

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
      if (!pinged.current) {
        pinged.current = true;
        sfxPing(0.02); // quiet sonar — the console has data (no-op with audio off)
      }
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
      sfxPing(0.026); // the seeded queue just surfaced
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
                    {/* round-33: each row opens its evidence chain — the verdict,
                        the engines behind it, and the replayable repro. */}
                    {top.map((f) => (
                      <a
                        key={f.id}
                        href={`/findings/${f.id}`}
                        className="sf-glass"
                        onPointerMove={glassGlow}
                        style={{ borderRadius: 10, padding: '9px 12px', fontSize: 13, display: 'flex', gap: 10, alignItems: 'center', textDecoration: 'none', color: 'inherit' }}
                      >
                        <b style={{ color: '#fff', minWidth: 34 }}>P{priority(f)}</b>
                        <span style={{ flex: 1 }}>{f.title}</span>
                        <Badge tone={f.confidence === 'Confirmed' ? 'green' : f.confidence === 'Likely' ? 'amber' : 'gray'}>{f.confidence.toUpperCase()}</Badge>
                        <span aria-hidden style={{ color: '#22d3ee' }}>›</span>
                      </a>
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
