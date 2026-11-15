'use client';
import { useEffect, useRef, useState } from 'react';
import { motion, useScroll, useTransform } from 'framer-motion';
import HeroScene from './HeroScene';
import { CountUp } from './motionKit';

// Full-viewport cinematic hero: live 3D scene, staged title reveal, live stat chips
// (from the API when running; static fleet aggregates otherwise), dual CTAs.
import { API_URL } from './lib/auth';

function useStats() {
  const [stats, setStats] = useState({ modules: 11, chains: 3, engines: 7, stages: 8 });
  useEffect(() => {
    let live = true;
    (async () => {
      try {
        const [demo, mods] = await Promise.all([
          fetch(`${API_URL}/v1/graph/demo`, { signal: AbortSignal.timeout(10000) }).then((r) => (r.ok ? r.json() : null)),
          fetch(`${API_URL}/v1/modules`, { signal: AbortSignal.timeout(10000) }).then((r) => (r.ok ? r.json() : null)),
        ]);
        if (live)
          setStats({
            modules: mods?.modules?.length ?? 11,
            chains: demo?.paths?.length ?? 3,
            engines: 7,
            stages: 8,
          });
      } catch {
        /* offline / signed-out — static aggregates stand in (no console noise) */
      }
    })();
    return () => {
      live = false;
    };
  }, []);
  return stats;
}

const container = { hidden: {}, show: { transition: { staggerChildren: 0.12, delayChildren: 0.25 } } };
const item = { hidden: { opacity: 0, y: 34, filter: 'blur(8px)' }, show: { opacity: 1, y: 0, filter: 'blur(0px)', transition: { duration: 0.9, ease: [0.22, 1, 0.36, 1] as const } } };

export default function CinematicHero() {
  const stats = useStats();
  const headerRef = useRef<HTMLDivElement>(null);
  const [immobile, setImmobile] = useState(false);
  useEffect(() => {
    setImmobile(window.matchMedia('(prefers-reduced-motion: reduce)').matches);
  }, []);
  // Scroll-linked depth: the hero sinks/blurs as the page scrolls away — the
  // 3D scene becomes a fading backdrop instead of a hard cut to content.
  const { scrollYProgress } = useScroll({ target: headerRef, offset: ['start start', 'end start'] });
  const sinkY = useTransform(scrollYProgress, [0, 1], [0, 110]);
  const fade = useTransform(scrollYProgress, [0, 0.75], [1, 0]);
  const blurPx = useTransform(scrollYProgress, [0, 0.8], [0, 12]);
  const blurFilter = useTransform(blurPx, (v) => `blur(${v.toFixed(2)}px)`);
  const depthStyle = immobile ? undefined : { y: sinkY, opacity: fade, filter: blurFilter };
  const chips = [
    { v: stats.modules, l: 'PLATFORM MODULES' },
    { v: stats.chains, l: 'RANKED CHAINS LIVE' },
    { v: stats.engines, l: 'MCP ENGINES' },
    { v: stats.stages, l: 'PIPELINE STAGES' },
  ];
  return (
    <header ref={headerRef} style={{ position: 'relative', height: '94vh', minHeight: 620, overflow: 'hidden' }}>
      <HeroScene />
      <div className="sf-hero-vignette" style={{ position: 'absolute', inset: 0, pointerEvents: 'none' }} />
      <motion.div style={{ position: 'absolute', inset: 0, zIndex: 2, pointerEvents: 'none', ...depthStyle }}>
      <motion.div
        variants={container}
        initial="hidden"
        animate="show"
        style={{ pointerEvents: 'auto', height: '100%', maxWidth: 1100, margin: '0 auto', padding: '0 32px', display: 'flex', flexDirection: 'column', justifyContent: 'center' }}
      >
        <motion.p variants={item} style={{ color: '#22d3ee', letterSpacing: 6, fontSize: 13, margin: 0 }}>
          SENTINELFORGE v3 · PREDICTIVE IOT SECURITY
        </motion.p>
        <motion.h1 variants={item} className="sf-gradient-text sf-shimmer" style={{ fontSize: 'clamp(44px, 7.5vw, 96px)', lineHeight: 1.02, margin: '14px 0', fontWeight: 800, letterSpacing: -2 }}>
          Find the flaws<br />nobody catalogued.
        </motion.h1>
        <motion.p variants={item} style={{ color: '#94a3b8', fontSize: 'clamp(15px, 2vw, 19px)', maxWidth: 640, lineHeight: 1.6 }}>
          Discovery engine, patch verification, and N-day radar — running continuously against
          your firmware and live devices. Not a point-in-time checklist.
        </motion.p>
        <motion.div variants={item} style={{ display: 'flex', gap: 14, marginTop: 28, flexWrap: 'wrap' }}>
          <a className="sf-btn-primary" href="/emulator">Boot a digital twin</a>
          <a className="sf-btn-ghost" href="/attacks">Run an attack sim</a>
        </motion.div>
        <motion.div variants={item} style={{ display: 'flex', gap: 10, marginTop: 30, flexWrap: 'wrap' }}>
          {chips.map((c) => (
            <span key={c.l} className="sf-chip" style={{ color: '#a5f3fc' }}>
              <CountUp to={c.v} /> {c.l}
            </span>
          ))}
        </motion.div>
      </motion.div>
      </motion.div>
      <div className="sf-scroll-cue" style={{ position: 'absolute', bottom: 22, left: '50%', marginLeft: -12, zIndex: 2, color: '#22d3ee', fontSize: 22 }}>
        ▾
      </div>
    </header>
  );
}
