'use client';
import { useEffect, useState } from 'react';
import { motion } from 'framer-motion';
import HeroScene from './HeroScene';

// Full-viewport cinematic hero: live 3D scene, staged title reveal, live stat chips
// (from the API when running; static fleet aggregates otherwise), dual CTAs.
const API = process.env.NEXT_PUBLIC_API_URL ?? 'http://localhost:4000';

function useStats() {
  const [stats, setStats] = useState({ modules: 11, chains: 3, engines: 7, stages: 8 });
  useEffect(() => {
    let live = true;
    (async () => {
      try {
        const [demo, mods] = await Promise.all([
          fetch(`${API}/v1/graph/demo`, { signal: AbortSignal.timeout(10000) }).then((r) => r.json()),
          fetch(`${API}/v1/modules`, { signal: AbortSignal.timeout(10000) }).then((r) => r.json()),
        ]);
        if (live) setStats({ modules: mods.modules?.length ?? 11, chains: demo.paths?.length ?? 3, engines: 7, stages: 8 });
      } catch {
        /* offline — static aggregates stand in */
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
  const chips = [
    `${stats.modules} PLATFORM MODULES`,
    `${stats.chains} RANKED CHAINS LIVE`,
    `${stats.engines} MCP ENGINES`,
    `${stats.stages} PIPELINE STAGES`,
  ];
  return (
    <header style={{ position: 'relative', height: '94vh', minHeight: 620, overflow: 'hidden' }}>
      <HeroScene />
      <div className="sf-hero-vignette" style={{ position: 'absolute', inset: 0, pointerEvents: 'none' }} />
      <motion.div
        variants={container}
        initial="hidden"
        animate="show"
        style={{ position: 'relative', zIndex: 2, height: '100%', maxWidth: 1100, margin: '0 auto', padding: '0 32px', display: 'flex', flexDirection: 'column', justifyContent: 'center' }}
      >
        <motion.p variants={item} style={{ color: '#22d3ee', letterSpacing: 6, fontSize: 13, margin: 0 }}>
          SENTINELFORGE v3 · PREDICTIVE IOT SECURITY
        </motion.p>
        <motion.h1 variants={item} className="sf-gradient-text" style={{ fontSize: 'clamp(44px, 7.5vw, 96px)', lineHeight: 1.02, margin: '14px 0', fontWeight: 800, letterSpacing: -2 }}>
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
            <span key={c} className="sf-chip" style={{ color: '#a5f3fc' }}>{c}</span>
          ))}
        </motion.div>
      </motion.div>
      <div className="sf-scroll-cue" style={{ position: 'absolute', bottom: 22, left: '50%', marginLeft: -12, zIndex: 2, color: '#22d3ee', fontSize: 22 }}>
        ▾
      </div>
    </header>
  );
}
