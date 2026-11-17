'use client';
import { useEffect, useRef, useState, type ReactNode } from 'react';
import dynamic from 'next/dynamic';
import { motion, useMotionValue, useMotionValueEvent, useReducedMotion, useTransform, type MotionValue, type Variants } from 'framer-motion';
import { CountUp, Magnetic } from './motionKit';
import { DecodeText, SplitWords } from './motionText';
import { useStory } from './storyStore';
import { sfxImpact } from './audio/sfx';
import { API_URL } from './lib/auth';

// Lusion-style pinned storytelling: one tall scroll section (480vh) whose inner
// sticky viewport holds the WebGL scene + four sparse copy "acts". Scrolling
// morphs the 3D ensemble (assemble → unpack → hunt → verdict) and cross-fades
// the acts. Round 5: per-act decode + word-by-word title reveals, magnetic
// CTAs, a bottom progress line, and a readability scrim under the copy.
// Reduced motion: the canvas never mounts and the acts render as plain
// stacked sections.

const StoryScene = dynamic(() => import('./StoryScene'), { ssr: false });

type ActDef = {
  eyebrow: string;
  title: string;
  body: string;
  range: [number, number];
};

const ACTS: ActDef[] = [
  {
    eyebrow: 'ACT 01 · THE FIRMWARE',
    title: 'Every device hides a story.',
    body: 'A camera, a router, a sensor board — each ships with code nobody reads. We read it.',
    range: [0, 0.25],
  },
  {
    eyebrow: 'ACT 02 · THE UNPACKING',
    title: 'Unpack it. Map it. Taint it.',
    body: 'Binwalk splits the image, the SBOM names every component, taint tracking follows attacker input to every dangerous sink.',
    range: [0.25, 0.5],
  },
  {
    eyebrow: 'ACT 03 · THE HUNT',
    title: 'Then the machines hunt.',
    body: 'Coverage-guided AI fuzzing, emulator snapshots, ranked exploit chains — the twin breaks so your fleet does not.',
    range: [0.5, 0.75],
  },
  {
    eyebrow: 'ACT 04 · THE VERDICT',
    title: 'Confirmed. Or nothing.',
    body: 'A finding ships only when two independent engines agree — with its repro bundle attached.',
    range: [0.75, 1],
  },
];

const fadeItem: Variants = {
  hidden: { opacity: 0, y: 12 },
  show: { opacity: 1, y: 0, transition: { duration: 0.55, ease: [0.22, 1, 0.36, 1] } },
};

const riseItem: Variants = {
  hidden: { opacity: 0, y: 18 },
  show: { opacity: 1, y: 0, transition: { duration: 0.6, ease: [0.22, 1, 0.36, 1] } },
};

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
        /* offline / signed-out — static aggregates stand in */
      }
    })();
    return () => {
      live = false;
    };
  }, []);
  return stats;
}

function Act({
  p,
  def,
  active,
  first = false,
  children,
}: {
  p: MotionValue<number>;
  def: ActDef;
  active: boolean;
  first?: boolean;
  children?: ReactNode;
}) {
  const [a, b] = def.range;
  const w = 0.07;
  // first act is already on screen at p=0 — no fade-in, just fade-out
  const opacity = useTransform(p, first ? [b - w, b] : [a, a + w, b - w, b], first ? [1, 0] : [0, 1, 1, 0]);
  const y = useTransform(p, first ? [b - w, b] : [a, a + w, b - w, b], first ? [0, -36] : [36, 0, 0, -36]);
  return (
    <motion.div className="sf-act" style={{ opacity, y }}>
      <motion.div
        initial="hidden"
        animate={active ? 'show' : 'hidden'}
        variants={{ hidden: {}, show: { transition: { staggerChildren: 0.065, delayChildren: first ? 0.35 : 0.06 } } }}
      >
        <DecodeText text={def.eyebrow} active={active} className="sf-act-eyebrow" />
        <SplitWords text={def.title} className="sf-act-title" />
        <motion.p className="sf-act-body" variants={fadeItem}>
          {def.body}
        </motion.p>
        {children}
      </motion.div>
    </motion.div>
  );
}

function Rail({ p }: { p: MotionValue<number> }) {
  const o1 = useTransform(p, [-0.01, 0, 0.25, 0.28], [0.3, 1, 1, 0.3]);
  const o2 = useTransform(p, [0.22, 0.25, 0.5, 0.53], [0.3, 1, 1, 0.3]);
  const o3 = useTransform(p, [0.47, 0.5, 0.75, 0.78], [0.3, 1, 1, 0.3]);
  const o4 = useTransform(p, [0.72, 0.75, 1.01, 1.02], [0.3, 1, 1, 0.3]);
  const ops = [o1, o2, o3, o4];
  return (
    <div className="sf-story-rail" aria-hidden>
      {ACTS.map((a, i) => (
        <motion.span key={a.eyebrow} style={{ opacity: ops[i] }}>
          {String(i + 1).padStart(2, '0')} · {a.eyebrow.split('· ')[1]}
        </motion.span>
      ))}
    </div>
  );
}

export default function StoryStage() {
  const ref = useRef<HTMLDivElement>(null);
  const reduced = useReducedMotion() ?? false;
  const p = useMotionValue(0);
  const [active, setActive] = useState(0);
  const stats = useStats();

  // Manual scroll measurement. framer-motion's useScroll({ target }) throws
  // the invariant "Target ref is defined but not hydrated" whenever the ref
  // never attaches — which happens on this reduced-motion branch (ref stays
  // null, tree renders without the section). Measuring the pinned section
  // ourselves keeps one MotionValue in sync without that machinery.
  useEffect(() => {
    const el = ref.current;
    if (!el || reduced) return;
    const measure = () => {
      const rect = el.getBoundingClientRect();
      const total = el.offsetHeight - window.innerHeight;
      const v = total > 0 ? Math.min(1, Math.max(0, -rect.top / total)) : 0;
      p.set(v);
      useStory.getState().setP(v); // WebGL render loop reads the store
    };
    measure();
    window.addEventListener('scroll', measure, { passive: true });
    window.addEventListener('resize', measure, { passive: true });
    return () => {
      window.removeEventListener('scroll', measure);
      window.removeEventListener('resize', measure);
    };
  }, [p, reduced]);

  // act switching (decode/title reveals) — re-renders only on act change
  useMotionValueEvent(p, 'change', (v) => {
    const idx = v < 0.25 ? 0 : v < 0.5 ? 1 : v < 0.75 ? 2 : 3;
    setActive((cur) => (cur === idx ? cur : idx));
  });

  // round-18: act-cut choreography — every act change lands like a hard cut:
  // a one-frame flash overlay (keyed remount replays the CSS animation), a
  // ghost act numeral slamming behind the copy, and an audio impact thud
  // (silent unless SF://AUDIO is on). The very first act doesn't flash — the
  // page is already entering.
  const [flashIdx, setFlashIdx] = useState<number | null>(null);
  const prevActive = useRef(0);
  useEffect(() => {
    if (prevActive.current === active) return;
    prevActive.current = active;
    setFlashIdx(active);
    sfxImpact();
  }, [active]);

  const cueOpacity = useTransform(p, [0, 0.05], [1, 0]);

  if (reduced) {
    return (
      <section aria-label="SentinelForge story" style={{ position: 'relative', padding: '72px 24px', background: 'radial-gradient(ellipse 60% 50% at 50% 30%, rgba(34,211,238,0.08), transparent 70%), #020617' }}>
        {ACTS.map((a) => (
          <div key={a.eyebrow} style={{ maxWidth: 720, margin: '0 auto', padding: '34px 0' }}>
            <p className="sf-act-eyebrow">{a.eyebrow}</p>
            <h2 className="sf-act-title sf-gradient-text">{a.title}</h2>
            <p className="sf-act-body">{a.body}</p>
          </div>
        ))}
        <div style={{ display: 'flex', gap: 12, justifyContent: 'center', flexWrap: 'wrap', paddingTop: 10 }}>
          <a className="sf-btn-primary" href="/devices">Connect a device</a>
          <a className="sf-btn-ghost" href="/attacks">Run an attack sim</a>
        </div>
      </section>
    );
  }

  return (
    <section ref={ref} style={{ height: '480vh', position: 'relative' }} aria-label="SentinelForge story">
      <div style={{ position: 'sticky', top: 0, height: '100vh', overflow: 'hidden', background: '#020617' }}>
        <StoryScene />
        <div className="sf-hero-vignette" style={{ position: 'absolute', inset: 0, pointerEvents: 'none' }} />
        {/* round 28: anamorphic letterbox bars — the story plays inside a frame */}
        <div className="sf-cinebar top" aria-hidden />
        <div className="sf-cinebar bottom" aria-hidden />
        {/* round-16: holographic scanline sweeps the pinned viewport every ~9s */}
        <div className="sf-scanline" aria-hidden />

        {/* round-18: ghost act numeral slams in behind the copy on every act cut */}
        <div key={`slam-${active}`} className="sf-act-slam" aria-hidden>
          {String(active + 1).padStart(2, '0')}
        </div>
        {/* one-frame flash at each act cut (skips the initial mount) */}
        {flashIdx !== null && <div key={`flash-${flashIdx}`} className="sf-act-flash" aria-hidden />}

        <Act p={p} def={ACTS[0]} active={active === 0} first>
          <motion.p variants={fadeItem} className="sf-act-sub" style={{ marginTop: 20 }}>
            SENTINELFORGE v3 · PREDICTIVE IOT SECURITY
          </motion.p>
          <motion.div variants={riseItem} style={{ display: 'flex', gap: 12, marginTop: 20, flexWrap: 'wrap', justifyContent: 'center' }}>
            <Magnetic><a className="sf-btn-primary" href="/devices">Connect a device</a></Magnetic>
            <Magnetic><a className="sf-btn-ghost" href="/attacks">Run an attack sim</a></Magnetic>
          </motion.div>
        </Act>
        <Act p={p} def={ACTS[1]} active={active === 1} />
        <Act p={p} def={ACTS[2]} active={active === 2} />
        <Act p={p} def={ACTS[3]} active={active === 3}>
          <motion.div variants={fadeItem} style={{ display: 'flex', gap: 10, marginTop: 20, flexWrap: 'wrap', justifyContent: 'center' }}>
            {(
              [
                [stats.modules, 'PLATFORM MODULES'],
                [stats.chains, 'RANKED CHAINS LIVE'],
                [stats.engines, 'MCP ENGINES'],
                [stats.stages, 'PIPELINE STAGES'],
              ] as const
            ).map(([v, l]) => (
              <span key={l} className="sf-chip" style={{ color: '#a5f3fc' }}>
                <CountUp to={v} /> {l}
              </span>
            ))}
          </motion.div>
          <motion.div variants={riseItem} style={{ display: 'flex', gap: 12, marginTop: 18, flexWrap: 'wrap', justifyContent: 'center' }}>
            <Magnetic><a className="sf-btn-primary" href="/dashboard">See the fleet</a></Magnetic>
            <Magnetic><a className="sf-btn-ghost" href="/reports">Export the evidence</a></Magnetic>
          </motion.div>
        </Act>

        <Rail p={p} />

        <div className="sf-hud sf-hud-tl" aria-hidden>
          SF://FORGE · PREDICTIVE IOT DEFENSE
        </div>
        <div className="sf-hud sf-hud-br" aria-hidden>
          ACT {String(active + 1).padStart(2, '0')}/04 · SF://STORY
        </div>

        <motion.div className="sf-story-cue" style={{ opacity: cueOpacity }} aria-hidden>
          <span className="sf-story-cue-line" />
          scroll to explore
        </motion.div>

        {/* whole-story progress line */}
        <motion.div className="sf-story-progress" style={{ scaleX: p }} aria-hidden />
      </div>
    </section>
  );
}
