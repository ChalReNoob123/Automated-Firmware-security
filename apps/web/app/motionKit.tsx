'use client';
import { motion, useMotionTemplate, useMotionValue, useSpring } from 'framer-motion';
import { DecodeText, SplitWords } from './motionText';
import { usePathname } from 'next/navigation';
import { useEffect, useRef, useState, type CSSProperties, type ReactNode } from 'react';

// Shared motion kit. Everything here respects prefers-reduced-motion — the
// fleet of ambient animations must never ship as an accessibility cliff.

const EASE = [0.22, 1, 0.36, 1] as const;

/* ---------------- Reveal: scroll-into-view fade/rise/blur ---------------- */

export function Reveal({
  children,
  delay = 0,
  y = 26,
  once = true,
}: {
  children: ReactNode;
  delay?: number;
  y?: number;
  once?: boolean;
}) {
  return (
    <motion.div
      initial={{ opacity: 0, y, filter: 'blur(8px)' }}
      whileInView={{ opacity: 1, y: 0, filter: 'blur(0px)' }}
      viewport={{ once, margin: '-60px' }}
      transition={{ duration: 0.7, delay, ease: EASE }}
    >
      {children}
    </motion.div>
  );
}

/* -------- PageHeader: staggered entrance for every inner page -------- */
// Round 6: the eyebrow decodes terminal-style, the title reveals word-by-word
// (variants propagate from this container into SplitWords' word spans), the
// sub rises, and a gradient rule draws itself under the block.

const headerItem = {
  hidden: { opacity: 0, y: 22, filter: 'blur(6px)' },
  show: { opacity: 1, y: 0, filter: 'blur(0px)', transition: { duration: 0.68, ease: EASE } },
};

const headerRule = {
  hidden: { scaleX: 0, opacity: 0 },
  show: { scaleX: 1, opacity: 1, transition: { duration: 0.9, delay: 0.35, ease: EASE } },
};

export function PageHeader({ eyebrow, title, sub }: { eyebrow: string; title: string; sub?: ReactNode }) {
  const path = usePathname();
  const [reduced, setReduced] = useState(false);
  const [on, setOn] = useState(false);
  useEffect(() => {
    const mq = window.matchMedia('(prefers-reduced-motion: reduce)');
    const sync = () => setReduced(mq.matches);
    sync();
    mq.addEventListener('change', sync);
    setOn(true); // the decode runs once per page load
    return () => mq.removeEventListener('change', sync);
  }, []);
  // console-style path tag pinned to the header's top-right
  const pathTag =
    path && path !== '/' ? <span className="sf-header-path" aria-hidden>{`SF://${path.replace(/^\//, '')}`}</span> : null;
  if (reduced) {
    return (
      <div className="sf-page-head">
        <p className="sf-eyebrow">{eyebrow}</p>
        <h1 className="sf-h1 sf-gradient-text">{title}</h1>
        {sub && <p className="sf-sub">{sub}</p>}
        <div className="sf-header-rule" aria-hidden />
        {pathTag}
      </div>
    );
  }
  return (
    <motion.div
      className="sf-page-head"
      initial="hidden"
      animate="show"
      variants={{ hidden: {}, show: { transition: { staggerChildren: 0.085 } } }}
    >
      <DecodeText text={eyebrow} active={on} className="sf-eyebrow" />
      <SplitWords as="h1" text={title} className="sf-h1" />
      {sub && (
        <motion.p variants={headerItem} className="sf-sub">
          {sub}
        </motion.p>
      )}
      <motion.div aria-hidden className="sf-header-rule" variants={headerRule} />
      {pathTag}
    </motion.div>
  );
}

/* ---------------- Tilt: pointer-tracked 3D card with glare ---------------- */
// Small angles (≤7°) — enough to feel physical, not enough to clip content.
// Touch pointers skip the effect entirely; reduced-motion renders a plain card
// (SSR-safe: decided in effect, never during hydration).

export function Tilt({
  children,
  max = 7,
  glare = true,
  className,
  style,
}: {
  children: ReactNode;
  max?: number;
  glare?: boolean;
  className?: string;
  style?: CSSProperties;
}) {
  const [immobile, setImmobile] = useState(false);
  const box = useRef<HTMLDivElement>(null);
  const rx = useMotionValue(0);
  const ry = useMotionValue(0);
  const gx = useMotionValue(50);
  const gy = useMotionValue(50);
  const hover = useMotionValue(0);
  const srx = useSpring(rx, { stiffness: 160, damping: 16 });
  const sry = useSpring(ry, { stiffness: 160, damping: 16 });
  const glareBg = useMotionTemplate`radial-gradient(340px circle at ${gx}% ${gy}%, rgba(255,255,255,0.11), transparent 60%)`;

  useEffect(() => {
    setImmobile(window.matchMedia('(prefers-reduced-motion: reduce)').matches);
  }, []);

  if (immobile) {
    return (
      <div className={className} style={style}>
        {children}
      </div>
    );
  }

  const onMove = (e: React.PointerEvent) => {
    const el = box.current;
    if (!el || e.pointerType === 'touch') return;
    const r = el.getBoundingClientRect();
    const nx = (e.clientX - r.left) / r.width;
    const ny = (e.clientY - r.top) / r.height;
    ry.set((nx - 0.5) * 2 * max);
    rx.set(-(ny - 0.5) * 2 * max);
    gx.set(nx * 100);
    gy.set(ny * 100);
  };
  const onLeave = () => {
    rx.set(0);
    ry.set(0);
    hover.set(0);
  };

  return (
    <div ref={box} style={{ perspective: 900, ...style }} className={className} onPointerMove={onMove} onPointerLeave={onLeave} onPointerEnter={(e) => e.pointerType !== 'touch' && hover.set(1)}>
      <motion.div
        style={{ rotateX: srx, rotateY: sry, transformStyle: 'preserve-3d', position: 'relative', height: '100%' }}
        whileHover={{ scale: 1.015 }}
        transition={{ duration: 0.2 }}
      >
        {children}
        {glare && (
          <motion.div
            aria-hidden
            style={{
              position: 'absolute',
              inset: 0,
              background: glareBg,
              opacity: hover,
              borderRadius: 'inherit',
              pointerEvents: 'none',
              mixBlendMode: 'overlay',
            }}
          />
        )}
      </motion.div>
    </div>
  );
}

/* -------- CountUp: numbers that tick up when they enter the viewport -------- */

export function CountUp({ to, duration = 1.2, suffix = '' }: { to: number; duration?: number; suffix?: string }) {
  const [v, setV] = useState(0);
  const ref = useRef<HTMLSpanElement>(null);
  const done = useRef(false);
  const anim = useRef(0); // generation — a newer target cancels an in-flight tick
  useEffect(() => {
    const el = ref.current;
    if (!el) return;
    const reduced = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    if (reduced) {
      setV(to);
      return;
    }
    if (done.current) {
      // target changed after a previous animation — snap, don't re-tick
      setV(to);
      return;
    }
    const my = ++anim.current;
    const io = new IntersectionObserver(
      (entries) => {
        for (const e of entries) {
          if (!e.isIntersecting || done.current) continue;
          done.current = true;
          const t0 = performance.now();
          const tick = (t: number) => {
            if (my !== anim.current) return; // superseded
            const p = Math.min(1, (t - t0) / (duration * 1000));
            setV(Math.round(to * (1 - Math.pow(1 - p, 3))));
            if (p < 1 && my === anim.current) requestAnimationFrame(tick);
          };
          requestAnimationFrame(tick);
        }
      },
      { threshold: 0.4 }
    );
    io.observe(el);
    return () => io.disconnect();
  }, [to, duration]);
  return (
    <span ref={ref}>
      {v}
      {suffix}
    </span>
  );
}

/* -------- Magnetic: buttons lean toward the pointer (fine pointers only) -------- */

export function Magnetic({
  children,
  strength = 0.26,
  className,
  style,
}: {
  children: ReactNode;
  strength?: number;
  className?: string;
  style?: CSSProperties;
}) {
  const ref = useRef<HTMLSpanElement>(null);
  const [on, setOn] = useState(false);

  useEffect(() => {
    if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) return;
    if (!window.matchMedia('(hover: hover) and (pointer: fine)').matches) return;
    setOn(true);
  }, []);

  useEffect(() => {
    const el = ref.current;
    if (!on || !el) return;
    const move = (e: PointerEvent) => {
      const r = el.getBoundingClientRect();
      const dx = e.clientX - (r.left + r.width / 2);
      const dy = e.clientY - (r.top + r.height / 2);
      el.style.transform = `translate(${(dx * strength).toFixed(1)}px, ${(dy * strength).toFixed(1)}px)`;
    };
    const reset = () => {
      el.style.transform = '';
    };
    el.addEventListener('pointermove', move);
    el.addEventListener('pointerleave', reset);
    return () => {
      el.removeEventListener('pointermove', move);
      el.removeEventListener('pointerleave', reset);
      el.style.transform = '';
    };
  }, [on, strength]);

  return (
    <span
      ref={ref}
      className={className}
      style={{ display: 'inline-block', transition: 'transform 0.22s cubic-bezier(0.22, 1, 0.36, 1)', ...style }}
    >
      {children}
    </span>
  );
}

/* -------- GhostNum: huge outlined section numeral (CSS float loop, gated) -------- */

export function GhostNum({ n }: { n: string }) {
  return (
    <span aria-hidden className="sf-ghost-num">
      {n}
    </span>
  );
}

/* -------- MaskWords: Lusion-signature word-rise for section headings --------
// Each word rises out of an overflow-hidden mask with a slight rotation, 
// staggered left to right — the reveal reads as typographic choreography,
// not a fade. Pure static JSX (no measurement, no scroll target), so
// hydration is deterministic; reduced motion renders the plain text. */

export function MaskWords({
  text,
  className,
  as: Tag = 'h2',
  stagger = 0.055,
  style,
}: {
  text: string;
  className?: string;
  as?: 'h1' | 'h2' | 'h3';
  stagger?: number;
  style?: CSSProperties;
}) {
  const [reduced, setReduced] = useState(false);
  useEffect(() => {
    setReduced(window.matchMedia('(prefers-reduced-motion: reduce)').matches);
  }, []);
  if (reduced) {
    return <Tag className={className} style={style}>{text}</Tag>;
  }
  const words = text.split(' ');
  return (
    <Tag className={className} style={style}>
      <motion.span
        className="sf-mask-sentence"
        initial="hidden"
        whileInView="show"
        viewport={{ once: true, margin: '-40px' }}
        variants={{ hidden: {}, show: { transition: { staggerChildren: stagger } } }}
      >
        {words.map((w, i) => (
          <span key={`${w}-${i}`} className="sf-mask-word">
            <motion.span
              className="sf-mask-word-inner"
              variants={{
                hidden: { y: '115%', rotate: 3 },
                show: { y: '0%', rotate: 0, transition: { duration: 0.72, ease: EASE } },
              }}
            >
              {w}
            </motion.span>
          </span>
        ))}
      </motion.span>
    </Tag>
  );
}
