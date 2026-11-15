'use client';
import { useEffect, useRef, useState, type CSSProperties } from 'react';
import { motion, useReducedMotion, type Variants } from 'framer-motion';

// Motion-text kit for the story acts: a terminal-style decode for eyebrows and
// word-by-word blur-up reveals for titles. Both collapse to plain text under
// prefers-reduced-motion, and DecodeText only ever runs while `active`.

const GLYPHS = '01<>#$%&*+=/\\|ABCDEF';

export function DecodeText({
  text,
  active,
  className,
  style,
}: {
  text: string;
  active: boolean;
  className?: string;
  style?: CSSProperties;
}) {
  const [out, setOut] = useState(text);
  const raf = useRef(0);

  useEffect(() => {
    if (!active) {
      setOut(text);
      return;
    }
    if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) return;
    const t0 = performance.now();
    const D = 780;
    const tick = (t: number) => {
      const k = Math.min(1, (t - t0) / D);
      const n = Math.floor(text.length * k);
      let s = text.slice(0, n);
      for (let i = n; i < text.length; i++) {
        const c = text[i];
        s += c === ' ' || c === '·' ? c : GLYPHS[(Math.random() * GLYPHS.length) | 0];
      }
      setOut(s);
      if (k < 1) raf.current = requestAnimationFrame(tick);
    };
    raf.current = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf.current);
  }, [active, text]);

  return (
    <p className={className} style={style}>
      <span aria-hidden="true">{out}</span>
      <span className="sf-sr-only">{text}</span>
    </p>
  );
}

const wordV: Variants = {
  hidden: { opacity: 0, y: 16, filter: 'blur(10px)' },
  show: {
    opacity: 1,
    y: 0,
    filter: 'blur(0px)',
    transition: { duration: 0.55, ease: [0.22, 1, 0.36, 1] },
  },
};

// Title reveal: each word carries its own gradient clip + blur-up, which keeps
// background-clip:text well-behaved (per-word clip instead of clipping against
// animated children). Words consume the enclosing container's variants, so the
// container's staggerChildren sets the word cadence. `as` switches tag for
// inner-page H1s.
export function SplitWords({
  text,
  className,
  as = 'h2',
}: {
  text: string;
  className?: string;
  as?: 'h1' | 'h2';
}) {
  const reduced = useReducedMotion() ?? false;
  const words = text.split(' ');
  const inner = (
    <>
      {words.map((w, i) => (
        <motion.span
          key={`${w}-${i}`}
          variants={wordV}
          aria-hidden="true"
          className="sf-gradient-text"
          style={{ display: 'inline-block', willChange: 'transform, filter, opacity' }}
        >
          {w}
          {i < words.length - 1 ? '\u00A0' : ''}
        </motion.span>
      ))}
    </>
  );
  if (reduced) {
    return as === 'h1' ? <h1 className={className}>{text}</h1> : <h2 className={className}>{text}</h2>;
  }
  return as === 'h1' ? (
    <h1 className={className} aria-label={text}>
      {inner}
    </h1>
  ) : (
    <h2 className={className} aria-label={text}>
      {inner}
    </h2>
  );
}
