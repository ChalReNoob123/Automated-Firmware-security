'use client';
import { useEffect, useRef } from 'react';
import { useReducedMotion } from 'framer-motion';
import { GhostNum } from './motionKit';
import DeviceWizard from './DeviceWizard';

// Round-17 closing act: the "Is your fleet ready to be proven?" headline is
// now a WEIGHT SCRUB — as the section crosses the viewport, a wave of font
// weight (220 → 900) sweeps across the words, so the question literally
// gathers conviction as you arrive. Progress is measured manually (the
// StoryStage pattern — framer-motion's useScroll({ target }) has a hydration
// invariant we avoid by construction): one rAF-throttled rect read per
// scroll event, weights written straight into spans (no React re-renders).
// Reduced motion keeps the original static bold.

const WORDS = ['Is', 'your', 'fleet', 'ready', 'to', 'be', 'proven?'];
const BR_AFTER = 3; // "Is your fleet ready" / "to be proven?"
const GRAD_WORD = WORDS.length - 1; // "proven?" keeps the gradient

export default function ProveSection() {
  const sec = useRef<HTMLElement>(null);
  const spans = useRef<(HTMLSpanElement | null)[]>([]);
  const reduced = useReducedMotion() ?? false;

  useEffect(() => {
    if (reduced) return;
    let raf = 0;
    const paint = () => {
      raf = 0;
      const el = sec.current;
      if (!el) return;
      const r = el.getBoundingClientRect();
      const vh = window.innerHeight;
      // 0 while the block's top is below 88% of the viewport, 1 by 30%
      const q = Math.min(1, Math.max(0, (vh * 0.88 - r.top) / (vh * 0.58)));
      const n = WORDS.length;
      spans.current.forEach((sp, i) => {
        if (!sp) return;
        // staggered window per word — boldness sweeps left to right
        const local = Math.min(1, Math.max(0, q * (n + 1.5) - i * 1.05));
        sp.style.fontWeight = String(Math.round(220 + local * 680));
      });
    };
    const onScroll = () => {
      if (!raf) raf = requestAnimationFrame(paint);
    };
    window.addEventListener('scroll', onScroll, { passive: true });
    window.addEventListener('resize', onScroll, { passive: true });
    paint();
    return () => {
      window.removeEventListener('scroll', onScroll);
      window.removeEventListener('resize', onScroll);
      if (raf) cancelAnimationFrame(raf);
    };
  }, [reduced]);

  return (
    <section ref={sec} style={{ maxWidth: 1100, margin: '0 auto', padding: '0 32px 72px', position: 'relative' }}>
      <GhostNum n="04" />
      <p style={{ color: '#22d3ee', letterSpacing: 5, fontSize: 12 }}>04 · GET STARTED</p>
      <h2 className="sf-prove-h" style={{ fontSize: 'clamp(34px, 5.4vw, 64px)', margin: '8px 0 6px', letterSpacing: -2, lineHeight: 1.05 }}>
        {WORDS.map((w, i) => (
          <span key={`${w}-${i}`}>
            <span
              ref={(el) => {
                spans.current[i] = el;
              }}
              className={`sf-prove-word${i === GRAD_WORD ? ' sf-gradient-text' : ''}`}
              style={reduced ? { fontWeight: 800 } : { fontWeight: 220 }}
            >
              {w}
            </span>
            {i === BR_AFTER ? <br /> : ' '}
          </span>
        ))}
      </h2>
      <p style={{ color: '#94a3b8', maxWidth: 640, lineHeight: 1.6 }}>
        USB, Wi-Fi, BLE, Zigbee, Z-Wave, UART or JTAG — every test begins with a logged authorization attestation. No
        attestation, no pipeline.
      </p>
      <DeviceWizard />
    </section>
  );
}
