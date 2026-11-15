'use client';
import { useEffect, useRef } from 'react';
import { useReducedMotion } from 'framer-motion';

// Round-18: the giant footer wordmark drifts horizontally as the footer
// crosses the viewport — a slow ±6% translate tied to scroll progress (the
// manual-measure pattern: one rAF-throttled rect read per scroll event,
// value written straight into a CSS var, no React re-renders). The mark
// itself keeps its CSS hover glow; this wrapper only carries the drift.
// Reduced motion: static wordmark (the var is simply never written).

export default function FooterMark() {
  const ref = useRef<HTMLDivElement>(null);
  const reduced = useReducedMotion() ?? false;

  useEffect(() => {
    if (reduced) return;
    let raf = 0;
    const paint = () => {
      raf = 0;
      const el = ref.current;
      if (!el) return;
      const r = el.getBoundingClientRect();
      const vh = window.innerHeight;
      // 0 while the footer's top is at the viewport bottom edge, 1 once its
      // center reaches the viewport center
      const q = Math.min(1, Math.max(0, (vh - r.top) / (vh * 0.9 + r.height * 0.5)));
      el.style.setProperty('--fp-x', `${(0.5 - q) * 12}%`);
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
    <div ref={ref} className="sf-footer-parallax" aria-hidden>
      <div className="sf-footer-mark">SENTINELFORGE</div>
    </div>
  );
}
