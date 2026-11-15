'use client';
import { useEffect } from 'react';

// Round 15 fix (user-reported hydration mismatch): this component USED to run a
// document-level delegated pointermove listener that wrote --gx/--gy into every
// .sf-glass under the pointer. Firing the moment the layout hydrated, it could
// mutate .sf-glass elements belonging to NOT-YET-HYDRATED components (streamed
// boundaries, late chunks) — React then compared its server HTML snapshot
// against the mutated DOM and logged "a tree hydrated but some attributes of
// the server rendered HTML didn't match". The glow now rides React's own
// delegated events instead (onPointerMove={glassGlow} on each glass element in
// components/ui.tsx and call sites): synthetic handlers only dispatch through
// hydrated fibers, so pre-hydration mutation is structurally impossible, while
// the perf profile is unchanged (one native pointermove listener total).
// Elements without the handler keep a centered glow (CSS var fallbacks).
//
// Round 10: still writes the nebula scroll-parallax var (--ns on the fixed wash
// container in the root layout). Safe to mutate from this effect: the nebula is
// part of the initial hydration commit, so it is already claimed by React
// before any effect runs. The container's long expo-out CSS transition turns
// raw scroll positions into a fluid chase. Skipped for reduced motion.
export default function PointerGlow() {
  useEffect(() => {
    const cleanups: (() => void)[] = [];

    const nebula = document.querySelector('.sf-nebula') as HTMLElement | null;
    const reduced = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    if (nebula && !reduced) {
      let raf = 0;
      const onScroll = () => {
        if (raf) return;
        raf = requestAnimationFrame(() => {
          raf = 0;
          nebula.style.setProperty('--ns', (window.scrollY * 0.045).toFixed(2));
        });
      };
      onScroll();
      window.addEventListener('scroll', onScroll, { passive: true });
      cleanups.push(() => {
        window.removeEventListener('scroll', onScroll);
        if (raf) cancelAnimationFrame(raf);
      });
    }

    return () => cleanups.forEach((fn) => fn());
  }, []);
  return null;
}
