'use client';
import { useEffect } from 'react';

// Round-18: a universal press pulse — every click lands with a small radial
// ring at the pointer, like the interface acknowledging the hit. The ripple
// elements are created imperatively, appended to <body>, and self-remove
// after the animation: they never touch React-managed DOM, so the round-15a
// hydration rule holds by construction (same pattern as the audio engine's
// delegated listeners). Fine pointers only; skipped under reduced motion.

export default function ClickFx() {
  useEffect(() => {
    const fine = window.matchMedia('(hover: hover) and (pointer: fine)').matches;
    const reduced = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    if (!fine || reduced) return;
    const down = (e: PointerEvent) => {
      const el = document.createElement('div');
      el.className = 'sf-click-pulse';
      el.style.left = `${e.clientX}px`;
      el.style.top = `${e.clientY}px`;
      document.body.appendChild(el);
      window.setTimeout(() => el.remove(), 640);
    };
    document.addEventListener('pointerdown', down, { passive: true });
    return () => document.removeEventListener('pointerdown', down);
  }, []);
  return null; // the pulses live outside React entirely
}
