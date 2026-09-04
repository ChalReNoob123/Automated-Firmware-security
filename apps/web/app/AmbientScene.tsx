'use client';
import { useMemo } from 'react';

// Ambient backdrop for inner pages: pure-CSS starfield (seeded, SSR-safe) +
// nebula gradients. Replaces the earlier three.js scene — identical vibe at ~0
// extra kilobytes, so only the landing hero carries the WebGL weight.
function mulberry(seed: number) {
  let a = seed >>> 0;
  return () => {
    a |= 0;
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

function layer(count: number, seed: number, color: string, size: number, area: number): string {
  const rng = mulberry(seed);
  const parts: string[] = [];
  for (let i = 0; i < count; i++) {
    const x = Math.floor(rng() * area);
    const y = Math.floor(rng() * area);
    parts.push(`${x}px ${y}px 0 ${size > 1 ? '1px' : '0'} ${color}`);
  }
  return parts.join(',');
}

export default function AmbientScene() {
  const { far, mid, near } = useMemo(
    () => ({
      far: layer(140, 0xfaa, 'rgba(148,163,184,0.7)', 1, 1600),
      mid: layer(70, 0xb1d, 'rgba(34,211,238,0.8)', 1, 1600),
      near: layer(36, 0xc10, 'rgba(168,85,247,0.9)', 2, 1600),
    }),
    []
  );
  return (
    <div aria-hidden style={{ position: 'fixed', inset: 0, zIndex: 0, pointerEvents: 'none', overflow: 'hidden' }}>
      <div
        style={{
          position: 'absolute', inset: -800,
          background:
            'radial-gradient(ellipse 45% 35% at 78% 12%, rgba(168,85,247,0.10), transparent 70%),' +
            'radial-gradient(ellipse 50% 38% at 12% 82%, rgba(34,211,238,0.08), transparent 70%)',
        }}
      />
      <div className="sf-stars sf-stars-far" style={{ boxShadow: far }} />
      <div className="sf-stars sf-stars-mid" style={{ boxShadow: mid }} />
      <div className="sf-stars sf-stars-near" style={{ boxShadow: near }} />
      <div style={{ position: 'absolute', inset: 0, background: 'linear-gradient(to bottom, rgba(2,6,23,0.35), rgba(2,6,23,0.78))' }} />
    </div>
  );
}
