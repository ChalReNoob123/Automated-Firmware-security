'use client';
import { useRef } from 'react';
import { motion, useAnimationFrame, useMotionValue, useReducedMotion, useScroll, useSpring, useTransform, useVelocity } from 'framer-motion';
import { glassGlow } from './components/ui';

// Round-17 "tactility": a full-bleed drift of glass plates under the threat
// ticker whose speed and shear lean into your scroll velocity — flick the
// page and the band surges and skews, then eases back to its idle crawl.
// Window-level useScroll/useVelocity (the ScrollProgress pattern — no target
// ref, so hydration stays deterministic); the drift itself is one motion
// value stepped in useAnimationFrame with a modulo wrap over the duplicated
// half. Reduced motion: a static plate row. Hover: the drift pauses.

const PLATES: [string, string][] = [
  ['ZERO-DAY RADAR', '#22d3ee'],
  ['EMULATED TWINS', '#a855f7'],
  ['ATTESTED RUNS ONLY', '#34d399'],
  ['FUZZER SWARM', '#fb923c'],
  ['SBOM PROVENANCE', '#38bdf8'],
  ['ROOT OF TRUST', '#e2e8f0'],
  ['PATCH VERIFY', '#6ee7b7'],
  ['CVE WATCH LIVE', '#f43f5e'],
];

export default function MarqueeBand() {
  const reduced = useReducedMotion() ?? false;
  const track = useRef<HTMLDivElement>(null);
  const paused = useRef(false);
  const base = useMotionValue(0);

  const { scrollY } = useScroll();
  const vel = useVelocity(scrollY);
  const smooth = useSpring(vel, { stiffness: 210, damping: 44, mass: 0.6 });
  const skew = useTransform(smooth, [-2600, 2600], [-8, 8]);

  useAnimationFrame((_, delta) => {
    if (reduced || paused.current) return;
    const d = Math.min(delta, 50) / 1000;
    const v = smooth.get();
    // idle crawl 46px/s, surging up to ~+780px/s under a hard flick
    const speed = 46 + Math.min(Math.abs(v) / 700, 2.6) * 300;
    let x = base.get() - speed * d;
    const half = track.current ? track.current.scrollWidth / 2 : 0;
    if (half > 0) {
      // modulo wrap so the duplicate half loops seamlessly, surge-proof
      x = ((x % half) - half) % half;
      if (x === 0 && speed > 0) x = -0.001; // keep the sign so motion never stalls
    }
    base.set(x);
  });

  return (
    <div
      className="sf-marquee"
      onPointerEnter={() => {
        paused.current = true;
      }}
      onPointerLeave={() => {
        paused.current = false;
      }}
      aria-label="Platform capability band"
    >
      <motion.div ref={track} className="sf-marquee-track" style={reduced ? undefined : { x: base, skewX: skew }}>
        {[0, 1].map((half) => (
          <div key={half} className="sf-marquee-half" aria-hidden={half === 1}>
            {PLATES.map(([name, color]) => (
              <span key={`${half}-${name}`} className="sf-glass sf-marquee-plate" onPointerMove={glassGlow}>
                <i style={{ background: color, boxShadow: `0 0 10px ${color}` }} aria-hidden />
                {name}
              </span>
            ))}
          </div>
        ))}
      </motion.div>
    </div>
  );
}
