'use client';
import { motion, useScroll, useSpring } from 'framer-motion';
import { useEffect, useState } from 'react';

// Thin reading-progress bar pinned under the top edge — the page answers every
// scroll with visible motion. Spring-smoothed so it glides instead of stepping.
// Hidden entirely for reduced-motion users.
export default function ScrollProgress() {
  const [immobile, setImmobile] = useState(false);
  useEffect(() => {
    setImmobile(window.matchMedia('(prefers-reduced-motion: reduce)').matches);
  }, []);
  const { scrollYProgress } = useScroll();
  const scaleX = useSpring(scrollYProgress, { stiffness: 140, damping: 30, mass: 0.35 });
  if (immobile) return null;
  return (
    <motion.div
      aria-hidden
      style={{
        position: 'fixed',
        top: 0,
        left: 0,
        right: 0,
        height: 3,
        zIndex: 90,
        transformOrigin: '0% 50%',
        scaleX,
        background: 'linear-gradient(90deg, #22d3ee, #a855f7)',
        boxShadow: '0 0 14px rgba(34, 211, 238, 0.5)',
        pointerEvents: 'none',
      }}
    />
  );
}
