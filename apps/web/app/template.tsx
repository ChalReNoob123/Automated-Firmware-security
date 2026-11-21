'use client';
import { motion } from 'framer-motion';
import type { ReactNode } from 'react';

// Route transition: every navigation resolves out of a shallow depth of field
// instead of hard-cutting. Round 32 deepens the shot — the incoming route
// rises from 18px below with a 1.4% push-in and a heavy 16px defocus that
// clears over the same expo-out curve the rest of the site moves on. The
// blur is the expensive part, so it is one compositor layer and it ends at
// exactly 0 (the element returns to normal rasterization once settled).
export default function Template({ children }: { children: ReactNode }) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 18, scale: 1.014, filter: 'blur(16px)' }}
      animate={{ opacity: 1, y: 0, scale: 1, filter: 'blur(0px)' }}
      transition={{ duration: 0.7, ease: [0.16, 1, 0.3, 1] }}
      style={{ willChange: 'transform, opacity, filter' }}
    >
      {children}
    </motion.div>
  );
}
