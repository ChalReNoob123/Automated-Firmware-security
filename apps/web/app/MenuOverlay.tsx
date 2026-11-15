'use client';
import { useEffect } from 'react';
import { AnimatePresence, motion, useReducedMotion } from 'framer-motion';

// Lusion-style fullscreen menu: opens from the nav burger, huge staggered links
// with index numbers + one-line descriptions, ESC to close, body scroll locked
// while open. Links are plain <a> (the site navigates with full loads), so
// clicking one closes the overlay before the reload.
const LINKS: [string, string, string][] = [
  ['Forge', '/', 'The full pipeline, live'],
  ['Dashboard', '/dashboard', 'Fleet posture at a glance'],
  ['Devices', '/devices', 'Auto-detected, then attested'],
  ['Device Lab', '/lab', 'Bench hardware, virtually'],
  ['Emulator', '/emulator', 'Boot · break · replay'],
  ['Attack Sim', '/attacks', 'Adversary emulation'],
  ['Radar', '/radar', 'CVE → verdict in minutes'],
  ['Reports', '/reports', 'Evidence, exported'],
  ['Copilot', '/copilot', 'Ask the engines'],
];

export default function MenuOverlay({ open, onClose }: { open: boolean; onClose: () => void }) {
  const reduced = useReducedMotion() ?? false;

  useEffect(() => {
    if (!open) return;
    const esc = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    document.addEventListener('keydown', esc);
    const prev = document.body.style.overflow;
    document.body.style.overflow = 'hidden';
    return () => {
      document.removeEventListener('keydown', esc);
      document.body.style.overflow = prev;
    };
  }, [open, onClose]);

  const item = reduced
    ? { hidden: { opacity: 0 }, show: { opacity: 1, transition: { duration: 0 } } }
    : { hidden: { opacity: 0, y: 42 }, show: { opacity: 1, y: 0, transition: { duration: 0.55, ease: [0.22, 1, 0.36, 1] as const } } };

  return (
    <AnimatePresence>
      {open && (
        <motion.div
          className="sf-menu"
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          transition={{ duration: 0.3 }}
          role="dialog"
          aria-modal="true"
          aria-label="Site menu"
        >
          <button className="sf-menu-close" onClick={onClose} aria-label="Close menu">
            CLOSE ✕
          </button>
          <motion.div
            className="sf-menu-inner"
            initial="hidden"
            animate="show"
            exit="hidden"
            variants={{ hidden: {}, show: { transition: { staggerChildren: reduced ? 0 : 0.05, delayChildren: reduced ? 0 : 0.08 } } }}
          >
            {LINKS.map(([label, href, desc], i) => (
              <motion.a key={href} href={href} onClick={onClose} className="sf-menu-link" variants={item}>
                <span className="sf-menu-idx">{String(i + 1).padStart(2, '0')}</span>
                <span className="sf-menu-label">{label}</span>
                <span className="sf-menu-desc">{desc}</span>
              </motion.a>
            ))}
            <motion.a href="/login" onClick={onClose} className="sf-menu-link sf-menu-link-auth" variants={item}>
              <span className="sf-menu-idx">··</span>
              <span className="sf-menu-label">Sign in / Enroll</span>
              <span className="sf-menu-desc">TOTP-protected console</span>
            </motion.a>
          </motion.div>
          <div className="sf-menu-foot">attestation-gated · isolated workloads · reproducible findings</div>
        </motion.div>
      )}
    </AnimatePresence>
  );
}
