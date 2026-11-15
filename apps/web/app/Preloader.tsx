'use client';
import { useEffect, useState } from 'react';
import { AnimatePresence, motion } from 'framer-motion';
import { sfxBlip } from './audio/sfx';

// Lusion-style preloader: fullscreen calibration overlay with a live counter,
// cycling boot status and a scan sweep, shown ONCE per browser session (full
// page loads happen on every nav — a preloader on each would be hostile).
// Skipped entirely for reduced-motion users and unblocked after ~3.5s in case
// `load` stalls.

const STATUS = [
  'MOUNTING DEVICE TREE',
  'SPINNING UP DIGITAL TWIN',
  'LINKING MCP ENGINES',
  'CALIBRATING PREDICTIVE ENGINES',
  'SEALING ATTESTATION CHAIN',
];

export default function Preloader() {
  const [show, setShow] = useState(false);
  const [n, setN] = useState(0);
  const [s, setS] = useState(0);

  useEffect(() => {
    try {
      if (sessionStorage.getItem('sf_preloaded')) return;
      sessionStorage.setItem('sf_preloaded', '1');
      if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) return;
      setShow(true);
    } catch {
      setShow(true);
    }
  }, []);

  useEffect(() => {
    if (!show) return;
    const prev = document.body.style.overflow;
    document.body.style.overflow = 'hidden';
    let raf = 0;
    const iv = window.setInterval(() => setS((v) => Math.min(v + 1, STATUS.length - 1)), 380);
    const t0 = performance.now();
    const tick = (t: number) => {
      const el = (t - t0) / 1400;
      if (el < 1) {
        setN(Math.round(el * 99));
        raf = requestAnimationFrame(tick);
      } else if (document.readyState === 'complete' || t - t0 > 3500) {
        setN(100);
        setS(STATUS.length - 1);
        // round 21: the reveal lands with a soft rising sweep (SF://AUDIO only —
        // the sfx layer self-guards on the engine existing)
        sfxBlip(340, 980, 0.2, 0.024);
        setTimeout(() => setShow(false), 320);
      } else {
        setN(99);
        raf = requestAnimationFrame(tick);
      }
    };
    raf = requestAnimationFrame(tick);
    return () => {
      cancelAnimationFrame(raf);
      window.clearInterval(iv);
      document.body.style.overflow = prev;
    };
  }, [show]);

  return (
    <AnimatePresence>
      {show && (
        <motion.div
          className="sf-preloader"
          exit={{ y: '-100%' }}
          transition={{ duration: 0.85, ease: [0.76, 0, 0.24, 1] }}
          aria-hidden
        >
          <div className="sf-pre-scan" />
          <div className="sf-pre-word">
            SENTINELFORGE <span>v3</span>
          </div>
          <div className="sf-pre-status">{STATUS[s]}</div>
          <div className="sf-pre-bar">
            <span style={{ width: `${n}%` }} />
          </div>
          <div className="sf-pre-n">{n}</div>
        </motion.div>
      )}
    </AnimatePresence>
  );
}
